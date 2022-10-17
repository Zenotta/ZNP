use crate::comms_handler::{CommsError, Event, Node, TcpTlsConfig};
use crate::configurations::{ExtraNodeParams, TlsPrivateInfo, UserAutoGenTxSetup, UserNodeConfig};
use crate::constants::PEER_LIMIT;
use crate::interfaces::{
    ComputeRequest, NodeType, RbPaymentData, RbPaymentRequestData, RbPaymentResponseData, Response,
    UserApiRequest, UserRequest, UtxoFetchType, UtxoSet,
};
use crate::transaction_gen::{PendingMap, TransactionGen};
use crate::utils::{
    generate_half_druid, get_paiments_for_wallet, get_paiments_for_wallet_from_utxo, to_api_keys,
    to_route_pow_infos, ApiKeys, LocalEvent, LocalEventChannel, LocalEventSender, ResponseResult,
    RoutesPoWInfo,
};
use crate::wallet::{AddressStore, WalletDb, WalletDbError};
use bincode::deserialize;
use bytes::Bytes;
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::block::Block;
use naom::primitives::druid::DruidExpectation;
use naom::primitives::transaction::{DrsTxHashSpec, Transaction, TxIn, TxOut};
use naom::utils::transaction_utils::{
    construct_rb_payments_send_tx, construct_rb_receive_payment_tx, construct_receipt_create_tx,
    construct_tx_core, construct_tx_hash, construct_tx_ins_address,
};
use std::{collections::BTreeMap, error::Error, fmt, future::Future, net::SocketAddr};
use tokio::task;
use tracing::{debug, error, error_span, info, info_span, trace, warn};
use tracing_futures::Instrument;

/// Key for last pow coinbase produced
pub const TX_GENERATOR_KEY: &str = "TxGeneratorKey";

/// Result wrapper for user errors
pub type Result<T> = std::result::Result<T, UserError>;

#[derive(Debug)]
pub enum UserError {
    ConfigError(&'static str),
    Network(CommsError),
    AsyncTask(task::JoinError),
    Serialization(bincode::Error),
    WalletError(WalletDbError),
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {}", err),
            Self::Network(err) => write!(f, "Network error: {}", err),
            Self::AsyncTask(err) => write!(f, "Async task error: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
            Self::WalletError(err) => write!(f, "Wallet error: {}", err),
        }
    }
}

impl Error for UserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::Network(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
            Self::AsyncTask(ref e) => Some(e),
            Self::WalletError(ref e) => Some(e),
        }
    }
}

impl From<CommsError> for UserError {
    fn from(other: CommsError) -> Self {
        Self::Network(other)
    }
}

impl From<task::JoinError> for UserError {
    fn from(other: task::JoinError) -> Self {
        Self::AsyncTask(other)
    }
}

impl From<bincode::Error> for UserError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

impl From<WalletDbError> for UserError {
    fn from(other: WalletDbError) -> Self {
        Self::WalletError(other)
    }
}

/// Generates transactions
#[derive(Debug)]
pub struct AutoGenTx {
    tx_generator: TransactionGen,
    tx_chunk_size: Option<usize>,
    tx_in_per_tx: Option<usize>,
    tx_max_count: usize,
}

/// info for a pending paiment
#[derive(Debug)]
pub struct PendingPayment {
    amount: TokenAmount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDonate {
    Disabled,
    Enabled(TokenAmount),
}

/// An instance of a UserNode
#[derive(Debug)]
pub struct UserNode {
    node: Node,
    wallet_db: WalletDb,
    local_events: LocalEventChannel,
    compute_addr: SocketAddr,
    api_info: (SocketAddr, Option<TlsPrivateInfo>, ApiKeys, RoutesPoWInfo),
    trading_peer: Option<SocketAddr>,
    next_payment: Option<(Option<SocketAddr>, Transaction)>,
    last_block_notified: Block,
    test_auto_gen_tx: Option<AutoGenTx>,
    received_utxo_set: Option<UtxoSet>,
    pending_payments: (BTreeMap<SocketAddr, PendingPayment>, AutoDonate),
    next_rb_payment_response: Option<(SocketAddr, Option<RbPaymentResponseData>)>,
    next_rb_payment_data: Option<RbPaymentData>,
    next_rb_payment: Option<(Option<SocketAddr>, Transaction)>,
}

impl UserNode {
    ///Constructor to create a new UserNode
    ///
    /// ### Arguments
    ///
    /// * `config` - UserNodeConfig object containing UserNode parameters.
    /// * `extra`  - additional parameter for construction
    pub async fn new(config: UserNodeConfig, mut extra: ExtraNodeParams) -> Result<UserNode> {
        let addr = config
            .user_nodes
            .get(config.user_node_idx)
            .ok_or(UserError::ConfigError("Invalid user index"))?
            .address;
        let compute_addr = config
            .compute_nodes
            .get(config.user_compute_node_idx)
            .ok_or(UserError::ConfigError("Invalid compute index"))?
            .address;
        let tcp_tls_config = TcpTlsConfig::from_tls_spec(addr, &config.tls_config)?;
        let api_addr = SocketAddr::new(addr.ip(), config.user_api_port);
        let api_tls_info = config
            .user_api_use_tls
            .then(|| tcp_tls_config.clone_private_info());
        let api_keys = to_api_keys(config.api_keys.clone());
        let api_pow_info = to_route_pow_infos(config.routes_pow.clone());

        let node = Node::new(&tcp_tls_config, PEER_LIMIT, NodeType::User).await?;

        let wallet_db = match extra.shared_wallet_db {
            Some(shared_db) => shared_db,
            None => WalletDb::new(
                config.user_db_mode,
                extra.wallet_db.take(),
                config.passphrase,
            ),
        };
        let wallet_db = wallet_db
            .with_seed(config.user_node_idx, &config.user_wallet_seeds)
            .await;

        let pending_payments = match config.user_auto_donate {
            0 => (Default::default(), AutoDonate::Disabled),
            amount => (Default::default(), AutoDonate::Enabled(TokenAmount(amount))),
        };

        let test_auto_gen_tx =
            make_transaction_gen(config.user_test_auto_gen_setup, config.user_node_idx);

        Ok(UserNode {
            node,
            wallet_db,
            local_events: Default::default(),
            compute_addr,
            api_info: (api_addr, api_tls_info, api_keys, api_pow_info),
            trading_peer: None,
            next_payment: None,
            last_block_notified: Default::default(),
            test_auto_gen_tx,
            received_utxo_set: None,
            pending_payments,
            next_rb_payment_response: None,
            next_rb_payment_data: None,
            next_rb_payment: None,
        })
    }

    /// Returns the node's public endpoint.
    pub fn address(&self) -> SocketAddr {
        self.node.address()
    }

    /// Returns the node's compute endpoint.
    pub fn compute_address(&self) -> SocketAddr {
        self.compute_addr
    }

    /// Check if auto generator is active
    pub fn is_test_auto_gen_tx_active(&self) -> bool {
        self.test_auto_gen_tx.is_some()
    }

    /// Connect to a peer on the network.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Socket Address of the peer to connect to.
    pub async fn connect_to(&mut self, peer: SocketAddr) -> Result<()> {
        self.node.connect_to(peer).await?;
        Ok(())
    }

    /// Connect info for peers on the network.
    pub fn connect_info_peers(&self) -> (Node, Vec<SocketAddr>, Vec<SocketAddr>) {
        let compute = Some(self.compute_addr);
        let to_connect = compute.iter();
        let expect_connect = compute.iter();
        (
            self.node.clone(),
            to_connect.copied().collect(),
            expect_connect.copied().collect(),
        )
    }

    /// Info needed to run the API point.
    pub fn api_inputs(
        &self,
    ) -> (
        WalletDb,
        Node,
        SocketAddr,
        Option<TlsPrivateInfo>,
        ApiKeys,
        RoutesPoWInfo,
    ) {
        let (api_addr, api_tls_info, api_keys, routes_pow_info) = self.api_info.clone();
        (
            self.wallet_db.clone(),
            self.node.clone(),
            api_addr,
            api_tls_info,
            api_keys,
            routes_pow_info,
        )
    }

    /// Extract persistent dbs
    pub async fn take_closed_extra_params(&mut self) -> ExtraNodeParams {
        let wallet_db = self.wallet_db.take_closed_persistent_store().await;
        ExtraNodeParams {
            wallet_db: wallet_db.in_memory(),
            ..Default::default()
        }
    }

    /// Backup persistent storage
    pub async fn backup_persistent_store(&mut self) {
        if let Err(e) = self.wallet_db.backup_persistent_store().await {
            error!("Error bakup up main db: {:?}", e);
        }
    }

    /// Update the running total from a retrieved UTXO set/subset
    pub async fn update_running_total(&mut self) {
        let utxo_set = self.received_utxo_set.take();
        let payments = get_paiments_for_wallet_from_utxo(utxo_set.into_iter().flatten());

        self.wallet_db
            .save_usable_payments_to_wallet(payments)
            .await
            .unwrap();
    }

    /// Listens for new events from peers and handles them, processing any errors.
    pub async fn handle_next_event_response(
        &mut self,
        response: Result<Response>,
    ) -> ResponseResult {
        debug!("Response: {:?}", response);

        match response {
            Ok(Response {
                success: true,
                reason: "Shutdown",
            }) => {
                warn!("Shutdown now");
                return ResponseResult::Exit;
            }
            Ok(Response {
                success: true,
                reason: "Donation Requested",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Request Payment Address",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Payment transaction received",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Receipt asset create transaction ready",
            }) => {
                self.send_next_payment_to_destinations(self.compute_address())
                    .await
                    .unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Received receipt-based payment request",
            }) => {
                self.send_rb_payment_response().await.unwrap();
                self.send_next_rb_transaction_to_destinations(self.compute_address())
                    .await
                    .unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Received receipt-based payment response",
            }) => {
                self.send_next_rb_transaction_to_destinations(self.compute_address())
                    .await
                    .unwrap();
            }
            Ok(Response {
                success: true,
                reason: "New address ready to be sent",
            }) => {
                debug!("Sending new payment address");
                self.send_address_to_trading_peer().await.unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Next payment transaction ready",
            }) => {
                self.send_next_payment_to_destinations(self.compute_address())
                    .await
                    .unwrap();
            }
            Ok(Response {
                success: false,
                reason: "Insufficient funds for payment",
            }) => {}
            Ok(Response {
                success: false,
                reason: "Ignore unexpected transaction",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Block mining notified",
            }) => {
                self.process_mining_notified().await;
            }
            Ok(Response {
                success: true,
                reason: "Request UTXO set",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Received UTXO set",
            }) => {
                self.update_running_total().await;
            }
            Ok(Response {
                success: true,
                reason,
            }) => {
                error!("UNHANDLED RESPONSE TYPE: {:?}", reason);
            }
            Ok(Response {
                success: false,
                reason,
            }) => {
                error!("WARNING: UNHANDLED RESPONSE TYPE FAILURE: {:?}", reason);
            }
            Err(error) => {
                panic!("ERROR HANDLING RESPONSE: {:?}", error);
            }
        };

        ResponseResult::Continue
    }

    /// Listens for new events from peers and handles them.
    /// The future returned from this function should be executed in the runtime. It will block execution.
    pub async fn handle_next_event<E: Future<Output = &'static str> + Unpin>(
        &mut self,
        exit: &mut E,
    ) -> Option<Result<Response>> {
        loop {
            // State machines are not keept between iterations or calls.
            // All selection calls (between = and =>), need to be dropable
            // i.e they should only await a channel.
            tokio::select! {
                event = self.node.next_event() => {
                    trace!("handle_next_event evt {:?}", event);
                    if let res @ Some(_) = self.handle_event(event?).await.transpose() {
                        return res;
                    }
                }
                Some(event) = self.local_events.rx.recv() => {
                    if let Some(res) = self.handle_local_event(event) {
                        return Some(Ok(res));
                    }
                }
                reason = &mut *exit => return Some(Ok(Response {
                    success: true,
                    reason,
                }))
            }
        }
    }

    /// Send initial requests:
    /// - block notification request (if active)
    pub async fn send_startup_requests(&mut self) -> Result<()> {
        if self.is_test_auto_gen_tx_active() {
            info!("Send startup requests: block notification");
            return self.send_block_notification_request().await;
        }
        Ok(())
    }

    /// Local event channel.
    pub fn local_event_tx(&self) -> &LocalEventSender {
        &self.local_events.tx
    }

    ///Handle a local event
    ///
    /// ### Arguments
    ///
    /// * `event` - Event to process.
    fn handle_local_event(&mut self, event: LocalEvent) -> Option<Response> {
        match event {
            LocalEvent::Exit(reason) => Some(Response {
                success: true,
                reason,
            }),
            LocalEvent::CoordinatedShutdown(_) => None,
            LocalEvent::Ignore => None,
        }
    }

    ///Passes a frame from an event to the handle_new_frame method
    ///
    /// ### Arguments
    ///
    /// * `event` - Event object holding the frame to be passed.
    async fn handle_event(&mut self, event: Event) -> Result<Option<Response>> {
        match event {
            Event::NewFrame { peer, frame } => {
                let peer_span = error_span!("peer", ?peer);
                self.handle_new_frame(peer, frame)
                    .instrument(peer_span)
                    .await
            }
        }
    }

    /// Hanldes a new incoming message from a peer.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Socket Address of the sending peer node.
    /// * `frame` - Byte object holding the frame being handled.
    async fn handle_new_frame(
        &mut self,
        peer: SocketAddr,
        frame: Bytes,
    ) -> Result<Option<Response>> {
        let req = deserialize::<UserRequest>(&frame).map_err(|error| {
            warn!(?error, "frame-deserialize");
            error
        })?;

        let req_span = error_span!("request", ?req);
        let response = self.handle_request(peer, req).instrument(req_span).await;
        trace!(?response, ?peer, "response");

        Ok(response)
    }

    /// Handles a request.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Peer sending the request.
    /// * `req`  - Request to execute
    async fn handle_request(&mut self, peer: SocketAddr, req: UserRequest) -> Option<Response> {
        use UserRequest::*;
        trace!("handle_request: {:?}", req);

        match req {
            UserApi(req) => self.handle_api_request(peer, req).await,
            SendUtxoSet { utxo_set } => Some(self.receive_utxo_set(utxo_set)),
            SendAddressRequest => Some(self.receive_payment_address_request(peer)),
            SendPaymentTransaction { transaction } => {
                Some(self.receive_payment_transaction(transaction).await)
            }
            SendPaymentAddress { address } => {
                self.process_pending_payment_transactions(peer, address)
                    .await
            }
            SendRbPaymentRequest {
                rb_payment_request_data,
            } => Some(
                self.receive_rb_payment_request(peer, rb_payment_request_data)
                    .await,
            ),
            SendRbPaymentResponse {
                rb_payment_response,
            } => Some(
                self.receive_rb_payment_response(peer, rb_payment_response)
                    .await,
            ),
            BlockMining { block } => Some(self.notified_block_mining(peer, block)),
            Closing => self.receive_closing(peer),
        }
    }

    /// Handles an API internal request.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Peer sending the request.
    /// * `req`  - Request to execute
    async fn handle_api_request(
        &mut self,
        peer: SocketAddr,
        req: UserApiRequest,
    ) -> Option<Response> {
        use UserApiRequest::*;

        if peer != self.address() {
            // Do not process if not internal request
            return None;
        }

        match req {
            UpdateWalletFromUtxoSet { address_list } => {
                self.request_utxo_set_for_wallet_update(address_list).await
            }
            RequestDonation { paying_peer } => self.request_donation_from_peer(paying_peer).await,
            MakeIpPayment {
                payment_peer,
                amount,
            } => {
                self.request_payment_address_for_peer(payment_peer, amount)
                    .await
            }
            MakePayment { address, amount } => {
                Some(self.make_payment_transactions(None, address, amount).await)
            }
            SendCreateReceiptRequest {
                receipt_amount,
                drs_tx_hash_spec,
                metadata,
            } => Some(
                self.generate_receipt_asset_tx(receipt_amount, drs_tx_hash_spec, metadata)
                    .await,
            ),
        }
    }

    /// Handles the receipt of closing event
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    fn receive_closing(&mut self, peer: SocketAddr) -> Option<Response> {
        if peer != self.compute_address() {
            return None;
        }

        Some(Response {
            success: true,
            reason: "Shutdown",
        })
    }

    pub async fn send_request_utxo_set(&mut self, address_list: UtxoFetchType) -> Result<()> {
        self.node
            .send(
                self.compute_address(),
                ComputeRequest::SendUtxoRequest { address_list },
            )
            .await?;
        Ok(())
    }

    pub fn get_next_payment_transaction(&self) -> Option<(Option<SocketAddr>, Transaction)> {
        self.next_payment.clone()
    }

    pub fn get_received_utxo(&self) -> Option<UtxoSet> {
        self.received_utxo_set.clone()
    }

    /// Sends the next internal payment transaction to be processed by the connected Compute
    /// node
    ///
    /// ### Arguments
    ///
    /// * `compute_peer`    - Compute peer to send the payment tx to
    /// * `payment_tx`      - Transaction to send
    pub async fn send_next_payment_to_destinations(
        &mut self,
        compute_peer: SocketAddr,
    ) -> Result<()> {
        let (peer, tx) = self.next_payment.take().unwrap();

        self.send_transactions_to_compute(compute_peer, vec![tx.clone()])
            .await?;

        self.store_payment_transaction(tx.clone()).await;
        if let Some(peer) = peer {
            self.send_payment_to_receiver(peer, tx).await?;
        }

        Ok(())
    }

    /// Sends the next internal receipt-based payment transaction to be processed by the connected Compute
    /// node
    ///
    /// ### Arguments
    ///
    /// * `compute_peer` - Compute peer to send the payment tx to
    pub async fn send_next_rb_transaction_to_destinations(
        &mut self,
        compute_peer: SocketAddr,
    ) -> Result<()> {
        let (peer, transaction) = self.next_rb_payment.take().unwrap();
        self.store_payment_transaction(transaction.clone()).await;
        let _peer_span =
            info_span!("sending receipt-based transaction to compute node for processing");
        let transactions = vec![transaction.clone()];
        self.node
            .send(
                compute_peer,
                ComputeRequest::SendTransactions { transactions },
            )
            .await?;

        if let Some(peer) = peer {
            self.send_payment_to_receiver(peer, transaction).await?;
        }

        Ok(())
    }

    /// Sends the next internal payment transaction to be processed by the connected Compute
    /// node
    ///
    /// ### Arguments
    ///
    /// * `compute_peer` - Compute peer to send the payment tx to
    /// * `transactions` - Transactions to send
    pub async fn send_transactions_to_compute(
        &mut self,
        compute_peer: SocketAddr,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let _peer_span = info_span!("sending transactions to compute node for processing");
        self.node
            .send(
                compute_peer,
                ComputeRequest::SendTransactions { transactions },
            )
            .await?;

        Ok(())
    }

    /// Request a UTXO set/subset from Compute for updating the running total
    ///
    /// ### Arguments
    ///
    /// * `address_list` - Address list of UTXO set/subset to retrieve
    pub async fn request_utxo_set_for_wallet_update(
        &mut self,
        address_list: UtxoFetchType,
    ) -> Option<Response> {
        self.send_request_utxo_set(address_list).await.ok()?;
        Some(Response {
            success: true,
            reason: "Request UTXO set",
        })
    }

    /// Request a UTXO set/subset from Compute for updating the running total
    ///
    /// ### Arguments
    ///
    /// * `payment_peer` - Peer to send request to
    pub async fn request_donation_from_peer(
        &mut self,
        payment_peer: SocketAddr,
    ) -> Option<Response> {
        self.connect_to(payment_peer).await.ok()?;
        self.send_donation_address_to_peer(payment_peer)
            .await
            .ok()?;
        Some(Response {
            success: true,
            reason: "Donation Requested",
        })
    }

    /// Request a UTXO set/subset from Compute for updating the running total
    ///
    /// ### Arguments
    ///
    /// * `payment_peer` - Peer to send request to
    /// * `amount`       - Amount to pay
    pub async fn request_payment_address_for_peer(
        &mut self,
        payment_peer: SocketAddr,
        amount: TokenAmount,
    ) -> Option<Response> {
        self.send_address_request(payment_peer, amount).await.ok()?;
        Some(Response {
            success: true,
            reason: "Request Payment Address",
        })
    }

    /// Receives a payment transaction to one of this user's addresses
    ///
    /// ### Arguments
    ///
    /// * `transaction` - Transaction to receive and save to wallet
    pub async fn receive_payment_transaction(&mut self, transaction: Transaction) -> Response {
        self.store_payment_transaction(transaction).await;

        Response {
            success: true,
            reason: "Payment transaction received",
        }
    }

    /// Store payment transaction
    ///
    /// ### Arguments
    ///
    /// * `transaction` - Transaction to be received and saved to wallet
    pub async fn store_payment_transaction(&mut self, transaction: Transaction) {
        let hash = construct_tx_hash(&transaction);

        let payments = get_paiments_for_wallet(Some((&hash, &transaction)).into_iter());

        let our_payments = self
            .wallet_db
            .save_usable_payments_to_wallet(payments)
            .await
            .unwrap();
        debug!("store_payment_transactions: {:?}", our_payments);
    }

    /// Process pending paiment transaction with received address
    ///
    /// ### Arguments
    ///
    /// * `peer`    - Peer recieving the payment.
    /// * `address` - Address to assign the payment transaction to
    pub async fn process_pending_payment_transactions(
        &mut self,
        peer: SocketAddr,
        address: String,
    ) -> Option<Response> {
        let amount = match (
            self.pending_payments.0.remove(&peer),
            self.pending_payments.1,
        ) {
            (Some(PendingPayment { amount }), _) => amount,
            (_, AutoDonate::Enabled(amount)) => amount,
            _ => {
                return Some(Response {
                    success: false,
                    reason: "Ignore unexpected transaction",
                })
            }
        };

        Some(
            self.make_payment_transactions(Some(peer), address, amount)
                .await,
        )
    }

    /// Process specified paiment, updating wallet and next_payment
    ///
    /// ### Arguments
    ///
    /// * `peer`    - Peer recieving the payment.
    /// * `address` - Address to assign the payment transaction to
    /// * `amount`  - Price/amount payed
    pub async fn make_payment_transactions(
        &mut self,
        peer: Option<SocketAddr>,
        address: String,
        amount: TokenAmount,
    ) -> Response {
        let tx_out = vec![TxOut::new_token_amount(address, amount)];
        let asset_required = Asset::Token(amount);
        let (tx_ins, tx_outs) =
            if let Ok(value) = self.fetch_tx_ins_and_tx_outs(asset_required, tx_out).await {
                value
            } else {
                return Response {
                    success: false,
                    reason: "Insufficient funds for payment",
                };
            };
        let payment_tx = construct_tx_core(tx_ins, tx_outs);
        self.next_payment = Some((peer, payment_tx));

        Response {
            success: true,
            reason: "Next payment transaction ready",
        }
    }

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    pub async fn fetch_tx_ins_and_tx_outs(
        &mut self,
        asset_required: Asset,
        mut tx_outs: Vec<TxOut>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>)> {
        let (tx_cons, total_amount, tx_used) = self
            .wallet_db
            .fetch_inputs_for_payment(asset_required.clone())
            .await?;

        if let Some(excess) = total_amount.get_excess(&asset_required) {
            let (excess_address, _) = self.wallet_db.generate_payment_address().await;
            tx_outs.push(TxOut::new_asset(excess_address, excess));
        }

        let tx_ins = self
            .wallet_db
            .consume_inputs_for_payment(tx_cons, tx_used)
            .await;

        Ok((tx_ins, tx_outs))
    }

    /// Sends a payment transaction to the receiving party
    ///
    /// ### Arguments
    ///
    /// * `peer`        - Peer to send the transaction to
    /// * `transaction` - The transaction to be sent
    pub async fn send_payment_to_receiver(
        &mut self,
        peer: SocketAddr,
        transaction: Transaction,
    ) -> Result<()> {
        let _peer_span = info_span!("sending payment transaction to receiver");

        self.node
            .send(peer, UserRequest::SendPaymentTransaction { transaction })
            .await?;

        Ok(())
    }

    /// Sends a request for a payment address
    ///
    /// ### Arguments
    ///
    /// * `peer`    - Socket address of peer to request from
    /// * `amount`    - Amount being payed
    pub async fn send_address_request(
        &mut self,
        peer: SocketAddr,
        amount: TokenAmount,
    ) -> Result<()> {
        let _peer_span = info_span!("sending payment address request");
        debug!("Sending request for payment address to peer: {:?}", peer);

        self.pending_payments
            .0
            .insert(peer, PendingPayment { amount });

        self.node
            .send(peer, UserRequest::SendAddressRequest)
            .await?;

        Ok(())
    }

    /// Sends a block notification request to a Compute node
    pub async fn send_block_notification_request(&mut self) -> Result<()> {
        let _peer_span = info_span!("sending block notification request");

        self.node
            .send(
                self.compute_addr,
                ComputeRequest::SendUserBlockNotificationRequest,
            )
            .await?;

        Ok(())
    }

    /// Sends a payment address from a request
    pub async fn send_address_to_trading_peer(&mut self) -> Result<()> {
        let peer = self.trading_peer.take().unwrap();
        let (address, _) = self.wallet_db.generate_payment_address().await;
        debug!("Address to send: {:?}", address);

        self.node
            .send(peer, UserRequest::SendPaymentAddress { address })
            .await?;
        Ok(())
    }

    /// Sends a donation payment address
    ///
    /// ### Arguments
    ///
    ///* `peer`    - Peer to send the address to
    pub async fn send_donation_address_to_peer(&mut self, peer: SocketAddr) -> Result<()> {
        self.trading_peer = Some(peer);
        self.send_address_to_trading_peer().await
    }

    /// Received a mined block notification: allow to update pending transactions
    ///
    /// ### Arguments
    ///
    /// * `peer` -  SocketAdress of the peer notifying.
    /// * `block` - Block that is being mined and will be stored.
    pub fn notified_block_mining(&mut self, peer: SocketAddr, block: Block) -> Response {
        if peer == self.compute_addr {
            self.last_block_notified = block;

            Response {
                success: true,
                reason: "Block mining notified",
            }
        } else {
            Response {
                success: false,
                reason: "Invalid block mining notifier",
            }
        }
    }

    /// Process a notification for block mining to auto generate next transactions
    pub async fn process_mining_notified(&mut self) {
        if self.test_auto_gen_tx.is_none() {
            return;
        }

        let auto_gen = self.test_auto_gen_tx.as_mut().unwrap();

        // Load any data after restart
        if !auto_gen.tx_generator.is_up_to_date_with_snapshot() {
            if let Some(v) = self.wallet_db.get_db_value(TX_GENERATOR_KEY).await {
                auto_gen.tx_generator.apply_snapshot_state(&v);
            }
        }

        // Process committed transactions
        {
            let txs = &self.last_block_notified.transactions;
            info!("Block notified with txs: {}", txs.len());
            auto_gen.tx_generator.commit_transactions(txs);
        }

        // Send next transactions
        let mut total_txs = 0;
        loop {
            let auto_gen = self.test_auto_gen_tx.as_mut().unwrap();
            let txs_chunk_len = std::cmp::min(
                auto_gen.tx_chunk_size.unwrap_or(usize::MAX),
                auto_gen.tx_max_count.saturating_sub(total_txs),
            );
            let txs_chunk: Vec<_> = auto_gen
                .tx_generator
                .make_all_transactions(auto_gen.tx_in_per_tx, txs_chunk_len)
                .into_iter()
                .map(|(_, tx)| tx)
                .collect();

            if txs_chunk.is_empty() {
                break;
            }

            total_txs += txs_chunk.len();
            debug!("New Generated txs:{:?}", txs_chunk);
            if let Err(e) = self
                .send_transactions_to_compute(self.compute_address(), txs_chunk)
                .await
            {
                error!("Autogenerated tx not sent to {:?}", e);
            }
        }
        if total_txs > 0 {
            info!("New Generated txs sent: {}", total_txs);
        }

        let auto_gen = self.test_auto_gen_tx.as_mut().unwrap();
        self.wallet_db
            .set_db_value(TX_GENERATOR_KEY, auto_gen.tx_generator.snapshot_state())
            .await;
    }

    /// Get pending autogenerated transactions
    pub fn pending_test_auto_gen_txs(&self) -> Option<&PendingMap> {
        self.test_auto_gen_tx
            .as_ref()
            .map(|a| a.tx_generator.pending_txs())
    }

    /// Get the wallet db
    pub fn get_wallet_db(&self) -> &WalletDb {
        &self.wallet_db
    }

    /// Get the last block notified to us
    pub fn get_last_block_notified(&self) -> &Block {
        &self.last_block_notified
    }

    /// Receive the requested UTXO set/subset from Compute
    ///
    /// ### Arguments
    ///
    /// * `utxo_set` - The requested UTXO set
    fn receive_utxo_set(&mut self, utxo_set: UtxoSet) -> Response {
        self.received_utxo_set = Some(utxo_set);

        Response {
            success: true,
            reason: "Received UTXO set",
        }
    }

    /// Receives a request for a new payment address to be produced
    ///
    /// ### Arguments
    ///
    /// * `peer`    - Peer who made the request
    /// * `amount`  - Amount the payment will be
    fn receive_payment_address_request(&mut self, peer: SocketAddr) -> Response {
        self.trading_peer = Some(peer);

        Response {
            success: true,
            reason: "New address ready to be sent",
        }
    }

    /// Sends a request for a new receipt-based payment
    ///
    /// ### Nomenclature
    ///
    /// The sender(Alice) and receiver(Bob) context stays consistent for
    /// `send_rb_payment_request`, `receive_rb_payment_request`,
    /// `send_rb_payment_response`, and `receive_rb_payment_response`
    ///
    /// ### Arguments
    ///
    /// * `peer`            - Peer who made the request
    /// * `send_asset`       - The asset to be sent
    pub async fn send_rb_payment_request(
        &mut self,
        peer: SocketAddr,
        sender_asset: Asset,
        drs_tx_hash: Option<String>, /* drs_tx_hash of Receipt asset to receive */
    ) -> Result<()> {
        let (sender_address, _) = self.wallet_db.generate_payment_address().await;
        let sender_half_druid = generate_half_druid();

        let (tx_ins, tx_outs) = self
            .fetch_tx_ins_and_tx_outs(sender_asset.clone(), Vec::new())
            .await?;

        let (rb_payment_data, rb_payment_request_data) = make_rb_payment_send_tx_and_request(
            sender_asset,
            (tx_ins, tx_outs),
            sender_half_druid,
            sender_address,
            drs_tx_hash,
        );

        self.next_rb_payment_data = Some(rb_payment_data);
        self.node
            .send(
                peer,
                UserRequest::SendRbPaymentRequest {
                    rb_payment_request_data,
                },
            )
            .await?;
        Ok(())
    }

    /// Sends a response to a new receipt-based payment request
    pub async fn send_rb_payment_response(&mut self) -> Result<()> {
        let (peer, rb_payment_response) = self.next_rb_payment_response.take().unwrap();
        self.node
            .send(
                peer,
                UserRequest::SendRbPaymentResponse {
                    rb_payment_response,
                },
            )
            .await?;
        Ok(())
    }

    /// Receives a request for a new receipt-based payment
    /// ### Nomenclature
    ///
    /// The sender(Alice) and receiver(Bob) context stays consistent for
    /// `send_rb_payment_request`, `receive_rb_payment_request`,
    /// `send_rb_payment_response`, and `receive_rb_payment_response`
    ///
    /// ### Arguments
    ///
    /// * `peer`                         - Peer who made the request
    /// * `rb_payment_request_data`      - Receipt-based payment request data struct
    async fn receive_rb_payment_request(
        &mut self,
        peer: SocketAddr,
        rb_payment_request_data: RbPaymentRequestData,
    ) -> Response {
        let receiver_half_druid = generate_half_druid();
        let (receiver_address, _) = self.wallet_db.generate_payment_address().await;
        let asset_required = Asset::receipt(
            1,
            rb_payment_request_data.sender_drs_tx_expectation.clone(),
            None,
        );
        let tx_ins_and_outs = self
            .fetch_tx_ins_and_tx_outs(asset_required, Vec::new())
            .await;

        let (tx_ins, tx_outs) = if let Ok(value) = tx_ins_and_outs {
            value
        } else {
            return Response {
                success: false,
                reason: "Insufficient funds for payment",
            };
        };

        let (rb_receive_tx, rb_payment_response) = make_rb_payment_receipt_tx_and_response(
            rb_payment_request_data,
            (tx_ins, tx_outs),
            receiver_half_druid,
            receiver_address,
        );

        self.next_rb_payment = Some((Some(peer), rb_receive_tx));
        self.next_rb_payment_response = Some((peer, Some(rb_payment_response)));

        Response {
            success: true,
            reason: "Received receipt-based payment request",
        }
    }

    /// Receive a response for a new receipt-based payment
    ///
    /// ### Nomenclature
    ///
    /// The sender(Alice) and receiver(Bob) context stays consistent for
    /// `send_rb_payment_request`, `receive_rb_payment_request`,
    /// `send_rb_payment_response`, and `receive_rb_payment_response`
    ///
    /// ### Arguments
    ///
    /// * `peer`                    - Peer who sent the response
    /// * `rb_payment_response`     - (receiver address, half druid value, hash value of Vec<TxIn>)
    async fn receive_rb_payment_response(
        &mut self,
        peer: SocketAddr,
        rb_payment_response: Option<RbPaymentResponseData>,
    ) -> Response {
        let rb_payment_data = self.next_rb_payment_data.take().unwrap();
        //TODO: Handle `None` value upon receipt-based payment rejection
        if let Some(rb_payment_response) = rb_payment_response {
            let rb_send_tx = make_rb_payment_send_transaction(rb_payment_response, rb_payment_data);
            self.next_rb_payment = Some((Some(peer), rb_send_tx));
        }
        Response {
            success: true,
            reason: "Received receipt-based payment response",
        }
    }

    /// Create new receipt-asset transaction to send to compute for processing
    pub async fn generate_receipt_asset_tx(
        &mut self,
        receipt_amount: u64,
        drs_tx_hash_spec: DrsTxHashSpec,
        metadata: Option<String>,
    ) -> Response {
        let AddressStore {
            public_key,
            secret_key,
            address_version: _,
        } = self.wallet_db.generate_payment_address().await.1;

        let block_num = self.last_block_notified.header.b_num;
        let receipt_asset_tx = construct_receipt_create_tx(
            block_num,
            public_key,
            &secret_key,
            receipt_amount,
            drs_tx_hash_spec,
            metadata,
        );

        self.next_payment = Some((None, receipt_asset_tx));

        Response {
            reason: "Receipt asset create transaction ready",
            success: true,
        }
    }

    /// Get `Node` member
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

/// Make the send initial request for receipt based transaction
///
/// * `send_asset`        - The asset to be sent
/// * `(tx_ins, tx_outs)` - The send transaction infos
/// * `sender_half_druid` - The sender half druid part
/// * `sender_address`    - The sender address
pub fn make_rb_payment_send_tx_and_request(
    sender_asset: Asset,
    (tx_ins, tx_outs): (Vec<TxIn>, Vec<TxOut>),
    sender_half_druid: String,
    sender_address: String,
    sender_drs_tx_expectation: Option<String>,
) -> (RbPaymentData, RbPaymentRequestData) {
    let sender_from_addr = construct_tx_ins_address(&tx_ins);

    let rb_payment_request_data = RbPaymentRequestData {
        sender_address,
        sender_half_druid: sender_half_druid.clone(),
        sender_from_addr,
        sender_asset: sender_asset.clone(),
        sender_drs_tx_expectation,
    };

    let rb_payment_data = RbPaymentData {
        sender_asset,
        sender_half_druid,
        tx_ins,
        tx_outs,
    };

    (rb_payment_data, rb_payment_request_data)
}

/// Make The receipt transaction and response
///
/// * `rb_payment_request_data` - Receipt-based payment request data struct
/// * `(tx_ins, tx_outs)`       - The receipt transaction infos
/// * `receiver_half_druid`     - The receiver half druid part
/// * `receiver_address`        - The receiver address
pub fn make_rb_payment_receipt_tx_and_response(
    rb_payment_request_data: RbPaymentRequestData,
    (tx_ins, tx_outs): (Vec<TxIn>, Vec<TxOut>),
    receiver_half_druid: String,
    receiver_address: String,
) -> (Transaction, RbPaymentResponseData) {
    //TODO: Decide if the send/receive assets are acceptable
    let RbPaymentRequestData {
        sender_address,
        sender_half_druid,
        sender_from_addr,
        sender_asset,
        sender_drs_tx_expectation,
    } = rb_payment_request_data;

    let druid = sender_half_druid + &receiver_half_druid;
    let receiver_from_addr = construct_tx_ins_address(&tx_ins);

    // DruidExpectation for sender(Alice)
    let sender_druid_expectation = DruidExpectation {
        from: receiver_from_addr,
        to: sender_address.clone(),
        asset: Asset::receipt(1, sender_drs_tx_expectation.clone(), None),
    };

    // DruidExpectation for receiver(Bob)
    let receiver_druid_expectation = DruidExpectation {
        from: sender_from_addr,
        to: receiver_address.clone(),
        asset: sender_asset,
    };

    let rb_receive_tx = construct_rb_receive_payment_tx(
        tx_ins,
        tx_outs,
        sender_address,
        0,
        druid,
        vec![receiver_druid_expectation],
        sender_drs_tx_expectation,
    );

    let rb_payment_response = RbPaymentResponseData {
        receiver_address,
        receiver_half_druid,
        sender_druid_expectation,
    };

    (rb_receive_tx, rb_payment_response)
}

/// Make The payment send transaction
///
/// * `rb_payment_response`- (receiver address, half druid value, hash value of Vec<TxIn>)
/// * `rb_payment_data`    - The data related to initial requrest for the payment
pub fn make_rb_payment_send_transaction(
    rb_payment_response: RbPaymentResponseData,
    rb_payment_data: RbPaymentData,
) -> Transaction {
    let RbPaymentData {
        sender_asset,
        sender_half_druid,
        tx_ins,
        tx_outs,
    } = rb_payment_data;

    let RbPaymentResponseData {
        receiver_address,
        receiver_half_druid,
        sender_druid_expectation,
    } = rb_payment_response;

    let druid = sender_half_druid + &receiver_half_druid;

    construct_rb_payments_send_tx(
        tx_ins,
        tx_outs,
        receiver_address,
        sender_asset.token_amount(),
        0,
        druid,
        vec![sender_druid_expectation],
    )
}

fn make_transaction_gen(setup: UserAutoGenTxSetup, user_node_idx: usize) -> Option<AutoGenTx> {
    let initial_transactions = setup
        .user_initial_transactions
        .get(user_node_idx)
        .cloned()
        .unwrap_or_default();
    if !initial_transactions.is_empty() {
        Some(AutoGenTx {
            tx_generator: TransactionGen::new(initial_transactions),
            tx_chunk_size: setup.user_setup_tx_chunk_size,
            tx_in_per_tx: setup.user_setup_tx_in_per_tx,
            tx_max_count: setup.user_setup_tx_max_count,
        })
    } else {
        None
    }
}
