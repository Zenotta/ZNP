use crate::comms_handler::{CommsError, Event, TcpTlsConfig};
use crate::configurations::{ExtraNodeParams, MinerNodeConfig, TlsPrivateInfo};
use crate::constants::PEER_LIMIT;
use crate::interfaces::{
    BlockchainItem, ComputeRequest, MineRequest, MinerInterface, NodeType, PowInfo, ProofOfWork,
    Response, StorageRequest,
};
use crate::utils::{
    self, apply_mining_tx, format_parition_pow_address, generate_pow_for_block,
    get_paiments_for_wallet, to_api_keys, to_route_pow_infos, ApiKeys, DeserializedBlockchainItem,
    LocalEvent, LocalEventChannel, LocalEventSender, ResponseResult, RoutesPoWInfo,
    RunningTaskOrResult,
};
use crate::wallet::WalletDb;
use crate::Node;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use naom::primitives::asset::TokenAmount;
use naom::primitives::block::{self, BlockHeader};
use naom::primitives::transaction::Transaction;
use naom::utils::transaction_utils::{construct_coinbase_tx, construct_tx_hash};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::{
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    net::{IpAddr, Ipv4Addr},
    str,
    time::SystemTime,
};
use tokio::task;
use tracing::{debug, error, error_span, info, trace, warn};
use tracing_futures::Instrument;

/// Key for last pow coinbase produced
pub const LAST_COINBASE_KEY: &str = "LastCoinbaseKey";

/// Key for last pow coinbase produced
pub const MINING_ADDRESS_KEY: &str = "MiningAddressKey";

/// Result wrapper for miner errors
pub type Result<T> = std::result::Result<T, MinerError>;

/// Wrapper for current block
///
/// TODO: Circumvent using a Mutex just for API purposes.
pub type CurrentBlockWithMutex = Arc<Mutex<Option<BlockPoWReceived>>>;

/// Block Pow task input/output
#[derive(Debug, Clone)]
pub struct BlockPoWInfo {
    peer: SocketAddr,
    start_time: SystemTime,
    header: BlockHeader,
    coinbase: Transaction,
}

/// Received block
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockPoWReceived {
    block: BlockHeader,
    reward: TokenAmount,
}

#[derive(Debug)]
pub enum MinerError {
    ConfigError(&'static str),
    Network(CommsError),
    Serialization(bincode::Error),
    AsyncTask(task::JoinError),
}

impl fmt::Display for MinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {}", err),
            Self::Network(err) => write!(f, "Network error: {}", err),
            Self::AsyncTask(err) => write!(f, "Async task error: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl Error for MinerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::Network(ref e) => Some(e),
            Self::AsyncTask(e) => Some(e),
            Self::Serialization(ref e) => Some(e),
        }
    }
}

impl From<bincode::Error> for MinerError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

impl From<CommsError> for MinerError {
    fn from(other: CommsError) -> Self {
        Self::Network(other)
    }
}

impl From<task::JoinError> for MinerError {
    fn from(other: task::JoinError) -> Self {
        Self::AsyncTask(other)
    }
}

/// An instance of a MinerNode
#[derive(Debug)]
pub struct MinerNode {
    node: Node,
    wallet_db: WalletDb,
    local_events: LocalEventChannel,
    compute_addr: SocketAddr,
    storage_addr: SocketAddr,
    rand_num: Vec<u8>,
    current_block: CurrentBlockWithMutex,
    last_pow: Option<ProofOfWork>,
    current_coinbase: Option<(String, Transaction)>,
    current_payment_address: Option<String>,
    wait_partition_task: bool,
    mining_partition_task: RunningTaskOrResult<(ProofOfWork, PowInfo, SocketAddr)>,
    mining_block_task: RunningTaskOrResult<BlockPoWInfo>,
    blockchain_item_received: Option<(String, BlockchainItem, SocketAddr)>,
    api_info: (SocketAddr, Option<TlsPrivateInfo>, ApiKeys, RoutesPoWInfo),
}

impl MinerNode {
    /// Creates a new instance of Mining implementor
    ///
    /// ### Arguments
    ///
    /// * `config`   - MinerNodeConfig object that hold the miner_nodes and miner_db_mode
    /// * `extra`  - additional parameter for construction
    pub async fn new(config: MinerNodeConfig, mut extra: ExtraNodeParams) -> Result<MinerNode> {
        let addr = config
            .miner_nodes
            .get(config.miner_node_idx)
            .ok_or(MinerError::ConfigError("Invalid miner index"))?
            .address;
        let compute_addr = config
            .compute_nodes
            .get(config.miner_compute_node_idx)
            .ok_or(MinerError::ConfigError("Invalid compute index"))?
            .address;
        let storage_addr = config
            .storage_nodes
            .get(config.miner_storage_node_idx)
            .ok_or(MinerError::ConfigError("Invalid storage index"))?
            .address;
        let wallet_db = WalletDb::new(
            config.miner_db_mode,
            extra.wallet_db.take(),
            config.passphrase,
        );

        let tcp_tls_config = TcpTlsConfig::from_tls_spec(addr, &config.tls_config)?;
        let api_addr = SocketAddr::new(addr.ip(), config.miner_api_port);
        let api_tls_info = config
            .miner_api_use_tls
            .then(|| tcp_tls_config.clone_private_info());
        let api_keys = to_api_keys(config.api_keys.clone());
        let node = Node::new(&tcp_tls_config, PEER_LIMIT, NodeType::Miner).await?;
        let api_pow_info = to_route_pow_infos(config.routes_pow.clone());

        MinerNode {
            node,
            local_events: Default::default(),
            wallet_db,
            compute_addr,
            storage_addr,
            rand_num: Default::default(),
            current_block: Arc::new(Mutex::new(None)),
            last_pow: None,
            current_coinbase: None,
            current_payment_address: None,
            wait_partition_task: Default::default(),
            mining_partition_task: Default::default(),
            mining_block_task: Default::default(),
            blockchain_item_received: Default::default(),
            api_info: (api_addr, api_tls_info, api_keys, api_pow_info),
        }
        .load_local_db()
        .await
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
        CurrentBlockWithMutex,
        RoutesPoWInfo,
    ) {
        let (api_addr, api_tls_info, api_keys, api_pow_info) = self.api_info.clone();
        (
            self.wallet_db.clone(),
            self.node.clone(),
            api_addr,
            api_tls_info,
            api_keys,
            self.current_block.clone(),
            api_pow_info,
        )
    }

    /// Returns the node's public endpoint.
    pub fn address(&self) -> SocketAddr {
        self.node.address()
    }

    /// Returns the node's compute endpoint.
    pub fn compute_address(&self) -> SocketAddr {
        self.compute_addr
    }

    /// Returns the node's storage endpoint.
    pub fn storage_address(&self) -> SocketAddr {
        self.storage_addr
    }

    /// Connect to a peer on the network.
    ///
    /// ### Arguments
    ///
    /// * `peer`   - Address of the peer to connect to.
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

    /// Send initial requests:
    /// - partition request
    pub async fn send_startup_requests(&mut self) -> Result<()> {
        info!("Send startup requests: partition");
        self.send_partition_request().await
    }

    /// Local event channel.
    pub fn local_event_tx(&self) -> &LocalEventSender {
        &self.local_events.tx
    }

    /// Extract persistent dbs
    pub async fn take_closed_extra_params(&mut self) -> ExtraNodeParams {
        let wallet_db = self.wallet_db.take_closed_persistent_store().await;
        ExtraNodeParams {
            wallet_db: wallet_db.in_memory(),
            ..Default::default()
        }
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
                reason: "Blockchain item received",
            }) => {
                if let Some((key, item, peer)) = self.blockchain_item_received.as_ref() {
                    log_received_blockchain_item(key, item, peer);
                } else {
                    warn!("Failed to retrieve blockchain item");
                }
            }
            Ok(Response {
                success: true,
                reason: "Received random number successfully",
            }) => {
                info!("RANDOM NUMBER RECEIVED: {:?}", self.rand_num);
            }
            Ok(Response {
                success: true,
                reason: "Partition PoW complete",
            }) => {
                if self.process_found_partition_pow().await {
                    info!("Partition Pow found and sent");
                }
            }
            Ok(Response {
                success: true,
                reason: "Pre-block received successfully",
            }) => {
                info!("PRE-BLOCK RECEIVED");
            }
            Ok(Response {
                success: true,
                reason: "Block is valid",
            }) => {
                info!("MERKLE ROOT VALID");
            }
            Ok(Response {
                success: false,
                reason: "Block is not valid",
            }) => {
                info!("MERKLE ROOT INVALID");
            }
            Ok(Response {
                success: true,
                reason: "Block PoW complete",
            }) => {
                if self.process_found_block_pow().await {
                    info!("Block PoW found and sent");
                }
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
                _ = self.mining_partition_task.wait() => {
                    self.wait_partition_task = false;
                    return Some(Ok(Response {
                        success: true,
                        reason: "Partition PoW complete",
                    }));
                }
                _ = self.mining_block_task.wait(), if !self.wait_partition_task => {
                    return Some(Ok(Response {
                        success: true,
                        reason: "Block PoW complete",
                    }));
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

    /// Handles an event using handle_new_frame
    ///
    /// ### Arguments
    ///
    /// * `event`   - Event object to be handled.
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
    /// * `peer`   - Socket address of the peer sending the message.
    /// * `frame`   - Bytes object holding the frame
    async fn handle_new_frame(
        &mut self,
        peer: SocketAddr,
        frame: Bytes,
    ) -> Result<Option<Response>> {
        let req = deserialize::<MineRequest>(&frame).map_err(|error| {
            warn!(?error, "frame-deserialize");
            error
        })?;

        let req_span = error_span!("request", ?req);
        let response = self.handle_request(peer, req).instrument(req_span).await;
        debug!(?response, ?peer, "response");

        Ok(response)
    }

    /// Handles a compute request.
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    /// * `req`   - MineRequest object that is the recieved request
    /// TODO: Find something to do with win_coinbase. Allows to know winner
    async fn handle_request(&mut self, peer: SocketAddr, req: MineRequest) -> Option<Response> {
        use MineRequest::*;
        trace!("handle_request: {:?}", req);

        match req {
            SendBlockchainItem { key, item } => Some(self.receive_blockchain_item(peer, key, item)),
            SendBlock {
                pow_info,
                rnum,
                win_coinbases,
                reward,
                block,
            } => {
                self.receive_pre_block_and_random(
                    peer,
                    pow_info,
                    rnum,
                    win_coinbases,
                    reward,
                    block,
                )
                .await
            }
            SendTransactions {
                tx_merkle_verification,
            } => {
                self.receive_trans_verification(tx_merkle_verification)
                    .await
            }
            Closing => self.receive_closing(peer),
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

    /// Sends a request to retrieve a blockchain item from storage
    ///
    /// ### Arguments
    ///
    /// * `key`  - The blockchain item key.
    pub async fn request_blockchain_item(&mut self, key: String) -> Result<()> {
        self.blockchain_item_received = None;
        self.node
            .send(self.storage_addr, StorageRequest::GetBlockchainItem { key })
            .await?;
        Ok(())
    }

    /// Return the blockchain item received
    pub async fn get_blockchain_item_received(
        &mut self,
    ) -> &Option<(String, BlockchainItem, SocketAddr)> {
        &self.blockchain_item_received
    }

    /// Receives a new block to be mined
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    /// * `pre_block` - New block to be mined
    /// * `reward`    - The block reward to be paid on successful PoW
    async fn receive_pre_block_and_random(
        &mut self,
        peer: SocketAddr,
        pow_info: PowInfo,
        rand_num: Vec<u8>,
        win_coinbases: Vec<String>,
        reward: TokenAmount,
        pre_block: Option<BlockHeader>,
    ) -> Option<Response> {
        let process_rnd = self
            .receive_random_number(peer, pow_info, rand_num, win_coinbases)
            .await;
        let process_block = if let Some(pre_block) = pre_block {
            self.receive_pre_block(peer, pre_block, reward).await
        } else {
            false
        };

        match (process_rnd, process_block) {
            (true, false) => Some(Response {
                success: true,
                reason: "Received random number successfully",
            }),
            (_, true) => Some(Response {
                success: true,
                reason: "Pre-block received successfully",
            }),
            (false, false) => None,
        }
    }

    /// Handles the receipt of the random number of partitioning
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    /// * `rand_num` - random num to be recieved in Vec<u8>
    async fn receive_random_number(
        &mut self,
        peer: SocketAddr,
        pow_info: PowInfo,
        rand_num: Vec<u8>,
        win_coinbases: Vec<String>,
    ) -> bool {
        if peer != self.compute_address() {
            return false;
        }

        if self.rand_num == rand_num {
            self.process_found_partition_pow().await;
            return false;
        }

        if self.is_current_coinbase_found(&win_coinbases) {
            self.commit_found_coinbase().await;
        }
        self.start_generate_partition_pow(peer, pow_info, rand_num)
            .await;
        true
    }

    /// Receives a new block to be mined
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    /// * `pre_block` - New block to be mined
    /// * `reward`    - The block reward to be paid on successful PoW
    async fn receive_pre_block(
        &mut self,
        peer: SocketAddr,
        pre_block: BlockHeader,
        reward: TokenAmount,
    ) -> bool {
        if peer != self.compute_address() {
            return false;
        }

        let new_block = BlockPoWReceived {
            block: pre_block,
            reward,
        };

        let new_b_num = Some(new_block.block.b_num);
        let current_b_num = self
            .current_block
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| c.block.b_num);
        if new_b_num <= current_b_num {
            if new_b_num == current_b_num {
                self.process_found_block_pow().await;
            }
            return false;
        }

        self.start_generate_pow_for_current_block(peer, new_block)
            .await;
        true
    }

    /// Verifies the block by checking the transactions using a merkle tree.
    ///
    /// ### Arguments
    ///
    /// * `transactions`     - Vec<String>. transactions used to build the merkle tree
    pub async fn receive_trans_verification(
        &self,
        tx_merkle_verification: Vec<String>,
    ) -> Option<Response> {
        let current_block_info = self.current_block.lock().unwrap().clone().unwrap();
        let merkle_root = current_block_info.block.txs_merkle_root_and_hash.0.clone();
        let mut valid = true;

        if !merkle_root.is_empty() {
            let (mtree, _) = block::build_merkle_tree(&tx_merkle_verification)
                .await
                .unwrap();
            valid = hex::encode(mtree.root()) == merkle_root;
        }

        if valid {
            Some(Response {
                success: true,
                reason: "Block is valid",
            })
        } else {
            Some(Response {
                success: false,
                reason: "Block is not valid",
            })
        }
    }

    /// Util function to get a socket address for PID table checks
    fn get_comparison_addr(&self) -> SocketAddr {
        let comparison_port = self.address().port() + 1;
        let mut comparison_addr = self.address();

        comparison_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        comparison_addr.set_port(comparison_port);

        comparison_addr
    }

    /// Process the found PoW sending it to the related peer and logging errors
    pub async fn process_found_block_pow(&mut self) -> bool {
        let BlockPoWInfo {
            peer,
            start_time,
            header:
                BlockHeader {
                    b_num,
                    nonce_and_mining_tx_hash: (nonce, coinbase_hash),
                    ..
                },
            coinbase,
            ..
        } = match self.mining_block_task.completed_result() {
            Some(Ok(v)) => v.clone(),
            Some(Err(e)) => {
                error!("process_found_block_pow PoW {:?}", e);
                return false;
            }
            None => {
                trace!("process_found_block_pow PoW Not ready yet");
                return false;
            }
        };

        if let Ok(elapsed) = start_time.elapsed() {
            debug!("Found block in {}ms", elapsed.as_millis());
        }

        if let Err(e) = self.send_pow(peer, b_num, nonce, coinbase.clone()).await {
            error!("process_found_block_pow PoW {:?}", e);
            return false;
        }

        let coinbase = (coinbase_hash, coinbase);
        self.current_coinbase = store_last_coinbase(&self.wallet_db, Some(coinbase)).await;
        true
    }

    /// Sends PoW to a compute node.
    ///
    /// ### Arguments
    ///
    /// * `peer`   - Socket address of recipient
    /// * `nonce`   - sequence number of a block in Vec<u8>
    /// * `coinbase`   - Transaction object
    pub async fn send_pow(
        &mut self,
        peer: SocketAddr,
        block_num: u64,
        nonce: Vec<u8>,
        coinbase: Transaction,
    ) -> Result<()> {
        self.node
            .send(
                peer,
                ComputeRequest::SendPoW {
                    block_num,
                    nonce,
                    coinbase,
                },
            )
            .await?;
        Ok(())
    }

    /// Process the found Pow sending it to the related peer and logging errors
    pub async fn process_found_partition_pow(&mut self) -> bool {
        let (partition_entry, p_info, peer) = match self.mining_partition_task.completed_result() {
            Some(Ok((e, p_info, p))) => (e.clone(), *p_info, *p),
            Some(Err(e)) => {
                error!("process_found_partition_pow PoW {:?}", e);
                return false;
            }
            None => {
                trace!("process_found_partition_pow PoW Not ready yet");
                return false;
            }
        };

        if let Err(e) = self.send_partition_pow(peer, p_info, partition_entry).await {
            error!("process_found_partition_pow PoW {:?}", e);
            return false;
        }

        true
    }

    /// Sends the light partition PoW to a compute node
    ///
    /// ### Arguments
    ///
    /// * `peer`   - Socket address of recipient/peer
    /// * `partition_entry`   - partition ProofOfWork being sent
    pub async fn send_partition_pow(
        &mut self,
        peer: SocketAddr,
        pow_info: PowInfo,
        partition_entry: ProofOfWork,
    ) -> Result<()> {
        self.node
            .send(
                peer,
                ComputeRequest::SendPartitionEntry {
                    pow_info,
                    partition_entry,
                },
            )
            .await?;
        Ok(())
    }

    /// Sends a request to partition to a Compute node
    pub async fn send_partition_request(&mut self) -> Result<()> {
        let peer_span = error_span!("sending partition participation request");
        self.node
            .send(self.compute_addr, ComputeRequest::SendPartitionRequest {})
            .instrument(peer_span)
            .await?;

        Ok(())
    }

    /// Check if block found include our wining mining tx
    fn is_current_coinbase_found(&self, win_coinbases: &[String]) -> bool {
        if let Some((tx_hash, _)) = &self.current_coinbase {
            win_coinbases.contains(tx_hash)
        } else {
            false
        }
    }

    /// Commit our winning mining tx to wallet
    async fn commit_found_coinbase(&mut self) {
        self.current_payment_address = Some(generate_mining_address(&self.wallet_db).await);
        let (hash, transaction) = std::mem::replace(
            &mut self.current_coinbase,
            store_last_coinbase(&self.wallet_db, None).await,
        )
        .unwrap();

        let payments = get_paiments_for_wallet(Some((&hash, &transaction)).into_iter());

        self.wallet_db
            .save_usable_payments_to_wallet(payments)
            .await
            .unwrap();
    }

    /// Generates a valid PoW for a block specifically
    /// TODO: Update the numbers used for reward and block time
    /// * `peer`      - Peer to send PoW to
    /// * `new_block` - Block for PoW
    pub async fn start_generate_pow_for_current_block(
        &mut self,
        peer: SocketAddr,
        new_block: BlockPoWReceived,
    ) {
        let b_num = new_block.block.b_num;
        let current_payment_address = self.current_payment_address.clone().unwrap();

        let mining_tx = construct_coinbase_tx(b_num, new_block.reward, current_payment_address);
        let mining_tx_hash = construct_tx_hash(&mining_tx);

        self.mining_block_task = {
            let header = apply_mining_tx(new_block.block.clone(), Vec::new(), mining_tx_hash);
            let start_time = SystemTime::now();
            RunningTaskOrResult::Running(Self::generate_pow_for_block(BlockPoWInfo {
                peer,
                start_time,
                header,
                coinbase: mining_tx,
            }))
        };
        let mut current_block = self.current_block.lock().unwrap();
        *current_block = Some(new_block);
    }

    /// Generates and returns the nonce of a block.active_raft
    /// Validates the POW using the block, hash and nonce
    ///
    /// ### Arguments
    ///
    /// * `info`      - Block Proof of work info
    fn generate_pow_for_block(mut info: BlockPoWInfo) -> task::JoinHandle<BlockPoWInfo> {
        task::spawn_blocking(move || {
            info.header = generate_pow_for_block(info.header);
            info
        })
    }

    /// Generates a valid Partition PoW
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Peer to send PoW to
    /// * `rand_num` - random num for PoW
    pub async fn start_generate_partition_pow(
        &mut self,
        peer: SocketAddr,
        pow_info: PowInfo,
        rand_num: Vec<u8>,
    ) {
        let address_proof = format_parition_pow_address(self.address());

        self.wait_partition_task = true;
        self.mining_partition_task = RunningTaskOrResult::Running(utils::generate_pow_for_address(
            peer,
            pow_info,
            address_proof,
            Some(rand_num.clone()),
        ));
        self.rand_num = rand_num;
    }

    /// Returns the last PoW.
    pub fn last_pow(&self) -> &Option<ProofOfWork> {
        &self.last_pow
    }

    // Get the wallet db
    pub fn get_wallet_db(&self) -> &WalletDb {
        &self.wallet_db
    }

    /// Load and apply the local database to our state
    async fn load_local_db(mut self) -> Result<Self> {
        self.current_coinbase = if let Some(cb) = load_last_coinbase(&self.wallet_db).await? {
            debug!("load_local_db: current_coinbase {:?}", cb);
            Some(cb)
        } else {
            None
        };

        self.current_payment_address =
            if let Some(addr) = load_mining_address(&self.wallet_db).await? {
                debug!("load_local_db: current_payment_address {:?}", addr);
                Some(addr)
            } else {
                Some(generate_mining_address(&self.wallet_db).await)
            };

        Ok(self)
    }

    /// Get `Node` member
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

impl MinerInterface for MinerNode {
    fn receive_blockchain_item(
        &mut self,
        peer: SocketAddr,
        key: String,
        item: BlockchainItem,
    ) -> Response {
        self.blockchain_item_received =
            Some((key, item, peer)).filter(|(_, i, _)| !i.data.is_empty());
        Response {
            success: true,
            reason: "Blockchain item received",
        }
    }
}

/// Load mining address from wallet
async fn load_mining_address(wallet_db: &WalletDb) -> Result<Option<String>> {
    Ok(wallet_db
        .get_db_value(MINING_ADDRESS_KEY)
        .await
        .map(|v| deserialize(&v))
        .transpose()?)
}

/// Generate mining address storing it in wallet
async fn generate_mining_address(wallet_db: &WalletDb) -> String {
    let addr: String = wallet_db.generate_payment_address().await.0;
    let ser_addr = serialize(&addr).unwrap();
    wallet_db.set_db_value(MINING_ADDRESS_KEY, ser_addr).await;
    addr
}

/// Load last coinbase from wallet
async fn load_last_coinbase(wallet_db: &WalletDb) -> Result<Option<(String, Transaction)>> {
    Ok(wallet_db
        .get_db_value(LAST_COINBASE_KEY)
        .await
        .map(|v| deserialize(&v))
        .transpose()?)
}

/// Store last coinbase in wallet
async fn store_last_coinbase(
    wallet_db: &WalletDb,
    coinbase: Option<(String, Transaction)>,
) -> Option<(String, Transaction)> {
    if let Some(cb) = &coinbase {
        let ser_cb = serialize(cb).unwrap();
        wallet_db.set_db_value(LAST_COINBASE_KEY, ser_cb).await;
    } else {
        wallet_db.delete_db_value(LAST_COINBASE_KEY).await;
    }
    coinbase
}

/// Log the received blockchain item
fn log_received_blockchain_item(_key: &str, item: &BlockchainItem, _peer: &SocketAddr) {
    use DeserializedBlockchainItem::*;
    match DeserializedBlockchainItem::from_item(item) {
        CurrentBlock(b, b_num, tx_len) => info!(
            "Successfully received blockchain item: b_num = {}({}), tx_len = {}, previous_hash = {:?}",
            b.block.header.b_num, b.block.header.b_num == b_num, tx_len, b.block.header.previous_hash
        ),
        CurrentTx(tx, b_num, tx_num) => info!(
            "Successfully received blockchain item: b_num = {}, tx_num = {}, tx_in={}, tx_out={}",
            b_num,
            tx_num,
            tx.inputs.len(),
            tx.outputs.len()
        ),
        VersionErr(v) => warn!("Unsupported blockchain item version {}", v),
        SerializationErr(e) => warn!("Failed to deserialize blockchain item {:?}", e),
    }
}
