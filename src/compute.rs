use crate::block_pipeline::{MiningPipelineItem, MiningPipelineStatus, Participants};
use crate::comms_handler::{CommsError, Event, TcpTlsConfig};
use crate::compute_raft::{CommittedItem, ComputeRaft};
use crate::configurations::{ComputeNodeConfig, ExtraNodeParams, TlsPrivateInfo};
use crate::constants::{DB_PATH, PEER_LIMIT};
use crate::db_utils::{self, SimpleDb, SimpleDbSpec};
use crate::hash_block::HashBlock;
use crate::interfaces::{
    BlockStoredInfo, CommonBlockInfo, ComputeApi, ComputeApiRequest, ComputeInterface,
    ComputeRequest, Contract, DruidDroplet, DruidPool, MineRequest, MinedBlock,
    MinedBlockExtraInfo, NodeType, ProofOfWork, Response, StorageRequest, UserRequest,
    UtxoFetchType, UtxoSet, WinningPoWInfo,
};
use crate::raft::RaftCommit;
use crate::threaded_call::{ThreadedCallChannel, ThreadedCallSender};
use crate::tracked_utxo::TrackedUtxoSet;
use crate::utils::{
    check_druid_participants, concat_merkle_coinbase, create_receipt_asset_tx_from_sig,
    format_parition_pow_address, generate_pow_random_num, serialize_hashblock_for_pow, to_api_keys,
    validate_pow_block, validate_pow_for_address, ApiKeys, LocalEvent, LocalEventChannel,
    LocalEventSender, ResponseResult,
};
use crate::Node;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use naom::utils::druid_utils::druid_expectations_are_met;
use naom::utils::script_utils::{tx_has_valid_create_script, tx_is_valid};
use naom::utils::transaction_utils::construct_tx_hash;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::{
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::task;
use tracing::{debug, error, error_span, info, trace, warn};
use tracing_futures::Instrument;

/// Key for local miner list
pub const REQUEST_LIST_KEY: &str = "RequestListKey";
pub const USER_NOTIFY_LIST_KEY: &str = "UserNotifyListKey";
pub const POW_RANDOM_NUM_KEY: &str = "PowRandomNumKey";
pub const RAFT_KEY_RUN: &str = "RaftKeyRun";

/// Database columns
pub const DB_COL_INTERNAL: &str = "internal";
pub const DB_COL_LOCAL_TXS: &str = "local_transactions";

pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
    db_path: DB_PATH,
    suffix: ".compute",
    columns: &[DB_COL_INTERNAL, DB_COL_LOCAL_TXS],
};

/// Result wrapper for compute errors
pub type Result<T> = std::result::Result<T, ComputeError>;

#[derive(Debug)]
pub enum ComputeError {
    ConfigError(&'static str),
    Network(CommsError),
    Serialization(bincode::Error),
    AsyncTask(task::JoinError),
}

impl fmt::Display for ComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {}", err),
            Self::Network(err) => write!(f, "Network error: {}", err),
            Self::AsyncTask(err) => write!(f, "Async task error: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl Error for ComputeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::Network(ref e) => Some(e),
            Self::AsyncTask(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
        }
    }
}

impl From<CommsError> for ComputeError {
    fn from(other: CommsError) -> Self {
        Self::Network(other)
    }
}

impl From<bincode::Error> for ComputeError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

impl From<task::JoinError> for ComputeError {
    fn from(other: task::JoinError) -> Self {
        Self::AsyncTask(other)
    }
}

#[derive(Debug)]
pub struct ComputeNode {
    node: Node,
    node_raft: ComputeRaft,
    db: SimpleDb,
    local_events: LocalEventChannel,
    threaded_calls: ThreadedCallChannel<dyn ComputeApi>,
    jurisdiction: String,
    current_mined_block: Option<MinedBlock>,
    druid_pool: DruidPool,
    current_random_num: Vec<u8>,
    partition_full_size: usize,
    request_list: BTreeSet<SocketAddr>,
    request_list_first_flood: Option<usize>,
    storage_addr: SocketAddr,
    sanction_list: Vec<String>,
    user_notification_list: BTreeSet<SocketAddr>,
    coordinated_shutdown: u64,
    shutdown_group: BTreeSet<SocketAddr>,
    fetched_utxo_set: Option<(SocketAddr, UtxoSet)>,
    api_info: (SocketAddr, Option<TlsPrivateInfo>, ApiKeys, Node),
}

impl ComputeNode {
    /// Generates a new compute node instance
    /// ### Arguments
    /// * `config` - ComputeNodeConfig for the current compute node containing compute nodes and storage nodes
    /// * `extra`  - additional parameter for construction
    pub async fn new(config: ComputeNodeConfig, mut extra: ExtraNodeParams) -> Result<Self> {
        let addr = config
            .compute_nodes
            .get(config.compute_node_idx)
            .ok_or(ComputeError::ConfigError("Invalid compute index"))?
            .address;
        let storage_addr = config
            .storage_nodes
            .get(config.compute_node_idx)
            .ok_or(ComputeError::ConfigError("Invalid storage index"))?
            .address;
        let tcp_tls_config = TcpTlsConfig::from_tls_spec(addr, &config.tls_config)?;
        let api_addr = SocketAddr::new(addr.ip(), config.compute_api_port);
        let api_tls_info = config
            .compute_api_use_tls
            .then(|| tcp_tls_config.clone_private_info());

        let node = Node::new(&tcp_tls_config, PEER_LIMIT, NodeType::Compute).await?;
        let node_raft = ComputeRaft::new(&config, extra.raft_db.take()).await;

        let db = db_utils::new_db(config.compute_db_mode, &DB_SPEC, extra.db.take());
        let shutdown_group = {
            let storage = std::iter::once(storage_addr);
            let raft_peers = node_raft.raft_peer_addrs().copied();
            raft_peers.chain(storage).collect()
        };

        let api_keys = to_api_keys(config.api_keys.clone());
        let api_info = (api_addr, api_tls_info, api_keys, node.clone());

        Ok(ComputeNode {
            node,
            node_raft,
            db,
            local_events: Default::default(),
            threaded_calls: Default::default(),
            current_mined_block: None,
            druid_pool: Default::default(),
            current_random_num: Default::default(),
            request_list: Default::default(),
            sanction_list: config.sanction_list,
            jurisdiction: config.jurisdiction,
            request_list_first_flood: Some(config.compute_minimum_miner_pool_len),
            partition_full_size: config.compute_partition_full_size,
            storage_addr,
            user_notification_list: Default::default(),
            coordinated_shutdown: u64::MAX,
            shutdown_group,
            api_info,
            fetched_utxo_set: None,
        }
        .load_local_db()?)
    }

    /// Returns the compute node's public endpoint.
    pub fn address(&self) -> SocketAddr {
        self.node.address()
    }

    /// Get the node's mined block if any
    pub fn get_current_mined_block(&self) -> &Option<MinedBlock> {
        &self.current_mined_block
    }

    /// Injects a new event into compute node
    pub fn inject_next_event(
        &self,
        from_peer_addr: SocketAddr,
        data: impl Serialize,
    ) -> Result<()> {
        Ok(self.node.inject_next_event(from_peer_addr, data)?)
    }

    /// Connect info for peers on the network.
    pub fn connect_info_peers(&self) -> (Node, Vec<SocketAddr>, Vec<SocketAddr>) {
        let storage = Some(self.storage_addr);
        let to_connect = self.node_raft.raft_peer_to_connect().chain(storage.iter());
        let expect_connect = self.node_raft.raft_peer_addrs().chain(storage.iter());
        (
            self.node.clone(),
            to_connect.copied().collect(),
            expect_connect.copied().collect(),
        )
    }

    /// Send initial requests:
    /// - None
    pub async fn send_startup_requests(&mut self) -> Result<()> {
        Ok(())
    }

    /// Local event channel.
    pub fn local_event_tx(&self) -> &LocalEventSender {
        &self.local_events.tx
    }

    /// Threaded call channel.
    pub fn threaded_call_tx(&self) -> &ThreadedCallSender<dyn ComputeApi> {
        &self.threaded_calls.tx
    }

    /// The current utxo_set including block being mined and previous block mining txs.
    pub fn get_committed_utxo_set(&self) -> &UtxoSet {
        self.node_raft.get_committed_utxo_set()
    }

    pub fn get_committed_utxo_set_to_send(&self) -> UtxoSet {
        self.node_raft.get_committed_utxo_set().clone()
    }

    pub fn get_committed_utxo_tracked_set_to_send(&self) -> TrackedUtxoSet {
        self.node_raft.get_committed_utxo_tracked_set().clone()
    }

    /// The current tx_pool that will be used to generate next block
    pub fn get_committed_tx_pool(&self) -> &BTreeMap<String, Transaction> {
        self.node_raft.get_committed_tx_pool()
    }

    /// The current tx_druid_pool that will be used to generate next block
    pub fn get_committed_tx_druid_pool(&self) -> &Vec<BTreeMap<String, Transaction>> {
        self.node_raft.get_committed_tx_druid_pool()
    }

    /// The current local DRUID transactions present in the `local_tx_druid_pool`
    pub fn get_local_druid_pool(&self) -> &Vec<BTreeMap<String, Transaction>> {
        self.node_raft.get_local_tx_druid_pool()
    }

    // The current druid pool of pending DDE transactions
    pub fn get_pending_druid_pool(&self) -> &DruidPool {
        &self.druid_pool
    }

    pub fn get_request_list(&self) -> &BTreeSet<SocketAddr> {
        &self.request_list
    }

    /// Return the raft loop to spawn in it own task.
    pub fn raft_loop(&self) -> impl Future<Output = ()> {
        self.node_raft.raft_loop()
    }

    /// Signal to the raft loop to complete
    pub async fn close_raft_loop(&mut self) {
        self.node_raft.close_raft_loop().await
    }

    /// Extract persistent dbs
    pub async fn take_closed_extra_params(&mut self) -> ExtraNodeParams {
        let raft_db = self.node_raft.take_closed_persistent_store().await;
        ExtraNodeParams {
            db: self.db.take().in_memory(),
            raft_db: raft_db.in_memory(),
            ..Default::default()
        }
    }

    /// Info needed to run the API point.
    pub fn api_inputs(&self) -> (SocketAddr, Option<TlsPrivateInfo>, ApiKeys, Node) {
        self.api_info.clone()
    }

    /// Validate and get DDE transactions that are ready to be added to the RAFT
    ///
    /// ### Arguments
    ///
    /// * `transactions` - DDE transactions to process
    pub fn validate_dde_txs(
        &mut self,
        transactions: BTreeMap<String, Transaction>,
    ) -> Vec<(bool, BTreeMap<String, Transaction>)> {
        let mut ready_txs = Vec::new();
        for (tx_hash, tx) in transactions {
            if let Some(druid_info) = tx.druid_info.clone() {
                let druid = druid_info.druid;
                let participants = druid_info.participants;

                let droplet = self
                    .druid_pool
                    .entry(druid.clone())
                    .or_insert_with(|| DruidDroplet::new(participants));

                droplet.txs.insert(tx_hash.clone(), tx);

                // Execute the DDE tx if it's ready
                if droplet.txs.len() == droplet.participants {
                    let valid = druid_expectations_are_met(&druid, droplet.txs.values())
                        && check_druid_participants(droplet);
                    ready_txs.push((valid, droplet.txs.clone()));
                    // TODO: Implement time-based removal?
                    self.druid_pool.remove(&druid);
                }
            }
        }
        ready_txs
    }

    /// Returns the mining block from the node_raft
    pub fn get_mining_block(&self) -> &Option<Block> {
        self.node_raft.get_mining_block()
    }

    /// Get mining participants selected
    pub fn get_mining_participants(&self) -> &Participants {
        self.node_raft.get_mining_participants()
    }

    ///Returns last generated block number from the node_raft
    pub fn get_committed_current_block_num(&self) -> Option<u64> {
        self.node_raft.get_committed_current_block_num()
    }

    /// Process block generation in single step (Test only)
    /// ### Arguments
    /// * `block`    - Block to be set to commited mining block
    /// * `block_tx` - BTreeMap of the block transactions
    pub fn test_skip_block_gen(&mut self, block: Block, block_tx: BTreeMap<String, Transaction>) {
        self.node_raft.test_skip_block_gen(block, block_tx)
    }

    /// Process all the mining phase in a single step (Test only)
    /// ### Arguments
    /// * `winning_pow`    - Address nad PoW for the winner to use
    pub fn test_skip_mining(&mut self, winning_pow: (SocketAddr, WinningPoWInfo)) {
        self.node_raft.test_skip_mining(winning_pow);
        self.mining_block_mined();
    }

    /// Gets a decremented socket address of peer for storage
    /// ### Arguments
    /// * `address`    - Address to decrement
    fn get_storage_address(&self, address: SocketAddr) -> SocketAddr {
        let mut storage_address = address;
        storage_address.set_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        storage_address.set_port(address.port() - 1);

        storage_address
    }

    /// Return closure use to validate a transaction
    fn transactions_validator(&self) -> impl Fn(&Transaction) -> bool + '_ {
        let utxo_set = self.node_raft.get_committed_utxo_set();
        let lock_expired = self
            .node_raft
            .get_committed_current_block_num()
            .unwrap_or_default();
        let sanction_list = &self.sanction_list;

        move |tx| {
            if tx.is_create_tx() {
                return tx_has_valid_create_script(
                    &tx.inputs[0].script_signature,
                    &tx.outputs[0].value,
                );
            }

            !tx.is_coinbase()
                && tx_is_valid(tx, |v| {
                    utxo_set
                        .get(v)
                        .filter(|_| !sanction_list.contains(&v.t_hash))
                        .filter(|tx_out| lock_expired >= tx_out.locktime)
                })
        }
    }

    /// Sends the latest block to storage
    pub async fn send_block_to_storage(&mut self) -> Result<()> {
        let mined_block = self.current_mined_block.clone();
        self.node
            .send(self.storage_addr, StorageRequest::SendBlock { mined_block })
            .await?;
        Ok(())
    }

    /// Floods all peers with a PoW for UnicornShard creation
    /// TODO: Add in comms handling for sending and receiving requests
    /// ### Arguments
    ///
    /// * `address` - Address of the contributing node
    /// * `pow`     - PoW to flood
    pub fn flood_pow_to_peers(&self, _address: SocketAddr, _pow: &[u8]) {
        error!("Flooding PoW to peers not implemented");
    }

    /// Floods all peers with a PoW commit for UnicornShard creation
    /// TODO: Add in comms handling for sending and receiving requests
    ///
    /// ### Arguments
    ///
    /// * `address` - Address of the contributing node
    /// * `_commit` - POW reference (&ProofOfWork)
    pub fn flood_commit_to_peers(&self, _address: SocketAddr, _commit: &ProofOfWork) {
        error!("Flooding commit to peers not implemented");
    }

    ///Sends the requested UTXO set to the user that requested it.
    pub async fn send_fetched_utxo_set(&mut self) -> Result<()> {
        if let Some((peer, utxo_set)) = self.fetched_utxo_set.take() {
            self.node
                .send(peer, UserRequest::SendUtxoSet { utxo_set })
                .await?;
        }
        Ok(())
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
                reason: "Received UTXO fetch request",
            }) => {
                if let Err(e) = self.send_fetched_utxo_set().await {
                    error!("Requested UTXO set not sent {:?}", e);
                }
            }
            Ok(Response {
                success: true,
                reason: "Shutdown",
            }) => {
                warn!("Shutdown now");
                return ResponseResult::Exit;
            }
            Ok(Response {
                success: true,
                reason: "Shutdown pending",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Start coordinated shutdown",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Received partition request successfully",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Received first full partition request",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Received PoW successfully",
            }) => {
                debug!("Proposing winning PoW entry");
            }
            Ok(Response {
                success: true,
                reason: "Winning PoW intake open",
            }) => {
                self.flood_block_to_partition().await.unwrap();
                self.flood_block_to_users().await.unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Pipeline halted",
            }) => {
                info!("Send Block to storage");
                debug!("CURRENT MINED BLOCK: {:?}", self.current_mined_block);
                if let Err(e) = self.send_block_to_storage().await {
                    error!("Block not sent to storage {:?}", e);
                }
            }
            Ok(Response {
                success: true,
                reason: "Transactions added to tx pool",
            }) => {
                debug!("Transactions received and processed successfully");
            }
            Ok(Response {
                success: true,
                reason: "First Block committed",
            }) => {
                debug!("First Block ready to mine: {:?}", self.get_mining_block());
                self.flood_rand_num_to_requesters().await.unwrap();
                self.flood_block_to_users().await.unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Block committed",
            }) => {
                debug!("Block ready to mine: {:?}", self.get_mining_block());
                self.flood_rand_num_to_requesters().await.unwrap();
                self.flood_block_to_users().await.unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Block shutdown",
            }) => {
                debug!("Block shutdown (not ready to mine)");
                self.flood_closing_events().await.unwrap();
            }
            Ok(Response {
                success: true,
                reason: "Transactions committed",
            }) => {
                debug!("Transactions ready to be used in next block");
            }
            Ok(Response {
                success: true,
                reason: "Received block stored",
            }) => {
                info!("Block info received from storage: ready to generate block");
            }
            Ok(Response {
                success: true,
                reason: "Snapshot applied",
            }) => {
                warn!("Snapshot applied");
            }
            Ok(Response {
                success: true,
                reason: "Received block notification",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Partition PoW received successfully",
            }) => {}
            Ok(Response {
                success: false,
                reason: "Partition list complete",
            }) => {}
            Ok(Response {
                success: false,
                reason: "PoW received is invalid",
            }) => {}
            Ok(Response {
                success: false,
                reason: "Not block currently mined",
            }) => {}
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
            let ready = !self.node_raft.need_initial_state();
            let shutdown = self.node_raft.is_shutdown_commit_processed();

            // State machines are not keept between iterations or calls.
            // All selection calls (between = and =>), need to be dropable
            // i.e they should only await a channel.
            tokio::select! {
                event = self.node.next_event(), if ready => {
                    trace!("handle_next_event evt {:?}", event);
                    if let res @ Some(_) = self.handle_event(event?).await.transpose() {
                        return res;
                    }
                }
                Some(commit_data) = self.node_raft.next_commit(), if !shutdown => {
                    trace!("handle_next_event commit {:?}", commit_data);
                    if let res @ Some(_) = self.handle_committed_data(commit_data).await {
                        return res;
                    }
                }
                Some((addr, msg)) = self.node_raft.next_msg(), if ready => {
                    trace!("handle_next_event msg {:?}: {:?}", addr, msg);
                    match self.node.send(
                        addr,
                        ComputeRequest::SendRaftCmd(msg)).await {
                            Err(e) => info!("Msg not sent to {}, from {}: {:?}", addr, self.address(), e),
                            Ok(()) => trace!("Msg sent to {}, from {}", addr, self.address()),
                        };
                }
                _ = self.node_raft.timeout_propose_transactions(), if ready && !shutdown => {
                    trace!("handle_next_event timeout transactions");
                    self.node_raft.propose_local_transactions_at_timeout().await;
                    self.node_raft.propose_local_druid_transactions().await;
                }
                _ = self.node_raft.timeout_propose_mining_event(), if ready && !shutdown => {
                    trace!("handle_next_event timeout mining pipeline");
                    if !self.node_raft.propose_mining_event_at_timeout().await {
                        self.node_raft.re_propose_uncommitted_current_b_num().await;
                        self.resend_trigger_message().await;
                    }
                }
                Some(event) = self.local_events.rx.recv(), if ready => {
                    if let Some(res) = self.handle_local_event(event) {
                        return Some(Ok(res));
                    }
                }
                Some(f) = self.threaded_calls.rx.recv(), if ready => {
                    f(self);
                }
                reason = &mut *exit => return Some(Ok(Response {
                    success: true,
                    reason,
                }))
            }
        }
    }

    /// Handle commit data
    ///
    /// ### Arguments
    ///
    /// * `commit_data` - Commit to process.
    async fn handle_committed_data(&mut self, commit_data: RaftCommit) -> Option<Result<Response>> {
        match self.node_raft.received_commit(commit_data).await {
            Some(CommittedItem::FirstBlock) => {
                self.reset_mining_block_process();
                Some(Ok(Response {
                    success: true,
                    reason: "First Block committed",
                }))
            }
            Some(CommittedItem::Block) => {
                self.reset_mining_block_process();
                Some(Ok(Response {
                    success: true,
                    reason: "Block committed",
                }))
            }
            Some(CommittedItem::BlockShutdown) => {
                self.reset_mining_block_process();
                Some(Ok(Response {
                    success: true,
                    reason: "Block shutdown",
                }))
            }
            Some(CommittedItem::StartPhasePowIntake) => Some(Ok(Response {
                success: true,
                reason: "Winning PoW intake open",
            })),
            Some(CommittedItem::StartPhaseHalted) => {
                self.mining_block_mined();
                Some(Ok(Response {
                    success: true,
                    reason: "Pipeline halted",
                }))
            }
            Some(CommittedItem::Transactions) => {
                delete_local_transactions(
                    &mut self.db,
                    &self.node_raft.take_local_tx_hash_last_commited(),
                );
                Some(Ok(Response {
                    success: true,
                    reason: "Transactions committed",
                }))
            }
            Some(CommittedItem::Snapshot) => Some(Ok(Response {
                success: true,
                reason: "Snapshot applied",
            })),
            None => None,
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
            LocalEvent::CoordinatedShutdown(shutdown) => {
                self.coordinated_shutdown = shutdown;
                Some(Response {
                    success: true,
                    reason: "Start coordinated shutdown",
                })
            }
            LocalEvent::Ignore => None,
        }
    }

    /// Haddles errors or events that are passed
    ///
    /// ### Arguments
    ///
    /// * `event` - Event holding the frame to be handled
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
    /// ### Arguments
    ///
    /// * `peer` - Sending peer's socket address
    /// * 'frame' - Bytes representing the new frame.
    async fn handle_new_frame(
        &mut self,
        peer: SocketAddr,
        frame: Bytes,
    ) -> Result<Option<Response>> {
        let req = deserialize::<ComputeRequest>(&frame).map_err(|error| {
            warn!(?error, "frame-deserialize");
            error
        })?;

        let req_span = error_span!("request", ?req);
        let response = self.handle_request(peer, req).instrument(req_span).await;
        debug!(?response, ?peer, "response");

        Ok(response)
    }

    /// Handles a compute request.
    /// ### Arguments
    ///
    /// * `peer` - Sending peer's socket address
    /// * 'req' - ComputeRequest object holding the request
    async fn handle_request(&mut self, peer: SocketAddr, req: ComputeRequest) -> Option<Response> {
        use ComputeRequest::*;
        trace!("handle_request");

        match req {
            ComputeApi(req) => self.handle_api_request(peer, req).await,
            SendUtxoRequest { address_list } => Some(self.fetch_utxo_set(peer, address_list)),
            SendBlockStored(info) => self.receive_block_stored(peer, info).await,
            SendPoW {
                block_num,
                nonce,
                coinbase,
            } => Some(self.receive_pow(peer, block_num, nonce, coinbase).await),
            SendPartitionEntry { partition_entry } => {
                Some(self.receive_partition_entry(peer, partition_entry).await)
            }
            SendTransactions { transactions } => Some(self.receive_transactions(transactions)),
            SendUserBlockNotificationRequest => {
                Some(self.receive_block_user_notification_request(peer))
            }
            SendPartitionRequest => Some(self.receive_partition_request(peer).await),
            Closing => self.receive_closing(peer),
            SendRaftCmd(msg) => {
                self.node_raft.received_message(msg).await;
                None
            }
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
        req: ComputeApiRequest,
    ) -> Option<Response> {
        use ComputeApiRequest::*;

        if peer != self.address() {
            // Do not process if not internal request
            return None;
        }

        match req {
            SendCreateReceiptRequest {
                receipt_amount,
                script_public_key,
                public_key,
                signature,
            } => {
                self.create_receipt_asset_tx(
                    receipt_amount,
                    script_public_key,
                    public_key,
                    signature,
                )
                .await
            }
            SendTransactions { transactions } => Some(self.receive_transactions(transactions)),
        }
    }

    /// Handles the receipt of closing event
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    fn receive_closing(&mut self, peer: SocketAddr) -> Option<Response> {
        if !self.shutdown_group.remove(&peer) {
            return None;
        }

        if !self.shutdown_group.is_empty() {
            return Some(Response {
                success: true,
                reason: "Shutdown pending",
            });
        }

        Some(Response {
            success: true,
            reason: "Shutdown",
        })
    }

    /// Receive a block notification request from a user node
    /// ### Arguments
    ///
    /// * `peer` - Sending peer's socket address
    fn receive_block_user_notification_request(&mut self, peer: SocketAddr) -> Response {
        self.user_notification_list.insert(peer);
        self.db
            .put_cf(
                DB_COL_INTERNAL,
                USER_NOTIFY_LIST_KEY,
                &serialize(&self.user_notification_list).unwrap(),
            )
            .unwrap();

        Response {
            success: true,
            reason: "Received block notification",
        }
    }

    /// Receive a partition request from a miner node
    /// TODO: This may need to be part of the ComputeInterface depending on key agreement
    /// ### Arguments
    ///
    /// * `peer` - Sending peer's socket address
    async fn receive_partition_request(&mut self, peer: SocketAddr) -> Response {
        self.request_list.insert(peer);
        self.db
            .put_cf(
                DB_COL_INTERNAL,
                REQUEST_LIST_KEY,
                &serialize(&self.request_list).unwrap(),
            )
            .unwrap();
        if self.request_list_first_flood == Some(self.request_list.len()) {
            self.request_list_first_flood = None;
            self.node_raft.propose_initial_item().await;
            Response {
                success: true,
                reason: "Received first full partition request",
            }
        } else {
            Response {
                success: true,
                reason: "Received partition request successfully",
            }
        }
    }

    /// Receives the light POW for partition inclusion
    /// ### Arguments
    ///
    /// * `peer` - Sending peer's socket address
    /// * 'partition_entry' - ProofOfWork object for the partition entry being recieved.
    async fn receive_partition_entry(
        &mut self,
        peer: SocketAddr,
        partition_entry: ProofOfWork,
    ) -> Response {
        if self.node_raft.get_mining_pipeline_status() != &MiningPipelineStatus::ParticipantIntake {
            return Response {
                success: false,
                reason: "Partition list complete",
            };
        }

        let valid_pow = format_parition_pow_address(peer) == partition_entry.address
            && validate_pow_for_address(&partition_entry, &Some(&self.current_random_num));

        if !valid_pow {
            return Response {
                success: false,
                reason: "PoW received is invalid",
            };
        }

        self.node_raft
            .propose_mining_pipeline_item(MiningPipelineItem::MiningParticipant(peer))
            .await;

        Response {
            success: true,
            reason: "Partition PoW received successfully",
        }
    }

    /// Floods the closing event to everyone
    pub async fn flood_closing_events(&mut self) -> Result<()> {
        self.node
            .send_to_all(Some(self.storage_addr).into_iter(), StorageRequest::Closing)
            .await
            .unwrap();

        self.node
            .send_to_all(
                self.node_raft.raft_peer_addrs().copied(),
                ComputeRequest::Closing,
            )
            .await
            .unwrap();

        self.node
            .send_to_all(self.request_list.iter().copied(), MineRequest::Closing)
            .await
            .unwrap();

        self.node
            .send_to_all(
                self.user_notification_list.iter().copied(),
                UserRequest::Closing,
            )
            .await
            .unwrap();

        Ok(())
    }

    /// Floods the random number to everyone who requested
    pub async fn flood_rand_num_to_requesters(&mut self) -> Result<()> {
        let rnum = self.current_random_num.clone();
        let win_coinbases = self.node_raft.get_last_mining_transaction_hashes().clone();
        info!(
            "RANDOM NUMBER IN COMPUTE: {:?}, (mined:{})",
            rnum,
            win_coinbases.len()
        );

        self.node
            .send_to_all(
                self.request_list.iter().copied(),
                MineRequest::SendRandomNum {
                    rnum,
                    win_coinbases,
                },
            )
            .await
            .unwrap();

        Ok(())
    }

    /// Floods the current block to participants for mining
    pub async fn flood_block_to_partition(&mut self) -> Result<()> {
        debug!("BLOCK TO SEND: {:?}", self.node_raft.get_mining_block());
        let block: &Block = self.node_raft.get_mining_block().as_ref().unwrap();
        let header = block.header.clone();
        let unicorn = header.previous_hash.unwrap_or_default();
        let hashblock =
            HashBlock::new_for_mining(unicorn, block.header.merkle_root_hash.clone(), header.b_num);
        let block = serialize_hashblock_for_pow(&hashblock);
        let reward = self.node_raft.get_current_reward();

        self.node
            .send_to_all(
                self.node_raft.get_mining_participants_iter(),
                MineRequest::SendBlock {
                    block,
                    reward: *reward,
                },
            )
            .await
            .unwrap();

        Ok(())
    }

    /// Floods the current block to participants for mining
    pub async fn flood_transactions_to_partition(&mut self) -> Result<()> {
        let block: &Block = self.node_raft.get_mining_block().as_ref().unwrap();
        let tx_merkle_verification = block.transactions.clone();

        self.node
            .send_to_all(
                self.node_raft.get_mining_participants_iter(),
                MineRequest::SendTransactions {
                    tx_merkle_verification,
                },
            )
            .await
            .unwrap();

        Ok(())
    }

    /// Floods the current block to user listening for updates
    pub async fn flood_block_to_users(&mut self) -> Result<()> {
        let block: Block = self.node_raft.get_mining_block().clone().unwrap();

        self.node
            .send_to_all(
                self.user_notification_list.iter().copied(),
                UserRequest::BlockMining { block },
            )
            .await
            .unwrap();

        Ok(())
    }

    /// Logs the winner of the block and changes the current block to a new block to be mined
    pub fn mining_block_mined(&mut self) {
        let (block, block_txs) = self.node_raft.take_mining_block().unwrap();
        let (_, winning_pow) = self.node_raft.get_winning_miner().clone().unwrap();
        let unicorn = self.node_raft.get_current_unicorn().clone();

        let extra_info = MinedBlockExtraInfo {
            shutdown: self.coordinated_shutdown <= block.header.b_num,
        };
        let pow = WinningPoWInfo {
            nonce: winning_pow.nonce,
            mining_tx: winning_pow.mining_tx,
            p_value: winning_pow.p_value,
            d_value: winning_pow.d_value,
        };
        let common = CommonBlockInfo {
            block,
            block_txs,
            pow,
            unicorn: unicorn.unicorn,
            unicorn_witness: unicorn.witness,
        };
        self.current_mined_block = Some(MinedBlock { common, extra_info });
    }

    /// Reset the mining block processing to allow a new block.
    fn reset_mining_block_process(&mut self) {
        self.current_random_num = generate_pow_random_num();
        self.db
            .put_cf(
                DB_COL_INTERNAL,
                POW_RANDOM_NUM_KEY,
                &self.current_random_num,
            )
            .unwrap();
        self.current_mined_block = None;
    }

    /// Load and apply the local database to our state
    fn load_local_db(mut self) -> Result<Self> {
        self.request_list = match self.db.get_cf(DB_COL_INTERNAL, REQUEST_LIST_KEY) {
            Ok(Some(list)) => {
                let list = deserialize::<BTreeSet<SocketAddr>>(&list)?;
                debug!("load_local_db: request_list {:?}", list);
                list
            }
            Ok(None) => self.request_list,
            Err(e) => panic!("Error accessing db: {:?}", e),
        };
        if let Some(first) = self.request_list_first_flood {
            if first <= self.request_list.len() {
                self.request_list_first_flood = None;
                self.node_raft.set_initial_proposal_done();
            }
        }

        self.user_notification_list = match self.db.get_cf(DB_COL_INTERNAL, USER_NOTIFY_LIST_KEY) {
            Ok(Some(list)) => {
                let list = deserialize::<BTreeSet<SocketAddr>>(&list)?;
                debug!("load_local_db: user_notification_list {:?}", list);
                list
            }
            Ok(None) => self.user_notification_list,
            Err(e) => panic!("Error accessing db: {:?}", e),
        };

        self.current_random_num = {
            let current_random_num = match self.db.get_cf(DB_COL_INTERNAL, POW_RANDOM_NUM_KEY) {
                Ok(Some(num)) => num,
                Ok(None) => generate_pow_random_num(),
                Err(e) => panic!("Error accessing db: {:?}", e),
            };
            debug!("load_local_db: current_random_num {:?}", current_random_num);
            if let Err(e) = self
                .db
                .put_cf(DB_COL_INTERNAL, POW_RANDOM_NUM_KEY, &current_random_num)
            {
                panic!("Error accessing db: {:?}", e);
            }
            current_random_num
        };

        self.node_raft.set_key_run({
            let key_run = match self.db.get_cf(DB_COL_INTERNAL, RAFT_KEY_RUN) {
                Ok(Some(key_run)) => deserialize::<u64>(&key_run)? + 1,
                Ok(None) => 0,
                Err(e) => panic!("Error accessing db: {:?}", e),
            };
            debug!("load_local_db: key_run update to {:?}", key_run);
            if let Err(e) = self
                .db
                .put_cf(DB_COL_INTERNAL, RAFT_KEY_RUN, &serialize(&key_run)?)
            {
                panic!("Error accessing db: {:?}", e);
            }
            key_run
        });

        self.node_raft
            .append_to_tx_pool(get_local_transactions(&self.db));

        Ok(self)
    }

    /// Recieves a ProofOfWork from miner
    ///
    /// ### Arguments
    ///
    /// * `address`    - Address of miner
    /// * `block_num`  - Block number the PoW is for
    /// * `nonce`      - Sequenc number of the block held in a Vec<u8>
    /// * 'coinbase'   - The transaction object  of the mining
    async fn receive_pow(
        &mut self,
        address: SocketAddr,
        block_num: u64,
        nonce: Vec<u8>,
        coinbase: Transaction,
    ) -> Response {
        let pow_mining_block = (self.node_raft.get_mining_block().as_ref())
            .filter(|b| block_num == b.header.b_num)
            .filter(|_| self.node_raft.get_mining_participants().contains(&address));

        // Check if expected block
        let block_to_check = if let Some(mining_block) = pow_mining_block {
            info!(?address, "Received expected PoW");
            let header = &mining_block.header;
            HashBlock {
                merkle_hash: header.merkle_root_hash.clone(),
                prev_hash: header.previous_hash.clone().unwrap_or_default(),
                nonce: nonce.clone(),
                b_num: header.b_num,
            }
        } else {
            trace!(?address, "Received outdated PoW");
            return Response {
                success: false,
                reason: "Not block currently mined",
            };
        };

        // Check coinbase amount and structure
        let coinbase_amount = self.node_raft.get_current_reward();
        if !coinbase.is_coinbase() || coinbase.outputs[0].value.token_amount() != *coinbase_amount {
            return Response {
                success: false,
                reason: "Coinbase transaction invalid",
            };
        }

        // Perform validation
        let coinbase_hash = construct_tx_hash(&coinbase);
        let merkle_for_pow =
            concat_merkle_coinbase(&block_to_check.merkle_hash, &coinbase_hash).await;
        if !validate_pow_block(&block_to_check.prev_hash, &merkle_for_pow, &nonce) {
            return Response {
                success: false,
                reason: "Invalid PoW for block",
            };
        }

        // TODO: D and P will need to change with keccak prime intro
        let pow_info = WinningPoWInfo {
            nonce,
            mining_tx: (coinbase_hash, coinbase),
            d_value: 0,
            p_value: 0,
        };

        // Propose the received PoW to the block pipeline
        self.node_raft
            .propose_mining_pipeline_item(MiningPipelineItem::WinningPoW(address, pow_info))
            .await;

        Response {
            success: true,
            reason: "Received PoW successfully",
        }
    }

    /// Receives block info from its storage node
    ///
    /// ### Arguments
    ///
    /// * `peer` - Address of the storage peer sending the block
    /// * `BlockStoredInfo` - Infomation about the recieved block
    async fn receive_block_stored(
        &mut self,
        peer: SocketAddr,
        previous_block_info: BlockStoredInfo,
    ) -> Option<Response> {
        if peer != self.storage_addr {
            return Some(Response {
                success: false,
                reason: "Received block stored not from our storage peer",
            });
        }

        if !self
            .node_raft
            .propose_block_with_last_info(previous_block_info)
            .await
        {
            self.node_raft.re_propose_uncommitted_current_b_num().await;
            return None;
        }

        Some(Response {
            success: true,
            reason: "Received block stored",
        })
    }

    /// Re-sends messages triggering the next step in flow
    pub async fn resend_trigger_message(&mut self) {
        match self.node_raft.get_mining_pipeline_status().clone() {
            MiningPipelineStatus::Halted => {
                info!("Resend block to storage");
                if let Err(e) = self.send_block_to_storage().await {
                    error!("Resend block to storage failed {:?}", e);
                }
            }
            MiningPipelineStatus::ParticipantIntake => {
                info!("Resend partition random number to miners");
                if let Err(e) = self.flood_rand_num_to_requesters().await {
                    error!("Resend partition random number to miners failed {:?}", e);
                }
            }
            MiningPipelineStatus::WinningPoWIntake => {
                info!("Resend block to partition miners");
                if let Err(e) = self.flood_block_to_partition().await {
                    error!("Resend block to partition miners failed {:?}", e);
                }
            }
        }
    }

    /// Create a receipt asset transaction from data received
    ///
    /// ### Arguments
    ///
    /// * `receipt_amount`      - Amount of receipt assets
    /// * `script_public_key`   - Public address key
    /// * `public_key`          - Public key
    /// * `signature`           - Signature
    pub async fn create_receipt_asset_tx(
        &mut self,
        receipt_amount: u64,
        script_public_key: String,
        public_key: String,
        signature: String,
    ) -> Option<Response> {
        let b_num = self.node_raft.get_current_block_num();
        match create_receipt_asset_tx_from_sig(
            b_num,
            receipt_amount,
            script_public_key,
            public_key,
            signature,
        ) {
            Ok(tx) => Some(self.receive_transactions(vec![tx])),
            Err(e) => {
                error!("Error creating receipt asset transaction: {:?}", e);
                None
            }
        }
    }

    /// Get `Node` member
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

impl ComputeInterface for ComputeNode {
    fn fetch_utxo_set(&mut self, peer: SocketAddr, address_list: UtxoFetchType) -> Response {
        self.fetched_utxo_set = match address_list {
            UtxoFetchType::All => Some((peer, self.get_committed_utxo_set_to_send())),
            UtxoFetchType::AnyOf(addresses) => {
                let utxo_set = self.get_committed_utxo_set();
                let utxo_tracked_set = self.get_committed_utxo_tracked_set_to_send();
                let utxo_subset: UtxoSet = addresses
                    .iter()
                    .filter_map(|v| utxo_tracked_set.get_pk_cache_vec(v))
                    .flatten()
                    .filter_map(|op| {
                        utxo_set
                            .get_key_value(op)
                            .map(|(k, v)| (k.clone(), v.clone()))
                    })
                    .collect();
                Some((peer, utxo_subset))
            }
        };
        Response {
            success: true,
            reason: "Received UTXO fetch request",
        }
    }

    fn partition(&self, _uuids: Vec<&'static str>) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn get_service_levels(&self) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn receive_transactions(&mut self, transactions: Vec<Transaction>) -> Response {
        let transactions_len = transactions.len();
        if !self.node_raft.tx_pool_can_accept(transactions_len) {
            return Response {
                success: false,
                reason: "Transaction pool for this compute node is full",
            };
        }

        let (valid_dde_txs, valid_txs): (BTreeMap<_, _>, BTreeMap<_, _>) = {
            let tx_validator = self.transactions_validator();
            transactions
                .into_iter()
                .filter(|tx| tx_validator(tx))
                .map(|tx| (construct_tx_hash(&tx), tx))
                .partition(|tx| tx.1.druid_info.is_some())
        };

        let total_valid_txs_len = valid_txs.len() + valid_dde_txs.len();

        // No valid transactions (normal or DDE) provided
        if total_valid_txs_len == 0 {
            return Response {
                success: false,
                reason: "No valid transactions provided",
            };
        }

        // `Normal` transactions
        store_local_transactions(&mut self.db, &valid_txs);
        self.node_raft.append_to_tx_pool(valid_txs);

        // `DDE` transactions
        // TODO: Save DDE transactions to local DB storage
        let ready_dde_txs = self.validate_dde_txs(valid_dde_txs);
        let mut invalid_dde_txs_len = 0;
        for (valid, ready) in ready_dde_txs {
            if !valid {
                invalid_dde_txs_len += 1;
                continue;
            }
            self.node_raft.append_to_tx_druid_pool(ready);
        }

        // Some txs are invalid or some DDE txs are ready to execute but fail to validate
        // TODO: Should provide better feedback on DDE transactions that fail
        if (total_valid_txs_len < transactions_len) || invalid_dde_txs_len != 0 {
            return Response {
                success: true,
                reason: "Some transactions invalid. Adding valid transactions only",
            };
        }

        Response {
            success: true,
            reason: "Transactions added to tx pool",
        }
    }

    fn execute_contract(&self, _contract: Contract) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn get_next_block_reward(&self) -> f64 {
        0.0
    }
}

impl ComputeApi for ComputeNode {
    fn get_committed_utxo_tracked_set(&self) -> &TrackedUtxoSet {
        self.node_raft.get_committed_utxo_tracked_set()
    }

    fn get_pending_druid_pool(&self) -> &DruidPool {
        self.get_pending_druid_pool()
    }
}

/// Get pending transactions
///
/// ### Arguments
///
/// * `db`             - Database
fn get_local_transactions(db: &SimpleDb) -> BTreeMap<String, Transaction> {
    db.iter_cf_clone(DB_COL_LOCAL_TXS)
        .map(|(k, v)| (String::from_utf8(k), deserialize(&v)))
        .map(|(k, v)| (k.unwrap(), v.unwrap()))
        .collect()
}

/// Add pending transactions
///
/// ### Arguments
///
/// * `db`             - Database
/// * `transactions`   - Transactions to store
fn store_local_transactions(db: &mut SimpleDb, transactions: &BTreeMap<String, Transaction>) {
    let mut batch = db.batch_writer();
    for (key, value) in transactions {
        let value = serialize(value).unwrap();
        batch.put_cf(DB_COL_LOCAL_TXS, key, &value);
    }
    let batch = batch.done();
    db.write(batch).unwrap();
}

/// Delete no longer relevant transaction
///
/// ### Arguments
///
/// * `db`     - Database
/// * `keys`   - Keys to delete
fn delete_local_transactions(db: &mut SimpleDb, keys: &[String]) {
    let mut batch = db.batch_writer();
    for key in keys {
        batch.delete_cf(DB_COL_LOCAL_TXS, key);
    }
    let batch = batch.done();
    db.write(batch).unwrap();
}
