use crate::comms_handler::{CommsError, Event, Node, TcpTlsConfig};
use crate::configurations::{ExtraNodeParams, StorageNodeConfig, TlsPrivateInfo};
use crate::constants::{
    DB_PATH, INDEXED_BLOCK_HASH_PREFIX_KEY, INDEXED_TX_HASH_PREFIX_KEY, LAST_BLOCK_HASH_KEY,
    NAMED_CONSTANT_PREPEND, PEER_LIMIT,
};
use crate::db_utils::{self, SimpleDb, SimpleDbError, SimpleDbSpec, SimpleDbWriteBatch};
use crate::interfaces::{
    BlockStoredInfo, BlockchainItem, BlockchainItemMeta, ComputeRequest, Contract, MineRequest,
    MinedBlock, NodeType, ProofOfWork, Response, StorageInterface, StorageRequest,
    StoredSerializingBlock,
};
use crate::raft::RaftCommit;
use crate::storage_fetch::{FetchStatus, FetchedBlockChain, StorageFetch};
use crate::storage_raft::{CommittedItem, CompleteBlock, StorageRaft};
use crate::utils::{
    construct_valid_block_pow_hash, get_genesis_tx_in_display, to_api_keys, ApiKeys, LocalEvent,
    LocalEventChannel, LocalEventSender, ResponseResult,
};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, error_span, info, trace, warn};
use tracing_futures::Instrument;

/// Key storing current proposer run
pub const RAFT_KEY_RUN: &str = "RaftKeyRun";
pub const LAST_CONTIGUOUS_BLOCK_KEY: &str = "LastContiguousBlockKey";

/// Database columns
pub const DB_COL_INTERNAL: &str = "internal";
pub const DB_COL_BC_ALL: &str = "block_chain_all";
pub const DB_COL_BC_NAMED: &str = "block_chain_named";
pub const DB_COL_BC_META: &str = "block_chain_meta";
pub const DB_COL_BC_JSON: &str = "block_chain_json";
pub const DB_COL_BC_NOW: &str = "block_chain_v0.4.0";
pub const DB_COL_BC_V0_3_0: &str = "block_chain_v0.3.0";
pub const DB_COL_BC_V0_2_0: &str = "block_chain_v0.2.0";

/// Version columns
pub const DB_COLS_BC: &[(&str, u32)] = &[
    (DB_COL_BC_NOW, 2),
    (DB_COL_BC_V0_3_0, 1),
    (DB_COL_BC_V0_2_0, 0),
];
pub const DB_POINTER_SEPARATOR: u8 = b':';

/// Database specification
pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
    db_path: DB_PATH,
    suffix: ".storage",
    columns: &[
        DB_COL_INTERNAL,
        DB_COL_BC_ALL,
        DB_COL_BC_NAMED,
        DB_COL_BC_META,
        DB_COL_BC_JSON,
        DB_COL_BC_NOW,
        DB_COL_BC_V0_3_0,
        DB_COL_BC_V0_2_0,
    ],
};

/// Result wrapper for compute errors
pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug)]
pub enum StorageError {
    ConfigError(&'static str),
    Network(CommsError),
    DbError(SimpleDbError),
    Serialization(bincode::Error),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {}", err),
            Self::Network(err) => write!(f, "Network error: {}", err),
            Self::DbError(err) => write!(f, "DB error: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::Network(ref e) => Some(e),
            Self::DbError(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
        }
    }
}

impl From<CommsError> for StorageError {
    fn from(other: CommsError) -> Self {
        Self::Network(other)
    }
}

impl From<SimpleDbError> for StorageError {
    fn from(other: SimpleDbError) -> Self {
        Self::DbError(other)
    }
}

impl From<bincode::Error> for StorageError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

#[derive(Debug)]
pub struct StorageNode {
    node: Node,
    node_raft: StorageRaft,
    catchup_fetch: StorageFetch,
    db: Arc<Mutex<SimpleDb>>,
    local_events: LocalEventChannel,
    compute_addr: SocketAddr,
    api_info: (SocketAddr, Option<TlsPrivateInfo>, ApiKeys),
    whitelisted: HashMap<SocketAddr, bool>,
    shutdown_group: BTreeSet<SocketAddr>,
    blockchain_item_fetched: Option<(String, BlockchainItem, SocketAddr)>,
}

impl StorageNode {
    ///Constructor for a new StorageNode
    ///
    /// ### Arguments
    ///
    /// * `config` - StorageNodeConfig object containing the parameters for the new StorageNode
    /// * `extra`  - additional parameter for construction
    pub async fn new(config: StorageNodeConfig, mut extra: ExtraNodeParams) -> Result<StorageNode> {
        let addr = config
            .storage_nodes
            .get(config.storage_node_idx)
            .ok_or(StorageError::ConfigError("Invalid storage index"))?
            .address;

        let compute_addr = config
            .compute_nodes
            .get(config.storage_node_idx)
            .ok_or(StorageError::ConfigError("Invalid compute index"))?
            .address;

        let tcp_tls_config = TcpTlsConfig::from_tls_spec(addr, &config.tls_config)?;
        let api_addr = SocketAddr::new(addr.ip(), config.storage_api_port);
        let api_tls_info = config
            .storage_api_use_tls
            .then(|| tcp_tls_config.clone_private_info());
        let api_keys = to_api_keys(config.api_keys.clone());

        let node = Node::new(&tcp_tls_config, PEER_LIMIT, NodeType::Storage).await?;
        let node_raft = StorageRaft::new(&config, extra.raft_db.take());
        let catchup_fetch = StorageFetch::new(&config, addr);

        let db = {
            let raw_db = db_utils::new_db(config.storage_db_mode, &DB_SPEC, extra.db.take());
            Arc::new(Mutex::new(raw_db))
        };

        let shutdown_group = {
            let compute = std::iter::once(compute_addr);
            let raft_peers = node_raft.raft_peer_addrs().copied();
            raft_peers.chain(compute).collect()
        };

        Ok(StorageNode {
            node,
            node_raft,
            catchup_fetch,
            db,
            api_info: (api_addr, api_tls_info, api_keys),
            local_events: Default::default(),
            compute_addr,
            whitelisted: Default::default(),
            shutdown_group,
            blockchain_item_fetched: Default::default(),
        }
        .load_local_db()?)
    }

    /// Returns the storage node's public endpoint.
    pub fn address(&self) -> SocketAddr {
        self.node.address()
    }

    /// Returns the storage node's API info
    pub fn api_inputs(
        &self,
    ) -> (
        Arc<Mutex<SimpleDb>>,
        SocketAddr,
        Option<TlsPrivateInfo>,
        ApiKeys,
    ) {
        let (api_addr, api_tls, api_keys) = self.api_info.clone();
        (self.db.clone(), api_addr, api_tls, api_keys)
    }

    ///Adds a uses data as the payload to create a frame, from the peer address, in the node object of this class.
    ///
    /// ### Arguments
    ///
    /// * `from_peer_addr` - Socket address that the data was sent from.
    /// * `data` - payload used to create a new frame in the node.
    pub fn inject_next_event(
        &self,
        from_peer_addr: SocketAddr,
        data: impl Serialize,
    ) -> Result<()> {
        Ok(self.node.inject_next_event(from_peer_addr, data)?)
    }

    /// Connect info for peers on the network.
    pub fn connect_info_peers(&self) -> (Node, Vec<SocketAddr>, Vec<SocketAddr>) {
        let to_connect = self.node_raft.raft_peer_to_connect();
        let expect_connect = self.node_raft.raft_peer_addrs();
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
        let mut self_db = self.db.lock().unwrap();

        ExtraNodeParams {
            db: self_db.take().in_memory(),
            raft_db: raft_db.in_memory(),
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
                reason: "Blockchain item fetched from storage",
            }) => {
                if let Err(e) = self.send_blockchain_item().await {
                    error!("Blockchain item not sent {:?}", e);
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
                reason: "Compute Shutdown",
            }) => {
                debug!("Compute shutdown");
                if self.flood_closing_events().await.unwrap() {
                    warn!("Flood closing event shutdown");
                    return ResponseResult::Exit;
                }
            }
            Ok(Response {
                success: true,
                reason: "Shutdown pending",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Block received to be added",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Block complete stored",
            }) => {
                info!("Block stored: Send to compute");
                if let Err(e) = self.send_stored_block().await {
                    error!("Block stored not sent {:?}", e);
                }
            }
            Ok(Response {
                success: true,
                reason: "Snapshot applied",
            }) => {
                warn!("Snapshot applied");
            }
            Ok(Response {
                success: true,
                reason: "Snapshot applied: Fetch missing blocks",
            }) => {
                warn!("Snapshot applied: Fetch missing blocks");
            }
            Ok(Response {
                success: true,
                reason: "Catch up stored blocks",
            }) => {
                if let Err(e) = self.catchup_fetch_blockchain_item().await {
                    error!("Resend block stored failed {:?}", e);
                }
            }
            Ok(Response {
                success: true,
                reason: "Blockchain item received",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Blockchain item received: Block stored",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Blockchain item received: Block stored(Done)",
            }) => {}
            Ok(Response {
                success: false,
                reason: "Blockchain item received: Block failed",
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
                        StorageRequest::SendRaftCmd(msg)).await {
                            Err(e) => info!("Msg not sent to {}, from {}: {:?}", addr, self.address(), e),
                            Ok(()) => trace!("Msg sent to {}, from {}", addr, self.address()),
                        };

                }
                Some(()) = self.catchup_fetch.timeout_fetch_blockchain_item(), if ready => {
                    trace!("handle_next_event timeout fetch blockchain item");
                    if self.catchup_fetch.set_retry_timeout() {
                        self.catchup_fetch.change_to_next_fetch_peer();
                    }
                    return Some(Ok(Response {
                        success: true,
                        reason: "Catch up stored blocks",
                    }))
                }
                Some(event) = self.local_events.rx.recv(), if ready => {
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

    ///Handle commit data
    ///
    /// ### Arguments
    ///
    /// * `commit_data` - Commit to process.
    async fn handle_committed_data(&mut self, commit_data: RaftCommit) -> Option<Result<Response>> {
        match self.node_raft.received_commit(commit_data).await {
            Some(CommittedItem::Block) => {
                let block = self.node_raft.generate_complete_block();
                let block_stored = {
                    let mut self_db = self.db.lock().unwrap();

                    let b_num = block.common.block.header.b_num;
                    let contiguous = self.catchup_fetch.check_contiguous_block_num(b_num);
                    let stored = Self::store_complete_block(&mut self_db, contiguous, block);
                    self.catchup_fetch.update_contiguous_block_num(contiguous);
                    self.catchup_fetch.increase_running_target(b_num);

                    stored
                };
                self.node_raft
                    .event_processed_generate_snapshot(block_stored);
                Some(Ok(Response {
                    success: true,
                    reason: "Block complete stored",
                }))
            }
            Some(CommittedItem::Snapshot) => {
                if let Some(stored) = self.node_raft.get_last_block_stored() {
                    let b_num = stored.block_num;
                    if self.catchup_fetch.fetch_missing_blockchain_items(b_num) {
                        debug!(
                            "Snapshot applied: Fetch missing blocks: {:?}",
                            &self.catchup_fetch
                        );
                        return Some(Ok(Response {
                            success: true,
                            reason: "Snapshot applied: Fetch missing blocks",
                        }));
                    }
                }
                Some(Ok(Response {
                    success: true,
                    reason: "Snapshot applied",
                }))
            }
            None => None,
        }
    }

    /// Takes message from the event and passes it to handle_new_frame to handle the message
    ///
    /// ### Arguments
    ///
    /// * `event` - Event object containing a message from a peer.
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
    /// * `peer` - Socket address of the sender.
    /// * `frame` - Bytes object holding the message from the sender.
    async fn handle_new_frame(
        &mut self,
        peer: SocketAddr,
        frame: Bytes,
    ) -> Result<Option<Response>> {
        let req = deserialize::<StorageRequest>(&frame).map_err(|error| {
            warn!(?error, "frame-deserialize");
            error
        })?;

        let req_span = error_span!("request", ?req);
        let response = self.handle_request(peer, req).instrument(req_span).await;
        trace!(?response, ?peer, "response");

        Ok(response)
    }

    /// Handles a compute request.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Socket address for the peer that the compute request came from.
    /// * `req` - StorageRequest object holding the compute request.
    async fn handle_request(&mut self, peer: SocketAddr, req: StorageRequest) -> Option<Response> {
        use StorageRequest::*;
        match req {
            GetBlockchainItem { key } => Some(self.get_blockchain_item(peer, key)),
            SendBlockchainItem { key, item } => Some(self.receive_blockchain_item(peer, key, item)),
            GetHistory {
                start_time,
                end_time,
            } => Some(self.get_history(&start_time, &end_time)),
            GetUnicornTable { n_last_items } => Some(self.get_unicorn_table(n_last_items)),
            SendPow { pow } => Some(self.receive_pow(pow)),
            SendBlock { mined_block } => self.receive_block(peer, mined_block).await,
            Store { incoming_contract } => Some(self.receive_contracts(incoming_contract)),
            Closing => self.receive_closing(peer),
            SendRaftCmd(msg) => {
                self.node_raft.received_message(msg).await;
                None
            }
        }
    }

    ///Sends the latest blockchain item fetched from storage.
    pub async fn send_blockchain_item(&mut self) -> Result<()> {
        if let Some((key, item, peer)) = self.blockchain_item_fetched.take() {
            match self.node.get_peer_node_type(peer).await? {
                NodeType::Miner => {
                    self.node
                        .send(peer, MineRequest::SendBlockchainItem { key, item })
                        .await?
                }
                NodeType::Storage => {
                    self.node
                        .send(peer, StorageRequest::SendBlockchainItem { key, item })
                        .await?
                }
                _ => return Ok(()),
            }
        }
        Ok(())
    }

    ///Stores a completed block including transactions and mining transactions.
    ///
    /// ### Arguments
    ///
    /// * `self_db`  - Database to update
    /// * `status`   - Block is contiguous with last contiguous
    /// * `complete` - CompleteBlock object to be stored.
    fn store_complete_block(
        self_db: &mut SimpleDb,
        status: FetchStatus,
        complete: CompleteBlock,
    ) -> BlockStoredInfo {
        // TODO: Makes the DB save process async
        // TODO: only accept whitelisted blocks

        // Save the complete block
        trace!("Store complete block: {:?}", complete);

        let ((stored_block, all_block_txs), (block_num, shutdown)) = {
            let CompleteBlock { common, extra_info } = complete;

            let block_num = common.block.header.b_num;
            let shutdown = extra_info.shutdown;

            let stored_block = StoredSerializingBlock {
                block: common.block,
            };
            let all_block_txs = common.block_txs;

            let to_store = (stored_block, all_block_txs);
            let store_extra_info = (block_num, shutdown);
            (to_store, store_extra_info)
        };

        let block_input = serialize(&stored_block).unwrap();
        let block_json = serde_json::to_vec(&stored_block).unwrap();
        let block_hash = construct_valid_block_pow_hash(&stored_block.block)
            .unwrap_or_else(|e| panic!("Block always validated before: {}", e));

        let (nonce, mining_tx_hash) = stored_block.block.header.nonce_and_mining_tx_hash.clone();
        let last_block_stored_info = BlockStoredInfo {
            block_hash: block_hash.clone(),
            block_num,
            nonce,
            mining_transactions: std::iter::once(&mining_tx_hash)
                .filter_map(|tx_hash| all_block_txs.get_key_value(tx_hash))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            shutdown,
        };

        info!(
            "Store complete block summary: b_num={}, txs={}, mining={}, hash={}",
            block_num,
            stored_block.block.transactions.len(),
            last_block_stored_info.mining_transactions.len(), /* Should always be 1 */
            block_hash
        );

        //
        // Store to database
        //
        let mut batch = self_db.batch_writer();

        let all_txs = all_ordered_stored_block_tx_hashes(
            &stored_block.block.transactions,
            std::iter::once(&stored_block.block.header.nonce_and_mining_tx_hash),
        );
        let mut tx_len = 0;
        for (tx_num, tx_hash) in all_txs {
            tx_len = tx_num + 1;
            if let Some(tx_value) = all_block_txs.get(tx_hash) {
                let tx_input = serialize(tx_value).unwrap();
                let tx_json = serde_json::to_vec(tx_value).unwrap();
                let t = BlockchainItemMeta::Tx { block_num, tx_num };
                put_to_block_chain(&mut batch, &t, tx_hash, &tx_input, &tx_json);
            } else {
                error!(
                    "Missing block {} transaction {}: \"{}\"",
                    block_num, tx_num, tx_hash
                );
            }
        }

        {
            let t = BlockchainItemMeta::Block { block_num, tx_len };
            let pointer =
                put_to_block_chain(&mut batch, &t, &block_hash, &block_input, &block_json);
            put_named_last_block_to_block_chain(&mut batch, &pointer);

            if FetchStatus::Contiguous(block_num) == status {
                put_contiguous_block_num(&mut batch, block_num);
            }
        }

        let batch = batch.done();
        self_db.write(batch).unwrap();

        //
        // Celebrate genesis block:
        //
        if block_num == 0 {
            info!("!!! Stored Genesis Block !!!");
            for hash in &stored_block.block.transactions {
                let tx = all_block_txs.get(hash).unwrap();
                let tx_in = get_genesis_tx_in_display(tx);
                info!("Genesis Transaction: Hash:{} -> TxIn:{}", hash, tx_in);

                for (idx, tx_out) in tx.outputs.iter().enumerate() {
                    if let Some(key) = &tx_out.script_public_key {
                        info!(
                            "Genesis entry: Index:{}, Key:{} -> Tokens:{}",
                            idx,
                            key,
                            tx_out.value.token_amount()
                        );
                    }
                }
            }
        }

        last_block_stored_info
    }

    ///Stores a completed block including transactions and mining transactions.
    ///
    /// ### Arguments
    ///
    /// * `self_db` - Database to update
    /// * `b_num`   - Block number to store
    /// * `status`  - Block is contiguous with last contiguous
    /// * `items`   - Complete block object to be stored.
    fn store_fetched_complete_block(
        self_db: &mut SimpleDb,
        last_block_stored: &BlockStoredInfo,
        status: FetchStatus,
        (b_num, items): FetchedBlockChain,
    ) -> Result<FetchStatus> {
        let mut batch = self_db.batch_writer();
        let mut block_pointer = None;

        info!(
            "Store catchup complete block summary: b_num={}, items={}",
            b_num,
            items.len(),
        );

        for item in &items {
            let key = str::from_utf8(&item.key)
                .map_err(|_| StorageError::ConfigError("Non UTF-8 blockchain key"))?;
            let pointer = put_to_block_chain(
                &mut batch,
                &item.item_meta,
                key,
                &item.data,
                &item.data_json,
            );

            if let BlockchainItemMeta::Block { block_num, .. } = &item.item_meta {
                if block_num == &b_num {
                    block_pointer = Some(pointer);
                }
            }
        }

        if let Some(block_pointer) = block_pointer {
            if last_block_stored.block_num == b_num {
                put_named_last_block_to_block_chain(&mut batch, &block_pointer);
            }
            if FetchStatus::Contiguous(b_num) == status {
                put_contiguous_block_num(&mut batch, b_num);
            }
        } else {
            return Err(StorageError::ConfigError("Block not specified"));
        }

        let batch = batch.done();
        self_db.write(batch).unwrap();
        Ok(status)
    }

    /// Sends a request to retrieve a blockchain item from storage
    pub async fn catchup_fetch_blockchain_item(&mut self) -> Result<()> {
        if let Some((peer, key)) = self.catchup_fetch.get_fetch_peer_and_key() {
            let request = StorageRequest::GetBlockchainItem { key };
            self.node.send(peer, request).await?;
        } else {
            error!("No peer to catchup from");
        };

        Ok(())
    }

    /// Gets a value from the stored blockchain via key
    ///
    /// ### Arguments
    ///
    /// * `key` - Key for the value to retrieve
    pub fn get_stored_value<K: AsRef<[u8]>>(&self, key: K) -> Option<BlockchainItem> {
        get_stored_value_from_db(self.db.clone(), key)
    }

    /// Get the last block stored info to send to the compute nodes
    pub fn get_last_block_stored(&self) -> &Option<BlockStoredInfo> {
        self.node_raft.get_last_block_stored()
    }

    /// Get count of all the stored values
    pub fn get_stored_values_count(&self) -> usize {
        let db = self.db.lock().unwrap();
        db.count_cf(DB_COL_BC_ALL)
    }

    /// Sends the latest block to storage
    pub async fn send_stored_block(&mut self) -> Result<()> {
        // Only the first call will send to storage.
        if let Some(block) = self.get_last_block_stored().clone() {
            self.node
                .send(self.compute_addr, ComputeRequest::SendBlockStored(block))
                .await?;
        }

        Ok(())
    }

    /// Re-sends messages triggering the next step in flow
    pub async fn resend_trigger_message(&mut self) {
        info!("Resend block stored: Send to compute");
        if let Err(e) = self.send_stored_block().await {
            error!("Resend lock stored not sent {:?}", e);
        }
    }

    /// Floods the closing event to everyone
    pub async fn flood_closing_events(&mut self) -> Result<bool> {
        self.node
            .send_to_all(Some(self.compute_addr).into_iter(), ComputeRequest::Closing)
            .await
            .unwrap();

        self.node
            .send_to_all(
                self.node_raft.raft_peer_addrs().copied(),
                StorageRequest::Closing,
            )
            .await
            .unwrap();

        Ok(self.shutdown_group.is_empty())
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

        if peer == self.compute_addr {
            return Some(Response {
                success: true,
                reason: "Compute Shutdown",
            });
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

    /// Receives a mined block from compute
    ///
    /// ### Arguments
    ///
    /// * `peer`            - Peer that the block is received from
    /// * `mined_block`     - The mined block
    async fn receive_block(
        &mut self,
        peer: SocketAddr,
        mined_block: Option<MinedBlock>,
    ) -> Option<Response> {
        let (common, extra_info) = if let Some(MinedBlock { common, extra_info }) = mined_block {
            (common, extra_info)
        } else {
            self.resend_trigger_message().await;
            return None;
        };

        if let Err(e) = construct_valid_block_pow_hash(&common.block) {
            debug!("Block received not added. PoW invalid: {}", e);
            return Some(Response {
                success: false,
                reason: "Block received not added. PoW invalid",
            });
        }

        if !self
            .node_raft
            .propose_received_part_block(peer, common, extra_info)
            .await
        {
            self.node_raft.re_propose_uncommitted_current_b_num().await;
            self.resend_trigger_message().await;
            return None;
        }

        Some(Response {
            success: true,
            reason: "Block received to be added",
        })
    }

    /// Load and apply the local database to our state
    fn load_local_db(mut self) -> Result<Self> {
        self.node_raft.set_key_run({
            let mut db = self.db.lock().unwrap();
            let key_run = match db.get_cf(DB_COL_INTERNAL, RAFT_KEY_RUN) {
                Ok(Some(key_run)) => deserialize::<u64>(&key_run)? + 1,
                Ok(None) => 0,
                Err(e) => panic!("Error accessing db: {:?}", e),
            };
            debug!("load_local_db: key_run update to {:?}", key_run);
            if let Err(e) = db.put_cf(DB_COL_INTERNAL, RAFT_KEY_RUN, &serialize(&key_run)?) {
                panic!("Error accessing db: {:?}", e);
            }
            key_run
        });

        self.catchup_fetch.set_initial_last_contiguous_block_key({
            let db = self.db.lock().unwrap();
            match db.get_cf(DB_COL_INTERNAL, LAST_CONTIGUOUS_BLOCK_KEY) {
                Ok(Some(b_num)) => Some(deserialize::<u64>(&b_num)?),
                Ok(None) => None,
                Err(e) => panic!("Error accessing db: {:?}", e),
            }
        });

        Ok(self)
    }

    /// Get `Node` member
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

impl StorageInterface for StorageNode {
    fn get_blockchain_item(&mut self, peer: SocketAddr, key: String) -> Response {
        let item = self.get_stored_value(&key).unwrap_or_default();
        self.blockchain_item_fetched = Some((key, item, peer));
        Response {
            success: true,
            reason: "Blockchain item fetched from storage",
        }
    }

    fn receive_blockchain_item(
        &mut self,
        peer: SocketAddr,
        key: String,
        item: BlockchainItem,
    ) -> Response {
        let to_store = self.catchup_fetch.receive_blockchain_items(key, item);
        let is_complete = self.catchup_fetch.is_complete();

        if let Some(block) = to_store {
            let mut self_db = self.db.lock().unwrap();
            let b_num = block.0;

            let result = match self.node_raft.get_last_block_stored() {
                Some(last_stored) if last_stored.block_num >= b_num => {
                    let contiguous = self.catchup_fetch.check_contiguous_block_num(b_num);
                    Self::store_fetched_complete_block(&mut self_db, last_stored, contiguous, block)
                }
                _ => Err(StorageError::ConfigError(
                    "Expect only block less than block stored",
                )),
            };

            match result {
                Ok(status) => {
                    self.catchup_fetch.update_contiguous_block_num(status);
                    self.catchup_fetch.set_first_timeout();
                    let reason = if is_complete {
                        "Blockchain item received: Block stored(Done)"
                    } else {
                        "Blockchain item received: Block stored"
                    };

                    info!("{}(b_num = {})", reason, b_num);
                    Response {
                        success: true,
                        reason,
                    }
                }
                Err(e) => {
                    error!(
                        "receive_blockchain_item from {} could not process block: {:?}",
                        peer, e
                    );
                    Response {
                        success: false,
                        reason: "Blockchain item received: Block failed",
                    }
                }
            }
        } else {
            if !is_complete {
                self.catchup_fetch.set_first_timeout();
            }

            Response {
                success: true,
                reason: "Blockchain item received",
            }
        }
    }

    fn get_history(&self, _start_time: &u64, _end_time: &u64) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn whitelist(&mut self, address: SocketAddr) -> Response {
        self.whitelisted.insert(address, true);

        Response {
            success: true,
            reason: "Address added to whitelist",
        }
    }

    fn get_unicorn_table(&self, _n_last_items: Option<u64>) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn receive_pow(&self, _pow: ProofOfWork) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }

    fn receive_contracts(&self, _contract: Contract) -> Response {
        Response {
            success: false,
            reason: "Not implemented yet",
        }
    }
}

/// Add to the block chain columns
///
/// ### Arguments
///
/// * `batch`      - Database writer
/// * `item_meta`  - The metadata for the data
/// * `key`        - The key for the data
/// * `value`      - The value to store
/// * `value_json` - The value to store in JSON
pub fn put_to_block_chain(
    batch: &mut SimpleDbWriteBatch,
    item_meta: &BlockchainItemMeta,
    key: &str,
    value: &[u8],
    value_json: &[u8],
) -> Vec<u8> {
    put_to_block_chain_at(batch, DB_COL_BC_NOW, item_meta, key, value, value_json)
}

/// Add to the block chain columns for specified version
///
/// ### Arguments
///
/// * `batch`      - Database writer
/// * `cf`         - Column family to store the key/value
/// * `item_meta`  - The metadata for the data
/// * `key`        - The key for the data
/// * `value`      - The value to store
/// * `value_json` - The value to store in JSON
pub fn put_to_block_chain_at<K: AsRef<[u8]>, V: AsRef<[u8]>>(
    batch: &mut SimpleDbWriteBatch,
    cf: &'static str,
    item_meta: &BlockchainItemMeta,
    key: K,
    value: V,
    value_json: V,
) -> Vec<u8> {
    let key = key.as_ref();
    let value = value.as_ref();
    let value_json = value_json.as_ref();
    let pointer = version_pointer(cf, key);
    let meta_key = match *item_meta {
        BlockchainItemMeta::Block { block_num, .. } => indexed_block_hash_key(block_num),
        BlockchainItemMeta::Tx { block_num, tx_num } => indexed_tx_hash_key(block_num, tx_num),
    };
    let meta_ser = serialize(item_meta).unwrap();

    batch.put_cf(cf, key, value);
    batch.put_cf(DB_COL_BC_JSON, key, value_json);
    batch.put_cf(DB_COL_BC_ALL, key, &pointer);
    batch.put_cf(DB_COL_BC_META, key, &meta_ser);
    batch.put_cf(DB_COL_BC_NAMED, &meta_key, &pointer);

    pointer
}

/// Add to the last block chain named column
///
/// ### Arguments
///
/// * `batch`   - Database writer
/// * `pointer` - The block version pointer
pub fn put_named_last_block_to_block_chain(batch: &mut SimpleDbWriteBatch, pointer: &[u8]) {
    batch.put_cf(DB_COL_BC_NAMED, LAST_BLOCK_HASH_KEY, &pointer);
}

/// Update database with contiguous value
pub fn put_contiguous_block_num(batch: &mut SimpleDbWriteBatch, block_num: u64) {
    let last_num = serialize(&block_num).unwrap();
    batch.put_cf(DB_COL_INTERNAL, LAST_CONTIGUOUS_BLOCK_KEY, &last_num);
}

/// Iterate on all the StoredSerializingBlock transaction hashes
/// First the transactions in provided order and then the mining txs
///
/// ### Arguments
///
/// * `transactions`              - The block transactions
/// * `nonce_and_mining_tx_hash` - The block mining transactions
pub fn all_ordered_stored_block_tx_hashes<'a>(
    transactions: &'a [String],
    nonce_and_mining_tx_hash: impl Iterator<Item = &'a (Vec<u8>, String)> + 'a,
) -> impl Iterator<Item = (u32, &'a String)> + 'a {
    let mining_hashes = nonce_and_mining_tx_hash.map(|(_, hash)| hash);
    let all_txs = transactions.iter().chain(mining_hashes);
    all_txs.enumerate().map(|(idx, v)| (idx as u32, v))
}

/// Get the stored value at the given key
///
/// ### Arguments
///
/// * `key` - Given key to find the value.
pub fn get_stored_value_from_db<K: AsRef<[u8]>>(
    db: Arc<Mutex<SimpleDb>>,
    key: K,
) -> Option<BlockchainItem> {
    let col_all = if key.as_ref().get(0) == Some(&NAMED_CONSTANT_PREPEND) {
        DB_COL_BC_NAMED
    } else {
        DB_COL_BC_ALL
    };
    let u_db = db.lock().unwrap();
    let pointer = ok_or_warn(u_db.get_cf(col_all, key), "get_stored_value pointer")?;

    let (version, cf, key) = decode_version_pointer(&pointer);
    let data = ok_or_warn(u_db.get_cf(cf, key), "get_stored_value data")?;
    let data_json = ok_or_warn(
        u_db.get_cf(DB_COL_BC_JSON, key),
        "get_stored_value data_json",
    )?;
    let meta = {
        let meta = u_db.get_cf(DB_COL_BC_META, key);
        let meta = ok_or_warn(meta, "get_stored_value meta")?;
        let meta = deserialize::<BlockchainItemMeta>(&meta).map(Some);
        ok_or_warn(meta, "get_stored_value meta ser")?
    };
    Some(BlockchainItem {
        version,
        item_meta: meta,
        key: key.to_owned(),
        data,
        data_json,
    })
}

/// Version pointer for the column:key
///
/// ### Arguments
///
/// * `cf`        - Column family the data is
/// * `key`       - The key for the data
fn version_pointer<K: AsRef<[u8]>>(cf: &'static str, key: K) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend(cf.as_bytes());
    r.extend(&[DB_POINTER_SEPARATOR]);
    r.extend(key.as_ref());
    r
}

/// The key for indexed block
///
/// ### Arguments
///
/// * `b_num`  - The block number
pub fn indexed_block_hash_key(b_num: u64) -> String {
    format!("{}{:016x}", INDEXED_BLOCK_HASH_PREFIX_KEY, b_num)
}

/// The key for indexed block
///
/// ### Arguments
///
/// * `b_num`  - The block number
/// * `tx_num` - The transaction index in the block
pub fn indexed_tx_hash_key(b_num: u64, tx_num: u32) -> String {
    format!(
        "{}{:016x}_{:08x}",
        INDEXED_TX_HASH_PREFIX_KEY, b_num, tx_num
    )
}

/// Decodes a version pointer
///
/// ### Arguments
///
/// * `pointer`    - String to be split and decoded
pub fn decode_version_pointer(pointer: &[u8]) -> (u32, &'static str, &[u8]) {
    let mut it = pointer.split(|c| c == &DB_POINTER_SEPARATOR);
    let cf = it.next().unwrap();
    let (cf, version) = DB_COLS_BC.iter().find(|(v, _)| v.as_bytes() == cf).unwrap();
    let key = it.next().unwrap();
    (*version, cf, key)
}

/// Return an option, emiting a warning for errors converted to
fn ok_or_warn<V, E: fmt::Display>(r: std::result::Result<Option<V>, E>, tag: &str) -> Option<V> {
    r.unwrap_or_else(|e| {
        warn!("{}: {}", tag, e);
        None
    })
}
