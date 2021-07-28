use crate::active_raft::ActiveRaft;
use crate::configurations::StorageNodeConfig;
use crate::constants::DB_PATH;
use crate::db_utils::{self, SimpleDb, SimpleDbSpec};
use crate::interfaces::{BlockStoredInfo, CommonBlockInfo, MinedBlockExtraInfo};
use crate::raft::{RaftCommit, RaftCommitData, RaftData, RaftMessageWrapper};
use crate::raft_util::{RaftContextKey, RaftInFlightProposals};
use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{self, Instant};
use tracing::{debug, trace, warn};

pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
    db_path: DB_PATH,
    suffix: ".storage_raft",
    columns: &[],
};

/// Item serialized into RaftData and process by Raft.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum StorageRaftItem {
    PartBlock(ReceivedBlock),
    CompleteBlock(u64),
}

/// Commited item to process.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommittedItem {
    Block,
    Snapshot,
}

/// Mined block received.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedBlock {
    pub peer: SocketAddr,
    pub common: CommonBlockInfo,
    pub per_node: MinedBlockExtraInfo,
}

/// Complete block info with all mining transactions and proof of work.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompleteBlock {
    pub common: CommonBlockInfo,
    pub per_node: BTreeMap<u64, MinedBlockExtraInfo>,
}

/// Different state for timeout
#[derive(Clone, Debug)]
pub enum ProposeBlockTimeout {
    First,
    None,
    Some(Instant),
}

/// All fields that are consensused between the RAFT group.
/// These fields need to be written and read from a committed log event.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageConsensused {
    /// Sufficient majority
    sufficient_majority: usize,
    /// Index of the last completed block.
    current_block_num: u64,
    /// Peer ids that have voted to complete the block.
    current_block_complete_timeout_peer_ids: BTreeSet<u64>,
    /// Part block completed by Peer ids.
    current_block_completed_parts: BTreeMap<Vec<u8>, CompleteBlock>,
    /// The last commited raft index.
    last_committed_raft_idx_and_term: (u64, u64),
    /// The last block stored by ours and other node in consensus.
    last_block_stored: Option<BlockStoredInfo>,
}

/// Consensused info to apply on start up after upgrade.
pub struct StorageConsensusedImport {
    pub sufficient_majority: usize,
    pub current_block_num: u64,
    pub last_committed_raft_idx_and_term: (u64, u64),
    pub last_block_stored: Option<BlockStoredInfo>,
}

/// Consensused Compute fields and consensus managment.
pub struct StorageRaft {
    /// True if first peer (leader).
    first_raft_peer: bool,
    /// The raft instance to interact with.
    raft_active: ActiveRaft,
    /// Consensused fields.
    consensused: StorageConsensused,
    /// Whether consensused received initial snapshot
    consensused_snapshot_applied: bool,
    /// Min duration between each block poposal.
    propose_block_timeout_duration: Duration,
    /// Timeout expiration time for block poposal.
    propose_block_timeout_at: ProposeBlockTimeout,
    /// Proposed items in flight.
    proposed_in_flight: RaftInFlightProposals,
    /// No longer process commits after shutdown reached
    shutdown_no_commit_process: bool,
}

impl fmt::Debug for StorageRaft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StorageRaft()")
    }
}

impl StorageRaft {
    /// Create a StorageRaft, need to spawn the raft loop to use raft.
    ///
    /// ### Arguments
    ///
    /// * `config`  - Configuration option for a storage node.
    /// * `raft_db` - Override raft db to use.
    pub fn new(config: &StorageNodeConfig, raft_db: Option<SimpleDb>) -> Self {
        let use_raft = config.storage_raft != 0;
        let raft_active = ActiveRaft::new(
            config.storage_node_idx,
            &config.storage_nodes,
            use_raft,
            Duration::from_millis(config.storage_raft_tick_timeout as u64),
            db_utils::new_db(config.storage_db_mode, &DB_SPEC, raft_db),
        );

        let propose_block_timeout_duration =
            Duration::from_millis(config.storage_block_timeout as u64);
        let propose_block_timeout_at = ProposeBlockTimeout::First;

        let first_raft_peer = config.storage_node_idx == 0 || !raft_active.use_raft();
        let peers_len = raft_active.peers_len();

        let consensused = StorageConsensused::default().with_peers_len(peers_len);

        Self {
            first_raft_peer,
            raft_active,
            consensused,
            consensused_snapshot_applied: !use_raft,
            propose_block_timeout_duration,
            propose_block_timeout_at,
            proposed_in_flight: Default::default(),
            shutdown_no_commit_process: false,
        }
    }

    /// Set the key run for all proposals (load from db before first proposal).
    pub fn set_key_run(&mut self, key_run: u64) {
        self.proposed_in_flight.set_key_run(key_run)
    }

    /// All the peers to connect to when using raft.
    pub fn raft_peer_to_connect(&self) -> impl Iterator<Item = &SocketAddr> {
        self.raft_active.raft_peer_to_connect()
    }

    /// All the peers expected to be connected when raft is running.
    pub fn raft_peer_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.raft_active.raft_peer_addrs()
    }

    /// Blocks & waits for a next event from a peer.
    pub fn raft_loop(&self) -> impl Future<Output = ()> {
        self.raft_active.raft_loop()
    }

    /// Signal to the raft loop to complete
    pub async fn close_raft_loop(&mut self) {
        self.raft_active.close_raft_loop().await
    }

    /// Extract persistent storage of a closed raft
    pub async fn take_closed_persistent_store(&mut self) -> SimpleDb {
        self.raft_active.take_closed_persistent_store().await
    }

    /// Check if we are waiting for initial state
    pub fn need_initial_state(&self) -> bool {
        !self.consensused_snapshot_applied
    }

    /// Blocks & waits for a next commit from a peer.
    pub async fn next_commit(&self) -> Option<RaftCommit> {
        self.raft_active.next_commit().await
    }

    /// Process result from next_commit.
    /// Return Some if block to mine is ready to generate.
    ///
    /// ### Arguments
    ///
    /// * `raft_commit` - RaftCommit object holding the data from the commit
    pub async fn received_commit(&mut self, raft_commit: RaftCommit) -> Option<CommittedItem> {
        self.consensused.last_committed_raft_idx_and_term = (raft_commit.index, raft_commit.term);
        match raft_commit.data {
            RaftCommitData::Proposed(data, context) => {
                self.received_commit_proposal(data, context).await
            }
            RaftCommitData::Snapshot(data) => self.apply_snapshot(data),
            RaftCommitData::NewLeader => {
                self.proposed_in_flight
                    .re_propose_all_items(&mut self.raft_active)
                    .await;
                None
            }
        }
    }

    /// Apply snapshot
    fn apply_snapshot(&mut self, consensused_ser: RaftData) -> Option<CommittedItem> {
        self.consensused_snapshot_applied = true;

        if consensused_ser.is_empty() {
            // Empty initial snapshot
            None
        } else {
            warn!("apply_snapshot called self.consensused updated");
            self.consensused = deserialize(&consensused_ser).unwrap();
            self.propose_block_timeout_at = self.next_propose_block_timeout_at();
            Some(CommittedItem::Snapshot)
        }
    }

    /// Checks a commit of the RaftData for validity
    /// Apply commited proposal
    ///
    /// ### Arguments
    ///
    /// * `raft_data` - Data for the commit
    /// * `raft_ctx`  - Context for the commit
    async fn received_commit_proposal(
        &mut self,
        raft_data: RaftData,
        raft_ctx: RaftData,
    ) -> Option<CommittedItem> {
        let (key, item, _) = self
            .proposed_in_flight
            .received_commit_proposal(&raft_data, &raft_ctx)
            .await?;

        trace!("received_commit_proposal {:?} -> {:?}", key, item);
        match item {
            StorageRaftItem::PartBlock(block) => {
                if self
                    .consensused
                    .is_current_block(block.common.block.header.b_num)
                {
                    debug!("PartBlock appened {:?}", key);
                    self.consensused.append_received_block(key, block);
                }
            }
            StorageRaftItem::CompleteBlock(idx) => {
                if self.consensused.is_current_block(idx) {
                    debug!("CompleteBlock appened ({},{:?})", idx, key);
                    self.consensused.append_received_block_timeout(key);
                }
            }
        }

        if self.consensused.has_block_ready_to_store() {
            Some(CommittedItem::Block)
        } else {
            None
        }
    }

    /// Blocks & waits for a next message to dispatch from a peer.
    /// Message needs to be sent to given peer address.
    pub async fn next_msg(&self) -> Option<(SocketAddr, RaftMessageWrapper)> {
        self.raft_active.next_msg().await
    }

    /// Process a raft message: send to spawned raft loop.
    ///
    /// ### Arguments
    ///
    /// * `msg` - RaftMessageWrapper object. Contains the recieved message to be sent to the raft.
    pub async fn received_message(&mut self, msg: RaftMessageWrapper) {
        self.raft_active.received_message(msg).await
    }

    /// Blocks & waits for a timeout to propose a block.
    pub async fn timeout_propose_block(&self) -> Option<()> {
        if let ProposeBlockTimeout::Some(time) = self.propose_block_timeout_at {
            time::sleep_until(time).await;
            Some(())
        } else {
            None
        }
    }

    /// Process as a result of timeout_propose_block.
    /// Signal that the current block should complete.
    /// Restart timeout, for re-proposal.
    pub async fn propose_block_at_timeout(&mut self) -> bool {
        self.propose_block_timeout_at = self.next_propose_block_timeout_at();

        let b_num = self.consensused.current_block_num;
        let item = StorageRaftItem::CompleteBlock(b_num);

        self.propose_item_dedup(&item, b_num).await.is_some()
    }

    /// Add block to our local pool from which to propose
    /// consensused blocks.
    ///
    /// ### Arguments
    ///
    /// * `peer` - socket address of the sending peer
    /// * `common` - CommonBlockInfo holding all block infomation to be stored
    /// * `mined_info` - MinedBlockExtraInfo holding mining info to be stored
    pub async fn propose_received_part_block(
        &mut self,
        peer: SocketAddr,
        common: CommonBlockInfo,
        mined_info: MinedBlockExtraInfo,
    ) -> bool {
        if let ProposeBlockTimeout::First = &self.propose_block_timeout_at {
            // Wait for compute and other nodes to be ready so we do not unecessarily
            // timeout early on first block.
            self.propose_block_timeout_at = self.next_propose_block_timeout_at();
        }

        let b_num = common.block.header.b_num;
        let item = StorageRaftItem::PartBlock(ReceivedBlock {
            peer,
            common,
            per_node: mined_info,
        });

        self.propose_item_dedup(&item, b_num).await.is_some()
    }

    /// Re-propose uncommited items relevant for current block.
    pub async fn re_propose_uncommitted_current_b_num(&mut self) {
        self.proposed_in_flight
            .re_propose_uncommitted_current_b_num(
                &mut self.raft_active,
                self.consensused.current_block_num,
            )
            .await;
    }

    /// Propose an item to raft if use_raft, or commit it otherwise.
    /// Deduplicate entries.
    ///
    /// ### Arguments
    ///
    ///  * `item`  - The item to be proposed to a raft.
    ///  * `b_num` - Block number associated with this item.
    async fn propose_item_dedup(
        &mut self,
        item: &StorageRaftItem,
        b_num: u64,
    ) -> Option<RaftContextKey> {
        self.proposed_in_flight
            .propose_item(&mut self.raft_active, item, Some(b_num))
            .await
    }

    /// Generate a snapshot, needs to happen at the end of the event processing.
    pub fn event_processed_generate_snapshot(&mut self, block_stored: BlockStoredInfo) {
        let shutdown = block_stored.shutdown;
        self.consensused.last_block_stored = Some(block_stored);

        let consensused_ser = serialize(&self.consensused).unwrap();
        let (snapshot_idx, term) = self.consensused.last_committed_raft_idx_and_term;

        debug!("generate_snapshot: (idx: {}, term: {})", snapshot_idx, term);
        self.raft_active
            .create_snapshot(snapshot_idx, consensused_ser);

        if shutdown {
            self.shutdown_no_commit_process = true;
        }
    }

    ///Creates and returns a complete block
    pub fn generate_complete_block(&mut self) -> CompleteBlock {
        self.propose_block_timeout_at = self.next_propose_block_timeout_at();

        let (block, b_num) = self.consensused.generate_complete_block();
        self.proposed_in_flight.ignore_dedeup_b_num_less_than(b_num);

        block
    }

    ///Returns the clock time after the proposed block time out
    fn next_propose_block_timeout_at(&mut self) -> ProposeBlockTimeout {
        ProposeBlockTimeout::Some(Instant::now() + self.propose_block_timeout_duration)
    }

    /// The duration for propose block time out
    pub fn propose_block_timeout_duration(&self) -> Duration {
        self.propose_block_timeout_duration
    }

    /// Get the last block stored info to send to the compute nodes
    pub fn get_last_block_stored(&self) -> &Option<BlockStoredInfo> {
        self.consensused.get_last_block_stored()
    }

    /// Whether shut down block already processed
    pub fn is_shutdown_commit_processed(&self) -> bool {
        self.shutdown_no_commit_process
    }
}

impl StorageConsensused {
    /// Specify the raft group size
    pub fn with_peers_len(mut self, peers_len: usize) -> Self {
        self.sufficient_majority = peers_len / 2 + 1;
        self
    }

    /// Create ComputeConsensused from imported data in upgrade
    pub fn from_import(consensused: StorageConsensusedImport) -> Self {
        let StorageConsensusedImport {
            sufficient_majority,
            current_block_num,
            last_committed_raft_idx_and_term,
            last_block_stored,
        } = consensused;

        Self {
            sufficient_majority,
            current_block_num,
            current_block_complete_timeout_peer_ids: Default::default(),
            current_block_completed_parts: Default::default(),
            last_committed_raft_idx_and_term,
            last_block_stored,
        }
    }

    /// Convert to import type
    pub fn into_import(self) -> StorageConsensusedImport {
        StorageConsensusedImport {
            sufficient_majority: self.sufficient_majority,
            current_block_num: self.current_block_num,
            last_committed_raft_idx_and_term: self.last_committed_raft_idx_and_term,
            last_block_stored: self.last_block_stored,
        }
    }

    ///Returns a bool variable of whether or not the input value matches the current block number
    ///
    /// ### Arguments
    ///
    /// * `block_num` - u64 object to be compared to the current block number
    pub fn is_current_block(&self, block_num: u64) -> bool {
        block_num == self.current_block_num
    }

    ///Returns false is current block timeout peer ids length of this class is less than the sufficient_majority object of this class.
    /// Returns true if a calculated completed block length of this class is greater or equal to the sufficient_majority object of this class.
    ///
    pub fn has_block_ready_to_store(&self) -> bool {
        if self.current_block_complete_timeout_peer_ids.len() < self.sufficient_majority {
            return false;
        }

        let completed_blocks_len = self
            .current_block_completed_parts
            .values()
            .map(|v| v.per_node.len())
            .max()
            .unwrap_or(0);

        completed_blocks_len >= self.sufficient_majority
    }

    ///Inserts a prosper_id into the current_block_complete_timeout_peer_ids.
    /// proposer_id is take from key
    ///
    /// ### Arguments
    ///
    /// * `key` - Key containing the proposer_id to be appended.
    pub fn append_received_block_timeout(&mut self, key: RaftContextKey) {
        self.current_block_complete_timeout_peer_ids
            .insert(key.proposer_id);
    }

    ///Appends a RecievedBlock into the current_block_completed_parts
    ///
    /// ### Arguments
    ///
    /// * `key`   - Key containing the proposer_id to be appended.
    /// * `block` - RecievedBlock object that is being appended.
    pub fn append_received_block(&mut self, key: RaftContextKey, block: ReceivedBlock) {
        let block_ser = serialize(&block.common).unwrap();
        let block_hash = Sha3_256::digest(&block_ser).to_vec();

        let common = block.common;
        let node_info = block.per_node;
        let per_node = BTreeMap::new();
        self.current_block_completed_parts
            .entry(block_hash)
            .or_insert(CompleteBlock { common, per_node })
            .per_node
            .insert(key.proposer_id, node_info);
    }

    ///generates a completed block and returns it.
    pub fn generate_complete_block(&mut self) -> (CompleteBlock, u64) {
        self.current_block_num += 1;
        let _timeouts = std::mem::take(&mut self.current_block_complete_timeout_peer_ids);
        let completed_parts = std::mem::take(&mut self.current_block_completed_parts);

        let (_, complete_block) = completed_parts
            .into_iter()
            .max_by_key(|(_, v)| v.per_node.len())
            .unwrap();

        (complete_block, self.current_block_num)
    }

    /// Get the last block stored info to send to the compute nodes
    pub fn get_last_block_stored(&self) -> &Option<BlockStoredInfo> {
        &self.last_block_stored
    }
}
