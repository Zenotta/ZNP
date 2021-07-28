use std::collections::BTreeMap;

use crate::active_raft::ActiveRaft;
use crate::block_pipeline::MiningPipelineInfo;
use crate::configurations::ComputeNodeConfig;
use crate::constants::{BLOCK_SIZE_IN_TX, DB_PATH, TX_POOL_LIMIT};
use crate::db_utils::{self, SimpleDb, SimpleDbSpec};
use crate::interfaces::{BlockStoredInfo, MinedBlockExtraInfo, UtxoSet, WinningPoWInfo};
use crate::raft::{RaftCommit, RaftCommitData, RaftData, RaftMessageWrapper};
use crate::raft_util::{RaftContextKey, RaftInFlightProposals};
use crate::tracked_utxo::TrackedUtxoSet;
use crate::unicorn::Unicorn;
use crate::utils::{calculate_reward, get_total_coinbase_tokens, make_utxo_set_from_seed};
use bincode::{deserialize, serialize};
use naom::primitives::asset::TokenAmount;
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use naom::utils::transaction_utils::{construct_tx_hash, get_inputs_previous_out_point};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{self, Instant};
use tracing::{debug, error, trace, warn};

pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
    db_path: DB_PATH,
    suffix: ".compute_raft",
    columns: &[],
};

/// Item serialized into RaftData and process by Raft.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ComputeRaftItem {
    FirstBlock(BTreeMap<String, Transaction>),
    Block(BlockStoredInfo),
    Transactions(BTreeMap<String, Transaction>),
    DruidTransactions(Vec<BTreeMap<String, Transaction>>),
    MiningParticipant(SocketAddr),
    WinningPoW((SocketAddr, WinningPoWInfo)),
    ParticipantIntakeClosed,
}

/// Commited item to process.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommittedItem {
    Transactions,
    FirstBlock,
    Block,
    Snapshot,
    ParticipantIntakeClosed,
    WinningPoWIntakeClosed,
}

/// Accumulated previous block info
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AccumulatingBlockStoredInfo {
    /// Accumulating first block utxo_set
    FirstBlock(BTreeMap<String, Transaction>),
    /// Accumulating other blocks BlockStoredInfo
    Block(BlockStoredInfo),
}

/// Accumulated previous block info
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SpecialHandling {
    /// Shutting down on this block.
    Shutdown,
    /// Waiting for first block after an upgrade.
    FirstUpgradeBlock,
}

/// Initial proposal state: Need both miner ready and block info ready
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum InitialProposal {
    PendingAll,
    PendingAuthorized,
    PendingItem {
        item: ComputeRaftItem,
        dedup_b_num: Option<u64>,
    },
}

/// All fields that are consensused between the RAFT group.
/// These fields need to be written and read from a committed log event.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ComputeConsensused {
    /// Sufficient majority
    unanimous_majority: usize,
    /// Sufficient majority
    sufficient_majority: usize,
    /// Committed transaction pool.
    tx_pool: BTreeMap<String, Transaction>,
    /// Committed DRUID transactions.
    tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
    /// Header to use for next block if ready to generate.
    tx_current_block_previous_hash: Option<String>,
    /// Index of the last block,
    tx_current_block_num: Option<u64>,
    /// Current block ready to mine (consensused).
    current_block: Option<Block>,
    /// All transactions present in current_block (consensused).
    current_block_tx: BTreeMap<String, Transaction>,
    /// The very first block to consensus.
    initial_utxo_txs: Option<BTreeMap<String, Transaction>>,
    /// UTXO set containain the valid transaction to use as previous input hashes.
    utxo_set: TrackedUtxoSet,
    /// Accumulating block:
    /// Require majority of compute node votes for normal blocks.
    /// Require unanimit for first block.
    current_block_stored_info: BTreeMap<Vec<u8>, (AccumulatingBlockStoredInfo, BTreeSet<u64>)>,
    /// The last commited raft index.
    last_committed_raft_idx_and_term: (u64, u64),
    /// The current circulation of tokens
    current_circulation: TokenAmount,
    /// The first block run in the parallel pipeline
    first_block_pipeline: MiningPipelineInfo,
    /// The second block run in the parallel pipeline
    second_block_pipeline: MiningPipelineInfo,
    /// The current reward for a given compute node
    current_reward: TokenAmount,
    /// The last mining rewards.
    last_mining_transaction_hashes: Vec<String>,
    /// Special handling for processing blocks.
    special_handling: Option<SpecialHandling>,
}

/// Consensused info to apply on start up after upgrade.
pub struct ComputeConsensusedImport {
    pub unanimous_majority: usize,
    pub sufficient_majority: usize,
    pub tx_current_block_num: Option<u64>,
    pub current_block: Option<Block>,
    pub utxo_set: UtxoSet,
    pub last_committed_raft_idx_and_term: (u64, u64),
    pub current_circulation: TokenAmount,
    pub special_handling: Option<SpecialHandling>,
}

/// Consensused Compute fields and consensus management.
pub struct ComputeRaft {
    /// True if first peer (leader).
    first_raft_peer: bool,
    /// The raft instance to interact with.
    raft_active: ActiveRaft,
    /// Consensused fields.
    consensused: ComputeConsensused,
    /// Whether consensused received initial snapshot
    consensused_snapshot_applied: bool,
    /// Initial item to propose when ready.
    local_initial_proposal: Option<InitialProposal>,
    /// Local transaction pool.
    local_tx_pool: BTreeMap<String, Transaction>,
    /// Local DRUID transaction pool.
    local_tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
    /// Ordered transaction hashes from the last commit.
    local_tx_hash_last_commited: Vec<String>,
    /// Min duration between each transaction poposal.
    propose_transactions_timeout_duration: Duration,
    /// Timeout expiration time for transactions poposal.
    propose_transactions_timeout_at: Instant,
    /// Proposed items in flight.
    proposed_in_flight: RaftInFlightProposals,
    /// Proposed transaction in flight length.
    proposed_tx_pool_len: usize,
    /// Maximum transaction in flight length.
    proposed_tx_pool_len_max: usize,
    /// Maximum number of mining participants for a given round
    participant_list_max: usize,
    /// Maximum transaction consensused and in flight for proposing more.
    proposed_and_consensused_tx_pool_len_max: usize,
    /// No longer process commits after shutdown reached
    shutdown_no_commit_process: bool,
}

impl fmt::Debug for ComputeRaft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ComputeRaft()")
    }
}

impl ComputeRaft {
    /// Create a ComputeRaft, need to spawn the raft loop to use raft.
    ///
    /// ### Arguments
    ///
    /// * `config`  - Configuration option for a computer node.
    /// * `raft_db` - Override raft db to use.
    pub async fn new(config: &ComputeNodeConfig, raft_db: Option<SimpleDb>) -> Self {
        let use_raft = config.compute_raft != 0;
        let raft_active = ActiveRaft::new(
            config.compute_node_idx,
            &config.compute_nodes,
            use_raft,
            Duration::from_millis(config.compute_raft_tick_timeout as u64),
            db_utils::new_db(config.compute_db_mode, &DB_SPEC, raft_db),
        );

        let propose_transactions_timeout_duration =
            Duration::from_millis(config.compute_transaction_timeout as u64);
        let propose_transactions_timeout_at = Instant::now();

        let utxo_set =
            make_utxo_set_from_seed(&config.compute_seed_utxo, &config.compute_genesis_tx_in);

        let first_raft_peer = config.compute_node_idx == 0 || !raft_active.use_raft();
        let peers_len = raft_active.peers_len();

        let consensused = ComputeConsensused::default().with_peers_len(peers_len);
        let local_initial_proposal = Some(InitialProposal::PendingItem {
            item: ComputeRaftItem::FirstBlock(utxo_set),
            dedup_b_num: None,
        });

        Self {
            first_raft_peer,
            raft_active,
            consensused,
            consensused_snapshot_applied: !use_raft,
            local_initial_proposal,
            local_tx_pool: Default::default(),
            local_tx_druid_pool: Default::default(),
            local_tx_hash_last_commited: Default::default(),
            propose_transactions_timeout_duration,
            propose_transactions_timeout_at,
            proposed_in_flight: Default::default(),
            proposed_tx_pool_len: 0,
            participant_list_max: config.compute_partition_full_size,
            proposed_tx_pool_len_max: BLOCK_SIZE_IN_TX / peers_len,
            proposed_and_consensused_tx_pool_len_max: BLOCK_SIZE_IN_TX * 2,
            shutdown_no_commit_process: false,
        }
    }

    /// Set the key run for all proposals (load from db before first proposal).
    pub fn set_key_run(&mut self, key_run: u64) {
        self.proposed_in_flight.set_key_run(key_run)
    }

    /// Mark the initial proposal as done (first block after start or upgrade).
    pub fn set_initial_proposal_done(&mut self) {
        self.local_initial_proposal = None;
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
    /// Return Some CommitedIten if block to mine is ready to generate. Returns 'not implemented' if not implemented
    /// ### Arguments
    /// * 'raft_commit' - a RaftCommit struct from the raft.rs class to be proposed to commit.
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
            self.propose_transactions_timeout_at = self.next_propose_transactions_timeout_at();
            None
        } else {
            // Non empty snapshot
            warn!("apply_snapshot called self.consensused updated");
            self.consensused = deserialize(&consensused_ser).unwrap();
            self.propose_transactions_timeout_at = self.next_propose_transactions_timeout_at();
            if let Some(proposal) = &mut self.local_initial_proposal {
                *proposal = InitialProposal::PendingAll;
            }
            Some(CommittedItem::Snapshot)
        }
    }

    /// Process data in RaftData.
    /// Return Some CommitedItem if block to mine is ready to generate or none if there is a deserialize error.
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
        let (key, item, removed) = self
            .proposed_in_flight
            .received_commit_proposal(&raft_data, &raft_ctx)
            .await?;
        if removed {
            if let ComputeRaftItem::Transactions(ref txs) = &item {
                self.proposed_tx_pool_len -= txs.len();
            }
        }

        trace!("received_commit_proposal {:?} -> {:?}", key, item);
        match item {
            ComputeRaftItem::FirstBlock(uxto_set) => {
                if !self.consensused.is_first_block() {
                    error!("Proposed FirstBlock after startup {:?}", key);
                    return None;
                }

                self.consensused.append_first_block_info(key, uxto_set);
                if self.consensused.has_different_block_stored_info() {
                    error!("Proposed uxtosets are different {:?}", key);
                }

                if self.consensused.has_block_stored_info_ready() {
                    // First block complete:
                    let b_num = self.consensused.apply_ready_block_stored_info();
                    self.proposed_in_flight.ignore_dedeup_b_num_less_than(b_num);
                    return Some(CommittedItem::FirstBlock);
                }
            }
            ComputeRaftItem::Transactions(mut txs) => {
                self.local_tx_hash_last_commited = txs.keys().cloned().collect();
                self.consensused.tx_pool.append(&mut txs);
                return Some(CommittedItem::Transactions);
            }
            ComputeRaftItem::DruidTransactions(mut txs) => {
                self.consensused.tx_druid_pool.append(&mut txs);
                return Some(CommittedItem::Transactions);
            }
            ComputeRaftItem::ParticipantIntakeClosed => {
                return Some(CommittedItem::ParticipantIntakeClosed);
            }
            ComputeRaftItem::MiningParticipant(addr) => {
                // Start countdown for first participant (best way to handle this countdown?)
                if self.consensused.first_block_pipeline.participant_len() == 0 {
                    self.timeout_miner_selection().await;
                }

                match self
                    .consensused
                    .first_block_pipeline
                    .add_to_participants(addr)
                {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                };
            }
            ComputeRaftItem::WinningPoW((addr, info)) => {
                match self
                    .consensused
                    .first_block_pipeline
                    .add_to_winning_pow((addr, info))
                {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                };
            }
            ComputeRaftItem::Block(info) => {
                if !self.consensused.is_current_block(info.block_num) {
                    // Ignore already known or invalid blocks
                    trace!("Ignore invalid or outdated block stored info {:?}", key);
                    return None;
                }

                self.consensused.append_block_stored_info(key, info);
                if self.consensused.has_different_block_stored_info() {
                    warn!("Proposed previous blocks are different {:?}", key);
                }

                if self.consensused.has_block_stored_info_ready() {
                    // New block:
                    // Must not populate further tx_pool & tx_druid_pool
                    // before generating block.
                    let b_num = self.consensused.apply_ready_block_stored_info();
                    self.proposed_in_flight.ignore_dedeup_b_num_less_than(b_num);
                    return Some(CommittedItem::Block);
                }
            }
        }
        None
    }

    /// Blocks & waits for a next message to dispatch from a peer.
    /// Message needs to be sent to given peer address.
    pub async fn next_msg(&self) -> Option<(SocketAddr, RaftMessageWrapper)> {
        self.raft_active.next_msg().await
    }

    /// Process a raft message: send to spawned raft loop.
    /// ### Arguments
    /// * `msg`   - holds the recieved message in a RaftMessageWrapper.
    pub async fn received_message(&mut self, msg: RaftMessageWrapper) {
        self.raft_active.received_message(msg).await
    }

    /// Blocks & waits for a timeout to propose transactions.
    pub async fn timeout_propose_transactions(&self) {
        time::sleep_until(self.propose_transactions_timeout_at).await;
    }

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    pub async fn propose_initial_item(&mut self) {
        self.local_initial_proposal = match self.local_initial_proposal.take() {
            Some(InitialProposal::PendingAll) => Some(InitialProposal::PendingAuthorized),
            Some(InitialProposal::PendingItem { item, dedup_b_num }) => {
                if let Some(b_num) = dedup_b_num {
                    self.propose_item_dedup(&item, b_num).await.unwrap();
                } else {
                    self.propose_item(&item).await;
                }
                None
            }
            Some(InitialProposal::PendingAuthorized) | None => {
                panic!("propose_initial_item called again")
            }
        };
    }

    pub async fn timeout_miner_selection(&mut self) {
        let _ = time::timeout(
            Duration::from_millis(1000),
            self.propose_participant_intake_closed(),
        )
        .await;
    }

    /// Process as received block info necessary for new block to be generated.
    pub async fn propose_block_with_last_info(&mut self, block: BlockStoredInfo) -> bool {
        let b_num = block.block_num;
        let item = ComputeRaftItem::Block(block);

        match self.local_initial_proposal {
            None | Some(InitialProposal::PendingAuthorized) => {
                self.local_initial_proposal = None;
                self.propose_item_dedup(&item, b_num).await.is_some()
            }
            Some(InitialProposal::PendingAll) | Some(InitialProposal::PendingItem { .. }) => {
                let dedup_b_num = Some(b_num);
                let proposal = Some(InitialProposal::PendingItem { item, dedup_b_num });

                let old = std::mem::replace(&mut self.local_initial_proposal, proposal);
                old != self.local_initial_proposal
            }
        }
    }

    ///Returns the clock time after the proposed block time out
    fn next_propose_transactions_timeout_at(&self) -> Instant {
        Instant::now() + self.propose_transactions_timeout_duration
    }

    async fn propose_participant_intake_closed(&mut self) {
        self.propose_item(&ComputeRaftItem::ParticipantIntakeClosed)
            .await;
    }

    /// Propose an incoming miner for entry into the mining pipelines
    pub async fn propose_mining_participant(&mut self, entry: SocketAddr) {
        self.propose_item(&ComputeRaftItem::MiningParticipant(entry))
            .await;
    }

    /// Propose a winning PoW for entry into the mining pipelines
    pub async fn propose_winning_pow(&mut self, winning_pow: (SocketAddr, WinningPoWInfo)) {
        self.propose_item(&ComputeRaftItem::WinningPoW(winning_pow))
            .await;
    }

    /// Process as a result of timeout_propose_transactions.
    /// Reset timeout, and propose local transactions if available.
    pub async fn propose_local_transactions_at_timeout(&mut self) {
        self.propose_transactions_timeout_at = self.next_propose_transactions_timeout_at();

        let max_add = self
            .proposed_and_consensused_tx_pool_len_max
            .saturating_sub(self.proposed_and_consensused_tx_pool_len());

        let max_propose_len = std::cmp::min(max_add, self.proposed_tx_pool_len_max);
        let txs = take_first_n(max_propose_len, &mut self.local_tx_pool);
        if !txs.is_empty() {
            self.proposed_tx_pool_len += txs.len();
            self.propose_item(&ComputeRaftItem::Transactions(txs)).await;
        }
    }

    /// Process as a result of timeout_propose_transactions.
    /// Propose druid transactions if available.
    pub async fn propose_local_druid_transactions(&mut self) {
        let txs = std::mem::take(&mut self.local_tx_druid_pool);
        if !txs.is_empty() {
            self.propose_item(&ComputeRaftItem::DruidTransactions(txs))
                .await;
        }
    }

    /// Re-propose uncommited items relevant for current block.
    pub async fn re_propose_uncommitted_current_b_num(&mut self) {
        self.proposed_in_flight
            .re_propose_uncommitted_current_b_num(
                &mut self.raft_active,
                self.consensused.tx_current_block_num.unwrap(),
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
        item: &ComputeRaftItem,
        b_num: u64,
    ) -> Option<RaftContextKey> {
        self.proposed_in_flight
            .propose_item(&mut self.raft_active, item, Some(b_num))
            .await
    }

    /// Propose an item to raft if use_raft, or commit it otherwise.
    ///
    /// ### Arguments
    ///
    /// * `item` - The item to be proposed to a raft.
    async fn propose_item(&mut self, item: &ComputeRaftItem) -> RaftContextKey {
        self.proposed_in_flight
            .propose_item(&mut self.raft_active, item, None)
            .await
            .unwrap()
    }

    pub fn get_current_unicorn(&self) -> &Unicorn {
        self.consensused.first_block_pipeline.get_unicorn()
    }

    pub fn get_mined_block_extra_info(&mut self) -> MinedBlockExtraInfo {
        self.consensused.get_mined_block_extra_info()
    }

    pub fn get_mining_participants(&self) -> &Vec<SocketAddr> {
        self.consensused.get_mining_participants()
    }

    /// The current tx_pool that will be used to generate next block
    /// Returns a BTreeMap reference which contains a String and a Transaction.
    pub fn get_committed_tx_pool(&self) -> &BTreeMap<String, Transaction> {
        &self.consensused.tx_pool
    }

    /// The current tx_druid_pool that will be used to generate next block
    /// Returns a Vec<BTreeMap> reference which contains a String and a Transaction.
    pub fn get_committed_tx_druid_pool(&self) -> &Vec<BTreeMap<String, Transaction>> {
        &self.consensused.tx_druid_pool
    }

    /// Gets the current number of tokens in circulation
    pub fn get_current_circulation(&self) -> &TokenAmount {
        &self.consensused.current_circulation
    }

    /// Gets the current reward for a given block
    pub fn get_current_reward(&self) -> &TokenAmount {
        &self.consensused.current_reward
    }

    /// Whether adding these will grow our pool within the limit. Returns a bool.
    pub fn tx_pool_can_accept(&self, extra_len: usize) -> bool {
        self.combined_tx_pool_len() + extra_len <= TX_POOL_LIMIT
    }

    /// Current tx_pool lenght handled by this node.
    fn combined_tx_pool_len(&self) -> usize {
        self.local_tx_pool.len() + self.proposed_and_consensused_tx_pool_len()
    }

    /// Current proposed tx_pool lenght handled by this node.
    fn proposed_and_consensused_tx_pool_len(&self) -> usize {
        self.proposed_tx_pool_len + self.consensused.tx_pool.len()
    }

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    /// ### Arguments
    /// * 'transactions' - a mutable BTreeMap that has a String and a Transaction parameters
    pub fn append_to_tx_pool(&mut self, mut transactions: BTreeMap<String, Transaction>) {
        self.local_tx_pool.append(&mut transactions);
    }

    /// Append

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    pub fn append_to_tx_druid_pool(&mut self, transactions: BTreeMap<String, Transaction>) {
        self.local_tx_druid_pool.push(transactions);
    }

    /// Set consensused committed block to mine.
    /// Internal call, public for test only.
    pub fn set_committed_mining_block(
        &mut self,
        block: Block,
        block_tx: BTreeMap<String, Transaction>,
    ) {
        self.consensused.set_committed_mining_block(block, block_tx)
    }

    /// Current block to mine or being mined.
    pub fn get_mining_block(&self) -> &Option<Block> {
        self.consensused.get_mining_block()
    }

    /// Current block number
    pub fn get_current_block_num(&self) -> u64 {
        if let Some(block) = self.consensused.get_mining_block() {
            block.header.b_num
        } else {
            0
        }
    }

    /// Current utxo_set returned as `UtxoSet` including block being mined
    pub fn get_committed_utxo_set(&self) -> &UtxoSet {
        self.consensused.get_committed_utxo_set()
    }

    /// Current utxo_set returned as `TrackedUtxoSet`
    pub fn get_committed_utxo_tracked_set(&self) -> &TrackedUtxoSet {
        self.consensused.get_committed_utxo_tracked_set()
    }

    /// Take mining block when mining is completed, use to populate mined block.
    pub fn take_mining_block(&mut self) -> (Block, BTreeMap<String, Transaction>) {
        self.consensused.take_mining_block()
    }

    /// Take all the transactions hashes last commited
    pub fn take_local_tx_hash_last_commited(&mut self) -> Vec<String> {
        std::mem::take(&mut self.local_tx_hash_last_commited)
    }

    /// Generate a snapshot, needs to happen at the end of the event processing.
    pub fn event_processed_generate_snapshot(&mut self) {
        let consensused_ser = serialize(&self.consensused).unwrap();
        let (snapshot_idx, term) = self.consensused.last_committed_raft_idx_and_term;

        debug!("generate_snapshot: (idx: {}, term: {})", snapshot_idx, term);
        self.raft_active
            .create_snapshot(snapshot_idx, consensused_ser);

        if self.is_shutdown_on_commit() {
            self.shutdown_no_commit_process = true;
        }
    }

    /// Processes the very first block with utxo_set
    pub fn generate_first_block(&mut self) {
        self.consensused.generate_first_block()
    }

    /// Processes the next batch of transactions from the floating tx pool
    /// to create the next block
    pub async fn generate_block(&mut self) {
        self.consensused.generate_block().await
    }

    /// Find transactions for the current block.
    /// ### Arguments
    ///
    /// * `new_txs`   - BTreeMap reference that has a String and a Transaction parameters
    pub fn find_invalid_new_txs(&self, new_txs: &BTreeMap<String, Transaction>) -> Vec<String> {
        self.consensused.find_invalid_new_txs(new_txs)
    }

    /// Get the current consensued block num.
    pub fn get_committed_current_block_num(&self) -> Option<u64> {
        self.consensused.tx_current_block_num
    }

    /// The mining transactions accepted for previous block
    pub fn get_last_mining_transaction_hashes(&self) -> &Vec<String> {
        &self.consensused.last_mining_transaction_hashes
    }

    /// Whether to shutdown when block committed
    pub fn is_shutdown_on_commit(&self) -> bool {
        self.consensused.special_handling == Some(SpecialHandling::Shutdown)
    }

    /// Whether shut down block already processed
    pub fn is_shutdown_commit_processed(&self) -> bool {
        self.shutdown_no_commit_process
    }
}

impl ComputeConsensused {
    /// Specify the raft group size
    pub fn with_peers_len(mut self, peers_len: usize) -> Self {
        self.unanimous_majority = peers_len;
        self.sufficient_majority = peers_len / 2 + 1;
        self
    }

    /// Create ComputeConsensused from imported data in upgrade
    pub fn from_import(consensused: ComputeConsensusedImport) -> Self {
        let ComputeConsensusedImport {
            unanimous_majority,
            sufficient_majority,
            tx_current_block_num,
            current_block,
            utxo_set,
            last_committed_raft_idx_and_term,
            current_circulation,
            special_handling,
        } = consensused;

        Self {
            unanimous_majority,
            sufficient_majority,
            tx_pool: Default::default(),
            tx_druid_pool: Default::default(),
            tx_current_block_previous_hash: Default::default(),
            tx_current_block_num,
            current_block,
            current_block_tx: Default::default(),
            initial_utxo_txs: Default::default(),
            utxo_set: TrackedUtxoSet::new(utxo_set),
            current_block_stored_info: Default::default(),
            last_committed_raft_idx_and_term,
            current_circulation,
            first_block_pipeline: Default::default(),
            second_block_pipeline: Default::default(),
            current_reward: Default::default(),
            last_mining_transaction_hashes: Default::default(),
            special_handling,
        }
    }

    /// Convert to import type
    pub fn into_import(
        self,
        special_handling: Option<SpecialHandling>,
    ) -> ComputeConsensusedImport {
        ComputeConsensusedImport {
            unanimous_majority: self.unanimous_majority,
            sufficient_majority: self.sufficient_majority,
            tx_current_block_num: self.tx_current_block_num,
            current_block: self.current_block,
            utxo_set: self.utxo_set.into_utxoset(),
            last_committed_raft_idx_and_term: self.last_committed_raft_idx_and_term,
            current_circulation: self.current_circulation,
            special_handling,
        }
    }

    /// Set consensused committed block to mine.
    /// Internal call, public for test only.
    /// ### Arguments
    /// * `block`   - mining Block to be set to be comitted
    /// * `block_tx`   - BTreeMap associated with Block to be set to be comitted.
    pub fn set_committed_mining_block(
        &mut self,
        block: Block,
        block_tx: BTreeMap<String, Transaction>,
    ) {
        // Transaction only depend on mined block: append at the end.
        // The block is about to be mined, all transaction accepted can be used
        // to accept next block transactions.
        // TODO: Roll back append and removal if block rejected by miners.
        let tx_inputs: Vec<String> = self.tx_pool.keys().cloned().collect();

        self.utxo_set.extend_tracked_utxo_set(&block_tx);

        self.current_block = Some(block);
        self.current_block_tx = block_tx;
        self.first_block_pipeline.construct_unicorn(&tx_inputs);
    }

    /// Get the current mining participants
    pub fn get_mining_participants(&self) -> &Vec<SocketAddr> {
        self.first_block_pipeline.get_participants()
    }

    /// Current block to mine or being mined.
    pub fn get_mining_block(&self) -> &Option<Block> {
        &self.current_block
    }

    /// Current number of tokens in circulation
    pub fn get_current_circulation(&self) -> &TokenAmount {
        &self.current_circulation
    }

    /// Current utxo_set including block being mined
    pub fn get_committed_utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }

    /// Current tracked UTXO set
    pub fn get_committed_utxo_tracked_set(&self) -> &TrackedUtxoSet {
        &self.utxo_set
    }

    /// Gets all the required extra info for the current block, to be saved to storage
    pub fn get_mined_block_extra_info(&mut self) -> MinedBlockExtraInfo {
        // TODO: This needs to be done externally
        let win = self.first_block_pipeline.select_winning_miner();

        if let Some((_addr, info)) = win {
            let cb_hash = construct_tx_hash(&info.coinbase);

            MinedBlockExtraInfo {
                nonce: info.nonce,
                mining_tx: (cb_hash, info.coinbase),
                p_value: info.p_value,
                d_value: info.d_value,
                shutdown: false,
                witness: self.first_block_pipeline.get_unicorn_witness(),
                unicorn: self.first_block_pipeline.get_unicorn().clone(),
            }
        } else {
            // TODO: Replace with restart of pipeline
            panic!("No winner found");
        }
    }

    /// Take mining block when mining is completed, use to populate mined block.
    pub fn take_mining_block(&mut self) -> (Block, BTreeMap<String, Transaction>) {
        let block = std::mem::take(&mut self.current_block).unwrap();
        let block_tx = std::mem::take(&mut self.current_block_tx);
        (block, block_tx)
    }

    /// Processes the very first block with utxo_set
    pub fn generate_first_block(&mut self) {
        let next_block_tx = self.initial_utxo_txs.take().unwrap();
        let next_block = Block {
            transactions: next_block_tx.keys().cloned().collect(),
            ..Default::default()
        };

        self.set_committed_mining_block(next_block, next_block_tx)
    }

    /// Processes the next batch of transactions from the floating tx pool
    /// to create the next block
    ///
    /// TODO: Label previous block time
    pub async fn generate_block(&mut self) {
        let mut next_block = Block::new();
        let mut next_block_tx = BTreeMap::new();

        self.update_committed_dde_tx(&mut next_block, &mut next_block_tx);
        self.update_current_block_tx(&mut next_block, &mut next_block_tx);
        self.update_block_header(&mut next_block).await;

        self.set_committed_mining_block(next_block, next_block_tx)
    }

    /// Apply all consensused transactions to the block
    /// ### Arguments
    ///
    /// * `block`   - commited Block to be set to be updated
    /// * `block_tx`   - BTreeMap associated with Block to be set to be updated.
    fn update_committed_dde_tx(
        &mut self,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        let mut tx_druid_pool = std::mem::take(&mut self.tx_druid_pool);
        for txs in tx_druid_pool.drain(..) {
            if !self.find_invalid_new_txs(&txs).is_empty() {
                // Drop invalid DRUID droplet
                continue;
            }

            // Process valid set of transactions from a single DRUID droplet.
            self.update_current_block_tx_with_given_valid_txs(txs, block, block_tx);
        }
    }

    /// Apply all valid consensused transactions to the block until BLOCK_SIZE_IN_TX
    /// ### Arguments
    ///
    /// * `block`   - current Block to be set to be updated
    /// * `block_tx`   - BTreeMap associated with Block to be set to be updated.
    fn update_current_block_tx(
        &mut self,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        // Clean tx_pool of invalid transactions for this block.
        for invalid in self.find_invalid_new_txs(&self.tx_pool) {
            self.tx_pool.remove(&invalid);
        }

        // Select subset of transaction to fill the block.
        let txs = take_first_n(BLOCK_SIZE_IN_TX, &mut self.tx_pool);

        // Process valid set of transactions.
        self.update_current_block_tx_with_given_valid_txs(txs, block, block_tx);
    }

    /// Apply the consensused information for the header.
    /// ### Arguments
    ///
    /// * `block`   - Block to be set to be updated
    async fn update_block_header(&mut self, block: &mut Block) {
        let previous_hash = std::mem::take(&mut self.tx_current_block_previous_hash).unwrap();
        let b_num = self.tx_current_block_num.unwrap();

        block.header.previous_hash = Some(previous_hash);
        block.header.b_num = b_num;
        block.set_merkle_root().await;
    }

    /// Apply set of valid transactions to the block.
    ///
    /// ### Arguments
    ///
    /// * `txs`   - given valid BTreeMap of transactions to apply to block
    /// * `block`   - current Block to be to be updated
    /// * `block_tx`   - Block BTreeMap to be to be updated
    fn update_current_block_tx_with_given_valid_txs(
        &mut self,
        mut txs: BTreeMap<String, Transaction>,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        for hash in get_inputs_previous_out_point(txs.values()) {
            // All previous hash in valid txs set are present and must be removed.
            self.utxo_set.remove_tracked_utxo_entry(hash);
        }
        block.transactions.extend(txs.keys().cloned());
        block_tx.append(&mut txs);
    }

    /// Find transactions for the current block.
    /// Finds and returns invalid transactions
    /// ### Arguments
    ///
    /// * `new_txs` - Transactions being iterated through and checked
    pub fn find_invalid_new_txs(&self, new_txs: &BTreeMap<String, Transaction>) -> Vec<String> {
        let mut invalid = Vec::new();

        let mut removed_all = HashSet::new();
        for (hash_tx, value) in new_txs.iter() {
            let mut removed_roll_back = Vec::new();

            for hash_in in get_inputs_previous_out_point(Some(value).into_iter()) {
                if self.utxo_set.contains_key(hash_in) && removed_all.insert(hash_in) {
                    removed_roll_back.push(hash_in);
                } else {
                    // Entry is invalid: roll back, mark entry and check next one.
                    for h in removed_roll_back {
                        removed_all.remove(h);
                    }
                    invalid.push(hash_tx.clone());
                    break;
                }
            }
        }

        invalid
    }

    /// Check if computing the first block.
    pub fn is_first_block(&self) -> bool {
        self.tx_current_block_num.is_none()
    }

    /// Check if computing the given block.
    /// ### Arguments
    ///
    /// * `block_num`   - u64 sequence number for the block to be checked
    pub fn is_current_block(&self, block_num: u64) -> bool {
        if let Some(tx_current_block_num) = self.tx_current_block_num {
            block_num == tx_current_block_num
        } else {
            false
        }
    }

    /// Check if we have inconsistent votes for the current block stored info.
    pub fn has_different_block_stored_info(&self) -> bool {
        self.current_block_stored_info.len() > 1
    }

    /// Check if we have enough votes to apply the block stored info.
    pub fn has_block_stored_info_ready(&self) -> bool {
        let threshold = if self.is_first_block() {
            self.unanimous_majority
        } else {
            self.sufficient_majority
        };

        self.max_agreeing_block_stored_info() >= threshold
    }

    /// Current maximum vote count for a block stored info.
    fn max_agreeing_block_stored_info(&self) -> usize {
        self.current_block_stored_info
            .values()
            .map(|v| v.1.len())
            .max()
            .unwrap_or(0)
    }

    /// Append a vote for first block info
    ///
    /// ### Arguments
    ///
    /// * `key`      - Key object of the first block
    /// * `utxo_set` - Transaction BTreeMap of the first block.
    pub fn append_first_block_info(
        &mut self,
        key: RaftContextKey,
        utxo_set: BTreeMap<String, Transaction>,
    ) {
        self.append_current_block_stored_info(
            key,
            AccumulatingBlockStoredInfo::FirstBlock(utxo_set),
        )
    }

    /// Append a vote for a non first block info
    ///
    /// ### Arguments
    ///
    /// * `key`   - Key object of the block to append
    /// * `block` - BlockStoredInfo to be appended.
    pub fn append_block_stored_info(&mut self, key: RaftContextKey, block: BlockStoredInfo) {
        self.append_current_block_stored_info(key, AccumulatingBlockStoredInfo::Block(block))
    }

    /// Append the given vote.
    ///     
    /// ### Arguments
    ///
    /// * `key`   - Key object of the block to append
    /// * `block` - AccumulatingBlockStoredInfo to be appended.
    pub fn append_current_block_stored_info(
        &mut self,
        key: RaftContextKey,
        block: AccumulatingBlockStoredInfo,
    ) {
        let block_ser = serialize(&block).unwrap();
        let block_hash = Sha3_256::digest(&block_ser).to_vec();

        self.current_block_stored_info
            .entry(block_hash)
            .or_insert((block, BTreeSet::new()))
            .1
            .insert(key.proposer_id);
    }

    /// Apply accumulated block info.
    pub fn apply_ready_block_stored_info(&mut self) -> u64 {
        // Reset block if not mined
        self.current_block = Default::default();
        self.current_block_tx = Default::default();

        match self.take_ready_block_stored_info() {
            AccumulatingBlockStoredInfo::FirstBlock(utxo_set) => {
                self.current_circulation = get_total_coinbase_tokens(&utxo_set);
                self.tx_current_block_num = Some(0);
                self.initial_utxo_txs = Some(utxo_set);
            }
            AccumulatingBlockStoredInfo::Block(info) => {
                if self.special_handling.is_none() && info.shutdown {
                    // Coordinated Shutdown for upgrade: Do not process this block until restart
                    // If we just restarted from shutdown, ignore it as it is the block that shut us down
                    self.special_handling = Some(SpecialHandling::Shutdown);
                    return info.block_num + 1;
                }

                self.special_handling = None;
                self.current_circulation += get_total_coinbase_tokens(&info.mining_transactions);
                self.tx_current_block_previous_hash = Some(info.block_hash);
                self.tx_current_block_num = Some(info.block_num + 1);
                self.utxo_set
                    .extend_tracked_utxo_set(&info.mining_transactions);
                self.last_mining_transaction_hashes =
                    info.mining_transactions.keys().cloned().collect();
            }
        }

        self.current_reward =
            calculate_reward(self.current_circulation) / self.unanimous_majority as u64;
        self.tx_current_block_num.unwrap()
    }

    /// Take the block info with most vote and reset accumulator.
    fn take_ready_block_stored_info(&mut self) -> AccumulatingBlockStoredInfo {
        let infos = std::mem::take(&mut self.current_block_stored_info);
        infos
            .into_iter()
            .map(|(_digest, value)| value)
            .max_by_key(|(_, vote_ids)| vote_ids.len())
            .map(|(block_info, _)| block_info)
            .unwrap()
    }
}

/// Take the first `n` items of the given map.
/// ### Arguments
///
/// * `n`   - number of items
/// * `from` - BTreeMap for values to be taken from
fn take_first_n<K: Clone + Ord, V>(n: usize, from: &mut BTreeMap<K, V>) -> BTreeMap<K, V> {
    let mut result = std::mem::take(from);
    if let Some(max_key) = result.keys().nth(n).cloned() {
        // Set back overflowing in from.
        *from = result.split_off(&max_key);
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::configurations::{DbMode, NodeSpec, TxOutSpec};
    use crate::utils::create_valid_transaction;
    use naom::crypto::sign_ed25519 as sign;
    use naom::primitives::asset::TokenAmount;
    use rug::Integer;
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn generate_first_block_no_raft() {
        //
        // Arrange
        //
        let seed_utxo = ["000000", "000001", "000002"];
        let mut node = new_test_node(&seed_utxo).await;
        let mut expected_block_addr_to_hashes = BTreeMap::new();

        // 1. Add 2 valid and 2 double spend and one spent transactions
        // Keep only 2 valids, and first double spent by hash.
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003"],
            &["000100", "000101", "000103"],
            &mut expected_block_addr_to_hashes,
        ));

        //
        // Act
        //
        node.propose_initial_item().await;
        node.propose_local_transactions_at_timeout().await;
        node.propose_local_druid_transactions().await;

        let commit = node.next_commit().await.unwrap();
        let first_block = node.received_commit(commit).await;
        node.generate_first_block();
        let commit = node.next_commit().await.unwrap();
        let tx_no_block = node.received_commit(commit).await;

        //
        // Assert
        //
        let expected_utxo_t_hashes: BTreeSet<String> =
            seed_utxo.iter().map(|h| h.to_string()).collect();

        let actual_utxo_t_hashes: BTreeSet<String> = node
            .get_committed_utxo_set()
            .keys()
            .map(|k| &k.t_hash)
            .cloned()
            .collect();

        assert_eq!(first_block, Some(CommittedItem::FirstBlock));
        assert_eq!(tx_no_block, Some(CommittedItem::Transactions));
        assert_eq!(actual_utxo_t_hashes, expected_utxo_t_hashes);
        assert_eq!(
            node.consensused.tx_pool.len(),
            expected_block_addr_to_hashes.len()
        );
        assert_eq!(node.consensused.tx_current_block_previous_hash, None);
    }

    #[tokio::test]
    async fn generate_current_block_no_raft() {
        //
        // Arrange
        //
        let seed_utxo = [
            // 1: (Skip "000003")
            "000000", "000001", "000002", // 2: (Skip "000012")
            "000010", "000011", // 3:
            "000020", "000021", "000023", // 4:
            "000030", "000031",
        ];
        let mut node = new_test_node(&seed_utxo).await;
        let mut expected_block_addr_to_hashes = BTreeMap::new();
        let mut expected_unused_utxo_hashes = Vec::<&str>::new();

        node.propose_initial_item().await;
        let commit = node.next_commit().await.unwrap();
        let _first_block = node.received_commit(commit).await.unwrap();
        node.generate_first_block();
        let previous_block = BlockStoredInfo {
            block_hash: "0123".to_string(),
            block_num: 0,
            nonce: vec![0],
            merkle_hash: "0123".to_string(),
            mining_transactions: BTreeMap::new(),
            shutdown: false,
        };

        // 1. Add 2 valid and 2 double spend and one spent transactions
        // Keep only 2 valids, and first double spent by hash.
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003"],
            &["000100", "000101", "000103"],
            &mut expected_block_addr_to_hashes,
        ));
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000002"],
            &["000200", "000202"],
            &mut expected_block_addr_to_hashes,
        ));
        expected_block_addr_to_hashes.remove(key_with_max_value(
            &expected_block_addr_to_hashes,
            "000100",
            "000200",
        ));
        expected_block_addr_to_hashes.remove("000103");
        // 2. Add double spend and spent within DRUID droplet
        // Drop all
        node.append_to_tx_druid_pool(valid_transaction(
            &["000010", "000010"],
            &["000310", "000311"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000011", "000012"],
            &["000311", "000312"],
            &mut BTreeMap::new(),
        ));
        expected_unused_utxo_hashes.extend(&["000010", "000011"]);
        // 3. Add double spend between DRUID droplet
        // Keep first one added
        node.append_to_tx_druid_pool(valid_transaction(
            &["000020", "000023"],
            &["000420", "000423"],
            &mut expected_block_addr_to_hashes,
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000021", "000023"],
            &["000521", "000523"],
            &mut BTreeMap::new(),
        ));
        expected_unused_utxo_hashes.extend(&["000021"]);
        // 4. Add double spend between DRUID droplet and transaction
        // Keep DRUID droplet
        node.append_to_tx_pool(valid_transaction(
            &["000030"],
            &["000621"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000030", "000031"],
            &["000730", "000731"],
            &mut expected_block_addr_to_hashes,
        ));

        //
        // Act
        //
        node.propose_local_transactions_at_timeout().await;
        node.propose_local_druid_transactions().await;

        node.propose_block_with_last_info(previous_block).await;
        let mut commits = Vec::new();
        for _ in 0..3 {
            let commit = node.next_commit().await.unwrap();
            commits.push(node.received_commit(commit).await.unwrap());
        }
        node.generate_block().await;

        //
        // Assert
        //
        let expected_block_t_hashes: BTreeSet<String> =
            expected_block_addr_to_hashes.values().cloned().collect();
        let expected_utxo_t_hashes: BTreeSet<String> = expected_unused_utxo_hashes
            .iter()
            .map(|h| h.to_string())
            .chain(expected_block_t_hashes.iter().cloned())
            .collect();

        let actual_block_t_hashes: Option<BTreeSet<String>> = node
            .get_mining_block()
            .as_ref()
            .map(|b| b.transactions.iter().cloned().collect());
        let actual_block_tx_t_hashes: BTreeSet<String> =
            node.consensused.current_block_tx.keys().cloned().collect();
        let actual_utxo_t_hashes: BTreeSet<String> = node
            .get_committed_utxo_set()
            .keys()
            .map(|k| &k.t_hash)
            .cloned()
            .collect();

        assert_eq!(
            commits,
            vec![
                CommittedItem::Transactions,
                CommittedItem::Transactions,
                CommittedItem::Block
            ]
        );
        assert_eq!(Some(expected_block_t_hashes.clone()), actual_block_t_hashes);
        assert_eq!(expected_block_t_hashes, actual_block_tx_t_hashes);
        assert_eq!(actual_utxo_t_hashes, expected_utxo_t_hashes);
        assert_eq!(node.consensused.tx_pool.len(), 0);
        assert_eq!(node.consensused.tx_druid_pool.len(), 0);
        assert_eq!(node.consensused.tx_current_block_previous_hash, None);
    }

    #[tokio::test]
    async fn in_flight_transactions_no_raft() {
        //
        // Arrange
        //
        let mut node = new_test_node(&[]).await;
        node.proposed_and_consensused_tx_pool_len_max = 3;
        node.proposed_tx_pool_len_max = 2;
        node.propose_initial_item().await;
        let commit = node.next_commit().await;
        node.received_commit(commit.unwrap()).await.unwrap();
        node.generate_first_block();

        let expected_seed = Integer::from_str_radix(
            "4884172366043866459154607462096288731322499881015937556796960093953580287561",
            10,
        )
        .unwrap();

        //
        // Act
        //
        let mut actual_combined_local_flight_consensused = Vec::new();
        let mut collect_info = |node: &ComputeRaft| {
            actual_combined_local_flight_consensused.push((
                node.combined_tx_pool_len(),
                node.local_tx_pool.len(),
                node.proposed_tx_pool_len,
                node.consensused.tx_pool.len(),
            ))
        };
        collect_info(&node);

        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003", "000004", "000005", "000006"],
            &["000100", "000101", "000103", "000104", "000105", "000106"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000010", "000011"],
            &["000200", "000200"],
            &mut BTreeMap::new(),
        ));
        collect_info(&node);

        for _ in 0u8..3u8 {
            node.propose_local_transactions_at_timeout().await;
            node.propose_local_druid_transactions().await;
            collect_info(&node);

            loop {
                tokio::select! {
                    commit = node.next_commit() => {node.received_commit(commit.unwrap()).await;}
                    _ = time::sleep(Duration::from_millis(5)) => {break;}
                }
            }
            collect_info(&node);
        }

        //
        // Assert
        //
        assert_eq!(
            expected_seed,
            node.consensused.first_block_pipeline.get_unicorn_seed()
        );
        assert_eq!(
            actual_combined_local_flight_consensused,
            vec![
                // Start
                (0, 0, 0, 0),
                // Transaction appended
                (6, 6, 0, 0),
                // Process 1st time out and commit: 2 in flight then consensused
                (6, 4, 2, 0),
                (6, 4, 0, 2),
                // Process 2nd time out and commit: 1 in flight then consensused
                // (max reached)
                (6, 3, 1, 2),
                (6, 3, 0, 3),
                // Process 3rd time out and commit: 0 in flight then consensused
                // (max reached)
                (6, 3, 0, 3),
                (6, 3, 0, 3),
            ]
        );
    }

    async fn new_test_node(seed_utxo: &[&str]) -> ComputeRaft {
        let compute_node = NodeSpec {
            address: "0.0.0.0:0".parse().unwrap(),
        };
        let tx_out = TxOutSpec {
            public_key: "5371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c"
                .to_owned(),
            amount: TokenAmount(1),
        };
        let compute_config = ComputeNodeConfig {
            compute_node_idx: 0,
            compute_db_mode: DbMode::InMemory,
            tls_config: Default::default(),
            api_keys: Default::default(),
            compute_nodes: vec![compute_node],
            storage_nodes: vec![],
            user_nodes: vec![],
            compute_raft: 0,
            compute_raft_tick_timeout: 10,
            compute_transaction_timeout: 50,
            compute_seed_utxo: seed_utxo
                .iter()
                .map(|v| (v.to_string(), vec![tx_out.clone()]))
                .collect(),
            compute_genesis_tx_in: None,
            compute_partition_full_size: 1,
            compute_minimum_miner_pool_len: 1,
            jurisdiction: "US".to_string(),
            sanction_list: Vec::new(),
            compute_api_use_tls: true,
            compute_api_port: 3003,
        };
        let mut node = ComputeRaft::new(&compute_config, Default::default()).await;
        node.set_key_run(0);
        node
    }

    fn valid_transaction(
        intial_t_hashes: &[&str],
        receiver_addrs: &[&str],
        new_hashes: &mut BTreeMap<String, String>,
    ) -> BTreeMap<String, Transaction> {
        let (pk, sk) = sign::gen_keypair();

        let txs: Vec<_> = intial_t_hashes
            .iter()
            .copied()
            .zip(receiver_addrs.iter().copied())
            .map(|(hash, addr)| (create_valid_transaction(hash, 0, addr, &pk, &sk), addr))
            .collect();

        new_hashes.extend(
            txs.iter()
                .map(|((h, _), addr)| (addr.to_string(), h.clone())),
        );
        txs.into_iter().map(|(tx, _)| tx).collect()
    }

    pub fn key_with_max_value<'a>(
        map: &BTreeMap<String, String>,
        key1: &'a str,
        key2: &'a str,
    ) -> &'a str {
        if map[key1] < map[key2] {
            key2
        } else {
            key1
        }
    }
}
