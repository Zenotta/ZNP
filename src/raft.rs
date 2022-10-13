use crate::db_utils::{SimpleDb, SimpleDbError};
use crate::raft_store::{self, RaftStore};
use crate::utils::MpscTracingSender;
use raft::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant};
use tracing::{error, info, trace};

pub type RaftData = Vec<u8>;
pub type CommitSender = MpscTracingSender<Vec<RaftCommit>>;
pub type CommitReceiver = mpsc::Receiver<Vec<RaftCommit>>;
pub type RaftCmdSender = mpsc::UnboundedSender<RaftCmd>;
pub type RaftCmdReceiver = mpsc::UnboundedReceiver<RaftCmd>;
pub type RaftMsgSender = MpscTracingSender<Message>;
pub type RaftMsgReceiver = mpsc::Receiver<Message>;
pub type CommittedIndex = raft_store::CommittedIndex;

/// Raft Commit entry
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct RaftCommit {
    pub term: u64,
    pub index: u64,
    pub data: RaftCommitData,
}

/// Key serialized into RaftData and process by Raft.
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RaftContext {
    pub proposer_id: u64,
    pub proposal_id: u64,
}

/// Raft Commit data
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaftCommitData {
    Proposed(RaftData, RaftData),
    Snapshot(RaftData),
    NewLeader,
}

impl RaftCommitData {
    fn take_data(self) -> Option<RaftData> {
        match self {
            Self::Proposed(data, _) => Some(data),
            Self::Snapshot(data) => Some(data),
            Self::NewLeader => None,
        }
    }
}

impl Default for RaftCommitData {
    fn default() -> Self {
        Self::Proposed(Default::default(), Default::default())
    }
}

/// Channels needed to interact with the running raft instance.
pub struct RaftNodeChannels {
    pub msg_out_rx: RaftMsgReceiver,
    pub cmd_tx: RaftCmdSender,
    pub committed_rx: CommitReceiver,
}

/// Fields necessary for launching a Raft loop.
pub struct RaftConfig {
    /// Raft RawNode config.
    cfg: Config,
    /// Raft persistent database to load/store.
    raft_db: SimpleDb,
    /// Input command and messages.
    cmd_rx: RaftCmdReceiver,
    /// Output commited data.
    committed_tx: CommitSender,
    /// Ouput raft messages that need to be dispatched to appropriate peers.
    msg_out_tx: RaftMsgSender,
    /// Tick timeout duration.
    tick_timeout_duration: Duration,
}

/// Wrapper for raft Messages enabling Serialize/Deserialize
#[derive(Clone, Debug, PartialEq)]
pub struct RaftMessageWrapper(pub Message);

impl Serialize for RaftMessageWrapper {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use protobuf::Message;
        let bytes = self.0.write_to_bytes().map_err(serde::ser::Error::custom)?;
        bytes.serialize(s)
    }
}

impl<'a> Deserialize<'a> for RaftMessageWrapper {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(RaftMessageWrapper(
            protobuf::parse_from_bytes::<Message>(bytes).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// Input command/messages to the raft loop.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RaftCmd {
    Propose {
        data: RaftData,
        context: RaftData,
    },
    Snapshot {
        idx: u64,
        data: RaftData,
        backup: bool,
    },
    Raft(RaftMessageWrapper),
    Close,
}

pub struct RaftNode {
    /// Runing raft node.
    node: RawNode<RaftStore>,
    /// Backlog of raft proposal while leader unavailable, and proposer id.
    propose_data_backlog: Vec<(RaftData, RaftData, u64)>,
    /// Input command and messages.
    cmd_rx: RaftCmdReceiver,
    /// Output commited data.
    committed_tx: CommitSender,
    /// Ouput raft messages that need to be dispatched to appropriate peers.
    msg_out_tx: RaftMsgSender,
    /// Tick timeout duration.
    tick_timeout_duration: Duration,
    /// Tick timeout expiration time.
    tick_timeout_at: Instant,
    /// Committed entries/group count.
    committed_entries_and_groups_count: (usize, usize),
    /// Outgoing messages/group count.
    outgoing_msgs_and_groups_count: (usize, usize),
    /// Incomming messages count.
    incoming_msgs_count: usize,
    /// Total tick count.
    total_tick_count: usize,
    /// Last snapshot index, and whether it need compacting.
    previous_snapshot_idx: (u64, bool),
    // Context already waiting for committing
}

impl RaftNode {
    /// RaftNode constructor.
    ///
    /// ### Arguments
    ///
    /// * `raft_Config` - RaftConfig object containing tick_timeout_duration and cfg
    pub fn new(raft_config: RaftConfig) -> Self {
        let tick_timeout_at = Instant::now() + raft_config.tick_timeout_duration;

        let node = {
            let (storage, cfg) = Self::storage_and_config(raft_config.cfg, raft_config.raft_db);
            let mut node = RawNode::new(&cfg, storage, vec![]).unwrap();

            if cfg.id == 1 {
                // Make first peer start election immediatly on start up to avoid unecessary wait.
                node.raft.election_elapsed = node.raft.get_randomized_election_timeout();
            }

            node
        };

        Self {
            node,
            propose_data_backlog: Default::default(),
            cmd_rx: raft_config.cmd_rx,
            committed_tx: raft_config.committed_tx,
            msg_out_tx: raft_config.msg_out_tx,
            tick_timeout_duration: raft_config.tick_timeout_duration,
            tick_timeout_at,
            committed_entries_and_groups_count: (0, 0),
            outgoing_msgs_and_groups_count: (0, 0),
            incoming_msgs_count: 0,
            total_tick_count: 0,
            previous_snapshot_idx: (0, false),
        }
    }

    /// Create the RaftConfig and needed channels to run the loop.
    ///
    /// ### Arguments
    ///
    /// * `node_cfg` - Config object
    /// * `tick_timeout_duration` - Duration object holding the tick timeout duration
    pub fn init_config(
        node_cfg: Config,
        raft_db: SimpleDb,
        tick_timeout_duration: Duration,
    ) -> (RaftConfig, RaftNodeChannels) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (committed_tx, committed_rx) = mpsc::channel(100);
        let (msg_out_tx, msg_out_rx) = mpsc::channel(100);

        (
            RaftConfig {
                cfg: node_cfg,
                cmd_rx,
                committed_tx: committed_tx.into(),
                msg_out_tx: msg_out_tx.into(),
                tick_timeout_duration,
                raft_db,
            },
            RaftNodeChannels {
                msg_out_rx,
                cmd_tx,
                committed_rx,
            },
        )
    }

    /// Async RAFT loop processing inputs and populating output channels.
    pub async fn run_raft_loop(&mut self) {
        // Notify commited snapshot if loaded one.
        let snapshot = self.node.get_store().snapshot().unwrap();
        self.apply_committed_entries(&mut Ready::default(), Some(&snapshot))
            .await;

        // Start processing events.
        loop {
            match self.next_event().await {
                Some(_) => (),
                None => {
                    // complete
                    return;
                }
            }
        }
    }

    /// Extract persistent storage of a closed raft
    pub fn take_closed_persistent_store(&mut self) -> SimpleDb {
        self.node.mut_store().take_persistent()
    }

    /// Backup persistent storage
    pub fn backup_persistent_store(&self) -> Result<(), SimpleDbError> {
        self.node.get_store().backup_persistent()
    }

    /// Async RAFT loop processing inputs and populating output channels.
    async fn next_event(&mut self) -> Option<()> {
        match timeout_at(self.tick_timeout_at, self.cmd_rx.recv()).await {
            Ok(Some(RaftCmd::Propose { data, context })) => {
                trace!("next_event Propose({}, {:?})", self.node.raft.id, data);
                self.propose_data_backlog
                    .push((data, context, self.node.raft.id));
            }
            Ok(Some(RaftCmd::Snapshot { idx, data, backup })) => {
                trace!("next_event snapshot({}, idx: {})", self.node.raft.id, idx);
                let store = self.node.mut_store();
                let (prev_idx, need_compact) = self.previous_snapshot_idx;
                if idx != prev_idx {
                    store.create_snapshot(idx, None, None, data).unwrap();
                }
                if need_compact {
                    store.compact(prev_idx).unwrap();
                }
                if backup {
                    if let Err(e) = store.backup_persistent() {
                        error!("Backup error: {:?}", e);
                    }
                }
                self.previous_snapshot_idx = (idx, idx != prev_idx);
            }
            Ok(Some(RaftCmd::Raft(RaftMessageWrapper(mut m)))) => {
                trace!("next_event receive message({}, {:?})", self.node.raft.id, m);
                self.incoming_msgs_count += 1;
                let from = m.get_from();
                if m.get_msg_type() == MessageType::MsgPropose {
                    for mut e in m.take_entries().into_iter() {
                        let data = e.take_data();
                        let context = e.take_context();
                        self.propose_data_backlog.push((data, context, from));
                    }
                } else {
                    self.node.step(m).unwrap();
                }
            }
            Err(_) => {
                // Timeout
                self.tick_timeout_at = Instant::now() + self.tick_timeout_duration;
                self.total_tick_count += 1;
                self.node.tick();
            }
            Ok(Some(RaftCmd::Close)) | Ok(None) => {
                // Disconnected
                info!(
                    peer_id = self.node.raft.id,
                    leader_id = self.node.raft.leader_id,
                    term = self.node.raft.term,
                    ?self.total_tick_count,
                    ?self.incoming_msgs_count,
                    ?self.committed_entries_and_groups_count,
                    ?self.outgoing_msgs_and_groups_count,
                    ?self.previous_snapshot_idx,
                    "Closing Raft: Summary"
                );
                return None;
            }
        }

        if self.node.raft.leader_id != raft::INVALID_ID {
            let is_leader = self.node.raft.leader_id == self.node.raft.id;
            for (data, context, from) in self.propose_data_backlog.drain(..) {
                let can_propose = is_leader || from == self.node.raft.id;
                if can_propose && !self.node.get_store().is_context_in_log(&context) {
                    self.node.propose(context, data).unwrap();
                }
            }
        }

        self.process_ready().await;
        Some(())
    }

    ///If current node has_ready is true then it returns. Otherwise, it sends messages to peers and updates ready.
    ///
    /// Advance notifies the node that the application has applied and saved progress in the last Ready results.
    async fn process_ready(&mut self) {
        if !self.node.has_ready() {
            return;
        }

        let mut ready = self.node.ready();

        let is_leader = self.node.raft.leader_id == self.node.raft.id;
        if is_leader {
            self.send_messages_to_peers(&mut ready).await;
            self.update_ready_mut_store(&mut ready);
        } else {
            self.update_ready_mut_store(&mut ready);
            self.send_messages_to_peers(&mut ready).await;
        }

        self.apply_committed_entries(&mut ready, None).await;
        self.node.advance(ready);
    }

    /// Sends all messages to peers
    ///
    /// ### Arguments
    ///
    /// * `ready` - Ready object that contains the messages to be sent.
    async fn send_messages_to_peers(&mut self, ready: &mut Ready) {
        self.outgoing_msgs_and_groups_count.1 += if ready.messages.is_empty() { 0 } else { 1 };
        for msg in ready.messages.drain(..) {
            trace!("send_messages_to_peers({}, {:?})", self.node.raft.id, msg);
            self.outgoing_msgs_and_groups_count.0 += 1;
            let _ok_or_closed = self.msg_out_tx.send(msg, "msg_out").await;
        }
    }

    ///Updates the node object of this class with values from the Ready object input.
    /// ### Arguments
    ///
    /// * `ready` - Ready object. Values from this object are used to update the node object in this class.
    fn update_ready_mut_store(&mut self, ready: &mut Ready) {
        if !raft::is_empty_snap(ready.snapshot()) {
            self.node
                .mut_store()
                .apply_snapshot(ready.snapshot().clone())
                .unwrap();

            let snap_idx = ready.snapshot().get_metadata().index;
            self.previous_snapshot_idx = (snap_idx, false);
        }

        if !ready.entries().is_empty() {
            self.node.mut_store().append(ready.entries()).unwrap();
        }

        if let Some(hs) = ready.hs() {
            self.node.mut_store().set_hardstate(hs.clone()).unwrap();
        }
    }

    ///Commits entries Ready object input exectues send on the class's committed_tx object
    /// ### Arguments
    ///
    /// * `ready`          - Ready object. Values from this object are commited.
    /// * `snap_overwrite` - Values overiding ready.snapshot (used for start up).
    async fn apply_committed_entries(
        &mut self,
        ready: &mut Ready,
        snap_overwrite: Option<&Snapshot>,
    ) {
        let mut committed = Vec::new();

        {
            let snapshot = snap_overwrite
                .or_else(|| Some(ready.snapshot()).filter(|s| !raft::is_empty_snap(s)));

            if let Some(snapshot) = snapshot {
                committed.push(RaftCommit {
                    term: snapshot.get_metadata().term,
                    index: snapshot.get_metadata().index,
                    data: RaftCommitData::Snapshot(snapshot.data.clone()),
                });
            }
        }

        if let Some(mut committed_entries) = ready.committed_entries.take() {
            committed.extend(
                committed_entries
                    .drain(..)
                    .filter(|entry| entry.get_entry_type() == EntryType::EntryNormal)
                    .map(|mut entry| {
                        let term = entry.get_term();
                        let index = entry.get_index();
                        let data = if entry.get_data().is_empty() {
                            RaftCommitData::NewLeader
                        } else {
                            RaftCommitData::Proposed(entry.take_data(), entry.take_context())
                        };
                        RaftCommit { term, index, data }
                    }),
            );
        }

        if !committed.is_empty() {
            self.committed_entries_and_groups_count.1 += 1;
            self.committed_entries_and_groups_count.0 += committed.len();
            let _ok_or_closed = self.committed_tx.send(committed, "committed").await;
        }
    }

    /// Create storage and config to use for new node
    fn storage_and_config(mut cfg: Config, db: SimpleDb) -> (RaftStore, Config) {
        let mut cs = ConfState::new();
        cs.set_nodes(std::mem::take(&mut cfg.peers));

        let storage = RaftStore::new(db).load_in_memory_or_default(cs).unwrap();

        (storage, cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::tracing_log_try_init;
    use futures::future::join_all;
    use std::cmp;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use tokio::time;
    use tracing::error_span;
    use tracing_futures::Instrument;

    const TIMEOUT_TEST_WAIT_DURATION: Duration = Duration::from_millis(5000);

    type ArcRaftHooks = Arc<Mutex<RaftHooks>>;
    type ArcPeerIds = Arc<Mutex<HashSet<u64>>>;

    struct TestNode {
        pub raft_config: Option<RaftConfig>,
        pub peer_id: u64,
        pub msg_out_rx: Option<RaftMsgReceiver>,
        pub cmd_tx: RaftCmdSender,
        pub committed_rx: CommitReceiver,
        pub last_committed: Option<RaftCommit>,
        pub last_proposed_id: u8,
    }

    struct RaftHooks {
        cmd_txs: Vec<RaftCmdSender>,
        closed_dbs: HashMap<u64, SimpleDb>,
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_proposal_is_commited_1_node() {
        test_send_proposal_check_commited(1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_proposal_is_commited_2_nodes() {
        test_send_proposal_check_commited(2).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_proposal_is_commited_3_nodes() {
        test_send_proposal_check_commited(3).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_proposal_is_commited_20_nodes() {
        test_send_proposal_check_commited(20).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Verify proposal are committed by all peers regardless of the proposer.
    async fn test_send_proposal_check_commited(num_peers: u64) {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(num_peers);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let idx_1 = cmp::min(1, num_peers - 1) as usize;

        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;
        all_recv_send_proposed_data(&mut test_nodes, idx_1, vec![33]).await;

        close_nodes_loops(test_nodes, join_handles).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_1_node() {
        test_snapshot(1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_2_nodes() {
        test_snapshot(2).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_3_nodes() {
        test_snapshot(3).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_20_nodes() {
        test_snapshot(20).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Verify snapshot does not interfer with later proposal.
    async fn test_snapshot(num_peers: u64) {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(num_peers);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;

        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;
        all_snapshot(&mut test_nodes, vec![12]).await;
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![33]).await;

        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node not receiving message can catch up.
    #[tokio::test(flavor = "current_thread")]
    async fn test_catch_up_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(Some(3).into_iter().collect::<HashSet<u64>>()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (last_test_node, majority_test_nodes) = test_nodes.split_last_mut().unwrap();

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![17]).await;
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![33]).await;

        info!("Unresponsive node back catching up");
        peer_msg_lost.lock().await.clear();
        let commits = one_recv_commiteds(last_test_node, 2).await;
        assert_eq!(commits, vec![vec![vec![17]], vec![vec![33]]]);

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node not receiving message can catch up, snapshot exist but record still there.
    #[tokio::test(flavor = "current_thread")]
    async fn test_skip_snapshot_catch_up_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(Some(3).into_iter().collect::<HashSet<u64>>()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (last_test_node, majority_test_nodes) = test_nodes.split_last_mut().unwrap();
        let snapshot = vec![12];

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![17]).await;
        all_snapshot(majority_test_nodes, snapshot.clone()).await;
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![33]).await;

        info!("Unresponsive node back catching up");
        peer_msg_lost.lock().await.clear();
        let commits = one_recv_commiteds(last_test_node, 2).await;
        assert_eq!(commits, vec![vec![vec![17]], vec![vec![33]]]);

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node not receiving message can catch up, need to use snapshot as record is gone.
    #[tokio::test(flavor = "current_thread")]
    async fn test_snap_catch_up_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(Some(3).into_iter().collect::<HashSet<u64>>()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (last_test_node, majority_test_nodes) = test_nodes.split_last_mut().unwrap();
        let (snapshot1, snapshot2) = (vec![12], vec![13]);

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![17]).await;
        info!("Two Snapshot so record compacted up to first one");
        all_snapshot(majority_test_nodes, snapshot1.clone()).await;
        all_snapshot(majority_test_nodes, snapshot2).await;
        info!("Proposal after snapshot");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![33]).await;

        info!("Unresponsive node back catching up");
        peer_msg_lost.lock().await.clear();
        let commits = one_recv_commiteds(last_test_node, 2).await;
        assert_eq!(commits, vec![vec![snapshot1], vec![vec![33]]]);

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node not receiving message can catch up, and then need to use snapshot as record is gone.
    #[tokio::test(flavor = "current_thread")]
    async fn test_snap_catch_up_after_start_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost_set: HashSet<u64> = Some(3).into_iter().collect();
        let peer_msg_lost = Arc::new(Mutex::new(peer_msg_lost_set.clone()));
        let (join_handles, _) = spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (last_test_node, majority_test_nodes) = test_nodes.split_last_mut().unwrap();
        let (snapshot1, snapshot2) = (vec![12], vec![13]);

        info!("Process with majority ignoring unresponsive node and catch up");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![17]).await;
        peer_msg_lost.lock().await.clear();
        let commit0 = one_recv_commited(last_test_node, 0, 1).await;
        assert_eq!(commit0, vec![vec![17]]);
        *peer_msg_lost.lock().await = peer_msg_lost_set;

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![18]).await;
        info!("Two Snapshot so record compacted up to first one");
        all_snapshot(majority_test_nodes, snapshot1.clone()).await;
        all_snapshot(majority_test_nodes, snapshot2).await;
        info!("Proposal after snapshot");
        all_recv_send_proposed_data(majority_test_nodes, 0, vec![33]).await;

        info!("Unresponsive node back catching up");
        peer_msg_lost.lock().await.clear();
        let commits = one_recv_commiteds(last_test_node, 2).await;
        assert_eq!(commits, vec![vec![snapshot1], vec![vec![33]]]);

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node killed can catch up, no snapshot needed.
    #[tokio::test(flavor = "current_thread")]
    async fn test_restart_after_start_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (mut join_handles, node_hooks) =
            spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let kill_id = 3;

        info!("Process with majority ignoring unresponsive node and catch up");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;

        info!("Kill node {}", kill_id);
        let node = kill_node(kill_id, &mut test_nodes, &mut join_handles, &peer_indexes).await;

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![18]).await;
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![33]).await;

        info!("Killed node back catching up");
        let node_index = restart_node(
            node,
            &mut test_nodes,
            &mut join_handles,
            &peer_indexes,
            &node_hooks,
            &peer_msg_lost,
        )
        .await;
        let commits = one_recv_commiteds(&mut test_nodes[node_index], 4).await;
        assert_eq!(
            commits,
            vec![vec![vec![]], vec![vec![17]], vec![vec![18]], vec![vec![33]]],
            "Should process loaded db entries before new received entries"
        );

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node killed can catch up, and then need to use snapshot as record is gone.
    #[tokio::test(flavor = "current_thread")]
    async fn test_snap_restart_after_start_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (mut join_handles, node_hooks) =
            spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (snapshot1, snapshot2) = (vec![12], vec![13]);
        let kill_id = 3;

        info!("Process with majority ignoring unresponsive node and catch up");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;

        info!("Kill node {}", kill_id);
        let node = kill_node(kill_id, &mut test_nodes, &mut join_handles, &peer_indexes).await;

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![18]).await;
        info!("Two Snapshot so record compacted up to first one");
        all_snapshot(&mut test_nodes, snapshot1.clone()).await;
        all_snapshot(&mut test_nodes, snapshot2).await;
        info!("Proposal after snapshot");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![33]).await;

        info!("Killed node back catching up");
        let node_index = restart_node(
            node,
            &mut test_nodes,
            &mut join_handles,
            &peer_indexes,
            &node_hooks,
            &peer_msg_lost,
        )
        .await;
        let commits = one_recv_commiteds(&mut test_nodes[node_index], 4).await;
        assert_eq!(
            commits,
            vec![
                vec![vec![]],
                vec![vec![17]],
                vec![snapshot1],
                vec![vec![33]]
            ],
            "Should process loaded db entries before new received entries"
        );

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node killed after initial snapshot can catch up without getting new snapshot.
    #[tokio::test(flavor = "current_thread")]
    async fn test_restart_skip_snapshot_after_snapshot_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (mut join_handles, node_hooks) =
            spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (snapshot1, snapshot2) = (vec![12], vec![13]);
        let kill_id = 3;

        info!("Process with majority ignoring unresponsive node and catch up");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;
        all_snapshot(&mut test_nodes, snapshot1.clone()).await;
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![18]).await;

        info!("Kill node {}", kill_id);
        let node = kill_node(kill_id, &mut test_nodes, &mut join_handles, &peer_indexes).await;

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![19]).await;
        all_snapshot(&mut test_nodes, snapshot2).await;
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![33]).await;

        info!("Killed node back catching up");
        let node_index = restart_node(
            node,
            &mut test_nodes,
            &mut join_handles,
            &peer_indexes,
            &node_hooks,
            &peer_msg_lost,
        )
        .await;
        let commits = one_recv_commiteds(&mut test_nodes[node_index], 4).await;
        assert_eq!(
            commits,
            vec![
                vec![snapshot1],
                vec![vec![18]],
                vec![vec![19]],
                vec![vec![33]]
            ],
            "Should process loaded db snapshot & entries before new received entries"
        );

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup a peer group running all raft loops and dispatching messages.
    // Node killed after initial snapshot can catch up, and then need to use snapshot as record is gone.
    #[tokio::test(flavor = "current_thread")]
    async fn test_snap_restart_after_snapshot_3() {
        let _ = tracing_log_try_init();
        let (peer_indexes, mut test_nodes) = test_configs(3);
        let peer_msg_lost = Arc::new(Mutex::new(HashSet::new()));
        let (mut join_handles, node_hooks) =
            spawn_nodes_loops(&peer_indexes, &mut test_nodes, &peer_msg_lost);
        all_recv_initial_snapshot(&mut test_nodes).await;
        let (snapshot1, snapshot2, snapshot3) = (vec![12], vec![13], vec![14]);
        let kill_id = 3;

        info!("Process with majority ignoring unresponsive node and catch up");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![17]).await;
        all_snapshot(&mut test_nodes, snapshot1.clone()).await;
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![18]).await;

        info!("Kill node {}", kill_id);
        let node = kill_node(kill_id, &mut test_nodes, &mut join_handles, &peer_indexes).await;

        info!("Process with majority ignoring unresponsive node");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![19]).await;
        info!("Two Snapshot so record compacted up to first one");
        all_snapshot(&mut test_nodes, snapshot2.clone()).await;
        all_snapshot(&mut test_nodes, snapshot3).await;
        info!("Proposal after snapshot");
        all_recv_send_proposed_data(&mut test_nodes, 0, vec![33]).await;

        info!("Killed node back catching up");
        let node_index = restart_node(
            node,
            &mut test_nodes,
            &mut join_handles,
            &peer_indexes,
            &node_hooks,
            &peer_msg_lost,
        )
        .await;
        let commits = one_recv_commiteds(&mut test_nodes[node_index], 4).await;
        assert_eq!(
            commits,
            vec![
                vec![snapshot1],
                vec![vec![18]],
                vec![snapshot2],
                vec![vec![33]]
            ],
            "Should process loaded db snapshot & entries before new received entries"
        );

        info!("Complete test");
        close_nodes_loops(test_nodes, join_handles).await;
    }

    // Setup RAFT: Raft loops and Raft message dispatching loops.
    fn spawn_nodes_loops(
        peer_indexes: &HashMap<u64, usize>,
        test_nodes: &mut [TestNode],
        peer_msg_lost: &ArcPeerIds,
    ) -> (Vec<Vec<JoinHandle<()>>>, ArcRaftHooks) {
        let node_hooks = Arc::new(Mutex::new(RaftHooks {
            cmd_txs: test_nodes.iter().map(|node| node.cmd_tx.clone()).collect(),
            closed_dbs: HashMap::new(),
        }));

        let mut join_handles = Vec::new();
        for test_node in test_nodes {
            join_handles.push(spawn_node_loops(
                peer_indexes,
                test_node,
                &node_hooks,
                peer_msg_lost,
            ));
        }
        (join_handles, node_hooks)
    }

    // Setup RAFT: Raft loops and Raft message dispatching loops.
    fn spawn_node_loops(
        peer_indexes: &HashMap<u64, usize>,
        test_node: &mut TestNode,
        node_hooks: &ArcRaftHooks,
        peer_msg_lost: &ArcPeerIds,
    ) -> Vec<JoinHandle<()>> {
        let mut join_handles = Vec::new();
        let raft_config = test_node.raft_config.take().unwrap();
        let peer_span = error_span!("", node_id = ?raft_config.cfg.id);

        {
            let node_hooks = node_hooks.clone();
            join_handles.push(tokio::spawn(
                async move {
                    run_raft_loop(raft_config, node_hooks).await;
                }
                .instrument(peer_span.clone()),
            ));
        }
        {
            let msg_out_rx = test_node.msg_out_rx.take().unwrap();
            let peer_indexes = peer_indexes.clone();
            let node_hooks = node_hooks.clone();
            let peer_msg_lost = peer_msg_lost.clone();
            join_handles.push(tokio::spawn(
                async move {
                    dispatch_messages_loop(msg_out_rx, peer_indexes, node_hooks, peer_msg_lost)
                        .await;
                }
                .instrument(peer_span),
            ));
        }

        join_handles
    }

    // Close raft loop so spawned task can complete and wait for completion.
    async fn close_nodes_loops(
        mut test_nodes: Vec<TestNode>,
        join_handles: Vec<Vec<JoinHandle<()>>>,
    ) {
        for test_node in &mut test_nodes {
            test_node.cmd_tx.send(RaftCmd::Close).unwrap();
        }
        join_all(join_handles.into_iter().flat_map(|v| v.into_iter())).await;
    }

    // Destroy and Restart loops for specified nodes.
    async fn kill_node(
        peer_id: u64,
        test_nodes: &mut Vec<TestNode>,
        join_handles: &mut Vec<Vec<JoinHandle<()>>>,
        peer_indexes: &HashMap<u64, usize>,
    ) -> TestNode {
        let node_index = peer_indexes[&peer_id];
        let peers: Vec<_> = test_nodes.iter().map(|n| n.peer_id).collect();

        let node = test_nodes.remove(node_index);
        let handles = join_handles.remove(node_index);
        close_nodes_loops(vec![node], vec![handles]).await;

        test_config(peer_id, &peers)
    }

    // Restart loops for specified nodes.
    async fn restart_node(
        mut node: TestNode,
        test_nodes: &mut Vec<TestNode>,
        join_handles: &mut Vec<Vec<JoinHandle<()>>>,
        peer_indexes: &HashMap<u64, usize>,
        node_hooks: &ArcRaftHooks,
        peer_msg_lost: &ArcPeerIds,
    ) -> usize {
        let node_index = peer_indexes[&node.peer_id];
        node_hooks.lock().await.cmd_txs[node_index] = node.cmd_tx.clone();

        let handles = spawn_node_loops(peer_indexes, &mut node, node_hooks, peer_msg_lost);
        test_nodes.insert(node_index, node);
        join_handles.insert(node_index, handles);

        node_index
    }

    // Send a proposal and wait for it to be commited.
    async fn all_recv_send_proposed_data(
        test_nodes: &mut [TestNode],
        from_node_idx: usize,
        proposed_data: RaftData,
    ) {
        send_proposal(&mut test_nodes[from_node_idx], proposed_data.clone()).await;

        let commited_data = recv_commited(test_nodes).await;
        let expected = expected_commited(test_nodes, &[proposed_data]);
        assert_eq!(commited_data, expected);
    }

    // Wait for initial snapshot to be commited.
    async fn all_recv_initial_snapshot(test_nodes: &mut [TestNode]) {
        let commited_data = recv_commited(test_nodes).await;
        let expected = expected_commited(test_nodes, &[Default::default()]);
        assert_eq!(commited_data, expected);
    }

    async fn run_raft_loop(mut raft_config: RaftConfig, node_hooks: ArcRaftHooks) {
        let id = raft_config.cfg.id;

        if let Some(persistent) = node_hooks.lock().await.closed_dbs.remove(&id) {
            raft_config.raft_db = persistent;
        }

        let mut raft_node = RaftNode::new(raft_config);
        raft_node.run_raft_loop().await;

        let persistent = raft_node.take_closed_persistent_store();
        node_hooks.lock().await.closed_dbs.insert(id, persistent);
    }

    async fn dispatch_messages_loop(
        mut msg_out_rx: RaftMsgReceiver,
        peer_indexes: HashMap<u64, usize>,
        node_hooks: ArcRaftHooks,
        peer_msg_lost: ArcPeerIds,
    ) {
        loop {
            match msg_out_rx.recv().await {
                Some(msg) => {
                    let peer_msg_lost = peer_msg_lost.lock().await;
                    if peer_msg_lost.contains(&msg.to) || peer_msg_lost.contains(&msg.from) {
                        trace!("Drop message: {:?}", &msg);
                        continue;
                    }
                    let to_index = peer_indexes[&msg.to];
                    let node_hooks = node_hooks.lock().await;

                    let msg_str = format!("{:?}", &msg);
                    if let Err(e) =
                        node_hooks.cmd_txs[to_index].send(RaftCmd::Raft(RaftMessageWrapper(msg)))
                    {
                        trace!("Could not send message: e={:?}, msg={}", e, msg_str);
                    }
                }
                None => {
                    // Disconnected
                    return;
                }
            }
        }
    }

    async fn send_proposal(test_node: &mut TestNode, data: RaftData) {
        test_node.last_proposed_id += 1;
        let context = vec![test_node.peer_id as u8, test_node.last_proposed_id];
        let cmd = RaftCmd::Propose { data, context };

        test_node.cmd_tx.send(cmd).unwrap();
    }

    async fn all_snapshot(test_nodes: &mut [TestNode], data: RaftData) {
        for test_node in test_nodes {
            let idx = test_node.last_committed.as_ref().unwrap().index;
            let data = data.clone();
            let backup = false;

            let cmd = RaftCmd::Snapshot { idx, data, backup };
            test_node.cmd_tx.send(cmd).unwrap();
        }
    }

    async fn recv_commited(test_nodes: &mut [TestNode]) -> Vec<Vec<RaftData>> {
        let mut received = Vec::new();
        for test_node in test_nodes {
            received.push(one_recv_commited(test_node, 0, 1).await)
        }
        received
    }

    async fn one_recv_commiteds(test_node: &mut TestNode, count: usize) -> Vec<Vec<RaftData>> {
        let mut result = Vec::new();
        for i in 0..count {
            result.push(one_recv_commited(test_node, i, count).await);
        }
        result
    }

    async fn one_recv_commited(test_node: &mut TestNode, i: usize, count: usize) -> Vec<RaftData> {
        loop {
            match time::timeout(TIMEOUT_TEST_WAIT_DURATION, test_node.committed_rx.recv()).await {
                Ok(commits) => {
                    let mut commits = commits.unwrap();
                    commits.retain(|e| e.data != RaftCommitData::NewLeader);

                    if !commits.is_empty() {
                        test_node.last_committed = Some(commits.last().cloned().unwrap());
                        return commits
                            .into_iter()
                            .map(|e| e.data.take_data().unwrap())
                            .collect();
                    }
                }
                Err(_) => panic!(
                    "Unexpected timeout: peer_id={}, i={} in 0..{}",
                    test_node.peer_id, i, count
                ),
            }
        }
    }

    fn expected_commited(test_nodes: &[TestNode], expected: &[RaftData]) -> Vec<Vec<RaftData>> {
        test_nodes.iter().map(|_| expected.to_owned()).collect()
    }

    fn test_configs(num_peers: u64) -> (HashMap<u64, usize>, Vec<TestNode>) {
        let peers: Vec<u64> = (1..num_peers + 1).collect();
        let test_nodes: Vec<_> = peers
            .iter()
            .map(|peer_id| test_config(*peer_id, &peers))
            .collect();
        let peer_to_indexes = peers
            .iter()
            .enumerate()
            .map(|(idx, id)| (*id, idx))
            .collect();
        (peer_to_indexes, test_nodes)
    }

    fn test_config(peer_id: u64, peers: &[u64]) -> TestNode {
        let (raft_config, node_channels) = RaftNode::init_config(
            Config {
                id: peer_id,
                peers: peers.to_owned(),
                ..Default::default()
            },
            SimpleDb::new_in_memory(&[], None).unwrap(),
            Duration::from_millis(1),
        );

        TestNode {
            raft_config: Some(raft_config),
            peer_id,
            cmd_tx: node_channels.cmd_tx,
            committed_rx: node_channels.committed_rx,
            msg_out_rx: Some(node_channels.msg_out_rx),
            last_committed: None,
            last_proposed_id: 0,
        }
    }
}
