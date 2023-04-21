//! This module provides a variety of utility functions to setup a test network,
//! to send a receive requests & responses, and generally to test the behavior and
//! correctness of the compute, miner, & storage modules.

use crate::comms_handler::{test_tls_certificates, Node, TcpTlsConfig, TcpTlsListner};
use crate::compute::ComputeNode;
use crate::configurations::{
    ComputeNodeConfig, DbMode, ExtraNodeParams, MinerNodeConfig, NodeSpec, PreLaunchNodeConfig,
    PreLaunchNodeType, StorageNodeConfig, TlsSpec, UserAutoGenTxSetup, UserNodeConfig, UtxoSetSpec,
    WalletTxSpec,
};
use crate::constants::{DB_PATH, DB_PATH_TEST, WALLET_PATH};
use crate::interfaces::Response;
use crate::miner::MinerNode;
use crate::pre_launch::PreLaunchNode;
use crate::storage::StorageNode;
use crate::upgrade::{
    upgrade_same_version_compute_db, upgrade_same_version_storage_db,
    upgrade_same_version_wallet_db,
};
use crate::user::{
    make_rb_payment_receipt_tx_and_response, make_rb_payment_send_transaction,
    make_rb_payment_send_tx_and_request, UserNode,
};
use crate::utils::{
    concat_maps, decode_pub_key, decode_secret_key, get_test_common_unicorn,
    loop_connnect_to_peers_async, loop_wait_connnect_to_peers_async, make_utxo_set_from_seed,
    LocalEventSender, ResponseResult, StringError,
};
use futures::future::join_all;
use naom::crypto::sign_ed25519 as sign;
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use naom::script::lang::Script;
use naom::utils::transaction_utils::{construct_tx_hash, construct_tx_in_signable_hash};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::error_span;
use tracing::info;
use tracing_futures::Instrument;

pub type ArcMinerNode = Arc<Mutex<MinerNode>>;
pub type ArcComputeNode = Arc<Mutex<ComputeNode>>;
pub type ArcStorageNode = Arc<Mutex<StorageNode>>;
pub type ArcUserNode = Arc<Mutex<UserNode>>;
pub type ArcPreLaunchNode = Arc<Mutex<PreLaunchNode>>;

/// Represents a virtual configurable Zenotta network.
pub struct Network {
    config: NetworkConfig,
    /// The info needed to create network nodes
    instance_info: NetworkInstanceInfo,
    /// All networked nodes
    arc_nodes: BTreeMap<String, ArcNode>,
    /// Handles for raft loop tasks
    raft_loop_handles: BTreeMap<String, JoinHandle<()>>,
    /// Currently active miner nodes
    active_nodes: BTreeMap<NodeType, Vec<String>>,
    /// compute to miner mapping of only active nodes
    active_compute_to_miner_mapping: BTreeMap<String, Vec<String>>,
    /// Currently dead nodes
    dead_nodes: BTreeSet<String>,
    /// Extra params to use for node construction
    extra_params: BTreeMap<String, ExtraNodeParams>,
}

/// Represents a virtual network configuration.
/// Can be created using the builder or deserialized from JSON.
#[derive(Clone)]
pub struct NetworkConfig {
    pub initial_port: u16,
    pub compute_raft: bool,
    pub storage_raft: bool,
    pub in_memory_db: bool,
    pub compute_partition_full_size: usize,
    pub compute_minimum_miner_pool_len: usize,
    pub compute_seed_utxo: UtxoSetSpec,
    pub compute_genesis_tx_in: Option<String>,
    pub user_wallet_seeds: Vec<Vec<WalletTxSpec>>,
    pub nodes: BTreeMap<NodeType, Vec<String>>,
    pub compute_to_miner_mapping: BTreeMap<String, Vec<String>>,
    pub test_duration_divider: usize,
    pub passphrase: Option<String>,
    pub user_auto_donate: u64,
    pub user_test_auto_gen_setup: UserAutoGenTxSetup,
    pub tls_config: TestTlsSpec,
    pub routes_pow: BTreeMap<String, usize>,
    pub backup_block_modulo: Option<u64>,
    pub backup_restore: Option<bool>,
    pub enable_pipeline_reset: Option<bool>,
}

/// Node info to create node
#[derive(Clone)]
pub struct NetworkNodeInfo {
    pub node_spec: NodeSpec,
    pub node_type: NodeType,
    pub db_mode: DbMode,
    pub index: usize,
}

/// Info needed to create all nodes in network
pub struct NetworkInstanceInfo {
    pub node_infos: BTreeMap<String, NetworkNodeInfo>,
    pub socket_name_mapping: BTreeMap<SocketAddr, String>,
    pub miner_nodes: Vec<NodeSpec>,
    pub compute_nodes: Vec<NodeSpec>,
    pub storage_nodes: Vec<NodeSpec>,
    pub user_nodes: Vec<NodeSpec>,
}

#[derive(Clone, Default)]
pub struct TestTlsSpec {
    pub pem_certificates: BTreeMap<String, String>,
    pub pem_pkcs8_private_keys: BTreeMap<String, String>,
    pub pem_certificates_with_ca: BTreeMap<String, String>,
    pub pem_pkcs8_private_keys_with_ca: BTreeMap<String, String>,
}

impl TestTlsSpec {
    pub fn make_tls_spec(&self, socket_name_mapping: &BTreeMap<SocketAddr, String>) -> TlsSpec {
        TlsSpec {
            socket_name_mapping: socket_name_mapping.clone(),
            pem_certificates: concat_maps(&self.pem_certificates, &self.pem_certificates_with_ca),
            pem_pkcs8_private_keys: concat_maps(
                &self.pem_pkcs8_private_keys,
                &self.pem_pkcs8_private_keys_with_ca,
            ),
            untrusted_names: Some(self.pem_certificates_with_ca.keys().cloned().collect()),
            pem_certificate_override: None,
            pem_pkcs8_private_key_override: None,
        }
    }
}

/// Types of nodes to create
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeType {
    Miner,
    Compute,
    Storage,
    User,
}

impl Network {
    ///Creates a Network instance using a config object
    ///
    /// ###Arguments
    ///
    /// * `config` - Holds the values to instanciate a Network object
    pub async fn create_from_config(config: &NetworkConfig) -> Self {
        let mut value = Self::create_stopped_from_config(config);
        value.re_spawn_dead_nodes().await;
        value
    }

    ///Creates a Network instance using a config object
    ///
    /// ###Arguments
    ///
    /// * `config` - Holds the values to instanciate a Network object
    pub fn create_stopped_from_config(config: &NetworkConfig) -> Self {
        let info = init_instance_info(config);
        let dead = info.node_infos.keys().cloned().collect();

        Self {
            config: config.clone(),
            active_nodes: config.nodes.clone(),
            active_compute_to_miner_mapping: config.compute_to_miner_mapping.clone(),
            instance_info: info,
            arc_nodes: Default::default(),
            raft_loop_handles: Default::default(),
            dead_nodes: dead,
            extra_params: Default::default(),
        }
    }

    /// Kill all nodes.
    pub async fn close_raft_loops_and_drop(mut self) -> BTreeMap<String, ExtraNodeParams> {
        close_raft_loops(&self.arc_nodes, &mut self.raft_loop_handles).await;
        stop_listening(&self.arc_nodes).await;
        disconnect_all_nodes(&self.arc_nodes).await;

        for (name, node) in &self.arc_nodes {
            let extra = take_closed_extra_params(node).await;
            self.extra_params.insert(name.clone(), extra);
        }
        self.extra_params
    }

    /// Add extra params to use
    pub fn add_extra_params(&mut self, name: &str, value: ExtraNodeParams) {
        self.extra_params.insert(name.to_owned(), value);
    }

    /// Set all extra params
    pub fn set_all_extra_params(&mut self, extra_params: BTreeMap<String, ExtraNodeParams>) {
        self.extra_params = extra_params;
    }

    /// Re-connect specified nodes.
    pub async fn re_connect_nodes_named(&mut self, names: &[String]) {
        // Re-spawn specified nodes
        for name in names {
            self.dead_nodes.remove(name);
            if let Some(node) = self.arc_nodes.get(name) {
                let (mut node_conn, _, _) = connect_info_peers(node).await;
                node_conn.set_pause_listening(false).await;
            }
        }
        self.update_active_nodes();
        self.re_establish_all_missing_connections().await;
    }

    /// disconnect specified nodes.
    pub async fn disconnect_nodes_named(&mut self, names: &[String]) {
        info!("Start disconnect to peers");
        for name in names {
            if let Some(node) = self.arc_nodes.get(name) {
                let (mut node_conn, _, _) = connect_info_peers(node).await;
                node_conn.set_pause_listening(true).await;
                join_all(node_conn.disconnect_all(None).await).await;
            }
        }
        // Remove from active nodes
        self.dead_nodes.extend(names.iter().cloned());
        self.update_active_nodes();
    }

    /// Re-spawn specified nodes.
    pub async fn re_spawn_dead_nodes(&mut self) {
        let dead: Vec<String> = self.dead_nodes.iter().cloned().collect();
        self.re_spawn_nodes_named(&dead).await;
    }

    /// Re-spawn specified nodes.
    pub async fn re_spawn_nodes_named(&mut self, names: &[String]) {
        // Re-spawn specified nodes
        let mut arc_nodes = BTreeMap::new();
        for name in names {
            let extra = self.extra_params.remove(name).unwrap_or_default();
            let arc_node = init_arc_node(name, &self.config, &self.instance_info, extra).await;
            arc_nodes.insert(name.clone(), arc_node);
            self.dead_nodes.remove(name);
        }
        self.arc_nodes.append(&mut arc_nodes.clone());
        self.update_active_nodes();
        self.re_establish_all_missing_connections().await;

        // Spawn new nodes raft loops
        let mut raft_loop_handles = spawn_raft_loops(&arc_nodes).await;
        self.raft_loop_handles.append(&mut raft_loop_handles);
    }

    /// Re-spawn specified nodes.
    pub async fn pre_launch_nodes_named(&mut self, names: &[String]) {
        // Re-spawn specified nodes
        let mut arc_nodes = BTreeMap::new();
        for name in names {
            let extra = self.extra_params.remove(name).unwrap_or_default();
            let arc_node = ArcNode::PreLaunch(
                init_pre_launch(name, &self.config, &self.instance_info, extra).await,
            );
            arc_nodes.insert(name.clone(), arc_node);
            self.dead_nodes.remove(name);
        }
        self.arc_nodes.append(&mut arc_nodes.clone());
        self.update_active_nodes();
        self.re_establish_all_missing_connections().await;
    }

    /// Kill specified nodes.
    pub async fn close_loops_and_drop_named(&mut self, names: &[String]) {
        let mut arc_nodes = BTreeMap::new();
        let mut raft_loop_handles = BTreeMap::new();

        // Kill nodes
        for name in names {
            if let Some((k, v)) = self.arc_nodes.remove_entry(name) {
                arc_nodes.insert(k, v);
            }
            if let Some((k, v)) = self.raft_loop_handles.remove_entry(name) {
                raft_loop_handles.insert(k, v);
            }
        }
        close_raft_loops(&arc_nodes, &mut raft_loop_handles).await;
        stop_listening(&arc_nodes).await;
        disconnect_all_nodes(&arc_nodes).await;

        // Store extra params for re-spawn
        for (name, node) in &arc_nodes {
            let extra = take_closed_extra_params(node).await;
            self.extra_params.insert(name.clone(), extra);
        }

        // Remove from active nodes
        self.dead_nodes.extend(names.iter().map(|v| v.to_string()));
        self.update_active_nodes();
    }

    /// Sent startup requests for specified node.
    pub async fn send_startup_requests_named(&mut self, names: &[String]) {
        for name in names {
            let node = self.arc_nodes.get(name).unwrap();
            send_startup_requests(node).await;
        }
    }

    pub async fn spawn_main_node_loops(
        &mut self,
        timeout: Duration,
    ) -> BTreeMap<String, JoinHandle<()>> {
        spawn_main_node_loops(&self.arc_nodes, timeout).await
    }

    /// Make all dead nodes as if upgraded.
    pub async fn upgrade_closed_nodes(&mut self) {
        for (name, extra) in std::mem::take(&mut self.extra_params) {
            let extra = upgrade_same_version_db(&name, &self.instance_info, extra).await;
            self.extra_params.insert(name, extra);
        }
    }

    /// Restore from config and Remove all dead nodes
    fn update_active_nodes(&mut self) {
        let mut active_nodes = self.config.nodes.clone();
        for nodes in active_nodes.values_mut() {
            nodes.retain(|n| !self.dead_nodes.contains(n));
        }

        let mut active_map: BTreeMap<_, _> = self
            .config
            .compute_to_miner_mapping
            .clone()
            .into_iter()
            .filter(|(c, _)| !self.dead_nodes.contains(c))
            .collect();

        for miners in active_map.values_mut() {
            miners.retain(|m| !self.dead_nodes.contains(m));
        }

        self.active_compute_to_miner_mapping = active_map;
        self.active_nodes = active_nodes;
    }

    /// Re-establish all missing connections
    async fn re_establish_all_missing_connections(&mut self) {
        let dead_addr: BTreeSet<_> = self
            .dead_nodes
            .iter()
            .map(|n| self.instance_info.node_infos[n].node_spec.address)
            .collect();
        connect_all_nodes(&self.arc_nodes, &dead_addr).await;
    }

    ///Returns a mutable reference to the miner node with the matching name
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the miner node's name to be found.
    pub fn miner(&self, name: &str) -> Option<&ArcMinerNode> {
        self.arc_nodes.get(name).and_then(|v| v.miner())
    }

    ///returns a mutable reference to the compute node with the matching name.
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the compute node's name to be found.
    pub fn compute(&self, name: &str) -> Option<&ArcComputeNode> {
        self.arc_nodes.get(name).and_then(|v| v.compute())
    }

    ///returns a mutable reference to the storage node with the matching name.
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the storage node's name to be found.
    pub fn storage(&self, name: &str) -> Option<&ArcStorageNode> {
        self.arc_nodes.get(name).and_then(|v| v.storage())
    }

    ///returns a mutable reference to the user node with the matching name.
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the user node's name to be found.
    pub fn user(&self, name: &str) -> Option<&ArcUserNode> {
        self.arc_nodes.get(name).and_then(|v| v.user())
    }

    ///Searches all node types and returns an address to the node with the matching name.
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the name of the node found.
    pub async fn get_address(&self, name: &str) -> Option<SocketAddr> {
        if let Some(node) = self.arc_nodes.get(name) {
            Some(address(node).await)
        } else {
            None
        }
    }

    ///Get the requested node local event tx
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the name of the node found.
    pub async fn get_local_event_tx(&self, name: &str) -> Option<LocalEventSender> {
        if let Some(node) = self.arc_nodes.get(name) {
            Some(local_event_tx(node).await)
        } else {
            None
        }
    }

    ///Searches all node types and returns the position of the node with the matching name.
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the name of the node found.
    pub fn get_position(&mut self, name: &str) -> Option<usize> {
        self.instance_info.node_infos.get(name).map(|i| i.index)
    }

    ///Get the requested node info
    ///
    /// ### Arguments
    ///
    /// * `name` - &str of the name of the node found.
    pub fn get_node_info(&mut self, name: &str) -> Option<&NetworkNodeInfo> {
        self.instance_info.node_infos.get(name)
    }

    ///Returns a list of initial transactions
    pub fn collect_initial_uxto_txs(&self) -> BTreeMap<String, Transaction> {
        make_utxo_set_from_seed(
            &self.config.compute_seed_utxo,
            &self.config.compute_genesis_tx_in,
        )
    }

    ///Returns active nodes of given type
    pub fn active_nodes(&self, node_type: NodeType) -> &[String] {
        &self.active_nodes[&node_type]
    }

    ///Returns all active nodes
    pub fn all_active_nodes(&self) -> &BTreeMap<NodeType, Vec<String>> {
        &self.active_nodes
    }

    ///Returns all active nodes
    pub fn all_active_nodes_flat_iter(&self) -> impl Iterator<Item = (&NodeType, &String)> {
        self.active_nodes
            .iter()
            .flat_map(|(t, ns)| ns.iter().map(move |n| (t, n)))
    }

    ///Returns all active nodes
    pub fn all_active_nodes_name_vec(&self) -> Vec<String> {
        self.all_active_nodes_flat_iter()
            .map(|(_, n)| n.to_string())
            .collect()
    }

    ///Active Compute miner mapping
    pub fn active_compute_to_miner_mapping(&self) -> &BTreeMap<String, Vec<String>> {
        &self.active_compute_to_miner_mapping
    }

    ///Config that launched the network
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    ///Config that launched the network
    pub fn mut_config(&mut self) -> &mut NetworkConfig {
        &mut self.config
    }

    ///Dead nodes not currently active
    pub fn dead_nodes(&self) -> &BTreeSet<String> {
        &self.dead_nodes
    }

    ///Mining Reward
    pub fn mining_reward(&self) -> TokenAmount {
        let c_len = self.config.nodes[&NodeType::Compute].len();
        TokenAmount(7510185) / c_len as u64
    }

    ///Returns all active nodes
    pub fn all_active_nodes_events(
        &self,
        evts: impl Fn(NodeType, &str) -> Vec<String>,
    ) -> BTreeMap<String, Vec<String>> {
        self.all_active_nodes_flat_iter()
            .map(|(t, n)| (n.clone(), evts(*t, n)))
            .collect()
    }
}

impl NetworkConfig {
    pub fn nodes_mut(&mut self, node_type: NodeType) -> &mut Vec<String> {
        self.nodes.get_mut(&node_type).unwrap()
    }

    pub fn with_raft(mut self, use_raft: bool) -> Self {
        self.compute_raft = use_raft;
        self.storage_raft = use_raft;
        self
    }

    pub fn with_groups(mut self, raft_count: usize, miner_count: usize) -> Self {
        let (rc, mc) = (raft_count, miner_count);
        self.nodes.insert(
            NodeType::Compute,
            (0..rc).map(|idx| format!("compute{}", idx + 1)).collect(),
        );
        self.nodes.insert(
            NodeType::Storage,
            (0..rc).map(|idx| format!("storage{}", idx + 1)).collect(),
        );
        self.nodes.insert(
            NodeType::Miner,
            (0..mc).map(|idx| format!("miner{}", idx + 1)).collect(),
        );
        self.compute_to_miner_mapping = {
            let miner_nodes = &self.nodes[&NodeType::Miner];
            let compute_nodes = &self.nodes[&NodeType::Compute];
            let miners = miner_nodes.iter().cloned();
            let computes = compute_nodes.iter().cloned().cycle();
            let mut mapping = BTreeMap::new();
            for (miner, compute) in miners.zip(computes) {
                mapping.entry(compute).or_insert_with(Vec::new).push(miner);
            }
            mapping
        };
        self
    }
}

/// Nodes of any type
#[derive(Clone)]
pub enum ArcNode {
    Miner(ArcMinerNode),
    Compute(ArcComputeNode),
    Storage(ArcStorageNode),
    User(ArcUserNode),
    PreLaunch(ArcPreLaunchNode),
}

impl ArcNode {
    /// Get miner from node
    pub fn miner(&self) -> Option<&ArcMinerNode> {
        if let Self::Miner(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Get compute from node
    pub fn compute(&self) -> Option<&ArcComputeNode> {
        if let Self::Compute(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Get storage from node
    pub fn storage(&self) -> Option<&ArcStorageNode> {
        if let Self::Storage(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Get user from node
    pub fn user(&self) -> Option<&ArcUserNode> {
        if let Self::User(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub async fn get_local_event_tx(&self) -> LocalEventSender {
        match self {
            ArcNode::Compute(c) => c.lock().await.local_event_tx().clone(),
            ArcNode::Miner(m) => m.lock().await.local_event_tx().clone(),
            ArcNode::Storage(s) => s.lock().await.local_event_tx().clone(),
            ArcNode::User(u) => u.lock().await.local_event_tx().clone(),
            ArcNode::PreLaunch(p) => p.lock().await.local_event_tx().clone(),
        }
    }
}

///Dispatch to address
async fn address(node: &ArcNode) -> SocketAddr {
    match node {
        ArcNode::Miner(v) => v.lock().await.local_address(),
        ArcNode::Compute(v) => v.lock().await.local_address(),
        ArcNode::Storage(v) => v.lock().await.local_address(),
        ArcNode::User(v) => v.lock().await.local_address(),
        ArcNode::PreLaunch(v) => v.lock().await.local_address(),
    }
}

/// Dispatch to local_event_tx
async fn send_startup_requests(node: &ArcNode) {
    match node {
        ArcNode::Miner(v) => v.lock().await.send_startup_requests().await.unwrap(),
        ArcNode::Compute(v) => v.lock().await.send_startup_requests().await.unwrap(),
        ArcNode::Storage(v) => v.lock().await.send_startup_requests().await.unwrap(),
        ArcNode::User(v) => v.lock().await.send_startup_requests().await.unwrap(),
        ArcNode::PreLaunch(v) => v.lock().await.send_startup_requests().await.unwrap(),
    }
}

/// Dispatch to local_event_tx
async fn local_event_tx(node: &ArcNode) -> LocalEventSender {
    match node {
        ArcNode::Miner(v) => v.lock().await.local_event_tx().clone(),
        ArcNode::Compute(v) => v.lock().await.local_event_tx().clone(),
        ArcNode::Storage(v) => v.lock().await.local_event_tx().clone(),
        ArcNode::User(v) => v.lock().await.local_event_tx().clone(),
        ArcNode::PreLaunch(v) => v.lock().await.local_event_tx().clone(),
    }
}

///Dispatch to connect_info_peers
async fn connect_info_peers(node: &ArcNode) -> (Node, Vec<SocketAddr>, Vec<SocketAddr>) {
    match node {
        ArcNode::Miner(n) => n.lock().await.connect_info_peers(),
        ArcNode::Compute(n) => n.lock().await.connect_info_peers(),
        ArcNode::Storage(n) => n.lock().await.connect_info_peers(),
        ArcNode::User(n) => n.lock().await.connect_info_peers(),
        ArcNode::PreLaunch(n) => n.lock().await.connect_info_peers(),
    }
}

///Dispatch to close_raft_loop
async fn close_raft_loop(node: &ArcNode) {
    match node {
        ArcNode::Compute(n) => n.lock().await.close_raft_loop().await,
        ArcNode::Storage(n) => n.lock().await.close_raft_loop().await,
        ArcNode::Miner(_) | ArcNode::User(_) | ArcNode::PreLaunch(_) => (),
    }
}

///Dispatch to raft_loop, providing also the address and a tag.
async fn raft_loop(node: &ArcNode) -> Option<(String, SocketAddr, impl Future<Output = ()>)> {
    use futures::future::FutureExt;
    match node {
        ArcNode::Compute(n) => {
            let node = n.lock().await;
            Some((
                "compute_node".to_owned(),
                node.local_address(),
                node.raft_loop().left_future(),
            ))
        }
        ArcNode::Storage(n) => {
            let node = n.lock().await;
            Some((
                "storage_node".to_owned(),
                node.local_address(),
                node.raft_loop().right_future(),
            ))
        }
        ArcNode::Miner(_) | ArcNode::User(_) | ArcNode::PreLaunch(_) => None,
    }
}

///Dispatch to take_closed_extra_params
async fn take_closed_extra_params(node: &ArcNode) -> ExtraNodeParams {
    match node {
        ArcNode::Compute(n) => n.lock().await.take_closed_extra_params().await,
        ArcNode::Storage(n) => n.lock().await.take_closed_extra_params().await,
        ArcNode::Miner(n) => n.lock().await.take_closed_extra_params().await,
        ArcNode::User(n) => n.lock().await.take_closed_extra_params().await,
        ArcNode::PreLaunch(n) => n.lock().await.take_closed_extra_params().await,
    }
}

///Dispatch processing next event and response
async fn handle_next_event_and_response(
    node: &ArcNode,
    timeout: Duration,
) -> Result<ResponseResult, String> {
    let mut test_timeout = test_timeout(timeout);

    match node {
        ArcNode::Compute(n) => {
            let mut n = n.lock().await;
            if let Some(response) = check_timeout(n.handle_next_event(&mut test_timeout).await)? {
                return Ok(n.handle_next_event_response(response).await);
            }
            Ok(ResponseResult::Exit)
        }
        ArcNode::Storage(n) => {
            let mut n = n.lock().await;
            if let Some(response) = check_timeout(n.handle_next_event(&mut test_timeout).await)? {
                return Ok(n.handle_next_event_response(response).await);
            }
            Ok(ResponseResult::Exit)
        }
        ArcNode::Miner(n) => {
            let mut n = n.lock().await;
            if let Some(response) = check_timeout(n.handle_next_event(&mut test_timeout).await)? {
                return Ok(n.handle_next_event_response(response).await);
            }
            Ok(ResponseResult::Exit)
        }
        ArcNode::User(n) => {
            let mut n = n.lock().await;
            if let Some(response) = check_timeout(n.handle_next_event(&mut test_timeout).await)? {
                return Ok(n.handle_next_event_response(response).await);
            }
            Ok(ResponseResult::Exit)
        }
        ArcNode::PreLaunch(n) => {
            let mut n = n.lock().await;
            if let Some(response) = check_timeout(n.handle_next_event(&mut test_timeout).await)? {
                return Ok(n.handle_next_event_response(response).await);
            }
            Ok(ResponseResult::Exit)
        }
    }
}

///Creates a NetworkInstanceInfo object with config object values.
///
/// ### Arguments
///
/// * `config` - &NetworkConfig object containing parameters for the NetworkInstanceInfo object creation.
pub fn init_instance_info(config: &NetworkConfig) -> NetworkInstanceInfo {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut first_port = config.initial_port;
    let tls_config = &config.tls_config;

    let mut nodes = BTreeMap::new();
    for (node_type, names) in &config.nodes {
        let (next_port, specs) = node_specs(ip, first_port, names.len());
        nodes.insert(*node_type, (names, specs));
        first_port = next_port;
    }

    let mem_db = config.in_memory_db;
    let node_infos: BTreeMap<_, _> = nodes
        .iter()
        .flat_map(|(node_type, infos)| node_infos(*node_type, infos, mem_db))
        .collect();
    let socket_name_mapping: BTreeMap<_, _> = node_infos
        .iter()
        .map(|(name, info)| (info.node_spec.address, get_test_tls_name(name, tls_config)))
        .collect();

    let mut nodes: BTreeMap<_, _> = nodes.into_iter().map(|(k, (_, v))| (k, v)).collect();
    NetworkInstanceInfo {
        node_infos,
        socket_name_mapping,
        miner_nodes: nodes.remove(&NodeType::Miner).unwrap_or_default(),
        compute_nodes: nodes.remove(&NodeType::Compute).unwrap_or_default(),
        storage_nodes: nodes.remove(&NodeType::Storage).unwrap_or_default(),
        user_nodes: nodes.remove(&NodeType::User).unwrap_or_default(),
    }
}

///Return the infos necessary to initialize the node.
fn node_infos(
    node_type: NodeType,
    (node_names, node_specs): &(&Vec<String>, Vec<NodeSpec>),
    in_memory_db: bool,
) -> BTreeMap<String, NetworkNodeInfo> {
    node_names
        .iter()
        .zip(node_specs)
        .enumerate()
        .map(|(index, (name, node_spec))| {
            (
                name.clone(),
                NetworkNodeInfo {
                    node_spec: *node_spec,
                    node_type,
                    db_mode: if in_memory_db {
                        DbMode::InMemory
                    } else {
                        DbMode::Test(node_spec.address.port() as usize)
                    },
                    index,
                },
            )
        })
        .collect()
}

///Returns a u16, of the initial_port and node length, and a Vec of node specs
fn node_specs(ip: IpAddr, initial_port: u16, node_len: usize) -> (u16, Vec<NodeSpec>) {
    (
        initial_port + node_len as u16,
        (0..node_len)
            .map(|idx| NodeSpec {
                address: SocketAddr::new(ip, initial_port + idx as u16),
            })
            .collect(),
    )
}

/// Run main loops
///
/// ### Arguments
///
/// * `arc_nodes`   - Nodes to initialize.
/// * `timeout`     - Event timeout.
pub async fn spawn_main_node_loops(
    arc_nodes: &BTreeMap<String, ArcNode>,
    timeout: Duration,
) -> BTreeMap<String, JoinHandle<()>> {
    let mut main_loop_handles = BTreeMap::new();

    for (name, node) in arc_nodes.clone() {
        let addr = address(&node).await;
        let peer_span = error_span!("main_loop", ?name, ?addr);
        main_loop_handles.insert(
            name.clone(),
            tokio::spawn(
                async move {
                    info!("Start main loop");
                    send_startup_requests(&node).await;

                    loop {
                        match handle_next_event_and_response(&node, timeout).await {
                            Err(e) => panic!("{} - {}", e, &name),
                            Ok(ResponseResult::Continue) => (),
                            Ok(ResponseResult::Exit) => break,
                        }
                    }
                    info!("main loop complete");
                }
                .instrument(peer_span),
            ),
        );
    }

    main_loop_handles
}

/// Run raft loops
///
/// ### Arguments
///
/// * `arc_nodes`   - Nodes to initialize.
pub async fn spawn_raft_loops(
    arc_nodes: &BTreeMap<String, ArcNode>,
) -> BTreeMap<String, JoinHandle<()>> {
    let mut raft_loop_handles = BTreeMap::new();

    for (name, node) in arc_nodes {
        if let Some((t, addr, raft_loop)) = raft_loop(node).await {
            let peer_span = error_span!("", ?t, ?name, ?addr);
            raft_loop_handles.insert(
                name.clone(),
                tokio::spawn(
                    async move {
                        info!("Start raft");
                        raft_loop.await;
                        info!("raft complete");
                    }
                    .instrument(peer_span),
                ),
            );
        }
    }

    raft_loop_handles
}

/// Completes and ends raft loops.
///
/// ### Arguments
///
/// * `arc_nodes`        - Nodes to complete.
/// * `raft_loop_handles`- Nodes running handles.
pub async fn close_raft_loops(
    arc_nodes: &BTreeMap<String, ArcNode>,
    raft_loop_handles: &mut BTreeMap<String, JoinHandle<()>>,
) {
    info!("Close raft");
    for node in arc_nodes.values() {
        close_raft_loop(node).await
    }

    join_all(std::mem::take(raft_loop_handles).into_values()).await;
}

/// Stop node listening on port
///
/// ### Arguments
///
/// * `arc_nodes`        - Nodes to complete.
pub async fn stop_listening(arc_nodes: &BTreeMap<String, ArcNode>) {
    info!("Stop listening arc_nodes");
    for node in arc_nodes.values() {
        let (mut node_conn, _, _) = connect_info_peers(node).await;
        join_all(node_conn.stop_listening().await).await;
    }
}

///Disconnect all required nodes
///
/// ### Arguments
///
/// * `arc_nodes`        - Nodes to complete.
pub async fn disconnect_all_nodes(arc_nodes: &BTreeMap<String, ArcNode>) {
    // Need to connect first so Raft messages can be sent.
    info!("Start disconnect to peers");
    for node in arc_nodes.values() {
        let (mut node_conn, _, _) = connect_info_peers(node).await;
        join_all(node_conn.disconnect_all(None).await).await;
    }
}

///Connect all required nodes
///
/// ### Arguments
///
/// * `arc_nodes`   - Nodes to use.
/// * `dead`        - Dead nodes to ignore.
pub async fn connect_all_nodes(arc_nodes: &BTreeMap<String, ArcNode>, dead: &BTreeSet<SocketAddr>) {
    // Need to connect first so Raft messages can be sent.
    info!("Start connect to peers");
    for (name, node) in arc_nodes {
        let local_event_tx = node.get_local_event_tx().await;
        let (node_conn, mut addrs, _) = connect_info_peers(node).await;
        addrs.retain(|a| !dead.contains(a));

        loop_connnect_to_peers_async(node_conn, addrs, None, local_event_tx).await;
        info!(?name, "Peer connect complete");
    }

    info!("Peers connect complete");

    for node in arc_nodes.values() {
        let (node_conn, _, mut expected_connected_addrs) = connect_info_peers(node).await;
        expected_connected_addrs.retain(|a| !dead.contains(a));

        loop_wait_connnect_to_peers_async(node_conn, expected_connected_addrs).await;
    }
    info!("Peers connect complete: all connected");
}

/// Update the database for the node of given name based on network info.
/// The database will be as if the node was freshly upgraded.
///
/// ### Arguments
///
/// * `name`   - Name of the node.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
pub async fn upgrade_same_version_db(
    name: &str,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ExtraNodeParams {
    let node_info = &info.node_infos[name];
    info!("upgrade_same_version_db: {}", name);
    match node_info.node_type {
        NodeType::Miner => upgrade_same_version_wallet_db(extra).unwrap(),
        NodeType::Compute => upgrade_same_version_compute_db(extra).unwrap(),
        NodeType::Storage => upgrade_same_version_storage_db(extra).unwrap(),
        NodeType::User => upgrade_same_version_wallet_db(extra).unwrap(),
    }
}

///Initialize network node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
pub async fn init_arc_node(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcNode {
    let node_info = &info.node_infos[name];
    match node_info.node_type {
        NodeType::Miner => ArcNode::Miner(init_miner(name, config, info, extra).await),
        NodeType::Compute => ArcNode::Compute(init_compute(name, config, info, extra).await),
        NodeType::Storage => ArcNode::Storage(init_storage(name, config, info, extra).await),
        NodeType::User => ArcNode::User(init_user(name, config, info, extra).await),
    }
}

///Initialize Miner node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
async fn init_miner(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcMinerNode {
    let miner_compute_node_idx = {
        let name = name.to_owned();
        let mut mapping = config.compute_to_miner_mapping.iter();
        let (c, _) = mapping.find(|(_, ms)| ms.contains(&name)).unwrap();
        info.node_infos[c].index
    };

    // Create node
    let node_info = &info.node_infos[name];
    let config = MinerNodeConfig {
        miner_address: node_info.node_spec.address,
        miner_db_mode: node_info.db_mode,
        tls_config: config.tls_config.make_tls_spec(&info.socket_name_mapping),
        api_keys: Default::default(),
        miner_compute_node_idx,
        compute_nodes: info.compute_nodes.clone(),
        passphrase: config.passphrase.clone(),
        miner_api_port: 3004,
        miner_api_use_tls: true,
        routes_pow: config.routes_pow.clone(),
        backup_block_modulo: Default::default(),
    };
    let info_str = format!("{} -> {}", name, node_info.node_spec.address);
    info!("New Miner {}", info_str);
    Arc::new(Mutex::new(
        MinerNode::new(config, extra).await.expect(&info_str),
    ))
}

///Initialize Storage node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
async fn init_storage(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcStorageNode {
    let node_info = &info.node_infos[name];
    let storage_raft = usize::from(config.storage_raft);

    let config = StorageNodeConfig {
        storage_node_idx: node_info.index,
        storage_db_mode: node_info.db_mode,
        tls_config: config.tls_config.make_tls_spec(&info.socket_name_mapping),
        api_keys: Default::default(),
        compute_nodes: info.compute_nodes.clone(),
        storage_nodes: info.storage_nodes.clone(),
        storage_raft,
        storage_api_port: 3001,
        storage_api_use_tls: true,
        storage_raft_tick_timeout: 200 / config.test_duration_divider,
        storage_catchup_duration: 2000 / config.test_duration_divider,
        routes_pow: Default::default(),
        backup_block_modulo: config.backup_block_modulo,
        backup_restore: config.backup_restore,
    };
    let info = format!("{} -> {}", name, node_info.node_spec.address);
    info!("New Storage {}", info);
    Arc::new(Mutex::new(
        StorageNode::new(config, extra).await.expect(&info),
    ))
}

///Initialize Compute node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
async fn init_compute(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcComputeNode {
    let node_info = &info.node_infos[name];
    let compute_raft = usize::from(config.compute_raft);

    let config = ComputeNodeConfig {
        compute_db_mode: node_info.db_mode,
        compute_node_idx: node_info.index,
        tls_config: config.tls_config.make_tls_spec(&info.socket_name_mapping),
        api_keys: Default::default(),
        compute_unicorn_fixed_param: get_test_common_unicorn(),
        compute_nodes: info.compute_nodes.clone(),
        storage_nodes: info.storage_nodes.clone(),
        user_nodes: info.user_nodes.clone(),
        compute_raft,
        compute_raft_tick_timeout: 200 / config.test_duration_divider,
        compute_mining_event_timeout: 500 / config.test_duration_divider,
        compute_transaction_timeout: 100 / config.test_duration_divider,
        compute_seed_utxo: config.compute_seed_utxo.clone(),
        compute_genesis_tx_in: config.compute_genesis_tx_in.clone(),
        compute_partition_full_size: config.compute_partition_full_size,
        compute_minimum_miner_pool_len: config.compute_minimum_miner_pool_len,
        jurisdiction: "US".to_string(),
        sanction_list: Vec::new(),
        compute_api_port: 3002,
        compute_api_use_tls: true,
        routes_pow: Default::default(),
        backup_block_modulo: config.backup_block_modulo,
        backup_restore: config.backup_restore,
        enable_trigger_messages_pipeline_reset: config.enable_pipeline_reset,
    };
    let info = format!("{} -> {}", name, node_info.node_spec.address);
    info!("New Compute {}", info);
    Arc::new(Mutex::new(
        ComputeNode::new(config, extra).await.expect(&info),
    ))
}

///Initialize User node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
async fn init_user(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcUserNode {
    let node_info = &info.node_infos[name];

    let user_wallet_seeds = if config.user_wallet_seeds.is_empty()
        || config.user_wallet_seeds.len() <= node_info.index
    {
        vec![]
    } else {
        config.user_wallet_seeds[node_info.index].clone()
    };

    let config = UserNodeConfig {
        user_address: node_info.node_spec.address,
        user_db_mode: node_info.db_mode,
        tls_config: config.tls_config.make_tls_spec(&info.socket_name_mapping),
        api_keys: Default::default(),
        user_compute_node_idx: 0,
        compute_nodes: info.compute_nodes.clone(),
        user_api_port: 3000,
        user_api_use_tls: true,
        user_wallet_seeds,
        passphrase: config.passphrase.clone(),
        user_auto_donate: config.user_auto_donate,
        user_test_auto_gen_setup: config.user_test_auto_gen_setup.clone(),
        routes_pow: Default::default(),
        backup_block_modulo: Default::default(),
    };

    let info = format!("{} -> {}", name, node_info.node_spec.address);
    info!("New User {}", info);
    Arc::new(Mutex::new(UserNode::new(config, extra).await.expect(&info)))
}

///Initialize PreLauch node of given name based on network info.
///
/// ### Arguments
///
/// * `name`   - Name of the node to initialize.
/// * `config` - &NetworkConfig holding configuration Infomation.
/// * `info`   - &NetworkInstanceInfo holding nodes to be cloned.
/// * `extra`  - additional parameter for construction
async fn init_pre_launch(
    name: &str,
    config: &NetworkConfig,
    info: &NetworkInstanceInfo,
    extra: ExtraNodeParams,
) -> ArcPreLaunchNode {
    let node_info = &info.node_infos[name];
    let node_type = match node_info.node_type {
        NodeType::Compute => PreLaunchNodeType::Compute,
        NodeType::Storage => PreLaunchNodeType::Storage,
        NodeType::Miner | NodeType::User => panic!("No pre launch fot this type"),
    };

    let config = PreLaunchNodeConfig {
        node_type,
        compute_node_idx: node_info.index,
        compute_db_mode: node_info.db_mode,
        tls_config: config.tls_config.make_tls_spec(&info.socket_name_mapping),
        storage_node_idx: node_info.index,
        storage_db_mode: node_info.db_mode,
        compute_nodes: info.compute_nodes.clone(),
        storage_nodes: info.storage_nodes.clone(),
    };

    let info = format!("{} -> {}", name, node_info.node_spec.address);
    info!("New PreLaunch {}", info);
    Arc::new(Mutex::new(
        PreLaunchNode::new(config, extra).await.expect(&info),
    ))
}

/// Remove all db for the given config
pub fn remove_all_node_dbs(config: &NetworkConfig) {
    let info = init_instance_info(config);
    remove_all_node_dbs_in_info(&info);
}

/// Remove all db for the given instance info
pub fn remove_all_node_dbs_in_info(info: &NetworkInstanceInfo) {
    for node in info.node_infos.values() {
        let port = node.node_spec.address.port();
        use NodeType::*;
        let db_paths = match node.node_type {
            Miner | User => {
                let v = format!("{WALLET_PATH}/{DB_PATH_TEST}.{port}");
                vec![v]
            }
            Compute => {
                let v1 = format!("{DB_PATH}/{DB_PATH_TEST}.compute.{port}");
                let v2 = format!("{DB_PATH}/{DB_PATH_TEST}.compute_raft.{port}");
                let v3 = format!("{v1}_backup");
                let v4 = format!("{v2}_backup");
                vec![v1, v2, v3, v4]
            }
            Storage => {
                let v1 = format!("{DB_PATH}/{DB_PATH_TEST}.storage.{port}");
                let v2 = format!("{DB_PATH}/{DB_PATH_TEST}.storage_raft.{port}");
                let v3 = format!("{v1}_backup");
                let v4 = format!("{v2}_backup");
                vec![v1, v2, v3, v4]
            }
        };
        for to_remove in db_paths {
            if let Err(e) = std::fs::remove_dir_all(to_remove.clone()) {
                info!("Not removed local db: {}, {:?}", to_remove, e);
            }
        }
    }
}

/// Future timeout to use for handle_next_event
fn test_timeout(timeout: Duration) -> impl Future<Output = &'static str> + Unpin {
    Box::pin(async move {
        tokio::time::sleep(timeout).await;
        "Test timeout elapsed"
    })
}

/// Wrap response in result, erroring if timed out
fn check_timeout<E>(
    response: Option<Result<Response, E>>,
) -> Result<Option<Result<Response, E>>, String> {
    if let Some(Ok(Response {
        success: true,
        reason: "Test timeout elapsed",
    })) = response
    {
        Err("Test timeout elapsed".to_owned())
    } else {
        Ok(response)
    }
}

/// join all handles panic if any error and provide helpful message
pub async fn node_join_all_checked<T, E: std::fmt::Debug>(
    join_handles: BTreeMap<String, JoinHandle<T>>,
    extra: &E,
) -> Result<(), StringError> {
    let (node_group, join_handles): (Vec<_>, Vec<_>) = join_handles.into_iter().unzip();
    let join_result: Vec<_> = join_all(join_handles).await;
    let join_result = join_result.iter().zip(&node_group);
    let failed_join = join_result.filter(|(r, _)| r.is_err());
    let failed_join: Vec<_> = failed_join.map(|(_, name)| name).collect();

    if !failed_join.is_empty() {
        Err(StringError(format!(
            "Failed joined {failed_join:?}, out of {node_group:?} (extra: {extra:?})"
        )))
    } else {
        Ok(())
    }
}

pub fn get_test_tls_spec() -> TestTlsSpec {
    TestTlsSpec {
        pem_certificates: test_tls_certificates::TEST_PEM_CERTIFICATES
            .iter()
            .copied()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        pem_pkcs8_private_keys: test_tls_certificates::TEST_PKCS8_KEYS
            .iter()
            .copied()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        pem_certificates_with_ca: test_tls_certificates::TEST_PEM_CERTIFICATES_WITH_CA
            .iter()
            .copied()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        pem_pkcs8_private_keys_with_ca: test_tls_certificates::TEST_PKCS8_KEYS_WITH_CA
            .iter()
            .copied()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    }
}

pub fn get_test_tls_name(name: &str, spec: &TestTlsSpec) -> String {
    let tls_name = format!("{name}.zenotta.xyz");
    if spec.pem_certificates.contains_key(&tls_name)
        || spec.pem_certificates_with_ca.contains_key(&tls_name)
    {
        tls_name
    } else {
        "node.zenotta.xyz".to_owned()
    }
}

pub fn get_common_tls_config() -> TcpTlsConfig {
    let addr = "127.0.0.1:0".parse().unwrap();
    let mapping = vec![(addr, "node.zenotta.xyz".to_owned())]
        .into_iter()
        .collect();
    let tls_spec = get_test_tls_spec().make_tls_spec(&mapping);
    TcpTlsConfig::from_tls_spec(addr, &tls_spec).unwrap()
}

pub async fn get_bound_common_tls_configs(
    names: &[&str],
    update_spec: impl Fn(&str, TlsSpec) -> TlsSpec,
) -> Vec<TcpTlsConfig> {
    let mut mapping = BTreeMap::new();
    let mut listeners = Vec::new();
    let tls_spec = get_test_tls_spec();
    for name in names.iter().copied() {
        let mut address = "127.0.0.1:0".parse().unwrap();
        let tcp_listener = TcpTlsListner::new_raw_listner(address).await.unwrap();
        address.set_port(tcp_listener.local_addr().unwrap().port());

        info!("Bound name address: {}: {:?}", name, address);
        mapping.insert(address, get_test_tls_name(name, &tls_spec));
        listeners.push((address, tcp_listener));
    }

    let mut configs = Vec::new();
    for (address, tcp_listener) in listeners.drain(..) {
        let name = &mapping[&address];
        let tls_spec = update_spec(name, tls_spec.make_tls_spec(&mapping));
        let config = TcpTlsConfig::from_tls_spec(address, &tls_spec).unwrap();
        let config = config.with_listener(tcp_listener).await;
        configs.push(config);
    }
    configs
}

pub struct RbSenderData {
    pub sender_pub_addr: String,
    pub sender_pub_key: String,
    pub sender_sec_key: String,
    pub sender_prev_out: OutPoint,
    pub sender_amount: TokenAmount,
    pub sender_half_druid: String,
    pub sender_expected_drs: Option<String>,
}

pub struct RbReceiverData {
    pub receiver_pub_addr: String,
    pub receiver_pub_key: String,
    pub receiver_sec_key: String,
    pub receiver_prev_out: OutPoint,
    pub receiver_half_druid: String,
}

// Generates a receipt-based transaction using the given sender and receiver data.
pub fn generate_rb_transactions(
    rb_sender_data: RbSenderData,
    rb_receiver_data: RbReceiverData,
) -> Vec<(String, Transaction)> {
    let RbSenderData {
        sender_pub_addr,
        sender_pub_key,
        sender_sec_key,
        sender_prev_out,
        sender_amount,
        sender_half_druid,
        sender_expected_drs,
    } = rb_sender_data;

    let RbReceiverData {
        receiver_pub_addr,
        receiver_pub_key,
        receiver_sec_key,
        receiver_prev_out,
        receiver_half_druid,
    } = rb_receiver_data;

    let rb_send_signable_data = construct_tx_in_signable_hash(&sender_prev_out);
    let rb_send_singature = sign::sign_detached(
        rb_send_signable_data.as_bytes(),
        &decode_secret_key(&sender_sec_key).unwrap(),
    );

    let rb_send_tx_in = TxIn {
        previous_out: Some(sender_prev_out),
        script_signature: Script::pay2pkh(
            rb_send_signable_data,
            rb_send_singature,
            decode_pub_key(&sender_pub_key).unwrap(),
            None,
        ),
    };

    let rb_receive_signable_data = construct_tx_in_signable_hash(&receiver_prev_out);
    let rb_receive_singature = sign::sign_detached(
        rb_receive_signable_data.as_bytes(),
        &decode_secret_key(&receiver_sec_key).unwrap(),
    );

    let rb_receive_tx_in = TxIn {
        previous_out: Some(receiver_prev_out),
        script_signature: Script::pay2pkh(
            rb_receive_signable_data,
            rb_receive_singature,
            decode_pub_key(&receiver_pub_key).unwrap(),
            None,
        ),
    };

    let (rb_payment_data, rb_payment_request_data) = make_rb_payment_send_tx_and_request(
        Asset::Token(sender_amount),
        (vec![rb_send_tx_in], vec![TxOut::new()]),
        sender_half_druid,
        sender_pub_addr,
        sender_expected_drs,
    );

    let (rb_receive_tx, rb_payment_response) = make_rb_payment_receipt_tx_and_response(
        rb_payment_request_data,
        (vec![rb_receive_tx_in], vec![TxOut::new()]),
        receiver_half_druid,
        receiver_pub_addr,
    );

    let rb_send_tx = make_rb_payment_send_transaction(rb_payment_response, rb_payment_data);
    let t_r_hash = construct_tx_hash(&rb_receive_tx);
    let t_s_hash = construct_tx_hash(&rb_send_tx);

    vec![(t_r_hash, rb_receive_tx), (t_s_hash, rb_send_tx)]
}

/// Create a `BTreeMap` struct from a vector of (drs_tx_hash, `Receipt` amount)
///
/// ### Arguments
///
/// * `receipts` - A vector of (drs_tx_hash, `Receipt` amount)
pub fn map_receipts(details: Vec<(String, u64)>) -> BTreeMap<String, u64> {
    details.into_iter().collect()
}
