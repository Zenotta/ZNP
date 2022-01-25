//! Test suite for the network functions.

use crate::compute::ComputeNode;
use crate::configurations::{TxOutSpec, UserAutoGenTxSetup, UtxoSetSpec, WalletTxSpec};
use crate::constants::{BLOCK_PREPEND, NETWORK_VERSION, SANC_LIST_TEST};
use crate::interfaces::{
    BlockStoredInfo, BlockchainItem, BlockchainItemMeta, BlockchainItemType, CommonBlockInfo,
    ComputeRequest, MinedBlockExtraInfo, Response, StorageRequest, StoredSerializingBlock,
    UserApiRequest, UserRequest, UtxoFetchType, UtxoSet,
};
use crate::miner::MinerNode;
use crate::storage::StorageNode;
use crate::storage_raft::CompleteBlock;
use crate::test_utils::{
    get_test_tls_spec, node_join_all_checked, remove_all_node_dbs, Network, NetworkConfig, NodeType,
};
use crate::user::UserNode;
use crate::utils::{
    calculate_reward, concat_merkle_coinbase, create_valid_create_transaction_with_ins_outs,
    create_valid_transaction_with_ins_outs, decode_secret_key, get_sanction_addresses,
    tracing_log_try_init, validate_pow_block, LocalEvent, StringError,
};
use crate::wallet::AssetValues;
use bincode::{deserialize, serialize};
use naom::crypto::sign_ed25519 as sign;
use naom::crypto::sign_ed25519::{PublicKey, SecretKey};
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::block::Block;
use naom::primitives::transaction::{OutPoint, Transaction, TxOut};
use naom::script::StackEntry;
use naom::utils::transaction_utils::{
    construct_address, construct_coinbase_tx, construct_tx_hash,
    construct_tx_in_signable_asset_hash, get_tx_out_with_out_point_cloned,
};
use rand::{self, Rng};
use sha3::Digest;
use sha3::Sha3_256;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use tokio::sync::Mutex;
use tokio::time;
use tracing::{debug, error, error_span, info, warn};
use tracing_futures::Instrument;

const TIMEOUT_TEST_WAIT_DURATION: Duration = Duration::from_millis(5000);

#[cfg(not(debug_assertions))] // Release
const TEST_DURATION_DIVIDER: usize = 10;
#[cfg(debug_assertions)] // Debug
const TEST_DURATION_DIVIDER: usize = 1;

const SEED_UTXO: &[(i32, &str)] = &[(1, "000000"), (3, "000001"), (1, "000002")];
const VALID_TXS_IN: &[(i32, &str)] = &[(0, "000000"), (0, "000001"), (1, "000001")];
const VALID_TXS_OUT: &[&str] = &["000101", "000102", "000103"];
const DEFAULT_SEED_AMOUNT: TokenAmount = TokenAmount(3);

const BLOCK_RECEIVED: &str = "Block received to be added";
const BLOCK_STORED: &str = "Block complete stored";
const BLOCK_RECEIVED_AND_STORED: [&str; 2] = [BLOCK_RECEIVED, BLOCK_STORED];

const SOME_PUB_KEYS: [&str; 3] = [
    COMMON_PUB_KEY,
    "6e86cc1fc5efbe64c2690efbb966b9fe1957facc497dce311981c68dac88e08c",
    "8b835e00c57ebff6637ec32276f2c6c0df71129c8f0860131a78a4692a0b59dc",
];

const SOME_SEC_KEYS: [&str; 3] = [
    COMMON_SEC_KEY,
    "3053020101300506032b65700422042070391d510eb988291d2dca15e5b8a54c552b4f2361bf29b1b945300a3e7cc9b4a1230321006e86cc1fc5efbe64c2690efbb966b9fe1957facc497dce311981c68dac88e08c",
    "3053020101300506032b6570042204201842082f6d8b0ecf75a309544980027e15ed1c00e95a14063705b2a4fc358670a1230321008b835e00c57ebff6637ec32276f2c6c0df71129c8f0860131a78a4692a0b59dc",
];

const SOME_PUB_KEY_ADDRS: [&str; 3] = [
    COMMON_PUB_ADDR,
    "77516e2d91606250e625546f86702510d2e893e4a27edfc932fdba03c955cc1b",
    "4cfd64a6692021fc417368a866d33d94e1c806747f61ac85e0b3935e7d5ed925",
];

const COMMON_PUB_KEY: &str = "5371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c";
const COMMON_SEC_KEY: &str = "3053020101300506032b6570042204200186bc08f16428d2059227082b93e439ff50f8c162f24b9594b132f2cc15fca4a1230321005371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c";
const COMMON_PUB_ADDR: &str = "5423e6bd848e0ce5cd794e55235c23138d8833633cd2d7de7f4a10935178457b";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Cfg {
    All,
    IgnoreStorage,
    IgnoreCompute,
    IgnoreMiner,
    IgnoreWaitTxComplete,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CfgNum {
    All,
    Majority,
}

#[derive(Clone, Debug)]
enum CfgModif {
    Drop(&'static str),
    Respawn(&'static str),
    HandleEvents(&'static [(&'static str, &'static str)]),
    RestartEventsAll(&'static [(NodeType, &'static str)]),
    RestartUpgradeEventsAll(&'static [(NodeType, &'static str)]),
    Disconnect(&'static str),
    Reconnect(&'static str),
}

#[test]
fn will_get_sanctioned_addresses() {
    let addresses = get_sanction_addresses(SANC_LIST_TEST.to_string(), &"US".to_string());
    assert!(addresses.contains(&"gjlkhflgkhdfklg".to_string()));

    let no_ju_addresses = get_sanction_addresses(SANC_LIST_TEST.to_string(), &"UK".to_string());
    assert_eq!(no_ju_addresses, Vec::<String>::new());

    let no_fs_addresses = get_sanction_addresses("/blah.json".to_string(), &"UK".to_string());
    assert_eq!(no_fs_addresses, Vec::<String>::new());
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_no_raft() {
    full_flow(complete_network_config(10500)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_real_db_1_node() {
    let mut cfg = complete_network_config_with_n_compute_raft(10505, 1);
    cfg.in_memory_db = false;

    remove_all_node_dbs(&cfg);
    full_flow(cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_1_no_tls_node() {
    full_flow_no_tls(complete_network_config_with_n_compute_raft(10510, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_1_node() {
    full_flow(complete_network_config_with_n_compute_raft(10515, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_2_nodes() {
    full_flow(complete_network_config_with_n_compute_raft(10520, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_3_nodes() {
    full_flow(complete_network_config_with_n_compute_raft(10530, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_majority_3_nodes() {
    full_flow_tls(
        complete_network_config_with_n_compute_raft(10540, 3),
        CfgNum::Majority,
        Vec::new(),
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_15_nodes() {
    full_flow(complete_network_config_with_n_compute_raft(10550, 15)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_multi_miners_no_raft() {
    full_flow_multi_miners(complete_network_config_with_n_compute_miner(
        11000, false, 1, 3,
    ))
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_multi_miners_raft_1_node() {
    full_flow_multi_miners(complete_network_config_with_n_compute_miner(
        11010, true, 1, 3,
    ))
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_multi_miners_raft_2_nodes() {
    full_flow_multi_miners(complete_network_config_with_n_compute_miner(
        11020, true, 2, 6,
    ))
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_kill_miner_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Drop("miner2")),
        ("After create block 1", CfgModif::Respawn("miner2")),
        (
            "After create block 1",
            CfgModif::HandleEvents(&[("compute2", "Received partition request successfully")]),
        ),
    ];
    let network_config = complete_network_config_with_n_compute_raft(11120, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_kill_compute_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Drop("compute2")),
        ("After create block 1", CfgModif::Respawn("compute2")),
        (
            "After create block 1",
            CfgModif::HandleEvents(&[
                ("compute2", "Snapshot applied"),
                ("compute2", "Transactions committed"),
                ("compute2", "Block committed"),
            ]),
        ),
    ];

    let network_config = complete_network_config_with_n_compute_raft(11140, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_kill_storage_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Drop("storage2")),
        ("After create block 1", CfgModif::Respawn("storage2")),
        (
            "After create block 1",
            CfgModif::HandleEvents(&[("storage2", BLOCK_STORED)]),
        ),
    ];

    let network_config = complete_network_config_with_n_compute_raft(11160, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_dis_and_re_connect_miner_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Disconnect("miner2")),
        ("After create block 1", CfgModif::Reconnect("miner2")),
    ];
    let network_config = complete_network_config_with_n_compute_raft(11180, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_dis_and_re_connect_compute_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Disconnect("compute2")),
        ("After create block 1", CfgModif::Reconnect("compute2")),
        (
            "After create block 1",
            CfgModif::HandleEvents(&[
                ("compute2", "Transactions committed"),
                ("compute2", "Block committed"),
            ]),
        ),
    ];

    let network_config = complete_network_config_with_n_compute_raft(11200, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_flow_raft_dis_and_re_connect_storage_node_3_nodes() {
    let modify_cfg = vec![
        ("After create block 0", CfgModif::Disconnect("storage2")),
        ("After create block 1", CfgModif::Reconnect("storage2")),
        (
            "After create block 1",
            CfgModif::HandleEvents(&[("storage2", BLOCK_STORED)]),
        ),
    ];

    let network_config = complete_network_config_with_n_compute_raft(11220, 3);
    full_flow_tls(network_config, CfgNum::All, modify_cfg).await;
}

async fn full_flow_multi_miners(mut network_config: NetworkConfig) {
    network_config.compute_partition_full_size = 2;
    network_config.compute_minimum_miner_pool_len = 3;
    full_flow(network_config).await;
}

async fn full_flow(network_config: NetworkConfig) {
    full_flow_tls(network_config, CfgNum::All, Vec::new()).await;
}

async fn full_flow_no_tls(network_config: NetworkConfig) {
    full_flow_common(network_config, CfgNum::All, Vec::new()).await;
}

async fn full_flow_tls(
    mut network_config: NetworkConfig,
    cfg_num: CfgNum,
    modify_cfg: Vec<(&str, CfgModif)>,
) {
    network_config.tls_config = get_test_tls_spec();
    full_flow_common(network_config, cfg_num, modify_cfg).await;
}

async fn full_flow_common(
    network_config: NetworkConfig,
    cfg_num: CfgNum,
    modify_cfg: Vec<(&str, CfgModif)>,
) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let miner_nodes = &network_config.nodes[&NodeType::Miner];
    let initial_utxo_txs = network.collect_initial_uxto_txs();
    let mining_reward = network.mining_reward();
    let transactions = valid_transactions(true);

    //
    // Act
    //
    create_first_block_act(&mut network).await;
    modify_network(&mut network, "After create block 0", &modify_cfg).await;
    proof_of_work_act(&mut network, Cfg::All, cfg_num).await;
    send_block_to_storage_act(&mut network, cfg_num).await;
    let stored0 = storage_get_last_block_stored(&mut network, "storage1").await;

    add_transactions_act(&mut network, &transactions).await;
    create_block_act(&mut network, Cfg::All, cfg_num).await;
    modify_network(&mut network, "After create block 1", &modify_cfg).await;
    proof_of_work_act(&mut network, Cfg::All, cfg_num).await;
    send_block_to_storage_act(&mut network, cfg_num).await;
    let stored1 = storage_get_last_block_stored(&mut network, "storage1").await;

    create_block_act(&mut network, Cfg::All, cfg_num).await;

    //
    // Assert
    //
    let actual1 = storage_all_get_last_stored_info(&mut network, storage_nodes).await;
    assert_eq!(equal_first(&actual1), node_all(storage_nodes, true));

    let stored0 = stored0.unwrap();
    let stored1 = stored1.unwrap();
    let stored0_mining_tx_len = stored0.mining_transactions.len();
    let stored1_mining_tx_len = stored1.mining_transactions.len();
    let majority = storage_nodes.len() / 2 + 1;
    assert!(
        stored0_mining_tx_len >= majority && stored1_mining_tx_len >= majority,
        "{} >= majority, {} >= majority, majority = {}",
        stored0_mining_tx_len,
        stored1_mining_tx_len,
        majority
    );

    let actual0_db_count =
        storage_all_get_stored_key_values_count(&mut network, storage_nodes).await;
    let expected_block0_db_count = 1 + initial_utxo_txs.len() + stored0_mining_tx_len;
    let expected_block1_db_count = 1 + transactions.len() + stored1_mining_tx_len;
    assert_eq!(
        actual0_db_count,
        node_all(
            storage_nodes,
            expected_block0_db_count + expected_block1_db_count
        )
    );

    let actual_w0 = node_all_combined_get_wallet_info(&mut network, miner_nodes).await;
    let expected_w0 =
        node_all_combined_expected_wallet_info(miner_nodes, mining_reward, &[&stored0]);
    assert_eq!((actual_w0.0, actual_w0.1.len(), actual_w0.2), expected_w0);

    test_step_complete(network).await;
}

async fn modify_network(network: &mut Network, tag: &str, modif_config: &[(&str, CfgModif)]) {
    for (_tag, modif) in modif_config.iter().filter(|(t, _)| tag == *t) {
        match modif {
            CfgModif::Drop(v) => network.close_loops_and_drop_named(&[v.to_string()]).await,
            CfgModif::Respawn(v) => {
                let nodes = vec![v.to_string()];
                network.re_spawn_nodes_named(&nodes).await;
                network.send_startup_requests_named(&nodes).await;
            }
            CfgModif::HandleEvents(es) => {
                let all_nodes = network.all_active_nodes_name_vec();
                let all_raisons = network.all_active_nodes_events(|_, n| {
                    let es_for_t = es.iter().filter(|(ne, _)| *ne == n);
                    es_for_t.map(|(_, e)| e.to_string()).collect()
                });
                node_all_handle_different_event(network, &all_nodes, &all_raisons).await
            }
            CfgModif::RestartEventsAll(es) | CfgModif::RestartUpgradeEventsAll(es) => {
                let all_nodes = network.all_active_nodes_name_vec();
                let all_raisons = network.all_active_nodes_events(|t, _| {
                    let es_for_t = es.iter().filter(|(te, _)| *te == t);
                    es_for_t.map(|(_, e)| e.to_string()).collect()
                });
                network.close_loops_and_drop_named(&all_nodes).await;
                if matches!(modif, CfgModif::RestartUpgradeEventsAll(_)) {
                    network.upgrade_closed_nodes().await;
                }
                network.re_spawn_nodes_named(&all_nodes).await;
                network.send_startup_requests_named(&all_nodes).await;
                if !es.is_empty() {
                    node_all_handle_different_event(network, &all_nodes, &all_raisons).await;
                }
            }
            CfgModif::Disconnect(v) => network.disconnect_nodes_named(&[v.to_string()]).await,
            CfgModif::Reconnect(v) => network.re_connect_nodes_named(&[v.to_string()]).await,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn create_first_block_no_raft() {
    create_first_block(complete_network_config(10000)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_first_block_raft_1_node() {
    create_first_block(complete_network_config_with_n_compute_raft(10010, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_first_block_raft_2_nodes() {
    create_first_block(complete_network_config_with_n_compute_raft(10020, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_first_block_raft_3_nodes() {
    create_first_block(complete_network_config_with_n_compute_raft(10030, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_first_block_raft_15_nodes() {
    create_first_block(complete_network_config_with_n_compute_raft(10040, 15)).await;
}

async fn create_first_block(network_config: NetworkConfig) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let expected_utxo = to_utxo_set(&network.collect_initial_uxto_txs());

    //
    // Act
    //
    create_first_block_act(&mut network).await;

    //
    // Assert
    //
    let utxo_set_after = compute_all_committed_utxo_set(&mut network, compute_nodes).await;
    assert_eq!(utxo_set_after, node_all(compute_nodes, expected_utxo));

    test_step_complete(network).await;
}

async fn create_first_block_act(network: &mut Network) {
    let config = network.config().clone();
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];
    let first_request_size = config.compute_minimum_miner_pool_len;

    info!("Test Step Connect nodes");
    for compute in compute_nodes {
        let miners = &config.compute_to_miner_mapping[compute];
        for (idx, miner) in miners.iter().enumerate() {
            node_send_startup_requests(network, miner).await;
            let evt = if idx == first_request_size - 1 {
                "Received first full partition request"
            } else {
                "Received partition request successfully"
            };
            compute_handle_event(network, compute, evt).await;
        }
    }

    info!("Test Step Create first Block");
    node_all_handle_event(network, compute_nodes, &["First Block committed"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_no_raft() {
    send_first_block_to_storage(complete_network_config(10800)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_raft_1_node() {
    send_first_block_to_storage(complete_network_config_with_n_compute_raft(10810, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_raft_2_nodes() {
    send_first_block_to_storage(complete_network_config_with_n_compute_raft(10820, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_raft_3_nodes() {
    send_first_block_to_storage(complete_network_config_with_n_compute_raft(10830, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_raft_majority_3_nodes() {
    send_first_block_to_storage_common(
        complete_network_config_with_n_compute_raft(10840, 3),
        CfgNum::Majority,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_first_block_to_storage_raft_15_nodes() {
    send_first_block_to_storage(complete_network_config_with_n_compute_raft(10850, 15)).await;
}

async fn send_first_block_to_storage(network_config: NetworkConfig) {
    send_first_block_to_storage_common(network_config, CfgNum::All).await;
}

async fn send_first_block_to_storage_common(network_config: NetworkConfig, cfg_num: CfgNum) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let initial_utxo_txs = network.collect_initial_uxto_txs();
    let c_mined = &node_select(compute_nodes, cfg_num);
    let (expected0, block_info0) = complete_first_block(&initial_utxo_txs, c_mined.len()).await;

    create_first_block_act(&mut network).await;
    compute_all_mining_block_mined(&mut network, c_mined, &block_info0).await;

    //
    // Act
    //
    send_block_to_storage_act(&mut network, cfg_num).await;

    //
    // Assert
    //
    let actual0 = storage_all_get_last_stored_info(&mut network, storage_nodes).await;
    assert_eq!(
        actual0[0],
        (
            Some(expected0.1),
            Some((
                expected0.0,
                0,             /*b_num*/
                c_mined.len(), /*mining txs*/
            ))
        )
    );
    assert_eq!(equal_first(&actual0), node_all(storage_nodes, true));

    let actual0_db_count =
        storage_all_get_stored_key_values_count(&mut network, storage_nodes).await;
    assert_eq!(
        actual0_db_count,
        node_all(storage_nodes, 1 + initial_utxo_txs.len() + c_mined.len())
    );

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_no_raft() {
    add_transactions(complete_network_config(10600)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_raft_1_node() {
    add_transactions(complete_network_config_with_n_compute_raft(10610, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_restart_tx_raft_1_node() {
    let tag = "After add local Transactions";
    let modify_cfg = vec![
        (tag, CfgModif::Drop("compute1")),
        (tag, CfgModif::Respawn("compute1")),
        (
            tag,
            CfgModif::HandleEvents(&[("compute1", "Snapshot applied")]),
        ),
    ];

    let network_config = complete_network_config_with_n_compute_raft(10615, 1);
    add_transactions_common(network_config, &modify_cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_raft_2_nodes() {
    add_transactions(complete_network_config_with_n_compute_raft(10620, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_raft_3_nodes() {
    add_transactions(complete_network_config_with_n_compute_raft(10630, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_transactions_raft_15_nodes() {
    add_transactions(complete_network_config_with_n_compute_raft(10640, 15)).await;
}

async fn add_transactions(network_config: NetworkConfig) {
    add_transactions_common(network_config, &[]).await;
}

async fn add_transactions_common(network_config: NetworkConfig, modify_cfg: &[(&str, CfgModif)]) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let transactions = valid_transactions(true);

    create_first_block_act(&mut network).await;

    //
    // Act
    //
    add_transactions_act_with(&mut network, &transactions, Cfg::IgnoreWaitTxComplete).await;
    modify_network(&mut network, "After add local Transactions", modify_cfg).await;
    add_transactions_act_with(&mut network, &Default::default(), Cfg::All).await;

    //
    // Assert
    //
    let actual = compute_all_committed_tx_pool(&mut network, compute_nodes).await;
    assert_eq!(actual[0], transactions);
    assert_eq!(equal_first(&actual), node_all(compute_nodes, true));

    test_step_complete(network).await;
}

async fn add_transactions_act(network: &mut Network, txs: &BTreeMap<String, Transaction>) {
    add_transactions_act_with(network, txs, Cfg::All).await;
}

async fn add_transactions_act_with(
    network: &mut Network,
    txs: &BTreeMap<String, Transaction>,
    cfg: Cfg,
) {
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];

    info!("Test Step Add Transactions");
    for tx in txs.values() {
        user_send_transaction_to_compute(network, "user1", "compute1", tx).await;
    }
    for _tx in txs.values() {
        compute_handle_event(network, "compute1", "Transactions added to tx pool").await;
    }

    if cfg != Cfg::IgnoreWaitTxComplete {
        node_all_handle_event(network, compute_nodes, &["Transactions committed"]).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_no_raft() {
    create_block(complete_network_config(10100)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_raft_1_node() {
    create_block(complete_network_config_with_n_compute_raft(10110, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_raft_2_nodes() {
    create_block(complete_network_config_with_n_compute_raft(10120, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_raft_3_nodes() {
    create_block(complete_network_config_with_n_compute_raft(10130, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_raft_majority_3_nodes() {
    create_block_common(
        complete_network_config_with_n_compute_raft(10140, 3),
        CfgNum::Majority,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_block_raft_15_nodes() {
    create_block(complete_network_config_with_n_compute_raft(10150, 15)).await;
}

async fn create_block(network_config: NetworkConfig) {
    create_block_common(network_config, CfgNum::All).await;
}

async fn create_block_common(network_config: NetworkConfig, cfg_num: CfgNum) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let transactions = valid_transactions(true);
    let transactions_h = transactions.keys().cloned().collect::<Vec<_>>();
    let transactions_utxo = to_utxo_set(&transactions);
    let (_, block_info0) = complete_first_block(&BTreeMap::new(), compute_nodes.len()).await;
    let block0_mining_tx = complete_block_mining_txs(&block_info0);
    let block0_mining_utxo = to_utxo_set(&block0_mining_tx);

    let mut left_init_utxo = to_utxo_set(&network.collect_initial_uxto_txs());
    remove_keys(&mut left_init_utxo, valid_txs_in().keys());

    create_first_block_act(&mut network).await;
    compute_all_mining_block_mined(&mut network, compute_nodes, &block_info0).await;
    send_block_to_storage_act(&mut network, CfgNum::All).await;
    add_transactions_act(&mut network, &transactions).await;

    //
    // Act
    //
    let block_transaction_before =
        compute_all_current_block_transactions(&mut network, compute_nodes).await;

    create_block_act(&mut network, Cfg::All, cfg_num).await;

    let block_transaction_after =
        compute_all_current_block_transactions(&mut network, compute_nodes).await;
    let utxo_set_after = compute_all_committed_utxo_set(&mut network, compute_nodes).await;

    //
    // Assert
    //
    assert_eq!(block_transaction_before, node_all(compute_nodes, None));
    assert_eq!(
        block_transaction_after,
        node_all(compute_nodes, Some(transactions_h))
    );

    let expected_utxo = merge_txs_3(&left_init_utxo, &transactions_utxo, &block0_mining_utxo);
    assert_eq!(len_and_map(&utxo_set_after[0]), len_and_map(&expected_utxo));
    assert_eq!(equal_first(&utxo_set_after), node_all(compute_nodes, true));

    test_step_complete(network).await;
}

async fn create_block_act(network: &mut Network, cfg: Cfg, cfg_num: CfgNum) {
    create_block_act_with(network, cfg, cfg_num, 0).await
}

async fn create_block_act_with(network: &mut Network, cfg: Cfg, cfg_num: CfgNum, block_num: u64) {
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];
    let (msg_c_nodes, msg_s_nodes) = node_combined_select(
        &network.config().nodes[&NodeType::Compute],
        &network.config().nodes[&NodeType::Storage],
        network.dead_nodes(),
        cfg_num,
    );

    info!("Test Step Storage signal new block");

    if cfg == Cfg::IgnoreStorage {
        let block = BlockStoredInfo {
            block_num,
            ..Default::default()
        };
        let req = ComputeRequest::SendBlockStored(block);
        compute_all_inject_next_event(network, &msg_s_nodes, &msg_c_nodes, req).await;
    } else {
        storage_all_send_stored_block(network, &msg_s_nodes).await;
    }
    compute_all_handle_event(network, &msg_c_nodes, "Received block stored").await;

    info!("Test Step Generate Block");
    node_all_handle_event(network, compute_nodes, &["Block committed"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_no_raft() {
    proof_of_work(complete_network_config(10200)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_raft_1_node() {
    proof_of_work(complete_network_config_with_n_compute_raft(10210, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_raft_2_nodes() {
    proof_of_work(complete_network_config_with_n_compute_raft(10220, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_raft_3_nodes() {
    proof_of_work(complete_network_config_with_n_compute_raft(10230, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_raft_majority_3_nodes() {
    proof_of_work_common(
        complete_network_config_with_n_compute_raft(10240, 3),
        CfgNum::Majority,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_multi_no_raft() {
    let mut cfg = complete_network_config_with_n_compute_miner(10250, false, 1, 3);
    cfg.compute_partition_full_size = 2;
    cfg.compute_minimum_miner_pool_len = 3;
    proof_of_work(cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_multi_raft_1_node() {
    let mut cfg = complete_network_config_with_n_compute_miner(10260, true, 1, 3);
    cfg.compute_partition_full_size = 2;
    cfg.compute_minimum_miner_pool_len = 3;
    proof_of_work(cfg).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_multi_raft_2_nodes() {
    let mut cfg = complete_network_config_with_n_compute_miner(10270, true, 2, 6);
    cfg.compute_partition_full_size = 2;
    cfg.compute_minimum_miner_pool_len = 3;
    proof_of_work(cfg).await;
}

async fn proof_of_work(network_config: NetworkConfig) {
    proof_of_work_common(network_config, CfgNum::All).await;
}

async fn proof_of_work_common(network_config: NetworkConfig, cfg_num: CfgNum) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];

    create_first_block_act(&mut network).await;
    create_block_act(&mut network, Cfg::IgnoreStorage, CfgNum::All).await;

    //
    // Act
    //
    let block_before = compute_all_mined_block_num(&mut network, compute_nodes).await;

    proof_of_work_act(&mut network, Cfg::All, cfg_num).await;
    proof_of_work_send_more_act(&mut network, cfg_num).await;

    let block_after = compute_all_mined_block_num(&mut network, compute_nodes).await;

    //
    // Assert
    //
    assert_eq!(block_before, node_all(compute_nodes, None));
    assert_eq!(
        block_after,
        node_all_or(compute_nodes, cfg_num, Some(1), None)
    );

    test_step_complete(network).await;
}

async fn proof_of_work_act(network: &mut Network, cfg: Cfg, cfg_num: CfgNum) {
    let config = network.config().clone();
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];
    let partition_size = config.compute_partition_full_size;
    let c_mined = &node_select(compute_nodes, cfg_num);
    let active_compute_to_miner_mapping = network.active_compute_to_miner_mapping().clone();

    info!("Test Step Miner block Proof of Work: partition-> rand num -> num pow -> pre-block -> block pow");
    if cfg == Cfg::IgnoreMiner {
        let (_, block_info) = complete_first_block(&BTreeMap::new(), c_mined.len()).await;
        compute_all_mining_block_mined(network, c_mined, &block_info).await;
        return;
    }

    for compute in c_mined {
        let partition_last_idx = partition_size - 1;
        let c_miners = &active_compute_to_miner_mapping.get(compute).unwrap();
        let in_miners: &[String] = &c_miners[0..std::cmp::min(partition_size, c_miners.len())];

        compute_flood_rand_num_to_requesters(network, compute).await;
        miner_all_handle_event(network, c_miners, "Received random number successfully").await;

        for (idx, miner) in c_miners.iter().enumerate() {
            miner_handle_event(network, miner, "Partition PoW complete").await;
            miner_process_found_partition_pow(network, miner).await;

            use std::cmp::Ordering::*;
            let (success, evt) = match idx.cmp(&partition_last_idx) {
                Less => (true, "Partition PoW received successfully"),
                Equal => (true, "Partition list is full"),
                Greater => (false, "Partition list is already full"),
            };

            if success {
                compute_handle_event(network, compute, evt).await;
            } else {
                compute_handle_error(network, compute, evt).await;
            }
        }

        compute_flood_block_to_partition(network, compute).await;
        miner_all_handle_event(network, in_miners, "Pre-block received successfully").await;
        miner_all_handle_event(network, in_miners, "Block PoW complete").await;
        compute_flood_transactions_to_partition(network, compute).await;
        miner_all_handle_event(network, in_miners, "Block is valid").await;

        if !c_miners.is_empty() {
            let win_miner: &String = &in_miners[0];
            miner_process_found_block_pow(network, win_miner).await;
            compute_handle_event(network, compute, "Received PoW successfully").await;
        }
    }
}

async fn proof_of_work_send_more_act(network: &mut Network, cfg_num: CfgNum) {
    let config = network.config().clone();
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];
    let c_mined = &node_select(compute_nodes, cfg_num);

    info!("Test Step Miner block Proof of Work to late");
    for compute in c_mined {
        let partition_size = config.compute_partition_full_size;
        let c_miners = config.compute_to_miner_mapping.get(compute).unwrap();
        let in_miners: &[String] = &c_miners[0..std::cmp::min(partition_size, c_miners.len())];
        for miner in in_miners {
            miner_process_found_block_pow(network, miner).await;
            compute_handle_error(network, compute, "Not block currently mined").await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn proof_winner_no_raft() {
    proof_winner(complete_network_config(10900)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_winner_raft_1_node() {
    proof_winner(complete_network_config_with_n_compute_raft(10910, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_winner_multi_no_raft() {
    proof_winner_multi(complete_network_config_with_n_compute_miner(
        10920, false, 1, 3,
    ))
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_winner_multi_raft_1_node() {
    proof_winner_multi(complete_network_config_with_n_compute_miner(
        10930, true, 1, 3,
    ))
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_winner_multi_raft_2_nodes() {
    proof_winner_multi(complete_network_config_with_n_compute_miner(
        10940, true, 2, 6,
    ))
    .await;
}

async fn proof_winner_multi(mut network_config: NetworkConfig) {
    network_config.compute_partition_full_size = 2;
    network_config.compute_minimum_miner_pool_len = 3;
    proof_winner(network_config).await;
}

async fn proof_winner(network_config: NetworkConfig) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let winning_miners: Vec<String> = network_config
        .compute_to_miner_mapping
        .values()
        .map(|ms| ms.first().unwrap().clone())
        .collect();
    let mining_reward = network.mining_reward();

    create_first_block_act(&mut network).await;

    //
    // Act
    // Does not allow miner reuse.
    //
    proof_of_work_act(&mut network, Cfg::All, CfgNum::All).await;
    send_block_to_storage_act(&mut network, CfgNum::All).await;
    create_block_act(&mut network, Cfg::All, CfgNum::All).await;

    let info_before = node_all_get_wallet_info(&mut network, &winning_miners).await;
    proof_winner_act(&mut network).await;
    let info_after = node_all_get_wallet_info(&mut network, &winning_miners).await;

    //
    // Assert
    //

    assert_eq!(
        info_before
            .iter()
            .map(|i| (&i.0, i.1.len(), i.2.len()))
            .collect::<Vec<_>>(),
        node_all(&winning_miners, (&AssetValues::default(), 1, 0)),
        "Info Before: {:?}",
        info_before
    );
    assert_eq!(
        info_after
            .iter()
            .map(|i| (&i.0, i.1.len(), i.2.len()))
            .collect::<Vec<_>>(),
        node_all(&winning_miners, (&AssetValues::new(mining_reward, 0), 2, 1)),
        "Info After: {:?}",
        info_after
    );

    test_step_complete(network).await;
}

async fn proof_winner_act(network: &mut Network) {
    let config = network.config().clone();
    let active_nodes = network.all_active_nodes().clone();
    let compute_nodes = &active_nodes[&NodeType::Compute];
    let miner_nodes = &active_nodes[&NodeType::Miner];

    if miner_nodes.len() < compute_nodes.len() {
        info!("Test Step Miner winner: Ignored/Miner re-use");
        return;
    }

    info!("Test Step Miner winner:");
    for compute in compute_nodes {
        let c_miners = &config.compute_to_miner_mapping.get(compute).unwrap();
        compute_flood_rand_num_to_requesters(network, compute).await;
        miner_all_handle_event(network, c_miners, "Received random number successfully").await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_no_raft() {
    send_block_to_storage(complete_network_config(10300)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_raft_1_node() {
    send_block_to_storage(complete_network_config_with_n_compute_raft(10310, 1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_raft_2_nodes() {
    send_block_to_storage(complete_network_config_with_n_compute_raft(10320, 2)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_raft_3_nodes() {
    send_block_to_storage(complete_network_config_with_n_compute_raft(10330, 3)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_raft_majority_3_nodes() {
    send_block_to_storage_common(
        complete_network_config_with_n_compute_raft(10340, 3),
        CfgNum::Majority,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn send_block_to_storage_raft_15_nodes() {
    send_block_to_storage(complete_network_config_with_n_compute_raft(10350, 15)).await;
}

async fn send_block_to_storage(network_config: NetworkConfig) {
    send_block_to_storage_common(network_config, CfgNum::All).await;
}

async fn send_block_to_storage_common(network_config: NetworkConfig, cfg_num: CfgNum) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let c_mined = &node_select(compute_nodes, cfg_num);

    let transactions = valid_transactions(true);
    let (expected1, block_info1) = complete_block(1, Some("0"), &transactions, c_mined.len()).await;
    let (_expected3, wrong_block3) = complete_block(3, Some("0"), &BTreeMap::new(), 1).await;
    let block1_mining_tx = complete_block_mining_txs(&block_info1);

    create_first_block_act(&mut network).await;
    proof_of_work_act(&mut network, Cfg::IgnoreMiner, CfgNum::All).await;
    send_block_to_storage_act(&mut network, CfgNum::All).await;

    compute_all_set_mining_block(&mut network, c_mined, &block_info1).await;
    compute_all_mining_block_mined(&mut network, c_mined, &block_info1).await;

    let initial_db_count =
        storage_all_get_stored_key_values_count(&mut network, storage_nodes).await;

    //
    // Act
    //
    storage_inject_send_block_to_storage(&mut network, "compute1", "storage1", &wrong_block3).await;
    storage_handle_event(&mut network, "storage1", BLOCK_RECEIVED).await;

    send_block_to_storage_act(&mut network, cfg_num).await;

    //
    // Assert
    //
    let actual1 = storage_all_get_last_stored_info(&mut network, storage_nodes).await;
    assert_eq!(
        actual1[0],
        (
            Some(expected1.1),
            Some((
                expected1.0,
                1,             /*b_num*/
                c_mined.len(), /*mining txs*/
            ))
        )
    );
    assert_eq!(equal_first(&actual1), node_all(storage_nodes, true));

    let actual0_db_count =
        storage_all_get_stored_key_values_count(&mut network, storage_nodes).await;
    assert_eq!(
        substract_vec(&actual0_db_count, &initial_db_count),
        node_all(
            storage_nodes,
            1 + transactions.len() + block1_mining_tx.len()
        )
    );

    test_step_complete(network).await;
}

async fn send_block_to_storage_act(network: &mut Network, cfg_num: CfgNum) {
    let active_nodes = network.all_active_nodes().clone();
    let storage_nodes = &active_nodes[&NodeType::Storage];

    let compute_no_mining = network
        .active_compute_to_miner_mapping()
        .iter()
        .filter(|(_, miners)| miners.is_empty())
        .map(|(c, _)| c.clone());
    let mut dead_nodes = network.dead_nodes().clone();
    dead_nodes.extend(compute_no_mining);

    let (msg_c_nodes, msg_s_nodes) = node_combined_select(
        &network.config().nodes[&NodeType::Compute],
        &network.config().nodes[&NodeType::Storage],
        &dead_nodes,
        cfg_num,
    );

    info!("Test Step Compute Send block to Storage");
    compute_all_send_block_to_storage(network, &msg_c_nodes).await;
    storage_all_handle_event(network, &msg_s_nodes, BLOCK_RECEIVED).await;
    node_all_handle_event(network, storage_nodes, &[BLOCK_STORED]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_raft_1_node() {
    let network_config = complete_network_config_with_n_compute_raft(11300, 1);
    main_loops_raft_1_node_common(network_config, vec![2], TokenAmount(17), 20, 1, 1_000, &[]).await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_raft_2_node() {
    let network_config = complete_network_config_with_n_compute_raft(11310, 2);
    main_loops_raft_1_node_common(network_config, vec![2], TokenAmount(17), 20, 1, 1_000, &[]).await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_raft_3_node() {
    let network_config = complete_network_config_with_n_compute_raft(11320, 3);
    main_loops_raft_1_node_common(network_config, vec![2], TokenAmount(17), 20, 1, 1_000, &[]).await
}

// Slow: Only run when explicitely specified for performance and large tests
// `RUST_LOG="info,raft=warn" cargo test --lib --release -- --ignored --nocapture main_loops_many_txs_threaded_raft_1_node`
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn main_loops_many_txs_threaded_raft_1_node() {
    let mut network_config = complete_network_config_with_n_compute_raft(11330, 1);
    network_config.test_duration_divider = 1;

    // 5_000 TxIn in transactions of 3 TxIn.
    // 10_000 TxIn available so we can create full transaction batch even if previous block did
    // not contain all transactions already created.
    main_loops_raft_1_node_common(
        network_config,
        vec![5],
        TokenAmount(1),
        1_000_000,
        10_000,
        5_000 / 3,
        &[],
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_restart_raft_1_node() {
    let network_config = complete_network_config_with_n_compute_raft(11340, 1);
    let stop_nums = vec![1, 2];
    let amount = TokenAmount(17);
    let modify = vec![("Before start 1", CfgModif::RestartEventsAll(&[]))];
    main_loops_raft_1_node_common(network_config, stop_nums, amount, 20, 1, 1_000, &modify).await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_restart_raft_3_node() {
    let network_config = complete_network_config_with_n_compute_raft(11350, 3);
    let stop_nums = vec![1, 2];
    let amount = TokenAmount(17);
    let modify = vec![("Before start 1", CfgModif::RestartEventsAll(&[]))];
    main_loops_raft_1_node_common(network_config, stop_nums, amount, 20, 1, 1_000, &modify).await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_restart_upgrade_raft_1_node() {
    let network_config = complete_network_config_with_n_compute_raft(11360, 1);
    let stop_nums = vec![1, 2];
    let amount = TokenAmount(17);
    let modify = vec![("Before start 1", CfgModif::RestartUpgradeEventsAll(&[]))];
    main_loops_raft_1_node_common(network_config, stop_nums, amount, 20, 1, 1_000, &modify).await
}

#[tokio::test(flavor = "current_thread")]
async fn main_loops_few_txs_restart_upgrade_raft_3_node() {
    let network_config = complete_network_config_with_n_compute_raft(11370, 3);
    let stop_nums = vec![1, 2];
    let amount = TokenAmount(17);
    let modify = vec![("Before start 1", CfgModif::RestartUpgradeEventsAll(&[]))];
    main_loops_raft_1_node_common(network_config, stop_nums, amount, 20, 1, 1_000, &modify).await
}

async fn main_loops_raft_1_node_common(
    mut network_config: NetworkConfig,
    expected_block_nums: Vec<u64>,
    initial_amount: TokenAmount,
    seed_count: i32,
    seed_wallet_count: i32,
    tx_max_count: usize,
    modify_cfg: &[(&str, CfgModif)],
) {
    test_step_start();

    //
    // Arrange
    // initial_amount is split into TokenAmount(1) TxOuts for the next round.
    //
    network_config.compute_seed_utxo =
        make_compute_seed_utxo(&[(seed_count, "000000")], initial_amount);
    network_config.user_test_auto_gen_setup = UserAutoGenTxSetup {
        user_initial_transactions: vec![(0..seed_wallet_count)
            .map(|i| wallet_seed((i, "000000"), &initial_amount))
            .collect()],
        user_setup_tx_chunk_size: Some(5),
        user_setup_tx_in_per_tx: Some(3),
        user_setup_tx_max_count: tx_max_count,
    };

    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let storage_nodes = &network_config.nodes[&NodeType::Storage];

    //
    // Act
    //
    let (mut actual_stored, mut expected_stored) = (Vec::new(), Vec::new());
    let (mut actual_compute, mut expected_compute) = (Vec::new(), Vec::new());
    for (idx, expected_block_num) in expected_block_nums.iter().copied().enumerate() {
        let tag = format!("Before start {}", idx);
        modify_network(&mut network, &tag, modify_cfg).await;

        for node_name in compute_nodes {
            node_send_coordinated_shutdown(&mut network, node_name, expected_block_num).await;
        }

        let handles = network
            .spawn_main_node_loops(TIMEOUT_TEST_WAIT_DURATION)
            .await;
        node_join_all_checked(handles, &"").await.unwrap();

        actual_stored
            .push(storage_all_get_last_block_stored_num(&mut network, storage_nodes).await);
        actual_compute
            .push(compute_all_committed_current_block_num(&mut network, compute_nodes).await);
        expected_stored.push(node_all(storage_nodes, Some(expected_block_num)));
        expected_compute.push(node_all(compute_nodes, Some(expected_block_num)));
    }

    //
    // Assert
    //
    assert_eq!(actual_stored, expected_stored);
    assert_eq!(actual_compute, expected_compute);

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn receive_payment_tx_user() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config(10400);
    network_config
        .nodes_mut(NodeType::User)
        .push("user2".to_string());
    network_config.compute_seed_utxo = make_compute_seed_utxo(SEED_UTXO, TokenAmount(11));
    network_config.user_wallet_seeds = vec![vec![wallet_seed(VALID_TXS_IN[0], &TokenAmount(11))]];
    let mut network = Network::create_from_config(&network_config).await;
    let user_nodes = &network_config.nodes[&NodeType::User];
    let amount = TokenAmount(5);

    create_first_block_act(&mut network).await;

    //
    // Act/Assert
    //
    let before = node_all_get_wallet_info(&mut network, user_nodes).await;

    node_connect_to(&mut network, "user1", "user2").await;

    // Process requested transactions:
    user_send_address_request(&mut network, "user1", "user2", amount).await;
    user_handle_event(&mut network, "user2", "New address ready to be sent").await;

    user_send_address_to_trading_peer(&mut network, "user2").await;
    user_handle_event(&mut network, "user1", "Next payment transaction ready").await;

    user_send_next_payment_to_destinations(&mut network, "user1", "compute1").await;
    compute_handle_event(&mut network, "compute1", "Transactions added to tx pool").await;
    user_handle_event(&mut network, "user2", "Payment transaction received").await;

    // Ignore donations:
    user_send_donation_address_to_peer(&mut network, "user2", "user1").await;
    user_handle_error(&mut network, "user1", "Ignore unexpected transaction").await;

    let after = node_all_get_wallet_info(&mut network, user_nodes).await;

    //
    // Assert
    //
    assert_eq!(
        before
            .iter()
            .map(|(total, _, _)| *total)
            .collect::<Vec<_>>(),
        vec![AssetValues::token_u64(11), AssetValues::token_u64(0),]
    );
    assert_eq!(
        after.iter().map(|(total, _, _)| *total).collect::<Vec<_>>(),
        vec![AssetValues::token_u64(6), AssetValues::token_u64(5)]
    );

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn payment_address_from_public_key() {
    let (public_key, _) = sign::gen_keypair();
    let public_key_vec: Vec<u8> = public_key.as_ref().to_vec();
    let pub_key = PublicKey::from_slice(&public_key_vec).unwrap();
    assert_eq!(pub_key, public_key);

    construct_address(&pub_key);
}

#[tokio::test(flavor = "current_thread")]
async fn receive_testnet_donation_payment_tx_user() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config(10405);
    network_config
        .nodes_mut(NodeType::User)
        .push("user2".to_string());
    network_config.user_auto_donate = 5;
    network_config.compute_seed_utxo = make_compute_seed_utxo(SEED_UTXO, TokenAmount(11));
    network_config.user_wallet_seeds = vec![vec![wallet_seed(VALID_TXS_IN[0], &TokenAmount(11))]];
    let mut network = Network::create_from_config(&network_config).await;
    let user_nodes = &network_config.nodes[&NodeType::User];

    create_first_block_act(&mut network).await;

    //
    // Act/Assert
    //
    let before = node_all_get_wallet_info(&mut network, user_nodes).await;

    node_connect_to(&mut network, "user1", "user2").await;

    user_send_donation_address_to_peer(&mut network, "user2", "user1").await;
    user_handle_event(&mut network, "user1", "Next payment transaction ready").await;

    user_send_next_payment_to_destinations(&mut network, "user1", "compute1").await;
    compute_handle_event(&mut network, "compute1", "Transactions added to tx pool").await;
    user_handle_event(&mut network, "user2", "Payment transaction received").await;

    let after = node_all_get_wallet_info(&mut network, user_nodes).await;

    //
    // Assert
    //
    assert_eq!(
        before
            .iter()
            .map(|(total, _, _)| *total)
            .collect::<Vec<_>>(),
        vec![AssetValues::token_u64(11), AssetValues::token_u64(0)]
    );
    assert_eq!(
        after.iter().map(|(total, _, _)| *total).collect::<Vec<_>>(),
        vec![AssetValues::token_u64(6), AssetValues::token_u64(5)]
    );

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn reject_payment_txs() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config(10410);
    network_config
        .nodes_mut(NodeType::User)
        .push("user2".to_string());
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];

    let valid_txs = valid_transactions(true);
    let invalid_txs = vec![
        // New keys not matching utxo_set
        valid_transactions_with(false, DEFAULT_SEED_AMOUNT, false),
        // Too much output amount for given inputs
        valid_transactions_with(true, DEFAULT_SEED_AMOUNT + TokenAmount(1), false),
        // Too little output amount for given inputs
        valid_transactions_with(true, DEFAULT_SEED_AMOUNT - TokenAmount(1), false),
        // Invalid script
        {
            let (k, v) = valid_txs.iter().next().unwrap();
            let (k, mut v) = (k.clone(), v.clone());
            v.inputs[0].script_signature.stack.push(StackEntry::Num(0));
            Some((k, v)).into_iter().collect()
        },
    ];

    create_first_block_act(&mut network).await;

    //
    // Act/Assert
    //
    for tx in invalid_txs.iter().flat_map(|txs| txs.values()) {
        user_send_transaction_to_compute(&mut network, "user2", "compute1", tx).await;
    }
    for _tx in invalid_txs.iter().flat_map(|txs| txs.values()) {
        compute_handle_error(&mut network, "compute1", "No valid transactions provided").await;
    }
    add_transactions_act(&mut network, &valid_txs).await;

    //
    // Assert
    //
    let actual = compute_all_committed_tx_pool(&mut network, compute_nodes).await;
    assert_eq!(actual[0], valid_txs);
    assert_eq!(equal_first(&actual), node_all(compute_nodes, true));

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn gen_transactions_no_restart() {
    let network_config = complete_network_config(10420);
    gen_transactions_common(network_config, &[]).await
}

#[tokio::test(flavor = "current_thread")]
async fn gen_transactions_restart() {
    let tag = "After block notification request";
    let name = "compute1";
    let modify_cfg = vec![(tag, CfgModif::Drop(name)), (tag, CfgModif::Respawn(name))];

    let network_config = complete_network_config(10425);
    gen_transactions_common(network_config, &modify_cfg).await
}

async fn gen_transactions_common(
    mut network_config: NetworkConfig,
    modify_cfg: &[(&str, CfgModif)],
) {
    test_step_start();

    //
    // Arrange
    //
    network_config.user_test_auto_gen_setup = UserAutoGenTxSetup {
        user_initial_transactions: vec![vec![wallet_seed(VALID_TXS_IN[0], &DEFAULT_SEED_AMOUNT)]],
        user_setup_tx_chunk_size: None,
        user_setup_tx_in_per_tx: Some(2),
        user_setup_tx_max_count: 4,
    };
    let mut network = Network::create_from_config(&network_config).await;

    //
    // Act
    //
    node_send_startup_requests(&mut network, "user1").await;
    compute_handle_event(&mut network, "compute1", "Received block notification").await;
    modify_network(&mut network, "After block notification request", modify_cfg).await;

    let mut tx_expected = Vec::new();
    let mut tx_committed = Vec::new();
    for b_num in 0..3 {
        if b_num == 0 {
            create_first_block_act(&mut network).await;
        } else {
            create_block_act_with(&mut network, Cfg::IgnoreStorage, CfgNum::All, b_num - 1).await;
        }

        compute_flood_block_to_users(&mut network, "compute1").await;
        user_handle_event(&mut network, "user1", "Block mining notified").await;
        let transactions = user_process_mining_notified(&mut network, "user1").await;
        compute_handle_event(&mut network, "compute1", "Transactions added to tx pool").await;
        compute_handle_event(&mut network, "compute1", "Transactions committed").await;
        let committed = compute_committed_tx_pool(&mut network, "compute1").await;

        tx_expected.push(transactions.unwrap());
        tx_committed.push(committed);
    }

    //
    // Assert
    //
    assert_eq!(tx_committed, tx_expected);

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_work_reject() {
    test_step_start();

    //
    // Arrange
    //
    let network_config = complete_network_config(10430);
    let mut network = Network::create_from_config(&network_config).await;

    let compute = "compute1";
    let miner = "miner1";
    let block_num = 1;
    create_first_block_act(&mut network).await;
    create_block_act(&mut network, Cfg::IgnoreStorage, CfgNum::All).await;
    compute_flood_rand_num_to_requesters(&mut network, compute).await;
    miner_handle_event(&mut network, miner, "Received random number successfully").await;
    miner_handle_event(&mut network, miner, "Partition PoW complete").await;
    miner_process_found_partition_pow(&mut network, miner).await;
    compute_handle_event(&mut network, compute, "Partition list is full").await;

    //
    // Act
    //
    {
        // From node not in partition (user1 is not a miner).
        let request = ComputeRequest::SendPoW {
            block_num,
            nonce: Default::default(),
            coinbase: Default::default(),
        };
        compute_inject_next_event(&mut network, "user1", compute, request).await;
        compute_handle_error(&mut network, compute, "Not block currently mined").await;
    }
    {
        // For not currently mined block number.
        let request = ComputeRequest::SendPoW {
            block_num: block_num + 1,
            nonce: Default::default(),
            coinbase: Default::default(),
        };
        compute_inject_next_event(&mut network, miner, compute, request).await;
        compute_handle_error(&mut network, compute, "Not block currently mined").await;
    }
    {
        // For miner in partition and correct block, but wrong nonce/coinbase
        let request = ComputeRequest::SendPoW {
            block_num,
            nonce: Default::default(),
            coinbase: Default::default(),
        };
        compute_inject_next_event(&mut network, miner, compute, request).await;
        compute_handle_error(&mut network, compute, "Coinbase transaction invalid").await;
    }

    //
    // Assert
    //
    let block = compute_current_mining_block(&mut network, compute).await;
    assert!(block.is_some(), "Expect still mining");

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_no_restart_no_raft() {
    handle_message_lost_common(complete_network_config(10440), &[]).await
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_no_restart_raft_1_node() {
    handle_message_lost_common(complete_network_config_with_n_compute_raft(10450, 1), &[]).await
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_restart_block_stored_raft_1_node() {
    let network_config = complete_network_config_with_n_compute_raft(10460, 1);
    handle_message_lost_restart_block_stored_raft_1_node_common(network_config).await
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_restart_block_stored_raft_real_db_1_node() {
    let mut network_config = complete_network_config_with_n_compute_raft(10465, 1);
    network_config.in_memory_db = false;

    remove_all_node_dbs(&network_config);
    handle_message_lost_restart_block_stored_raft_1_node_common(network_config).await
}

async fn handle_message_lost_restart_block_stored_raft_1_node_common(
    network_config: NetworkConfig,
) {
    let modify_cfg = vec![(
        "After store block 0",
        CfgModif::RestartEventsAll(&[
            (NodeType::Compute, "Snapshot applied"),
            (NodeType::Compute, "Received partition request successfully"),
            (NodeType::Storage, "Snapshot applied"),
        ]),
    )];
    handle_message_lost_common(network_config, &modify_cfg).await
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_restart_block_complete_raft_1_node() {
    let modify_cfg = vec![(
        "After create block 1",
        CfgModif::RestartEventsAll(&[
            (NodeType::Compute, "Snapshot applied"),
            (NodeType::Compute, "Received partition request successfully"),
            (NodeType::Compute, "Received block stored"),
            (NodeType::Storage, "Snapshot applied"),
        ]),
    )];

    let network_config = complete_network_config_with_n_compute_raft(10470, 1);
    handle_message_lost_common(network_config, &modify_cfg).await
}

#[tokio::test(flavor = "current_thread")]
async fn handle_message_lost_restart_upgrade_block_complete_raft_1_node() {
    let modify_cfg = vec![(
        "After store block 0",
        CfgModif::RestartUpgradeEventsAll(&[
            (NodeType::Compute, "Snapshot applied"),
            (NodeType::Compute, "Received first full partition request"),
            (NodeType::Storage, "Snapshot applied"),
        ]),
    )];

    let network_config = complete_network_config_with_n_compute_raft(10480, 1);
    handle_message_lost_common(network_config, &modify_cfg).await
}

async fn handle_message_lost_common(
    mut network_config: NetworkConfig,
    modify_cfg: &[(&str, CfgModif)],
) {
    test_step_start();

    //
    // Arrange
    //
    network_config.test_duration_divider = 10;
    let mut network = Network::create_from_config(&network_config).await;
    let miner_nodes = &network_config.nodes[&NodeType::Miner];
    let all_nodes = network.all_active_nodes_name_vec();
    let mining_reward = network.mining_reward();

    let expected_events_b1_create = network.all_active_nodes_events(|t, _| match t {
        NodeType::Compute => vec![
            "Received block stored".to_owned(),
            "Block committed".to_owned(),
        ],
        NodeType::Storage | NodeType::Miner | NodeType::User => vec![],
    });
    let expected_events_b1_stored = network.all_active_nodes_events(|t, _| match t {
        NodeType::Storage => vec![BLOCK_RECEIVED.to_owned(), BLOCK_STORED.to_owned()],
        NodeType::Compute => vec![
            "Partition list is full".to_owned(),
            "Received PoW successfully".to_owned(),
        ],
        NodeType::Miner => vec![
            "Received random number successfully".to_owned(),
            "Partition PoW complete".to_owned(),
            "Received partition list successfully".to_owned(),
            "Pre-block received successfully".to_owned(),
            "Block PoW complete".to_owned(),
        ],
        NodeType::User => vec![],
    });

    create_first_block_act(&mut network).await;
    proof_of_work_act(&mut network, Cfg::All, CfgNum::All).await;
    send_block_to_storage_act(&mut network, CfgNum::All).await;
    let stored0 = storage_get_last_block_stored(&mut network, "storage1").await;

    //
    // Act
    //
    modify_network(&mut network, "After store block 0", modify_cfg).await;
    node_all_handle_different_event(&mut network, &all_nodes, &expected_events_b1_create).await;
    modify_network(&mut network, "After create block 1", modify_cfg).await;
    node_all_handle_different_event(&mut network, &all_nodes, &expected_events_b1_stored).await;

    //
    // Assert
    //
    let actual1 = storage_get_last_stored_info(&mut network, "storage1").await;
    let actual1_values = actual1.1.as_ref();
    let actual1_values = actual1_values.map(|(_, b_num, min_tx)| (*b_num, *min_tx));
    assert_eq!(actual1_values, Some((1, 1)), "Actual: {:?}", actual1);

    let stored0 = stored0.unwrap();
    let actual_w0 = node_all_combined_get_wallet_info(&mut network, miner_nodes).await;
    let expected_w0 =
        node_all_combined_expected_wallet_info(miner_nodes, mining_reward, &[&stored0]);
    assert_eq!((actual_w0.0, actual_w0.1.len(), actual_w0.2), expected_w0);

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_blockchain_item_no_raft() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config(11400);
    network_config.test_duration_divider = 10;

    let mut network = Network::create_from_config(&network_config).await;
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let transactions = vec![network.collect_initial_uxto_txs(), valid_transactions(true)];
    let all_txs = transactions.iter().cloned();
    let all_txs: Vec<Vec<_>> = all_txs.map(|v| v.into_iter().collect()).collect();
    let ((block_keys, _), blocks) = complete_blocks(11, &transactions, 1).await;

    for block in &blocks {
        storage_inject_send_block_to_storage(&mut network, "compute1", "storage1", block).await;
        node_all_handle_event(&mut network, storage_nodes, &BLOCK_RECEIVED_AND_STORED).await;
    }

    let inputs_block: Vec<&str> = vec![
        block_keys[0].as_str(),
        "nLastBlockHashKey",
        "nIndexedBlockHashKey_0000000000000000",
        "nIndexedBlockHashKey_000000000000000a",
        "0000_non_existent",
        "nIndexedBlockHashKey_000000000000000b",
    ];
    let expected_block = vec![
        Some((0, ('b', 0, 4))),
        Some((10, ('b', 10, 1))),
        Some((0, ('b', 0, 4))),
        Some((10, ('b', 10, 1))),
        None,
        None,
    ];

    let inputs_tx: Vec<&str> = vec![
        all_txs[0][0].0.as_str(),
        "nIndexedTxHashKey_0000000000000000_00000000",
        "nIndexedTxHashKey_0000000000000000_00000001",
        "nIndexedTxHashKey_0000000000000001_00000000",
        "nIndexedTxHashKey_0000000000000000_00000100",
    ];
    let expected_tx = {
        let t00 = &all_txs[0][0].1;
        let t01 = &all_txs[0][1].1;
        let t10 = &all_txs[1][0].1;
        vec![
            Some((t00.inputs.len(), t00.outputs.len(), ('t', 0, 0))),
            Some((t00.inputs.len(), t00.outputs.len(), ('t', 0, 0))),
            Some((t01.inputs.len(), t01.outputs.len(), ('t', 0, 1))),
            Some((t10.inputs.len(), t10.outputs.len(), ('t', 1, 0))),
            None,
        ]
    };

    //
    // Act
    //
    let mut actual_block = Vec::new();
    let mut actual_tx = Vec::new();

    node_connect_to(&mut network, "miner1", "storage1").await;
    for input in inputs_block {
        request_blockchain_item_act(&mut network, "miner1", "storage1", input).await;
        actual_block.push(miner_get_blockchain_item_received_b_num(&mut network, "miner1").await);
    }
    for input in inputs_tx {
        request_blockchain_item_act(&mut network, "miner1", "storage1", input).await;
        actual_tx.push(miner_get_blockchain_item_received_tx_lens(&mut network, "miner1").await);
    }

    //
    // Assert
    //
    assert_eq!(actual_block, expected_block);
    assert_eq!(actual_tx, expected_tx);

    test_step_complete(network).await;
}

async fn request_blockchain_item_act(
    network: &mut Network,
    miner_from: &str,
    storage_to: &str,
    block_key: &str,
) {
    miner_request_blockchain_item(network, miner_from, block_key).await;
    storage_handle_event(network, storage_to, "Blockchain item fetched from storage").await;
    storage_send_blockchain_item(network, storage_to).await;
    miner_handle_event(network, miner_from, "Blockchain item received").await;
}

#[tokio::test(flavor = "current_thread")]
async fn catchup_fetch_blockchain_item_raft() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11420, 3);
    network_config.test_duration_divider = 10;

    let mut network = Network::create_from_config(&network_config).await;
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let transactions = vec![network.collect_initial_uxto_txs(), valid_transactions(true)];
    let all_txs = transactions.iter().cloned();
    let _all_txs: Vec<Vec<_>> = all_txs.map(|v| v.into_iter().collect()).collect();
    let ((_block_keys, _), blocks) = complete_blocks(3, &transactions, 2).await;

    let tx_lens = transactions.iter().map(|v| v.len());
    let items_counts = tx_lens.chain(std::iter::repeat(0)).map(|tx| 3 + tx);
    let items_counts: Vec<usize> = items_counts.take(blocks.len()).collect();

    let modify_cfg = vec![
        ("Before store block 1", CfgModif::Drop("storage3")),
        ("Before store block 3", CfgModif::Respawn("storage3")),
        (
            "Before store block 3",
            CfgModif::HandleEvents(&[
                ("storage3", "Snapshot applied"),
                ("storage3", "Snapshot applied: Fetch missing blocks"),
            ]),
        ),
    ];

    //
    // Act
    //
    for (i, block) in blocks.iter().enumerate() {
        info!("Test Step Storage add block {}", i);

        let tag = format!("Before store block {}", i);
        modify_network(&mut network, &tag, &modify_cfg).await;
        let storage_nodes = network.active_nodes(NodeType::Storage).to_owned();

        storage_inject_send_block_to_storage(&mut network, "compute1", "storage1", block).await;
        storage_inject_send_block_to_storage(&mut network, "compute2", "storage2", block).await;

        storage_all_handle_event(&mut network, &storage_nodes[0..2], BLOCK_RECEIVED).await;
        node_all_handle_event(&mut network, &storage_nodes, &[BLOCK_STORED]).await;
    }

    let tag = "Before store block 3";
    modify_network(&mut network, tag, &modify_cfg).await;

    // Process event and treat it as messaged lost => switch to storage2
    storage_handle_event(&mut network, "storage3", "Catch up stored blocks").await;

    for (b_num, items_count) in items_counts.iter().copied().enumerate().skip(1) {
        for i in 0..items_count {
            info!(
                "Test Step Storage catchup b_num={} (count={}) i={}",
                b_num, items_count, i,
            );

            let network = &mut network;
            let receive_evt = if i < items_count - 1 {
                "Blockchain item received"
            } else if b_num < items_counts.len() - 1 {
                "Blockchain item received: Block stored"
            } else {
                "Blockchain item received: Block stored(Done)"
            };

            storage_handle_event(network, "storage3", "Catch up stored blocks").await;
            storage_catchup_fetch_blockchain_item(network, "storage3").await;
            storage_handle_event(network, "storage2", "Blockchain item fetched from storage").await;
            storage_send_blockchain_item(network, "storage2").await;
            storage_handle_event(network, "storage3", receive_evt).await;
        }
    }

    //
    // Assert
    //
    let all_items_count = items_counts[..].iter().sum::<usize>();
    let actual_db_count =
        storage_all_get_stored_key_values_count(&mut network, storage_nodes).await;
    assert_eq!(actual_db_count, node_all(storage_nodes, all_items_count));

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn relaunch_with_new_raft_nodes() {
    test_step_start();

    //
    // Arrange
    //
    let extra_params = {
        let mut network_config = complete_network_config_with_n_compute_raft(11430, 1);
        network_config.nodes.insert(NodeType::User, vec![]);
        let mut network = Network::create_from_config(&network_config).await;

        // Create intiial snapshoot in compute and storage
        create_first_block_act(&mut network).await;
        proof_of_work_act(&mut network, Cfg::All, CfgNum::All).await;
        send_block_to_storage_act(&mut network, CfgNum::All).await;
        network.close_raft_loops_and_drop().await
    };

    let mut network_config = complete_network_config_with_n_compute_raft(11430, 3);
    network_config.compute_seed_utxo = Default::default();
    network_config.nodes.insert(NodeType::User, vec![]);

    let mut network = Network::create_stopped_from_config(&network_config);
    network.set_all_extra_params(extra_params);
    network.upgrade_closed_nodes().await;

    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    let storage_nodes = &network_config.nodes[&NodeType::Storage];
    let raft_nodes: Vec<String> = compute_nodes.iter().chain(storage_nodes).cloned().collect();

    let restart_raft_reasons: BTreeMap<String, Vec<String>> = {
        let snap_applied = vec!["Snapshot applied".to_owned()];
        let snap_applied_fetch = vec!["Snapshot applied: Fetch missing blocks".to_owned()];
        vec![
            ("storage1".to_owned(), snap_applied.clone()),
            ("storage2".to_owned(), snap_applied_fetch.clone()),
            ("storage3".to_owned(), snap_applied_fetch),
            ("compute1".to_owned(), snap_applied.clone()),
            ("compute2".to_owned(), snap_applied.clone()),
            ("compute3".to_owned(), snap_applied),
        ]
        .into_iter()
        .collect()
    };

    //
    // Act
    //
    let (mut actual_stored, mut expected_stored) = (Vec::new(), Vec::new());
    let (mut actual_compute, mut expected_compute) = (Vec::new(), Vec::new());

    network.pre_launch_nodes_named(&raft_nodes).await;
    for (pre_launch, expected_block_num) in vec![(true, 0u64), (false, 1u64)].into_iter() {
        if !pre_launch {
            for node_name in compute_nodes {
                node_send_coordinated_shutdown(&mut network, node_name, expected_block_num).await;
            }
        }

        let handles = network
            .spawn_main_node_loops(TIMEOUT_TEST_WAIT_DURATION)
            .await;
        node_join_all_checked(handles, &"").await.unwrap();

        if pre_launch {
            network.close_loops_and_drop_named(&raft_nodes).await;
            network.re_spawn_dead_nodes().await;
            node_all_handle_different_event(&mut network, &raft_nodes, &restart_raft_reasons).await;
        }

        actual_stored
            .push(storage_all_get_last_block_stored_num(&mut network, storage_nodes).await);
        actual_compute
            .push(compute_all_committed_current_block_num(&mut network, compute_nodes).await);
        expected_stored.push(node_all(storage_nodes, Some(expected_block_num)));
        expected_compute.push(node_all(compute_nodes, Some(expected_block_num)));
    }

    //
    // Assert
    //
    assert_eq!(actual_stored, expected_stored);
    assert_eq!(actual_compute, expected_compute);

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_utxo_set_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11440, 1);
    network_config.compute_seed_utxo = make_compute_seed_utxo_with_info({
        let a = DEFAULT_SEED_AMOUNT;
        let pk = SOME_PUB_KEYS;
        &[
            ("000000", vec![(pk[0], a)]),
            ("000001", vec![(pk[1], a), (pk[0], a)]),
            ("000002", vec![(pk[2], a)]),
        ]
    });
    let mut network = Network::create_from_config(&network_config).await;
    create_first_block_act(&mut network).await;

    let committed_utxo_set = compute_committed_utxo_set(&mut network, "compute1").await;

    let addresses = {
        let a = SOME_PUB_KEY_ADDRS;
        let ne = vec!["DoesNotExist".to_string()];
        vec![
            //Request full UTXO set
            UtxoFetchType::All,
            //Request single address with multiple OutPoints
            UtxoFetchType::AnyOf(vec![a[0].to_string()]),
            //Request single address with one OutPoint
            UtxoFetchType::AnyOf(vec![a[1].to_string()]),
            //Request single address with one OutPoint
            UtxoFetchType::AnyOf(vec![a[2].to_string()]),
            //Request combination of different addresses with different OutPoints
            UtxoFetchType::AnyOf(vec![a[1].to_string(), a[2].to_string()]),
            //Request combination of different addresses containing invalid address
            UtxoFetchType::AnyOf(vec![
                "DoesNotExist".to_string(),
                a[1].to_string(),
                a[2].to_string(),
            ]),
            //Single invalid address
            UtxoFetchType::AnyOf(ne),
        ]
    };
    let expected = vec![
        //No address - Should return full UTXO set
        committed_utxo_set.keys().cloned().collect(),
        //Single address with multiple OutPoints
        vec![
            OutPoint::new("000000".to_string(), 0),
            OutPoint::new("000001".to_string(), 1),
        ],
        //Single address with one OutPoint
        vec![OutPoint::new("000001".to_string(), 0)],
        //Single address with one OutPoint
        vec![OutPoint::new("000002".to_string(), 0)],
        //Combination of different addresses with different OutPoints
        vec![
            OutPoint::new("000001".to_string(), 0),
            OutPoint::new("000002".to_string(), 0),
        ],
        //Combination of different addresses containing an invalid address - Should filter out invalid address
        vec![
            OutPoint::new("000001".to_string(), 0),
            OutPoint::new("000002".to_string(), 0),
        ],
        //Single invalid address - Should return an empty set
        Vec::new(),
    ];

    //
    // Act
    //
    let mut actual = Vec::new();
    for address_list in addresses {
        request_utxo_set_act(&mut network, "user1", "compute1", address_list).await;
        actual.push(user_get_received_utxo_set_keys(&mut network, "user1").await);
    }

    //
    // Assert
    //
    assert_eq!(actual, expected);
    test_step_complete(network).await;
}

async fn request_utxo_set_act(
    network: &mut Network,
    user: &str,
    compute: &str,
    address_list: UtxoFetchType,
) {
    user_send_request_utxo_set(network, user, address_list).await;
    compute_handle_event(network, compute, "Received UTXO fetch request").await;
    compute_send_utxo_set(network, compute).await;
    user_handle_event(network, user, "Received UTXO set").await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_utxo_set_and_update_running_total_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11450, 1);
    network_config.compute_seed_utxo = make_compute_seed_utxo_with_info({
        let a = DEFAULT_SEED_AMOUNT;
        let pk = SOME_PUB_KEYS;
        &[
            ("000000", vec![(pk[0], a)]),
            ("000001", vec![(pk[1], a), (pk[0], a)]),
            ("000002", vec![(pk[2], a), (pk[1], a)]),
        ]
    });
    network_config.user_wallet_seeds = {
        let pk = SOME_PUB_KEYS;
        let sk = SOME_SEC_KEYS;
        vec![vec![
            WalletTxSpec {
                out_point: "0-000000".to_string(),
                secret_key: sk[0].to_string(),
                public_key: pk[0].to_string(),
                amount: 3,
                address_version: None,
            },
            WalletTxSpec {
                out_point: "0-000001".to_string(),
                secret_key: sk[1].to_string(),
                public_key: pk[1].to_string(),
                amount: 3,
                address_version: None,
            },
            WalletTxSpec {
                out_point: "0-000002".to_string(),
                secret_key: sk[2].to_string(),
                public_key: pk[2].to_string(),
                amount: 3,
                address_version: None,
            },
        ]]
    };

    let user_nodes = &network_config.nodes[&NodeType::User];
    let mut network = Network::create_from_config(&network_config).await;
    let address_list: UtxoFetchType =
        UtxoFetchType::AnyOf(SOME_PUB_KEY_ADDRS.iter().map(|v| v.to_string()).collect());

    //
    // Act
    //
    create_first_block_act(&mut network).await;
    proof_of_work_act(&mut network, Cfg::All, CfgNum::All).await;
    send_block_to_storage_act(&mut network, CfgNum::All).await;

    let before = node_all_get_wallet_info(&mut network, user_nodes).await;
    request_utxo_set_and_update_running_total_act(&mut network, "user1", "compute1", address_list)
        .await;
    let after = node_all_get_wallet_info(&mut network, user_nodes).await;

    //
    // Assert
    //
    assert_eq!(
        before
            .iter()
            .map(|(total, _, _)| *total)
            .collect::<Vec<_>>(),
        vec![AssetValues::token_u64(9)]
    );

    assert_eq!(
        after.iter().map(|(total, _, _)| *total).collect::<Vec<_>>(),
        vec![AssetValues::token_u64(15)]
    );

    test_step_complete(network).await;
}

async fn request_utxo_set_and_update_running_total_act(
    network: &mut Network,
    user: &str,
    compute: &str,
    address_list: UtxoFetchType,
) {
    user_trigger_update_wallet_from_utxo_set(network, user, address_list).await;
    user_handle_event(network, user, "Request UTXO set").await;
    compute_handle_event(network, compute, "Received UTXO fetch request").await;
    compute_send_utxo_set(network, compute).await;
    user_handle_event(network, user, "Received UTXO set").await;
    user_update_running_total(network, user).await;
}

#[tokio::test(flavor = "current_thread")]
pub async fn create_receipt_asset_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11460, 1);
    network_config.compute_seed_utxo = BTreeMap::new();
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    create_first_block_act(&mut network).await;

    //
    // Act
    //
    let actual_running_total_before = node_get_wallet_info(&mut network, "user1").await.0;
    create_receipt_asset_act(&mut network, "user1", "compute1", 10).await;
    compute_handle_event(&mut network, "compute1", "Transactions committed").await;
    create_block_act(&mut network, Cfg::IgnoreStorage, CfgNum::All).await;

    let committed_utxo_set = compute_all_committed_utxo_set(&mut network, compute_nodes).await;
    let actual_utxo_receipt: Vec<Vec<_>> = committed_utxo_set
        .into_iter()
        .map(|v| v.into_iter().map(|(_, v)| v.value).collect())
        .collect();

    let actual_running_total_after = node_get_wallet_info(&mut network, "user1").await.0;

    //
    // Assert
    //
    assert_eq!(
        actual_utxo_receipt,
        node_all(compute_nodes, vec![Asset::Receipt(10)])
    );
    assert_eq!(actual_running_total_before, AssetValues::receipt(0));
    assert_eq!(actual_running_total_after, AssetValues::receipt(10));

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
pub async fn create_receipt_asset_on_compute_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11465, 1);
    network_config.compute_seed_utxo = BTreeMap::new();
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];
    network_config.compute_seed_utxo =
        make_compute_seed_utxo_with_info(&[("000000", vec![(COMMON_PUB_KEY, TokenAmount(0))])]);
    create_first_block_act(&mut network).await;

    //
    // Act
    //
    let asset_hash = construct_tx_in_signable_asset_hash(&Asset::Receipt(1));
    let secret_key = decode_secret_key(COMMON_SEC_KEY).unwrap();
    let signature = hex::encode(sign::sign_detached(asset_hash.as_bytes(), &secret_key).as_ref());

    compute_create_receipt_asset_tx(
        &mut network,
        "compute1",
        1,
        COMMON_PUB_ADDR.to_string(),
        COMMON_PUB_KEY.to_string(),
        signature,
    )
    .await;

    compute_handle_event(&mut network, "compute1", "Transactions committed").await;
    create_block_act(&mut network, Cfg::IgnoreStorage, CfgNum::All).await;

    let committed_utxo_set = compute_all_committed_utxo_set(&mut network, compute_nodes).await;
    let actual_utxo_receipt: Vec<Vec<_>> = committed_utxo_set
        .into_iter()
        .map(|v| v.into_iter().map(|(_, v)| v.value).collect())
        .collect();

    //
    // Assert
    //
    assert_eq!(
        actual_utxo_receipt,
        node_all(compute_nodes, vec![Asset::Receipt(1)])
    );

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
pub async fn make_receipt_based_payment_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11470, 1);
    network_config
        .nodes_mut(NodeType::User)
        .push("user2".to_string());
    network_config.compute_seed_utxo = make_compute_seed_utxo(SEED_UTXO, TokenAmount(11));
    network_config.user_wallet_seeds = vec![vec![wallet_seed(VALID_TXS_IN[0], &TokenAmount(11))]];
    let mut network = Network::create_from_config(&network_config).await;
    let compute_nodes = &network_config.nodes[&NodeType::Compute];

    create_first_block_act(&mut network).await;
    node_connect_to(&mut network, "user1", "user2").await;
    create_receipt_asset_act(&mut network, "user2", "compute1", 5).await;
    compute_handle_event(&mut network, "compute1", "Transactions committed").await;
    create_block_act(&mut network, Cfg::IgnoreStorage, CfgNum::All).await;

    //
    // Act
    //
    let wallet_assets_before_actual =
        user_get_wallet_asset_totals_for_tx(&mut network, "user1", "user2").await;

    make_receipt_based_payment_act(
        &mut network,
        "user1",
        "user2",
        "compute1",
        Asset::Token(DEFAULT_SEED_AMOUNT),
    )
    .await;

    let wallet_assets_after_actual =
        user_get_wallet_asset_totals_for_tx(&mut network, "user1", "user2").await;

    let committed_tx_druid_pool: Vec<Transaction> =
        compute_all_committed_tx_druid_pool(&mut network, compute_nodes)
            .await
            .into_iter()
            .flatten()
            .flatten()
            .map(|(_, tx)| tx)
            .collect();

    let actual_druid_string: Vec<String> = committed_tx_druid_pool
        .iter()
        .map(|v| v.druid_info.clone().unwrap().druid)
        .collect();

    let actual_participants: Vec<usize> = committed_tx_druid_pool
        .iter()
        .map(|v| v.druid_info.clone().unwrap().participants)
        .collect();

    let actual_assets: Vec<Vec<Asset>> = committed_tx_druid_pool
        .into_iter()
        .map(|v| {
            v.druid_info
                .unwrap()
                .expectations
                .iter()
                .map(|ex| ex.asset.clone())
                .collect()
        })
        .collect();

    //
    // Assert
    //
    //Assert wallet asset running total before and after
    assert_eq!(
        wallet_assets_before_actual,
        (AssetValues::token_u64(11), AssetValues::receipt(5))
    );
    assert_eq!(
        wallet_assets_after_actual,
        (
            AssetValues::new(TokenAmount(8), 1),
            AssetValues::new(TokenAmount(3), 4)
        )
    );

    //Assert committed DDE transactions have identical DRUID value
    assert_eq!(actual_druid_string[0], actual_druid_string[1]);

    //Assert committed DDE transactions contain valid DDE participation count
    assert!(actual_participants.iter().all(|v| *v == 2));

    //Assert committed DDE transactions contain valid DDE asset values
    let expected_assets = vec![vec![Asset::token_u64(3)], vec![Asset::Receipt(1)]];
    assert!(actual_assets.iter().all(|v| expected_assets.contains(v)));

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
pub async fn make_multiple_receipt_based_payments_raft_1_node() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config_with_n_compute_raft(11480, 1);
    network_config
        .nodes_mut(NodeType::User)
        .push("user2".to_string());
    network_config.compute_seed_utxo = make_compute_seed_utxo_with_info({
        let a = TokenAmount(11);
        let pk = SOME_PUB_KEYS;
        &[("000000", vec![(pk[0], a)]), ("000001", vec![(pk[1], a)])]
    });
    network_config.user_wallet_seeds = {
        let pk = SOME_PUB_KEYS;
        let sk = SOME_SEC_KEYS;
        vec![
            vec![WalletTxSpec {
                out_point: "0-000000".to_string(),
                secret_key: sk[0].to_string(),
                public_key: pk[0].to_string(),
                amount: 11,
                address_version: None,
            }],
            vec![WalletTxSpec {
                out_point: "0-000001".to_string(),
                secret_key: sk[1].to_string(),
                public_key: pk[1].to_string(),
                amount: 11,
                address_version: None,
            }],
        ]
    };

    let mut network = Network::create_from_config(&network_config).await;
    create_first_block_act(&mut network).await;
    create_receipt_asset_act(&mut network, "user1", "compute1", 5).await;
    create_receipt_asset_act(&mut network, "user2", "compute1", 10).await;
    compute_handle_event(&mut network, "compute1", "Transactions committed").await;
    node_connect_to(&mut network, "user1", "user2").await;

    //
    // Act
    //
    let amounts_to_pay = vec![
        (TokenAmount(3), "user1", "user2", 0),
        (TokenAmount(4), "user1", "user2", 1),
        (TokenAmount(2), "user2", "user1", 2),
        (TokenAmount(6), "user2", "user1", 3),
    ];

    let mut all_gathered_wallet_asset_info: BTreeMap<
        (&'static str, &'static str),
        Vec<(AssetValues, AssetValues)>,
    > = BTreeMap::new();

    for (payment_amount, from, to, b_num) in amounts_to_pay {
        create_block_act_with(&mut network, Cfg::IgnoreStorage, CfgNum::All, b_num).await;
        let initial_info = vec![user_get_wallet_asset_totals_for_tx(&mut network, from, to).await];
        let infos = all_gathered_wallet_asset_info
            .entry((from, to))
            .or_insert(initial_info);

        make_receipt_based_payment_act(
            &mut network,
            from,
            to,
            "compute1",
            Asset::Token(payment_amount),
        )
        .await;

        infos.push(user_get_wallet_asset_totals_for_tx(&mut network, from, to).await);
    }

    let all_wallet_assets_actual: Vec<_> = all_gathered_wallet_asset_info.into_iter().collect();
    let all_wallet_assets_expected = vec![
        (
            ("user1", "user2"),
            vec![
                (
                    AssetValues::new(TokenAmount(11), 5),
                    AssetValues::new(TokenAmount(11), 10),
                ),
                (
                    AssetValues::new(TokenAmount(8), 6),
                    AssetValues::new(TokenAmount(14), 9),
                ),
                (
                    AssetValues::new(TokenAmount(4), 7),
                    AssetValues::new(TokenAmount(18), 8),
                ),
            ],
        ),
        (
            ("user2", "user1"),
            vec![
                (
                    AssetValues::new(TokenAmount(18), 8),
                    AssetValues::new(TokenAmount(4), 7),
                ),
                (
                    AssetValues::new(TokenAmount(16), 9),
                    AssetValues::new(TokenAmount(6), 6),
                ),
                (
                    AssetValues::new(TokenAmount(10), 10),
                    AssetValues::new(TokenAmount(12), 5),
                ),
            ],
        ),
    ];

    //
    // Assert
    //

    assert_eq!(all_wallet_assets_actual, all_wallet_assets_expected);

    test_step_complete(network).await;
}

async fn create_receipt_asset_act(
    network: &mut Network,
    user: &str,
    compute: &str,
    receipt_amount: u64,
) {
    user_send_receipt_asset(network, user, compute, receipt_amount).await;
    compute_handle_event(network, compute, "Transactions added to tx pool").await;
}

async fn compute_create_receipt_asset_tx(
    network: &mut Network,
    compute: &str,
    receipt_amount: u64,
    script_public_key: String,
    public_key: String,
    signature: String,
) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.create_receipt_asset_tx(receipt_amount, script_public_key, public_key, signature)
        .await;
}

async fn make_receipt_based_payment_act(
    network: &mut Network,
    from: &str,
    to: &str,
    compute: &str,
    send_asset: Asset,
) {
    user_send_receipt_based_payment_request(network, from, to, send_asset).await;
    user_handle_event(network, to, "Received receipt-based payment request").await;
    user_send_receipt_based_payment_response(network, to).await;
    user_handle_event(network, from, "Received receipt-based payment response").await;
    user_send_receipt_based_payment_to_desinations(network, from, compute).await;
    compute_handle_event(
        network,
        compute,
        "Transaction added to DRUID pool. Awaiting other parties",
    )
    .await;
    user_handle_event(network, to, "Payment transaction received").await;
    user_send_receipt_based_payment_to_desinations(network, to, compute).await;
    compute_handle_event(
        network,
        compute,
        "Transaction added to corresponding DRUID droplets",
    )
    .await;
    user_handle_event(network, from, "Payment transaction received").await;
    compute_handle_event(network, compute, "Transactions committed").await;
}

#[tokio::test(flavor = "current_thread")]
async fn restart_user_with_seed() {
    test_step_start();

    //
    // Arrange
    //
    let mut network_config = complete_network_config(11490);
    let modify_cfg = vec![
        ("stop", CfgModif::Drop("user1")),
        ("start", CfgModif::Respawn("user1")),
    ];
    let seed_0 = vec![vec![wallet_seed(VALID_TXS_IN[0], &TokenAmount(11))]];
    let seed_1 = vec![vec![wallet_seed(VALID_TXS_IN[1], &TokenAmount(12))]];
    network_config.user_wallet_seeds = seed_0;
    let mut network = Network::create_from_config(&network_config).await;

    //
    // Act
    //
    let db_0 = node_get_wallet_info(&mut network, "user1").await;
    modify_network(&mut network, "stop", &modify_cfg).await;
    network.mut_config().user_wallet_seeds = seed_1;
    modify_network(&mut network, "start", &modify_cfg).await;
    let db_1 = node_get_wallet_info(&mut network, "user1").await;

    //
    // Assert
    //
    assert_eq!(db_0, db_1);
}

//
// Node helpers
//

fn node_all<T: Clone>(nodes: &[String], value: T) -> Vec<T> {
    let len = nodes.len();
    (0..len).map(|_| value.clone()).collect()
}

fn node_all_or<T: Clone>(
    nodes: &[String],
    cfg_num: CfgNum,
    value: T,
    unselected_value: T,
) -> Vec<T> {
    let select_len = node_select_len(nodes, cfg_num);
    let len = nodes.len();

    let selected = (0..select_len).map(|_| value.clone());
    let unselected = (select_len..len).map(|_| unselected_value.clone());
    selected.chain(unselected).collect()
}

fn node_select(nodes: &[String], cfg_num: CfgNum) -> Vec<String> {
    let len = node_select_len(nodes, cfg_num);
    nodes.iter().cloned().take(len).collect()
}

fn node_combined_select(
    nodes1: &[String],
    nodes2: &[String],
    ignore: &BTreeSet<String>,
    cfg_num: CfgNum,
) -> (Vec<String>, Vec<String>) {
    let len = node_select_len(nodes1, cfg_num);
    nodes1
        .iter()
        .cloned()
        .zip(nodes2.iter().cloned())
        .filter(|(n1, _)| !ignore.contains(n1))
        .filter(|(_, n2)| !ignore.contains(n2))
        .take(len)
        .unzip()
}

fn node_select_len(nodes: &[String], cfg_num: CfgNum) -> usize {
    let len = nodes.len();
    if cfg_num == CfgNum::Majority {
        len / 2 + 1
    } else {
        len
    }
}

async fn node_connect_to(network: &mut Network, from: &str, to: &str) {
    let to_addr = network.get_address(to).await.unwrap();
    if let Some(u) = network.user(from) {
        u.lock().await.connect_to(to_addr).await.unwrap();
    } else if let Some(m) = network.miner(from) {
        m.lock().await.connect_to(to_addr).await.unwrap();
    } else {
        panic!("node not found");
    }
}

async fn node_all_handle_event(network: &mut Network, node_group: &[String], reason_str: &[&str]) {
    let reason_str: Vec<_> = reason_str.iter().map(|s| s.to_string()).collect();
    let all_raisons = node_group
        .iter()
        .map(|n| (n.clone(), reason_str.clone()))
        .collect();
    node_all_handle_different_event(network, node_group, &all_raisons).await
}

async fn node_all_handle_different_event<'a>(
    network: &mut Network,
    node_group: &[String],
    all_raisons: &BTreeMap<String, Vec<String>>,
) {
    let mut join_handles = BTreeMap::new();
    let barrier = Arc::new(Barrier::new(node_group.len()));
    for node_name in node_group {
        let barrier = barrier.clone();
        let reason_str = all_raisons.get(node_name).cloned().unwrap_or_default();
        let node_name = node_name.clone();
        let compute = network.compute(&node_name).cloned();
        let storage = network.storage(&node_name).cloned();
        let miner = network.miner(&node_name).cloned();
        let user = network.user(&node_name).cloned();

        let peer_span = error_span!("peer", ?node_name);
        join_handles.insert(
            node_name.clone(),
            tokio::spawn(
                async move {
                    if let Some(compute) = compute {
                        compute_one_handle_event(&compute, &barrier, &reason_str).await;
                    } else if let Some(storage) = storage {
                        storage_one_handle_event(&storage, &barrier, &reason_str).await;
                    } else if let Some(miner) = miner {
                        miner_one_handle_event(&miner, &barrier, &reason_str).await;
                    } else if let Some(user) = user {
                        user_one_handle_event(&user, &barrier, &reason_str).await;
                    } else {
                        panic!("Node not found");
                    }
                }
                .instrument(peer_span),
            ),
        );
    }

    node_join_all_checked(join_handles, all_raisons)
        .await
        .unwrap();
}

async fn node_get_wallet_info(
    network: &mut Network,
    node: &str,
) -> (
    AssetValues,
    Vec<String>,
    BTreeMap<OutPoint, (String, Asset)>,
) {
    let (miner, user) = if let Some(miner) = network.miner(node) {
        (Some(miner.lock().await), None)
    } else if let Some(user) = network.user(node) {
        (None, Some(user.lock().await))
    } else {
        (None, None)
    };

    let wallet = match (&miner, &user) {
        (Some(m), _) => m.get_wallet_db(),
        (_, Some(u)) => u.get_wallet_db(),
        _ => panic!("node not found"),
    };

    let addresses = wallet.get_known_addresses();

    let fund = wallet.get_fund_store();
    let total = fund.running_total();

    let mut txs_to_address_and_ammount = BTreeMap::new();
    for (tx, amount) in fund.into_transactions().into_iter() {
        let addr = wallet.get_transaction_address(&tx);
        txs_to_address_and_ammount.insert(tx, (addr, amount));
    }
    (total, addresses, txs_to_address_and_ammount)
}

async fn node_all_get_wallet_info(
    network: &mut Network,
    miner_group: &[String],
) -> Vec<(
    AssetValues,
    Vec<String>,
    BTreeMap<OutPoint, (String, Asset)>,
)> {
    let mut result = Vec::new();
    for name in miner_group {
        let r = node_get_wallet_info(network, name).await;
        result.push(r);
    }
    result
}

async fn user_get_wallet_asset_totals_for_tx(
    network: &mut Network,
    from: &str,
    to: &str,
) -> (AssetValues, AssetValues) {
    let from_info = node_get_wallet_info(network, from).await.0;
    let to_info = node_get_wallet_info(network, to).await.0;
    (from_info, to_info)
}

async fn node_all_combined_get_wallet_info(
    network: &mut Network,
    miner_group: &[String],
) -> (
    AssetValues,
    Vec<String>,
    BTreeMap<OutPoint, (String, Asset)>,
) {
    let mut total = AssetValues::default();
    let mut addresses = Vec::new();
    let mut txs_to_address_and_ammount = BTreeMap::new();
    for name in miner_group {
        let (t, mut a, mut txs) = node_get_wallet_info(network, name).await;
        total += t;
        addresses.append(&mut a);
        txs_to_address_and_ammount.append(&mut txs);
    }
    (total, addresses, txs_to_address_and_ammount)
}

fn node_all_combined_expected_wallet_info(
    miner_group: &[String],
    mining_reward: TokenAmount,
    stored: &[&BlockStoredInfo],
) -> (AssetValues, usize, BTreeMap<OutPoint, (String, Asset)>) {
    let mining_txs: Vec<_> = {
        let txs = stored.iter().flat_map(|b| b.mining_transactions.iter());
        txs.collect()
    };

    let total = mining_reward * mining_txs.len() as u64;
    let addresses = miner_group.len() + mining_txs.len();
    let txs_to_address_and_ammount = {
        let mining_tx_out = get_tx_out_with_out_point_cloned(mining_txs.iter().copied());
        mining_tx_out
            .map(|(k, tx_out)| (k, (tx_out.script_public_key, tx_out.value)))
            .map(|(k, (addr, amount))| (k, (addr.unwrap(), amount)))
            .collect()
    };

    (
        AssetValues::new(total, 0),
        addresses,
        txs_to_address_and_ammount,
    )
}

async fn node_send_coordinated_shutdown(network: &mut Network, node: &str, at_block: u64) {
    let mut event_tx = network.get_local_event_tx(node).await.unwrap();
    let event = LocalEvent::CoordinatedShutdown(at_block);
    event_tx.send(event, "test shutdown").await.unwrap();
}

async fn node_send_startup_requests(network: &mut Network, node: &str) {
    network
        .send_startup_requests_named(&[node.to_string()])
        .await;
}

//
// ComputeNode helpers
//

async fn compute_handle_event(network: &mut Network, compute: &str, reason_str: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    compute_handle_event_for_node(&mut c, true, reason_str, &mut test_timeout()).await;
}

async fn compute_all_handle_event(
    network: &mut Network,
    compute_group: &[String],
    reason_str: &str,
) {
    for compute in compute_group {
        compute_handle_event(network, compute, reason_str).await;
    }
}

async fn compute_handle_error(network: &mut Network, compute: &str, reason_str: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    compute_handle_event_for_node(&mut c, false, reason_str, &mut test_timeout()).await;
}

async fn compute_all_handle_error(
    network: &mut Network,
    compute_group: &[String],
    reason_str: &str,
) {
    for compute in compute_group {
        compute_handle_error(network, compute, reason_str).await;
    }
}

async fn compute_handle_event_for_node<E: Future<Output = &'static str> + Unpin>(
    c: &mut ComputeNode,
    success_val: bool,
    reason_val: &str,
    exit: &mut E,
) {
    match c.handle_next_event(exit).await {
        Some(Ok(Response { success, reason }))
            if success == success_val && reason == reason_val => {}
        other => {
            error!("Unexpected result: {:?} (expected:{})", other, reason_val);
            panic!("Unexpected result: {:?} (expected:{})", other, reason_val);
        }
    }
}

async fn compute_one_handle_event(
    compute: &Arc<Mutex<ComputeNode>>,
    barrier: &Barrier,
    reason_str: &[String],
) {
    debug!("Start wait for event");

    let mut compute = compute.lock().await;
    for reason in reason_str {
        compute_handle_event_for_node(&mut compute, true, reason, &mut test_timeout()).await;
    }

    debug!("Start wait for completion of other in raft group");

    let mut exit = test_timeout_barrier(barrier);
    compute_handle_event_for_node(&mut compute, true, "Barrier complete", &mut exit).await;

    debug!("Stop wait for event");
}

async fn compute_set_mining_block(
    network: &mut Network,
    compute: &str,
    block_info: &CompleteBlock,
) {
    let mut c = network.compute(compute).unwrap().lock().await;
    let common = block_info.common.clone();
    c.set_committed_mining_block(common.block, common.block_txs);
}

async fn compute_all_set_mining_block(
    network: &mut Network,
    compute_group: &[String],
    block_info: &CompleteBlock,
) {
    for compute in compute_group {
        compute_set_mining_block(network, compute, block_info).await;
    }
}

async fn compute_mined_block_num(network: &mut Network, compute: &str) -> Option<u64> {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_current_mined_block()
        .as_ref()
        .map(|b| b.block.header.b_num)
}

async fn compute_all_mined_block_num(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<Option<u64>> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_mined_block_num(network, name).await;
        result.push(r);
    }
    result
}

async fn compute_all_current_block_transactions(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<Option<Vec<String>>> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_current_block_transactions(network, name).await;
        result.push(r);
    }
    result
}

async fn compute_current_block_transactions(
    network: &mut Network,
    compute: &str,
) -> Option<Vec<String>> {
    compute_current_mining_block(network, compute)
        .await
        .map(|b| b.transactions)
}

async fn compute_current_mining_block(network: &mut Network, compute: &str) -> Option<Block> {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_mining_block().clone()
}

async fn compute_committed_current_block_num(network: &mut Network, compute: &str) -> Option<u64> {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_committed_current_block_num()
}

async fn compute_all_committed_current_block_num(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<Option<u64>> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_committed_current_block_num(network, name).await;
        result.push(r);
    }
    result
}

async fn compute_all_committed_utxo_set(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<UtxoSet> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_committed_utxo_set(network, name).await;
        result.push(r);
    }
    result
}

async fn compute_committed_utxo_set(network: &mut Network, compute: &str) -> UtxoSet {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_committed_utxo_set().clone()
}

async fn compute_all_committed_tx_pool(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<BTreeMap<String, Transaction>> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_committed_tx_pool(network, name).await;
        result.push(r);
    }
    result
}

pub async fn compute_committed_tx_pool(
    network: &mut Network,
    compute: &str,
) -> BTreeMap<String, Transaction> {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_committed_tx_pool().clone()
}

async fn compute_all_committed_tx_druid_pool(
    network: &mut Network,
    compute_group: &[String],
) -> Vec<Vec<BTreeMap<String, Transaction>>> {
    let mut result = Vec::new();
    for name in compute_group {
        let r = compute_committed_tx_druid_pool(network, name).await;
        result.push(r);
    }
    result
}

async fn compute_committed_tx_druid_pool(
    network: &mut Network,
    compute: &str,
) -> Vec<BTreeMap<String, Transaction>> {
    let c = network.compute(compute).unwrap().lock().await;
    c.get_committed_tx_druid_pool().clone()
}

async fn compute_all_inject_next_event(
    network: &mut Network,
    from_group: &[String],
    to_compute_group: &[String],
    request: ComputeRequest,
) {
    for (from, to) in from_group.iter().zip(to_compute_group.iter()) {
        compute_inject_next_event(network, from, to, request.clone()).await;
    }
}

async fn compute_inject_next_event(
    network: &mut Network,
    from: &str,
    to_compute: &str,
    request: ComputeRequest,
) {
    let from_addr = network.get_address(from).await.unwrap();
    let c = network.compute(to_compute).unwrap().lock().await;

    c.inject_next_event(from_addr, request).unwrap();
}

async fn compute_flood_rand_num_to_requesters(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.flood_rand_num_to_requesters().await.unwrap();
}

async fn compute_flood_block_to_partition(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.flood_block_to_partition().await.unwrap();
}

async fn compute_flood_transactions_to_partition(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.flood_transactions_to_partition().await.unwrap();
}

async fn compute_flood_block_to_users(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.flood_block_to_users().await.unwrap();
}

async fn compute_send_block_to_storage(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    if let Err(e) = c.send_block_to_storage().await {
        warn!("Block not sent to storage {:?}", e);
    }
}

async fn compute_all_send_block_to_storage(network: &mut Network, compute_group: &[String]) {
    for compute in compute_group {
        compute_send_block_to_storage(network, compute).await;
    }
}

async fn compute_mining_block_mined(
    network: &mut Network,
    compute: &str,
    block_info: &CompleteBlock,
) {
    let id = network.get_position(compute).unwrap() as u64 + 1;
    let mut c = network.compute(compute).unwrap().lock().await;
    let mined = block_info.per_node.get(&id).unwrap();

    c.mining_block_mined(mined.nonce.clone(), mined.mining_tx.clone());
}

async fn compute_all_mining_block_mined(
    network: &mut Network,
    compute_group: &[String],
    block_info: &CompleteBlock,
) {
    for compute in compute_group {
        compute_mining_block_mined(network, compute, block_info).await;
    }
}

async fn compute_send_utxo_set(network: &mut Network, compute: &str) {
    let mut c = network.compute(compute).unwrap().lock().await;
    c.send_fetched_utxo_set().await.unwrap();
}

//
// StorageNode helpers
//

async fn storage_inject_next_event(
    network: &mut Network,
    from: &str,
    to_storage: &str,
    request: StorageRequest,
) {
    let from_addr = network.get_address(from).await.unwrap();
    let s = network.storage(to_storage).unwrap().lock().await;

    s.inject_next_event(from_addr, request).unwrap();
}

async fn storage_send_blockchain_item(network: &mut Network, from_storage: &str) {
    let mut s = network.storage(from_storage).unwrap().lock().await;
    s.send_blockchain_item().await.unwrap();
}

async fn storage_catchup_fetch_blockchain_item(network: &mut Network, from_storage: &str) {
    let mut s = network.storage(from_storage).unwrap().lock().await;
    s.catchup_fetch_blockchain_item().await.unwrap();
}

async fn storage_inject_send_block_to_storage(
    network: &mut Network,
    compute: &str,
    storage: &str,
    block_info: &CompleteBlock,
) {
    let id: u64;
    if network.get_position(compute) == None {
        id = 1;
    } else {
        id = network.get_position(compute).unwrap() as u64 + 1;
    }

    let mined = block_info.per_node.get(&id).unwrap();
    let block = block_info.common.block.clone();
    let block_txs = block_info.common.block_txs.clone();
    let nonce = mined.nonce.clone();
    let mining_tx = mined.mining_tx.clone();
    let shutdown = false;

    let request = StorageRequest::SendBlock {
        common: CommonBlockInfo { block, block_txs },
        mined_info: MinedBlockExtraInfo {
            nonce,
            mining_tx,
            shutdown,
        },
    };

    storage_inject_next_event(network, compute, storage, request).await;
}

async fn storage_get_stored_key_values_count(network: &mut Network, storage: &str) -> usize {
    let s = network.storage(storage).unwrap().lock().await;
    s.get_stored_values_count()
}

async fn storage_all_get_stored_key_values_count(
    network: &mut Network,
    storage_group: &[String],
) -> Vec<usize> {
    let mut result = Vec::new();
    for name in storage_group {
        let r = storage_get_stored_key_values_count(network, name).await;
        result.push(r);
    }
    result
}

async fn storage_get_last_block_stored(
    network: &mut Network,
    storage: &str,
) -> Option<BlockStoredInfo> {
    let s = network.storage(storage).unwrap().lock().await;
    s.get_last_block_stored().clone()
}

async fn storage_all_get_last_block_stored_num(
    network: &mut Network,
    storage_group: &[String],
) -> Vec<Option<u64>> {
    let mut result = Vec::new();
    for name in storage_group {
        let r = storage_get_last_block_stored(network, name).await;
        result.push(r.map(|bs| bs.block_num));
    }
    result
}

async fn storage_get_last_stored_info(
    network: &mut Network,
    storage: &str,
) -> (Option<String>, Option<(String, u64, usize)>) {
    let s = network.storage(storage).unwrap().lock().await;
    if let Some(info) = s.get_last_block_stored() {
        let complete = storage_get_stored_complete_block_for_node(&s, &info.block_hash);

        (
            complete,
            Some((
                info.block_hash.clone(),
                info.block_num,
                info.mining_transactions.len(),
            )),
        )
    } else {
        (None, None)
    }
}

fn storage_get_stored_complete_block_for_node(s: &StorageNode, block_hash: &str) -> Option<String> {
    let stored_block = {
        let stored_value = s.get_stored_value(block_hash)?;
        let stored_value =
            checked_blockchain_item_data(stored_value, BlockchainItemType::Block).unwrap();
        match deserialize::<StoredSerializingBlock>(&stored_value) {
            Err(e) => return Some(format!("error: {:?}", e)),
            Ok(v) => v,
        }
    };

    let mut block_txs = BTreeMap::new();
    for tx_hash in &stored_block.block.transactions {
        let stored_value = s.get_stored_value(tx_hash)?;
        let stored_value =
            checked_blockchain_item_data(stored_value, BlockchainItemType::Tx).unwrap();
        let stored_tx = match deserialize::<Transaction>(&stored_value) {
            Err(e) => return Some(format!("error tx hash: {:?} : {:?}", e, tx_hash)),
            Ok(v) => v,
        };
        block_txs.insert(tx_hash.clone(), stored_tx);
    }

    let mut per_node = BTreeMap::new();
    for (idx, (tx_hash, nonce)) in &stored_block.mining_tx_hash_and_nonces {
        let stored_value = s.get_stored_value(tx_hash)?;
        let stored_value =
            checked_blockchain_item_data(stored_value, BlockchainItemType::Tx).unwrap();
        let stored_tx = match deserialize::<Transaction>(&stored_value) {
            Err(e) => return Some(format!("error mining tx hash: {:?} : {:?}", e, tx_hash)),
            Ok(v) => v,
        };
        per_node.insert(
            *idx,
            MinedBlockExtraInfo {
                nonce: nonce.clone(),
                mining_tx: (tx_hash.clone(), stored_tx),
                shutdown: false,
            },
        );
    }

    let block = stored_block.block;
    let common = CommonBlockInfo { block, block_txs };
    let complete = CompleteBlock { common, per_node };
    Some(format!("{:?}", complete))
}

async fn storage_all_get_last_stored_info(
    network: &mut Network,
    storage_group: &[String],
) -> Vec<(Option<String>, Option<(String, u64, usize)>)> {
    let mut result = Vec::new();
    for name in storage_group {
        let r = storage_get_last_stored_info(network, name).await;
        result.push(r);
    }
    result
}

async fn storage_send_stored_block(network: &mut Network, storage: &str) {
    let mut s = network.storage(storage).unwrap().lock().await;
    s.send_stored_block().await.unwrap();
}

async fn storage_all_send_stored_block(network: &mut Network, storage_group: &[String]) {
    for storage in storage_group {
        storage_send_stored_block(network, storage).await;
    }
}

async fn storage_handle_event(network: &mut Network, storage: &str, reason_str: &str) {
    let mut s = network.storage(storage).unwrap().lock().await;
    storage_handle_event_for_node(&mut s, true, reason_str, &mut test_timeout()).await;
}

async fn storage_all_handle_event(
    network: &mut Network,
    storage_group: &[String],
    reason_str: &str,
) {
    for storage in storage_group {
        storage_handle_event(network, storage, reason_str).await;
    }
}

async fn storage_handle_event_for_node<E: Future<Output = &'static str> + Unpin>(
    s: &mut StorageNode,
    success_val: bool,
    reason_val: &str,
    exit: &mut E,
) {
    match s.handle_next_event(exit).await {
        Some(Ok(Response { success, reason }))
            if success == success_val && reason == reason_val => {}
        other => {
            error!("Unexpected result: {:?} (expected:{})", other, reason_val);
            panic!("Unexpected result: {:?} (expected:{})", other, reason_val);
        }
    }
}

async fn storage_one_handle_event(
    storage: &Arc<Mutex<StorageNode>>,
    barrier: &Barrier,
    reason_str: &[String],
) {
    debug!("Start wait for event");

    let mut storage = storage.lock().await;
    for reason in reason_str {
        storage_handle_event_for_node(&mut storage, true, reason, &mut test_timeout()).await;
    }

    debug!("Start wait for completion of other in raft group");

    let mut exit = test_timeout_barrier(barrier);
    storage_handle_event_for_node(&mut storage, true, "Barrier complete", &mut exit).await;

    debug!("Stop wait for event");
}

//
// UserNode helpers
//

async fn user_handle_event(network: &mut Network, user: &str, reason_val: &str) {
    let mut u = network.user(user).unwrap().lock().await;
    user_handle_event_for_node(&mut u, true, reason_val, &mut test_timeout()).await;
}

async fn user_handle_error(network: &mut Network, user: &str, reason_val: &str) {
    let mut u = network.user(user).unwrap().lock().await;
    user_handle_event_for_node(&mut u, false, reason_val, &mut test_timeout()).await;
}

async fn user_handle_event_for_node<E: Future<Output = &'static str> + Unpin>(
    u: &mut UserNode,
    success_val: bool,
    reason_val: &str,
    exit: &mut E,
) {
    match u.handle_next_event(exit).await {
        Some(Ok(Response { success, reason }))
            if success == success_val && reason == reason_val => {}
        other => {
            error!("Unexpected result: {:?} (expected:{})", other, reason_val);
            panic!("Unexpected result: {:?} (expected:{})", other, reason_val);
        }
    }
}

async fn user_one_handle_event(
    user: &Arc<Mutex<UserNode>>,
    barrier: &Barrier,
    reason_str: &[String],
) {
    debug!("Start wait for event");

    let mut user = user.lock().await;
    for reason in reason_str {
        user_handle_event_for_node(&mut user, true, reason, &mut test_timeout()).await;
    }

    debug!("Start wait for completion of other in raft group");

    let mut exit = test_timeout_barrier(barrier);
    user_handle_event_for_node(&mut user, true, "Barrier complete", &mut exit).await;

    debug!("Stop wait for event");
}

async fn user_send_transaction_to_compute(
    network: &mut Network,
    from_user: &str,
    to_compute: &str,
    tx: &Transaction,
) {
    let compute_node_addr = network.get_address(to_compute).await.unwrap();
    let mut u = network.user(from_user).unwrap().lock().await;
    u.send_transactions_to_compute(compute_node_addr, vec![tx.clone()])
        .await
        .unwrap();
}

async fn user_send_next_payment_to_destinations(
    network: &mut Network,
    from_user: &str,
    to_compute: &str,
) {
    let compute_node_addr = network.get_address(to_compute).await.unwrap();
    let mut u = network.user(from_user).unwrap().lock().await;
    u.send_next_payment_to_destinations(compute_node_addr)
        .await
        .unwrap();
}

async fn user_send_address_request(
    network: &mut Network,
    from_user: &str,
    to_user: &str,
    amount: TokenAmount,
) {
    let user_node_addr = network.get_address(to_user).await.unwrap();
    let mut u = network.user(from_user).unwrap().lock().await;
    u.send_address_request(user_node_addr, amount)
        .await
        .unwrap();
}

async fn user_send_donation_address_to_peer(network: &mut Network, from_user: &str, to_user: &str) {
    let user_node_addr = network.get_address(to_user).await.unwrap();
    let mut u = network.user(from_user).unwrap().lock().await;
    u.send_donation_address_to_peer(user_node_addr)
        .await
        .unwrap();
}

async fn user_send_address_to_trading_peer(network: &mut Network, user: &str) {
    let mut u = network.user(user).unwrap().lock().await;
    u.send_address_to_trading_peer().await.unwrap();
}

async fn user_process_mining_notified(
    network: &mut Network,
    user: &str,
) -> Option<BTreeMap<String, Transaction>> {
    let mut u = network.user(user).unwrap().lock().await;
    u.process_mining_notified().await;
    u.pending_test_auto_gen_txs()
        .cloned()
        .map(|m| m.into_iter().map(|(k, (tx, _))| (k, tx)).collect())
}

async fn user_get_received_utxo_set_keys(network: &mut Network, user: &str) -> Vec<OutPoint> {
    let u = network.user(user).unwrap().lock().await;
    let received_utxo_set = u.get_received_utxo().unwrap();
    received_utxo_set.keys().cloned().collect()
}

async fn user_update_running_total(network: &mut Network, user: &str) {
    let mut u = network.user(user).unwrap().lock().await;
    u.update_running_total().await;
}

async fn user_trigger_update_wallet_from_utxo_set(
    network: &mut Network,
    user: &str,
    address_list: UtxoFetchType,
) {
    let u = network.user(user).unwrap().lock().await;
    let request = UserRequest::UserApi(UserApiRequest::UpdateWalletFromUtxoSet { address_list });
    u.api_inputs()
        .1
        .inject_next_event(u.address(), request)
        .unwrap();
}

async fn user_send_request_utxo_set(
    network: &mut Network,
    user: &str,
    address_list: UtxoFetchType,
) {
    let mut u = network.user(user).unwrap().lock().await;
    u.send_request_utxo_set(address_list).await.unwrap();
}

async fn user_send_receipt_based_payment_request(
    network: &mut Network,
    from: &str,
    to: &str,
    send_asset: Asset,
) {
    let mut u = network.user(from).unwrap().lock().await;
    let to_addr = network.get_address(to).await.unwrap();
    u.send_rb_payment_request(to_addr, send_asset)
        .await
        .unwrap();
}

async fn user_send_receipt_based_payment_response(network: &mut Network, user: &str) {
    let mut u = network.user(user).unwrap().lock().await;
    u.send_rb_payment_response().await.unwrap();
}

async fn user_send_receipt_based_payment_to_desinations(
    network: &mut Network,
    user: &str,
    compute: &str,
) {
    let mut u = network.user(user).unwrap().lock().await;
    let compute_addr = network.get_address(compute).await.unwrap();
    u.send_next_rb_transaction_to_destinations(compute_addr)
        .await
        .unwrap();
}

async fn user_send_receipt_asset(
    network: &mut Network,
    user: &str,
    compute: &str,
    receipt_amount: u64,
) {
    let mut u = network.user(user).unwrap().lock().await;
    let compute_addr = network.get_address(compute).await.unwrap();
    u.generate_receipt_asset_tx(receipt_amount).await;
    u.send_next_payment_to_destinations(compute_addr)
        .await
        .unwrap();
}

//
// MinerNode helpers
//

async fn miner_request_blockchain_item(network: &mut Network, miner_from: &str, block_key: &str) {
    let mut m = network.miner(miner_from).unwrap().lock().await;
    m.request_blockchain_item(block_key.to_owned())
        .await
        .unwrap();
}

async fn miner_get_blockchain_item_received_b_num(
    network: &mut Network,
    miner: &str,
) -> Option<(u64, (char, u64, u32))> {
    let mut m = network.miner(miner).unwrap().lock().await;
    let (_, item, _) = m.get_blockchain_item_received().await.as_ref()?;
    let block: StoredSerializingBlock = deserialize(&item.data).ok()?;
    Some((block.block.header.b_num, miner_blockchain_item_meta(item)))
}

async fn miner_get_blockchain_item_received_tx_lens(
    network: &mut Network,
    miner: &str,
) -> Option<(usize, usize, (char, u64, u32))> {
    let mut m = network.miner(miner).unwrap().lock().await;
    let (_, item, _) = m.get_blockchain_item_received().await.as_ref()?;
    let tx: Transaction = deserialize(&item.data).ok()?;
    Some((
        tx.inputs.len(),
        tx.outputs.len(),
        miner_blockchain_item_meta(item),
    ))
}

fn miner_blockchain_item_meta(item: &BlockchainItem) -> (char, u64, u32) {
    match item.item_meta {
        BlockchainItemMeta::Block { block_num, tx_len } => ('b', block_num, tx_len),
        BlockchainItemMeta::Tx { block_num, tx_num } => ('t', block_num, tx_num),
    }
}

async fn miner_handle_event(network: &mut Network, miner: &str, reason_val: &str) {
    let mut m = network.miner(miner).unwrap().lock().await;
    miner_handle_event_for_node(&mut m, true, reason_val, &mut test_timeout()).await;
}

async fn miner_all_handle_event(network: &mut Network, miner_group: &[String], reason_str: &str) {
    for miner in miner_group {
        miner_handle_event(network, miner, reason_str).await;
    }
}

async fn miner_handle_event_for_node<E: Future<Output = &'static str> + Unpin>(
    m: &mut MinerNode,
    success_val: bool,
    reason_val: &str,
    exit: &mut E,
) {
    match m.handle_next_event(exit).await {
        Some(Ok(Response { success, reason }))
            if success == success_val && reason == reason_val => {}
        other => {
            error!("Unexpected result: {:?} (expected:{})", other, reason_val);
            panic!("Unexpected result: {:?} (expected:{})", other, reason_val);
        }
    }
}

async fn miner_one_handle_event(
    miner: &Arc<Mutex<MinerNode>>,
    barrier: &Barrier,
    reason_str: &[String],
) {
    debug!("Start wait for event");

    let mut miner = miner.lock().await;
    for reason in reason_str {
        miner_handle_event_for_node(&mut miner, true, reason, &mut test_timeout()).await;
    }

    debug!("Start wait for completion of other in raft group");

    let mut exit = test_timeout_barrier(barrier);
    miner_handle_event_for_node(&mut miner, true, "Barrier complete", &mut exit).await;

    debug!("Stop wait for event");
}

async fn miner_process_found_partition_pow(network: &mut Network, from_miner: &str) {
    let mut m = network.miner(from_miner).unwrap().lock().await;
    m.process_found_partition_pow().await;
}

async fn miner_process_found_block_pow(network: &mut Network, from_miner: &str) {
    let mut m = network.miner(from_miner).unwrap().lock().await;
    m.process_found_block_pow().await;
}

//
// Test helpers
//

fn test_step_start() {
    let _ = tracing_log_try_init();
    info!("Test Step start");
}

async fn test_step_complete(network: Network) {
    network.close_raft_loops_and_drop().await;
    info!("Test Step complete")
}

fn valid_transactions(fixed: bool) -> BTreeMap<String, Transaction> {
    valid_transactions_with(fixed, DEFAULT_SEED_AMOUNT, true)
}

fn valid_transactions_with(
    fixed: bool,
    amount: TokenAmount,
    with_create: bool,
) -> BTreeMap<String, Transaction> {
    let (pk, sk) = if !fixed {
        let (pk, sk) = sign::gen_keypair();
        println!("sk: {}, pk: {}", hex::encode(&sk), hex::encode(&pk));
        (pk, sk)
    } else {
        let sk_slice = hex::decode(COMMON_SEC_KEY).unwrap();
        let pk_slice = hex::decode(COMMON_PUB_KEY).unwrap();
        let sk = SecretKey::from_slice(&sk_slice).unwrap();
        let pk = PublicKey::from_slice(&pk_slice).unwrap();
        (pk, sk)
    };

    let txs = vec![
        (&VALID_TXS_IN[0..1], &VALID_TXS_OUT[0..1]),
        (&VALID_TXS_IN[1..3], &VALID_TXS_OUT[1..3]),
    ];

    let mut transactions = BTreeMap::new();
    for (ins, outs) in &txs {
        let (t_hash, payment_tx) =
            create_valid_transaction_with_ins_outs(ins, outs, &pk, &sk, amount, None);
        transactions.insert(t_hash, payment_tx);
    }

    // Add one create tx
    if with_create {
        let drs = vec![0, 1, 2, 3, 4, 5];
        let (create_hash, create_tx) = create_valid_create_transaction_with_ins_outs(drs, pk, &sk);
        transactions.insert(create_hash, create_tx);
    }

    transactions
}

fn make_compute_seed_utxo(seed: &[(i32, &str)], amount: TokenAmount) -> UtxoSetSpec {
    let seed: Vec<_> = seed
        .iter()
        .copied()
        .map(|(n, v)| (v, (0..n).map(|_| (COMMON_PUB_KEY, amount)).collect()))
        .collect();
    make_compute_seed_utxo_with_info(&seed)
}

fn make_compute_seed_utxo_with_info(seed: &[(&str, Vec<(&str, TokenAmount)>)]) -> UtxoSetSpec {
    seed.iter()
        .map(|(v, txo)| {
            (
                v.to_string(),
                txo.iter()
                    .map(|(pk, amount)| TxOutSpec {
                        public_key: pk.to_string(),
                        amount: *amount,
                    })
                    .collect(),
            )
        })
        .collect()
}

fn panic_on_timeout<E>(response: &Result<Response, E>, tag: &str) {
    if let Ok(Response {
        success: true,
        reason: "Test timeout elapsed",
    }) = response
    {
        panic!("Test timeout elapsed - {}", tag);
    }
}

fn test_timeout() -> impl Future<Output = &'static str> + Unpin {
    Box::pin(async move {
        time::sleep(TIMEOUT_TEST_WAIT_DURATION).await;
        "Test timeout elapsed"
    })
}

fn test_timeout_barrier(barrier: &'_ Barrier) -> impl Future<Output = &'static str> + Unpin + '_ {
    Box::pin(async move {
        tokio::select! {
            r = test_timeout() => r,
            _ = barrier.wait() => "Barrier complete",
        }
    })
}

fn equal_first<T: Eq>(values: &[T]) -> Vec<bool> {
    values.iter().map(|v| *v == values[0]).collect()
}

fn len_and_map<K, V>(values: &BTreeMap<K, V>) -> (usize, &BTreeMap<K, V>) {
    (values.len(), values)
}

fn remove_keys<'a, Q: 'a + ?Sized + Ord, K: std::borrow::Borrow<Q> + Ord, V>(
    value: &mut BTreeMap<K, V>,
    keys: impl Iterator<Item = &'a Q>,
) {
    for key in keys {
        value.remove(key).unwrap();
    }
}

fn substract_vec(value1: &[usize], value2: &[usize]) -> Vec<usize> {
    value1
        .iter()
        .zip(value2.iter())
        .map(|(v1, v2)| v1 - v2)
        .collect()
}

fn merge_txs_3(v1: &UtxoSet, v2: &UtxoSet, v3: &UtxoSet) -> UtxoSet {
    v1.clone()
        .into_iter()
        .chain(v2.clone().into_iter())
        .chain(v3.clone().into_iter())
        .collect()
}

fn wallet_seed(out_p: (i32, &str), amount: &TokenAmount) -> WalletTxSpec {
    WalletTxSpec {
        out_point: format!("{}-{}", out_p.0, out_p.1),
        secret_key: COMMON_SEC_KEY.to_owned(),
        public_key: COMMON_PUB_KEY.to_owned(),
        amount: amount.0,
        address_version: None,
    }
}

fn valid_txs_in() -> UtxoSet {
    VALID_TXS_IN
        .iter()
        .map(|(n, h)| (OutPoint::new(h.to_string(), *n), TxOut::new()))
        .collect()
}

fn to_utxo_set(txs: &BTreeMap<String, Transaction>) -> UtxoSet {
    get_tx_out_with_out_point_cloned(txs.iter()).collect()
}

fn complete_block_mining_txs(block: &CompleteBlock) -> BTreeMap<String, Transaction> {
    block
        .per_node
        .values()
        .map(|m_info| m_info.mining_tx.clone())
        .collect()
}

async fn complete_first_block(
    next_block_tx: &BTreeMap<String, Transaction>,
    mining_txs: usize,
) -> ((String, String), CompleteBlock) {
    complete_block(0, None, next_block_tx, mining_txs).await
}

async fn construct_mining_extra_info(
    block: Block,
    block_num: u64,
    addr: String,
) -> MinedBlockExtraInfo {
    let amount = calculate_reward(TokenAmount(0));
    let tx = construct_coinbase_tx(block_num, amount, addr);
    let hash = construct_tx_hash(&tx);

    MinedBlockExtraInfo {
        nonce: generate_pow_for_block(&block.clone(), hash.clone()).await,
        mining_tx: (hash, tx),
        shutdown: false,
    }
}

fn checked_blockchain_item_data(
    v: BlockchainItem,
    t: BlockchainItemType,
) -> Result<Vec<u8>, StringError> {
    if v.version != NETWORK_VERSION || v.item_meta.as_type() != t {
        Err(StringError(format!(
            "blockchain_item check v:{}={}, t:{:?}=={:?}",
            v.version,
            NETWORK_VERSION,
            v.item_meta.as_type(),
            t
        )))
    } else {
        Ok(v.data)
    }
}

async fn complete_blocks(
    block_count: usize,
    block_txs: &[BTreeMap<String, Transaction>],
    mining_txs: usize,
) -> ((Vec<String>, Vec<String>), Vec<CompleteBlock>) {
    let no_transactions = BTreeMap::new();

    let mut block_keys: Vec<String> = Vec::new();
    let mut complete_strs: Vec<String> = Vec::new();
    let mut blocks: Vec<CompleteBlock> = Vec::new();

    for i in 0..block_count {
        let previous = block_keys.last().map(|v| v.as_str());
        let transactions = block_txs.get(i).unwrap_or(&no_transactions);
        let ((block_key, complete_str), block) =
            complete_block(i as u64, previous, transactions, mining_txs).await;

        block_keys.push(block_key);
        complete_strs.push(complete_str);
        blocks.push(block);
    }
    ((block_keys, complete_strs), blocks)
}

async fn complete_block(
    block_num: u64,
    previous_hash: Option<&str>,
    block_txs: &BTreeMap<String, Transaction>,
    mining_txs: usize,
) -> ((String, String), CompleteBlock) {
    let mut block = Block::new();
    block.header.b_num = block_num;
    block.header.previous_hash = previous_hash.map(|v| v.to_string());
    block.transactions = block_txs.keys().cloned().collect();

    let per_node_init: BTreeMap<u64, String> = (0..mining_txs)
        .map(|i| i as u64 + 1)
        .map(|idx| (idx, hex::encode(vec![block_num as u8, idx as u8])))
        .collect();

    let mut per_node: BTreeMap<u64, MinedBlockExtraInfo> = BTreeMap::new();
    let init_keys: Vec<_> = per_node_init.keys().cloned().collect();
    for idx in init_keys {
        let addr = per_node_init.get(&idx).unwrap().clone();
        let mined_block_info = construct_mining_extra_info(block.clone(), block_num, addr).await;
        per_node.insert(idx, mined_block_info);
    }

    let complete = CompleteBlock {
        common: CommonBlockInfo {
            block,
            block_txs: block_txs.clone(),
        },
        per_node,
    };
    let stored = StoredSerializingBlock {
        block: complete.common.block.clone(),
        mining_tx_hash_and_nonces: complete
            .per_node
            .iter()
            .map(|(idx, v)| (*idx, (v.mining_tx.0.clone(), v.nonce.clone())))
            .collect(),
    };

    let hash_key = {
        let hash_input = serialize(&stored).unwrap();
        let hash_digest = Sha3_256::digest(&hash_input);
        let mut hash_digest = hex::encode(hash_digest);
        hash_digest.insert(0, BLOCK_PREPEND as char);
        hash_digest
    };
    let complete_str = format!("{:?}", complete);

    ((hash_key, complete_str), complete)
}

async fn generate_pow_for_block(block: &Block, mining_tx_hash: String) -> Vec<u8> {
    let hash_to_mine =
        concat_merkle_coinbase(&block.header.merkle_root_hash, &mining_tx_hash).await;
    let mut nonce: Vec<u8> = generate_nonce();
    let prev_hash: String;
    let temp_option = block.header.previous_hash.clone();
    match temp_option {
        None => prev_hash = String::from(""),
        _ => prev_hash = temp_option.unwrap(),
    }

    while !validate_pow_block(&prev_hash, &hash_to_mine, &nonce) {
        nonce = generate_nonce();
    }
    nonce
}
/// Generates a random sequence of values for a nonce
fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen_range(0, 200)).collect()
}

fn basic_network_config(initial_port: u16) -> NetworkConfig {
    NetworkConfig {
        initial_port,
        compute_raft: false,
        storage_raft: false,
        in_memory_db: true,
        compute_partition_full_size: 1,
        compute_minimum_miner_pool_len: 1,
        nodes: vec![(NodeType::User, vec!["user1".to_string()])]
            .into_iter()
            .collect(),
        compute_seed_utxo: make_compute_seed_utxo(SEED_UTXO, DEFAULT_SEED_AMOUNT),
        compute_genesis_tx_in: None,
        user_wallet_seeds: Vec::new(),
        compute_to_miner_mapping: Default::default(),
        test_duration_divider: TEST_DURATION_DIVIDER,
        passphrase: Some("Test Passphrase".to_owned()),
        user_auto_donate: 0,
        user_test_auto_gen_setup: Default::default(),
        tls_config: Default::default(),
    }
}

fn complete_network_config(initial_port: u16) -> NetworkConfig {
    complete_network_config_with_n_compute_miner(initial_port, false, 1, 1)
}

fn complete_network_config_with_n_compute_raft(
    initial_port: u16,
    compute_count: usize,
) -> NetworkConfig {
    complete_network_config_with_n_compute_miner(initial_port, true, compute_count, compute_count)
}

fn complete_network_config_with_n_compute_miner(
    initial_port: u16,
    use_raft: bool,
    raft_count: usize,
    miner_count: usize,
) -> NetworkConfig {
    basic_network_config(initial_port)
        .with_raft(use_raft)
        .with_groups(raft_count, miner_count)
}
