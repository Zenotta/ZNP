use super::tests_last_version_db::{self, DbEntryType};
use super::{
    dump_db, get_upgrade_compute_db, get_upgrade_storage_db, get_upgrade_wallet_db, old,
    upgrade_compute_db, upgrade_storage_db, upgrade_wallet_db, UpgradeCfg, UpgradeError,
    UpgradeStatus,
};
use crate::configurations::{DbMode, ExtraNodeParams, UserAutoGenTxSetup, WalletTxSpec};
use crate::constants::{LAST_BLOCK_HASH_KEY, NETWORK_VERSION_SERIALIZED};
use crate::db_utils::{
    new_db, new_db_with_version, SimpleDb, SimpleDbError, SimpleDbSpec, DB_COL_DEFAULT,
};
use crate::interfaces::{BlockStoredInfo, BlockchainItem, BlockchainItemMeta, Response};
use crate::test_utils::{
    get_test_tls_spec, node_join_all_checked, remove_all_node_dbs, Network, NetworkConfig,
    NetworkNodeInfo, NodeType,
};
use crate::tests::compute_committed_tx_pool;
use crate::utils::{get_test_common_unicorn, tracing_log_try_init};
use crate::{compute, compute_raft, storage, storage_raft, wallet};
use naom::primitives::asset::{Asset, TokenAmount};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use tracing::info;

type ExtraNodeParamsFilterMap = BTreeMap<String, ExtraNodeParamsFilter>;

const WALLET_PASSWORD: &str = "TestPassword";
const LAST_BLOCK_STORED_NUM: u64 = 6;
const LAST_BLOCK_BLOCK_HASH: &str =
    "b57dc8fbe539699a43af4f16c2f9293f013976571422524a492e5d5a54193b868";
const LAST_BLOCK_STORAGE_DB_V0_3_0_INDEX: usize = 8;
const STORAGE_DB_V0_3_0_JSON_OFFSET: usize = 29;
const STORAGE_DB_V0_3_0_CHAIN_VS_OFFSET: usize = 117;
const STORAGE_DB_V0_3_0_INDEXES: &[(&str, usize)] = &[
    ("nIndexedTxHashKey_0000000000000000_00000000", 0),
    ("nIndexedTxHashKey_0000000000000000_00000001", 1),
    ("nIndexedTxHashKey_0000000000000000_00000002", 2),
    ("nIndexedTxHashKey_0000000000000000_00000003", 3),
    ("nIndexedBlockHashKey_0000000000000001", 4),
    ("nIndexedBlockHashKey_0000000000000002", 5),
    ("nIndexedBlockHashKey_0000000000000000", 6),
    ("nIndexedBlockHashKey_0000000000000004", 15),
    ("nIndexedBlockHashKey_0000000000000006", 16),
    ("nIndexedBlockHashKey_0000000000000005", 17),
    ("nIndexedBlockHashKey_0000000000000003", 18),
    ("nIndexedTxHashKey_0000000000000006_00000000", 19),
    ("nIndexedTxHashKey_0000000000000005_00000000", 20),
    ("nIndexedTxHashKey_0000000000000001_00000000", 7),
    ("nIndexedTxHashKey_0000000000000002_00000003", 8),
    ("nIndexedTxHashKey_0000000000000006_00000001", 21),
    ("nIndexedTxHashKey_0000000000000002_00000000", 9),
    ("nIndexedTxHashKey_0000000000000001_00000001", 10),
    ("nIndexedTxHashKey_0000000000000000_00000004", 11),
    ("nIndexedTxHashKey_0000000000000005_00000003", 22),
    ("nIndexedTxHashKey_0000000000000003_00000000", 23),
    ("nIndexedTxHashKey_0000000000000006_00000003", 24),
    ("nIndexedTxHashKey_0000000000000001_00000002", 12),
    ("nIndexedTxHashKey_0000000000000005_00000001", 25),
    ("nIndexedTxHashKey_0000000000000004_00000000", 26),
    ("nIndexedTxHashKey_0000000000000002_00000001", 13),
    ("nIndexedTxHashKey_0000000000000005_00000002", 27),
    ("nIndexedTxHashKey_0000000000000006_00000002", 28),
    ("nIndexedTxHashKey_0000000000000002_00000002", 14),
];
const STORAGE_DB_V0_3_0_BLOCK_LEN: &[u32] = &[5, 3, 4, 1, 1, 4, 4];
const STORAGE_DB_V0_3_0_BLOCK_VERSION: &[u32] = &[0, 0, 0, 1, 1, 1, 1];
const TIMEOUT_TEST_WAIT_DURATION: Duration = Duration::from_millis(5000);

const KEEP_ALL_FILTER: ExtraNodeParamsFilter = ExtraNodeParamsFilter {
    db: true,
    raft_db: true,
    wallet_db: true,
};

enum Specs {
    Db(SimpleDbSpec, SimpleDbSpec),
    Wallet(SimpleDbSpec),
}

#[derive(Clone, Copy)]
pub struct ExtraNodeParamsFilter {
    pub db: bool,
    pub raft_db: bool,
    pub wallet_db: bool,
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_compute_real_db() {
    let config = real_db(complete_network_config(20000));
    remove_all_node_dbs(&config);
    upgrade_common(config, "compute1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_compute_in_memory() {
    let config = complete_network_config(20010);
    upgrade_common(config, "compute1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_storage_in_memory() {
    let config = complete_network_config(20020);
    upgrade_common(config, "storage1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_miner_in_memory() {
    let config = complete_network_config(20030);
    upgrade_common(config, "miner1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_user_in_memory() {
    let config = complete_network_config(20040);
    upgrade_common(config, "user1", cfg_upgrade()).await;
}

async fn upgrade_common(config: NetworkConfig, name: &str, upgrade_cfg: UpgradeCfg) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_stopped_from_config(&config);
    let n_info = network.get_node_info(name).unwrap().clone();
    let db = create_old_node_db(&n_info);

    //
    // Act
    //
    let db = get_upgrade_node_db(&n_info, in_memory(db)).unwrap();
    let (db, status) = upgrade_node_db(&n_info, db, &upgrade_cfg).unwrap();
    let db = open_as_new_node_db(&n_info, in_memory(db)).unwrap();

    network.add_extra_params(name, in_memory(db));
    network.re_spawn_dead_nodes().await;
    raft_node_handle_event(&mut network, name, "Snapshot applied").await;

    //
    // Assert
    //
    match n_info.node_type {
        NodeType::Compute => {
            let (expected_mining_b_num, expected_b_num) = (None, Some(LAST_BLOCK_STORED_NUM));

            let compute = network.compute(name).unwrap().lock().await;

            let block = compute.get_mining_block();
            assert_eq!(
                block.as_ref().map(|bs| bs.header.b_num),
                expected_mining_b_num
            );

            let b_num = compute.get_committed_current_block_num();
            assert_eq!(b_num, expected_b_num);
            assert_eq!(compute.get_request_list(), &Default::default());
            assert_eq!(status.last_block_num, None);
            assert_eq!(status.last_raft_block_num, expected_b_num);
        }
        NodeType::Storage => {
            let storage = network.storage(name).unwrap().lock().await;

            {
                let mut expected = Vec::new();
                let mut actual = Vec::new();
                let mut actual_indexed = Vec::new();
                let db_v3 = tests_last_version_db::STORAGE_DB_V0_3_0;
                for (i, (idx_k, data_i)) in STORAGE_DB_V0_3_0_INDEXES.iter().enumerate() {
                    let (_, k, _) = db_v3[i];
                    let json_idx = STORAGE_DB_V0_3_0_JSON_OFFSET + i;
                    let data_v_idx = STORAGE_DB_V0_3_0_CHAIN_VS_OFFSET + data_i;
                    let item_meta = index_meta(idx_k);
                    expected.push(Some(test_hash(BlockchainItem {
                        version: STORAGE_DB_V0_3_0_BLOCK_VERSION[item_meta.block_num() as usize],
                        item_meta,
                        key: k.to_vec(),
                        data: db_v3[data_v_idx].2.to_vec(),
                        data_json: db_v3[json_idx].2.to_vec(),
                    })));
                    actual.push(storage.get_stored_value(k).map(test_hash));
                    actual_indexed.push(storage.get_stored_value(idx_k).map(test_hash));
                }
                assert_eq!(actual, expected);
                assert_eq!(actual_indexed, expected);
                assert_eq!(storage.get_stored_values_count(), expected.len());
                assert_eq!(
                    storage.get_stored_value(LAST_BLOCK_HASH_KEY).map(test_hash),
                    expected[LAST_BLOCK_STORAGE_DB_V0_3_0_INDEX]
                );
                assert_eq!(
                    storage.get_last_block_stored(),
                    &Some(get_expected_last_block_stored())
                );
                assert_eq!(status.last_block_num, Some(LAST_BLOCK_STORED_NUM));
                assert_eq!(status.last_raft_block_num, Some(LAST_BLOCK_STORED_NUM + 1));
            }
        }
        NodeType::User => {
            let user = network.user(name).unwrap().lock().await;
            let wallet = user.get_wallet_db();
            let payment = wallet
                .fetch_inputs_for_payment(Asset::token_u64(123))
                .await
                .unwrap();
            assert_eq!(
                (payment.0.len(), payment.1, payment.2.len()),
                (1, Asset::token_u64(123), 1)
            );
        }
        NodeType::Miner => {
            let miner = network.miner(name).unwrap().lock().await;
            let wallet = miner.get_wallet_db();
            let payment = wallet
                .fetch_inputs_for_payment(Asset::token_u64(37550922))
                .await
                .unwrap();
            assert_eq!(
                (payment.0.len(), payment.1, payment.2.len()),
                (5, Asset::token_u64(37550922), 5)
            );
        }
    }

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_upgrade_started_compute_real_db() {
    let config = real_db(complete_network_config(20100));
    remove_all_node_dbs(&config);
    open_upgrade_started_compute_common(config, "compute1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_upgrade_started_compute_in_memory() {
    let config = complete_network_config(20110);
    open_upgrade_started_compute_common(config, "compute1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_upgrade_started_storage_in_memory() {
    let config = complete_network_config(20120);
    open_upgrade_started_compute_common(config, "storage1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_upgrade_started_miner_in_memory() {
    let config = complete_network_config(20130);
    open_upgrade_started_compute_common(config, "miner1", cfg_upgrade()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_upgrade_started_user_in_memory() {
    let config = complete_network_config(20140);
    open_upgrade_started_compute_common(config, "user1", cfg_upgrade()).await;
}

async fn open_upgrade_started_compute_common(
    config: NetworkConfig,
    name: &str,
    _upgrade_cfg: UpgradeCfg,
) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_stopped_from_config(&config);
    let n_info = network.get_node_info(name).unwrap().clone();
    let db = create_old_node_db(&n_info);

    //
    // Act
    //
    let err_new_1 = open_as_new_node_db(&n_info, cloned_in_memory(&db)).err();
    let db = open_as_old_node_db(&n_info, in_memory(db)).unwrap();

    let db = get_upgrade_node_db(&n_info, in_memory(db)).unwrap();
    let db = open_as_old_node_db(&n_info, in_memory(db)).unwrap();
    let db = get_upgrade_node_db(&n_info, in_memory(db)).unwrap();

    let err_new_2 = open_as_new_node_db(&n_info, cloned_in_memory(&db)).err();

    //
    // Assert
    //
    assert!(err_new_1.is_some());
    assert!(err_new_2.is_some());

    test_step_complete(network).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_real_db() {
    let config = real_db(complete_network_config(20200));
    remove_all_node_dbs(&config);
    upgrade_restart_network_common(config, cfg_upgrade(), Default::default(), false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_in_memory() {
    let config = complete_network_config(20210);
    upgrade_restart_network_common(config, cfg_upgrade(), Default::default(), false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_raft_2_in_memory() {
    // Create 2 identical copy of the database in memory for each node in raft grup.
    // Upgrade applying the configuration data and run.
    let raft_len = 2;

    let config = complete_network_config(20220).with_groups(raft_len, raft_len);
    let mut upgrade_cfg = cfg_upgrade();
    upgrade_cfg.raft_len = raft_len;
    upgrade_restart_network_common(config, upgrade_cfg, Default::default(), false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_raft_3_raft_db_only_in_memory() {
    // Only copy over the upgraded raft database, and pull main db
    let raft_len = 3;
    let filter = ExtraNodeParamsFilter {
        db: false,
        raft_db: true,
        wallet_db: false,
    };
    let params_filters = vec![
        ("storage1".to_owned(), filter),
        ("storage2".to_owned(), filter),
        ("compute1".to_owned(), filter),
        ("compute2".to_owned(), filter),
    ]
    .into_iter()
    .collect();

    let config = complete_network_config(20230).with_groups(raft_len, raft_len - 1);
    let mut upgrade_cfg = cfg_upgrade();
    upgrade_cfg.raft_len = raft_len;
    upgrade_restart_network_common(config, upgrade_cfg, params_filters, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_raft_3_pre_launch_only_in_memory() {
    // Pull raft database during pre-launch, and pull main db
    let raft_len = 3;
    let filter = ExtraNodeParamsFilter {
        db: false,
        raft_db: false,
        wallet_db: false,
    };
    let params_filters = vec![
        ("storage2".to_owned(), filter),
        ("storage3".to_owned(), filter),
        ("compute2".to_owned(), filter),
        ("compute3".to_owned(), filter),
    ]
    .into_iter()
    .collect();

    let config = complete_network_config(20240).with_groups(raft_len, raft_len - 1);
    let mut upgrade_cfg = cfg_upgrade();
    upgrade_cfg.raft_len = raft_len;
    upgrade_restart_network_common(config, upgrade_cfg, params_filters, true).await;
}

async fn upgrade_restart_network_common(
    mut config: NetworkConfig,
    upgrade_cfg: UpgradeCfg,
    params_filters: ExtraNodeParamsFilterMap,
    pre_launch: bool,
) {
    test_step_start();

    //
    // Arrange
    //
    config.user_test_auto_gen_setup = get_test_auto_gen_setup(Some(0));
    let mut network = Network::create_stopped_from_config(&config);
    let compute_nodes = &config.nodes[&NodeType::Compute];
    let storage_nodes = &config.nodes[&NodeType::Storage];
    let raft_nodes: Vec<String> = compute_nodes.iter().chain(storage_nodes).cloned().collect();
    let extra_blocks = 2usize;
    let expected_block_num = LAST_BLOCK_STORED_NUM + extra_blocks as u64;

    for name in network.dead_nodes().clone() {
        let n_info = network.get_node_info(&name).unwrap();
        let db = create_old_node_db(n_info);
        let db = get_upgrade_node_db(n_info, in_memory(db)).unwrap();
        let (db, _) = upgrade_node_db(n_info, db, &upgrade_cfg).unwrap();
        let db = filter_dbs(db, params_filters.get(&name).unwrap_or(&KEEP_ALL_FILTER));
        network.add_extra_params(&name, in_memory(db));
    }

    //
    // Act
    //
    if pre_launch {
        network.pre_launch_nodes_named(&raft_nodes).await;
        let handles = network
            .spawn_main_node_loops(TIMEOUT_TEST_WAIT_DURATION)
            .await;
        node_join_all_checked(handles, &"").await.unwrap();
        network.close_loops_and_drop_named(&raft_nodes).await;
    }

    network.re_spawn_dead_nodes().await;
    for node_name in compute_nodes {
        node_send_coordinated_shutdown(&mut network, node_name, expected_block_num).await;
    }

    let handles = network
        .spawn_main_node_loops(TIMEOUT_TEST_WAIT_DURATION)
        .await;
    node_join_all_checked(handles, &"").await.unwrap();

    //
    // Assert
    //
    {
        let compute = network.compute("compute1").unwrap().lock().await;
        let b_num = compute.get_committed_current_block_num();
        assert_eq!(b_num, Some(expected_block_num));
    }
    {
        let mut actual_count = Vec::new();
        let mut actual_last_bnum = Vec::new();
        for node in storage_nodes {
            let storage = network.storage(node).unwrap().lock().await;
            let count = storage.get_stored_values_count();
            let block_stored = storage.get_last_block_stored().as_ref();
            let last_bnum = block_stored.map(|b| b.block_num);

            actual_count.push(count);
            actual_last_bnum.push(last_bnum);

            let (db, _, _, _, _) = storage.api_inputs();
            let db = db.lock().unwrap();
            info!(
                "dump_db {}: count:{} b_num:{:?}, \n{}",
                node,
                count,
                last_bnum,
                dump_db(&db).collect::<Vec<String>>().join("\n")
            );
        }

        let raft_len = upgrade_cfg.raft_len;
        let expected_count = STORAGE_DB_V0_3_0_INDEXES.len() + extra_blocks * (1 + 1);
        assert_eq!(actual_count, vec![expected_count; raft_len]);
        assert_eq!(actual_last_bnum, vec![Some(expected_block_num); raft_len]);
    }

    test_step_complete(network).await;
}

// Spend transactions with old address structure
#[tokio::test(flavor = "current_thread")]
async fn upgrade_spend_old_tx() {
    //
    // Arrange
    //
    let config = complete_network_config(20260);
    let mut network = Network::create_stopped_from_config(&config);

    for name in ["user1", "compute1"] {
        let node_info = network.get_node_info(name).unwrap().clone();
        let db = create_old_node_db(&node_info);
        let db = get_upgrade_node_db(&node_info, in_memory(db)).unwrap();
        let (db, _) = upgrade_node_db(&node_info, db, &cfg_upgrade()).unwrap();
        let db = open_as_new_node_db(&node_info, in_memory(db)).unwrap();
        network.add_extra_params(name, in_memory(db));
    }

    //
    // Act
    //
    network.re_spawn_dead_nodes().await;
    raft_node_handle_event(&mut network, "user1", "Snapshot applied").await;
    raft_node_handle_event(&mut network, "compute1", "Snapshot applied").await;

    user_make_payment_transaction(
        &mut network,
        "user1",
        "compute1",
        TokenAmount(123),
        "payment_address00000000000000000".to_owned(),
    )
    .await;

    raft_node_handle_event(&mut network, "compute1", "Transactions added to tx pool").await;
    raft_node_handle_event(&mut network, "compute1", "Transactions committed").await;
    let actual_tx_pool = compute_committed_tx_pool(&mut network, "compute1").await;

    //
    // Assert
    //
    assert_eq!(actual_tx_pool.len(), 1);
}

//
// Test helpers
//

fn create_old_node_db(info: &NetworkNodeInfo) -> ExtraNodeParams {
    match info.node_type {
        NodeType::Compute => ExtraNodeParams {
            db: Some(create_old_db(
                &old::compute::DB_SPEC,
                info.db_mode,
                tests_last_version_db::COMPUTE_DB_V0_3_0,
            )),
            raft_db: Some(create_old_db(
                &old::compute_raft::DB_SPEC,
                info.db_mode,
                tests_last_version_db::COMPUTE_RAFT_DB_V0_3_0,
            )),
            ..Default::default()
        },
        NodeType::Storage => ExtraNodeParams {
            db: Some(create_old_db(
                &old::storage::DB_SPEC,
                info.db_mode,
                tests_last_version_db::STORAGE_DB_V0_3_0,
            )),
            raft_db: Some(create_old_db(
                &old::storage_raft::DB_SPEC,
                info.db_mode,
                tests_last_version_db::STORAGE_RAFT_DB_V0_3_0,
            )),
            ..Default::default()
        },
        NodeType::User => ExtraNodeParams {
            wallet_db: Some(create_old_db(
                &old::wallet::DB_SPEC,
                info.db_mode,
                tests_last_version_db::USER_DB_V0_3_0,
            )),
            ..Default::default()
        },
        NodeType::Miner => ExtraNodeParams {
            wallet_db: Some(create_old_db(
                &old::wallet::DB_SPEC,
                info.db_mode,
                tests_last_version_db::MINER_DB_V0_3_0,
            )),
            ..Default::default()
        },
    }
}

fn test_step_start() {
    let _ = tracing_log_try_init();
    info!("Test Step start");
}

async fn test_step_complete(network: Network) {
    network.close_raft_loops_and_drop().await;
    info!("Test Step complete")
}

fn create_old_db(spec: &SimpleDbSpec, db_mode: DbMode, entries: &[DbEntryType]) -> SimpleDb {
    let mut db = new_db(db_mode, spec, None);
    db.import_items(entries.iter().copied()).unwrap();
    db
}

fn open_as_old_node_db(
    info: &NetworkNodeInfo,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams, SimpleDbError> {
    let version = old::constants::NETWORK_VERSION_SERIALIZED;
    let specs = match info.node_type {
        NodeType::Compute => Specs::Db(old::compute::DB_SPEC, old::compute_raft::DB_SPEC),
        NodeType::Storage => Specs::Db(old::storage::DB_SPEC, old::storage_raft::DB_SPEC),
        NodeType::User => Specs::Wallet(old::wallet::DB_SPEC),
        NodeType::Miner => Specs::Wallet(old::wallet::DB_SPEC),
    };
    open_as_version_node_db(info, &specs, version, old_dbs)
}

fn open_as_new_node_db(
    info: &NetworkNodeInfo,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams, SimpleDbError> {
    let version = Some(NETWORK_VERSION_SERIALIZED);
    let specs = match info.node_type {
        NodeType::Compute => Specs::Db(compute::DB_SPEC, compute_raft::DB_SPEC),
        NodeType::Storage => Specs::Db(storage::DB_SPEC, storage_raft::DB_SPEC),
        NodeType::User => Specs::Wallet(wallet::DB_SPEC),
        NodeType::Miner => Specs::Wallet(wallet::DB_SPEC),
    };
    open_as_version_node_db(info, &specs, version, old_dbs)
}

fn open_as_version_node_db(
    info: &NetworkNodeInfo,
    specs: &Specs,
    version: Option<&[u8]>,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams, SimpleDbError> {
    match specs {
        Specs::Db(spec, raft_spec) => {
            let db = new_db_with_version(info.db_mode, spec, version, old_dbs.db)?;
            let raft_db = new_db_with_version(info.db_mode, raft_spec, version, old_dbs.raft_db)?;
            Ok(ExtraNodeParams {
                db: Some(db),
                raft_db: Some(raft_db),
                ..Default::default()
            })
        }
        Specs::Wallet(spec) => {
            let wallet_db = new_db_with_version(info.db_mode, spec, version, old_dbs.wallet_db)?;
            Ok(ExtraNodeParams {
                wallet_db: Some(wallet_db),
                ..Default::default()
            })
        }
    }
}

pub fn get_upgrade_node_db(
    info: &NetworkNodeInfo,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams, UpgradeError> {
    match info.node_type {
        NodeType::Compute => get_upgrade_compute_db(info.db_mode, old_dbs),
        NodeType::Storage => get_upgrade_storage_db(info.db_mode, old_dbs),
        NodeType::User => get_upgrade_wallet_db(info.db_mode, old_dbs),
        NodeType::Miner => get_upgrade_wallet_db(info.db_mode, old_dbs),
    }
}

pub fn upgrade_node_db(
    info: &NetworkNodeInfo,
    dbs: ExtraNodeParams,
    upgrade_cfg: &UpgradeCfg,
) -> Result<(ExtraNodeParams, UpgradeStatus), UpgradeError> {
    match info.node_type {
        NodeType::Compute => upgrade_compute_db(dbs, upgrade_cfg),
        NodeType::Storage => upgrade_storage_db(dbs, upgrade_cfg),
        NodeType::User => upgrade_wallet_db(dbs, upgrade_cfg),
        NodeType::Miner => upgrade_wallet_db(dbs, upgrade_cfg),
    }
}

fn complete_network_config(initial_port: u16) -> NetworkConfig {
    NetworkConfig {
        initial_port,
        compute_raft: true,
        storage_raft: true,
        in_memory_db: true,
        compute_partition_full_size: 1,
        compute_minimum_miner_pool_len: 1,
        nodes: vec![(NodeType::User, vec!["user1".to_string()])]
            .into_iter()
            .collect(),
        compute_seed_utxo: Default::default(),
        compute_genesis_tx_in: None,
        user_wallet_seeds: Default::default(),
        compute_to_miner_mapping: Default::default(),
        test_duration_divider: 1,
        passphrase: Some(WALLET_PASSWORD.to_owned()),
        user_auto_donate: 0,
        user_test_auto_gen_setup: Default::default(),
        tls_config: get_test_tls_spec(),
        routes_pow: Default::default(),
    }
    .with_groups(1, 1)
}

fn real_db(mut config: NetworkConfig) -> NetworkConfig {
    config.in_memory_db = false;
    config
}

fn get_static_column(spec: SimpleDbSpec, name: &str) -> &'static str {
    [DB_COL_DEFAULT]
        .iter()
        .chain(spec.columns.iter())
        .find(|sn| **sn == name)
        .unwrap()
}

fn cfg_upgrade() -> UpgradeCfg {
    UpgradeCfg {
        raft_len: 1,
        compute_partition_full_size: 1,
        compute_unicorn_fixed_param: get_test_common_unicorn(),
        passphrase: WALLET_PASSWORD.to_owned(),
    }
}

fn get_expected_last_block_stored() -> BlockStoredInfo {
    use naom::primitives::transaction::{Transaction, TxIn, TxOut};
    use naom::script::{lang::Script, StackEntry};

    BlockStoredInfo {
        block_hash: LAST_BLOCK_BLOCK_HASH.to_owned(),
        block_num: LAST_BLOCK_STORED_NUM,
        nonce: Vec::new(),
        mining_transactions: std::iter::once((
            "g801b501129674d9a0b389617665a95a".to_owned(),
            Transaction {
                inputs: vec![TxIn {
                    previous_out: None,
                    script_signature: Script {
                        stack: vec![StackEntry::Num(LAST_BLOCK_STORED_NUM as usize)],
                    },
                }],
                outputs: vec![TxOut {
                    value: Asset::Token(TokenAmount(7510183)),
                    locktime: 0,
                    drs_block_hash: None,
                    script_public_key: Some(
                        "bdba6089d59492c9f89d9e3244fd6c38789884fde14e6192d87899a326a7415e"
                            .to_owned(),
                    ),
                }],
                version: old::constants::NETWORK_VERSION as usize,
                druid_info: None,
            },
        ))
        .collect(),
        shutdown: false,
    }
}

fn get_test_auto_gen_setup(count_override: Option<usize>) -> UserAutoGenTxSetup {
    let user1_tx = vec![
        WalletTxSpec {
            out_point:  "0-000000".to_owned(),
            secret_key: "e2fa624994ec5c6f46e9a991ed8e8791c4d2ce2d7ed05a827bd45416e5a19555f4f0c1a951959e88fe343de5a2ebe7efbcb15422090b3549577f424db6851ca5".to_owned(),
            public_key: "f4f0c1a951959e88fe343de5a2ebe7efbcb15422090b3549577f424db6851ca5".to_owned(),
            amount: 2,
            address_version: None,
        },
        WalletTxSpec {
            out_point: "0-000001".to_owned(),
            secret_key: "09784182e825fbd7e53333aa6b5f1d55bc19a992d5cf71253212264825bc89c8a80fc230590e38bd648dc6bc4b6019d39e841f78657ad5138f351a70b6165c43".to_owned(),
            public_key: "a80fc230590e38bd648dc6bc4b6019d39e841f78657ad5138f351a70b6165c43".to_owned(),
            amount: 5,
            address_version: None,
        }
    ];

    UserAutoGenTxSetup {
        user_initial_transactions: vec![user1_tx],
        user_setup_tx_chunk_size: Some(5),
        user_setup_tx_in_per_tx: Some(3),
        user_setup_tx_max_count: count_override.unwrap_or(100000),
    }
}

fn in_memory(dbs: ExtraNodeParams) -> ExtraNodeParams {
    ExtraNodeParams {
        db: dbs.db.and_then(|v| v.in_memory()),
        raft_db: dbs.raft_db.and_then(|v| v.in_memory()),
        wallet_db: dbs.wallet_db.and_then(|v| v.in_memory()),
        shared_wallet_db: None,
    }
}

fn filter_dbs(dbs: ExtraNodeParams, filter_dbs: &ExtraNodeParamsFilter) -> ExtraNodeParams {
    ExtraNodeParams {
        db: dbs.db.filter(|_| filter_dbs.db),
        raft_db: dbs.raft_db.filter(|_| filter_dbs.raft_db),
        wallet_db: dbs.wallet_db.filter(|_| filter_dbs.wallet_db),
        shared_wallet_db: None,
    }
}

fn cloned_in_memory(dbs: &ExtraNodeParams) -> ExtraNodeParams {
    ExtraNodeParams {
        db: dbs.db.as_ref().and_then(|v| v.cloned_in_memory()),
        raft_db: dbs.raft_db.as_ref().and_then(|v| v.cloned_in_memory()),
        wallet_db: dbs.wallet_db.as_ref().and_then(|v| v.cloned_in_memory()),
        shared_wallet_db: None,
    }
}

fn test_timeout() -> impl Future<Output = &'static str> + Unpin {
    Box::pin(async move {
        tokio::time::sleep(TIMEOUT_TEST_WAIT_DURATION).await;
        "Test timeout elapsed"
    })
}

// Make a payment transaction from inputs containing old address structure
async fn user_make_payment_transaction(
    network: &mut Network,
    user: &str,
    compute: &str,
    amount: TokenAmount,
    to_addr: String,
) {
    let mut user = network.user(user).unwrap().lock().await;
    let compute_addr = network.get_address(compute).await.unwrap();
    user.make_payment_transactions(None, to_addr, amount).await;
    user.send_next_payment_to_destinations(compute_addr)
        .await
        .unwrap();
}

async fn raft_node_handle_event(network: &mut Network, node: &str, reason_val: &str) {
    if let Some(n) = network.compute(node) {
        let mut n = n.lock().await;
        match n.handle_next_event(&mut test_timeout()).await {
            Some(Ok(Response { success, reason })) if success && reason == reason_val => {}
            other => panic!("Unexpected result: {:?} (expected:{})", other, reason_val),
        }
    } else if let Some(n) = network.storage(node) {
        let mut n = n.lock().await;
        match n.handle_next_event(&mut test_timeout()).await {
            Some(Ok(Response { success, reason })) if success && reason == reason_val => {}
            other => panic!("Unexpected result: {:?} (expected:{})", other, reason_val),
        }
    }
}

async fn node_send_coordinated_shutdown(network: &mut Network, node: &str, at_block: u64) {
    use crate::utils::LocalEvent;
    let mut event_tx = network.get_local_event_tx(node).await.unwrap();
    let event = LocalEvent::CoordinatedShutdown(at_block);
    event_tx.send(event, "test shutdown").await.unwrap();
}

fn test_hash(t: BlockchainItem) -> (u32, BlockchainItemMeta, u64, u64) {
    use std::hash::{Hash, Hasher};
    let data_hash = {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        t.data.hash(&mut s);
        s.finish()
    };
    let json_hash = {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        t.data_json.hash(&mut s);
        s.finish()
    };

    (t.version, t.item_meta, data_hash, json_hash)
}

fn index_meta(v: &str) -> BlockchainItemMeta {
    let mut it = v.split('_');
    match (it.next(), it.next(), it.next()) {
        (Some("nIndexedBlockHashKey"), Some(block_num), None) => {
            let block_num = u64::from_str_radix(block_num, 16).unwrap();
            BlockchainItemMeta::Block {
                block_num,
                tx_len: STORAGE_DB_V0_3_0_BLOCK_LEN[block_num as usize],
            }
        }
        (Some("nIndexedTxHashKey"), Some(block_num), Some(tx_num)) => BlockchainItemMeta::Tx {
            block_num: u64::from_str_radix(block_num, 16).unwrap(),
            tx_num: u32::from_str_radix(tx_num, 16).unwrap(),
        },
        _ => panic!("index_meta not found {}", v),
    }
}
