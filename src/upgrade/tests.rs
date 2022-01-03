use super::tests_last_version_db::{self, DbEntryType};
use super::tests_last_version_db_no_block;
use super::{
    dump_db, get_upgrade_compute_db, get_upgrade_storage_db, get_upgrade_wallet_db, old,
    upgrade_compute_db, upgrade_storage_db, upgrade_wallet_db, DbCfg, UpgradeCfg, UpgradeError,
    UpgradeStatus,
};
use crate::configurations::{DbMode, ExtraNodeParams, UserAutoGenTxSetup, WalletTxSpec};
use crate::constants::{DB_VERSION_KEY, LAST_BLOCK_HASH_KEY, NETWORK_VERSION_SERIALIZED};
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
const LAST_BLOCK_STORED_NUM: u64 = 2;
const LAST_BLOCK_BLOCK_HASH: &str =
    "7825220b591e99ad654acd0268f9ec0a5e08d3f46929f93cd4195ce943bb9f5c";
const LAST_BLOCK_STORAGE_DB_V0_2_0_INDEX: usize = 5;
const STORAGE_DB_V0_2_0_INDEXES: &[&str] = &[
    "nIndexedTxHashKey_0000000000000000_00000000",
    "nIndexedTxHashKey_0000000000000000_00000001",
    "nIndexedTxHashKey_0000000000000000_00000002",
    "nIndexedTxHashKey_0000000000000000_00000003",
    "nIndexedBlockHashKey_0000000000000001",
    "nIndexedBlockHashKey_0000000000000002",
    "nIndexedBlockHashKey_0000000000000000",
    "nIndexedTxHashKey_0000000000000001_00000000",
    "nIndexedTxHashKey_0000000000000002_00000003",
    "nIndexedTxHashKey_0000000000000002_00000000",
    "nIndexedTxHashKey_0000000000000001_00000001",
    "nIndexedTxHashKey_0000000000000000_00000004",
    "nIndexedTxHashKey_0000000000000001_00000002",
    "nIndexedTxHashKey_0000000000000002_00000001",
    "nIndexedTxHashKey_0000000000000002_00000002",
];
const STORAGE_DB_V0_2_0_BLOCK_LEN: &[u32] = &[5, 3, 4];
const TIMEOUT_TEST_WAIT_DURATION: Duration = Duration::from_millis(5000);

const STORAGE_DB_V0_2_0_JSON: &[&str] = &[
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Bytes\":\"+ (39) No person shall be seized or imprisoned, or stripped of their rights or possessions, or outlawed or exiled, or deprived of their standing in any way, nor will we proceed with force against them, or send others to do so, except by the lawful judgment of their equals or by the law of the land.\"}]}}],\"outputs\":[{\"value\":{\"Token\":2},\"amount\":2,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"be570a79d3066e78714600f5eb0e9b91\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"1e47c0a4a718ad926d8d4cf0c2070344\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"ef8cee427395f08788b7b7ffb94326ea\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"8767ae43bc20271fe841ccd4bce36d5d\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Bytes\":\"+ (39) No person shall be seized or imprisoned, or stripped of their rights or possessions, or outlawed or exiled, or deprived of their standing in any way, nor will we proceed with force against them, or send others to do so, except by the lawful judgment of their equals or by the law of the land.\"}]}}],\"outputs\":[{\"value\":{\"Token\":5},\"amount\":5,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Bytes\":\"+ (39) No person shall be seized or imprisoned, or stripped of their rights or possessions, or outlawed or exiled, or deprived of their standing in any way, nor will we proceed with force against them, or send others to do so, except by the lawful judgment of their equals or by the law of the land.\"}]}}],\"outputs\":[{\"value\":{\"Token\":123},\"amount\":123,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"e3f86d92484539e695581ee111580eb3\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Bytes\":\"+ (39) No person shall be seized or imprisoned, or stripped of their rights or possessions, or outlawed or exiled, or deprived of their standing in any way, nor will we proceed with force against them, or send others to do so, except by the lawful judgment of their equals or by the law of the land.\"}]}}],\"outputs\":[{\"value\":{\"Token\":1234},\"amount\":1234,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"b78d8dae72a6b79401cebaa64a8063db\"},{\"value\":{\"Token\":1235},\"amount\":1235,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"5a4f627b0be3245edc7601bf3236bc77\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"block\":{\"header\":{\"version\":0,\"bits\":0,\"nonce\":[],\"b_num\":1,\"seed_value\":[],\"previous_hash\":\"abd4012af0eb398f7fed06cdc633c506d374bb8e38174035c0fb9910d3d7a7f6\",\"merkle_root_hash\":\"225cf9332e9e3518ea7111c31fcfab29b5ba4bb66e8c6dcdf0b2c99b32ba893d\"},\"transactions\":[\"g15d207734998a4c4343df9dd0195dbf\",\"g3beca40882c0403330fcced1c25786c\"]},\"mining_tx_hash_and_nonces\":{\"1\":[\"ga6d71de293071a6b8105dc8977952bc\",[123,185,41,76,125,197,57,74,136,173,162,115,51,48,52,85]]}}",
    "{\"block\":{\"header\":{\"version\":0,\"bits\":0,\"nonce\":[],\"b_num\":2,\"seed_value\":[],\"previous_hash\":\"04d6006a3923d06c00be1c9f26e38142e1defbe0d5a57ea60d94255c20a59a04\",\"merkle_root_hash\":\"24c87c26cf5233f59ffe9b3f8f19cd7e1cdcf871dafb2e3e800e15cf155da944\"},\"transactions\":[\"g2f6dbde7bb8fad8bc8f2d60ed152fb7\",\"gdfcdf57e87352ab2fe3e9c356e1e718\",\"gffb9abab147d717bd9cb6da3987db62\"]},\"mining_tx_hash_and_nonces\":{\"1\":[\"g27fac41a2d62a56c8962e3d360838c8\",[105,193,78,76,22,66,126,68,153,72,115,5,186,3,121,186]]}}",
    "{\"block\":{\"header\":{\"version\":0,\"bits\":0,\"nonce\":[],\"b_num\":0,\"seed_value\":[],\"previous_hash\":null,\"merkle_root_hash\":\"\"},\"transactions\":[\"000000\",\"000001\",\"000010\",\"000011\"]},\"mining_tx_hash_and_nonces\":{\"1\":[\"g50675ae09b507f5b02bd05f5ba49f4f\",[188,60,127,73,12,31,64,140,172,68,45,64,102,152,100,140]]}}",
    "{\"inputs\":[{\"previous_out\":{\"t_hash\":\"000001\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"060000000000000030303030303100000000\"},{\"Signature\":[15,237,67,91,55,60,111,53,186,10,225,72,215,108,191,108,95,130,87,205,12,236,67,124,29,118,171,215,4,218,220,52,51,41,239,216,154,126,203,240,50,148,246,18,6,219,74,147,223,193,23,59,41,11,45,228,38,185,83,153,25,20,140,6]},{\"PubKey\":[168,15,194,48,89,14,56,189,100,141,198,188,75,96,25,211,158,132,31,120,101,122,213,19,143,53,26,112,182,22,92,67]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"fa2165facd049a33f1134c6043012ffb\"},{\"Op\":61},{\"Op\":95}]}}],\"outputs\":[{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Num\":2}]}}],\"outputs\":[{\"value\":{\"Token\":7510184},\"amount\":7510184,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"79609a5b997a265ab3f370c4abef00ad\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":{\"t_hash\":\"g15d207734998a4c4343df9dd0195dbf\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673135643230373733343939386134633433343364663964643031393564626600000000\"},{\"Signature\":[6,96,188,24,55,108,7,52,186,146,6,89,191,24,147,151,43,71,140,191,92,125,7,193,60,61,200,178,8,161,146,195,141,113,107,236,16,149,179,34,238,234,7,34,246,89,243,198,57,236,246,141,237,153,208,78,53,0,118,228,91,223,177,2]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}},{\"previous_out\":{\"t_hash\":\"g15d207734998a4c4343df9dd0195dbf\",\"n\":1},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673135643230373733343939386134633433343364663964643031393564626601000000\"},{\"Signature\":[109,88,99,175,220,193,176,165,242,203,174,230,196,85,191,198,116,31,116,87,114,139,19,91,80,131,243,110,162,110,135,145,16,83,6,19,75,10,73,32,240,221,152,66,225,239,1,51,228,51,56,169,65,117,156,253,211,40,61,143,53,50,68,9]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}},{\"previous_out\":{\"t_hash\":\"g15d207734998a4c4343df9dd0195dbf\",\"n\":2},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673135643230373733343939386134633433343364663964643031393564626602000000\"},{\"Signature\":[89,191,216,65,117,175,209,105,189,170,246,174,140,61,199,115,137,144,198,84,233,78,44,29,28,107,230,99,10,170,46,49,21,206,110,73,22,246,14,85,60,50,122,125,32,228,89,8,117,176,1,214,59,234,68,83,49,148,34,136,247,221,117,13]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}}],\"outputs\":[{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":{\"t_hash\":\"000000\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"060000000000000030303030303000000000\"},{\"Signature\":[51,224,185,21,223,149,19,164,216,28,169,33,79,61,20,12,74,28,61,173,24,154,243,35,237,190,145,8,115,111,103,97,69,148,32,191,237,141,206,62,193,21,6,218,63,94,90,28,177,32,43,244,226,231,132,169,55,4,37,94,236,73,134,0]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}}],\"outputs\":[{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Num\":0}]}}],\"outputs\":[{\"value\":{\"Token\":7510185},\"amount\":7510185,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"d0031ff80365354c3a3162a407a9fe92\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":null,\"script_signature\":{\"stack\":[{\"Num\":1}]}}],\"outputs\":[{\"value\":{\"Token\":7510185},\"amount\":7510185,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"b2791ed55fb72717d96e1197eee1ca7b\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":{\"t_hash\":\"g15d207734998a4c4343df9dd0195dbf\",\"n\":3},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673135643230373733343939386134633433343364663964643031393564626603000000\"},{\"Signature\":[130,136,85,195,70,24,196,166,116,166,239,78,228,33,199,157,153,199,195,23,64,37,172,62,90,156,33,173,174,133,219,213,180,26,95,166,45,109,168,2,132,208,65,162,167,22,223,164,180,55,75,197,122,121,154,130,148,65,179,155,241,132,204,14]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}},{\"previous_out\":{\"t_hash\":\"g15d207734998a4c4343df9dd0195dbf\",\"n\":4},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673135643230373733343939386134633433343364663964643031393564626604000000\"},{\"Signature\":[220,49,169,206,205,116,247,147,201,167,122,222,133,184,55,45,234,225,178,98,99,195,43,40,111,45,130,5,123,229,22,223,74,164,87,57,116,39,197,116,110,121,192,87,130,67,36,58,142,217,192,68,238,127,194,245,212,217,188,126,70,83,177,11]},{\"PubKey\":[244,240,193,169,81,149,158,136,254,52,61,229,162,235,231,239,188,177,84,34,9,11,53,73,87,127,66,77,182,133,28,165]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"Op\":61},{\"Op\":95}]}}],\"outputs\":[{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"fa2165facd049a33f1134c6043012ffb\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}",
    "{\"inputs\":[{\"previous_out\":{\"t_hash\":\"g3beca40882c0403330fcced1c25786c\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673362656361343038383263303430333333306663636564316332353738366300000000\"},{\"Signature\":[9,204,102,199,118,96,243,170,213,121,102,32,252,48,172,54,59,193,107,29,176,151,142,81,168,49,112,146,94,193,86,184,44,77,195,16,20,171,224,237,119,230,2,212,250,111,241,44,221,188,50,87,56,90,240,167,187,168,13,133,104,180,32,5]},{\"PubKey\":[168,15,194,48,89,14,56,189,100,141,198,188,75,96,25,211,158,132,31,120,101,122,213,19,143,53,26,112,182,22,92,67]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"fa2165facd049a33f1134c6043012ffb\"},{\"Op\":61},{\"Op\":95}]}},{\"previous_out\":{\"t_hash\":\"g3beca40882c0403330fcced1c25786c\",\"n\":1},\"script_signature\":{\"stack\":[{\"Bytes\":\"2000000000000000673362656361343038383263303430333333306663636564316332353738366301000000\"},{\"Signature\":[19,242,222,156,30,233,59,112,39,88,61,225,188,230,233,152,174,162,32,138,130,212,162,39,158,127,100,110,193,94,217,134,30,242,14,64,211,17,238,112,75,109,204,152,173,187,126,178,121,44,18,77,136,212,20,157,196,7,163,176,36,145,140,3]},{\"PubKey\":[168,15,194,48,89,14,56,189,100,141,198,188,75,96,25,211,158,132,31,120,101,122,213,19,143,53,26,112,182,22,92,67]},{\"Op\":43},{\"Op\":93},{\"PubKeyHash\":\"fa2165facd049a33f1134c6043012ffb\"},{\"Op\":61},{\"Op\":95}]}}],\"outputs\":[{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"},{\"value\":{\"Token\":1},\"amount\":1,\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"7027eda6d9ef25d7e1c4f833475e544f\"}],\"version\":0,\"druid\":null,\"druid_participants\":null,\"expect_value\":null,\"expect_value_amount\":null}"
];

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
async fn upgrade_compute_no_block_in_memory() {
    let config = complete_network_config(20015);
    let upgrade_cfg = cfg_upgrade_no_block();
    upgrade_common(config, "compute1", upgrade_cfg).await;
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
    let db = create_old_node_db(&n_info, upgrade_cfg.db_cfg);

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
            let (expected_mining_b_num, expected_b_num) =
                if upgrade_cfg.db_cfg == DbCfg::ComputeBlockToMine {
                    let expected = Some(LAST_BLOCK_STORED_NUM + 1);
                    (expected, expected)
                } else {
                    (None, Some(LAST_BLOCK_STORED_NUM))
                };

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
                for (idx, (_, k, v)) in tests_last_version_db::STORAGE_DB_V0_2_0.iter().enumerate()
                {
                    let idx_k = STORAGE_DB_V0_2_0_INDEXES[idx];
                    let v_json = STORAGE_DB_V0_2_0_JSON[idx];
                    println!("{}", v_json);
                    expected.push(Some(test_hash(BlockchainItem {
                        version: 0,
                        item_meta: index_meta(idx_k),
                        key: k.to_vec(),
                        data: v.to_vec(),
                        data_json: v_json.as_bytes().to_vec(),
                    })));
                    actual.push(storage.get_stored_value(k).map(test_hash));
                    actual_indexed.push(storage.get_stored_value(idx_k).map(test_hash));
                }
                assert_eq!(actual, expected);
                assert_eq!(actual_indexed, expected);
                assert_eq!(storage.get_stored_values_count(), expected.len());
                assert_eq!(
                    storage.get_stored_value(LAST_BLOCK_HASH_KEY).map(test_hash),
                    expected[LAST_BLOCK_STORAGE_DB_V0_2_0_INDEX]
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
                .fetch_inputs_for_payment(Asset::token_u64(15020370))
                .await
                .unwrap();
            assert_eq!(
                (payment.0.len(), payment.1, payment.2.len()),
                (2, Asset::token_u64(15020370), 2)
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
async fn open_upgrade_started_compute_no_block_in_memory() {
    let config = complete_network_config(20115);
    let upgrade_cfg = cfg_upgrade_no_block();
    open_upgrade_started_compute_common(config, "compute1", upgrade_cfg).await;
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
    upgrade_cfg: UpgradeCfg,
) {
    test_step_start();

    //
    // Arrange
    //
    let mut network = Network::create_stopped_from_config(&config);
    let n_info = network.get_node_info(name).unwrap().clone();
    let db = create_old_node_db(&n_info, upgrade_cfg.db_cfg);

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
async fn upgrade_restart_network_compute_no_block_in_memory() {
    let config = complete_network_config(20215);
    let upgrade_cfg = cfg_upgrade_no_block();
    upgrade_restart_network_common(config, upgrade_cfg, Default::default(), false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_compute_no_block_raft_2_in_memory() {
    // Create 2 identical copy of the database in memory for each node in raft grup.
    // Upgrade applying the configuration data and run.
    let raft_len = 2;

    let config = complete_network_config(20220).with_groups(raft_len, raft_len);
    let mut upgrade_cfg = cfg_upgrade_no_block();
    upgrade_cfg.raft_len = raft_len;
    upgrade_restart_network_common(config, upgrade_cfg, Default::default(), false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_compute_no_block_raft_3_raft_db_only_in_memory() {
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
    let mut upgrade_cfg = cfg_upgrade_no_block();
    upgrade_cfg.raft_len = raft_len;
    upgrade_restart_network_common(config, upgrade_cfg, params_filters, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn upgrade_restart_network_compute_no_block_raft_3_pre_launch_only_in_memory() {
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
    let mut upgrade_cfg = cfg_upgrade_no_block();
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
        let db = create_old_node_db(n_info, upgrade_cfg.db_cfg);
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

            let (db, _, _, _) = storage.api_inputs();
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
        let expected_count =
            tests_last_version_db::STORAGE_DB_V0_2_0.len() + extra_blocks * (1 + 1);
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
        let db = create_old_node_db(&node_info, DbCfg::ComputeBlockToMine);
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
        "payment_address".to_owned(),
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

fn create_old_node_db(info: &NetworkNodeInfo, db_cfg: DbCfg) -> ExtraNodeParams {
    match info.node_type {
        NodeType::Compute => ExtraNodeParams {
            db: Some(create_old_db(
                &old::compute::DB_SPEC,
                info.db_mode,
                if db_cfg == DbCfg::ComputeBlockToMine {
                    tests_last_version_db::COMPUTE_DB_V0_2_0
                } else {
                    tests_last_version_db_no_block::COMPUTE_DB_V0_2_0
                },
            )),
            raft_db: Some(create_old_db(
                &old::compute_raft::DB_SPEC,
                info.db_mode,
                if db_cfg == DbCfg::ComputeBlockToMine {
                    tests_last_version_db::COMPUTE_RAFT_DB_V0_2_0
                } else {
                    tests_last_version_db_no_block::COMPUTE_RAFT_DB_V0_2_0
                },
            )),
            ..Default::default()
        },
        NodeType::Storage => ExtraNodeParams {
            db: Some(create_old_db(
                &old::storage::DB_SPEC,
                info.db_mode,
                tests_last_version_db::STORAGE_DB_V0_2_0,
            )),
            raft_db: Some(create_old_db(
                &old::storage_raft::DB_SPEC,
                info.db_mode,
                tests_last_version_db::STORAGE_RAFT_DB_V0_2_0,
            )),
            ..Default::default()
        },
        NodeType::User => ExtraNodeParams {
            wallet_db: Some(create_old_db(
                &old::wallet::DB_SPEC,
                info.db_mode,
                tests_last_version_db::USER_DB_V0_2_0,
            )),
            ..Default::default()
        },
        NodeType::Miner => ExtraNodeParams {
            wallet_db: Some(create_old_db(
                &old::wallet::DB_SPEC,
                info.db_mode,
                tests_last_version_db::MINER_DB_V0_2_0,
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

    let mut batch = db.batch_writer();
    batch.delete_cf(DB_COL_DEFAULT, DB_VERSION_KEY);
    for (_column, key, value) in entries {
        batch.put_cf(DB_COL_DEFAULT, key, value);
    }
    let batch = batch.done();
    db.write(batch).unwrap();

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
        db_cfg: DbCfg::ComputeBlockToMine,
    }
}

fn cfg_upgrade_no_block() -> UpgradeCfg {
    UpgradeCfg {
        raft_len: 1,
        compute_partition_full_size: 1,
        compute_unicorn_fixed_param: get_test_common_unicorn(),
        passphrase: WALLET_PASSWORD.to_owned(),
        db_cfg: DbCfg::ComputeBlockInStorage,
    }
}

fn get_expected_last_block_stored() -> BlockStoredInfo {
    use naom::primitives::transaction::{Transaction, TxIn, TxOut};
    use naom::script::{lang::Script, StackEntry};

    BlockStoredInfo {
        block_hash: LAST_BLOCK_BLOCK_HASH.to_owned(),
        block_num: LAST_BLOCK_STORED_NUM,
        nonce: Vec::new(),
        merkle_hash: "24c87c26cf5233f59ffe9b3f8f19cd7e1cdcf871dafb2e3e800e15cf155da944".to_owned(),
        mining_transactions: std::iter::once((
            "g27fac41a2d62a56c8962e3d360838c8".to_owned(),
            Transaction {
                inputs: vec![TxIn {
                    previous_out: None,
                    script_signature: Script {
                        stack: vec![StackEntry::Num(LAST_BLOCK_STORED_NUM as usize)],
                    },
                }],
                outputs: vec![TxOut {
                    value: Asset::Token(TokenAmount(7510184)),
                    locktime: 0,
                    drs_block_hash: None,
                    drs_tx_hash: None,
                    script_public_key: Some("79609a5b997a265ab3f370c4abef00ad".to_owned()),
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
            amount: 2
        },
        WalletTxSpec {
            out_point: "0-000001".to_owned(),
            secret_key: "09784182e825fbd7e53333aa6b5f1d55bc19a992d5cf71253212264825bc89c8a80fc230590e38bd648dc6bc4b6019d39e841f78657ad5138f351a70b6165c43".to_owned(),
            public_key: "a80fc230590e38bd648dc6bc4b6019d39e841f78657ad5138f351a70b6165c43".to_owned(),
            amount: 5
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
                tx_len: STORAGE_DB_V0_2_0_BLOCK_LEN[block_num as usize],
            }
        }
        (Some("nIndexedTxHashKey"), Some(block_num), Some(tx_num)) => BlockchainItemMeta::Tx {
            block_num: u64::from_str_radix(block_num, 16).unwrap(),
            tx_num: u32::from_str_radix(tx_num, 16).unwrap(),
        },
        _ => panic!("index_meta not found {}", v),
    }
}
