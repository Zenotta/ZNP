use crate::api::handlers::{
    AddressConstructData, Addresses, ChangePassphraseData, CreateReceiptAssetData,
    CreateReceiptAssetDataUser, CreateTransaction, CreateTxIn, CreateTxInScript, DbgPaths,
    EncapsulatedPayment, FetchPendingData, PublicKeyAddresses,
};
use crate::api::routes;
use crate::api::utils::{
    auth_request, create_new_cache, handle_rejection, ANY_API_KEY, CACHE_LIVE_TIME,
};
use crate::comms_handler::{Event, Node, TcpTlsConfig};
use crate::configurations::DbMode;
use crate::constants::FUND_KEY;
use crate::db_utils::{new_db, SimpleDb};
use crate::interfaces::{
    BlockchainItemMeta, ComputeApi, ComputeApiRequest, DruidDroplet, DruidPool, NodeType, Response,
    StoredSerializingBlock, UserApiRequest, UserRequest, UtxoFetchType,
};
use crate::storage::{put_named_last_block_to_block_chain, put_to_block_chain, DB_SPEC};
use crate::test_utils::{generate_rb_transactions, RbReceiverData, RbSenderData};
use crate::threaded_call::ThreadedCallChannel;
use crate::tracked_utxo::TrackedUtxoSet;
use crate::utils::{
    apply_mining_tx, construct_valid_block_pow_hash, decode_secret_key, generate_pow_for_block,
    to_api_keys, to_route_pow_infos, tracing_log_try_init, validate_pow_block,
};
use crate::wallet::{WalletDb, WalletDbError};
use crate::ComputeRequest;
use bincode::serialize;
use naom::constants::{NETWORK_VERSION_TEMP, NETWORK_VERSION_V0};
use naom::crypto::sign_ed25519::{self as sign};
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::block::Block;
use naom::primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use naom::script::lang::Script;
use naom::utils::transaction_utils::{
    construct_tx_hash, construct_tx_in_signable_asset_hash, construct_tx_in_signable_hash,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use warp::http::{HeaderMap, HeaderValue, StatusCode};
use warp::Filter;

const COMMON_ROUTE_POW_DIFFICULTY: usize = 2;
const COMMON_REQ_ID: &str = "2ae7bc9cba924e3cb73c0249893078d7";
const COMMON_VALID_API_KEY: &str = "valid_api_key";
const COMMON_VALID_POW_NONCE: &str = "81234";
const COMMON_PUB_KEY: &str = "5371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c";
const COMMON_SEC_KEY: &str = "3053020101300506032b6570042204200186bc08f16428d2059227082b93e439ff50f8c162f24b9594b132f2cc15fca4a1230321005371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c";
const COMMON_PUB_ADDR: &str = "13bd3351b78beb2d0dadf2058dcc926c";

const COMMON_ADDR_STORE: (&str, [u8; 152]) = (
    "4348536e3d5a13e347262b5023963edf",
    [
        195, 253, 191, 157, 40, 253, 233, 186, 96, 35, 27, 83, 83, 224, 191, 126, 133, 101, 235,
        168, 233, 122, 174, 109, 18, 247, 175, 139, 253, 55, 164, 187, 238, 175, 251, 110, 53, 47,
        158, 241, 103, 144, 49, 65, 247, 147, 145, 140, 12, 129, 123, 19, 187, 121, 31, 163, 16,
        231, 248, 38, 243, 200, 34, 91, 4, 241, 40, 42, 97, 236, 37, 180, 26, 16, 34, 171, 12, 92,
        4, 8, 53, 193, 181, 209, 97, 76, 164, 76, 0, 122, 44, 120, 212, 27, 145, 224, 20, 207, 215,
        134, 23, 178, 170, 157, 218, 55, 14, 64, 185, 128, 63, 131, 194, 24, 6, 228, 34, 50, 252,
        118, 94, 153, 105, 236, 92, 122, 169, 219, 119, 9, 250, 255, 20, 40, 148, 74, 182, 73, 180,
        83, 10, 240, 193, 201, 45, 5, 205, 34, 188, 174, 229, 96,
    ],
);

const COMMON_ADDRS: &[&str] = &[
    "0008536e3d5a13e347262b5023963000",
    "1118536e3d5a13e347262b5023963111",
    "2228536e3d5a13e347262b5023963222",
];

const BLOCK_NONCE: &str = "780c05806a3b70b15c9673396171674f";

/*------- UTILS--------*/

#[derive(Default)]
struct ComputeTest {
    pub utxo_set: TrackedUtxoSet,
    pub druid_pool: DruidPool,
    pub threaded_calls: ThreadedCallChannel<dyn ComputeApi>,
}

impl ComputeTest {
    fn new(tx_vals: Vec<(String, Transaction)>) -> Self {
        let druid =
            if let Some(druid_info) = tx_vals.get(0).and_then(|(_, tx)| tx.druid_info.as_ref()) {
                druid_info.druid.clone()
            } else {
                "Druid1".to_owned()
            };
        let droplets = vec![(
            druid,
            DruidDroplet {
                participants: 2,
                txs: tx_vals.clone().into_iter().collect(),
            },
        )];

        Self {
            utxo_set: TrackedUtxoSet::new(
                tx_vals
                    .iter()
                    .map(|(_, tx)| {
                        (
                            tx.inputs[0].clone().previous_out.unwrap(),
                            tx.outputs[0].clone(),
                        )
                    })
                    .collect(),
            ),
            druid_pool: droplets.into_iter().collect(),
            ..Default::default()
        }
    }

    fn spawn(self) -> tokio::task::JoinHandle<Self> {
        tokio::spawn({
            let mut c = self;
            async move {
                let f = c.threaded_calls.rx.recv().await.unwrap();
                f(&mut c);
                c
            }
        })
    }
}

impl ComputeApi for ComputeTest {
    fn get_committed_utxo_tracked_set(&self) -> &TrackedUtxoSet {
        &self.utxo_set
    }
    fn get_pending_druid_pool(&self) -> &DruidPool {
        &self.druid_pool
    }

    fn receive_transactions(&mut self, _transactions: Vec<Transaction>) -> Response {
        let reason: &'static str = "";

        Response {
            success: true,
            reason,
        }
    }

    fn create_receipt_asset_tx(
        &mut self,
        _receipt_amount: u64,
        _script_public_key: String,
        _public_key: String,
        _signature: String,
    ) -> Option<Response> {
        let reason: &'static str = "";

        Some(Response {
            success: true,
            reason,
        })
    }
}

fn from_utf8(data: &[u8]) -> &str {
    std::str::from_utf8(data).unwrap()
}

/// Util function to create a stub DB containing a single block
async fn get_db_with_block() -> Arc<Mutex<SimpleDb>> {
    let db = get_db_with_block_no_mutex().await;
    Arc::new(Mutex::new(db))
}

async fn get_wallet_db(passphrase: &str) -> WalletDb {
    let simple_db = Some(get_db_with_block_no_mutex().await);
    let passphrase = Some(passphrase.to_owned());
    WalletDb::new(DbMode::InMemory, simple_db, passphrase)
}

async fn get_db_with_block_no_mutex() -> SimpleDb {
    let tx = Transaction::new();
    let tx_value = serialize(&tx).unwrap();
    let tx_json = serde_json::to_vec(&tx).unwrap();
    let tx_hash = construct_tx_hash(&tx);
    let nonce = hex::decode(BLOCK_NONCE).unwrap();

    let mut block = Block::new();
    block.transactions.push(tx_hash.clone());
    block.set_txs_merkle_root_and_hash().await;
    block.header = apply_mining_tx(block.header, nonce, "test".to_string());

    if !validate_pow_block(&block.header) {
        block.header = generate_pow_for_block(block.header);
        let new_nonce = hex::encode(&block.header.nonce_and_mining_tx_hash.0);
        panic!(
            "get_db_with_block_no_mutex: Out of date nonce: {} -> new({})",
            BLOCK_NONCE, new_nonce
        );
    }

    let block_to_input = StoredSerializingBlock { block };

    let mut db = new_db(DbMode::InMemory, &DB_SPEC, None);
    let mut batch = db.batch_writer();

    // Handle block insert
    let block_input = serialize(&block_to_input).unwrap();
    let block_json = serde_json::to_vec(&block_to_input).unwrap();
    let block_hash = construct_valid_block_pow_hash(&block_to_input.block).unwrap();

    {
        let block_num = 0;
        let tx_len = 1;
        let t = BlockchainItemMeta::Block { block_num, tx_len };
        let pointer = put_to_block_chain(&mut batch, &t, &block_hash, &block_input, &block_json);
        put_named_last_block_to_block_chain(&mut batch, &pointer);
    }
    // Handle tx insert
    {
        let t = BlockchainItemMeta::Tx {
            block_num: 0,
            tx_num: 1,
        };
        put_to_block_chain(&mut batch, &t, &tx_hash, &tx_value, &tx_json);
    }

    let batch = batch.done();
    db.write(batch).unwrap();
    db
}

// Util function to create a transaction.
// Returns the hash of the tx and the tx itself
fn get_transaction() -> (String, Transaction) {
    generate_transaction("tx_hash", COMMON_ADDR_STORE.0)
}

// Generates a transaction using the given `tx_hash` and `script_public_key`
fn generate_transaction(tx_hash: &str, script_public_key: &str) -> (String, Transaction) {
    let asset = TokenAmount(25_200);
    let mut tx = Transaction::new();

    let tx_in = TxIn::new_from_input(OutPoint::new(tx_hash.to_string(), 0), Script::new());
    let tx_out = TxOut::new_token_amount(script_public_key.to_string(), asset);
    tx.inputs = vec![tx_in];
    tx.outputs = vec![tx_out];

    let t_hash = construct_tx_hash(&tx);

    (t_hash, tx)
}

// Util function to create receipt base transactions.
// Returns the hash of the tx and the tx itself
fn get_rb_transactions() -> Vec<(String, Transaction)> {
    let rb_sender_data = RbSenderData {
        sender_pub_addr: "sender_address".to_owned(),
        sender_pub_key: COMMON_PUB_KEY.to_owned(),
        sender_sec_key: COMMON_SEC_KEY.to_owned(),
        sender_prev_out: OutPoint::new("000000".to_owned(), 0),
        sender_amount: TokenAmount(25_200),
        sender_half_druid: "full_".to_owned(),
    };

    let rb_receiver_data = RbReceiverData {
        receiver_pub_addr: "receiver_address".to_owned(),
        receiver_pub_key: COMMON_PUB_KEY.to_owned(),
        receiver_sec_key: COMMON_SEC_KEY.to_owned(),
        receiver_prev_out: OutPoint::new("000001".to_owned(), 0),
        receiver_half_druid: "druid".to_owned(),
    };

    generate_rb_transactions(rb_sender_data, rb_receiver_data)
}

fn success_json() -> (StatusCode, HeaderMap) {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    (StatusCode::from_u16(200).unwrap(), headers)
}

fn fail_json(code: StatusCode) -> (StatusCode, HeaderMap) {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    (code, headers)
}

pub async fn ok_reply() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&0))
}

fn user_api_request_as_frame(request: UserApiRequest) -> Option<Vec<u8>> {
    let sent_request = UserRequest::UserApi(request);
    Some(serialize(&sent_request).unwrap())
}

fn compute_api_request_as_frame(request: ComputeApiRequest) -> Option<Vec<u8>> {
    let sent_request = ComputeRequest::ComputeApi(request);
    Some(serialize(&sent_request).unwrap())
}

async fn next_event_frame(node: &mut Node) -> Option<Vec<u8>> {
    let evt = node.next_event().await;
    evt.map(|Event::NewFrame { peer: _, frame }| frame.to_vec())
}

async fn new_self_node(node_type: NodeType) -> (Node, SocketAddr) {
    new_self_node_with_port(node_type, 0).await
}

async fn new_self_node_with_port(node_type: NodeType, port: u16) -> (Node, SocketAddr) {
    let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let mut socket_address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
    bind_address.set_port(port);

    let tcp_tls_config = TcpTlsConfig::new_no_tls(bind_address);
    let self_node = Node::new(&tcp_tls_config, 20, node_type).await.unwrap();
    socket_address.set_port(self_node.address().port());
    (self_node, socket_address)
}

fn dp() -> DbgPaths {
    Default::default()
}

/*------- GET TESTS--------*/

/// Test GET latest block info
#[tokio::test(flavor = "current_thread")]
async fn test_get_latest_block() {
    let _ = tracing_log_try_init();

    let db = get_db_with_block().await;
    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/latest_block");
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::latest_block(&mut dp(), db, Default::default(), ks, cache)
        .recover(handle_rejection);
    let res = request.reply(&filter).await;

    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Database item(s) successfully retrieved\",\"route\":\"latest_block\",\"content\":{\"block\":{\"header\":{\"version\":2,\"bits\":0,\"nonce_and_mining_tx_hash\":[[120,12,5,128,106,59,112,177,92,150,115,57,97,113,103,79],\"test\"],\"b_num\":0,\"seed_value\":[],\"previous_hash\":null,\"txs_merkle_root_and_hash\":[\"42fbcc73bc0eeb41a991a32a6f6e145d1d45b2738657db5b4781d1fa707693cf\",\"35260a02627ae9d586dbb9f11de79afd46d1096f41ffb6b9ee88cca6b78bf374\"]},\"transactions\":[\"g98d0ab9304ca82f098a86ad6251803b\"]}}}");
}

/// Test GET wallet keypairs
#[tokio::test(flavor = "current_thread")]
async fn test_get_export_keypairs() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let (address, keys) = (
        COMMON_ADDR_STORE.0.to_string(),
        COMMON_ADDR_STORE.1.to_vec(),
    );

    db.save_encrypted_address_to_wallet(address.clone(), keys.clone())
        .await
        .unwrap();

    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/export_keypairs");
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::export_keypairs(&mut dp(), db, Default::default(), ks, cache)
        .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Key-pairs successfully exported\",\"route\":\"export_keypairs\",\"content\":{\"4348536e3d5a13e347262b5023963edf\":[195,253,191,157,40,253,233,186,96,35,27,83,83,224,191,126,133,101,235,168,233,122,174,109,18,247,175,139,253,55,164,187,238,175,251,110,53,47,158,241,103,144,49,65,247,147,145,140,12,129,123,19,187,121,31,163,16,231,248,38,243,200,34,91,4,241,40,42,97,236,37,180,26,16,34,171,12,92,4,8,53,193,181,209,97,76,164,76,0,122,44,120,212,27,145,224,20,207,215,134,23,178,170,157,218,55,14,64,185,128,63,131,194,24,6,228,34,50,252,118,94,153,105,236,92,122,169,219,119,9,250,255,20,40,148,74,182,73,180,83,10,240,193,201,45,5,205,34,188,174,229,96]}}");
}

/// Test get user debug data
#[tokio::test(flavor = "current_thread")]
async fn test_get_user_debug_data() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let ks = to_api_keys(vec!["key".to_owned()]);
    let (mut self_node, _self_socket) = new_self_node(NodeType::User).await;
    let (_c_node, c_socket) = new_self_node_with_port(NodeType::Compute, 13000).await;
    self_node.connect_to(c_socket).await.unwrap();

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .path("/debug_data")
    };
    let request_x_api = || request().header("x-api-key", "key");

    //
    // Act
    //
    let filter = routes::user_node_routes(ks, Default::default(), db, self_node.clone())
        .recover(handle_rejection);
    let res_a = request_x_api().reply(&filter).await;
    let res_m = request().reply(&filter).await;

    //
    // Assert
    //
    let expected_string = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Debug data successfully retrieved\",\"route\":\"debug_data\",\"content\":{\"node_type\":\"User\",\"node_api\":[\"wallet_info\",\"make_payment\",\"make_ip_payment\",\"request_donation\",\"export_keypairs\",\"import_keypairs\",\"update_running_total\",\"create_receipt_asset\",\"payment_address\",\"change_passphrase\",\"address_construction\",\"debug_data\"],\"node_peers\":[[\"127.0.0.1:13000\",\"127.0.0.1:13000\",\"Compute\"]],\"routes_pow\":{}}}";
    assert_eq!((res_a.status(), res_a.headers().clone()), success_json());
    assert_eq!(res_a.body(), expected_string);

    assert_eq!(
        (res_m.status(), res_m.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(res_m.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}");
}

/// Test get storage debug data
#[tokio::test(flavor = "current_thread")]
async fn test_get_storage_debug_data() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_db_with_block().await;
    let ks = to_api_keys(vec!["key".to_owned()]);
    let (mut self_node, _self_socket) = new_self_node(NodeType::Storage).await;
    let (_c_node, c_socket) = new_self_node_with_port(NodeType::Compute, 13010).await;
    self_node.connect_to(c_socket).await.unwrap();

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .path("/debug_data")
    };
    let request_x_api = || request().header("x-api-key", "key");

    //
    // Act
    //
    let filter = routes::storage_node_routes(ks, Default::default(), db, self_node.clone())
        .recover(handle_rejection);
    let res_a = request_x_api().reply(&filter).await;
    let res_m = request().reply(&filter).await;

    //
    // Assert
    //
    let expected_string = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Debug data successfully retrieved\",\"route\":\"debug_data\",\"content\":{\"node_type\":\"Storage\",\"node_api\":[\"block_by_num\",\"latest_block\",\"blockchain_entry\",\"check_transaction_presence\",\"address_construction\",\"debug_data\"],\"node_peers\":[[\"127.0.0.1:13010\",\"127.0.0.1:13010\",\"Compute\"]],\"routes_pow\":{}}}";
    assert_eq!((res_a.status(), res_a.headers().clone()), success_json());
    assert_eq!(res_a.body(), expected_string);

    assert_eq!(
        (res_m.status(), res_m.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(res_m.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}");
}

/// Test get compute debug data
#[tokio::test(flavor = "current_thread")]
async fn test_get_compute_debug_data() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let compute = ComputeTest::new(vec![]);
    let ks = to_api_keys(vec!["key".to_owned()]);
    let (mut self_node, _self_socket) = new_self_node(NodeType::Compute).await;
    let (_c_node, c_socket) = new_self_node_with_port(NodeType::Compute, 13020).await;
    self_node.connect_to(c_socket).await.unwrap();

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .path("/debug_data")
    };
    let request_x_api = || request().header("x-api-key", "key");

    //
    // Act
    //
    let tx = compute.threaded_calls.tx.clone();
    let routes_pow = to_route_pow_infos(
        vec![(
            "create_transactions".to_owned(),
            COMMON_ROUTE_POW_DIFFICULTY,
        )]
        .into_iter()
        .collect(),
    );
    let filter = routes::compute_node_routes(ks, routes_pow, tx, self_node.clone())
        .recover(handle_rejection);
    let res_a = request_x_api().reply(&filter).await;
    let res_m = request().reply(&filter).await;

    //
    // Assert
    //
    let expected_string = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Debug data successfully retrieved\",\"route\":\"debug_data\",\"content\":{\"node_type\":\"Compute\",\"node_api\":[\"fetch_balance\",\"fetch_pending\",\"create_receipt_asset\",\"create_transactions\",\"utxo_addresses\",\"address_construction\",\"debug_data\"],\"node_peers\":[[\"127.0.0.1:13020\",\"127.0.0.1:13020\",\"Compute\"]],\"routes_pow\":{\"create_transactions\":2}}}";
    assert_eq!((res_a.status(), res_a.headers().clone()), success_json());
    assert_eq!(res_a.body(), expected_string);

    assert_eq!(
        (res_m.status(), res_m.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(res_m.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}");
}

/// Test get miner debug data
#[tokio::test(flavor = "current_thread")]
async fn test_get_miner_debug_data() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let current_block = Default::default();
    let ks = to_api_keys(vec!["key".to_owned()]);
    let (mut self_node, _self_socket) = new_self_node(NodeType::Miner).await;
    let (_c_node, c_socket) = new_self_node_with_port(NodeType::Compute, 13030).await;
    self_node.connect_to(c_socket).await.unwrap();

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .path("/debug_data")
    };
    let request_x_api = || request().header("x-api-key", "key");

    //
    // Act
    //
    let filter =
        routes::miner_node_routes(ks, Default::default(), current_block, db, self_node.clone())
            .recover(handle_rejection);
    let res_a = request_x_api().reply(&filter).await;
    let res_m = request().reply(&filter).await;

    //
    // Assert
    //
    let expected_string = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Debug data successfully retrieved\",\"route\":\"debug_data\",\"content\":{\"node_type\":\"Miner\",\"node_api\":[\"wallet_info\",\"export_keypairs\",\"import_keypairs\",\"payment_address\",\"change_passphrase\",\"current_mining_block\",\"address_construction\",\"debug_data\"],\"node_peers\":[[\"127.0.0.1:13030\",\"127.0.0.1:13030\",\"Compute\"]],\"routes_pow\":{}}}";
    assert_eq!((res_a.status(), res_a.headers().clone()), success_json());
    assert_eq!(res_a.body(), expected_string);

    assert_eq!(
        (res_m.status(), res_m.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(res_m.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}");
}

/// Test get miner with user debug data
#[tokio::test(flavor = "current_thread")]
async fn test_get_miner_with_user_debug_data() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let current_block = Default::default();
    let ks = to_api_keys(vec!["key".to_owned()]);
    let (mut self_node, _self_socket) = new_self_node(NodeType::Miner).await;
    let (mut self_node_u, _self_socket_u) = new_self_node(NodeType::User).await;
    let (_c_node, c_socket) = new_self_node_with_port(NodeType::Compute, 13040).await;
    let (_s_node, s_socket) = new_self_node_with_port(NodeType::Storage, 13041).await;
    self_node.connect_to(c_socket).await.unwrap();
    self_node_u.connect_to(s_socket).await.unwrap();

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .path("/debug_data")
    };
    let request_x_api = || request().header("x-api-key", "key");

    //
    // Act
    //
    let filter = routes::miner_node_with_user_routes(
        ks,
        Default::default(),
        current_block,
        db,
        self_node,
        self_node_u,
    )
    .recover(handle_rejection);
    let res_a = request_x_api().reply(&filter).await;
    let res_m = request().reply(&filter).await;

    //
    // Assert
    //
    let expected_string = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Debug data successfully retrieved\",\"route\":\"debug_data\",\"content\":{\"node_type\":\"Miner/User\",\"node_api\":[\"wallet_info\",\"make_payment\",\"make_ip_payment\",\"request_donation\",\"export_keypairs\",\"import_keypairs\",\"update_running_total\",\"create_receipt_asset\",\"payment_address\",\"change_passphrase\",\"current_mining_block\",\"address_construction\",\"debug_data\"],\"node_peers\":[[\"127.0.0.1:13040\",\"127.0.0.1:13040\",\"Compute\"],[\"127.0.0.1:13041\",\"127.0.0.1:13041\",\"Storage\"]],\"routes_pow\":{}}}";
    assert_eq!((res_a.status(), res_a.headers().clone()), success_json());
    assert_eq!(res_a.body(), expected_string);

    assert_eq!(
        (res_m.status(), res_m.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(res_m.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}");
}

// Authorize a request where no proof-of-work or API key is required
#[tokio::test(flavor = "current_thread")]
async fn auth_request_no_pow_with_no_api_key() {
    auth_request_common((ANY_API_KEY, ""), None, true).await;
}

// Authorize a request where proof-of-work IS required BUT no API key is required
#[tokio::test(flavor = "current_thread")]
async fn auth_request_pow_with_no_api_key() {
    auth_request_common(
        (ANY_API_KEY, ""),
        Some((COMMON_ROUTE_POW_DIFFICULTY, COMMON_VALID_POW_NONCE)),
        true,
    )
    .await;
}

// Authorize a request where NO proof-of-work is required BUT a valid API key is required
#[tokio::test(flavor = "current_thread")]
async fn auth_request_no_pow_with_api_key() {
    auth_request_common((COMMON_VALID_API_KEY, COMMON_VALID_API_KEY), None, true).await;
}

// Authorize a request where valid proof of work is required AND a valid API key
#[tokio::test(flavor = "current_thread")]
async fn auth_request_pow_with_api_key() {
    auth_request_common(
        (COMMON_VALID_API_KEY, COMMON_VALID_API_KEY),
        Some((COMMON_ROUTE_POW_DIFFICULTY, COMMON_VALID_POW_NONCE)),
        true,
    )
    .await;
}

// Authorize a request where valid proof of work is required AND a valid API key
// , but the provided nonce for PoW is invalid
#[tokio::test(flavor = "current_thread")]
async fn auth_request_invalid_pow_with_api_key_failure() {
    auth_request_common(
        (COMMON_VALID_API_KEY, COMMON_VALID_API_KEY),
        /* Invalid nonce value */
        Some((COMMON_ROUTE_POW_DIFFICULTY, "99999")),
        false,
    )
    .await;
}

// Authorize a request where valid proof of work is required AND a valid API key
// , but the provided API key is invalid
#[tokio::test(flavor = "current_thread")]
async fn auth_request_pow_with_invalid_api_key_failure() {
    auth_request_common(
        /* Invalid API key */
        (COMMON_VALID_API_KEY, "invalid_api_key"),
        Some((COMMON_ROUTE_POW_DIFFICULTY, COMMON_VALID_POW_NONCE)),
        false,
    )
    .await;
}

async fn auth_request_common(
    api_keys_and_key: (&str, &str),
    difficulty_and_nonce: Option<(usize, &str)>,
    authorization_success: bool,
) {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //

    let routes_pow = to_route_pow_infos(
        difficulty_and_nonce
            .into_iter()
            .map(|(d, _)| ("debug_data".to_owned(), d))
            .collect(),
    );
    let nonce = difficulty_and_nonce.map(|(_, n)| n).unwrap_or_default();
    let (api_keys, api_key) = (
        to_api_keys(vec![api_keys_and_key.0.to_owned()]),
        api_keys_and_key.1,
    );

    let request = || {
        warp::test::request()
            .method("GET")
            .header("x-request-id", COMMON_REQ_ID)
            .header("x-api-key", api_key)
            .header("x-nonce", nonce)
            .path("/debug_data")
    };

    //
    // Act
    //
    let filter = auth_request(routes_pow, api_keys)
        .and_then(|_| ok_reply())
        .recover(handle_rejection);
    let actual_response = request().reply(&filter).await;

    let (expected_response, expected_response_body) = if authorization_success {
        (success_json(), "0")
    } else {
        (fail_json(StatusCode::UNAUTHORIZED), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Unauthorized\",\"route\":\"debug_data\",\"content\":\"null\"}")
    };

    //
    // Assert
    //
    assert_eq!(
        (actual_response.status(), actual_response.headers().clone()),
        expected_response
    );
    assert_eq!(actual_response.body(), expected_response_body);
}

/// Test GET wallet info
#[tokio::test(flavor = "current_thread")]
async fn test_get_wallet_info() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let mut fund_store = db.get_fund_store();
    let out_point = OutPoint::new("tx_hash".to_string(), 0);
    let out_point_s = OutPoint::new("tx_hash_spent".to_string(), 0);
    let asset = Asset::token_u64(11);
    fund_store.store_tx(out_point.clone(), asset.clone());
    fund_store.store_tx(out_point_s.clone(), asset.clone());
    fund_store.spend_tx(&out_point_s);

    db.set_db_value(FUND_KEY, serialize(&fund_store).unwrap())
        .await;

    db.save_transaction_to_wallet(out_point, "public_address".to_string())
        .await
        .unwrap();
    db.save_transaction_to_wallet(out_point_s, "public_address_spent".to_string())
        .await
        .unwrap();

    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/wallet_info");

    let com_req_id_plus_1 = "2ae7bc9cba924e3cb73c0249893078d8";
    let request_spent = warp::test::request()
        .method("GET")
        .header("x-request-id", com_req_id_plus_1)
        .path("/wallet_info/spent");
    let cache = create_new_cache(CACHE_LIVE_TIME);

    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let filter =
        routes::wallet_info(&mut dp(), db, Default::default(), ks, cache).recover(handle_rejection);
    let res = request.reply(&filter).await;
    let r_s = request_spent.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address\":[{\"out_point\":{\"t_hash\":\"tx_hash\",\"n\":0},\"value\":{\"Token\":11}}]}}}");

    assert_eq!((r_s.status(), r_s.headers().clone()), success_json());
    assert_eq!(r_s.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d8\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address_spent\":[{\"out_point\":{\"t_hash\":\"tx_hash_spent\",\"n\":0},\"value\":{\"Token\":11}}]}}}");
}

/// Test cache
#[tokio::test(flavor = "current_thread")]
async fn test_cache() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let mut fund_store = db.get_fund_store();
    let out_point = OutPoint::new("tx_hash".to_string(), 0);
    let out_point_s = OutPoint::new("tx_hash_spent".to_string(), 0);
    let asset = Asset::token_u64(11);
    fund_store.store_tx(out_point.clone(), asset.clone());
    fund_store.store_tx(out_point_s.clone(), asset.clone());
    fund_store.spend_tx(&out_point_s);

    db.set_db_value(FUND_KEY, serialize(&fund_store).unwrap())
        .await;

    db.save_transaction_to_wallet(out_point, "public_address".to_string())
        .await
        .unwrap();
    db.save_transaction_to_wallet(out_point_s, "public_address_spent".to_string())
        .await
        .unwrap();

    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/wallet_info");
    let request_spent = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/wallet_info/spent");
    let com_req_id_plus_1 = "2ae7bc9cba924e3cb73c0249893078d8";
    let request_spent_diff_id = warp::test::request()
        .method("GET")
        .header("x-request-id", com_req_id_plus_1)
        .path("/wallet_info/spent");

    let cache = create_new_cache(1);
    let two_sec = Duration::from_secs(2);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);

    let filter =
        routes::wallet_info(&mut dp(), db, Default::default(), ks, cache).recover(handle_rejection);
    let res = request.reply(&filter).await;
    let r_s = request_spent.reply(&filter).await;
    let r_s_diff_id = request_spent_diff_id.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address\":[{\"out_point\":{\"t_hash\":\"tx_hash\",\"n\":0},\"value\":{\"Token\":11}}]}}}");

    //test saved value is returned when the id is the same
    assert_eq!((r_s.status(), r_s.headers().clone()), success_json());
    assert_eq!(r_s.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address\":[{\"out_point\":{\"t_hash\":\"tx_hash\",\"n\":0},\"value\":{\"Token\":11}}]}}}");

    //differnt id used
    assert_eq!(
        (r_s_diff_id.status(), r_s_diff_id.headers().clone()),
        success_json()
    );
    assert_eq!(r_s_diff_id.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d8\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address_spent\":[{\"out_point\":{\"t_hash\":\"tx_hash_spent\",\"n\":0},\"value\":{\"Token\":11}}]}}}");

    thread::sleep(two_sec);
    //repeat with same id after value expires
    let request_spent = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/wallet_info/spent");
    let r_s = request_spent.reply(&filter).await;
    assert_eq!((r_s.status(), r_s.headers().clone()), success_json());
    assert_eq!(r_s.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Wallet info successfully fetched\",\"route\":\"wallet_info\",\"content\":{\"running_total\":0.0004365079365079365,\"receipt_total\":0,\"addresses\":{\"public_address_spent\":[{\"out_point\":{\"t_hash\":\"tx_hash_spent\",\"n\":0},\"value\":{\"Token\":11}}]}}}");
}

/// Test GET new payment address
#[tokio::test(flavor = "current_thread")]
async fn test_get_payment_address() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("").await;
    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/payment_address");
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::payment_address(&mut dp(), db.clone(), Default::default(), ks, cache)
        .recover(handle_rejection);
    let res = request.reply(&filter).await;
    let store_address = db.get_known_addresses().pop().unwrap();
    let expected = format!("{{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"New payment address generated\",\"route\":\"payment_address\",\"content\":\"{}\"}}", store_address);

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), &expected);
}

/// Test GET all addresses on the UTXO set
#[tokio::test(flavor = "current_thread")]
async fn test_get_utxo_set_addresses() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //

    let tx_vals = vec![
        generate_transaction("tx_hash_1", "public_address_1"),
        generate_transaction("tx_hash_2", "public_address_2"),
        generate_transaction("tx_hash_3", "public_address_3"),
    ];

    let compute = ComputeTest::new(tx_vals);
    let request = warp::test::request()
        .method("GET")
        .header("x-request-id", COMMON_REQ_ID)
        .path("/utxo_addresses");

    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::utxo_addresses(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let handle = compute.spawn();
    let res = request.reply(&filter).await;
    let _compute = handle.await.unwrap();

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(
        res.body(),
        "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"UTXO addresses successfully retrieved\",\"route\":\"utxo_addresses\",\"content\":[\"public_address_1\",\"public_address_2\",\"public_address_3\"]}"
    );
}

/*------- POST TESTS--------*/

/// Test POST for get blockchain block by key
#[tokio::test(flavor = "current_thread")]
async fn test_post_blockchain_entry_by_key_block() {
    let expected_meta = success_json();
    let expected_body = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Database item(s) successfully retrieved\",\"route\":\"blockchain_entry\",\"content\":{\"Block\":{\"block\":{\"header\":{\"version\":2,\"bits\":0,\"nonce_and_mining_tx_hash\":[[120,12,5,128,106,59,112,177,92,150,115,57,97,113,103,79],\"test\"],\"b_num\":0,\"seed_value\":[],\"previous_hash\":null,\"txs_merkle_root_and_hash\":[\"42fbcc73bc0eeb41a991a32a6f6e145d1d45b2738657db5b4781d1fa707693cf\",\"35260a02627ae9d586dbb9f11de79afd46d1096f41ffb6b9ee88cca6b78bf374\"]},\"transactions\":[\"g98d0ab9304ca82f098a86ad6251803b\"]}}}}";

    test_post_blockchain_entry_by_key(
        "b0004e829238707b7a600a95d3089e320448f706c2c7f6b0427201cc384c7fbfc",
        expected_meta.clone(),
        expected_body,
    )
    .await;
    test_post_blockchain_entry_by_key(
        "nIndexedBlockHashKey_0000000000000000",
        expected_meta,
        expected_body,
    )
    .await;
}

/// Test POST for get blockchain tx by key
#[tokio::test(flavor = "current_thread")]
async fn test_post_blockchain_entry_by_key_tx() {
    let expected_meta = success_json();
    let expected_body =
    "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Database item(s) successfully retrieved\",\"route\":\"blockchain_entry\",\"content\":{\"Transaction\":{\"inputs\":[],\"outputs\":[],\"version\":2,\"druid_info\":null}}}";

    test_post_blockchain_entry_by_key(
        "g98d0ab9304ca82f098a86ad6251803b",
        expected_meta.clone(),
        expected_body,
    )
    .await;
}

/// Test POST for get blockchain with wrong key
#[tokio::test(flavor = "current_thread")]
async fn test_post_blockchain_entry_by_key_failure() {
    let expected_meta = fail_json(StatusCode::NO_CONTENT);
    let expected_body = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"No data found for key\",\"route\":\"blockchain_entry\",\"content\":\"null\"}";

    test_post_blockchain_entry_by_key(
        "b6d369ad3595c1348772ad89e7ce314032687579f1bbe288b1a4d065a00000000",
        expected_meta.clone(),
        expected_body,
    )
    .await;
    test_post_blockchain_entry_by_key(
        "1842d4e51e99e14671077e4cac648339c3ca57e7219257fed707afd0f0000000",
        expected_meta.clone(),
        expected_body,
    )
    .await;
    test_post_blockchain_entry_by_key(
        "nIndexedTxHashKey_0000000000000011",
        expected_meta.clone(),
        expected_body,
    )
    .await;
    test_post_blockchain_entry_by_key(
        "nIndexedTxHashKey_0000000000000000_00000011",
        expected_meta.clone(),
        expected_body,
    )
    .await;
    test_post_blockchain_entry_by_key("Test", expected_meta, expected_body).await;
}

async fn test_post_blockchain_entry_by_key(
    key: &str,
    expected_meta: (StatusCode, HeaderMap),
    expected_body: &str,
) {
    let _ = tracing_log_try_init();

    let db = get_db_with_block().await;
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::blockchain_entry_by_key(&mut dp(), db, Default::default(), ks, cache)
        .recover(handle_rejection);

    let res = warp::test::request()
        .method("POST")
        .path("/blockchain_entry")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&key)
        .reply(&filter)
        .await;
    assert_eq!((res.status(), res.headers().clone()), expected_meta);
    assert_eq!(res.body(), expected_body);
}

/// Test POST for get block info by nums
#[tokio::test(flavor = "current_thread")]
async fn test_post_block_info_by_nums() {
    let _ = tracing_log_try_init();

    let db = get_db_with_block().await;
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::block_by_num(&mut dp(), db, Default::default(), ks, cache)
        .recover(handle_rejection);

    let res = warp::test::request()
        .method("POST")
        .path("/block_by_num")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&vec![0_u64, 10, 0])
        .reply(&filter)
        .await;

    // Header to match
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    assert_eq!(res.status(), 200);
    assert_eq!(res.headers(), &headers);
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Database item(s) successfully retrieved\",\"route\":\"block_by_num\",\"content\":[[\"b0004e829238707b7a600a95d3089e320448f706c2c7f6b0427201cc384c7fbfc\",{\"block\":{\"header\":{\"version\":2,\"bits\":0,\"nonce_and_mining_tx_hash\":[[120,12,5,128,106,59,112,177,92,150,115,57,97,113,103,79],\"test\"],\"b_num\":0,\"seed_value\":[],\"previous_hash\":null,\"txs_merkle_root_and_hash\":[\"42fbcc73bc0eeb41a991a32a6f6e145d1d45b2738657db5b4781d1fa707693cf\",\"35260a02627ae9d586dbb9f11de79afd46d1096f41ffb6b9ee88cca6b78bf374\"]},\"transactions\":[\"g98d0ab9304ca82f098a86ad6251803b\"]}}],[\"\",\"\"],[\"b0004e829238707b7a600a95d3089e320448f706c2c7f6b0427201cc384c7fbfc\",{\"block\":{\"header\":{\"version\":2,\"bits\":0,\"nonce_and_mining_tx_hash\":[[120,12,5,128,106,59,112,177,92,150,115,57,97,113,103,79],\"test\"],\"b_num\":0,\"seed_value\":[],\"previous_hash\":null,\"txs_merkle_root_and_hash\":[\"42fbcc73bc0eeb41a991a32a6f6e145d1d45b2738657db5b4781d1fa707693cf\",\"35260a02627ae9d586dbb9f11de79afd46d1096f41ffb6b9ee88cca6b78bf374\"]},\"transactions\":[\"g98d0ab9304ca82f098a86ad6251803b\"]}}]]}");
}

/// Test POST make payment
#[tokio::test(flavor = "current_thread")]
async fn test_post_make_payment() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let (mut self_node, self_socket) = new_self_node(NodeType::User).await;

    let encapsulated_data = EncapsulatedPayment {
        address: COMMON_ADDR_STORE.0.to_string(),
        amount: TokenAmount(25),
        passphrase: String::new(),
    };

    let db = get_wallet_db(&encapsulated_data.passphrase).await;
    let request = warp::test::request()
        .method("POST")
        .path("/make_payment")
        .remote_addr(self_socket)
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&encapsulated_data);

    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::make_payment(
        &mut dp(),
        db,
        self_node.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Payment processing\",\"route\":\"make_payment\",\"content\":{\"4348536e3d5a13e347262b5023963edf\":{\"asset\":\"token\",\"amount\":25,\"metadata\":null}}}");

    // Frame expected
    let (address, amount) = (encapsulated_data.address, encapsulated_data.amount);
    let expected_frame = user_api_request_as_frame(UserApiRequest::MakePayment { address, amount });
    let actual_frame = next_event_frame(&mut self_node).await;
    assert_eq!(expected_frame, actual_frame);
}

/// Test POST make ip payment with correct address
#[tokio::test(flavor = "current_thread")]
async fn test_post_make_ip_payment() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let (mut self_node, self_socket) = new_self_node(NodeType::User).await;

    let encapsulated_data = EncapsulatedPayment {
        address: "127.0.0.1:12345".to_owned(),
        amount: TokenAmount(25),
        passphrase: String::new(),
    };
    let db = get_wallet_db(&encapsulated_data.passphrase).await;
    let request = warp::test::request()
        .method("POST")
        .path("/make_ip_payment")
        .remote_addr(self_socket)
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&encapsulated_data);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::make_ip_payment(
        &mut dp(),
        db,
        self_node.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"IP payment processing\",\"route\":\"make_ip_payment\",\"content\":{\"127.0.0.1:12345\":{\"asset\":\"token\",\"amount\":25,\"metadata\":null}}}");

    // Frame expected
    let (payment_peer, amount) = (
        encapsulated_data.address.parse::<SocketAddr>().unwrap(),
        encapsulated_data.amount,
    );
    let expected_frame = user_api_request_as_frame(UserApiRequest::MakeIpPayment {
        payment_peer,
        amount,
    });
    let actual_frame = next_event_frame(&mut self_node).await;
    assert_eq!(expected_frame, actual_frame);
}

/// Test POST construct address from public key
#[tokio::test(flavor = "current_thread")]
async fn test_address_construction() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let mut address1 = BTreeMap::new();
    address1.insert(
        "pub_key",
        vec![
            109, 133, 37, 100, 46, 243, 13, 156, 189, 123, 142, 12, 24, 169, 49, 186, 187, 0, 63,
            27, 129, 207, 183, 13, 156, 208, 171, 164, 179, 118, 131, 183,
        ],
    );

    let mut address2 = BTreeMap::new();
    address2.insert(
        "pub_key_hex",
        "6d8525642ef30d9cbd7b8e0c18a931babb003f1b81cfb70d9cd0aba4b37683b7",
    );

    let address3 = AddressConstructData {
        pub_key_hex: Some(
            "6d8525642ef30d9cbd7b8e0c18a931babb003f1b81cfb70d9cd0aba4b37683b7".to_owned(),
        ),
        version: Some(0),
        ..Default::default()
    };

    let request1 = || {
        warp::test::request()
            .method("POST")
            .path("/address_construction")
            .header("x-request-id", COMMON_REQ_ID)
            .header("Content-Type", "application/json")
    };

    let com_req_id_plus_1 = "2ae7bc9cba924e3cb73c0249893078d8";
    let request2 = || {
        warp::test::request()
            .method("POST")
            .path("/address_construction")
            .header("x-request-id", com_req_id_plus_1)
            .header("Content-Type", "application/json")
    };

    let com_req_id_plus_2 = "2ae7bc9cba924e3cb73c0249893078d9";
    let request3 = || {
        warp::test::request()
            .method("POST")
            .path("/address_construction")
            .header("x-request-id", com_req_id_plus_2)
            .header("Content-Type", "application/json")
    };
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::address_construction(&mut dp(), Default::default(), ks, cache)
        .recover(handle_rejection);
    let res1 = request1().json(&address1).reply(&filter).await;
    let res2 = request2().json(&address2).reply(&filter).await;
    let res3 = request3().json(&address3).reply(&filter).await;

    //
    // Assert
    //
    let expected1 = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Address successfully constructed\",\"route\":\"address_construction\",\"content\":\"ca0abdcd2826a77218af0914601ee34c7ff44127aab9d0671267b25a7d36946a\"}";
    let expected2 = "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d8\",\"status\":\"Success\",\"reason\":\"Address successfully constructed\",\"route\":\"address_construction\",\"content\":\"ca0abdcd2826a77218af0914601ee34c7ff44127aab9d0671267b25a7d36946a\"}";

    assert_eq!((res1.status(), res1.headers().clone()), success_json());
    assert_eq!(res1.body(), expected1);

    assert_eq!((res2.status(), res2.headers().clone()), success_json());
    assert_eq!(res2.body(), expected2);

    assert_eq!((res3.status(), res3.headers().clone()), success_json());
    assert_eq!(res3.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d9\",\"status\":\"Success\",\"reason\":\"Address successfully constructed\",\"route\":\"address_construction\",\"content\":\"56d5b6da467e6c588966967ef5405dd2\"}");
}

/// Test POST make ip payment with correct address
#[tokio::test(flavor = "current_thread")]
async fn test_post_request_donation() {
    let _ = tracing_log_try_init();

    //
    // Arange
    //
    let (mut self_node, self_socket) = new_self_node(NodeType::User).await;

    let address = "127.0.0.1:12345".to_owned();
    let paying_peer = address.parse::<SocketAddr>().unwrap();

    let request = warp::test::request()
        .method("POST")
        .path("/request_donation")
        .remote_addr(self_socket)
        .header("x-request-id", COMMON_REQ_ID)
        .header("Content-Type", "application/json")
        .json(&address);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter =
        routes::request_donation(&mut dp(), self_node.clone(), Default::default(), ks, cache)
            .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Donation request sent\",\"route\":\"request_donation\",\"content\":\"null\"}");

    // Frame expected
    let expected_frame = user_api_request_as_frame(UserApiRequest::RequestDonation { paying_peer });
    let actual_frame = next_event_frame(&mut self_node).await;
    assert_eq!(expected_frame, actual_frame);
}

/// Test POST import key-pairs
#[tokio::test(flavor = "current_thread")]
async fn test_post_import_keypairs_success() {
    let _ = tracing_log_try_init();

    let db = get_wallet_db("").await;
    let mut addresses: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    addresses.insert(
        COMMON_ADDR_STORE.0.to_string(),
        COMMON_ADDR_STORE.1.to_vec(),
    );
    let imported_addresses = Addresses { addresses };
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::import_keypairs(&mut dp(), db.clone(), Default::default(), ks, cache)
        .recover(handle_rejection);
    let wallet_addresses_before = db.get_known_addresses();

    let res = warp::test::request()
        .method("POST")
        .path("/import_keypairs")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&imported_addresses)
        .reply(&filter)
        .await;

    let wallet_addresses_after = db.get_known_addresses();

    // Header to match
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    assert_eq!(wallet_addresses_before, Vec::<String>::new());
    assert_eq!(wallet_addresses_after, vec![COMMON_ADDR_STORE.0]);
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Key-pairs successfully imported\",\"route\":\"import_keypairs\",\"content\":[\"4348536e3d5a13e347262b5023963edf\"]}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_post_fetch_balance() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let tx_vals = vec![get_transaction()];
    let compute = ComputeTest::new(tx_vals);
    let addresses = PublicKeyAddresses {
        address_list: vec![COMMON_ADDR_STORE.0.to_string()],
    };

    let request = warp::test::request()
        .method("POST")
        .path("/fetch_balance")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&addresses);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::fetch_balance(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let handle = compute.spawn();
    let res = request.reply(&filter).await;
    let _compute = handle.await.unwrap();

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(
        res.body(),
        "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Balance successfully fetched\",\"route\":\"fetch_balance\",\"content\":{\"total\":{\"tokens\":25200,\"receipts\":0},\"address_list\":{\"4348536e3d5a13e347262b5023963edf\":[{\"out_point\":{\"t_hash\":\"tx_hash\",\"n\":0},\"value\":{\"Token\":25200}}]}}}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_post_fetch_pending() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let tx_vals = get_rb_transactions();
    let compute = ComputeTest::new(tx_vals);
    let druids = FetchPendingData {
        druid_list: vec!["full_druid".to_owned(), "non_existing_druid".to_owned()],
    };

    let request = warp::test::request()
        .method("POST")
        .path("/fetch_pending")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&druids);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::fetch_pending(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let handle = compute.spawn();
    let res = request.reply(&filter).await;
    let _compute = handle.await.unwrap();

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(
        res.body(),
        "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Pending transactions successfully fetched\",\"route\":\"fetch_pending\",\"content\":{\"full_druid\":{\"participants\":2,\"txs\":{\"g274712ea22292d1a60446dc93566e96\":{\"inputs\":[{\"previous_out\":{\"t_hash\":\"000001\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"754dc248d1c847e8a10c6f8ded6ccad96381551ebb162583aea2a86b9bb78dfa\"},{\"Signature\":[21,103,185,228,19,36,74,158,249,211,229,41,187,113,248,98,27,55,85,97,36,94,216,242,20,156,39,245,55,212,95,22,52,161,77,8,211,241,24,217,126,208,39,154,87,136,126,31,154,177,219,197,151,174,148,122,67,147,4,59,177,191,172,8]},{\"PubKey\":[83,113,131,33,34,168,232,4,250,53,32,236,104,97,195,250,85,74,127,111,182,23,230,240,118,132,82,9,2,7,224,124]},{\"Op\":\"OP_DUP\"},{\"Op\":\"OP_HASH256\"},{\"PubKeyHash\":\"5423e6bd848e0ce5cd794e55235c23138d8833633cd2d7de7f4a10935178457b\"},{\"Op\":\"OP_EQUALVERIFY\"},{\"Op\":\"OP_CHECKSIG\"}]}}],\"outputs\":[{\"value\":{\"Token\":0},\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":null},{\"value\":{\"Receipt\":1},\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"sender_address\"}],\"version\":2,\"druid_info\":{\"druid\":\"full_druid\",\"participants\":2,\"expectations\":[{\"from\":\"6efcefb27d1e1149b243ce319c5e5352bb100dc328a59f630ee7a9fd5ebe9da9\",\"to\":\"receiver_address\",\"asset\":{\"Token\":25200}}]}},\"g7f6fdc695f1127b466c39f049179aae\":{\"inputs\":[{\"previous_out\":{\"t_hash\":\"000000\",\"n\":0},\"script_signature\":{\"stack\":[{\"Bytes\":\"927b3411743452e5e0d73e9e40a4fa3c842b3d00dabde7f9af7e44661ce02c88\"},{\"Signature\":[35,226,158,202,184,227,77,178,40,234,140,161,109,206,131,187,171,159,103,146,89,201,220,227,212,184,216,166,69,26,92,67,221,248,253,165,17,176,190,4,48,76,146,12,179,195,90,227,170,17,196,234,76,57,254,242,83,89,237,117,68,193,105,10]},{\"PubKey\":[83,113,131,33,34,168,232,4,250,53,32,236,104,97,195,250,85,74,127,111,182,23,230,240,118,132,82,9,2,7,224,124]},{\"Op\":\"OP_DUP\"},{\"Op\":\"OP_HASH256\"},{\"PubKeyHash\":\"5423e6bd848e0ce5cd794e55235c23138d8833633cd2d7de7f4a10935178457b\"},{\"Op\":\"OP_EQUALVERIFY\"},{\"Op\":\"OP_CHECKSIG\"}]}}],\"outputs\":[{\"value\":{\"Token\":0},\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":null},{\"value\":{\"Token\":25200},\"locktime\":0,\"drs_block_hash\":null,\"drs_tx_hash\":null,\"script_public_key\":\"receiver_address\"}],\"version\":2,\"druid_info\":{\"druid\":\"full_druid\",\"participants\":2,\"expectations\":[{\"from\":\"b519b3fd271bb33a7ea949a918cc45b00b32095a04f2a9172797f7441f7298e6\",\"to\":\"sender_address\",\"asset\":{\"Receipt\":1}}]}}}}}}");
}

/// Test POST update running total successful
#[tokio::test(flavor = "current_thread")]
async fn test_post_update_running_total() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let (mut self_node, _self_socket) = new_self_node(NodeType::User).await;

    let addresses = PublicKeyAddresses {
        address_list: vec![COMMON_ADDR_STORE.0.to_string()],
    };
    let address_list = UtxoFetchType::AnyOf(addresses.address_list.clone());

    let request = warp::test::request()
        .method("POST")
        .path("/update_running_total")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&addresses);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter =
        routes::update_running_total(&mut dp(), self_node.clone(), Default::default(), ks, cache)
            .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Running total updated\",\"route\":\"update_running_total\",\"content\":\"null\"}");

    // Expected Frame
    let expected_frame =
        user_api_request_as_frame(UserApiRequest::UpdateWalletFromUtxoSet { address_list });
    let actual_frame = next_event_frame(&mut self_node).await;
    assert_eq!(expected_frame, actual_frame);
}

/// Test POST create receipt asset on compute node successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_transactions() {
    test_post_create_transactions_common(None).await;
}

/// Test POST create receipt asset on compute node successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_transactions_v0() {
    test_post_create_transactions_common(Some(NETWORK_VERSION_V0)).await;
}

/// Test POST create receipt asset on compute node successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_transactions_temp() {
    test_post_create_transactions_common(Some(NETWORK_VERSION_TEMP)).await;
}

async fn test_post_create_transactions_common(address_version: Option<u64>) {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let compute = ComputeTest::new(Vec::new());

    let previous_out = OutPoint::new(COMMON_PUB_ADDR.to_owned(), 0);
    let signable_data = construct_tx_in_signable_hash(&previous_out);
    let secret_key = decode_secret_key(COMMON_SEC_KEY).unwrap();
    let raw_signature = sign::sign_detached(signable_data.as_bytes(), &secret_key);
    let signature = hex::encode(raw_signature.as_ref());
    let public_key = COMMON_PUB_KEY.to_owned();

    let json_body = vec![CreateTransaction {
        inputs: vec![CreateTxIn {
            previous_out: Some(previous_out.clone()),
            script_signature: Some(CreateTxInScript::Pay2PkH {
                signable_data,
                signature,
                public_key,
                address_version,
            }),
        }],
        outputs: vec![TxOut {
            value: Asset::Token(TokenAmount(1)),
            script_public_key: Some(COMMON_ADDRS[0].to_owned()),
            drs_block_hash: None,
            drs_tx_hash: None,
            locktime: 0,
        }],
        version: 1,
        druid_info: None,
    }];

    let request = warp::test::request()
        .method("POST")
        .path("/create_transactions")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::create_transactions(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let handle = compute.spawn();
    let res = request.reply(&filter).await;
    let _compute = handle.await.unwrap();

    //
    // Assert
    //
    assert_eq!(
        ((res.status(), res.headers().clone()), from_utf8(res.body())),
        (success_json(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Transaction(s) processing\",\"route\":\"create_transactions\",\"content\":{\"0008536e3d5a13e347262b5023963000\":{\"asset\":\"token\",\"amount\":1,\"metadata\":null}}}")
    );
}

/// Test POST create receipt asset on compute node successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_receipt_asset_tx_compute() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let compute = ComputeTest::new(Vec::new());

    let asset_hash = construct_tx_in_signable_asset_hash(&Asset::Receipt(1));
    let secret_key = decode_secret_key(COMMON_SEC_KEY).unwrap();
    let signature = hex::encode(sign::sign_detached(asset_hash.as_bytes(), &secret_key).as_ref());

    let json_body = CreateReceiptAssetData {
        receipt_amount: 1,
        script_public_key: Some(COMMON_PUB_ADDR.to_owned()),
        public_key: Some(COMMON_PUB_KEY.to_owned()),
        signature: Some(signature),
    };

    let request = warp::test::request()
        .method("POST")
        .path("/create_receipt_asset")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::create_receipt_asset(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let handle = compute.spawn();
    let res = request.reply(&filter).await;
    let _compute = handle.await.unwrap();

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Receipt asset(s) created\",\"route\":\"create_receipt_asset\",\"content\":{\"asset\":\"receipt\",\"amount\":1,\"to_address\":\"13bd3351b78beb2d0dadf2058dcc926c\"}}");
}

/// Test POST create receipt asset on user node successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_receipt_asset_tx_user() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let (mut self_node, self_socket) = new_self_node(NodeType::User).await;

    let json_body = CreateReceiptAssetDataUser { receipt_amount: 1 };

    let request = warp::test::request()
        .method("POST")
        .path("/create_receipt_asset")
        .remote_addr(self_socket)
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::create_receipt_asset_user(
        &mut dp(),
        self_node.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Receipt asset(s) created\",\"route\":\"create_receipt_asset\",\"content\":1}");

    // Expected Frame
    let expected_frame = user_api_request_as_frame(UserApiRequest::SendCreateReceiptRequest {
        receipt_amount: json_body.receipt_amount,
    });

    let actual_frame = next_event_frame(&mut self_node).await;
    assert_eq!(expected_frame, actual_frame);
}

/// Test POST create receipt asset on compute node failure
#[tokio::test(flavor = "current_thread")]
async fn test_post_create_receipt_asset_tx_compute_failure() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let compute = ComputeTest::new(Vec::new());

    let json_body = CreateReceiptAssetData {
        receipt_amount: 1,
        // These fields should be occupied for compute node
        script_public_key: None,
        public_key: None,
        signature: None,
    };

    let request = warp::test::request()
        .method("POST")
        .path("/create_receipt_asset")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::create_receipt_asset(
        &mut dp(),
        compute.threaded_calls.tx.clone(),
        Default::default(),
        ks,
        cache,
    )
    .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!(
        (res.status(), res.headers().clone()),
        fail_json(StatusCode::BAD_REQUEST)
    );
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Invalid request body\",\"route\":\"create_receipt_asset\",\"content\":{\"asset\":\"receipt\",\"amount\":1,\"to_address\":\"\"}}");
}

/// Test POST change passphrase successfully
#[tokio::test(flavor = "current_thread")]
async fn test_post_change_passphrase() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("old_passphrase").await;
    let (payment_address, expected_address_store) = db.generate_payment_address().await;

    let json_body = ChangePassphraseData {
        old_passphrase: String::from("old_passphrase"),
        new_passphrase: String::from("new_passphrase"),
    };

    let request = warp::test::request()
        .method("POST")
        .path("/change_passphrase")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let filter = routes::change_passphrase(&mut dp(), db.clone(), Default::default(), ks, cache)
        .recover(handle_rejection);
    let res = request.reply(&filter).await;
    let actual = db.test_passphrase(String::from("new_passphrase")).await;
    let actual_address_store = db.get_address_store(&payment_address);

    //
    // Assert
    //
    assert_eq!(
        expected_address_store.secret_key, actual_address_store.secret_key,
        "Not able to decrypt addresses stored in WalletDb"
    );

    assert!(matches!(actual, Ok(())), "{:?}", actual);
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Passphrase changed successfully\",\"route\":\"change_passphrase\",\"content\":\"null\"}");
}

/// Test POST change passphrase failure
#[tokio::test(flavor = "current_thread")]
async fn test_post_change_passphrase_failure() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_wallet_db("old").await;
    let json_body = ChangePassphraseData {
        old_passphrase: String::from("invalid_passphrase"),
        new_passphrase: String::from("new_passphrase"),
    };

    let request = warp::test::request()
        .method("POST")
        .path("/change_passphrase")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&json_body.clone());
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::change_passphrase(&mut dp(), db.clone(), Default::default(), ks, cache)
        .recover(handle_rejection);
    let actual = db.test_passphrase(String::from("new_passphrase")).await;
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert!(
        matches!(actual, Err(WalletDbError::PassphraseError)),
        "{:?}",
        actual
    );
    assert_eq!(
        (res.status(), res.headers().clone()),
        fail_json(StatusCode::UNAUTHORIZED)
    ); // TODO: Convert to fail_json
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Error\",\"reason\":\"Invalid passphrase\",\"route\":\"change_passphrase\",\"content\":\"null\"}");
}

/// Test POST fetch block hashes for blocks that contain given `tx_hashes`
#[tokio::test(flavor = "current_thread")]
async fn test_post_block_nums_by_tx_hashes() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let db = get_db_with_block().await;

    let request = warp::test::request()
        .method("POST")
        .path("/check_transaction_presence")
        .header("Content-Type", "application/json")
        .header("x-request-id", COMMON_REQ_ID)
        .json(&vec!["g393e26d47ede87b84808c1a5664ea41"]);
    //
    // Act
    //
    let ks = to_api_keys(vec![ANY_API_KEY.to_owned()]);
    let cache = create_new_cache(CACHE_LIVE_TIME);
    let filter = routes::blocks_by_tx_hashes(&mut dp(), db, Default::default(), ks, cache)
        .recover(handle_rejection);
    let res = request.reply(&filter).await;

    //
    // Assert
    //
    assert_eq!((res.status(), res.headers().clone()), success_json());
    assert_eq!(res.body(), "{\"id\":\"2ae7bc9cba924e3cb73c0249893078d7\",\"status\":\"Success\",\"reason\":\"Database item(s) successfully retrieved\",\"route\":\"check_transaction_presence\",\"content\":[]}");
}
