use crate::api::handlers::{self, DbgPaths};
use crate::comms_handler::Node;
use crate::db_utils::SimpleDb;
use crate::interfaces::ComputeApi;
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::threaded_call::ThreadedCallSender;
use crate::wallet::WalletDb;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use warp::{self, Filter, Rejection, Reply};

fn with_node_component<T: Clone + Send>(
    comp: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || comp.clone())
}

fn warp_path(
    dp: &mut DbgPaths,
    p: &'static str,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    dp.push(p);
    warp::path(p)
}

//======= GET ROUTES =======//

// GET CORS
fn get_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["*"])
        .allow_methods(vec!["GET"])
}

// GET wallet info
pub fn wallet_info(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "wallet_info")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_wallet_info)
        .with(get_cors())
}

// GET all keypairs
// TODO: Requires password (will move to POST)
pub fn export_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "export_keypairs")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_export_keypairs)
        .with(get_cors())
}

// GET new payment address
pub fn new_payment_address(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "new_payment_address")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_new_payment_address)
        .with(get_cors())
}

// GET latest block
pub fn latest_block(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "latest_block")
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(handlers::get_latest_block)
        .with(get_cors())
}

// GET debug data
pub fn debug_data(
    mut dp: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(&mut dp, "debug_data")
        .and(warp::get())
        .and(with_node_component(dp))
        .and(with_node_component(node))
        .and(with_node_component(aux_node))
        .and_then(handlers::get_debug_data)
        .with(get_cors())
}

// GET current block being mined
pub fn current_mining_block(
    dp: &mut DbgPaths,
    current_block: Arc<Mutex<Option<BlockPoWReceived>>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "current_mining_block")
        .and(warp::get())
        .and(with_node_component(current_block))
        .and_then(handlers::get_current_mining_block)
        .with(get_cors())
}

// GET UTXO set addresses
pub fn utxo_addresses(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "utxo_addresses")
        .and(warp::get())
        .and(with_node_component(threaded_calls))
        .and_then(handlers::get_utxo_addresses)
        .with(get_cors())
}

//======= POST ROUTES =======//

// POST CORS
fn post_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"])
}

// POST get db item by key
pub fn blockchain_entry_by_key(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "blockchain_entry_by_key")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_blockchain_entry_by_key)
        .with(post_cors())
}

// POST get block information by number
pub fn block_by_num(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "block_by_num")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_block_by_num)
        .with(post_cors())
}

// POST save keypair
// TODO: Requires password
pub fn import_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "import_keypairs")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_import_keypairs)
        .with(post_cors())
}

// POST make payment
pub fn make_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "make_payment")
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(handlers::post_make_payment)
        .with(post_cors())
}

// POST make payment
pub fn make_ip_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "make_ip_payment")
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(handlers::post_make_ip_payment)
        .with(post_cors())
}

// POST request donation payment
pub fn request_donation(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "request_donation")
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(handlers::post_request_donation)
        .with(post_cors())
}

// POST update running total
pub fn update_running_total(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "update_running_total")
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(handlers::post_update_running_total)
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_balance(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "fetch_balance")
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(handlers::post_fetch_utxo_balance)
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_pending(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "fetch_pending")
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(handlers::post_fetch_druid_pending)
        .with(post_cors())
}

// POST create receipt-based asset transaction
pub fn create_receipt_asset(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "create_receipt_asset")
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(handlers::post_create_receipt_asset)
        .with(post_cors())
}

// POST change passphrase
pub fn change_passphrase(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "change_passphrase")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_change_wallet_passphrase)
        .with(post_cors())
}

// POST create transactions
pub fn create_transactions(
    dp: &mut DbgPaths,
    peer: Node,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp_path(dp, "create_transactions")
        .and(warp::post())
        .and(with_node_component(peer))
        .and(warp::body::json())
        .and_then(handlers::post_create_transactions)
        .with(post_cors())
}

// POST check for address presence
pub fn blocks_by_tx_hashes(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp_path(dp, "block_by_tx_hashes")
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(handlers::post_blocks_by_tx_hashes)
        .with(post_cors())
}

// POST construct payment address
pub fn address_construction(
    dp: &mut DbgPaths,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp_path(dp, "address_construction")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handlers::post_payment_address_construction)
        .with(post_cors())
}

//======= NODE ROUTES =======//
//TODO: Nodes share similar routes; We need to find a way to reduce ambiguity

// API routes for User nodes
pub fn user_node_routes(
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    wallet_info(dp, db.clone())
        .or(make_payment(dp, db.clone(), node.clone()))
        .or(make_ip_payment(dp, db.clone(), node.clone()))
        .or(request_donation(dp, node.clone()))
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(update_running_total(dp, node.clone()))
        .or(create_receipt_asset(dp, node.clone()))
        .or(new_payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None))
}

// API routes for Storage nodes
pub fn storage_node_routes(
    db: Arc<Mutex<SimpleDb>>,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    block_by_num(dp, db.clone())
        .or(latest_block(dp, db.clone()))
        .or(blockchain_entry_by_key(dp, db.clone()))
        .or(blocks_by_tx_hashes(dp, db))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None))
}

// API routes for Compute nodes
pub fn compute_node_routes(
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    fetch_balance(dp, threaded_calls.clone())
        .or(fetch_pending(dp, threaded_calls.clone()))
        .or(create_receipt_asset(dp, node.clone()))
        .or(create_transactions(dp, node.clone()))
        .or(utxo_addresses(dp, threaded_calls))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None))
}

// API routes for Miner nodes
pub fn miner_node_routes(
    current_block: CurrentBlockWithMutex,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    wallet_info(dp, db.clone())
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(new_payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(current_mining_block(dp, current_block))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None))
}

// API routes for Miner nodes with User node capabilities
pub fn miner_node_with_user_routes(
    current_block: CurrentBlockWithMutex,
    db: WalletDb, /* Shared WalletDb */
    miner_node: Node,
    user_node: Node, /* Additional User `Node` */
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    wallet_info(dp, db.clone())
        .or(make_payment(dp, db.clone(), user_node.clone()))
        .or(make_ip_payment(dp, db.clone(), user_node.clone()))
        .or(request_donation(dp, user_node.clone()))
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(update_running_total(dp, user_node.clone()))
        .or(create_receipt_asset(dp, user_node.clone()))
        .or(new_payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(current_mining_block(dp, current_block))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, miner_node, Some(user_node)))
}
