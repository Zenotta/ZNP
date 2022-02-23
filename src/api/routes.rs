use crate::api::errors;
use crate::api::handlers::{self, DbgPaths};
use crate::api::responses::JsonReply;
use crate::comms_handler::Node;
use crate::db_utils::SimpleDb;
use crate::interfaces::ComputeApi;
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::threaded_call::ThreadedCallSender;
use crate::utils::ApiKeys;
use crate::wallet::WalletDb;
use std::convert::Infallible;
use std::future::Future;
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

fn map_api_res(
    r: impl Future<Output = Result<JsonReply, JsonReply>>,
) -> impl Future<Output = Result<impl warp::Reply, warp::Rejection>> {
    use futures::future::TryFutureExt;
    r.map_ok_or_else(Ok, Ok)
}

/// Validate x-api-key if api_keys is provided
pub fn x_api_key(api_keys: ApiKeys) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let need_check = !api_keys.lock().unwrap().contains("any_key");

    warp::header::<String>("x-api-key")
        .and_then(move |n: String| {
            let api_keys = api_keys.clone();
            async move {
                if !api_keys.lock().unwrap().contains(&n) {
                    Err(warp::reject::custom(errors::Unauthorized))
                } else {
                    Ok(())
                }
            }
        })
        .untuple_one()
        .or_else(move |err| async move {
            if need_check {
                Err(err)
            } else {
                Ok(())
            }
        })
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
    let route = "wallet_info";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and(
            warp::path::param::<String>()
                .map(Some)
                .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) }),
        )
        .and_then(move |db, ei| map_api_res(handlers::get_wallet_info(db, ei, route, call_id)))
        .with(get_cors())
}

// GET all keypairs
// TODO: Requires password (will move to POST)
pub fn export_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "export_keypairs";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(move |db| map_api_res(handlers::get_export_keypairs(db, route, call_id)))
        .with(get_cors())
}

// GET new payment address
pub fn payment_address(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "payment_address";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(move |db| map_api_res(handlers::get_payment_address(db, route, call_id)))
        .with(get_cors())
}

// GET latest block
pub fn latest_block(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "latest_block";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and_then(move |db| map_api_res(handlers::get_latest_block(db, route, call_id)))
        .with(get_cors())
}

// GET debug data
pub fn debug_data(
    mut dp: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "debug_data";
    let call_id = "";
    warp_path(&mut dp, route)
        .and(warp::get())
        .and(with_node_component(dp))
        .and(with_node_component(node))
        .and(with_node_component(aux_node))
        .and_then(move |dp, node, aux| {
            map_api_res(handlers::get_debug_data(dp, node, aux, route, call_id))
        })
        .with(get_cors())
}

// GET current block being mined
pub fn current_mining_block(
    dp: &mut DbgPaths,
    current_block: Arc<Mutex<Option<BlockPoWReceived>>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "current_mining_block";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(current_block))
        .and_then(move |cb| map_api_res(handlers::get_current_mining_block(cb, route, call_id)))
        .with(get_cors())
}

// GET UTXO set addresses
pub fn utxo_addresses(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "utxo_addresses";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(threaded_calls))
        .and_then(move |a| map_api_res(handlers::get_utxo_addresses(a, route, call_id)))
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
    let route = "blockchain_entry";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(move |db, info| {
            map_api_res(handlers::post_blockchain_entry_by_key(
                db, info, route, call_id,
            ))
        })
        .with(post_cors())
}

// POST get block information by number
pub fn block_by_num(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "block_by_num";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(move |db, info| {
            map_api_res(handlers::post_block_by_num(db, info, route, call_id))
        })
        .with(post_cors())
}

// POST save keypair
// TODO: Requires password
pub fn import_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "import_keypairs";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(move |db, kp| map_api_res(handlers::post_import_keypairs(db, kp, route, call_id)))
        .with(post_cors())
}

// POST make payment
pub fn make_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "make_payment";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(move |db, node, pi| {
            map_api_res(handlers::post_make_payment(db, node, pi, route, call_id))
        })
        .with(post_cors())
}

// POST make payment
pub fn make_ip_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "make_ip_payment";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(move |db, node, pi| {
            map_api_res(handlers::post_make_ip_payment(db, node, pi, route, call_id))
        })
        .with(post_cors())
}

// POST request donation payment
pub fn request_donation(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "request_donation";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(move |node, info| {
            map_api_res(handlers::post_request_donation(node, info, route, call_id))
        })
        .with(post_cors())
}

// POST update running total
pub fn update_running_total(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "update_running_total";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(move |node, info| {
            map_api_res(handlers::post_update_running_total(
                node, info, route, call_id,
            ))
        })
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_balance(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "fetch_balance";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(move |tc, info| {
            map_api_res(handlers::post_fetch_utxo_balance(tc, info, route, call_id))
        })
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_pending(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "fetch_pending";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(move |tc, info| {
            map_api_res(handlers::post_fetch_druid_pending(tc, info, route, call_id))
        })
        .with(post_cors())
}

// POST create receipt-based asset transaction
pub fn create_receipt_asset(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "create_receipt_asset";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(move |tc, info| {
            map_api_res(handlers::post_create_receipt_asset(
                tc, info, route, call_id,
            ))
        })
        .with(post_cors())
}

/// POST create a receipt-based asset transaction on user
pub fn create_receipt_asset_user(
    dp: &mut DbgPaths,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "create_receipt_asset";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and_then(move |node, info| {
            map_api_res(handlers::post_create_receipt_asset_user(
                node, info, route, call_id,
            ))
        })
        .with(post_cors())
}

// POST change passphrase
pub fn change_passphrase(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "change_passphrase";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(move |db, info| {
            map_api_res(handlers::post_change_wallet_passphrase(
                db, info, route, call_id,
            ))
        })
        .with(post_cors())
}

// POST create transactions
pub fn create_transactions(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let route = "create_transactions";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and_then(move |tc, info| {
            map_api_res(handlers::post_create_transactions(tc, info, route, call_id))
        })
        .with(post_cors())
}

// POST check for address presence
pub fn blocks_by_tx_hashes(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let route = "check_transaction_presence";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and_then(move |db, info| {
            map_api_res(handlers::post_blocks_by_tx_hashes(db, info, route, call_id))
        })
        .with(post_cors())
}

// POST construct payment address
pub fn address_construction(
    dp: &mut DbgPaths,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "address_construction";
    let call_id = "";
    warp_path(dp, route)
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |info| {
            map_api_res(handlers::post_payment_address_construction(
                info, route, call_id,
            ))
        })
        .with(post_cors())
}

//======= NODE ROUTES =======//
//TODO: Nodes share similar routes; We need to find a way to reduce ambiguity

// API routes for User nodes
pub fn user_node_routes(
    api_keys: ApiKeys,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = wallet_info(dp, db.clone())
        .or(make_payment(dp, db.clone(), node.clone()))
        .or(make_ip_payment(dp, db.clone(), node.clone()))
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(update_running_total(dp, node.clone()))
        .or(create_receipt_asset_user(dp, node.clone()))
        .or(payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None));

    x_api_key(api_keys).and(routes)
}

// API routes for Storage nodes
pub fn storage_node_routes(
    api_keys: ApiKeys,
    db: Arc<Mutex<SimpleDb>>,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = block_by_num(dp, db.clone())
        .or(latest_block(dp, db.clone()))
        .or(blockchain_entry_by_key(dp, db.clone()))
        .or(blocks_by_tx_hashes(dp, db))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None));

    x_api_key(api_keys).and(routes)
}

// API routes for Compute nodes
pub fn compute_node_routes(
    api_keys: ApiKeys,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = fetch_balance(dp, threaded_calls.clone())
        .or(fetch_pending(dp, threaded_calls.clone()))
        .or(create_receipt_asset(dp, threaded_calls.clone()))
        .or(create_transactions(dp, threaded_calls.clone()))
        .or(utxo_addresses(dp, threaded_calls))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None));

    x_api_key(api_keys).and(routes)
}

// API routes for Miner nodes
pub fn miner_node_routes(
    api_keys: ApiKeys,
    current_block: CurrentBlockWithMutex,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = wallet_info(dp, db.clone())
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(current_mining_block(dp, current_block))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, node, None));

    x_api_key(api_keys).and(routes)
}

// API routes for Miner nodes with User node capabilities
pub fn miner_node_with_user_routes(
    api_keys: ApiKeys,
    current_block: CurrentBlockWithMutex,
    db: WalletDb, /* Shared WalletDb */
    miner_node: Node,
    user_node: Node, /* Additional User `Node` */
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = wallet_info(dp, db.clone())
        .or(make_payment(dp, db.clone(), user_node.clone()))
        .or(make_ip_payment(dp, db.clone(), user_node.clone()))
        .or(request_donation(dp, user_node.clone()))
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(update_running_total(dp, user_node.clone()))
        .or(create_receipt_asset_user(dp, user_node.clone()))
        .or(payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(current_mining_block(dp, current_block))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, miner_node, Some(user_node)));

    x_api_key(api_keys).and(routes)
}
