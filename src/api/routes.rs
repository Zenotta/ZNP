use crate::api::handlers::{self, DbgPaths};
use crate::api::utils::extract_id;
use crate::api::utils::{
    auth_request, handle_rejection, map_api_res, warp_path, with_node_component,
};
use crate::comms_handler::Node;
use crate::db_utils::SimpleDb;
use crate::interfaces::ComputeApi;
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::threaded_call::ThreadedCallSender;
use crate::utils::{ApiKeys, RoutesPoWInfo};
use crate::wallet::WalletDb;
use std::sync::{Arc, Mutex};
use warp::{Filter, Rejection, Reply};

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
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and(
            warp::path::param::<String>()
                .map(Some)
                .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) }),
        )
        .and(extract_id())
        .and_then(move |db, ei, call_id| {
            map_api_res(handlers::get_wallet_info(db, ei, route, call_id))
        })
        .with(get_cors())
}

// GET all keypairs
// TODO: Requires password (will move to POST)
pub fn export_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "export_keypairs";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and(extract_id())
        .and_then(move |db, call_id| map_api_res(handlers::get_export_keypairs(db, route, call_id)))
        .with(get_cors())
}

// GET new payment address
pub fn payment_address(
    dp: &mut DbgPaths,
    db: WalletDb,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "payment_address";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and(extract_id())
        .and_then(move |db, call_id| map_api_res(handlers::get_payment_address(db, route, call_id)))
        .with(get_cors())
}

// GET latest block
pub fn latest_block(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "latest_block";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(db))
        .and(extract_id())
        .and_then(move |db, call_id| map_api_res(handlers::get_latest_block(db, route, call_id)))
        .with(get_cors())
}

// GET debug data
pub fn debug_data(
    mut dp: DbgPaths,
    routes_pow: RoutesPoWInfo,
    node: Node,
    aux_node: Option<Node>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "debug_data";
    warp_path(&mut dp, route)
        .and(warp::get())
        .and(with_node_component(dp))
        .and(with_node_component(node))
        .and(with_node_component(aux_node))
        .and(with_node_component(routes_pow))
        .and(extract_id())
        .and_then(move |dp, node, aux, routes_pow: RoutesPoWInfo, call_id| {
            let routes = routes_pow.lock().unwrap().clone();
            map_api_res(handlers::get_debug_data(
                dp, node, aux, route, call_id, routes,
            ))
        })
        .with(get_cors())
}

// GET current block being mined
pub fn current_mining_block(
    dp: &mut DbgPaths,
    current_block: Arc<Mutex<Option<BlockPoWReceived>>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "current_mining_block";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(current_block))
        .and(extract_id())
        .and_then(move |cb, call_id| {
            map_api_res(handlers::get_current_mining_block(cb, route, call_id))
        })
        .with(get_cors())
}

// GET UTXO set addresses
pub fn utxo_addresses(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "utxo_addresses";
    warp_path(dp, route)
        .and(warp::get())
        .and(with_node_component(threaded_calls))
        .and(extract_id())
        .and_then(move |a, call_id| map_api_res(handlers::get_utxo_addresses(a, route, call_id)))
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, kp, call_id| {
            map_api_res(handlers::post_import_keypairs(db, kp, route, call_id))
        })
        .with(post_cors())
}

// POST make payment
pub fn make_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "make_payment";
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, node, pi, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, node, pi, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |node, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |node, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |tc, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |tc, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |tc, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |node, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |tc, info, call_id| {
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
    warp_path(dp, route)
        .and(warp::post())
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |db, info, call_id| {
            map_api_res(handlers::post_blocks_by_tx_hashes(db, info, route, call_id))
        })
        .with(post_cors())
}

// POST construct payment address
pub fn address_construction(
    dp: &mut DbgPaths,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "address_construction";
    warp_path(dp, route)
        .and(warp::post())
        .and(warp::body::json())
        .and(extract_id())
        .and_then(move |info, call_id| {
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
    routes_pow_info: RoutesPoWInfo,
    db: WalletDb,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;

    let routes = wallet_info(dp, db.clone())
        .or(make_payment(dp, db.clone(), node.clone()))
        .or(make_ip_payment(dp, db.clone(), node.clone()))
        .or(request_donation(dp, node.clone()))
        .or(export_keypairs(dp, db.clone()))
        .or(import_keypairs(dp, db.clone()))
        .or(update_running_total(dp, node.clone()))
        .or(create_receipt_asset_user(dp, node.clone()))
        .or(payment_address(dp, db.clone()))
        .or(change_passphrase(dp, db))
        .or(address_construction(dp))
        .or(debug_data(dp_vec, routes_pow_info.clone(), node, None));

    auth_request(routes_pow_info, api_keys)
        .and(routes)
        .recover(handle_rejection)
}

// API routes for Storage nodes
pub fn storage_node_routes(
    api_keys: ApiKeys,
    routes_pow_info: RoutesPoWInfo,
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
        .or(debug_data(dp_vec, routes_pow_info.clone(), node, None));

    auth_request(routes_pow_info, api_keys)
        .and(routes)
        .recover(handle_rejection)
}

// API routes for Compute nodes
pub fn compute_node_routes(
    routes_pow_info: RoutesPoWInfo,
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
        .or(debug_data(dp_vec, routes_pow_info.clone(), node, None));

    auth_request(routes_pow_info, api_keys)
        .and(routes)
        .recover(handle_rejection)
}

// API routes for Miner nodes
pub fn miner_node_routes(
    api_keys: ApiKeys,
    routes_pow_info: RoutesPoWInfo,
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
        .or(debug_data(dp_vec, routes_pow_info.clone(), node, None));

    auth_request(routes_pow_info, api_keys)
        .and(routes)
        .recover(handle_rejection)
}

// API routes for Miner nodes with User node capabilities
pub fn miner_node_with_user_routes(
    api_keys: ApiKeys,
    routes_pow_info: RoutesPoWInfo,
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
        .or(debug_data(
            dp_vec,
            routes_pow_info.clone(),
            miner_node,
            Some(user_node),
        ));

    auth_request(routes_pow_info, api_keys)
        .and(routes)
        .recover(handle_rejection)
}
