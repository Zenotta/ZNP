use crate::api::handlers::{self, DbgPaths};
use crate::api::utils::{
    auth_request, create_new_cache, handle_rejection, map_api_res_and_cache, warp_path,
    with_node_component, ReplyCache, CACHE_LIVE_TIME,
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
pub fn get_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Accept",
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Headers",
            "Content-Type",
            "x-request-id",
            "x-nonce",
            "x-api-key",
        ])
        .allow_methods(vec!["GET"])
}

// GET wallet info
pub fn wallet_info(
    dp: &mut DbgPaths,
    db: WalletDb,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "wallet_info";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(
            warp::path::param::<String>()
                .map(Some)
                .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) }),
        )
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, ei, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_wallet_info(db, ei, route, call_id),
            )
        })
        .with(get_cors())
}

// GET all keypairs
// TODO: Requires password (will move to POST)
pub fn export_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "export_keypairs";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_export_keypairs(db, route, call_id),
            )
        })
        .with(get_cors())
}

// GET new payment address
pub fn payment_address(
    dp: &mut DbgPaths,
    db: WalletDb,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "payment_address";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_payment_address(db, route, call_id),
            )
        })
        .with(get_cors())
}

// GET latest block
pub fn latest_block(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "latest_block";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_latest_block(db, route, call_id),
            )
        })
        .with(get_cors())
}

// GET debug data
pub fn debug_data(
    mut dp: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "debug_data";
    warp_path(&mut dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow.clone(), api_keys))
        .and(with_node_component(dp))
        .and(with_node_component(node))
        .and(with_node_component(aux_node))
        .and(with_node_component(routes_pow))
        .and(with_node_component(cache))
        .and_then(
            move |call_id: String, dp, node, aux, routes_pow: RoutesPoWInfo, cache| {
                let routes = routes_pow.lock().unwrap().clone();
                map_api_res_and_cache(
                    call_id.clone(),
                    cache,
                    handlers::get_debug_data(dp, node, aux, route, call_id, routes),
                )
            },
        )
        .with(get_cors())
}

// GET current block being mined
pub fn current_mining_block(
    dp: &mut DbgPaths,
    current_block: Arc<Mutex<Option<BlockPoWReceived>>>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "current_mining_block";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(current_block))
        .and(with_node_component(cache))
        .and_then(move |call_id: String, cb, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_current_mining_block(cb, route, call_id),
            )
        })
        .with(get_cors())
}

// GET UTXO set addresses
pub fn utxo_addresses(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "utxo_addresses";
    warp_path(dp, route)
        .and(warp::get())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(threaded_calls))
        .and(with_node_component(cache))
        .and_then(move |call_id: String, a, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::get_utxo_addresses(a, route, call_id),
            )
        })
        .with(get_cors())
}

//======= POST ROUTES =======//

// POST CORS
pub fn post_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Accept",
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Headers",
            "Content-Type",
            "x-request-id",
            "x-nonce",
            "x-api-key",
        ])
        .allow_methods(vec!["POST"])
}

// POST get db item by key
pub fn blockchain_entry_by_key(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "blockchain_entry";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_blockchain_entry_by_key(db, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST get block information by number
pub fn block_by_num(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "block_by_num";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_block_by_num(db, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST save keypair
// TODO: Requires password
pub fn import_keypairs(
    dp: &mut DbgPaths,
    db: WalletDb,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "import_keypairs";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, kp, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_import_keypairs(db, kp, route, call_id),
            )
        })
        .with(post_cors())
}

// POST make payment
pub fn make_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "make_payment";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, node, pi, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_make_payment(db, node, pi, route, call_id),
            )
        })
        .with(post_cors())
}

// POST make payment
pub fn make_ip_payment(
    dp: &mut DbgPaths,
    db: WalletDb,
    node: Node,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "make_ip_payment";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, node, pi, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_make_ip_payment(db, node, pi, route, call_id),
            )
        })
        .with(post_cors())
}

// POST request donation payment
pub fn request_donation(
    dp: &mut DbgPaths,
    node: Node,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "request_donation";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, node, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_request_donation(node, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST update running total
pub fn update_running_total(
    dp: &mut DbgPaths,
    node: Node,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "update_running_total";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, node, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_update_running_total(node, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_balance(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "fetch_balance";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, tc, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_fetch_utxo_balance(tc, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST fetch balance for addresses
pub fn fetch_pending(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "fetch_pending";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, tc, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_fetch_druid_pending(tc, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST create receipt-based asset transaction
pub fn create_receipt_asset(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "create_receipt_asset";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, tc, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_create_receipt_asset(tc, info, route, call_id),
            )
        })
        .with(post_cors())
}

/// POST create a receipt-based asset transaction on user
pub fn create_receipt_asset_user(
    dp: &mut DbgPaths,
    node: Node,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "create_receipt_asset";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(node))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, node, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_create_receipt_asset_user(node, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST change passphrase
pub fn change_passphrase(
    dp: &mut DbgPaths,
    db: WalletDb,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "change_passphrase";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_change_wallet_passphrase(db, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST create transactions
pub fn create_transactions(
    dp: &mut DbgPaths,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let route = "create_transactions";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(threaded_calls))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, tc, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_create_transactions(tc, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST check for address presence
pub fn blocks_by_tx_hashes(
    dp: &mut DbgPaths,
    db: Arc<Mutex<SimpleDb>>,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let route = "check_transaction_presence";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(with_node_component(db))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, db, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_blocks_by_tx_hashes(db, info, route, call_id),
            )
        })
        .with(post_cors())
}

// POST construct payment address
pub fn address_construction(
    dp: &mut DbgPaths,
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
    cache: ReplyCache,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let route = "address_construction";
    warp_path(dp, route)
        .and(warp::post())
        .and(auth_request(routes_pow, api_keys))
        .and(warp::body::json())
        .and(with_node_component(cache))
        .and_then(move |call_id: String, info, cache| {
            map_api_res_and_cache(
                call_id.clone(),
                cache,
                handlers::post_payment_address_construction(info, route, call_id),
            )
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
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let routes = wallet_info(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    )
    .or(make_payment(
        dp,
        db.clone(),
        node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(make_ip_payment(
        dp,
        db.clone(),
        node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(request_donation(
        dp,
        node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(export_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(import_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(update_running_total(
        dp,
        node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(create_receipt_asset_user(
        dp,
        node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(payment_address(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(change_passphrase(
        dp,
        db,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(address_construction(
        dp,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(debug_data(
        dp_vec,
        node,
        None,
        routes_pow_info,
        api_keys,
        cache,
    ));

    routes.recover(handle_rejection)
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
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let routes = block_by_num(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    )
    .or(latest_block(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(blockchain_entry_by_key(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(blocks_by_tx_hashes(
        dp,
        db,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(address_construction(
        dp,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(debug_data(
        dp_vec,
        node,
        None,
        routes_pow_info,
        api_keys,
        cache,
    ));

    routes.recover(handle_rejection)
}

// API routes for Compute nodes
pub fn compute_node_routes(
    api_keys: ApiKeys,
    routes_pow_info: RoutesPoWInfo,
    threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    node: Node,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let mut dp_vec = DbgPaths::new();
    let dp = &mut dp_vec;
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let routes = fetch_balance(
        dp,
        threaded_calls.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    )
    .or(fetch_pending(
        dp,
        threaded_calls.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(create_receipt_asset(
        dp,
        threaded_calls.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(create_transactions(
        dp,
        threaded_calls.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(utxo_addresses(
        dp,
        threaded_calls,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(address_construction(
        dp,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(debug_data(
        dp_vec,
        node,
        None,
        routes_pow_info,
        api_keys,
        cache,
    ));

    routes.recover(handle_rejection)
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
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let routes = wallet_info(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    )
    .or(export_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(import_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(payment_address(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(change_passphrase(
        dp,
        db,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(current_mining_block(
        dp,
        current_block,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(address_construction(
        dp,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(debug_data(
        dp_vec,
        node,
        None,
        routes_pow_info,
        api_keys,
        cache,
    ));

    routes.recover(handle_rejection)
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
    let cache = create_new_cache(CACHE_LIVE_TIME);

    let routes = wallet_info(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    )
    .or(make_payment(
        dp,
        db.clone(),
        user_node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(make_ip_payment(
        dp,
        db.clone(),
        user_node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(request_donation(
        dp,
        user_node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(export_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(import_keypairs(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(update_running_total(
        dp,
        user_node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(create_receipt_asset_user(
        dp,
        user_node.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(payment_address(
        dp,
        db.clone(),
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(change_passphrase(
        dp,
        db,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(current_mining_block(
        dp,
        current_block,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(address_construction(
        dp,
        routes_pow_info.clone(),
        api_keys.clone(),
        cache.clone(),
    ))
    .or(debug_data(
        dp_vec,
        miner_node,
        Some(user_node),
        routes_pow_info,
        api_keys,
        cache,
    ));

    routes.recover(handle_rejection)
}
