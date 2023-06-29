//! App to run a mining node.

use clap::{App, Arg, ArgMatches};
use config::{ConfigError, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use znp::configurations::{ExtraNodeParams, MinerNodeConfig, UserNodeConfig};
use znp::{
    loop_wait_connnect_to_peers_async, loops_re_connect_disconnect, routes, shutdown_connections,
    ResponseResult,
};
use znp::{MinerNode, UserNode};

pub async fn run_node(matches: &ArgMatches<'_>) {
    let (config, user_config) = configuration(load_settings(matches));
    println!("Start node with config {:?}", config);
    let node = MinerNode::new(config, Default::default()).await.unwrap();
    println!("Started node at {}", node.local_address());

    let miner_api_inputs = node.api_inputs();
    let shared_wallet_db = Some(node.get_wallet_db().clone());
    let (node_conn, addrs_to_connect, expected_connected_addrs) = node.connect_info_peers();
    let local_event_tx = node.local_event_tx().clone();

    // PERMANENT CONNEXION/DISCONNECTION HANDLING
    let ((conn_loop_handle, stop_re_connect_tx), (disconn_loop_handle, stop_disconnect_tx)) = {
        let (re_connect, disconnect_test) =
            loops_re_connect_disconnect(node_conn.clone(), addrs_to_connect, local_event_tx);

        (
            (tokio::spawn(re_connect.0), re_connect.1),
            (tokio::spawn(disconnect_test.0), disconnect_test.1),
        )
    };

    // Need to connect first so Raft messages can be sent.
    loop_wait_connnect_to_peers_async(node_conn.clone(), expected_connected_addrs).await;

    // Miner main loop
    let main_loop_handle = tokio::spawn({
        let mut node = node;
        let mut node_conn = node_conn;

        async move {
            node.send_startup_requests().await.unwrap();

            let mut exit = std::future::pending();
            while let Some(response) = node.handle_next_event(&mut exit).await {
                if node.handle_next_event_response(response).await == ResponseResult::Exit {
                    break;
                }
            }
            stop_re_connect_tx.send(()).unwrap();
            stop_disconnect_tx.send(()).unwrap();

            shutdown_connections(&mut node_conn).await;
        }
    });

    match user_config {
        Some(config) => {
            let shared_members = ExtraNodeParams {
                shared_wallet_db,
                ..Default::default()
            };

            println!("Start user node with config {config:?}");
            let user_node = UserNode::new(config, shared_members).await.unwrap();
            let api_inputs = (user_node.api_inputs(), miner_api_inputs);
            println!("Started user node at {}", user_node.local_address());

            let (user_node_conn, user_addrs_to_connect, user_expected_connected_addrs) =
                user_node.connect_info_peers();
            let user_local_event_tx = user_node.local_event_tx().clone();

            // PERMANENT CONNEXION/DISCONNECTION HANDLING
            let (
                (user_conn_loop_handle, user_stop_re_connect_tx),
                (user_disconn_loop_handle, user_stop_disconnect_tx),
            ) = {
                let (user_re_connect, user_disconnect_test) = loops_re_connect_disconnect(
                    user_node_conn.clone(),
                    user_addrs_to_connect,
                    user_local_event_tx,
                );

                (
                    (tokio::spawn(user_re_connect.0), user_re_connect.1),
                    (tokio::spawn(user_disconnect_test.0), user_disconnect_test.1),
                )
            };

            // Need to connect first so Raft messages can be sent.
            loop_wait_connnect_to_peers_async(
                user_node_conn.clone(),
                user_expected_connected_addrs,
            )
            .await;

            // User main loop
            let user_main_loop_handle = tokio::spawn({
                let mut node = user_node;
                let mut node_conn = user_node_conn;

                async move {
                    node.send_startup_requests().await.unwrap();

                    let mut exit = std::future::pending();
                    while let Some(response) = node.handle_next_event(&mut exit).await {
                        if node.handle_next_event_response(response).await == ResponseResult::Exit {
                            break;
                        }
                    }
                    user_stop_re_connect_tx.send(()).unwrap();
                    user_stop_disconnect_tx.send(()).unwrap();

                    shutdown_connections(&mut node_conn).await;
                }
            });

            // User / Miner combined warp API
            let warp_handle = tokio::spawn({
                let (
                    (db, user_node, api_addr, api_tls, api_keys, api_pow_info),
                    (_, miner_node, _, _, _, current_block, _),
                ) = api_inputs;

                println!("Warp API started on port {:?}", api_addr.port());
                println!();

                let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
                bind_address.set_port(api_addr.port());

                async move {
                    let serve = warp::serve(routes::miner_node_with_user_routes(
                        api_keys,
                        api_pow_info,
                        current_block,
                        db,
                        miner_node,
                        user_node,
                    ));
                    if let Some(api_tls) = api_tls {
                        serve
                            .tls()
                            .key(&api_tls.pem_pkcs8_private_keys)
                            .cert(&api_tls.pem_certs)
                            .run(bind_address)
                            .await;
                    } else {
                        serve.run(bind_address).await;
                    }
                }
            });

            let (result, result_user, conn, conn_user, disconn, disconn_user, warp_result) = tokio::join!(
                main_loop_handle,
                user_main_loop_handle,
                conn_loop_handle,
                user_conn_loop_handle,
                disconn_loop_handle,
                user_disconn_loop_handle,
                warp_handle
            );

            result.unwrap();
            conn.unwrap();
            disconn.unwrap();
            result_user.unwrap();
            conn_user.unwrap();
            disconn_user.unwrap();
            warp_result.unwrap();
        }
        None => {
            // Miner warp API
            let warp_handle = tokio::spawn({
                let (db, miner_node, api_addr, api_tls, api_keys, current_block, api_pow_info) =
                    miner_api_inputs;

                println!("Warp API started on port {:?}", api_addr.port());
                println!();

                let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
                bind_address.set_port(api_addr.port());

                async move {
                    let serve = warp::serve(routes::miner_node_routes(
                        api_keys,
                        api_pow_info,
                        current_block,
                        db,
                        miner_node,
                    ));
                    if let Some(api_tls) = api_tls {
                        serve
                            .tls()
                            .key(&api_tls.pem_pkcs8_private_keys)
                            .cert(&api_tls.pem_certs)
                            .run(bind_address)
                            .await;
                    } else {
                        serve.run(bind_address).await;
                    }
                }
            });

            let (result, conn, disconn, warp_result) = tokio::join!(
                main_loop_handle,
                conn_loop_handle,
                disconn_loop_handle,
                warp_handle
            );

            result.unwrap();
            conn.unwrap();
            disconn.unwrap();
            warp_result.unwrap();
        }
    }
}

pub fn clap_app<'a, 'b>() -> App<'a, 'b> {
    App::new("miner")
        .about("Runs a basic miner node.")
        .arg(
            Arg::with_name("self_update")
                .long("self_update")
                .help("Whether to check for new releases and perform self_update")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .help("Run the miner node using the given config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_config")
                .long("tls_config")
                .help("Use file to provide tls configuration options.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mining_api_key")
                .long("mining_api_key")
                .help("Use an API key to participate in mining.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("initial_block_config")
                .long("initial_block_config")
                .help("Run the compute node using the given initial block config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api_config")
                .long("api_config")
                .help("Use file to provide api configuration options.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api_port")
                .long("api_port")
                .help("The port to run the http API from")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api_use_tls")
                .long("api_use_tls")
                .env("ZENOTTA_API_USE_TLS")
                .help("Whether to use TLS for API: 0 to disable")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("address_aggregation_limit")
                .long("address_aggregation_limit")
                .help("Limit the amount of addresses that can be kept before aggregation is triggered")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Run the specified miner node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("with_user_index")
                .long("with_user_index")
                .help("Run the specified user node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("compute_index")
                .long("compute_index")
                .help("Endpoint index of a compute node that the miner should connect to")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("passphrase")
                .long("passphrase")
                .help("Enter a password or passphase for the encryption of the Wallet.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("address")
                .long("address")
                .help("Run node index at the given address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("with_user_address")
                .long("with_user_address")
                .help("Run the specified user node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_certificate_override")
                .long("tls_certificate_override")
                .env("ZENOTTA_TLS_CERTIFICATE")
                .help("Use PEM certificate as a string to use for this node TLS certificate.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_private_key_override")
                .long("tls_private_key_override")
                .env("ZENOTTA_TLS_PRIVATE_KEY")
                .help("Use PKCS8 private key as a string to use for this node TLS certificate.")
                .takes_value(true),
        )
}

fn load_settings(matches: &clap::ArgMatches) -> (config::Config, Option<config::Config>) {
    let mut settings = config::Config::default();
    let mut miner_index: usize = 0;
    let mut user_index: usize = 0;

    let setting_file = matches
        .value_of("config")
        .unwrap_or("src/bin/node_settings.toml");
    let tls_setting_file = matches
        .value_of("tls_config")
        .unwrap_or("src/bin/tls_certificates.json");
    let intial_block_setting_file = matches
        .value_of("initial_block_config")
        .unwrap_or("src/bin/initial_block.json");
    let api_setting_file = matches
        .value_of("api_config")
        .unwrap_or("src/bin/api_config.json");

    settings
        .set_default("api_keys", Vec::<String>::new())
        .unwrap();
    settings.set_default("miner_compute_node_idx", 0).unwrap();
    settings.set_default("miner_storage_node_idx", 0).unwrap();
    settings.set_default("user_api_port", 3000).unwrap();
    settings.set_default("miner_api_port", 3000).unwrap();
    settings.set_default("user_api_use_tls", true).unwrap();
    settings.set_default("miner_api_use_tls", true).unwrap();
    settings.set_default("user_node_idx", 0).unwrap();
    settings.set_default("user_compute_node_idx", 0).unwrap();
    settings.set_default("peer_user_node_idx", 0).unwrap();
    settings.set_default("user_auto_donate", 0).unwrap();

    settings
        .set_default(
            "user_test_auto_gen_setup",
            default_user_test_auto_gen_setup(),
        )
        .unwrap();

    settings
        .merge(config::File::with_name(setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(tls_setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(intial_block_setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(api_setting_file))
        .unwrap();

    // ======== Miner settings ========

    // If index is passed, take note of the index to set address later
    if let Some(idx) = matches.value_of("index") {
        miner_index = idx.parse::<usize>().unwrap();
        // If index is not passed, lookout if 'address' is supplied
    } else if let Some(address) = matches.value_of("address") {
        let mut node = HashMap::new();
        node.insert("address".to_owned(), address.to_owned());

        if let Ok(mut miner_nodes) = settings.get_array("miner_nodes") {
            let passed_addr_val = Value::new(None, node);

            // Check if the address is already present in the toml
            // if yes, take index from the toml
            miner_index = if miner_nodes.contains(&passed_addr_val) {
                miner_nodes
                    .iter()
                    .position(|r| r == &passed_addr_val)
                    .unwrap()
            } else {
                // if no, consider the node to be a new entry
                // hence the index will be the existing length + 1
                // which is already adjusted in the `Vec::len()` method.
                miner_nodes.push(passed_addr_val);
                miner_nodes.len() - 1
            };
        }
        settings.set("miner_address", address).unwrap();
    }

    if let Err(ConfigError::NotFound(_)) = settings.get_int("peer_limit") {
        settings.set("peer_limit", 1000).unwrap();
    }

    // Set node's address from the miner_node's map if it is not supplied as an argument
    // NOTE: Index will be defaulted to 0 if not updated in the above block
    if matches.value_of("address").is_none() {
        let miner_nodes = settings
            .get_array("miner_nodes")
            .expect("No miner_nodes entry in the TOML");
        let raw_map: &Value = miner_nodes
            .get(miner_index)
            .expect("No entry found at provided index");
        let map = raw_map.clone().into_table().unwrap();
        let addr = map.get("address").unwrap();
        settings.set("miner_address", addr.to_string()).unwrap();
    }

    let mut db_mode = settings.get_table("miner_db_mode").unwrap();
    if let Some(test_idx) = db_mode.get_mut("Test") {
        *test_idx = Value::new(None, miner_index.to_string());
        settings.set("miner_db_mode", db_mode.clone()).unwrap();
    }

    // ======== User settings ========
    // TODO: This can soon be removed/refactored due to the introduction of Transactor trait.

    let mut has_user_settings = false;

    // If index is passed, take note of the index to set address later
    if let Some(idx) = matches.value_of("with_user_index") {
        user_index = idx.parse::<usize>().unwrap();
        let db_mode = settings.get_table("miner_db_mode").unwrap();
        settings.set("user_db_mode", db_mode).unwrap();
        has_user_settings = true;
        // If index is not passed, lookout if 'address' is supplied
    } else if let Some(address) = matches.value_of("with_user_address") {
        let mut node = HashMap::new();
        node.insert("address".to_owned(), address.to_owned());

        if let Ok(mut user_nodes) = settings.get_array("user_nodes") {
            let passed_addr_val = Value::new(None, node);

            // Check if the address is already present in the toml
            // if yes, take index from the toml
            user_index = if user_nodes.contains(&passed_addr_val) {
                user_nodes
                    .iter()
                    .position(|r| r == &passed_addr_val)
                    .unwrap()
            } else {
                // if no, consider the node to be a new entry
                // hence the index will be the existing length + 1
                // which is already adjusted in the `Vec::len()` method.
                user_nodes.push(passed_addr_val);
                user_nodes.len() - 1
            };
            has_user_settings = true;
        }
    }

    if has_user_settings {
        // Index will be defaulted to 0 if not updated in the above block
        // Set node's address from the user_node's map
        let user_nodes = settings.get_array("user_nodes").unwrap();
        let raw_map: &Value = user_nodes.get(user_index).unwrap();
        let map = raw_map.clone().into_table().unwrap();
        let addr = map.get("address").unwrap();
        settings.set("user_address", addr.to_string()).unwrap();

        // Select the user_wallet_seed according to the node_index
        if let Ok(user_wallet_seeds) = settings.get_array("user_wallet_seeds") {
            settings
                .set("user_wallet_seeds", user_wallet_seeds[user_index].clone())
                .unwrap();
        }
    }

    if let Some(mining_api_key) = matches.value_of("mining_api_key") {
        settings.set("mining_api_key", mining_api_key).unwrap();
    }

    if let Some(address_aggregation_limit) = matches.value_of("address_aggregation_limit") {
        settings
            .set("address_aggregation_limit", address_aggregation_limit)
            .unwrap();
    }

    if let Some(certificate) = matches.value_of("tls_certificate_override") {
        let mut tls_config = settings.get_table("tls_config").unwrap();
        tls_config.insert(
            "pem_certificate_override".to_owned(),
            Value::new(None, certificate),
        );
        settings.set("tls_config", tls_config).unwrap();
    }
    if let Some(key) = matches.value_of("tls_private_key_override") {
        let mut tls_config = settings.get_table("tls_config").unwrap();
        tls_config.insert(
            "pem_pkcs8_private_key_override".to_owned(),
            Value::new(None, key),
        );
        settings.set("tls_config", tls_config).unwrap();
    }

    if let Some(index) = matches.value_of("compute_index") {
        settings.set("miner_compute_node_idx", index).unwrap();
        settings.set("user_compute_node_idx", index).unwrap();
    }

    if let Some(index) = matches.value_of("passphrase") {
        settings.set("passphrase", index).unwrap();
    }

    if let Some(index) = matches.value_of("storage_index") {
        settings.set("miner_storage_node_idx", index).unwrap();
    }

    // Only one API instance will run- there will be no port conflict
    if let Some(api_port) = matches.value_of("api_port") {
        settings.set("user_api_port", api_port).unwrap();
        settings.set("miner_api_port", api_port).unwrap();
    }
    if let Some(use_tls) = matches.value_of("api_use_tls") {
        settings.set("user_api_use_tls", use_tls).unwrap();
        settings.set("miner_api_use_tls", use_tls).unwrap();
    }

    let user_settings = has_user_settings.then(|| settings.clone());
    (settings, user_settings)
}

fn configuration(
    settings: (config::Config, Option<config::Config>),
) -> (MinerNodeConfig, Option<UserNodeConfig>) {
    (
        settings.0.try_into::<MinerNodeConfig>().unwrap(),
        settings.1.map(|v| v.try_into::<UserNodeConfig>().unwrap()),
    )
}

fn default_user_test_auto_gen_setup() -> HashMap<String, Value> {
    let mut value = HashMap::new();
    let zero = config::Value::new(None, 0);
    let empty = config::Value::new(None, Vec::<String>::new());
    value.insert("user_initial_transactions".to_owned(), empty);
    value.insert("user_setup_tx_chunk_size".to_owned(), zero.clone());
    value.insert("user_setup_tx_in_per_tx".to_owned(), zero.clone());
    value.insert("user_setup_tx_max_count".to_owned(), zero);
    value
}

#[cfg(test)]
mod test {
    use super::*;
    use znp::configurations::DbMode;

    type Expected = (DbMode, Option<String>);
    type UserExpected = Option<(DbMode, Option<String>)>;

    #[test]
    fn validate_startup_no_args() {
        let args = vec!["bin_name"];
        let expected = (DbMode::Test(0), None);

        validate_startup_common(args, expected, None);
    }

    #[test]
    fn validate_startup_with_user_index_1() {
        let args = vec!["bin_name", "--index=1", "--with_user_index=1"];
        let expected: Expected = (DbMode::Test(1), None);
        let user_expected: UserExpected = Some((DbMode::Test(1), None));

        validate_startup_common(args, expected, user_expected);
    }

    #[test]
    fn validate_startup_key_override() {
        // Use argument instead of std::env as env apply to all tests
        let args = vec!["bin_name", "--tls_private_key_override=42"];
        let expected = (DbMode::Test(0), Some("42".to_owned()));

        validate_startup_common(args, expected, None);
    }

    #[test]
    fn validate_startup_key_override_with_user_index_1() {
        // Use argument instead of std::env as env apply to all tests
        let args = vec![
            "bin_name",
            "--index=1",
            "--tls_private_key_override=42",
            "--with_user_index=1",
        ];
        let expected: Expected = (DbMode::Test(1), Some("42".to_owned()));
        let user_expected: UserExpected = Some((DbMode::Test(1), Some("42".to_owned())));
        validate_startup_common(args, expected, user_expected);
    }

    #[test]
    fn validate_startup_aws() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_aws.toml",
            "--initial_block_config=src/bin/initial_block_aws.json",
            "--with_user_index=0",
        ];
        let expected = (DbMode::Live, None);
        let user_expected: UserExpected = Some((DbMode::Live, None));

        validate_startup_common(args, expected, user_expected);
    }

    #[test]
    fn validate_startup_raft_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_1.toml",
        ];
        let expected = (DbMode::Test(0), None);

        validate_startup_common(args, expected, None);
    }

    #[test]
    fn validate_startup_raft_2_index_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_2.toml",
            "--index=1",
        ];
        let expected = (DbMode::Test(1), None);

        validate_startup_common(args, expected, None);
    }

    #[test]
    fn validate_startup_raft_3() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_1.toml",
        ];
        let expected = (DbMode::Test(0), None);

        validate_startup_common(args, expected, None);
    }

    fn validate_startup_common(args: Vec<&str>, expected: Expected, user_expected: UserExpected) {
        //
        // Act
        //
        let app = clap_app();
        let matches = app.get_matches_from_safe(args.into_iter()).unwrap();
        let settings = load_settings(&matches);
        let config = configuration(settings);

        //
        // Assert
        //
        let (expected_mode, expected_key) = expected;
        assert_eq!(config.0.miner_db_mode, expected_mode);
        assert_eq!(
            config.0.tls_config.pem_pkcs8_private_key_override,
            expected_key
        );
        match user_expected {
            Some((user_expected_mode, user_expected_key)) => {
                let user_config = config.1.unwrap();
                assert_eq!(user_config.user_db_mode, user_expected_mode);
                assert_eq!(
                    user_config.tls_config.pem_pkcs8_private_key_override,
                    user_expected_key
                );
            }
            None => assert!(config.1.is_none()),
        }
    }
}
