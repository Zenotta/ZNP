//! App to run a user node.

use clap::{App, Arg, ArgMatches};
use config::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use system::configurations::UserNodeConfig;
use system::{
    loop_wait_connnect_to_peers_async, loops_re_connect_disconnect, routes, shutdown_connections,
    ResponseResult, UserNode,
};

pub async fn run_node(matches: &ArgMatches<'_>) {
    let config = configuration(load_settings(matches));

    println!("Starting node with config: {config:?}");
    println!();

    let node = UserNode::new(config, Default::default()).await.unwrap();

    println!("Started node at {}", node.local_address());

    let (node_conn, addrs_to_connect, expected_connected_addrs) = node.connect_info_peers();
    let local_event_tx = node.local_event_tx().clone();
    let api_inputs = node.api_inputs();

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

    // REQUEST HANDLING
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

    // Warp API
    let warp_handle = tokio::spawn({
        let (db, node, api_addr, api_tls, api_keys, api_pow_info) = api_inputs;

        println!("Warp API started on port {:?}", api_addr.port());
        println!();

        let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        bind_address.set_port(api_addr.port());

        async move {
            let serve = warp::serve(routes::user_node_routes(api_keys, api_pow_info, db, node));
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

    let (main_result, warp_result, conn, disconn) = tokio::join!(
        main_loop_handle,
        warp_handle,
        conn_loop_handle,
        disconn_loop_handle
    );
    main_result.unwrap();
    warp_result.unwrap();
    conn.unwrap();
    disconn.unwrap();
}

pub fn clap_app<'a, 'b>() -> App<'a, 'b> {
    App::new("user")
        .about("Runs a basic User node.")
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .help("Run the user node using the given config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_config")
                .long("tls_config")
                .help("Use file to provide tls configuration options.")
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
            Arg::with_name("auto_donate")
                .long("auto_donate")
                .help("The amount of tokens to send any requester")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Run the specified user node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("compute_index")
                .long("compute_index")
                .help("Endpoint index of a compute node that the user should connect to")
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

fn load_settings(matches: &clap::ArgMatches) -> config::Config {
    let mut settings = config::Config::default();
    let mut node_index = 0;
    let setting_file = matches
        .value_of("config")
        .unwrap_or("src/bin/node_settings.toml");
    let intial_block_setting_file = matches
        .value_of("initial_block_config")
        .unwrap_or("src/bin/initial_block.json");
    let tls_setting_file = matches
        .value_of("tls_config")
        .unwrap_or("src/bin/tls_certificates.json");
    let api_setting_file = matches
        .value_of("api_config")
        .unwrap_or("src/bin/api_config.json");

    settings
        .set_default("api_keys", Vec::<String>::new())
        .unwrap();
    settings.set_default("user_api_port", 3000).unwrap();
    settings.set_default("user_api_use_tls", true).unwrap();
    settings.set_default("user_compute_node_idx", 0).unwrap();
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
        .merge(config::File::with_name(intial_block_setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(tls_setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(api_setting_file))
        .unwrap();

    // If index is passed, take note of the index to set address later
    if let Some(idx) = matches.value_of("index") {
        node_index = idx.parse::<usize>().unwrap();
    // If index is not passed, lookout if 'address' is supplied
    } else if let Some(address) = matches.value_of("address") {
        let mut node = HashMap::new();
        node.insert("address".to_owned(), address.to_owned());

        if let Ok(mut user_nodes) = settings.get_array("user_nodes") {
            let passed_addr_val = Value::new(None, node);

            // Check if the address is already present in the toml
            // if yes, take index from the toml
            node_index = if user_nodes.contains(&passed_addr_val) {
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
        }
        settings.set("user_address", address).unwrap();
    }

    // Set node's address from the user_node's map if it is not supplied as an argument
    // NOTE: Index will be defaulted to 0 if not updated in the above block
    if matches.value_of("address").is_none() {
        let user_nodes = settings
            .get_array("user_nodes")
            .expect("No 'user_nodes' entry in the TOML");
        let raw_map: &Value = user_nodes.get(node_index).unwrap();
        let map = raw_map.clone().into_table().unwrap();
        let addr = map.get("address").unwrap();
        settings.set("user_address", addr.to_string()).unwrap();
    }

    let mut db_mode = settings.get_table("user_db_mode").unwrap();
    if let Some(test_idx) = db_mode.get_mut("Test") {
        let index = node_index + test_idx.clone().try_into::<usize>().unwrap();
        *test_idx = Value::new(None, index.to_string());
        settings.set("user_db_mode", db_mode).unwrap();
    }

    // Select the user_wallet_seed according to the node_index
    if let Ok(user_wallet_seeds) = settings.get_array("user_wallet_seeds") {
        settings
            .set("user_wallet_seeds", user_wallet_seeds[node_index].clone())
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

    if let Some(api_port) = matches.value_of("api_port") {
        settings.set("user_api_port", api_port).unwrap();
    }

    if let Some(index) = matches.value_of("compute_index") {
        settings.set("user_compute_node_idx", index).unwrap();
    }

    if let Some(index) = matches.value_of("passphrase") {
        settings.set("passphrase", index).unwrap();
    }

    if let Some(api_port) = matches.value_of("auto_donate") {
        settings.set("user_auto_donate", api_port).unwrap();
    }
    if let Some(use_tls) = matches.value_of("api_use_tls") {
        settings.set("user_api_use_tls", use_tls).unwrap();
    }

    settings
}

fn configuration(settings: config::Config) -> UserNodeConfig {
    settings.try_into().unwrap()
}

fn default_user_test_auto_gen_setup() -> HashMap<String, Value> {
    let mut value = HashMap::new();
    let zero = Value::new(None, 0);
    let empty = Value::new(None, Vec::<String>::new());
    value.insert("user_initial_transactions".to_owned(), empty);
    value.insert("user_setup_tx_chunk_size".to_owned(), zero.clone());
    value.insert("user_setup_tx_in_per_tx".to_owned(), zero.clone());
    value.insert("user_setup_tx_max_count".to_owned(), zero);
    value
}

#[cfg(test)]
mod test {
    use super::*;
    use system::configurations::DbMode;

    type Expected = (DbMode, Option<String>);

    #[test]
    fn validate_startup_no_args() {
        let args = vec!["bin_name"];
        let expected = (DbMode::Test(1000), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_key_override() {
        // Use argument instead of std::env as env apply to all tests
        let args = vec!["bin_name", "--tls_private_key_override=42"];
        let expected = (DbMode::Test(1000), Some("42".to_owned()));

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_aws() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_aws.toml",
            "--initial_block_config=src/bin/initial_block_aws.json",
        ];
        let expected = (DbMode::Live, None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_raft_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_1.toml",
        ];
        let expected = (DbMode::Test(1000), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_raft_2_index_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_2.toml",
            "--index=1",
        ];
        let expected = (DbMode::Test(1001), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_raft_3() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_1.toml",
        ];
        let expected = (DbMode::Test(1000), None);

        validate_startup_common(args, expected);
    }

    fn validate_startup_common(args: Vec<&str>, expected: Expected) {
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
        assert_eq!(config.user_db_mode, expected_mode);
        assert_eq!(
            config.tls_config.pem_pkcs8_private_key_override,
            expected_key
        );
    }
}
