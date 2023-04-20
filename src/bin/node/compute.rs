//! App to run a compute node.

use clap::{App, Arg, ArgMatches};
use std::net::SocketAddr;
use system::configurations::ComputeNodeConfig;
use system::ComputeNode;
use system::{
    get_sanction_addresses, loop_wait_connnect_to_peers_async, loops_re_connect_disconnect, routes,
    shutdown_connections, ResponseResult, SANC_LIST_PROD,
};

pub async fn run_node(matches: &ArgMatches<'_>) {
    let mut config = configuration(load_settings(matches));

    println!("Start node with config {config:?}");

    config.sanction_list = get_sanction_addresses(SANC_LIST_PROD.to_string(), &config.jurisdiction);
    let node = ComputeNode::new(config, Default::default()).await.unwrap();
    let api_inputs = node.api_inputs();

    println!("API Inputs: {api_inputs:?}");
    println!("Started node at {}", node.local_address());

    let (node_conn, addrs_to_connect, expected_connected_addrs) = node.connect_info_peers();
    let local_event_tx = node.local_event_tx().clone();
    let threaded_calls_tx = node.threaded_call_tx().clone();

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
    println!("Raft and Storage connection complete");

    // RAFT HANDLING
    let raft_loop_handle = {
        let raft_loop = node.raft_loop();
        tokio::spawn(async move {
            println!("Peer connect complete, start Raft");
            raft_loop.await;
            println!("Raft complete");
        })
    };

    // Warp API
    let warp_handle = tokio::spawn({
        let (api_addr, api_tls, api_keys, routes_pow, peer) = api_inputs;
        let threaded_calls_tx = threaded_calls_tx;

        println!("Warp API started on port {:?}", api_addr.port());
        println!();

        let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        bind_address.set_port(api_addr.port());

        async move {
            let serve = warp::serve(routes::compute_node_routes(
                api_keys,
                routes_pow,
                threaded_calls_tx,
                peer,
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

            node.close_raft_loop().await;
            shutdown_connections(&mut node_conn).await;
        }
    });

    let (main, warp, raft, conn, disconn) = tokio::join!(
        main_loop_handle,
        warp_handle,
        raft_loop_handle,
        conn_loop_handle,
        disconn_loop_handle
    );
    main.unwrap();
    warp.unwrap();
    raft.unwrap();
    conn.unwrap();
    disconn.unwrap();
}

pub fn clap_app<'a, 'b>() -> App<'a, 'b> {
    App::new("compute")
        .about("Runs a basic compute node.")
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .help("Run the compute node using the given config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_config")
                .long("tls_config")
                .help("Use file to provide tls configuration options.")
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
            Arg::with_name("initial_block_config")
                .long("initial_block_config")
                .help("Run the compute node using the given initial block config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Run the specified compute node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_private_key_override")
                .long("tls_private_key_override")
                .env("ZENOTTA_TLS_PRIVATE_KEY")
                .help("Use PKCS8 private key as a string to use for this node TLS certificate.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable_pipeline_reset")
                .long("enable_pipeline_reset")
                .help(
                    "Enable the compute node to vote for a pipeline reset if it should get stuck.",
                )
                .takes_value(true),
        )
}

fn load_settings(matches: &clap::ArgMatches) -> config::Config {
    let mut settings = config::Config::default();
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
        .set_default("sanction_list", Vec::<String>::new())
        .unwrap();
    settings
        .set_default("api_keys", Vec::<String>::new())
        .unwrap();
    settings.set_default("compute_api_port", 3002).unwrap();
    settings.set_default("compute_api_use_tls", true).unwrap();
    settings.set_default("jurisdiction", "US").unwrap();
    settings.set_default("compute_node_idx", 0).unwrap();
    settings.set_default("compute_raft", 0).unwrap();

    settings
        .set_default("compute_raft_tick_timeout", 10)
        .unwrap();
    settings
        .set_default("compute_transaction_timeout", 100)
        .unwrap();
    settings
        .set_default("compute_mining_event_timeout", 500)
        .unwrap();
    settings
        .set_default("enable_pipeline_reset", false)
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

    if let Some(port) = matches.value_of("api_port") {
        settings.set("compute_api_port", port).unwrap();
    }
    if let Some(use_tls) = matches.value_of("api_use_tls") {
        settings.set("compute_api_use_tls", use_tls).unwrap();
    }
    if let Some(enable_pipeline_reset) = matches.value_of("enable_pipeline_reset") {
        settings
            .set(
                "enable_trigger_messages_pipeline_reset",
                enable_pipeline_reset,
            )
            .unwrap();
    }

    if let Some(index) = matches.value_of("index") {
        settings.set("compute_node_idx", index).unwrap();
        let mut db_mode = settings.get_table("compute_db_mode").unwrap();
        if let Some(test_idx) = db_mode.get_mut("Test") {
            *test_idx = config::Value::new(None, index);
            settings.set("compute_db_mode", db_mode).unwrap();
        }
    }

    if let Some(key) = matches.value_of("tls_private_key_override") {
        let mut tls_config = settings.get_table("tls_config").unwrap();
        tls_config.insert(
            "pem_pkcs8_private_key_override".to_owned(),
            config::Value::new(None, key),
        );
        settings.set("tls_config", tls_config).unwrap();
    }

    settings
}

fn configuration(settings: config::Config) -> ComputeNodeConfig {
    settings.try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use system::configurations::DbMode;

    type Expected = (DbMode, Option<String>);

    #[test]
    fn validate_startup_no_args() {
        let args = vec!["bin_name"];
        let expected = (DbMode::Test(0), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_key_override() {
        // Use argument instead of std::env as env apply to all tests
        let args = vec!["bin_name", "--tls_private_key_override=42"];
        let expected = (DbMode::Test(0), Some("42".to_owned()));

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
        let expected = (DbMode::Test(0), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_raft_2_index_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_2.toml",
            "--index=1",
        ];
        let expected = (DbMode::Test(1), None);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_raft_3() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_1.toml",
        ];
        let expected = (DbMode::Test(0), None);

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
        assert_eq!(config.compute_db_mode, expected_mode);
        assert_eq!(
            config.tls_config.pem_pkcs8_private_key_override,
            expected_key
        );
    }
}
