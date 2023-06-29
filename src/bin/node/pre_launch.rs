//! App to run a pre-launch node.

use clap::{App, Arg, ArgMatches};
use config::ConfigError;
use znp::configurations::PreLaunchNodeConfig;
use znp::PreLaunchNode;
use znp::{
    loop_wait_connnect_to_peers_async, loops_re_connect_disconnect, shutdown_connections,
    ResponseResult,
};

pub async fn run_node(matches: &ArgMatches<'_>) {
    let config = configuration(load_settings(matches));

    println!("Start node with config {config:?}");
    let node = PreLaunchNode::new(config, Default::default())
        .await
        .unwrap();

    println!("Started node at {}", node.local_address());

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

    let (main, conn, disconn) =
        tokio::join!(main_loop_handle, conn_loop_handle, disconn_loop_handle);

    main.unwrap();
    conn.unwrap();
    disconn.unwrap();
}

pub fn clap_app<'a, 'b>() -> App<'a, 'b> {
    App::new("pre_launch")
        .about("Runs a pre_launch node.")
        .arg(
            Arg::with_name("self_update")
                .long("self_update")
                .help("Whether to check for new releases and perform self_update")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .help("Run the storage node using the given config file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls_config")
                .long("tls_config")
                .help("Use file to provide tls configuration options.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Run the specified storage node index from config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("type")
                .long("type")
                .help("Run the upgrade for type (compute, storage)")
                .takes_value(true)
                .required(true),
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
    let setting_file = matches
        .value_of("config")
        .unwrap_or("src/bin/node_settings.toml");
    let tls_setting_file = matches
        .value_of("tls_config")
        .unwrap_or("src/bin/tls_certificates.json");

    settings.set_default("storage_node_idx", 0).unwrap();
    settings.set_default("compute_node_idx", 0).unwrap();

    settings
        .merge(config::File::with_name(setting_file))
        .unwrap();
    settings
        .merge(config::File::with_name(tls_setting_file))
        .unwrap();

    if let Err(ConfigError::NotFound(_)) = settings.get_int("peer_limit") {
        settings.set("peer_limit", 1000).unwrap();
    }

    if let Some(index) = matches.value_of("index") {
        settings.set("compute_node_idx", index).unwrap();
        let mut db_mode = settings.get_table("compute_db_mode").unwrap();
        if let Some(test_idx) = db_mode.get_mut("Test") {
            *test_idx = config::Value::new(None, index);
            settings.set("compute_db_mode", db_mode).unwrap();
        }

        settings.set("storage_node_idx", index).unwrap();
        let mut db_mode = settings.get_table("storage_db_mode").unwrap();
        if let Some(test_idx) = db_mode.get_mut("Test") {
            *test_idx = config::Value::new(None, index);
            settings.set("storage_db_mode", db_mode).unwrap();
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

    {
        let node_type = match matches.value_of("type").unwrap() {
            "compute" => "Compute",
            "storage" => "Storage",
            v => panic!("expect type compute or storage: {}", v),
        };
        settings.set("node_type", node_type).unwrap();
    }

    settings
}

fn configuration(settings: config::Config) -> PreLaunchNodeConfig {
    settings.try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use znp::configurations::{DbMode, PreLaunchNodeType};

    type Expected = (DbMode, Option<String>, PreLaunchNodeType);

    #[test]
    fn validate_startup_compute() {
        let args = vec!["bin_name", "--type=compute"];
        let expected = (DbMode::Test(0), None, PreLaunchNodeType::Compute);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_storage() {
        let args = vec!["bin_name", "--type=storage"];
        let expected = (DbMode::Test(0), None, PreLaunchNodeType::Storage);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_key_override() {
        // Use argument instead of std::env as env apply to all tests
        let args = vec![
            "bin_name",
            "--type=storage",
            "--tls_private_key_override=42",
        ];
        let expected = (
            DbMode::Test(0),
            Some("42".to_owned()),
            PreLaunchNodeType::Storage,
        );

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_compute_index_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_2.toml",
            "--type=compute",
            "--index=1",
        ];
        let expected = (DbMode::Test(1), None, PreLaunchNodeType::Compute);

        validate_startup_common(args, expected);
    }

    #[test]
    fn validate_startup_storage_index_1() {
        let args = vec![
            "bin_name",
            "--config=src/bin/node_settings_local_raft_2.toml",
            "--type=storage",
            "--index=1",
        ];
        let expected = (DbMode::Test(1), None, PreLaunchNodeType::Storage);

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
        let (expected_mode, expected_key, expected_type) = expected;
        assert_eq!(config.storage_db_mode, expected_mode);
        assert_eq!(config.compute_db_mode, expected_mode);
        assert_eq!(
            config.tls_config.pem_pkcs8_private_key_override,
            expected_key
        );
        assert_eq!(config.node_type, expected_type);
    }
}
