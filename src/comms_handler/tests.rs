//! Tests for peer-to-peer communication.

use super::{CommsError, Event, Node, TcpTlsConfig};
use crate::constants::NETWORK_VERSION;
use crate::interfaces::NodeType;
use crate::test_utils::{get_bound_common_tls_configs, get_common_tls_config, get_test_tls_spec};
use crate::utils::tracing_log_try_init;
use bincode::deserialize;
use futures::future::join_all;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time;
use tracing::debug;

const TIMEOUT_TEST_WAIT_DURATION: Duration = Duration::from_millis(5000);

/// Check that 2 nodes can exchange arbitrary messages in both direction,
/// using their public address after one node connected to the other.
#[tokio::test(flavor = "current_thread")]
async fn direct_messages() {
    let _ = tracing_log_try_init();

    let mut nodes = create_compute_nodes(2, 2).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, _) = tail.split_first_mut().unwrap();

    n2.connect_to(n1.address()).await.unwrap();
    n2.send(n1.address(), "Hello1").await.unwrap();
    n1.send(n2.address(), "Hello2").await.unwrap();

    if let Some(Event::NewFrame { peer: _, frame }) = n1.next_event().await {
        let recv_frame: &str = deserialize(&frame).unwrap();
        assert_eq!(recv_frame, "Hello1");
    }
    if let Some(Event::NewFrame { peer: _, frame }) = n2.next_event().await {
        let recv_frame: &str = deserialize(&frame).unwrap();
        assert_eq!(recv_frame, "Hello2");
    }

    complete_compute_nodes(nodes).await;
}

/// Check that 2 prelaunch nodes can exchange arbitrary messages in both direction,
/// using their public address after one node connected to the other.
#[tokio::test(flavor = "current_thread")]
async fn direct_prelaunch_messages() {
    let _ = tracing_log_try_init();

    let mut nodes = create_compute_nodes(0, 2).await;
    nodes.push(create_node_type_version(2, NodeType::PreLaunch, NETWORK_VERSION).await);
    nodes.push(create_node_type_version(2, NodeType::PreLaunch, NETWORK_VERSION).await);
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, _) = tail.split_first_mut().unwrap();

    n2.connect_to(n1.address()).await.unwrap();
    n2.send(n1.address(), "Hello1").await.unwrap();
    n1.send(n2.address(), "Hello2").await.unwrap();

    if let Some(Event::NewFrame { peer: _, frame }) = n1.next_event().await {
        let recv_frame: &str = deserialize(&frame).unwrap();
        assert_eq!(recv_frame, "Hello1");
    }
    if let Some(Event::NewFrame { peer: _, frame }) = n2.next_event().await {
        let recv_frame: &str = deserialize(&frame).unwrap();
        assert_eq!(recv_frame, "Hello2");
    }

    complete_compute_nodes(nodes).await;
}

/// In this test, we
/// 1. Start N nodes (e.g., N = 64).
/// 2. node_1 will send a multicast message to F (= Fanout, e.g. 8) nodes.
/// 3. Everyone connects to node_1, and the contact list should be propagated to all other nodes.
/// 4. We check that all other nodes (node_2, node_3, ... node_N) have received the same message.
#[tokio::test(flavor = "current_thread")]
async fn multicast() {
    let _ = tracing_log_try_init();

    // Initialize nodes.
    let mut nodes = create_compute_nodes(16, 16).await;
    nodes
        .iter_mut()
        .for_each(|n| n.set_connect_to_handshake_contacts(true));

    // Connect everyone in a ring.
    let first_node = nodes[0].address();
    let mut conn_handles = Vec::new();

    for (i, node) in nodes.iter().enumerate().skip(1) {
        let mut node = node.clone();

        conn_handles.push(tokio::spawn(async move {
            node.connect_to(first_node).await.unwrap();
            debug!(?i, "connected");
        }));
    }

    join_all(conn_handles).await;

    // Send a multicast message.
    nodes[0].multicast("Hello").await.unwrap();

    // Verify that all other nodes have received the message
    for (i, node) in nodes.iter_mut().enumerate().skip(1) {
        match time::timeout(TIMEOUT_TEST_WAIT_DURATION, node.next_event()).await {
            Ok(Some(Event::NewFrame { peer: _, frame })) => {
                debug!(?i, "received");

                let recv_frame: &str = deserialize(&frame).unwrap();
                assert_eq!(recv_frame, "Hello");
            }
            Ok(None) => {
                panic!("Channel disconnected {}", i);
            }
            Err(_) => {
                panic!("Timeout elapsed {}", i);
            }
        }
    }

    complete_compute_nodes(nodes).await;
}

/// Check that 2 nodes connected node are disconnected once one of them disconnect.
#[tokio::test(flavor = "current_thread")]
async fn disconnect_connection_all() {
    disconnect_connection(false).await;
}

/// Check that 2 nodes connected node are disconnected once one of them disconnect.
#[tokio::test(flavor = "current_thread")]
async fn disconnect_connection_some() {
    disconnect_connection(true).await;
}

async fn disconnect_connection(subset: bool) {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let mut nodes = create_compute_nodes(3, 2).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();
    n2.connect_to(n1.address()).await.unwrap();
    n3.connect_to(n1.address()).await.unwrap();

    //
    // Act
    //
    let (actual2, actual3) = {
        let mut joins = Vec::new();
        let subset = if subset {
            Some(vec![n3.address()])
        } else {
            joins.append(&mut n2.take_join_handle(n1.address()).await);
            None
        };
        joins.append(&mut n3.take_join_handle(n1.address()).await);
        joins.append(&mut n1.disconnect_all(subset.as_deref()).await);
        join_all(joins.into_iter()).await;

        let actual2_1 = n2.send(n1.address(), "Hello1_2").await;
        let actual1_2 = n1.send(n2.address(), "Hello2_1").await;
        let actual3_1 = n3.send(n1.address(), "Hello1_3").await;
        let actual1_3 = n1.send(n3.address(), "Hello3_1").await;

        ((actual2_1, actual1_2), (actual3_1, actual1_3))
    };

    //
    // Assert
    //
    let success2 = if subset {
        matches!(actual2, (Ok(_), Ok(_)),)
    } else {
        matches!(
            actual2,
            (
                Err(CommsError::PeerNotFound(_)),
                Err(CommsError::PeerNotFound(_))
            )
        )
    };
    let success3 = matches!(
        actual3,
        (
            Err(CommsError::PeerNotFound(_)),
            Err(CommsError::PeerNotFound(_))
        ),
    );
    assert!(success2 && success3, "{:?}", (actual2, actual3));

    complete_compute_nodes(nodes).await;
}

/// Check a node cannot connect to a node that stopped listening.
#[tokio::test(flavor = "current_thread")]
async fn listen_paused_resumed_stopped() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let mut nodes = create_compute_nodes(3, 3).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    n1.set_pause_listening(true).await;
    let actual_paused_to = n2.connect_to(n1.address()).await;
    let actual_paused_from = n1.connect_to(n2.address()).await;
    n1.set_pause_listening(false).await;
    let actual_resumed = n2.connect_to(n1.address()).await;

    join_all(n1.stop_listening().await).await;
    let actual_stopped = n3.connect_to(n1.address()).await;

    //
    // Assert
    //
    let actual = (
        actual_paused_to,
        actual_paused_from,
        actual_resumed,
        actual_stopped,
    );
    assert!(
        matches!(
            actual,
            (
                Err(CommsError::PeerNotFound(_)),
                Err(CommsError::PeerNotFound(_)),
                Ok(_),
                Err(CommsError::Io(_))
            )
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_full_from() {
    connect_full(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_full_to() {
    connect_full(false).await;
}

/// Check behaviour when peer list is full.
async fn connect_full(from_full: bool) {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let mut nodes = create_compute_nodes(3, 1).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    let conn_error = if from_full {
        n1.connect_to(n2.address()).await.unwrap();
        let err = n1.connect_to(n3.address()).await;
        let is_expected = matches!(err, Err(CommsError::PeerListFull));
        (err, is_expected)
    } else {
        n2.connect_to(n1.address()).await.unwrap();
        let err = n3.connect_to(n1.address()).await;
        let is_expected = matches!(err, Err(CommsError::PeerNotFound(_)));
        (err, is_expected)
    };

    let actual3_1 = n3.send(n1.address(), "Hello3_1").await;
    let actual1_3 = n1.send(n3.address(), "Hello1_3").await;

    let actual2_1 = n2.send(n1.address(), "Hello2_1").await;
    let actual1_2 = n1.send(n2.address(), "Hello1_2").await;

    //
    // Assert
    //
    let actual = (conn_error, actual3_1, actual1_3, actual2_1, actual1_2);
    assert!(
        matches!(
            actual,
            (
                (Err(_), true),
                Err(CommsError::PeerNotFound(_)),
                Err(CommsError::PeerNotFound(_)),
                Ok(()),
                Ok(()),
            ),
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

/// Check incompatible nodes who cannot establish connections.
#[tokio::test(flavor = "current_thread")]
async fn nodes_incompatible() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let mut nodes = create_compute_nodes(1, 4).await;
    nodes.push(create_compute_node_version(4, NETWORK_VERSION + 1).await);
    nodes.push(create_node_type_version(4, NodeType::PreLaunch, NETWORK_VERSION).await);
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    let actual_c1_2 = n1.connect_to(n2.address()).await;
    let actual_c2_1 = n2.connect_to(n1.address()).await;
    let actual_c1_3 = n1.connect_to(n3.address()).await;
    let actual_c3_1 = n3.connect_to(n1.address()).await;
    let actual_s1_2 = n1.send(n2.address(), "Hello2").await;
    let actual_s2_1 = n2.send(n1.address(), "Hello1").await;
    let actual_s1_3 = n1.send(n3.address(), "Hello4").await;
    let actual_s3_1 = n3.send(n1.address(), "Hello3").await;

    //
    // Assert
    //
    let actual = (
        (actual_c1_2, actual_c2_1, actual_s1_2, actual_s2_1),
        (actual_c1_3, actual_c3_1, actual_s1_3, actual_s3_1),
    );
    assert!(
        matches!(
            actual,
            (
                (
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_))
                ),
                (
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_))
                )
            )
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

/// Check nodes who cannot establish connections because of unexpected certificates.
#[tokio::test(flavor = "current_thread")]
async fn nodes_tls_mismatch() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let configs =
        get_bound_common_tls_configs(&["compute1", "compute2", "compute3"], |name, mut s| {
            if name == "compute1.zenotta.xyz" {
                let mapping = &mut s.socket_name_mapping;
                let key1 = find_key_with_value(mapping, "compute2.zenotta.xyz").unwrap();
                let key2 = find_key_with_value(mapping, "compute3.zenotta.xyz").unwrap();
                swap_map_values(mapping, &key1, &key2);
            }
            s
        })
        .await;
    let mut nodes = create_config_compute_nodes(configs, 4).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    let actual_c1_2 = n1.connect_to(n2.address()).await;
    let actual_c2_1 = n2.connect_to(n1.address()).await;
    let actual_c2_3 = n2.connect_to(n3.address()).await;
    let actual_s1_2 = n1.send(n2.address(), "Hello2").await;
    let actual_s2_1 = n2.send(n1.address(), "Hello1").await;
    let actual_s2_3 = n2.send(n3.address(), "Hello4").await;

    //
    // Assert
    //
    let actual = (
        (actual_c1_2, actual_c2_1, actual_s1_2, actual_s2_1),
        (actual_c2_3, actual_s2_3),
    );
    assert!(
        matches!(
            actual,
            (
                (
                    Err(CommsError::Io(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_))
                ),
                (Ok(_), Ok(_))
            )
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

/// Check nodes who cannot establish connections because of unexpected root certificates.
#[tokio::test(flavor = "current_thread")]
async fn nodes_tls_ca_mismatch() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let configs =
        get_bound_common_tls_configs(&["compute1", "compute2", "miner101"], |name, mut s| {
            match name {
                "compute1.zenotta.xyz" => {
                    debug!("Socket Mapping: {:?}", &s.socket_name_mapping);
                    let untrusted_names = s.untrusted_names.as_mut().unwrap();
                    untrusted_names.insert("ca_root.zenotta.xyz".to_owned());
                }
                "compute2.zenotta.xyz" => {
                    let untrusted_names = s.untrusted_names.as_mut().unwrap();
                    untrusted_names.remove("miner101.zenotta.xyz");
                    s.pem_certificates.remove("miner101.zenotta.xyz");
                }
                _ => (),
            }
            s
        })
        .await;
    let mut nodes = create_config_compute_nodes(configs, 4).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    let actual_c1_3 = n1.connect_to(n3.address()).await;
    let actual_c3_1 = n3.connect_to(n1.address()).await;
    let actual_c2_3 = n2.connect_to(n3.address()).await;
    let actual_c3_2 = n3.connect_to(n2.address()).await;
    let actual_s1_3 = n1.send(n3.address(), "Hello2").await;
    let actual_s3_1 = n3.send(n1.address(), "Hello1").await;
    let actual_s2_3 = n2.send(n3.address(), "Hello4").await;
    let actual_s3_2 = n3.send(n2.address(), "Hello3").await;

    //
    // Assert
    //
    let actual = (
        (actual_c1_3, actual_c3_1, actual_s1_3, actual_s3_1),
        (actual_c2_3, actual_c3_2, actual_s2_3, actual_s3_2),
    );
    assert!(
        matches!(
            actual,
            (
                (
                    Err(CommsError::Io(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_))
                ),
                (Ok(_), Err(CommsError::PeerInvalidState(_)), Ok(_), Ok(_))
            )
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

/// Check nodes who cannot establish connections because of unexpected root certificates.
#[tokio::test(flavor = "current_thread")]
async fn nodes_tls_ca_unmapped_mismatch() {
    let _ = tracing_log_try_init();

    //
    // Arrange
    //
    let configs = {
        let mut configs = Vec::new();
        let tls_spec = get_test_tls_spec();
        for (address, name) in [
            ("127.0.0.1:12515", "node101.zenotta.xyz"),
            ("127.0.0.1:12520", "miner101.zenotta.xyz"),
            ("127.0.0.1:12530", "miner102.zenotta.xyz"),
        ]
        .iter()
        {
            let address = address.parse::<SocketAddr>().unwrap();

            let mut mapping = BTreeMap::new();
            mapping.insert(address, name.to_string());

            let tls_spec = tls_spec.make_tls_spec(&mapping);
            configs.push(TcpTlsConfig::from_tls_spec(address, &tls_spec).unwrap());
        }
        configs
    };
    let mut nodes = create_config_compute_nodes(configs, 4).await;
    let (n1, tail) = nodes.split_first_mut().unwrap();
    let (n2, tail) = tail.split_first_mut().unwrap();
    let (n3, _) = tail.split_first_mut().unwrap();

    //
    // Act
    //
    let actual_c1_3 = n1.connect_to(n3.address()).await;
    let actual_c3_1 = n3.connect_to(n1.address()).await;
    let actual_c2_3 = n2.connect_to(n3.address()).await;
    let actual_c3_2 = n3.connect_to(n2.address()).await;
    let actual_s1_3 = n1.send(n3.address(), "Hello2").await;
    let actual_s3_1 = n3.send(n1.address(), "Hello1").await;
    let actual_s2_3 = n2.send(n3.address(), "Hello4").await;
    let actual_s3_2 = n3.send(n2.address(), "Hello3").await;

    //
    // Assert
    //
    let actual = (
        (actual_c1_3, actual_c3_1, actual_s1_3, actual_s3_1),
        (actual_c2_3, actual_c3_2, actual_s2_3, actual_s3_2),
    );
    assert!(
        matches!(
            actual,
            (
                (
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::Io(_)),
                    Err(CommsError::PeerNotFound(_)),
                    Err(CommsError::PeerNotFound(_))
                ),
                (Ok(_), Err(CommsError::PeerInvalidState(_)), Ok(_), Ok(_))
            )
        ),
        "{:?}",
        "{actual:?}"
    );

    complete_compute_nodes(nodes).await;
}

async fn create_compute_nodes(num_nodes: usize, peer_limit: usize) -> Vec<Node> {
    let configs = std::iter::repeat_with(get_common_tls_config)
        .take(num_nodes)
        .collect();
    create_config_compute_nodes(configs, peer_limit).await
}

async fn create_config_compute_nodes(configs: Vec<TcpTlsConfig>, peer_limit: usize) -> Vec<Node> {
    let mut nodes = Vec::new();
    for tcp_tls_config in configs {
        nodes.push(
            Node::new(&tcp_tls_config, peer_limit, NodeType::Compute, false)
                .await
                .unwrap(),
        );
    }
    nodes
}

async fn create_compute_node_version(peer_limit: usize, network_version: u32) -> Node {
    create_node_type_version(peer_limit, NodeType::Compute, network_version).await
}

async fn create_node_type_version(
    peer_limit: usize,
    node_type: NodeType,
    network_version: u32,
) -> Node {
    let tcp_tls_config = get_common_tls_config();
    Node::new_with_version(
        &tcp_tls_config,
        peer_limit,
        node_type,
        network_version,
        false,
    )
    .await
    .unwrap()
}

async fn complete_compute_nodes(nodes: Vec<Node>) {
    for mut node in nodes.into_iter() {
        join_all(node.stop_listening().await).await;
    }
}

fn swap_map_values<K: Ord, V>(mapping: &mut BTreeMap<K, V>, k1: &K, k2: &K) {
    let (k1, v1) = mapping.remove_entry(k1).unwrap();
    let (k2, v2) = mapping.remove_entry(k2).unwrap();
    mapping.insert(k1, v2);
    mapping.insert(k2, v1);
}

fn find_key_with_value<VFind: ?Sized, K: Ord + Clone, V: PartialEq<VFind>>(
    mapping: &BTreeMap<K, V>,
    value: &VFind,
) -> Option<K> {
    let (key, _) = mapping.iter().find(|(_, v)| v == &value)?;
    Some(key.clone())
}
