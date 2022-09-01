//! This module implements a Node type with basic network communication capabilities.
//!
//! ## Peer-to-peer system & rings
//!
//! Each node in the system acts both as a server and as a client, effectively forming a peer-to-peer network.
//!
//! Nodes use a custom TCP protocol to communicate which is message-based. The available message types can be found in [`CommMessage`](crate::interfaces::CommMessage).
//! The messages are serialized into a binary format using the `bincode` crate for efficiency (it can be easily replaced with any other [serde][serde]-compatible serialization
//! format such as JSON if needed).
//!
//! Because each node acts as a server, a _listener_ service is started automatically when you crate a new [`Node`](crate::comms_handler::node::Node).
//!
//! ### Joining the network
//!
//! When a node wants to join the network, it should initiate a connection to any known peer (i.e., a known participant of the network).
//! The address of this peer is obtained externally to the system - i.e., it can be provided in the configuration file, as a command line argument, etc.
//! This peer is our first contact: once we connect to it, it will send us its _contact list_, i.e. a list of other peers it knows, and we subsequently
//! connect to all of the other peers from this contact list.
//!
//! Once the TCP connection with the peer is established, a node sends a [`HandshakeRequest`](crate::interfaces::CommMessage::HandshakeRequest),
//! a specially crafted message which contains a [node type](crate::interfaces::NodeType) and the node's public address (which is derived from the
//! listener address). Please note that this address should be publicly available (i.e., we assume that a node is not behind a NAT or a firewall).
//!
//! In response, a node expects a [`HandshakeResponse`](crate::interfaces::CommMessage::HandshakeResponse) message which contains a contact list
//! of all other peers that form a _ring_.
//!
//! ### Rings
//!
//! Peers form _rings_ which are groups determined by the [node type](crate::interfaces::NodeType) - that is, each node type has its own associated ring.
//! We set the node type as a parameter when a [`Node`](crate::comms_handler::Node::new) instance is created.
//!
//! In a ring, each and every peer is connected to all other peers within the ring. This is a deliberate design choice that was dictated by several reasons:
//! first, it's more efficient, as we don't need to maintain complex membership lists and form complex routing patterns to disseminate messages in the network
//! (basically, we rely on the TCP/IP routing), and _all_ messages can be delivered within a single 'hop' (we don't need to relay messages through a third-party node).
//!
//! Second, it's more simple: we don't need to follow a complex membership logic in order to understand how rings work. Third, even on a regular system, we can have
//! a large number of active TCP connections which are limited mostly by a number of available file descriptors on Linux (this limit can be increased or lifted by executing
//! the `ulimit -n unlimited` command), and by available system memory in general (this can also be tweaked by [setting a network buffer size][netbuffersize]).
//!
//! If a node is the first of its type in a ring, it becomes a first contact peer for all new other nodes that want to join the network.
//!
//! ## Message types
//!
//! `CommMessage` has two message types: [`Direct`](crate::interfaces::CommMessage::Direct) (used for one-to-one communication between peers) and
//! [`Gossip`](crate::interfaces::CommMessage::Gossip) (used for multicast). Both have a parameter that's called `payload` which can contain an arbitrary
//! sequence of bytes (`Vec<u8>`). Usually, however, it should be interpreted as a serialized message specific to a given node type. For example, it can
//! encapsulate a [`ComputeRequest`](crate::interfaces::ComputeRequest) if a message is being sent within a compute ring.
//!
//! Usually, a single message type handles both requests and responses (i.e., instead of having separate `ComputeRequest` or `ComputeResponse` enums, we
//! but both types of messages within a single `ComputeRequest` type). This simplifies deserialization and handling of these
//! messages.
//!
//! ## Multicast
//!
//! Multicast messages are delivered to all nodes within a ring.
//!
//! The multicast algorithm implements the [gossip protocol][gossipproto]. The idea behind it is pretty simple: we pick a number of nodes from our contact list at random
//! (this number can be tweaked by the [`FANOUT`](crate::comms_handler::node::FANOUT) constant), and send them a [`Gossip`](crate::interfaces::CommMessage::Gossip) message.
//! Each gossip message includes three fields: the payload (serialized message contents), a number of hops already made (covered further), and a unique ID for the message.
//! Once this message is received by a peer, it's handled like a [direct message](crate::interfaces::CommMessage::Direct), but with one additional step: the gossip algorithm
//! is repeated again by the receiver - _N_ random nodes picked from the contact list and the _same_ message is retransmitted to these nodes with the `ttl` (number of hops) number
//! increased. The 'number of hops' parameter serves an important function: the [`GOSSIP_MAX_TTL`](crate::comms_handler::node::GOSSIP_MAX_TTL) constant regulates a maximum number
//! of hops that a single message can make. A message ID is chosen randomly, and it also serves an important function: each node maintains a list of
//! [_seen messsage IDs_](crate::comms_handler::node::Node::seen_gossip_messages), and if a newly received message is in that list, then it's discarded and not propagated further.
//! This guarantees that a message will eventually reach _all_ nodes within a ring with a high probability - e.g., even if a connection between node A and node B is severed, a
//! node B can send its message to a node C which will retransmit it to a node B.
//!
//! ## Resources
//!
//! This is a list of reference papers used in the implementation design:
//!
//! 1. [Probabilistic reliable dissemination in large-scale systems, A.-M. Kermarrec et al.][reliabledissemination]
//! 1. [Scalable Byzantine Fault-Tolerant Gossip, Matej Pavlovic][scalablegossip]
//! 1. [The peer sampling service: experimental evaluation of unstructured gossip-based implementations, Márk Jelasity et al.][peersampling]
//!
//! [gossipproto]: https://en.wikipedia.org/wiki/Gossip_protocol
//! [reliabledissemination]: https://ieeexplore.ieee.org/document/1189583
//! [scalablegossip]: https://www.semanticscholar.org/paper/Scalable-Byzantine-Fault-Tolerant-Gossip-Pavlovic/d8e19629323dbcf37dc86919babccbd37f35a1f5
//! [peersampling]: https://dl.acm.org/doi/10.5555/1045658.1045666
//! [serde]: https://serde.rs
//! [netbuffersize]: https://stackoverflow.com/a/7865130/168853

use super::tcp_tls::{
    verify_is_valid_for_dns_names, TcpTlsConnector, TcpTlsListner, TcpTlsStream, TlsCertificate,
};
use super::{CommsError, Event, Result, TcpTlsConfig};
use crate::constants::NETWORK_VERSION;
use crate::interfaces::{node_type_as_str, CommMessage, NodeType, Token};
use crate::utils::MpscTracingSender;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::future::join_all;
use futures::SinkExt;
use rand::prelude::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fmt, io};
use tokio::time::{timeout, Duration};
use tokio::{
    self,
    sync::{mpsc, oneshot, Mutex, RwLock},
    task::JoinHandle,
};
use tokio_stream::{Stream, StreamExt};
use tokio_util::codec::{length_delimited, FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{error, info_span, trace, warn, Span};
use tracing_futures::Instrument;
extern crate serde_json;

pub type ResultBytesSender = MpscTracingSender<io::Result<Bytes>>;

/// Number of peers we select for gossip message retransmittion.
const FANOUT: usize = 8;

/// Max. number of gossip message retransmissions.
const GOSSIP_MAX_TTL: u8 = 4;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5); // 5 seconds is just a wild guess. Tweak if necessary.

/// Contains a shared list of connected peers.
type PeerList = HashMap<SocketAddr, Peer>;

/// Closing listener info
type CloseListener = Option<(oneshot::Sender<()>, JoinHandle<()>)>;

/// An abstract communication interface in the network.
#[derive(Debug, Clone)]
pub struct Node {
    /// Node network version.
    network_version: u32,
    /// This node's listener address.
    listener_address: SocketAddr,
    /// Stop channel tx and joining handle for this node listener loop.
    listener_stop_and_join_handles: Arc<Mutex<CloseListener>>,
    /// Pause accepting and starting connections.
    listener_and_connect_paused: Arc<RwLock<bool>>,
    /// Connector used to initialize connection.
    tcp_tls_connector: Arc<RwLock<TcpTlsConnector>>,
    /// List of all connected peers.
    pub(crate) peers: Arc<RwLock<PeerList>>,
    /// Node type.
    node_type: NodeType,
    /// The max number of peers this node should handle.
    peer_limit: usize,
    /// Tracing context.
    span: Span,
    /// Channel to transmit incoming frames and events from peers.
    event_tx: mpsc::UnboundedSender<Event>,
    /// Incoming events from peers.
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<Event>>>,
    /// Contains message IDs that have been already seen and retransmitted by this node.
    // TODO: this requires further work - a list of seen gossip messages can grow unbounded,
    // and it requires to be purged periodically in order to conserve resources.
    seen_gossip_messages: Arc<RwLock<HashSet<Token>>>,
    /// Connect to all unknown contacts in HandshakeResponse
    connect_to_handshake_contacts: bool,
}

pub(crate) struct Peer {
    /// Node network version.
    network_version: Option<u32>,
    /// Channel for sending frames to the peer.
    send_tx: ResultBytesSender,
    /// Peer remote address.
    addr: SocketAddr,
    /// Peer type.
    peer_type: Option<NodeType>,
    /// Peer's public address for inbound connections.
    /// Notice that this address is different from `addr`: e.g., if a peer connects to us,
    /// `addr` will have its address with the ephemeral port, while `public_address` will contain
    /// the address that this peer is listening on.
    public_address: Option<SocketAddr>,
    /// Notification to trigger a task waiting for a handshake response.
    // TODO: move it to a separate state enum, manage state transitions in a better way
    notify_handshake_response: (Option<oneshot::Sender<()>>, Option<oneshot::Receiver<()>>),
    /// Stop receiving when message sent or Sender dropped.
    close_receiver_tx: oneshot::Sender<()>,
    /// Joining handles for this connection tasks.
    sock_in_out_join_handles: (Option<JoinHandle<()>>, Option<JoinHandle<()>>),
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Peer {{ addr: {:?}, peer_type: {:?} }}",
            self.addr, self.peer_type
        )
    }
}

#[derive(Debug)]
enum PeerState {
    WaitingForHandshake,
    Ready,
}

impl Node {
    /// Creates a new node.
    ///
    /// ### Arguments
    /// * `config`     - socket address and tls config the node listener will use.
    /// * `peer_limit` - the maximum number of peers that this node will handle.
    /// * `node_type`  - the node type that will be broadcasted on the network.
    pub async fn new(
        config: &TcpTlsConfig,
        peer_limit: usize,
        node_type: NodeType,
    ) -> Result<Self> {
        Self::new_with_version(config, peer_limit, node_type, NETWORK_VERSION).await
    }

    /// Creates a new node.
    ///
    /// ### Arguments
    /// * `config`          - socket address and tls config the node listener will use.
    /// * `peer_limit`      - the maximum number of peers that this node will handle.
    /// * `node_type`       - the node type that will be broadcasted on the network.
    /// * `network_version` - The version of the network the node is running.
    pub async fn new_with_version(
        config: &TcpTlsConfig,
        peer_limit: usize,
        node_type: NodeType,
        network_version: u32,
    ) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let listener = TcpTlsListner::new(config).await?;
        let listener_address = listener.listener_address();
        let span = info_span!("node", ?listener_address);

        let tcp_tls_connector = TcpTlsConnector::new(config)?;

        Self {
            network_version,
            listener_address,
            listener_stop_and_join_handles: Arc::new(Mutex::new(None)),
            listener_and_connect_paused: Arc::new(RwLock::new(false)),
            tcp_tls_connector: Arc::new(RwLock::new(tcp_tls_connector)),
            node_type,
            peers: Arc::new(RwLock::new(HashMap::with_capacity(peer_limit))),
            peer_limit,
            span,
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            seen_gossip_messages: Arc::new(RwLock::new(HashSet::new())),
            connect_to_handshake_contacts: false,
        }
        .listen(listener)
        .await
    }

    fn is_compatible(&self, node_type: NodeType, network_version: u32) -> bool {
        self.network_version == network_version
            && (self.node_type == NodeType::PreLaunch) == (node_type == NodeType::PreLaunch)
    }

    pub fn set_connect_to_handshake_contacts(&mut self, value: bool) {
        self.connect_to_handshake_contacts = value;
    }

    /// Handles the listener.
    async fn listen(self, listener: TcpTlsListner) -> Result<Self> {
        let node = self.clone();
        let (close_tx, close_rx) = oneshot::channel();
        let handle = tokio::spawn(
            async move {
                trace!("listen");

                let listener = listener.listener_as_stream();
                futures_util::pin_mut!(listener);

                use super::stream_cancel::StreamCancel;
                use futures::TryFutureExt;
                let mut cancellable_listener = listener.take_until(close_rx.unwrap_or_else(|_| ()));

                while let Some(new_conn) = cancellable_listener.next().await {
                    match new_conn {
                        Ok(conn) => {
                            if *node.listener_and_connect_paused.read().await {
                                // Ignore new connections
                                continue;
                            }

                            // TODO: have a timeout for incoming handshake to disconnect clients who linger on without any communication
                            let peer_span = info_span!(
                                "accepted peer",
                                peer_addr = tracing::field::debug(conn.peer_addr())
                            );

                            let new_peer = node.add_peer(conn, false, peer_span, true).await;
                            match new_peer {
                                Ok(()) => {}
                                Err(error) => warn!(?error, "Could not add a new peer"),
                            }
                        }
                        Err(error) => {
                            warn!(?error, "Connection failure");
                        }
                    }
                }
            }
            .instrument(self.span.clone()),
        );

        *self.listener_stop_and_join_handles.lock().await = Some((close_tx, handle));
        Ok(self)
    }

    /// Adds a new peer to a list of peers.
    /// TODO: Could make peer_list a LRU cache later.
    ///
    /// ### Arguments
    ///
    /// * `event_tx`     - Channel to transmit events from the peer.
    /// * `peers_list`   - Shared list of a node peers.
    /// * `socket`       - A new peer's TcpStream socket.
    /// * `force_add`    - If true and the peer limit is reached, an old peer will be ejected to make space.
    /// * `peer_span`    - Tracing scope for this peer.
    /// * `is_initiator` - If `true`, this peer has connected to us. If `false`, then _we_ are
    ///                    connecting to this peer.
    async fn add_peer(
        &self,
        socket: TcpTlsStream,
        force_add: bool,
        peer_span: Span,
        is_initiator: bool,
    ) -> Result<()> {
        let mut peers = self.peers.write().await;
        let is_full = peers.len() >= self.peer_limit;

        if force_add && is_full {
            // TODO: make sure it's disconnected and shut down gracefully
            let peer = peers.drain().take(1);
            warn!("Remove peer full: {:?}", peer);
        }

        if !is_full {
            // Spawn the tasks to manage the peer
            let peer_addr = socket.peer_addr();
            let peer = self.handle_peer(socket, peer_span.clone(), is_initiator);

            peer_span.in_scope(|| trace!("added new peer: {:?}", peer_addr));

            peers.insert(peer_addr, peer);

            Ok(())
        } else {
            warn!(peers = tracing::field::debug(&*peers), "PeerListFull");
            Err(CommsError::PeerListFull)
        }
    }

    /// Return collection of unconnected peers.
    pub async fn unconnected_peers(&self, peers: &[SocketAddr]) -> Vec<SocketAddr> {
        let connected = self.peers.read().await;
        let unconnected = peers
            .iter()
            .filter(|p| connected.get(p).and_then(|p| p.network_version).is_none());
        unconnected.copied().collect()
    }

    /// Establishes a connection to a remote peer.
    /// Compared to `connect_to`, this function will not send the handshake message and won't wait for a response.
    async fn connect_to_peer(&mut self, peer: SocketAddr) -> Result<()> {
        if !self.peers.read().await.contains_key(&peer) {
            if *self.listener_and_connect_paused.read().await {
                return Err(CommsError::PeerNotFound);
            }

            let stream = self.tcp_tls_connector.read().await.connect(peer).await?;
            let peer_addr = stream.peer_addr();

            let span = info_span!(parent: &self.span, "connect_to", ?peer_addr);
            self.add_peer(stream, false, span, false).await?;
        }
        Ok(())
    }

    /// Connects to a remote peer.
    ///
    /// ### Arguments
    /// * `peer` - Endpoint address of a remote peer.
    ///
    /// ### Returns
    /// * `Ok(())` if this node has successfully connected to a peer.
    /// * See [`CommsError`][error] for a list of possible errors.
    ///
    /// [error]: enum.CommsError.html
    pub async fn connect_to(&mut self, peer: SocketAddr) -> Result<()> {
        trace!(?peer, "connection attempt");
        self.connect_to_peer(peer).await?;
        self.send_handshake(peer).await?;
        self.wait_handshake_response(peer).await?;
        Ok(())
    }

    /// Wait for the handshake response to be received
    async fn wait_handshake_response(&mut self, peer: SocketAddr) -> Result<()> {
        // Wait for a handshake response
        let handshake_response = {
            let mut peers = self.peers.write().await;
            let peer = peers.get_mut(&peer).ok_or(CommsError::PeerNotFound)?;
            peer.notify_handshake_response
                .1
                .take()
                .ok_or(CommsError::PeerInvalidState)?
        };

        match timeout(RESPONSE_TIMEOUT, handshake_response)
            .await
            .map_err(|e| {
                trace!("Timeout after {e}. Failed connection to {:?}", peer);
                CommsError::PeerNotFound
            })? {
            Ok(()) => trace!("Complete connection to {:?}", peer),
            Err(_) => {
                trace!("Complete failed connection to {:?}", peer);
                return Err(CommsError::PeerNotFound);
            }
        }

        Ok(())
    }

    /// Pause/Resume accepting new connections
    pub async fn set_pause_listening(&mut self, pause: bool) {
        *self.listener_and_connect_paused.write().await = pause;
    }

    /// Stop accepting new connections
    pub async fn stop_listening(&mut self) -> Vec<JoinHandle<()>> {
        trace!("stop_listening {:?}", self.listener_address);
        if let Some((stop_tx, handle)) = self.listener_stop_and_join_handles.lock().await.take() {
            stop_tx.send(()).unwrap();
            vec![handle]
        } else {
            Vec::new()
        }
    }

    /// Disconnect all remote peers and provide JoinHandles.
    /// If provided, only disconnect subset of peers.
    pub async fn disconnect_all(&mut self, subset: Option<&[SocketAddr]>) -> Vec<JoinHandle<()>> {
        let mut all_peers = {
            let mut all_peers = self.peers.write().await;
            if let Some(subset) = subset {
                subset
                    .iter()
                    .filter_map(|addr| all_peers.remove_entry(addr))
                    .collect()
            } else {
                let all_peers: &mut PeerList = &mut all_peers;
                std::mem::take(all_peers)
            }
        };

        trace!("disconnect_all {:?}", all_peers);
        take_join_handles(all_peers.iter_mut().map(|(_, p)| p))
    }

    /// Take the specified join handle to wait on externally.
    pub async fn take_join_handle(&mut self, addr: SocketAddr) -> Vec<JoinHandle<()>> {
        let mut all_peers = self.peers.write().await;
        take_join_handles(all_peers.get_mut(&addr).into_iter())
    }

    /// Sends a multicast message to a group of peers in our ring.
    ///
    /// ### Errors
    /// - `CommsError::PeerListEmpty` - in case if we don't know anyone we can multicast to.
    pub async fn multicast(&mut self, data: impl Serialize) -> Result<()> {
        let peers = self.sample_peers(FANOUT).await;
        if peers.is_empty() {
            return Err(CommsError::PeerListEmpty);
        }

        let message_id = rand::thread_rng().gen();
        let payload = Bytes::from(serialize(&data)?);

        self.send_multicast(
            peers.into_iter(),
            CommMessage::Gossip {
                payload: payload.clone(),
                id: message_id,
                ttl: 0,
            },
        )
        .await;

        Ok(())
    }

    async fn send_multicast(&self, peers: impl Iterator<Item = SocketAddr>, msg: CommMessage) {
        trace!("send_multicast");

        let join_handles: Vec<_> = peers
            .map(|peer| {
                let mut node = self.clone();
                let msg = msg.clone();

                tokio::spawn(async move {
                    if let Err(error) = node.send_message(peer, msg).await {
                        warn!(?error, "send_multicast");
                    }
                })
            })
            .collect();

        join_all(join_handles).await;
    }

    /// Returns a list of known peers who are members of the same ring as ours.
    fn ring_peers<'a>(&self, peers: &'a PeerList) -> impl Iterator<Item = SocketAddr> + 'a {
        let own_node_type = self.node_type;

        peers.values().filter_map(move |p| {
            if let Some(peer_type) = p.peer_type {
                if peer_type == own_node_type {
                    return p.public_address;
                }
            }
            None
        })
    }

    /// Select `n` random peers from known contacts.
    async fn sample_peers(&self, n: usize) -> HashSet<SocketAddr> {
        let peers = (*self.peers).read().await;

        let rng = &mut rand::thread_rng();

        peers
            .keys()
            .cloned()
            .choose_multiple(rng, n)
            .into_iter()
            .collect()
    }

    /// Sends raw bytes to a given peer.
    async fn send_bytes(
        &self,
        peer: SocketAddr,
        tx: &mut ResultBytesSender,
        bytes: Bytes,
    ) -> Result<()> {
        trace!(?bytes, ?peer, "send_bytes");
        if let Err(error) = tx.send(Ok(bytes), "tx_bytes").await {
            error!(?error, "Error sending a frame through the message channel");
        }
        Ok(())
    }

    /// Get peer type.
    pub async fn get_peer_node_type(&self, peer_addr: SocketAddr) -> Result<NodeType> {
        let peers = self.peers.read().await;
        let peer = peers.get(&peer_addr).ok_or(CommsError::PeerNotFound)?;
        peer.peer_type.ok_or(CommsError::PeerInvalidState)
    }

    /// Sends data to a peer.
    async fn send_message(&mut self, peer_addr: SocketAddr, message: CommMessage) -> Result<()> {
        let data = Bytes::from(serialize(&message)?);

        let peers = self.peers.read().await;
        let peer = peers.get(&peer_addr).ok_or(CommsError::PeerNotFound)?;
        let mut tx = peer.send_tx.clone();
        self.send_bytes(peer_addr, &mut tx, data).await
    }

    /// Sends a serialized message to a given peer.
    pub async fn send(&mut self, peer: SocketAddr, data: impl Serialize) -> Result<()> {
        let payload = Bytes::from(serialize(&data)?);
        let id = rand::thread_rng().gen();
        self.send_message(peer, CommMessage::Direct { payload, id })
            .await
    }

    /// Sends a serialized message to given peers.
    pub async fn send_to_all(
        &mut self,
        peers: impl Iterator<Item = SocketAddr>,
        data: impl Serialize,
    ) -> Result<()> {
        let payload = Bytes::from(serialize(&data)?);
        let id = rand::thread_rng().gen();
        self.send_multicast(peers, CommMessage::Direct { payload, id })
            .await;
        Ok(())
    }

    /// Prepares and sends a handshake message to a given peer.
    async fn send_handshake(&mut self, peer: SocketAddr) -> Result<()> {
        self.send_message(
            peer,
            CommMessage::HandshakeRequest {
                network_version: self.network_version,
                node_type: self.node_type,
                public_address: self.listener_address,
            },
        )
        .await
    }

    /// Blocks & waits for a next event from a peer.
    pub async fn next_event(&mut self) -> Option<Event> {
        self.event_rx.lock().await.recv().await
    }

    pub fn inject_next_event(
        &self,
        from_peer_addr: SocketAddr,
        data: impl Serialize,
    ) -> Result<()> {
        let payload = Bytes::from(serialize(&data)?);
        Ok(self.event_tx.send(Event::NewFrame {
            peer: from_peer_addr,
            frame: payload,
        })?)
    }

    /// Returns this node's listener address.
    pub fn address(&self) -> SocketAddr {
        self.listener_address
    }

    /// Handles incoming messages from a peer waiting for an handshake.
    ///
    /// ### Arguments
    /// * `peer_addr`    - address of a remote peer.
    /// * `send_tx`      - a queue to send messages to the peer.
    /// * `messages`     - stream of incoming messages.
    async fn handle_peer_recv_handshake(
        &self,
        peer_addr: SocketAddr,
        peer_cert: Option<TlsCertificate>,
        send_tx: ResultBytesSender,
        mut messages: impl Stream<Item = CommMessage> + std::marker::Unpin,
    ) -> Result<SocketAddr> {
        while let Some(message) = messages.next().await {
            trace!(?message, "handle_peer_recv_handshake");

            match message {
                CommMessage::HandshakeRequest {
                    network_version: v,
                    node_type: t,
                    public_address,
                } => {
                    match self
                        .handle_handshake_request(
                            peer_addr,
                            public_address,
                            &peer_cert,
                            send_tx.clone(),
                            v,
                            t,
                        )
                        .await
                    {
                        Ok(()) => return Ok(public_address),
                        Err(e) => {
                            // Drop peer since we don't expect handshake to succeed.
                            warn!(?public_address, "handle_handshake_request: {}", e);
                            return Err(e);
                        }
                    }
                }
                CommMessage::HandshakeResponse {
                    network_version,
                    node_type,
                    contacts,
                } => {
                    match self
                        .handle_handshake_response(peer_addr, network_version, node_type, contacts)
                        .await
                    {
                        Ok(()) => return Ok(peer_addr),
                        Err(e) => {
                            // Drop peer since we don't expect handshake to succeed.
                            warn!(?peer_addr, "handle_handshake_response: {}", e);
                            return Err(e);
                        }
                    }
                }
                other => warn!(?other, "Ignoring unexpected message waiting for handshake"),
            };
        }

        Ok(peer_addr)
    }

    /// Handles incoming messages from a peer not waiting for an handshake.
    ///
    /// ### Arguments
    /// * `peer_addr`    - address of a remote peer.
    /// * `messages`     - stream of incoming messages.
    async fn handle_peer_recv(
        &self,
        peer_addr: SocketAddr,
        mut messages: impl Stream<Item = CommMessage> + std::marker::Unpin,
    ) {
        while let Some(message) = messages.next().await {
            trace!(?message, "handle_peer_recv");
            match message {
                CommMessage::Direct {
                    payload: frame,
                    id: _,
                } => {
                    if let Err(error) = self.event_tx.send(Event::NewFrame {
                        peer: peer_addr,
                        frame,
                    }) {
                        warn!(?error, ?peer_addr, "event_tx.send");
                    }
                }
                CommMessage::Gossip { payload, ttl, id } => {
                    trace!(?payload, ?ttl, ?id, "gossip");
                    if let Err(error) = self.handle_gossip(peer_addr, payload, ttl, id).await {
                        warn!(?error, "handle_gossip");
                    }
                }
                other => {
                    warn!(?other, "Received unexpected message; ignoring");
                }
            }
        }
    }

    async fn handle_gossip(
        &self,
        from_peer: SocketAddr,
        payload: Bytes,
        ttl: u8,
        message_id: Token,
    ) -> Result<()> {
        {
            // Have we already seen a message with this id?
            let mut seen_list = self.seen_gossip_messages.write().await;

            if seen_list.contains(&message_id) {
                // This message was already seen, do nothing.
                trace!(?ttl, ?message_id, "gossip - already seen");
                return Ok(());
            }

            let _ = seen_list.insert(message_id);
        }

        // Notify a user about the message.
        self.event_tx.send(Event::NewFrame {
            peer: from_peer,
            frame: payload.clone(),
        })?;

        // Retransmit the gossip message.
        if ttl > GOSSIP_MAX_TTL {
            // The message has exceeded its TTL.
            return Ok(());
        }

        let mut peers = self.sample_peers(FANOUT).await;
        peers.remove(&from_peer);

        if peers.is_empty() {
            // Our contact list is empty.
            trace!(?message_id, "gossip - contact list is empty");
            return Ok(());
        }

        // Create a new task for retransmission to make sure we don't block the listener.
        let node = self.clone();
        let payload = payload.clone();

        tokio::spawn(async move {
            node.send_multicast(
                peers.into_iter(),
                CommMessage::Gossip {
                    payload,
                    id: message_id,
                    ttl: ttl + 1,
                },
            )
            .await;
        });

        Ok(())
    }

    /// Handles an incoming handshake request.
    /// Sends a handshake response with a list of peers we know within our ring.
    async fn handle_handshake_request(
        &self,
        peer_out_addr: SocketAddr,
        peer_in_addr: SocketAddr,
        peer_cert: &Option<TlsCertificate>,
        mut send_tx: ResultBytesSender,
        network_version: u32,
        peer_type: NodeType,
    ) -> Result<()> {
        if !self.is_compatible(peer_type, network_version) {
            return Err(CommsError::PeerIncompatible);
        }

        let mut all_peers = self.peers.write().await;
        if all_peers.contains_key(&peer_in_addr) {
            return Err(CommsError::PeerDuplicate);
        }

        let peer = all_peers
            .get_mut(&peer_out_addr)
            .ok_or(CommsError::PeerNotFound)?;

        if let Some(peer_cert) = peer_cert {
            let connector = self.tcp_tls_connector.read().await;
            let peer_name = connector.socket_name_mapping(peer_in_addr);

            verify_is_valid_for_dns_names(peer_cert, std::iter::once(peer_name.as_str()))?;
        }

        peer.network_version = Some(network_version);
        peer.peer_type = Some(peer_type);
        peer.public_address = Some(peer_in_addr);

        // Send handshake response which will contain contacts of all valid peers within our ring.
        let response = CommMessage::HandshakeResponse {
            network_version: self.network_version,
            node_type: self.node_type,
            contacts: self.ring_peers(&all_peers).collect(),
        };
        let message = Bytes::from(serialize(&response)?);
        self.send_bytes(peer_out_addr, &mut send_tx, message)
            .await?;

        Ok(())
    }

    /// Handles a handshake response.
    /// Connects to all nodes that we receive in the contact list.
    async fn handle_handshake_response(
        &self,
        peer_addr: SocketAddr,
        network_version: u32,
        peer_type: NodeType,
        contacts: Vec<SocketAddr>,
    ) -> Result<()> {
        if !self.is_compatible(peer_type, network_version) {
            return Err(CommsError::PeerIncompatible);
        }

        let mut all_peers = self.peers.write().await;

        // Notify the peer about the handshake response if someone's waiting for it.
        {
            let peer = all_peers
                .get_mut(&peer_addr)
                .ok_or(CommsError::PeerNotFound)?;
            peer.network_version = Some(network_version);
            peer.peer_type = Some(peer_type);

            if let Some(notify) = peer.notify_handshake_response.0.take() {
                notify.send(()).unwrap();
            }
        }

        // Find out if we have received new peer contacts in the response.
        let known_peers: HashSet<_> = all_peers
            .values()
            .filter_map(|p| p.public_address)
            .collect();

        let contacts = contacts.into_iter().collect::<HashSet<_>>();
        let unknown_peers = contacts.difference(&known_peers);

        trace!(?known_peers, ?unknown_peers);

        if self.connect_to_handshake_contacts {
            // TODO: Fix this as connections arriving from both directions do not work.
            // Connect to all previously unknown peers (in the background - i.e. we don't wait for these connections to succeed).
            for &peer in unknown_peers {
                let mut node = self.clone();
                tokio::spawn(
                    async move {
                        if let Err(error) = node.connect_to(peer).await {
                            warn!(?error, "connect_to failed");
                        }
                    }
                    .instrument(
                        info_span!(parent: &self.span, "handshake_response_connect", ?peer),
                    ),
                );
            }
        }

        Ok(())
    }

    /// Manages the data exchange with the peer.
    /// Accepts incoming data and decodes it to frames.
    ///
    /// ### Arguments
    ///
    /// * `socket`       - The peer's TCP socket.
    /// * `event_tx`     - A channel for user-level messages.
    /// * `span`         - The logging scope for this peer.
    /// * `is_initiator` - If `true`, this peer has connected to us. If `false`, then _we_ are
    ///                    connecting to this peer.
    ///
    /// ### Returns
    /// A new `Peer` instance.
    fn handle_peer(&self, socket: TcpTlsStream, span: Span, is_initiator: bool) -> Peer {
        let peer_addr = socket.peer_addr();
        let peer_cert = socket.peer_tls_certificate();

        let (send_tx, mut send_rx) = mpsc::channel(128);

        // Wrap the peer socket into the tokio codec which handles length-delimited frames.
        let (sock_in, sock_out) = tokio::io::split(socket);
        let codec_builder = *length_delimited::Builder::new().max_frame_length(
            // max frame length of 100MB
            100 * 1_024 * 1_024,
        );
        let sock_in = FramedRead::new(sock_in, codec_builder.new_codec());
        let mut sock_out = FramedWrite::new(sock_out, codec_builder.new_codec());

        // Spawn the sender task.
        // Redirect messages from the mpsc channel into the TCP socket
        let sock_out_h = tokio::spawn(
            async move {
                let send_rx = async_stream::stream! {
                    while let Some(item) = send_rx.recv().await {
                        yield item;
                    }
                };
                futures_util::pin_mut!(send_rx);

                if let Err(error) = sock_out.send_all(&mut send_rx).await {
                    error!(?error, "Error while redirecting messages");
                }
                trace!("sock_out dropped for {:?}", peer_addr);
            }
            .instrument(span.clone()),
        );

        // Spawn the receiver task which will redirect the incoming messages into the MPSC channel
        // and manage the peer state transitions.
        let (messages, close_receiver_tx) = get_messages_stream(sock_in);
        let sock_in_h = tokio::spawn({
            let node = self.clone();
            let send_tx = send_tx.clone().into();
            let peers = self.peers.clone();
            async move {
                let mut messages = messages;
                let public_address = {
                    match node
                        .handle_peer_recv_handshake(peer_addr, peer_cert, send_tx, &mut messages)
                        .await
                    {
                        Ok(public_address) => {
                            // Update key to public address so we know where to route messages
                            {
                                let mut peers_list = peers.write().await;
                                if let Some(peer) = peers_list.remove(&peer_addr) {
                                    trace!(
                                        "Move peer to public address: {} -> {}",
                                        peer_addr,
                                        public_address
                                    );
                                    peers_list.insert(public_address, peer);
                                    public_address
                                } else {
                                    // Peer not present
                                    trace!("sock_in dropped for {:?}", peer_addr);
                                    return;
                                }
                            }
                        }
                        Err(err) => {
                            // Drop error connection
                            warn!("Remove peer: {}, err: {:?}", peer_addr, err);
                            let mut peers_list = peers.write().await;
                            let _ = peers_list.remove(&peer_addr);
                            trace!("sock_in dropped for {:?}", peer_addr);
                            return;
                        }
                    }
                };

                node.handle_peer_recv(public_address, messages).await;
                // Since we don't wait for any messages from this peer, we can drop the connection.
                warn!("Remove peer: {}", public_address);
                let mut peers_list = peers.write().await;
                let _ = peers_list.remove(&public_address);
                trace!("sock_in dropped for {:?}", peer_addr);
            }
            .instrument(span)
        });

        Peer {
            network_version: None,
            addr: peer_addr,
            send_tx: send_tx.into(),
            peer_type: None,
            public_address: if !is_initiator { Some(peer_addr) } else { None },
            notify_handshake_response: if is_initiator {
                (None, None)
            } else {
                let (tx, rx) = oneshot::channel::<()>();
                (Some(tx), Some(rx))
            },
            close_receiver_tx,
            sock_in_out_join_handles: (Some(sock_in_h), Some(sock_out_h)),
        }
    }

    /// Get node type
    pub fn get_node_type(&self) -> NodeType {
        self.node_type
    }

    /// Get list of node peers
    pub async fn get_peer_list(&self) -> Vec<(String, SocketAddr, String)> {
        let peer_clone = self.peers.clone();
        let peers = peer_clone.read().await;
        let keys = peers.keys();
        let mut sort_keys: Vec<(String, &SocketAddr)> = Vec::new();
        let mut return_vec: Vec<(String, SocketAddr, String)> = Vec::new();
        for key in keys.clone() {
            sort_keys.push((key.to_string(), key));
        }
        for i in 0..(sort_keys.len()) {
            for j in 0..(sort_keys.len() - i - 1) {
                if std::cmp::Ordering::Greater == (sort_keys[j].0).cmp(&sort_keys[j + 1].0) {
                    sort_keys.swap(j, j + 1);
                }
            }
        }

        for key in sort_keys {
            if let Ok(peertype) = self.get_peer_node_type(*key.1).await {
                if peertype == NodeType::Compute || peertype == NodeType::Storage {
                    return_vec.push((key.0, *key.1, String::from(node_type_as_str(peertype))));
                }
            }
        }
        return_vec
    }
}

/// Transforms a stream of incoming TCP frames into a stream of deserialized messages.
fn get_messages_stream(
    sock_in: FramedRead<tokio::io::ReadHalf<TcpTlsStream>, LengthDelimitedCodec>,
) -> (impl Stream<Item = CommMessage>, oneshot::Sender<()>) {
    let messages = sock_in
        .map(|frame| {
            trace!(?frame, "recv_frame");

            let frame = match frame {
                Ok(inner) => inner,
                Err(error) => {
                    warn!(?error, "Could not decode frame");
                    return None;
                }
            };

            match deserialize::<CommMessage>(&frame) {
                Ok(message) => Some(message),
                Err(error) => {
                    warn!(?error, "Could not deserialize message; ignoring");
                    None
                }
            }
        })
        .take_while(|v| v.is_some())
        .filter_map(|v| v);

    use super::stream_cancel::StreamCancel;
    use futures::TryFutureExt;
    let (close_tx, close_rx) = oneshot::channel::<()>();
    let cancellable_messages = messages.take_until(close_rx.unwrap_or_else(|_| ()));

    (cancellable_messages, close_tx)
}

fn take_join_handles<'a>(peers: impl Iterator<Item = &'a mut Peer>) -> Vec<JoinHandle<()>> {
    peers
        .map(|p| &mut p.sock_in_out_join_handles)
        .flat_map(|hs| hs.0.take().into_iter().chain(hs.1.take()))
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_common_tls_config;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn handshake_processing() {
        //
        // Arrange
        //
        let mut n1 = create_compute_node_version(2, 0).await;
        let mut n2 = create_compute_node_version(2, 0).await;
        let conn_address_1 = vec![n2.address()];
        let conn_address_2 = vec![n1.address()];

        //
        // Act
        //

        // No handshake
        n1.connect_to_peer(n2.address()).await.unwrap();
        let n2_n1_addres = {
            while n2.sample_peers(1).await.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            n2.sample_peers(1).await.into_iter().next().unwrap()
        };
        n1.send(n2.address(), "HelloDropped2").await.unwrap();
        n2.send(n2_n1_addres, "HelloDropped1").await.unwrap();

        let no_handshake_unconn_1 = n1.unconnected_peers(&conn_address_1).await;
        let no_handshake_unconn_2 = n2.unconnected_peers(&conn_address_2).await;

        // Send handshake
        n1.send_handshake(n2.address()).await.unwrap();
        n1.wait_handshake_response(n2.address()).await.unwrap();
        n1.send(n2.address(), "Hello2").await.unwrap();
        n2.send(n1.address(), "Hello1").await.unwrap();
        let handshake_unconn_1 = n1.unconnected_peers(&conn_address_1).await;
        let handshake_unconn_2 = n2.unconnected_peers(&conn_address_2).await;

        //
        // Assert
        //
        if let Some(Event::NewFrame { peer: _, frame }) = n1.next_event().await {
            let recv_frame: &str = deserialize(&frame).unwrap();
            assert_eq!(recv_frame, "Hello1");
        }
        if let Some(Event::NewFrame { peer: _, frame }) = n2.next_event().await {
            let recv_frame: &str = deserialize(&frame).unwrap();
            assert_eq!(recv_frame, "Hello2");
        }

        assert_eq!(
            (
                (no_handshake_unconn_1, no_handshake_unconn_2),
                (handshake_unconn_1, handshake_unconn_2)
            ),
            ((conn_address_1, conn_address_2), (vec![], vec![]))
        );

        complete_compute_nodes(vec![n1, n2]).await;
    }

    async fn create_compute_node_version(peer_limit: usize, network_version: u32) -> Node {
        let tcp_tls_config = get_common_tls_config();
        Node::new_with_version(
            &tcp_tls_config,
            peer_limit,
            NodeType::Compute,
            network_version,
        )
        .await
        .unwrap()
    }

    async fn complete_compute_nodes(nodes: Vec<Node>) {
        for mut node in nodes.into_iter() {
            join_all(node.stop_listening().await).await;
        }
    }
}
