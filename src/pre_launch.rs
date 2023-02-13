use crate::comms_handler::{CommsError, Event, Node, TcpTlsConfig};
use crate::configurations::{
    DbMode, ExtraNodeParams, NodeSpec, PreLaunchNodeConfig, PreLaunchNodeType, TlsSpec,
};
use crate::constants::PEER_LIMIT;
use crate::db_utils::{self, SimpleDb, SimpleDbSpec};
use crate::interfaces::{DbItem, NodeType, PreLaunchRequest, Response};
use crate::raft_store::{get_presistent_committed, CommittedIndex};
use crate::utils::{LocalEvent, LocalEventChannel, LocalEventSender, ResponseResult};
use bincode::deserialize;
use bytes::Bytes;
use std::{collections::BTreeSet, error::Error, fmt, future::Future, net::SocketAddr};
use tokio::task;
use tracing::{debug, error, error_span, info, trace, warn};
use tracing_futures::Instrument;

/// Result wrapper for miner errors
pub type Result<T> = std::result::Result<T, PreLaunchError>;

#[derive(Debug)]
pub enum PreLaunchError {
    ConfigError(&'static str),
    Network(CommsError),
    AsyncTask(task::JoinError),
    Serialization(bincode::Error),
}

impl fmt::Display for PreLaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {err}"),
            Self::Network(err) => write!(f, "Network error: {err}"),
            Self::AsyncTask(err) => write!(f, "Async task error: {err}"),
            Self::Serialization(err) => write!(f, "Serialization error: {err}"),
        }
    }
}

impl Error for PreLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::Network(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
            Self::AsyncTask(ref e) => Some(e),
        }
    }
}

impl From<CommsError> for PreLaunchError {
    fn from(other: CommsError) -> Self {
        Self::Network(other)
    }
}

impl From<task::JoinError> for PreLaunchError {
    fn from(other: task::JoinError) -> Self {
        Self::AsyncTask(other)
    }
}

impl From<bincode::Error> for PreLaunchError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

/// Configuration option for a pre-launch node
#[derive(Debug, Clone)]
struct PreLaunchNodeConfigSelected {
    /// Index of the current node in pre_launch_nodes
    pub pre_launch_node_idx: usize,
    /// Use specific database
    pub pre_launch_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// All nodes addresses
    pub pre_launch_nodes: Vec<NodeSpec>,
    /// Db spec
    pub db_spec: SimpleDbSpec,
    /// Raft db spec
    pub raft_db_spec: SimpleDbSpec,
}

impl PreLaunchNodeConfigSelected {
    fn new(config: PreLaunchNodeConfig) -> Self {
        match config.node_type {
            PreLaunchNodeType::Compute => Self {
                pre_launch_node_idx: config.compute_node_idx,
                pre_launch_db_mode: config.compute_db_mode,
                tls_config: config.tls_config,
                pre_launch_nodes: config.compute_nodes,
                db_spec: crate::compute::DB_SPEC,
                raft_db_spec: crate::compute_raft::DB_SPEC,
            },
            PreLaunchNodeType::Storage => Self {
                pre_launch_node_idx: config.storage_node_idx,
                pre_launch_db_mode: config.storage_db_mode,
                tls_config: config.tls_config,
                pre_launch_nodes: config.storage_nodes,
                db_spec: crate::storage::DB_SPEC,
                raft_db_spec: crate::storage_raft::DB_SPEC,
            },
        }
    }
}

/// An instance of a PreLaunchNode
#[derive(Debug)]
pub struct PreLaunchNode {
    node: Node,
    db: SimpleDb,
    raft_db: SimpleDb,
    local_events: LocalEventChannel,
    pre_launch_nodes: Vec<SocketAddr>,
    shutdown_group: BTreeSet<SocketAddr>,
    raft_db_send: Option<PreLaunchRequest>,
}

impl PreLaunchNode {
    ///Constructor to create a new PreLaunchNode
    ///
    /// ### Arguments
    ///
    /// * `config` - PreLaunchNodeConfig object containing PreLaunchNode parameters.
    /// * `extra`  - additional parameter for construction
    pub async fn new(
        config: PreLaunchNodeConfig,
        mut extra: ExtraNodeParams,
    ) -> Result<PreLaunchNode> {
        let config = PreLaunchNodeConfigSelected::new(config);
        let addr = config
            .pre_launch_nodes
            .get(config.pre_launch_node_idx)
            .ok_or(PreLaunchError::ConfigError("Invalid pre-launch index"))?
            .address;
        let tcp_tls_config = TcpTlsConfig::from_tls_spec(addr, &config.tls_config)?;

        let node = Node::new(&tcp_tls_config, PEER_LIMIT, NodeType::PreLaunch).await?;
        let db = {
            let spec = &config.db_spec;
            db_utils::new_db(config.pre_launch_db_mode, spec, extra.db.take())
        };
        let raft_db = {
            let spec = &config.raft_db_spec;
            db_utils::new_db(config.pre_launch_db_mode, spec, extra.raft_db.take())
        };

        let pre_launch_nodes = config.pre_launch_nodes.iter().map(|s| s.address);
        let shutdown_group: BTreeSet<SocketAddr> = pre_launch_nodes.clone().collect();
        let pre_launch_nodes: Vec<_> = pre_launch_nodes.filter(|a| *a != addr).collect();

        let raft_db_send = if config.pre_launch_node_idx == 0 {
            Some(PreLaunchRequest::SendDbItems {
                committed: get_presistent_committed(&raft_db)
                    .map_err(|e| {
                        error!("Invalid pre-launch db: {:?}", e);
                        PreLaunchError::ConfigError("Invalid pre-launch index")
                    })?
                    .unwrap_or_default(),
                items: raft_db
                    .iter_all_cf_clone()
                    .into_iter()
                    .flat_map(|(c, it)| it.map(move |(k, v)| (c.clone(), k, v)))
                    .map(|(column, key, data)| DbItem { column, key, data })
                    .collect(),
            })
        } else {
            None
        };

        Ok(PreLaunchNode {
            node,
            db,
            raft_db,
            local_events: Default::default(),
            pre_launch_nodes,
            shutdown_group,
            raft_db_send,
        })
    }

    /// Returns the node's public endpoint.
    pub fn address(&self) -> SocketAddr {
        self.node.address()
    }

    /// Connect to a peer on the network.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Socket Address of the peer to connect to.
    pub async fn connect_to(&mut self, peer: SocketAddr) -> Result<()> {
        self.node.connect_to(peer).await?;
        Ok(())
    }

    /// Connect info for peers on the network.
    pub fn connect_info_peers(&self) -> (Node, Vec<SocketAddr>, Vec<SocketAddr>) {
        let to_connect = self.pre_launch_nodes.iter();
        let expect_connect = self.pre_launch_nodes.iter();
        (
            self.node.clone(),
            to_connect.copied().collect(),
            expect_connect.copied().collect(),
        )
    }

    /// Send initial requests:
    /// - None
    pub async fn send_startup_requests(&mut self) -> Result<()> {
        if self.raft_db_send.is_some() {
            self.flood_closing_events().await?;
        }
        if let Some(r) = &self.raft_db_send {
            let nodes = &self.pre_launch_nodes;
            self.node.send_to_all(nodes.iter().copied(), r).await?;
        }
        Ok(())
    }

    /// Extract persistent dbs
    pub async fn take_closed_extra_params(&mut self) -> ExtraNodeParams {
        ExtraNodeParams {
            db: self.db.take().in_memory(),
            raft_db: self.raft_db.take().in_memory(),
            ..Default::default()
        }
    }

    /// Listens for new events from peers and handles them, processing any errors.
    pub async fn handle_next_event_response(
        &mut self,
        response: Result<Response>,
    ) -> ResponseResult {
        debug!("Response: {:?}", response);

        match response {
            Ok(Response {
                success: true,
                reason: "Sent startup requests on reconnection",
            }) => debug!("Sent startup requests on reconnection"),
            Ok(Response {
                success: false,
                reason: "Failed to send startup requests on reconnection",
            }) => error!("Failed to send startup requests on reconnection"),
            Ok(Response {
                success: true,
                reason: "Shutdown",
            }) => {
                warn!("Shutdown now");
                return ResponseResult::Exit;
            }
            Ok(Response {
                success: true,
                reason: "Shutdown pending",
            }) => {}
            Ok(Response {
                success: true,
                reason: "Received Db Items",
            }) => {
                info!("Received Db Items: Closing");
                if self.flood_closing_events().await.unwrap() {
                    warn!("Flood closing event shutdown");
                    return ResponseResult::Exit;
                }
            }
            Ok(Response {
                success: true,
                reason,
            }) => {
                error!("UNHANDLED RESPONSE TYPE: {:?}", reason);
            }
            Ok(Response {
                success: false,
                reason,
            }) => {
                error!("WARNING: UNHANDLED RESPONSE TYPE FAILURE: {:?}", reason);
            }
            Err(error) => {
                panic!("ERROR HANDLING RESPONSE: {:?}", error);
            }
        };

        ResponseResult::Continue
    }

    /// Listens for new events from peers and handles them.
    /// The future returned from this function should be executed in the runtime. It will block execution.
    pub async fn handle_next_event<E: Future<Output = &'static str> + Unpin>(
        &mut self,
        exit: &mut E,
    ) -> Option<Result<Response>> {
        loop {
            // State machines are not kept between iterations or calls.
            // All selection calls (between = and =>), need to be droppable
            // i.e they should only await a channel.
            tokio::select! {
                event = self.node.next_event() => {
                    trace!("handle_next_event evt {:?}", event);
                    if let res @ Some(_) = self.handle_event(event?).await.transpose() {
                        return res;
                    }
                }
                Some(event) = self.local_events.rx.recv() => {
                    if let Some(res) = self.handle_local_event(event).await {
                        return Some(Ok(res));
                    }
                }
                reason = &mut *exit => return Some(Ok(Response {
                    success: true,
                    reason,
                }))
            }
        }
    }

    /// Local event channel.
    pub fn local_event_tx(&self) -> &LocalEventSender {
        &self.local_events.tx
    }

    ///Handle a local event
    ///
    /// ### Arguments
    ///
    /// * `event` - Event to process.
    async fn handle_local_event(&mut self, event: LocalEvent) -> Option<Response> {
        match event {
            LocalEvent::Exit(reason) => Some(Response {
                success: true,
                reason,
            }),
            LocalEvent::ReconnectionComplete => {
                if let Err(err) = self.send_startup_requests().await {
                    error!("Failed to send startup requests on reconnect: {}", err);
                    return Some(Response {
                        success: false,
                        reason: "Failed to send startup requests on reconnection",
                    });
                }
                Some(Response {
                    success: true,
                    reason: "Sent startup requests on reconnection",
                })
            }
            LocalEvent::CoordinatedShutdown(_) => None,
            LocalEvent::Ignore => None,
        }
    }

    ///Passes a frame from an event to the handle_new_frame method
    ///
    /// ### Arguments
    ///
    /// * `event` - Event object holding the frame to be passed.
    async fn handle_event(&mut self, event: Event) -> Result<Option<Response>> {
        match event {
            Event::NewFrame { peer, frame } => {
                let peer_span = error_span!("peer", ?peer);
                self.handle_new_frame(peer, frame)
                    .instrument(peer_span)
                    .await
            }
        }
    }

    /// Handles a new incoming message from a peer.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Socket Address of the sending peer node.
    /// * `frame` - Byte object holding the frame being handled.
    async fn handle_new_frame(
        &mut self,
        peer: SocketAddr,
        frame: Bytes,
    ) -> Result<Option<Response>> {
        let req = deserialize::<PreLaunchRequest>(&frame).map_err(|error| {
            warn!(?error, "frame-deserialize");
            error
        })?;

        let req_span = error_span!("request", ?req);
        let response = self.handle_request(peer, req).instrument(req_span).await;
        trace!(?response, ?peer, "response");

        Ok(response)
    }

    /// Handles a request.
    ///
    /// ### Arguments
    ///
    /// * `peer` - Peer sending the request.
    /// * `req`  - Request to execute
    async fn handle_request(
        &mut self,
        peer: SocketAddr,
        req: PreLaunchRequest,
    ) -> Option<Response> {
        use PreLaunchRequest::*;
        trace!("handle_request: {:?}", req);

        match req {
            SendDbItems { committed, items } => self.receive_db_items(peer, committed, items),
            Closing => self.receive_closing(peer),
        }
    }

    /// Handles the receipt of closing event
    ///
    /// ### Arguments
    ///
    /// * `peer`      - Sending peer's socket address
    /// * `committed` - Info on last committed item
    /// * `items`     - Database items
    fn receive_db_items(
        &mut self,
        _peer: SocketAddr,
        _committed: CommittedIndex,
        items: Vec<DbItem>,
    ) -> Option<Response> {
        if let Err(e) = self.raft_db.import_items(
            items
                .iter()
                .map(|v| (v.column.as_ref(), v.key.as_ref(), v.data.as_ref())),
        ) {
            error!("Received invalid item: {:?}", e);
            return Some(Response {
                success: false,
                reason: "Received Invalid Db Items",
            });
        }

        Some(Response {
            success: true,
            reason: "Received Db Items",
        })
    }

    /// Handles the receipt of closing event
    ///
    /// ### Arguments
    ///
    /// * `peer`     - Sending peer's socket address
    fn receive_closing(&mut self, peer: SocketAddr) -> Option<Response> {
        if !self.shutdown_group.remove(&peer) {
            return None;
        }

        if !self.shutdown_group.is_empty() {
            return Some(Response {
                success: true,
                reason: "Shutdown pending",
            });
        }

        Some(Response {
            success: true,
            reason: "Shutdown",
        })
    }

    /// Floods the closing event to everyone
    pub async fn flood_closing_events(&mut self) -> Result<bool> {
        self.shutdown_group.remove(&self.address());
        self.node
            .send_to_all(
                self.pre_launch_nodes.iter().copied(),
                PreLaunchRequest::Closing,
            )
            .await?;
        Ok(self.shutdown_group.is_empty())
    }
}
