//! Utilities necessary to establish a TCP connection with TLS overay stream.

use super::{CommsError, Result};
use crate::configurations::{TlsPrivateInfo, TlsSpec};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, Certificate, ClientConfig, NoClientAuth, PrivateKey,
    RootCertStore, ServerConfig, Session,
};
use tokio_rustls::webpki::{DNSNameRef, EndEntityCert};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::Stream;

pub type TlsStreamClient = tokio_rustls::client::TlsStream<TcpStream>;
pub type TlsStreamServer = tokio_rustls::server::TlsStream<TcpStream>;
pub type TlsCertificate = Certificate;

pub struct TcpTlsConfig {
    address: SocketAddr,
    socket_name_mapping: BTreeMap<SocketAddr, String>,
    pem_certs: String,
    pem_pkcs8_private_keys: String,
    trusted_pem_certs: Vec<String>,
    use_tls: bool,
    listener: Arc<Mutex<Option<TcpListener>>>,
}

impl TcpTlsConfig {
    pub fn new_no_tls(address: SocketAddr) -> Self {
        Self {
            address,
            socket_name_mapping: Default::default(),
            pem_certs: Default::default(),
            pem_pkcs8_private_keys: Default::default(),
            trusted_pem_certs: Default::default(),
            use_tls: false,
            listener: Default::default(),
        }
    }

    pub fn from_tls_spec(address: SocketAddr, config: &TlsSpec) -> Result<Self> {
        if config.pem_certificates.is_empty() {
            Ok(Self::new_no_tls(address))
        } else {
            let name = socket_name_mapping_or_default(&config.socket_name_mapping, address);
            let (socket_name_mapping, trusted_pem_certs) =
                if let Some(untrusted_names) = &config.untrusted_names {
                    (
                        config
                            .socket_name_mapping
                            .clone()
                            .into_iter()
                            .filter(|(_, v)| !untrusted_names.contains(v))
                            .collect(),
                        config
                            .pem_certificates
                            .iter()
                            .filter(|(k, _)| !untrusted_names.contains(k.as_str()))
                            .map(|(_, v)| v.clone())
                            .collect(),
                    )
                } else {
                    (
                        config.socket_name_mapping.clone(),
                        config.pem_certificates.values().cloned().collect(),
                    )
                };

            Ok(Self {
                address,
                socket_name_mapping,
                pem_certs: config
                    .pem_certificate_override
                    .as_ref()
                    .or_else(|| config.pem_certificates.get(&name))
                    .ok_or(CommsError::ConfigError("Missing TLS node certificate"))?
                    .clone(),
                pem_pkcs8_private_keys: config
                    .pem_pkcs8_private_key_override
                    .as_ref()
                    .or_else(|| config.pem_pkcs8_private_keys.get(&name))
                    .ok_or(CommsError::ConfigError("Missing TLS node keys"))?
                    .clone(),
                trusted_pem_certs,
                use_tls: true,
                listener: Default::default(),
            })
        }
    }

    pub fn mut_socket_name_mapping(&mut self) -> &mut BTreeMap<SocketAddr, String> {
        &mut self.socket_name_mapping
    }

    pub fn mut_trusted_pem_certs(&mut self) -> &mut Vec<String> {
        &mut self.trusted_pem_certs
    }

    pub async fn with_listener(self, listener: TcpListener) -> Self {
        *self.listener.lock().await = Some(listener);
        self
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn clone_private_info(&self) -> TlsPrivateInfo {
        TlsPrivateInfo {
            pem_certs: self.pem_certs.clone(),
            pem_pkcs8_private_keys: self.pem_pkcs8_private_keys.clone(),
        }
    }
}

pub struct TcpTlsListner {
    tcp_listener: TcpListener,
    tls_acceptor: Option<TlsAcceptor>,
    listener_address: SocketAddr,
}

impl TcpTlsListner {
    pub async fn new(config: &TcpTlsConfig) -> Result<Self> {
        let tls_acceptor = if config.use_tls {
            let server_config = new_server_config(config)?;
            Some(TlsAcceptor::from(Arc::new(server_config)))
        } else {
            None
        };

        let tcp_listener = if let Some(listener) = config.listener.lock().await.take() {
            listener
        } else {
            Self::new_raw_listner(config.address).await?
        };
        let mut listener_address = config.address;
        listener_address.set_port(tcp_listener.local_addr()?.port());

        Ok(Self {
            tcp_listener,
            tls_acceptor,
            listener_address,
        })
    }

    pub async fn new_raw_listner(address: SocketAddr) -> Result<TcpListener> {
        let mut bind_address = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        bind_address.set_port(address.port());
        Ok(TcpListener::bind(bind_address).await?)
    }

    pub fn listener_address(&self) -> SocketAddr {
        self.listener_address
    }

    pub fn listener_as_stream(mut self) -> impl Stream<Item = Result<TcpTlsStream>> {
        async_stream::stream! {
            loop {
                yield self.next_tcp_tls_stream().await;
            }
        }
    }

    async fn next_tcp_tls_stream(&mut self) -> Result<TcpTlsStream> {
        let (stream, _addr) = self.tcp_listener.accept().await?;
        if let Some(tls_acceptor) = &mut self.tls_acceptor {
            let stream = tls_acceptor.accept(stream).await?;
            let peer_addr = stream.get_ref().0.peer_addr()?;
            Ok(TcpTlsStream::Server(stream, peer_addr))
        } else {
            let peer_addr = stream.peer_addr()?;
            Ok(TcpTlsStream::RawTcp(stream, peer_addr))
        }
    }
}

#[derive(Clone)]
pub struct TcpTlsConnector {
    socket_name_mapping: BTreeMap<SocketAddr, String>,
    tls_connector: Option<TlsConnector>,
}

impl TcpTlsConnector {
    pub fn new(config: &TcpTlsConfig) -> Result<Self> {
        let tls_connector = if config.use_tls {
            let client_config = new_client_config(config)?;
            Some(TlsConnector::from(Arc::new(client_config)))
        } else {
            None
        };
        let socket_name_mapping = config.socket_name_mapping.clone();

        Ok(Self {
            socket_name_mapping,
            tls_connector,
        })
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<TcpTlsStream> {
        let stream = TcpStream::connect(addr).await?;

        if let Some(tls_connector) = &self.tls_connector {
            let tls_name = socket_name_mapping_or_default(&self.socket_name_mapping, addr);
            let domain = DNSNameRef::try_from_ascii_str(&tls_name)
                .map_err(|_| CommsError::ConfigError("invalid dnsname"))?;
            let stream = tls_connector.connect(domain, stream).await?;
            let peer_addr = stream.get_ref().0.peer_addr()?;
            Ok(TcpTlsStream::Client(stream, peer_addr))
        } else {
            let peer_addr = stream.peer_addr()?;
            Ok(TcpTlsStream::RawTcp(stream, peer_addr))
        }
    }

    pub fn socket_name_mapping(&self, addr: SocketAddr) -> String {
        socket_name_mapping_or_default(&self.socket_name_mapping, addr)
    }
}

impl fmt::Debug for TcpTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TcpTlsConnector()")
    }
}

fn load_certs(pem: &str) -> Result<Vec<TlsCertificate>> {
    certs(&mut Cursor::new(pem)).map_err(|_| CommsError::ConfigError("invalid cert"))
}

fn load_keys(pem: &str) -> Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut Cursor::new(pem)).map_err(|_| CommsError::ConfigError("invalid key"))
}

fn add_cert_to_root(
    root_store: &mut RootCertStore,
    trusted_certs: &[TlsCertificate],
) -> Result<()> {
    for cert in trusted_certs {
        root_store
            .add(cert)
            .map_err(|_| CommsError::ConfigError("invalid root cert"))?;
    }
    Ok(())
}

fn new_root_certs(trusted_pem_certs: &[String]) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    for trusted_pem_cert in trusted_pem_certs {
        let trusted_certs = load_certs(trusted_pem_cert)?;
        add_cert_to_root(&mut root_store, &trusted_certs)?;
    }
    Ok(root_store)
}

fn new_server_config(config: &TcpTlsConfig) -> Result<ServerConfig> {
    let root_store = new_root_certs(&config.trusted_pem_certs)?;
    let certs = load_certs(&config.pem_certs)?;
    let mut keys = load_keys(&config.pem_pkcs8_private_keys)?;
    let _client_auth = NoClientAuth::new();
    let client_auth = AllowAnyAnonymousOrAuthenticatedClient::new(root_store);

    let mut server_config = ServerConfig::new(client_auth);
    server_config.set_single_cert(certs, keys.remove(0))?;
    Ok(server_config)
}

fn new_client_config(config: &TcpTlsConfig) -> Result<ClientConfig> {
    let root_store = new_root_certs(&config.trusted_pem_certs)?;
    let certs = load_certs(&config.pem_certs)?;
    let mut keys = load_keys(&config.pem_pkcs8_private_keys)?;

    let mut client_config = ClientConfig::new();
    client_config.root_store = root_store;
    client_config.set_single_client_cert(certs, keys.remove(0))?;
    Ok(client_config)
}

#[derive(Debug)]
pub enum TcpTlsStream {
    Client(TlsStreamClient, SocketAddr),
    Server(TlsStreamServer, SocketAddr),
    RawTcp(TcpStream, SocketAddr),
}

impl TcpTlsStream {
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Client(_, a) | Self::Server(_, a) | Self::RawTcp(_, a) => *a,
        }
    }

    pub fn peer_tls_certificate(&self) -> Option<TlsCertificate> {
        match self {
            Self::Client(tls, _) => get_first_certificate(tls.get_ref().1),
            Self::Server(tls, _) => get_first_certificate(tls.get_ref().1),
            Self::RawTcp(_, _) => None,
        }
    }
}

impl AsyncRead for TcpTlsStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s, _) => Pin::new(s).poll_read(ctx, buffer),
            Self::Server(s, _) => Pin::new(s).poll_read(ctx, buffer),
            Self::RawTcp(s, _) => Pin::new(s).poll_read(ctx, buffer),
        }
    }
}

impl AsyncWrite for TcpTlsStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Client(s, _) => Pin::new(s).poll_write(ctx, buffer),
            Self::Server(s, _) => Pin::new(s).poll_write(ctx, buffer),
            Self::RawTcp(s, _) => Pin::new(s).poll_write(ctx, buffer),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s, _) => Pin::new(s).poll_flush(ctx),
            Self::Server(s, _) => Pin::new(s).poll_flush(ctx),
            Self::RawTcp(s, _) => Pin::new(s).poll_flush(ctx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s, _) => Pin::new(s).poll_shutdown(ctx),
            Self::Server(s, _) => Pin::new(s).poll_shutdown(ctx),
            Self::RawTcp(s, _) => Pin::new(s).poll_shutdown(ctx),
        }
    }
}

/// verify the dna name is valid for the certificae
pub fn verify_is_valid_for_dns_names<'a>(
    cert: &TlsCertificate,
    tls_names: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let domains: std::result::Result<Vec<_>, _> =
        tls_names.map(DNSNameRef::try_from_ascii_str).collect();
    let domains = domains.map_err(|_| CommsError::ConfigError("invalid dnsname"))?;

    let cert = EndEntityCert::from(&cert.0)?;
    cert.verify_is_valid_for_at_least_one_dns_name(domains.iter().copied())?;
    Ok(())
}

fn get_first_certificate(session: &impl Session) -> Option<TlsCertificate> {
    session
        .get_peer_certificates()
        .and_then(|mut v| v.drain(..).next())
}

pub fn socket_name_mapping_or_default(
    mapping: &BTreeMap<SocketAddr, String>,
    addr: SocketAddr,
) -> String {
    mapping
        .get(&addr)
        .or_else(|| {
            let mut addr = addr;
            addr.set_port(0);
            mapping.get(&addr)
        })
        .cloned()
        .unwrap_or_else(|| default_name_mapping(addr))
}

pub fn default_name_mapping(addr: SocketAddr) -> String {
    format!("{}.{}.nodes.zenotta.xyz", addr.ip(), addr.port())
}
