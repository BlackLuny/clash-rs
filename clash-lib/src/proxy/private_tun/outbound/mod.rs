mod datagram;
use super::Client;
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        net::OutboundInterface,
    },
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, ProxyStream,
        utils::{
            GLOBAL_DIRECT_CONNECTOR, RemoteConnector, new_tcp_stream, new_udp_socket,
        },
    },
    session::{Session, SocksAddr},
};
use async_trait::async_trait;
use tracing::error;

use private_tun::snell_impl_ver::{
    client::ServerConnector,
    client_zfc::{ConnType, run_client_with_config_and_name},
    config::ClientConfig,
    udp_intf::{
        create_ringbuf_channel, create_udp_ringbuf_channel_l2t,
        create_udp_ringbuf_channel_t2l,
    },
};
use socket2::Socket;
use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{io::duplex, sync::oneshot};
use tracing::debug;
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub udp: bool,
    pub origin_client_config: ClientConfig,
    pub is_uot: bool,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,

    client: tokio::sync::RwLock<Option<Client>>,

    is_started: AtomicBool,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateTun")
            .field("name", &self.opts.name)
            .finish()
    }
}

struct PrivateRemoteConnector {
    iface: Option<OutboundInterface>,
    dns_resolver: ThreadSafeDNSResolver,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
}

impl PrivateRemoteConnector {
    pub fn new(
        iface: Option<OutboundInterface>,
        dns_resolver: ThreadSafeDNSResolver,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> Self {
        Self {
            iface,
            dns_resolver,
            #[cfg(target_os = "linux")]
            so_mark,
        }
    }
}
#[async_trait::async_trait]
impl ServerConnector for PrivateRemoteConnector {
    async fn connect(
        &self,
        addr: &private_tun::address::Address,
    ) -> anyhow::Result<tokio::net::TcpStream> {
        let target_addr = match addr {
            private_tun::address::Address::Socket(addr) => *addr,
            private_tun::address::Address::Domain(domain, port) => {
                let server_addr = self.dns_resolver.resolve(domain, false).await?;
                if let Some(server_addr) = server_addr {
                    (server_addr, *port).into()
                } else {
                    return Err(anyhow::anyhow!(
                        "failed to resolve domain: {domain}"
                    ));
                }
            }
        };
        let stream = new_tcp_stream(
            target_addr,
            self.iface.as_ref(),
            #[cfg(target_os = "linux")]
            self.so_mark,
        )
        .await?;
        Ok(stream)
    }
}

struct DnsClientWrapper(ThreadSafeDNSResolver);
#[async_trait::async_trait]
impl ::private_tun::dns_cache::DnsResolver for DnsClientWrapper {
    async fn resolve_dns(
        &self,
        host: &str,
        _port: u16,
    ) -> anyhow::Result<Vec<IpAddr>> {
        self.0
            .resolve(host, false)
            .await
            .map(|x| x.into_iter().collect())
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            client: tokio::sync::RwLock::new(None),
            is_started: AtomicBool::new(false),
            connector: tokio::sync::Mutex::new(None),
        }
    }

    async fn start_client(
        &self,
        dns_resolver: ThreadSafeDNSResolver,
        iface: Option<OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> Result<(), io::Error> {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (inbound_tx, inbound_rx) = create_ringbuf_channel(13);
        let config_name = self.opts.name.clone();
        let dns_resolver = Arc::new(DnsClientWrapper(dns_resolver))
            as Arc<dyn ::private_tun::dns_cache::DnsResolver>;

        let client_config = self.opts.origin_client_config.clone();
        tokio::spawn(async move {
            use ::private_tun::snell_impl_ver::client_run::init_ring_provider;
            let _ = init_ring_provider();
            let _h = run_client_with_config_and_name(
                client_config,
                inbound_rx,
                &config_name,
                Some(cancel_token),
                true,
                Some(Arc::new(Box::new(
                    move |socket: &Socket, endpoint: &SocketAddr| {
                        use crate::proxy::utils::must_bind_socket_on_interface;
                        let family = match endpoint {
                            SocketAddr::V4(_) => socket2::Domain::IPV4,

                            SocketAddr::V6(_) => socket2::Domain::IPV6,
                        };
                        #[cfg(not(target_os = "android"))]
                        if let Some(iface) = &iface {
                            debug!(
                                "binding tcp socket to interface: {iface:?}, \
                                 family: {family:?}"
                            );
                            if let Err(e) =
                                must_bind_socket_on_interface(socket, iface, family)
                            {
                                error!("failed to bind socket to interface: {e}");
                            }
                        }

                        #[cfg(target_os = "linux")]
                        if let Some(so_mark) = so_mark {
                            if let Err(e) = socket.set_mark(so_mark) {
                                error!("failed to set mark: {e}");
                            }
                        }
                    },
                ))),
                Some(dns_resolver),
            )
            .await;
        });
        let client =
            Client::new(tokio::sync::Mutex::new(inbound_tx), cancel_token_clone);
        self.client.write().await.replace(client);
        Ok(())
    }

    async fn proxy_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        debug!(
            "Proxying stream for session: {:?}, server: {}, port: {}",
            sess, self.opts.server, self.opts.port
        );
        if !self.is_started.load(Ordering::Relaxed) {
            self.start_client(
                resolver.clone(),
                sess.iface.as_ref().cloned(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
            self.is_started.store(true, Ordering::Relaxed);
        }

        // Create a duplex channel to bridge leaf's stream with private_tun
        let (client_side_pipe0, client_side_pipe1) = duplex(8192);
        // let (server_side_pipe0, mut server_side_pipe1) = duplex(8192);

        // Create MemDuplex using private_tun's implementation
        let mem_duplex = private_tun::self_proxy::MemDuplex::new(
            client_side_pipe0,
            self.client
                .read()
                .await
                .as_ref()
                .unwrap()
                .cancel_token
                .clone(),
        );

        // Convert destination to private_tun's Address format
        let target = match &sess.destination {
            crate::session::SocksAddr::Ip(addr) => {
                private_tun::address::Address::Socket(*addr)
            }
            crate::session::SocksAddr::Domain(domain, port) => {
                private_tun::address::Address::Domain(domain.clone().into(), *port)
            }
        };

        // Create oneshot channel for response
        let (rst_tx, _rst_rx) = oneshot::channel();

        // Create ConnType for Duplex connection
        let conn_type = ConnType::Duplex {
            stream: mem_duplex,
            target,
            rst_tx,
            server_name: None,
            traffic_collector: None,
            one_rtt: false,
            reuse_tcp: true,
            piped_stream: None,
            remote_stream_connector: Some(Box::new(PrivateRemoteConnector::new(
                sess.iface.as_ref().cloned(),
                resolver,
                #[cfg(target_os = "linux")]
                sess.so_mark,
            ))),
        };

        // Send connection request to private_tun client
        self.client
            .read()
            .await
            .as_ref()
            .unwrap()
            .push_event(conn_type)
            .await
            .map_err(|_e| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("failed to send connection request"),
                )
            })?;

        Ok(Box::new(client_side_pipe1))
    }

    async fn proxy_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<datagram::OutboundDatagramPrivateTun> {
        debug!(
            "Proxying stream for session: {:?}, server: {}, port: {}",
            sess, self.opts.server, self.opts.port
        );
        if !self.is_started.load(Ordering::Relaxed) {
            self.start_client(
                resolver.clone(),
                sess.iface.as_ref().cloned(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
            self.is_started.store(true, Ordering::Relaxed);
        }

        let cancel_token = self
            .client
            .read()
            .await
            .as_ref()
            .unwrap()
            .cancel_token
            .clone();

        // Convert destination to private_tun's Address format
        let target = match &sess.destination {
            SocksAddr::Ip(addr) => private_tun::address::Address::Socket(*addr),
            SocksAddr::Domain(domain, port) => {
                private_tun::address::Address::Domain(domain.clone().into(), *port)
            }
        };

        // Create UDP ring buffer channels
        let (l2t_sender, l2t_receiver) = create_udp_ringbuf_channel_l2t();
        let (t2l_sender, t2l_receiver) = create_udp_ringbuf_channel_t2l();

        // Create oneshot channel for response
        let (rst_tx, _rst_rx) = oneshot::channel();

        // Use a default peer address since we don't have socket info
        let peer_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let src = if resolver.ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        };
        let remote_udp_socket = new_udp_socket(
            Some(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)),
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )
        .await?;

        // Create ConnType for UDP connection
        let conn_type = ConnType::Udp {
            peer_addr,
            target,
            rst_tx,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            out_ip: None,
            cancel_token,
            data_send_to_remote: l2t_receiver,
            data_send_to_local: t2l_sender,
            traffic_collector: None,
            server_name: None,
            piped_stream: None,
            custom_udp_socket: Some(remote_udp_socket),
        };

        // Send connection request to private_tun client
        self.client
            .read()
            .await
            .as_ref()
            .unwrap()
            .push_event(conn_type)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed to send UDP connection request",
                )
            })?;

        Ok(datagram::OutboundDatagramPrivateTun::new(
            l2t_sender,
            t2l_receiver,
        ))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::PrivateTun
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        self.connect_stream_with_connector(
            sess,
            resolver,
            GLOBAL_DIRECT_CONNECTOR.as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        self.connect_datagram_with_connector(
            sess,
            resolver,
            GLOBAL_DIRECT_CONNECTOR.as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector, // todo support proxy chain
    ) -> io::Result<BoxedChainedStream> {
        let s = self.proxy_stream(sess, resolver).await?;
        let chained: ChainedStreamWrapper<Box<dyn ProxyStream>> =
            ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let d = self.proxy_datagram(sess, resolver).await?;
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}
