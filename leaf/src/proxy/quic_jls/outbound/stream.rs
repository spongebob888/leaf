use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::sync::Mutex;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

use super::QuicProxyStream;

use quinn_jls as quinn;
use rustls_jls as rustls;
use rustls_jls::JlsConfig;
use tracing::{info, trace, error};

fn quic_err<E>(error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}

struct Connection {
    pub new_conn: quinn::Connection,
    pub total_accepted: usize,
    pub completed: bool,
    pub zero_rtt: bool,
}

struct Manager {
    address: String,
    port: u16,
    server_name: Option<String>,
    dns_client: SyncDnsClient,
    client_config: quinn::ClientConfig,
    connections: Mutex<Vec<Connection>>,
    zero_rtt: bool,
}

impl Manager {
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        dns_client: SyncDnsClient,
        zero_rtt: bool,
        jls_pwd: String,
        jls_iv: String,
        congestion_ctrl: String,
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_server_trust_anchors(webpki_roots_old::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.enable_early_data = zero_rtt;
        client_crypto.jls_config = JlsConfig::new(&jls_pwd, &jls_iv);
        for alpn in alpns {
            client_crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            300_000,
        )))); // ms
        match congestion_ctrl.as_str() {
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
            "cubic" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::CubicConfig::default(),
                ));
            }
            "newreno" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            "" => {} // Default congestion controller
            _ => {
                error!(
                    "[quic-jls] congestion controller {:?} not supported",
                    congestion_ctrl
                );
            }
        };

        client_config.transport_config(Arc::new(transport_config));

        Manager {
            address,
            port,
            server_name,
            dns_client,
            client_config,
            connections: Mutex::new(Vec::new()),
            zero_rtt: zero_rtt,
        }
    }
}

impl Manager {
    pub async fn new_stream(
        &self,
    ) -> io::Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
        self.connections.lock().await.retain(|c| {
            if c.completed {
                return false;
            }
            match c.new_conn.is_jls() {
                Some(true) => {
                    return true;
                }
                Some(false) => {
                    error!("[quic-jls] jls pwd/iv error or connection hijacked");
                    return false;
                }
                None => return c.zero_rtt, // Wait for handshake (for zero rtt, handshake may not be finished)
            }
        });

        for conn in self.connections.lock().await.iter_mut() {
            if conn.total_accepted < 128 {
                // FIXME I think awaiting here is fine, it should return immediately, not sure.
                match conn.new_conn.open_bi().await {
                    Ok((send, recv)) => {
                        conn.total_accepted += 1;
                        trace!(
                            "[quic-jls] opened quic stream on connection with rtt {}ms, total_accepted {}",
                            conn.new_conn.rtt().as_millis(),
                            conn.total_accepted,
                        );
                        return Ok(QuicProxyStream { recv, send });
                    }
                    Err(e) => {
                        conn.completed = true;
                        debug!("[quic-jls] open quic bidirectional stream failed: {}", e);
                    }
                }
            } else {
                conn.completed = true;
            }
        }

        // FIXME A better indicator.
        let socket = self
            .new_udp_socket(&*crate::option::UNSPECIFIED_BIND_ADDR)
            .await?;
        let runtime = quinn::default_runtime().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "[quic-jls] no async runtime found")
        })?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into_std()?,
            runtime,
        )
        .map_err(quic_err)?;
        endpoint.set_default_client_config(self.client_config.clone());

        let ips = {
            self.dns_client
                .read()
                .await
                .direct_lookup(&self.address)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("[quic-jls] lookup {} failed: {}", &self.address, e),
                    )
                })
                .await?
        };
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "[quic-jls] could not resolve to any address",
            ));
        }
        let connect_addr = SocketAddr::new(ips[0], self.port);

        let server_name = if let Some(name) = self.server_name.as_ref() {
            name
        } else {
            &self.address
        };

        let connecting = endpoint
            .connect(connect_addr, server_name)
            .map_err(quic_err)?;
        let conn_zero_rtt;
        let new_conn = if self.zero_rtt {
            match connecting.into_0rtt() {
                Ok((new_conn, zero_rtt_accept)) => {
                    tokio::spawn(async move {
                        if zero_rtt_accept.await {
                            info!("[quic-jls] zero rtt accepted");
                        } else {
                            info!("[quic-jls] zero rtt rejected");
                        }
                    });
                    conn_zero_rtt = true;
                    new_conn
                }
                Err(conn) => {
                    info!("[quic-jls] zero rtt not available");
                    conn_zero_rtt = false;
                    conn.await?
                }
            }
        } else {
            conn_zero_rtt = false;
            connecting.await.map_err(quic_err)?
        };

        let (send, recv) = new_conn.open_bi().await.map_err(quic_err)?;

        self.connections.lock().await.push(Connection {
            new_conn,
            total_accepted: 1,
            completed: false,
            zero_rtt: conn_zero_rtt,
        });

        Ok(QuicProxyStream { recv, send })
    }
}

impl UdpConnector for Manager {}

pub struct Handler {
    manager: Manager,
}

impl Handler {
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        dns_client: SyncDnsClient,
        zero_rtt: bool,
        jls_pwd: String,
        jls_iv: String,
        congestion_ctrl: String,
    ) -> Self {
        Self {
            manager: Manager::new(
                address,
                port,
                server_name,
                alpns,
                dns_client,
                zero_rtt,
                jls_pwd,
                jls_iv,
                congestion_ctrl,
            ),
        }
    }

    pub async fn new_stream(
        &self,
    ) -> io::Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
        self.manager.new_stream().await
    }
}

impl UdpConnector for Handler {}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        Ok(Box::new(self.new_stream().await?))
    }
}
