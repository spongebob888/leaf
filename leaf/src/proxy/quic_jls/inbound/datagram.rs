use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rustls_jls::JlsConfig;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{proxy::*, session::Session};

use super::QuicProxyStream;
use quinn_jls as quinn;
use quinn_jls::{RecvStream, SendStream};
use rustls_jls as rustls;

struct Incoming {
    bi_recv: Receiver<(SendStream, RecvStream, SocketAddr)>,
    incoming_closed: bool,
}

impl Incoming {
    pub fn new(inner: quinn::Endpoint, zero_rtt: bool) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::channel(20);
        let (bi_send, bi_recv) = tokio::sync::mpsc::channel(20);
        tokio::spawn(handle_connectings(inner.clone(), conn_send, zero_rtt));
        tokio::spawn(handle_connections(conn_recv, bi_send));
        Incoming {
            bi_recv: bi_recv,
            incoming_closed: false,
        }
    }
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.bi_recv).poll_recv(cx) {
            Poll::Ready(Some((send, recv, addr))) => {
                let mut sess = Session {
                    source: addr,
                    ..Default::default()
                };
                // TODO Check whether the index suitable for this purpose.
                sess.stream_id = Some(send.id().index());
                let stream =
                    AnyBaseInboundTransport::Stream(Box::new(QuicProxyStream { recv, send }), sess);
                Poll::Ready(Some(stream))
            }
            Poll::Ready(None) => {
                self.incoming_closed = true;
                log::error!("[quic-jls] endpoint closed");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn quic_err<E>(error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}

pub struct Handler {
    server_config: quinn::ServerConfig,
    zero_rtt: bool,
}

impl Handler {
    pub fn new(
        certificate: String,
        certificate_key: String,
        alpns: Vec<String>,
        zero_rtt: bool,
        jls_pwd: String,
        jls_iv: String,
        upstream_addr: String,
        congestion_ctrl: String,
    ) -> Result<Self> {
        let (cert, key) = if certificate.is_empty() && certificate_key.is_empty() {
            let cert =
                rcgen::generate_simple_self_signed(vec![upstream_addr.clone().into()]).unwrap();
            let cert_der = cert.serialize_der().unwrap();
            let priv_key = cert.serialize_private_key_der();
            let priv_key = rustls::PrivateKey(priv_key);
            let cert_chain = vec![rustls::Certificate(cert_der.clone())];
            log::info!("[quic-jls] generate self-signed cert automatically");
            (cert_chain, priv_key)
        } else {
            let (cert, key) =
                fs::read(&certificate).and_then(|x| Ok((x, fs::read(&certificate_key)?)))?;

            let cert = match Path::new(&certificate).extension().map(|ext| ext.to_str()) {
                Some(Some(ext)) if ext == "der" => {
                    vec![rustls::Certificate(cert)]
                }
                _ => rustls_pemfile::certs(&mut &*cert)?
                    .into_iter()
                    .map(rustls::Certificate)
                    .collect(),
            };

            let key = match Path::new(&certificate_key)
                .extension()
                .map(|ext| ext.to_str())
            {
                Some(Some(ext)) if ext == "der" => rustls::PrivateKey(key),
                _ => {
                    let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)?;
                    match pkcs8.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)?;
                            match rsa.into_iter().next() {
                                Some(x) => rustls::PrivateKey(x),
                                None => {
                                    let rsa = rustls_pemfile::ec_private_keys(&mut &*key)?;
                                    match rsa.into_iter().next() {
                                        Some(x) => rustls::PrivateKey(x),
                                        None => {
                                            return Err(anyhow!("no private keys found",));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            (cert, key)
        };

        let mut crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;
        (crypto.send_half_rtt_data, crypto.max_early_data_size) = if zero_rtt {
            (true, u32::MAX)
        } else {
            (false, 0)
        };
        if jls_pwd.is_empty() {
            return Err(anyhow!("quic-jls: empty jls pwd"));
        }
        crypto.jls_config = JlsConfig::new(&jls_pwd, &jls_iv);
        for alpn in alpns {
            crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
            .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
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
                log::error!("congestion controller {:?} not supported", congestion_ctrl);
            }
        };
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.jls_config = quinn::JlsServerConfig::new(&upstream_addr).into();
        server_config.transport = Arc::new(transport_config);

        Ok(Self {
            server_config,
            zero_rtt,
        })
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        let incoming = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(self.server_config.clone()),
            socket.into_std()?,
            runtime,
        )
        .map_err(quic_err)?;
        Ok(InboundTransport::Incoming(Box::new(Incoming::new(
            incoming,
            self.zero_rtt,
        ))))
    }
}

async fn handle_connectings(
    ep: quinn::Endpoint,
    conn_send: Sender<quinn::Connection>,
    zero_rtt: bool,
) {
    while let Some(conn) = ep.accept().await {
        log::trace!("[quic-jls] incoming connecting");
        if zero_rtt {
            match conn.into_0rtt() {
                Ok((conn, _accept)) => {
                    log::trace!("[quic-jls] try into half rtt");
                    let _ = conn_send.send(conn).await.map_err(|e| {
                        log::trace!("[quic-jls] connection send channel closed: {:?}", e)
                    });
                }
                Err(conn) => {
                    log::trace!("[quic-jls] into half rtt failed");
                    match conn.await {
                        Ok(conn) => {
                            let _ = conn_send.send(conn).await.map_err(|e| {
                                log::trace!("[quic-jls] connection send channel closed: {:?}", e)
                            });
                        }
                        Err(e) => {
                            log::trace!("[quic-jls]] into connnection failed");
                        }
                    }
                }
            }
        } else {
            match conn.await {
                Ok(conn) => {
                    let _ = conn_send.send(conn).await.map_err(|e| {
                        log::trace!("[quic-jls] connection send channel closed: {:?}", e)
                    });
                }
                Err(e) => {
                    log::trace!("[quic-jls] into connnection failed");
                }
            }
        }
    }
}

async fn handle_connections(
    mut conn_recv: Receiver<quinn::Connection>,
    bi_send: Sender<(SendStream, RecvStream, SocketAddr)>,
) {
    let mut conns = Vec::<quinn::Connection>::new();
    let mut futs = FuturesUnordered::new();
    loop {
        conns.retain(|x| x.close_reason() == None);
        if futs.is_empty() {
            match conn_recv.recv().await {
                Some(conn) => conns.push(conn),
                None => {
                    log::error!("[quic-jls] connection send channel closed");
                    break;
                }
            }
        }
        while let Some(conn) = conns.pop() {
            let fut = async {
                loop {
                    match conn.accept_bi().await {
                        Ok((send, recv)) => {
                            match bi_send.send((send, recv, conn.remote_address())).await {
                                Ok(()) => (),
                                Err(e) => {
                                    log::error!(
                                        "[quic-jls] bi stream recv channel closed: {:?}",
                                        e
                                    );
                                    drop(conn);
                                    break Err("Send Err");
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("[quic-jls] accept bi error: {:?}", e);
                            drop(conn);
                            break Err("Connection Err");
                        }
                    }
                }
            };
            futs.push(fut);
        }
        select! {
            incoming = conn_recv.recv() => {
                match incoming {
                    Some(conn) => {conns.push(conn)}
                    None => {
                        log::error!("[quic-jls] connection send channel closed");
                        break
                    }
                }
            }
            incoming = futs.next() => {
                match incoming {
                    Some(Ok(())) => {}
                    Some(Err("Send Err")) => {break;}
                    Some(Err(_e)) => {}
                    None => {}
                }

            }
        }
    }
}
