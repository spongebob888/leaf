use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::{io, pin::Pin};

use ::quinn::Connecting;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::{
    task::{Context, Poll},
    Future,
};
use futures_util::pin_mut;
use rustls_jls::JlsConfig;

use crate::{proxy::*, session::Session};

use super::QuicProxyStream;
use quinn_jls as quinn;
use rustls_jls as rustls;

struct Incoming {
    inner: quinn::Endpoint,
    connectings: Vec<quinn::Connecting>,
    new_conns: Vec<quinn::Connection>,
    incoming_closed: bool,
    zero_rtt: bool,
}

impl Incoming {
    pub fn new(inner: quinn::Endpoint, zero_rtt: bool) -> Self {
        Incoming {
            inner,
            connectings: Vec::new(),
            new_conns: Vec::new(),
            incoming_closed: false,
            zero_rtt: zero_rtt,
        }
    }
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // FIXME don't iterate and poll all
        let mut connectings = Vec::<quinn::Connecting>::new();
        let mut closed = false;
        if !self.incoming_closed {
            let fut = Box::pin(self.inner.accept());
            pin_mut!(fut);
            match fut.poll(cx) {
                Poll::Ready(Some(connecting)) => {
                    connectings.push(connecting);
                }
                Poll::Ready(None) => {
                    closed = true;
                }
                Poll::Pending => (),
            }
        }
        self.connectings.append(&mut connectings);
        self.incoming_closed = closed;
        let mut new_conns = Vec::new();
        let zero_rtt = self.zero_rtt;
        while let Some(connecting) = self.connectings.pop() {
            if zero_rtt {
                if let Ok((new_conn, _accept_zero_rtt)) = connecting.into_0rtt() {
                    new_conns.push(new_conn);
                } else {
                    log::error!("error while setup zero rtt connection");
                }
            } else {
                let fut = Box::pin(connecting);
                pin_mut!(fut);
                match fut.poll(cx) {
                    Poll::Ready(Ok(new_conn)) => {
                        new_conns.push(new_conn);
                    }
                    Poll::Ready(Err(e)) => {
                        log::debug!("quic connect failed: {}", e);
                    }
                    Poll::Pending => (),
                }
            }
        }
        if !new_conns.is_empty() {
            self.new_conns.append(&mut new_conns);
        }

        let mut stream: Option<Self::Item> = None;
        let mut completed = Vec::new();
        for (idx, new_conn) in self.new_conns.iter_mut().enumerate() {
            let fut = Box::pin(new_conn.accept_bi());
            pin_mut!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok((send, recv))) => {
                    let mut sess = Session {
                        source: new_conn.remote_address(),
                        ..Default::default()
                    };
                    // TODO Check whether the index suitable for this purpose.
                    sess.stream_id = Some(send.id().index());
                    stream.replace(AnyBaseInboundTransport::Stream(
                        Box::new(QuicProxyStream { recv, send }),
                        sess,
                    ));
                    break;
                }
                Poll::Ready(Err(e)) => {
                    log::debug!("new quic bidirectional stream failed: {}", e);
                    completed.push(idx);
                }
                Poll::Pending => (),
            }
        }
        for idx in completed.iter().rev() {
            self.new_conns.remove(*idx);
        }

        if let Some(stream) = stream.take() {
            Poll::Ready(Some(stream))
        } else if self.incoming_closed && self.connectings.is_empty() && self.new_conns.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
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
