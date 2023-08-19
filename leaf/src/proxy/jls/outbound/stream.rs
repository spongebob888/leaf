use std::{io, pin::Pin, task::Poll};

use anyhow::Result;
use async_trait::async_trait;
use futures::TryFutureExt;
use futures_util::FutureExt;
use log::*;
use ring::digest::Context;
use tokio::io::AsyncReadExt;
use tokio_rustls_jls::client::{self, JlsHandler};
use tokio_rustls_jls::rustls::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use tokio_rustls_jls::rustls::version::TLS13;
use tokio_rustls_jls::TlsStream;

use {
    std::sync::Arc,
    tokio_rustls_jls::{
        rustls::{ClientConfig, JlsConfig, OwnedTrustAnchor, RootCertStore, ServerName},
        TlsConnector,
    },
};

use crate::{proxy::*, session::Session};

mod dangerous {
    use std::time::SystemTime;
    use tokio_rustls::rustls::{
        client::{ServerCertVerified, ServerCertVerifier},
        Certificate, Error, ServerName,
    };

    pub(super) struct NotVerified;

    impl ServerCertVerifier for NotVerified {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> core::result::Result<ServerCertVerified, Error> {
            log::debug!("TLS cert for {:?} not verified", server_name);
            Ok(ServerCertVerified::assertion())
        }
    }
}

pub struct Handler {
    server_name: String,
    tls_config: Arc<ClientConfig>,
    zero_rtt: bool,
}

impl Handler {
    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        zero_rtt: bool,
        jls_pwd: String,
        jls_iv: String,
    ) -> Result<Self> {
        {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));

            let mut config = ClientConfig::builder()
                .with_cipher_suites(&[
                    TLS13_AES_256_GCM_SHA384,
                    TLS13_AES_128_GCM_SHA256,
                    TLS13_CHACHA20_POLY1305_SHA256,
                ])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            if jls_pwd.is_empty() {
                return Err(anyhow::anyhow!("jls: empty jls pwd"));
            }
            config.jls_config = JlsConfig::new(&jls_pwd, &jls_iv);
            config.enable_early_data = zero_rtt;

            for alpn in alpns {
                config.alpn_protocols.push(alpn.as_bytes().to_vec());
            }
            Ok(Handler {
                server_name,
                tls_config: Arc::new(config),
                zero_rtt: zero_rtt,
            })
        }
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        trace!("wrapping jls with name {}", &name);
        if let Some(stream) = stream {
            let connector = TlsConnector::from(self.tls_config.clone()).early_data(self.zero_rtt);
            let domain = ServerName::try_from(name.as_str()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid jls server name {}: {}", &name, e),
                )
            })?;
            let mut tls_stream = connector
                .connect_with(domain, stream,Box::new(JlsFallbackHandler{}),|_|{})
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("connect jls failed: {}", e),
                    )
                })
                .await?;
            if !tls_stream.get_mut().1.early_data().is_some() {
                match tls_stream.is_jls() {
                    Some(false) => {
                        // Make some http request
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "jls authenticated failed",
                        ));
                    }
                    Some(true) => {
                        log::debug!("[jls] jls authenticated");
                    }
                    None => {
                        return Err(io::Error::new(io::ErrorKind::Other, "jls not handshaked"));
                    }
                }
            } else {
                log::info!("[jls] zero rtt available");
                let zero_rtt_acc = tls_stream.early_data_accepted().expect("zero rtt acceptor not available");
                tokio::spawn(async {
                    if zero_rtt_acc.await {
                        log::debug!("[jls] early data accepted");
                    } else {
                       log::warn!("[jls] early data rejected");
                    }
                });
            }
            // FIXME check negotiated alpn
            Ok(Box::new(tls_stream))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid jls input"))
        }
    }
}

struct JlsFallbackHandler;
impl<IO> JlsHandler<IO> for JlsFallbackHandler {
    fn handle(&mut self,stream: &mut client::TlsStream<IO>) {
        match stream.is_jls() {
            Some(true) => (),
            Some(false) => {
                log::error!("[jls] close jls connection");
                stream.get_mut().1.send_close_notify()
            },
            None => (),
        }
    }
}
