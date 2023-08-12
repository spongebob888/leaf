use std::io;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryFutureExt;
use log::*;

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
                root_cert_store.add_server_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }),
                );
            
            let mut config = ClientConfig::builder()
                .with_safe_defaults()
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
            let connector = TlsConnector::from(self.tls_config.clone());
            let domain = ServerName::try_from(name.as_str()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid jls server name {}: {}", &name, e),
                )
            })?;
            let tls_stream = connector
                .connect(domain, stream)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("connect jls failed: {}", e),
                    )
                })
                .await?;
            match tls_stream.is_jls() {
                Some(false) => {
                    // Make some http request
                    return Err(io::Error::new(io::ErrorKind::Other, "jls authenticated failed"));

                }
                Some(true) => {}
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "jls not handshaked"));
                }
            }
            // FIXME check negotiated alpn
            Ok(Box::new(tls_stream))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid jls input"))
        }
    }
}
