use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use anyhow::Result;

use {
    rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys},
    tokio_rustls_jls::rustls::{Certificate, JlsServerConfig, PrivateKey, ServerConfig},
    tokio_rustls_jls::TlsAcceptor,
};

use crate::config::internal::SniProxyEntry;
use crate::{proxy::*, session::Session};

pub struct Handler {
    acceptor: TlsAcceptor,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    let mut keys2: Vec<PrivateKey> = rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    let mut keys3: Vec<PrivateKey> = ec_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    keys.append(&mut keys3);
    keys.append(&mut keys2);
    Ok(keys)
}

impl Handler {
    pub fn new(
        certificate: String,
        certificate_key: String,
        alpns: Vec<String>,
        zero_rtt: bool,
        jls_pwd: String,
        jls_iv: String,
        upstream_url: String,
        sni_proxy: Vec<SniProxyEntry>,
    ) -> Result<Self> {
        let (certs, key) = if certificate.is_empty() && certificate_key.is_empty() {
            let cert =
                rcgen::generate_simple_self_signed(vec![upstream_url.clone().into()]).unwrap();
            let cert_der = cert.serialize_der().unwrap();
            let priv_key = cert.serialize_private_key_der();
            let priv_key = PrivateKey(priv_key);
            let cert_chain = vec![Certificate(cert_der.clone())];
            log::info!("[jls] generate self-signed cert automatically");
            (cert_chain, priv_key)
        } else {
            let certs = load_certs(Path::new(&certificate))?;
            let mut keys = load_keys(Path::new(&certificate_key))?;
            (certs, keys.remove(0))
        };

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        config.jls_config = JlsServerConfig::new(&jls_pwd, &jls_iv, &upstream_url)?;
        if zero_rtt {
            config.max_early_data_size = u32::MAX;
            config.send_half_rtt_data = true;
        } else {
            config.max_early_data_size = 0;
            config.send_half_rtt_data = false;
        }
        config.alpn_protocols = alpns.iter().map(|x| x.as_bytes().to_vec()).collect();

        for sni_entry in sni_proxy {
            config
                .jls_config
                .push_sni(&sni_entry.server_name, &sni_entry.upstream_url)?;
        }

        let acceptor = TlsAcceptor::from(Arc::new(config));
        Ok(Self { acceptor })
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        {
            let conn = self.acceptor.accept(stream).await?;
            match conn.is_jls() {
                Some(true) => Ok(InboundTransport::Stream(Box::new(conn), sess)),
                Some(false) => {
                    log::debug!("[jls] JLS authenticated failed start forwarding");
                    tokio::spawn(conn.forward());
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Jls Authenticated Failed",
                    ));
                }
                None => {
                    // Usually impossible
                    panic!("Not handshaked");
                }
            }
        }
    }
}
