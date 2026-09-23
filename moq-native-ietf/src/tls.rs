// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// O3 pure-Rust patch: rustls-rustcrypto provider, sha2 fingerprints (no ring).

use anyhow::Context;
use clap::Parser;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Cursor, Read};
use std::path;
use std::sync::Arc;

#[derive(Parser, Clone, Default)]
#[group(id = "tls")]
pub struct Args {
    /// Use the certificates at this path, encoded as PEM.
    #[arg(long = "tls-cert")]
    pub cert: Vec<path::PathBuf>,

    /// Use the private key at this path, encoded as PEM.
    #[arg(long = "tls-key")]
    pub key: Vec<path::PathBuf>,

    /// Use the TLS root at this path, encoded as PEM.
    #[arg(long = "tls-root")]
    pub root: Vec<path::PathBuf>,

    /// Danger: Disable TLS certificate verification.
    #[arg(long = "tls-disable-verify", env = "TLS_DISABLE_VERIFY")]
    pub disable_verify: bool,
}

#[derive(Clone)]
pub struct Config {
    pub client: rustls::ClientConfig,
    pub server: Option<rustls::ServerConfig>,
    pub fingerprints: Vec<String>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    // Prefer process-wide default (e.g. o3_tls); else install rustls-rustcrypto.
    if let Some(p) = rustls::crypto::CryptoProvider::get_default() {
        return p.clone();
    }
    let p = rustls_rustcrypto::provider();
    match rustls::crypto::CryptoProvider::install_default(p) {
        Ok(()) => rustls::crypto::CryptoProvider::get_default()
            .expect("provider just installed")
            .clone(),
        Err(existing) => existing,
    }
}

impl Args {
    pub fn load(&self) -> anyhow::Result<Config> {
        let provider = provider();
        let mut serve = ServeCerts::default();

        anyhow::ensure!(
            self.cert.len() == self.key.len(),
            "--tls-cert and --tls-key counts differ"
        );
        for (chain, key) in self.cert.iter().zip(self.key.iter()) {
            serve.load(chain, key, &provider)?;
        }

        let mut roots = RootCertStore::empty();

        if self.root.is_empty() {
            for cert in
                rustls_native_certs::load_native_certs().context("could not load platform certs")?
            {
                let _ = roots.add(cert);
            }
        } else {
            for root in &self.root {
                let root = fs::File::open(root).context("failed to open root cert file")?;
                let mut root = io::BufReader::new(root);

                let root = rustls_pemfile::certs(&mut root)
                    .next()
                    .context("no roots found")?
                    .context("failed to read root cert")?;

                roots.add(root).context("failed to add root cert")?;
            }
        }

        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();

        if self.disable_verify {
            let noop = NoCertificateVerification(provider.clone());
            client.dangerous().set_certificate_verifier(Arc::new(noop));
        }

        let fingerprints = serve.fingerprints();

        let server = if !self.key.is_empty() {
            Some(
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])?
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(serve)),
            )
        } else {
            None
        };

        Ok(Config {
            server,
            client,
            fingerprints,
        })
    }
}

#[derive(Default, Debug)]
struct ServeCerts {
    list: Vec<Arc<CertifiedKey>>,
}

impl ServeCerts {
    pub fn load(
        &mut self,
        chain: &path::PathBuf,
        key: &path::PathBuf,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> anyhow::Result<()> {
        let chain = fs::File::open(chain).context("failed to open cert file")?;
        let mut chain = io::BufReader::new(chain);

        let chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut chain)
            .collect::<Result<_, _>>()
            .context("failed to read certs")?;

        anyhow::ensure!(!chain.is_empty(), "could not find certificate");

        let mut keys = fs::File::open(key).context("failed to open key file")?;
        let mut buf = Vec::new();
        keys.read_to_end(&mut buf)?;

        let key =
            rustls_pemfile::private_key(&mut Cursor::new(&buf))?.context("missing private key")?;
        let key = provider
            .key_provider
            .load_private_key(key)
            .context("failed to load private key with pure provider")?;

        let certified = Arc::new(CertifiedKey::new(chain, key));
        self.list.push(certified);

        Ok(())
    }

    pub fn fingerprints(&self) -> Vec<String> {
        self.list
            .iter()
            .map(|ck| {
                let digest = Sha256::digest(ck.cert[0].as_ref());
                hex::encode(digest)
            })
            .collect()
    }
}

impl ResolvesServerCert for ServeCerts {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Pure path: skip webpki 0.22 (ring). Prefer last cert; SNI-aware matching
        // can be restored with rustls-webpki if needed.
        let _ = client_hello.server_name();
        self.list.last().cloned()
    }
}

#[derive(Debug)]
pub struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
