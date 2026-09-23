//! End-to-end pure-Rust QUIC + WebTransport smoke (no ring / no cc).
//!
//! Spins a moq-native-ietf endpoint, dials it as a client with certificate
//! verification disabled, and confirms a WebTransport session is established.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use moq_native_ietf::quic::{self, Config};
use moq_native_ietf::tls::Args as TlsArgs;
use url::Url;

fn cert_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/certs")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_webtransport_handshake() {
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());

    let cert = cert_dir().join("cert.pem");
    let key = cert_dir().join("key.pem");
    assert!(cert.is_file(), "missing test cert at {}", cert.display());
    assert!(key.is_file(), "missing test key at {}", key.display());

    let mut tls_args = TlsArgs::default();
    tls_args.cert.push(cert);
    tls_args.key.push(key);
    tls_args.disable_verify = true;
    let tls = tls_args.load().expect("load pure TLS config");
    assert!(tls.server.is_some(), "server TLS config required");
    assert!(
        !tls.fingerprints.is_empty(),
        "sha256 fingerprint should be set"
    );

    // Bind server on an explicit free port.
    let ports = [44443u16, 44444, 44445, 45443, 0];
    let mut bound = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut endpoint = None;
    for port in ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        match quic::Endpoint::new(Config::new(addr, None, tls.clone()).expect("cfg")) {
            Ok(ep) if ep.server.is_some() => {
                // When port=0, discover actual bound address from the server socket if possible.
                // Config stores the requested bind; for port 0, dialing 0 won't work — skip 0 for client.
                if port == 0 {
                    continue;
                }
                bound = addr;
                endpoint = Some(ep);
                break;
            }
            Ok(_) | Err(_) => continue,
        }
    }
    let mut endpoint = endpoint.expect("could not bind pure QUIC endpoint");
    let mut server = endpoint.server.take().expect("server");

    let server_task = tokio::spawn(async move {
        let accepted = tokio::time::timeout(Duration::from_secs(15), server.accept())
            .await
            .expect("server accept timed out")
            .expect("server accept returned None");
        let (session, info) = accepted;
        assert!(!info.id.is_empty(), "connection id should be set");
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(session);
        info.id
    });

    let mut client_tls = TlsArgs::default();
    client_tls.disable_verify = true;
    let client_tls = client_tls.load().expect("client tls");
    let client_ep = quic::Endpoint::new(
        Config::new("127.0.0.1:0".parse().unwrap(), None, client_tls).expect("client config"),
    )
    .expect("client endpoint");

    let url = Url::parse(&format!("https://localhost:{}/", bound.port())).unwrap();
    let connect = client_ep.client.connect(&url, Some(bound));
    let (session, cid, transport) = tokio::time::timeout(Duration::from_secs(15), connect)
        .await
        .expect("client connect timed out")
        .expect("client connect failed");

    assert!(!cid.is_empty(), "client should capture connection id");
    // WebTransport over https ALPN
    let _ = transport;
    let server_cid = server_task.await.expect("server task");
    assert!(!server_cid.is_empty());

    drop(session);
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_webtransport_bidi_stream_echo() {
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());

    let mut tls_args = TlsArgs::default();
    tls_args.cert.push(cert_dir().join("cert.pem"));
    tls_args.key.push(cert_dir().join("key.pem"));
    tls_args.disable_verify = true;
    let tls = tls_args.load().expect("tls");

    let ports = [45543u16, 45544, 45545];
    let mut bound = None;
    let mut endpoint = None;
    for port in ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(ep) = quic::Endpoint::new(Config::new(addr, None, tls.clone()).unwrap()) {
            if ep.server.is_some() {
                bound = Some(addr);
                endpoint = Some(ep);
                break;
            }
        }
    }
    let mut endpoint = endpoint.expect("bind");
    let bound = bound.unwrap();
    let mut server = endpoint.server.take().unwrap();

    let server_task = tokio::spawn(async move {
        let (session, _) = tokio::time::timeout(Duration::from_secs(15), server.accept())
            .await
            .expect("timeout")
            .expect("accept");
        let (mut send, mut recv) = session.accept_bi().await.expect("accept bi");
        let data = recv.read(64).await.expect("read").expect("some data");
        send.write(&data).await.expect("echo write");
        // half-close
        drop(send);
        drop(recv);
        drop(session);
    });

    let mut client_tls = TlsArgs::default();
    client_tls.disable_verify = true;
    let client_tls = client_tls.load().unwrap();
    let client_ep = quic::Endpoint::new(
        Config::new("127.0.0.1:0".parse().unwrap(), None, client_tls).unwrap(),
    )
    .unwrap();
    let url = Url::parse(&format!("https://localhost:{}/", bound.port())).unwrap();
    let (session, _, _) = client_ep
        .client
        .connect(&url, Some(bound))
        .await
        .expect("connect");

    let (mut send, mut recv) = session.open_bi().await.expect("open bi");
    let payload = b"pure-quic-echo";
    send.write(payload).await.expect("write");
    drop(send);
    let echoed = recv.read(64).await.expect("read").expect("echo data");
    assert_eq!(&echoed[..], payload);

    server_task.await.expect("server");
    drop(session);
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_webtransport_datagram_echo() {
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());

    let mut tls_args = TlsArgs::default();
    tls_args.cert.push(cert_dir().join("cert.pem"));
    tls_args.key.push(cert_dir().join("key.pem"));
    tls_args.disable_verify = true;
    let tls = tls_args.load().expect("tls");

    let ports = [45643u16, 45644, 45645];
    let mut bound = None;
    let mut endpoint = None;
    for port in ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(ep) = quic::Endpoint::new(Config::new(addr, None, tls.clone()).unwrap()) {
            if ep.server.is_some() {
                bound = Some(addr);
                endpoint = Some(ep);
                break;
            }
        }
    }
    let mut endpoint = endpoint.expect("bind");
    let bound = bound.unwrap();
    let mut server = endpoint.server.take().unwrap();

    let server_task = tokio::spawn(async move {
        let (session, _) = tokio::time::timeout(Duration::from_secs(15), server.accept())
            .await
            .expect("timeout")
            .expect("accept");
        let data = session.recv_datagram().await.expect("recv datagram");
        session
            .send_datagram(data.clone())
            .await
            .expect("echo datagram");
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(session);
        data
    });

    let mut client_tls = TlsArgs::default();
    client_tls.disable_verify = true;
    let client_tls = client_tls.load().unwrap();
    let client_ep = quic::Endpoint::new(
        Config::new("127.0.0.1:0".parse().unwrap(), None, client_tls).unwrap(),
    )
    .unwrap();
    let url = Url::parse(&format!("https://localhost:{}/", bound.port())).unwrap();
    let (session, _, _) = client_ep
        .client
        .connect(&url, Some(bound))
        .await
        .expect("connect");

    let payload = bytes::Bytes::from_static(b"pure-quic-dgram");
    session.send_datagram(payload.clone()).await.expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(5), session.recv_datagram())
        .await
        .expect("recv timeout")
        .expect("recv");
    assert_eq!(echoed, payload);

    let server_data = server_task.await.expect("server");
    assert_eq!(server_data, payload);

    drop(session);
    drop(endpoint);
}

#[test]
fn pure_provider_has_quic_initial_suite() {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let has_quic = provider.cipher_suites.iter().any(|cs| match cs {
        rustls::SupportedCipherSuite::Tls13(t13)
            if t13.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 =>
        {
            t13.quic.is_some()
        }
        _ => false,
    });
    assert!(
        has_quic,
        "TLS13_AES_128_GCM_SHA256 must expose QUIC algorithm for Quinn initial secrets"
    );
}

#[test]
fn pure_fingerprint_is_sha256_hex() {
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());
    let mut args = TlsArgs::default();
    args.cert.push(cert_dir().join("cert.pem"));
    args.key.push(cert_dir().join("key.pem"));
    let cfg = args.load().unwrap();
    let fp = &cfg.fingerprints[0];
    assert_eq!(fp.len(), 64, "sha256 hex is 64 chars");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}
