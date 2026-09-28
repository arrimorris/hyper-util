//! An HTTP/3 client.
//!
//! Start `http3_server` first, then:
//!
//! ```notrust
//! cargo run --features http3,client,tokio --example http3_client
//! ```
//!
//! It trusts the certificate `http3_server` wrote to `http3-cert.der`.
//!
//! Note what is *not* here: any handling of the local address. The connection
//! is identified by its QUIC Connection ID, so if this machine changes network
//! mid-request the request carries on unaffected.

#![deny(warnings)]

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::client::conn::http3;
use hyper_util::rt::TokioExecutor;
use quinn::{ClientConfig, Endpoint};

// See the note in `http3_server.rs`: dev-only scaffolding, not something you
// would vendor into an application.
#[path = "../tests/support/quic.rs"]
mod quic;

const CERT_PATH: &str = "http3-cert.der";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr: SocketAddr = (Ipv4Addr::LOCALHOST, 4433).into();

    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(client_config()?);

    let conn = endpoint.connect(addr, "localhost")?.await?;
    println!("connected to {}", conn.remote_address());

    let (mut send_request, connection) =
        http3::handshake(TokioExecutor::new(), quic::Connection::new(conn)).await?;

    // The connection future drives the shared parts of HTTP/3 — the control
    // and QPACK streams — and must be polled for anything to happen.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("connection error: {err}");
        }
    });

    let req = Request::builder()
        .uri("https://localhost/")
        .body(Empty::<Bytes>::new())?;

    let res = send_request.send_request(req).await?;
    println!("Status: {}", res.status());
    println!("Version: {:?}", res.version());
    println!("Headers: {:#?}", res.headers());

    let body = res.into_body().collect().await?.to_bytes();
    print!("{}", String::from_utf8_lossy(&body));

    Ok(())
}

fn client_config() -> Result<ClientConfig, Box<dyn Error + Send + Sync>> {
    let cert = std::fs::read(CERT_PATH).map_err(|err| {
        format!("could not read {CERT_PATH} ({err}); run the http3_server example first")
    })?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(cert))?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));

    Ok(config)
}
