//! An HTTP/3 server.
//!
//! HTTP/3 runs over QUIC, so unlike the HTTP/1 and HTTP/2 examples this one
//! does not accept TCP connections — it accepts whole QUIC connections and
//! hands each to `hyper_util::server::conn::http3`.
//!
//! Run it with:
//!
//! ```notrust
//! cargo run --features http3,server,tokio --example http3_server
//! ```
//!
//! It writes the self-signed certificate it generated to `http3-cert.der` so
//! `http3_client` can trust it, then serves on
//! `127.0.0.1:4433`.

#![deny(warnings)]

use std::convert::Infallible;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::http3::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::http3;
use quinn::{Endpoint, ServerConfig};

// An `rt::quic` implementation over quinn. It lives with the tests because it
// is dev-only scaffolding: in a real application this would come from a
// published adapter rather than being vendored into your project.
#[path = "../tests/support/quic.rs"]
mod quic;

const CERT_PATH: &str = "http3-cert.der";

async fn hello(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    println!("{} {} {:?}", req.method(), req.uri().path(), req.version());
    Ok(Response::new(Full::new(Bytes::from("Hello, HTTP/3!\n"))))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr: SocketAddr = (Ipv4Addr::LOCALHOST, 4433).into();
    let endpoint = Endpoint::server(server_config()?, addr)?;

    println!("Listening on https://{addr} (HTTP/3)");
    println!("Certificate written to {CERT_PATH}");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("QUIC handshake failed: {err}");
                    return;
                }
            };
            println!("connection from {}", conn.remote_address());

            // One QUIC connection carries many requests, each on its own
            // stream and each dispatched to the executor as its own task.
            if let Err(err) = http3::Builder::new(TokioExecutor::new())
                .serve_connection(quic::Connection::new(conn), service_fn(hello))
                .await
            {
                eprintln!("connection error: {err}");
            }
        });
    }

    Ok(())
}

fn server_config() -> Result<ServerConfig, Box<dyn Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    // So the client example can trust this run's certificate.
    std::fs::write(CERT_PATH, &cert_der)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));

    let mut transport = quinn::TransportConfig::default();
    // A client that walks out of coverage should still find its connection
    // waiting when it comes back. HTTP/3 adds no timeout of its own, so this is
    // the only thing that decides when a quiet connection is declared dead.
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    // Let a peer keep its connection across a change of network.
    config.migration(true);

    Ok(config)
}
