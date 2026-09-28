//! End-to-end HTTP/3 tests against a real QUIC stack (quinn).
//!
//! Beyond the happy path, these deliberately abuse the connection in the ways a
//! mobile client actually gets abused: the client's network changes underneath
//! an in-flight request, and every packet in both directions is dropped for
//! long enough that a naive stack would give up.
//!
//! Run with:
//!
//! ```notrust
//! cargo test --features http3,client,server,tokio --test http3
//! ```

#![deny(rust_2018_idioms)]
// Real sockets and a TLS stack with C in it: nothing here can run under Miri.
#![cfg(not(miri))]

use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Body, Frame};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use hyper_util::client::conn::http3 as client_http3;
use hyper_util::http3::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::http3 as server_http3;
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use tokio::sync::oneshot;

#[path = "support/quic.rs"]
mod quic;

type BoxError = Box<dyn StdError + Send + Sync>;
type TestBody = BoxBody<Bytes, Infallible>;

const ALPN: &[u8] = b"h3";

/// How long a connection may go without receiving a single packet before QUIC
/// declares it dead.
///
/// This is the number that decides whether a client survives a tunnel, and it
/// is the *transport's* number, not hyper-util's — nothing here times a connection
/// out on its own. It must be longer than the worst outage you intend to
/// survive: a five-minute blackout against a five-minute idle timeout is a dead
/// connection, not a surviving one (see `blackout_longer_than_idle_timeout`).
///
/// Note that keep-alives do not help here. During a real blackout the
/// keep-alive packets are dropped along with everything else.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

// ===== harness =====

struct Tls {
    server: ServerConfig,
    client: ClientConfig,
}

fn tls() -> Tls {
    tls_with_idle_timeout(IDLE_TIMEOUT)
}

fn tls_with_idle_timeout(idle: Duration) -> Tls {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    server.transport_config(Arc::new(transport(idle)));
    // Explicit, because the whole point of several tests below is that the
    // client may change address without the connection noticing.
    server.migration(true);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    client.transport_config(Arc::new(transport(idle)));

    Tls { server, client }
}

fn transport(idle: Duration) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(IdleTimeout::try_from(idle).unwrap()));
    // Keep-alives are what stop an idle-but-alive connection from being
    // reaped, and they resume on their own once packets flow again.
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    transport
}

/// Spawn an HTTP/3 server, returning the address it is listening on.
fn spawn_server<S, B>(tls: &Tls, service: S) -> SocketAddr
where
    S: hyper::service::Service<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().expect("local_addr");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };
                let _ = server_http3::Builder::new(TokioExecutor::new())
                    .serve_connection(quic::Connection::new(conn), service)
                    .await;
            });
        }
    });

    addr
}

/// Connect a client, returning its endpoint (so tests can rebind it) and the
/// request sender.
async fn connect(tls: &Tls, addr: SocketAddr) -> (Endpoint, client_http3::SendRequest<TestBody>) {
    let (endpoint, send_request, _driver) = connect_with_driver(tls, addr).await;
    (endpoint, send_request)
}

/// Like [`connect`], but also hands back the connection future's outcome.
async fn connect_with_driver(
    tls: &Tls,
    addr: SocketAddr,
) -> (
    Endpoint,
    client_http3::SendRequest<TestBody>,
    tokio::task::JoinHandle<Result<(), hyper_util::http3::Error>>,
) {
    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(tls.client.clone());

    let conn = endpoint
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("quic handshake");

    let (send_request, connection) =
        client_http3::handshake(TokioExecutor::new(), quic::Connection::new(conn))
            .await
            .expect("http3 handshake");

    let driver = tokio::spawn(connection);

    (endpoint, send_request, driver)
}

fn full(body: &'static str) -> TestBody {
    Full::new(Bytes::from_static(body.as_bytes())).boxed()
}

fn empty() -> TestBody {
    Empty::<Bytes>::new().boxed()
}

fn get(path: &str) -> Request<TestBody> {
    Request::builder()
        .uri(format!("https://localhost{path}"))
        .body(empty())
        .unwrap()
}

// ===== the basics =====

#[tokio::test]
async fn hello_world() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|req: Request<Incoming>| async move {
            assert_eq!(req.version(), Version::HTTP_3);
            assert_eq!(req.uri().path(), "/hello");
            Ok::<_, Infallible>(Response::new(full("Hello, HTTP/3!")))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    let res = send_request.send_request(get("/hello")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.version(), Version::HTTP_3);
    // Set by the server by default, like HTTP/1 and HTTP/2.
    assert!(res.headers().contains_key("date"));

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "Hello, HTTP/3!");
}

#[tokio::test]
async fn echoes_request_body_and_trailers() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|req: Request<Incoming>| async move {
            let collected = req.into_body().collect().await.unwrap();
            let trailers = collected.trailers().cloned();
            let data = collected.to_bytes();

            let mut echoed = HeaderMap::new();
            echoed.insert(
                "x-echoed-trailer",
                trailers
                    .and_then(|t| t.get("x-checksum").cloned())
                    .unwrap_or_else(|| "missing".parse().unwrap()),
            );

            let frames = futures_util::stream::iter(vec![
                Ok::<_, Infallible>(Frame::data(data)),
                Ok(Frame::trailers(echoed)),
            ]);
            Ok::<_, Infallible>(Response::new(StreamBody::new(frames).boxed()))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().unwrap());
    let body = StreamBody::new(futures_util::stream::iter(vec![
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"one "))),
        Ok(Frame::data(Bytes::from_static(b"two "))),
        Ok(Frame::data(Bytes::from_static(b"three"))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed();

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/echo")
        .body(body)
        .unwrap();

    let res = send_request.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let collected = res.into_body().collect().await.unwrap();
    let echoed_trailer = collected
        .trailers()
        .and_then(|t| t.get("x-echoed-trailer"))
        .cloned();
    assert_eq!(collected.to_bytes(), "one two three");
    assert_eq!(echoed_trailer.unwrap(), "abc123");
}

/// The whole reason HTTP/3 exists: one slow request must not hold up another on
/// the same connection. The first request cannot finish until the second one
/// has, so this deadlocks if the two share a queue.
#[tokio::test]
async fn requests_do_not_block_each_other() {
    let tls = tls();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_tx)));
    let gate = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let addr = spawn_server(
        &tls,
        service_fn(move |req: Request<Incoming>| {
            let release = Arc::clone(&release);
            let gate = Arc::clone(&gate);
            async move {
                if req.uri().path() == "/slow" {
                    // Waits for /fast to complete.
                    let rx = gate.lock().await.take().expect("one /slow request");
                    let _ = rx.await;
                    Ok::<_, Infallible>(Response::new(full("slow")))
                } else {
                    if let Some(tx) = release.lock().await.take() {
                        let _ = tx.send(());
                    }
                    Ok(Response::new(full("fast")))
                }
            }
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let mut second = send_request.clone();

    let slow = tokio::spawn(async move { send_request.send_request(get("/slow")).await });
    // Give /slow a head start so it is definitely in flight first.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let fast = second.send_request(get("/fast")).await.unwrap();

    assert_eq!(
        fast.into_body().collect().await.unwrap().to_bytes(),
        "fast",
        "the second request must complete while the first is still blocked"
    );

    let slow = slow.await.unwrap().unwrap();
    assert_eq!(slow.into_body().collect().await.unwrap().to_bytes(), "slow");
}

/// A server that rejects an upload without reading it should be heard
/// immediately, not after the client has finished uploading.
#[tokio::test]
async fn early_response_reaches_client_mid_upload() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            // Note: the request body is dropped unread, which sends
            // STOP_SENDING to the peer.
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(full("too big"))
                    .unwrap(),
            )
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    // A body that would take ~10s to finish uploading if anyone waited for it.
    let chunks = futures_util::stream::unfold(0usize, |n| async move {
        if n >= 100 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Some((
            Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'x'; 1024]))),
            n + 1,
        ))
    });

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/upload")
        .body(StreamBody::new(chunks).boxed())
        .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(5), send_request.send_request(req))
        .await
        .expect("response must arrive without waiting for the upload to finish")
        .unwrap();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "too big"
    );
}

#[tokio::test]
async fn graceful_shutdown_finishes_inflight_request() {
    let tls = tls();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");

        let service = service_fn(move |_req: Request<Incoming>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = release.lock().await.take() {
                    let _ = rx.await;
                }
                Ok::<_, Infallible>(Response::new(full("finished anyway")))
            }
        });

        let conn = server_http3::Builder::new(TokioExecutor::new())
            .serve_connection(quic::Connection::new(conn), service);
        tokio::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => return res,
            _ = shutdown_rx => {}
        }

        conn.as_mut().graceful_shutdown();
        conn.await
    });

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let request = tokio::spawn(async move { send_request.send_request(get("/slow")).await });

    // Ask for shutdown only once the request is actually being handled.
    started_rx.await.unwrap();
    shutdown_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    release_tx.send(()).unwrap();

    let res = request.await.unwrap().unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "finished anyway",
        "a request accepted before GOAWAY must still be answered"
    );

    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the connection future must resolve after shutdown")
        .unwrap()
        .expect("graceful shutdown is not an error");
}

/// A client that simply goes away is not a server error.
///
/// The last `SendRequest` dropping is how a caller says "done". If that
/// reaches the server as anything other than a clean close, every ordinary
/// disconnect shows up as a connection error in the log — which on a fleet of
/// roaming devices is the entire log.
#[tokio::test]
async fn a_client_disconnecting_is_a_clean_close() {
    let tls = tls();

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");
        server_http3::Builder::new(TokioExecutor::new())
            .serve_connection(
                quic::Connection::new(conn),
                service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(full("bye")))
                }),
            )
            .await
    });

    let (endpoint, mut send_request) = connect(&tls, addr).await;
    let res = send_request.send_request(get("/")).await.unwrap();
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "bye");

    drop(send_request);

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server connection must notice the client is gone")
        .unwrap();
    assert!(
        result.is_ok(),
        "a client hanging up must not surface as an error: {:?}",
        result.err()
    );

    drop(endpoint);
}

/// And the same in the other direction: a server finishing a graceful
/// shutdown is not a client error.
///
/// This one holds on its own — h3's server `Connection` closes with
/// `H3_NO_ERROR` in its own `Drop`. It is here so the pair is covered, and so
/// that a regression on either side is visible.
#[tokio::test]
async fn a_server_shutting_down_is_a_clean_close() {
    let tls = tls();

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");
        let conn = server_http3::Builder::new(TokioExecutor::new()).serve_connection(
            quic::Connection::new(conn),
            service_fn(|_req: Request<Incoming>| async move {
                Ok::<_, Infallible>(Response::new(full("bye")))
            }),
        );
        tokio::pin!(conn);

        tokio::select! {
            _ = conn.as_mut() => return,
            _ = shutdown_rx => {}
        }
        conn.as_mut().graceful_shutdown();
        let _ = conn.await;
    });

    let mut client = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    client.set_default_client_config(tls.client.clone());
    let quic_conn = client
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("quic handshake");
    let (mut send_request, connection) =
        client_http3::handshake(TokioExecutor::new(), quic::Connection::new(quic_conn))
            .await
            .expect("http3 handshake");
    let driver = tokio::spawn(connection);

    let res = send_request.send_request(get("/")).await.unwrap();
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "bye");

    shutdown_tx.send(()).unwrap();

    // `send_request` is deliberately still alive, so the client is not the one
    // ending the connection — the server is.
    let result = tokio::time::timeout(Duration::from_secs(10), driver)
        .await
        .expect("the client connection must notice the server is gone")
        .unwrap();
    assert!(
        result.is_ok(),
        "a server shutting down must not surface as an error: {:?}",
        result.err()
    );

    drop(send_request);
    drop(client);
}

/// A service that answers early and keeps reading the upload must keep the
/// connection with it, even into a graceful shutdown.
///
/// This is the ingest shape: accept the submission, return `202` so the device
/// can stop waiting, and go on draining the body in the background. The
/// response being finished does not mean the exchange is — the request stream
/// is still open, and h3 still counts it — so shutting the connection down
/// underneath the reader would silently truncate an upload that was
/// mid-flight.
#[tokio::test]
async fn shutdown_waits_for_a_body_the_service_is_still_reading() {
    let tls = tls();
    let (answered_tx, answered_rx) = oneshot::channel::<()>();
    let (read_tx, read_rx) = oneshot::channel::<Result<usize, String>>();
    let answered = Arc::new(tokio::sync::Mutex::new(Some(answered_tx)));
    let read = Arc::new(tokio::sync::Mutex::new(Some(read_tx)));

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");

        let service = service_fn(move |req: Request<Incoming>| {
            let answered = Arc::clone(&answered);
            let read = Arc::clone(&read);
            async move {
                // Answer now, drain later — the request body outlives the
                // response, and outlives `serve_stream` with it.
                let body = req.into_body();
                tokio::spawn(async move {
                    let outcome = match body.collect().await {
                        Ok(collected) => Ok(collected.to_bytes().len()),
                        Err(err) => Err(err.to_string()),
                    };
                    if let Some(tx) = read.lock().await.take() {
                        let _ = tx.send(outcome);
                    }
                });
                if let Some(tx) = answered.lock().await.take() {
                    let _ = tx.send(());
                }
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(empty())
                        .unwrap(),
                )
            }
        });

        let conn = server_http3::Builder::new(TokioExecutor::new())
            .serve_connection(quic::Connection::new(conn), service);
        tokio::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => return res,
            _ = shutdown_rx => {}
        }

        conn.as_mut().graceful_shutdown();
        conn.await
    });

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    // 40 KiB dribbled out over ~2s, so most of it is still in flight when the
    // shutdown begins.
    const CHUNKS: usize = 40;
    const CHUNK: usize = 1024;
    let chunks = futures_util::stream::unfold(0usize, |n| async move {
        if n >= CHUNKS {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        Some((
            Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'x'; CHUNK]))),
            n + 1,
        ))
    });

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/telemetry")
        .body(StreamBody::new(chunks).boxed())
        .unwrap();
    let request = tokio::spawn(async move { send_request.send_request(req).await });

    // Shut down the moment the service has answered — the upload has barely
    // started.
    answered_rx.await.unwrap();
    shutdown_tx.send(()).unwrap();

    let res = request.await.unwrap().unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let read = tokio::time::timeout(Duration::from_secs(20), read_rx)
        .await
        .expect("the background reader must finish")
        .unwrap();
    assert_eq!(
        read,
        Ok(CHUNKS * CHUNK),
        "the upload was truncated by the shutdown"
    );

    tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .expect("the connection future must resolve once the body is drained")
        .unwrap()
        .expect("graceful shutdown is not an error");
}

/// GREASE goes out on the first request of a connection, not on every one.
///
/// Nothing in hyper's API can see a GREASE frame — the peer skips it, as it
/// must — so this counts what the server actually wrote on each request
/// stream. The responses are byte-for-byte identical, so any stream that is
/// longer than the others is carrying a GREASE frame.
///
/// This is the test that makes removing `suppress_further_grease` safe. h3
/// 0.0.8's `create_resolver` never clears the flag, so without the workaround
/// every response carries GREASE and this fails; h3 #362 fixes that
/// upstream. Delete the workaround only on an h3 version where this still
/// passes without it.
#[tokio::test]
async fn grease_is_sent_once_per_connection() {
    let tls = tls();
    let sent: quic::SentBytes = Default::default();

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let tap = Arc::clone(&sent);
    tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");
        let _ = server_http3::Builder::new(TokioExecutor::new())
            .send_grease(true)
            .serve_connection(
                quic::Connection::new(conn).count_sent_bytes(tap),
                service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(full("same every time")))
                }),
            )
            .await;
    });

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    for _ in 0..4 {
        let res = send_request.send_request(get("/")).await.unwrap();
        // Read to the end, so the stream's FIN — and anything the server wrote
        // before it — has arrived.
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "same every time");
    }

    let sent = sent.lock().unwrap().clone();
    let per_stream: Vec<usize> = sent.values().copied().collect();
    assert_eq!(
        per_stream.len(),
        4,
        "one entry per request stream: {sent:?}"
    );
    assert!(
        per_stream[0] > per_stream[1],
        "the first response should carry the connection's one GREASE frame: {sent:?}"
    );
    assert!(
        per_stream[1..].iter().all(|&n| n == per_stream[1]),
        "no response after the first should carry GREASE: {sent:?}"
    );
}

/// A request that never made it onto the wire must come back to the caller.
///
/// Once the peer has sent GOAWAY, opening a new QUIC stream fails before a
/// single byte of the request is serialized. Nothing about that request is
/// spent, so `try_send_request` hands it back and a pool can put it on a
/// fresh connection instead of failing it. For a client on a flaky network
/// this is the difference between a retry and a lost submission.
#[tokio::test]
async fn a_request_that_never_left_is_handed_back() {
    let tls = tls();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");

        let service = service_fn(move |_req: Request<Incoming>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = release.lock().await.take() {
                    let _ = rx.await;
                }
                Ok::<_, Infallible>(Response::new(full("held open")))
            }
        });

        let conn = server_http3::Builder::new(TokioExecutor::new())
            .serve_connection(quic::Connection::new(conn), service);
        tokio::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => return res,
            _ = shutdown_rx => {}
        }

        // GOAWAY goes out, but the connection stays up: the first request is
        // still being served, which is exactly the window a late request
        // arrives in.
        conn.as_mut().graceful_shutdown();
        conn.await
    });

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let mut first = send_request.clone();
    let first = tokio::spawn(async move { first.send_request(get("/slow")).await });

    started_rx.await.unwrap();
    shutdown_tx.send(()).unwrap();

    // Wait for the GOAWAY to actually land before asking for another request.
    // Until it does, the request is sent and the server rejects the stream
    // instead — a real failure, but not the one under test.
    let mut recovered = None;
    for _ in 0..100 {
        let mut req = get("/late");
        req.headers_mut()
            .insert("x-marker", "keep-me".parse().unwrap());

        match send_request.try_send_request(req).await {
            Ok(_) => {}
            Err(mut err) => {
                if let Some(req) = err.take_message() {
                    recovered = Some(req);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let recovered = recovered
        .expect("a request rejected before it was serialized must be returned via TrySendError");
    assert_eq!(recovered.uri().path(), "/late");
    assert_eq!(
        recovered.headers().get("x-marker").unwrap(),
        "keep-me",
        "the caller gets its own request back, headers and all"
    );
    assert_eq!(
        recovered.version(),
        Version::HTTP_11,
        "the request comes back as it was handed in, not rewritten for HTTP/3"
    );

    release_tx.send(()).unwrap();
    let res = first.await.unwrap().unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the connection future must resolve")
        .unwrap()
        .expect("graceful shutdown is not an error");
}

/// Dropping the future returned by `send_request` is how hyper cancels an
/// in-flight request. On HTTP/3 that must reset this one QUIC stream — the
/// peer should find out, rather than keep working on a request nobody wants.
#[tokio::test]
async fn dropping_the_request_future_resets_the_stream() {
    let tls = tls();
    let (result_tx, result_rx) = tokio::sync::mpsc::unbounded_channel();

    let addr = spawn_server(
        &tls,
        service_fn(move |req: Request<Incoming>| {
            let result_tx = result_tx.clone();
            async move {
                // Never responds; just reads until the client goes away.
                let outcome = req.into_body().collect().await;
                let _ = result_tx.send(outcome.is_err());
                Ok::<_, Infallible>(Response::new(full("unreachable")))
            }
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    // A body that never ends, so the server stays in `collect()`.
    let never_ending = futures_util::stream::unfold((), |()| async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Some((
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"tick"))),
            (),
        ))
    });
    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/abandoned")
        .body(StreamBody::new(never_ending).boxed())
        .unwrap();

    let pending = send_request.send_request(req);
    // Let it reach the server, then give up on it.
    let timed_out = tokio::time::timeout(Duration::from_millis(300), pending).await;
    assert!(timed_out.is_err(), "the server never responds");
    // `timed_out` being an error means the future was dropped: cancelled.

    let mut result_rx = result_rx;
    let saw_reset = tokio::time::timeout(Duration::from_secs(10), result_rx.recv())
        .await
        .expect("the server must notice the cancellation")
        .expect("channel open");

    assert!(
        saw_reset,
        "the server's read of the request body should fail once the client cancels"
    );
}

/// A body big enough that the QUIC flow-control window closes part way
/// through, so the send path really does go `Pending` and resume, and the
/// stream is finished only once everything queued has been flushed.
#[tokio::test]
async fn large_response_body_survives_flow_control() {
    const LEN: usize = 4 * 1024 * 1024;

    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            // 64 KiB at a time, so the body is many frames rather than one.
            let chunks = futures_util::stream::unfold(0usize, |sent| async move {
                if sent >= LEN {
                    return None;
                }
                let chunk = vec![(sent / 65536) as u8; 65536];
                Some((
                    Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))),
                    sent + 65536,
                ))
            });
            Ok::<_, Infallible>(Response::new(StreamBody::new(chunks).boxed()))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    let res = send_request.send_request(get("/big")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), LEN, "the whole body must arrive, not a prefix");
    // Every 64 KiB block carries its own index, so a dropped or reordered
    // chunk shows up as a wrong byte rather than just a wrong length.
    for (i, block) in body.chunks(65536).enumerate() {
        assert!(block.iter().all(|&b| b == i as u8), "block {i} is corrupt");
    }
}

/// A response body must keep streaming after the last `SendRequest` is
/// dropped. Dropping the sender means "no more requests", not "abandon the
/// response I am already reading".
#[tokio::test]
async fn response_body_survives_dropping_the_sender() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            // Dribbled out, so the body is definitely still in flight when the
            // sender goes away rather than already buffered on the client.
            let chunks = futures_util::stream::unfold(0usize, |n| async move {
                if n >= 10 {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                Some((
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"chunk"))),
                    n + 1,
                ))
            });
            Ok::<_, Infallible>(Response::new(StreamBody::new(chunks).boxed()))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let res = send_request.send_request(get("/stream")).await.unwrap();

    // The caller is done issuing requests, but not done reading this one.
    drop(send_request);

    let body = tokio::time::timeout(Duration::from_secs(10), res.into_body().collect())
        .await
        .expect("reading the body must not hang")
        .expect("the connection must stay up while a response body is unread")
        .to_bytes();
    assert_eq!(body.len(), 50);
}

/// `is_end_stream` must reflect the QUIC stream, not the content-length.
/// A zero-length body can still be followed by trailers.
#[tokio::test]
async fn zero_length_body_with_trailers_is_not_end_of_stream() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", "abc123".parse().unwrap());
            let frames =
                futures_util::stream::iter(vec![Ok::<_, Infallible>(Frame::trailers(trailers))]);
            Ok::<_, Infallible>(
                Response::builder()
                    .header("content-length", "0")
                    .body(StreamBody::new(frames).boxed())
                    .unwrap(),
            )
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let res = send_request
        .send_request(get("/trailers-only"))
        .await
        .unwrap();

    let body = res.into_body();
    assert!(
        !body.is_end_stream(),
        "trailers are still pending, so this is not the end of the stream"
    );

    let collected = body.collect().await.unwrap();
    assert_eq!(
        collected
            .trailers()
            .and_then(|t| t.get("x-checksum"))
            .expect("trailers must survive a zero-length body"),
        "abc123"
    );
}

/// A response body with a known size gets a `content-length`, as it does on
/// HTTP/2, without the service having to set one.
#[tokio::test]
async fn response_gets_automatic_content_length() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            Ok::<_, Infallible>(Response::new(full("twelve bytes")))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let res = send_request.send_request(get("/sized")).await.unwrap();

    assert_eq!(
        res.headers()
            .get("content-length")
            .map(|v| v.to_str().unwrap()),
        Some("12")
    );
}

// ===== being mean to the connection =====

/// Wi-Fi to cellular, mid-request.
///
/// The client's UDP socket is replaced with a new one on a different port while
/// a request is in flight. Under TCP the 4-tuple would be gone and the request
/// lost. Under QUIC the Connection ID still identifies the session, so the same
/// request finishes on the new path.
#[tokio::test]
async fn survives_network_migration_mid_request() {
    let tls = tls();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let addr = spawn_server(
        &tls,
        service_fn(move |_req: Request<Incoming>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = release.lock().await.take() {
                    let _ = rx.await;
                }
                Ok::<_, Infallible>(Response::new(full("survived the handover")))
            }
        }),
    );

    let (endpoint, mut send_request) = connect(&tls, addr).await;
    let before = endpoint.local_addr().unwrap();

    let request = tokio::spawn(async move { send_request.send_request(get("/epro")).await });

    // The request is on the wire and the server is holding it open.
    started_rx.await.unwrap();

    // The device changes network.
    let new_socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    endpoint.rebind(new_socket).expect("rebind");
    let after = endpoint.local_addr().unwrap();
    assert_ne!(before, after, "the client must actually have moved");

    release_tx.send(()).unwrap();

    let res = tokio::time::timeout(Duration::from_secs(20), request)
        .await
        .expect("the response must survive the address change")
        .unwrap()
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "survived the handover"
    );

    // And the connection is still usable afterwards, from the new address.
    let (_endpoint2, mut again) = connect(&tls, addr).await;
    let res = again.send_request(get("/again")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Total loss of signal, mid-request.
///
/// Every packet in both directions is dropped for `blackout`, then the network
/// comes back. Because the idle timeout is five minutes and HTTP/3 adds no
/// timeout of its own, the in-flight request simply resumes.
async fn blackout_case(blackout: Duration, idle_timeout: Duration) -> BlackoutOutcome {
    let tls = tls_with_idle_timeout(idle_timeout);
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            Ok::<_, Infallible>(Response::new(full("still here")))
        }),
    );

    let dropping = Arc::new(AtomicBool::new(false));
    let relay_addr = spawn_relay(addr, Arc::clone(&dropping)).await;

    let (_endpoint, mut send_request, driver) = connect_with_driver(&tls, relay_addr).await;

    // Warm the connection up so the handshake is definitely behind us.
    let res = send_request.send_request(get("/warmup")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let _ = res.into_body().collect().await.unwrap();

    // Into the tunnel.
    dropping.store(true, Ordering::SeqCst);
    let request = tokio::spawn(async move { send_request.send_request(get("/in-the-dark")).await });
    tokio::time::sleep(blackout).await;

    // Out of the tunnel.
    dropping.store(false, Ordering::SeqCst);

    // Generous: after a long outage QUIC's probe timeout has backed off, so
    // recovery is not instant. What matters is that it happens at all.
    let settled = tokio::time::timeout(Duration::from_secs(120), request)
        .await
        .expect("the request must resolve one way or the other, not hang forever")
        .unwrap();

    match settled {
        Ok(res) => {
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(
                res.into_body().collect().await.unwrap().to_bytes(),
                "still here"
            );
            BlackoutOutcome::Survived
        }
        Err(request) => {
            let connection = tokio::time::timeout(Duration::from_secs(30), driver)
                .await
                .expect("a dead connection's future must resolve")
                .unwrap();
            BlackoutOutcome::Died {
                request,
                connection,
            }
        }
    }
}

enum BlackoutOutcome {
    Survived,
    Died {
        /// What the in-flight request saw.
        request: hyper_util::http3::Error,
        /// What the connection future itself resolved to.
        connection: Result<(), hyper_util::http3::Error>,
    },
}

#[tokio::test]
async fn survives_short_blackout_mid_request() {
    match blackout_case(Duration::from_secs(3), IDLE_TIMEOUT).await {
        BlackoutOutcome::Survived => {}
        BlackoutOutcome::Died { request, .. } => {
            panic!("connection died during a 3s blackout: {request:?}")
        }
    }
}

/// The real thing: five minutes with no signal at all, against an idle timeout
/// that is longer than the outage.
///
/// `#[ignore]`d so it does not add five minutes to every pull request, not
/// because it is optional: CI runs it on every merge to master, and it is the
/// test the whole design is for. Locally, `cargo test --features
/// http3,client,server,tokio --test http3 -- --ignored --nocapture`.
///
/// The three-second case above exercises the same code; what this one adds is
/// the duration itself — the timers, keep-alives and loss recovery underneath
/// have five real minutes to get it wrong.
#[tokio::test]
#[ignore = "takes over five minutes by design"]
async fn survives_five_minute_blackout_mid_request() {
    match blackout_case(Duration::from_secs(300), Duration::from_secs(600)).await {
        BlackoutOutcome::Survived => {}
        BlackoutOutcome::Died { request, .. } => {
            panic!("connection died during a 5m blackout: {request:?}")
        }
    }
}

/// The other side of the same coin, and the reason the idle timeout has to be
/// chosen deliberately: an outage *longer* than the idle timeout does end the
/// connection. What matters is that it ends — promptly, with an error the
/// caller can act on by reconnecting — rather than hanging forever.
#[tokio::test]
async fn blackout_longer_than_idle_timeout_fails_cleanly() {
    match blackout_case(Duration::from_secs(10), Duration::from_secs(2)).await {
        BlackoutOutcome::Survived => {
            panic!("a 10s blackout must not survive a 2s idle timeout")
        }
        // Both the request and the connection must say *why*: an app deciding
        // whether to reconnect needs to tell "out of coverage too long" from
        // a protocol failure, and it may hear about it from either.
        BlackoutOutcome::Died {
            request,
            connection,
        } => {
            assert!(
                request.is_timeout(),
                "expected the idle timeout to end the request, got {request:?}"
            );
            let connection = connection.expect_err("a timed-out connection is not a clean close");
            assert!(
                connection.is_timeout(),
                "expected the idle timeout to end the connection, got {connection:?}"
            );
        }
    }
}

/// A UDP relay sitting between client and server that can be told to drop
/// everything, simulating a total loss of signal rather than a clean
/// disconnect. Returns the address clients should talk to.
async fn spawn_relay(server: SocketAddr, dropping: Arc<AtomicBool>) -> SocketAddr {
    let to_client = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap(),
    );
    let to_server = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap(),
    );
    let relay_addr = to_client.local_addr().unwrap();

    // Learned from the first packet the client sends.
    let client_addr = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));

    {
        let (to_client, to_server) = (Arc::clone(&to_client), Arc::clone(&to_server));
        let dropping = Arc::clone(&dropping);
        let client_addr = Arc::clone(&client_addr);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, from) = match to_client.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                *client_addr.lock().unwrap() = Some(from);
                if dropping.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = to_server.send_to(&buf[..n], server).await;
            }
        });
    }

    {
        let (to_client, to_server) = (Arc::clone(&to_client), Arc::clone(&to_server));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, _from) = match to_server.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if dropping.load(Ordering::SeqCst) {
                    continue;
                }
                let dst = *client_addr.lock().unwrap();
                if let Some(dst) = dst {
                    let _ = to_client.send_to(&buf[..n], dst).await;
                }
            }
        });
    }

    relay_addr
}

/// Many requests at once, so the per-stream tasks and the shared connection are
/// exercised together rather than one at a time.
#[tokio::test]
async fn many_concurrent_requests() {
    let tls = tls();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);

    let addr = spawn_server(
        &tls,
        service_fn(move |req: Request<Incoming>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_owned();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(path)).boxed()))
            }
        }),
    );

    let (_endpoint, send_request) = connect(&tls, addr).await;

    let mut handles = Vec::new();
    for i in 0..50 {
        let mut sender = send_request.clone();
        handles.push(tokio::spawn(async move {
            let res = sender
                .send_request(get(&format!("/req/{i}")))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, format!("/req/{i}"));
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(served.load(Ordering::SeqCst), 50);
}
