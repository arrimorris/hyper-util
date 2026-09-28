//! HTTP/3 types shared by clients and servers.
//!
//! HTTP/3 connections themselves live in
//! [`server::conn::http3`](crate::server::conn) and
//! [`client::conn::http3`](crate::client::conn), and run over any QUIC
//! implementation that implements [`rt::quic`](crate::rt::quic). This module
//! holds what both sides share: the [`Incoming`] body type and the [`Error`]
//! type.
//!
//! The wire format itself comes from the [`h3`](https://docs.rs/h3) crate,
//! the same way HTTP/2 comes from `h2`. `h3` never appears in this crate's
//! public API.
//!
//! This module requires the `http3` feature, which is **experimental** and
//! not part of `full`.

mod body;
mod error;
pub(crate) mod glue;

#[cfg(feature = "client")]
pub(crate) mod client;
#[cfg(feature = "server")]
pub(crate) mod server;

pub use self::body::Incoming;
pub use self::error::Error;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

// ===== spawned work =====

/// A piece of HTTP/3 work that a connection spawns on its executor.
///
/// Each request runs as its own `Task`, so one slow body cannot hold up the
/// others sharing a connection. The executor given to a server or client
/// builder must be able to run these; any [`hyper::rt::Executor`] for
/// `Send + 'static` futures can, hyper-util's `TokioExecutor` included.
///
/// This is a boxed future rather than a hand-written state machine because h3
/// 0.0.8 only offers `async fn` for the send half of a request stream, and a
/// header block cannot be produced without it — QPACK encoding is private to
/// h3. One allocation per request is the price; it disappears if h3 grows a
/// poll-based send API.
#[must_use = "futures do nothing unless polled"]
pub struct Task {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Task {
    pub(crate) fn new<F>(fut: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Task {
            inner: Box::pin(fut),
        }
    }
}

impl Future for Task {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task").finish_non_exhaustive()
    }
}

// ===== in-flight request tracking =====

/// Held for as long as one request is still in flight.
///
/// A request is not finished when its task is: the response body outlives the
/// exchange that produced it, and the request body may still be uploading. So
/// this is shared (via `Arc`) by every piece a single request owns, and the
/// connection only hears about the request once the last of them is dropped.
pub(crate) struct TaskGuard(tokio::sync::mpsc::UnboundedSender<()>);

impl TaskGuard {
    pub(crate) fn new(tx: tokio::sync::mpsc::UnboundedSender<()>) -> Self {
        TaskGuard(tx)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        // The connection future decrements its in-flight count for each of
        // these. A send failure just means the connection is already gone.
        let _ = self.0.send(());
    }
}

// ===== headers =====

/// The `content-length` of a message, if it has exactly one well-formed value.
///
/// Several `content-length` values are fine as long as they agree; anything
/// else — disagreement, a sign, junk — means there is no usable length.
pub(crate) fn content_length(headers: &http::HeaderMap) -> Option<u64> {
    let mut content_length: Option<u64> = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH) {
        let line = value.to_str().ok()?;
        for v in line.split(',') {
            let n = from_digits(v.trim().as_bytes())?;
            match content_length {
                None => content_length = Some(n),
                Some(existing) if existing != n => return None,
                Some(_) => {}
            }
        }
    }
    content_length
}

fn from_digits(bytes: &[u8]) -> Option<u64> {
    // Not `str::parse`, which accepts a leading `+`.
    if bytes.is_empty() {
        return None;
    }
    let mut result = 0u64;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {
                result = result.checked_mul(10)?;
                result = result.checked_add(u64::from(b - b'0'))?;
            }
            _ => return None,
        }
    }
    Some(result)
}

pub(crate) fn set_content_length_if_missing(headers: &mut http::HeaderMap, len: u64) {
    headers
        .entry(http::header::CONTENT_LENGTH)
        .or_insert_with(|| http::HeaderValue::from(len));
}

/// Which side of an exchange a header block belongs to.
pub(crate) enum MessageKind {
    #[cfg(feature = "client")]
    Request,
    #[cfg(feature = "server")]
    Response,
}

/// Remove the connection-specific headers HTTP/3 forbids.
///
/// RFC 9114 §4.2 forbids exactly the headers RFC 9113 §8.2.2 does for HTTP/2,
/// so this is the same list hyper strips there. The one exception is `TE`,
/// which a request may carry as long as its value is `trailers`.
pub(crate) fn strip_connection_headers(headers: &mut http::HeaderMap, kind: MessageKind) {
    use http::header::{CONNECTION, TE, TRANSFER_ENCODING, UPGRADE};

    for header in [
        http::HeaderName::from_static("keep-alive"),
        http::HeaderName::from_static("proxy-connection"),
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        if headers.remove(&header).is_some() {
            tracing::warn!("connection header illegal in HTTP/3: {}", header.as_str());
        }
    }

    // Each half gated on its own feature: under one `cfg`, the other half
    // would silently disappear from builds with only one of them.
    #[cfg(feature = "client")]
    if matches!(kind, MessageKind::Request) && headers.get(TE).is_some_and(|te| te != "trailers") {
        tracing::warn!("TE headers not set to \"trailers\" are illegal in HTTP/3 requests");
        headers.remove(TE);
    }
    #[cfg(feature = "server")]
    if matches!(kind, MessageKind::Response) && headers.remove(TE).is_some() {
        tracing::warn!("TE headers illegal in HTTP/3 responses");
    }

    if let Some(header) = headers.remove(CONNECTION) {
        tracing::warn!(
            "connection header illegal in HTTP/3: {}",
            CONNECTION.as_str()
        );
        // A `Connection` header may name other headers that are meant for
        // this connection only. Those go too.
        if let Ok(names) = header.to_str() {
            for name in names.split(',') {
                headers.remove(name.trim());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_accepts_agreeing_duplicates_only() {
        let mut h = http::HeaderMap::new();
        h.append("content-length", "5".parse().unwrap());
        h.append("content-length", "5, 5".parse().unwrap());
        assert_eq!(content_length(&h), Some(5));

        h.append("content-length", "6".parse().unwrap());
        assert_eq!(content_length(&h), None, "disagreeing values");

        let mut h = http::HeaderMap::new();
        h.insert("content-length", "+5".parse().unwrap());
        assert_eq!(content_length(&h), None, "a sign is not a digit");
    }

    #[test]
    fn strips_the_connection_headers() {
        let mut h = http::HeaderMap::new();
        for (name, value) in [
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("connection", "x-hop"),
            ("x-hop", "gone"),
            ("x-keep", "kept"),
        ] {
            h.append(name, value.parse().unwrap());
        }

        #[cfg(feature = "client")]
        strip_connection_headers(&mut h, MessageKind::Request);
        #[cfg(not(feature = "client"))]
        strip_connection_headers(&mut h, MessageKind::Response);

        assert_eq!(h.len(), 1);
        assert_eq!(h["x-keep"], "kept");
    }

    #[cfg(feature = "client")]
    #[test]
    fn a_request_keeps_te_trailers_but_nothing_else() {
        let mut h = http::HeaderMap::new();
        h.insert("te", "trailers".parse().unwrap());
        strip_connection_headers(&mut h, MessageKind::Request);
        assert_eq!(h["te"], "trailers");

        h.insert("te", "gzip".parse().unwrap());
        strip_connection_headers(&mut h, MessageKind::Request);
        assert!(!h.contains_key("te"));
    }

    #[cfg(feature = "server")]
    #[test]
    fn a_response_never_keeps_te() {
        for value in ["trailers", "gzip"] {
            let mut h = http::HeaderMap::new();
            h.insert("te", value.parse().unwrap());
            strip_connection_headers(&mut h, MessageKind::Response);
            assert!(!h.contains_key("te"), "TE: {value} survived a response");
        }
    }
}
