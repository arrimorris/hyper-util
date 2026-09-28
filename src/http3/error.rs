//! The error type shared by HTTP/3 clients and servers.

use std::error::Error as StdError;
use std::fmt;

type BoxError = Box<dyn StdError + Send + Sync>;

/// An error from an HTTP/3 connection, or from one request on it.
///
/// HTTP/3 fails at two granularities, and they call for different responses: a
/// *stream* error ends one request and leaves the connection usable, a
/// *connection* error ends every request on it. The underlying cause is
/// available through [`source`](StdError::source).
///
/// A connection that ends with `H3_NO_ERROR` — a peer hanging up, or a
/// graceful shutdown completing — ended cleanly, and is never reported as an
/// `Error`.
pub struct Error {
    kind: Kind,
    source: Option<BoxError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The QUIC or HTTP/3 connection failed.
    Connection,
    /// The connection went unheard-from for longer than the transport's idle
    /// timeout.
    Timeout,
    /// One request stream failed; the connection may be fine.
    Stream,
    /// The request was canceled, or its connection closed before it could be
    /// sent.
    Canceled,
    /// The body being sent returned an error.
    Body,
    /// The service returned an error.
    #[cfg(feature = "server")]
    Service,
}

impl Error {
    fn new(kind: Kind) -> Self {
        Error { kind, source: None }
    }

    fn with(mut self, cause: impl Into<BoxError>) -> Self {
        self.source = Some(cause.into());
        self
    }

    /// Map an h3 connection error.
    ///
    /// A connection that ended with `H3_NO_ERROR` ended cleanly; that is not a
    /// failure and must not be reported as one.
    pub(crate) fn from_connection(cause: h3::error::ConnectionError) -> Option<Self> {
        if cause.is_h3_no_error() {
            return None;
        }
        let kind = match cause {
            h3::error::ConnectionError::Timeout => Kind::Timeout,
            _ => Kind::Connection,
        };
        Some(Error::new(kind).with(cause))
    }

    /// Map an h3 stream error. A stream that failed because its connection did
    /// is reported as the connection's failure.
    pub(crate) fn stream(cause: h3::error::StreamError) -> Self {
        let kind = match cause {
            h3::error::StreamError::ConnectionError(h3::error::ConnectionError::Timeout) => {
                Kind::Timeout
            }
            h3::error::StreamError::ConnectionError(_) => Kind::Connection,
            _ => Kind::Stream,
        };
        Error::new(kind).with(cause)
    }

    #[cfg(feature = "client")]
    pub(crate) fn canceled() -> Self {
        Error::new(Kind::Canceled)
    }

    #[cfg(feature = "client")]
    pub(crate) fn canceled_with(cause: impl Into<BoxError>) -> Self {
        Error::new(Kind::Canceled).with(cause)
    }

    pub(crate) fn body(cause: impl Into<BoxError>) -> Self {
        Error::new(Kind::Body).with(cause)
    }

    #[cfg(feature = "server")]
    pub(crate) fn service(cause: impl Into<BoxError>) -> Self {
        Error::new(Kind::Service).with(cause)
    }

    /// Returns true if the request was canceled, or its connection closed
    /// before it could be sent.
    pub fn is_canceled(&self) -> bool {
        self.kind == Kind::Canceled
    }

    /// Returns true if the connection's idle timeout expired.
    ///
    /// This is the *transport's* timeout — the QUIC `max_idle_timeout` — not
    /// one of hyper-util's; nothing here times a connection out on its own. A
    /// client that goes out of coverage for longer than that timeout sees
    /// this, and should reconnect.
    pub fn is_timeout(&self) -> bool {
        self.kind == Kind::Timeout
    }

    fn description(&self) -> &'static str {
        match self.kind {
            Kind::Connection => "http3 connection error",
            Kind::Timeout => "http3 connection timed out",
            Kind::Stream => "http3 stream error",
            Kind::Canceled => "http3 request canceled",
            Kind::Body => "error sending http3 body",
            #[cfg(feature = "server")]
            Kind::Service => "http3 service error",
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut t = f.debug_tuple("hyper_util::http3::Error");
        t.field(&self.kind);
        if let Some(source) = &self.source {
            t.field(source);
        }
        t.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn StdError + 'static))
    }
}
