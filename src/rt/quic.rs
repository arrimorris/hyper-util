//! Generic QUIC transport support.
//!
//! HTTP/1 and HTTP/2 both run over a single, ordered byte stream, which hyper
//! abstracts with the [`Read`](hyper::rt::Read) and [`Write`](hyper::rt::Write)
//! traits.
//! HTTP/3 cannot: QUIC multiplexes independent streams *inside* the transport,
//! so a connection is no longer a pair of byte pipes. It is a thing that
//! streams can be opened on and accepted from.
//!
//! This module is that abstraction. Implement these traits for a QUIC
//! implementation — [quinn], [s2n-quic], [quiche], anything — and hyper-util
//! can speak HTTP/3 over it without ever depending on it.
//!
//! # Connection migration
//!
//! Nothing in this module names a socket address, and hyper-util never caches
//! one.
//! A QUIC connection is identified by its Connection ID, not by the 4-tuple, so
//! a peer that changes network — a phone moving from Wi-Fi to cellular, a
//! laptop switching access points — keeps the same connection, the same
//! streams, and the same in-flight requests. Implementations are expected to
//! let that happen underneath hyper-util: an address change is not a connection
//! error and must not be reported as one. Likewise, a connection that is merely
//! *idle* (a peer out of coverage for minutes) must keep returning
//! [`Poll::Pending`] rather than an error, until the transport's own idle
//! timeout actually expires.
//!
//! # Stability
//!
//! This module is enabled by the `http3` feature, which is **experimental** and
//! deliberately excluded from `full`. The traits are meant to settle here, in
//! hyper-util, before anything about HTTP/3 is proposed for hyper itself; until
//! then they may change in a minor release.
//!
//! [quinn]: https://docs.rs/quinn
//! [s2n-quic]: https://docs.rs/s2n-quic
//! [quiche]: https://docs.rs/quiche

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Buf;

/// A QUIC connection.
///
/// This is the entry point hyper-util needs to run HTTP/3: something that streams
/// can be accepted from, plus (via [`OpenStreams`]) something they can be
/// opened on.
///
/// The `B` parameter is the buffer type used for outgoing data. It is the
/// same type as the `Data` of the [`Body`](http_body::Body) being sent, which
/// lets payload bytes reach the transport without a copy.
pub trait Connection<B: Buf>: OpenStreams<B> {
    /// Unidirectional streams accepted from the peer.
    type RecvStream: RecvStream;

    /// A handle that can open new outgoing streams.
    ///
    /// HTTP/3 needs to open its control and QPACK streams while it is also
    /// accepting incoming ones, so opening is split out into a separate handle
    /// that can be held independently of `&mut self`.
    type OpenStreams: OpenStreams<B, SendStream = Self::SendStream, BidiStream = Self::BidiStream>;

    /// Accept an incoming bidirectional stream.
    ///
    /// On a server these carry requests. This should stay [`Pending`] for as
    /// long as the connection is alive but quiet, however long that is.
    ///
    /// [`Pending`]: Poll::Pending
    fn poll_accept_bidirectional_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionError>>;

    /// Accept an incoming unidirectional stream.
    ///
    /// These carry the peer's control and QPACK streams.
    fn poll_accept_recv_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionError>>;

    /// Get a handle for opening outgoing streams.
    fn opener(&self) -> Self::OpenStreams;
}

/// The ability to open outgoing QUIC streams.
pub trait OpenStreams<B: Buf> {
    /// Bidirectional streams opened by this side.
    ///
    /// These must be splittable: hyper-util hands a request body to a
    /// [`Service`](hyper::service::Service) while still writing the response on
    /// the same stream, so it needs the two halves separately.
    type BidiStream: BidiStream<B>;

    /// Unidirectional send streams opened by this side.
    type SendStream: SendStream<B>;

    /// Open a new bidirectional stream.
    ///
    /// On a client these carry requests.
    fn poll_open_bidirectional_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>>;

    /// Open a new unidirectional send stream.
    fn poll_open_send_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>>;

    /// Close the whole connection immediately, with an application error code.
    ///
    /// The `code` is an HTTP/3 error code, as defined in [RFC 9114 §8.1].
    ///
    /// [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
    fn close(&mut self, code: u64, reason: &[u8]);
}

/// The send half of a QUIC stream.
pub trait SendStream<B: Buf> {
    /// Poll until previously queued data has been handed to the transport.
    ///
    /// Returning [`Pending`] is how a QUIC implementation applies flow-control
    /// backpressure to hyper-util, which passes it on to the [`Body`] being sent.
    ///
    /// [`Pending`]: Poll::Pending
    /// [`Body`]: http_body::Body
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>>;

    /// Queue data to be sent on this stream.
    ///
    /// This does not block and does not report backpressure; it takes ownership
    /// of `data` and returns. Call [`poll_ready`] to learn when the transport
    /// has taken it and another buffer may be queued.
    ///
    /// Implementations may assume [`poll_ready`] returned
    /// [`Ready`](Poll::Ready) since the last call.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream or the connection has already failed, so
    /// the data can never be sent.
    ///
    /// [`poll_ready`]: SendStream::poll_ready
    fn send_data(&mut self, data: WriteBuf<B>) -> Result<(), StreamError>;

    /// Poll until the sending half has been closed cleanly (a QUIC `FIN`).
    ///
    /// Implementations must flush anything still queued by [`send_data`]
    /// before signalling the `FIN`. A stream finished at the wrong offset
    /// truncates silently: the peer sees a complete stream that is short.
    ///
    /// [`send_data`]: SendStream::send_data
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>>;

    /// Abruptly terminate the sending half with a `RESET_STREAM`.
    fn reset(&mut self, reset_code: u64);

    /// The ID of this stream.
    fn send_id(&self) -> StreamId;
}

/// The receive half of a QUIC stream.
pub trait RecvStream {
    /// The buffer type yielded by this stream.
    ///
    /// Backends that already own their received bytes as
    /// [`Bytes`](bytes::Bytes) hand them to hyper-util without a copy.
    type Buf: Buf;

    /// Poll for the next chunk of data from the peer.
    ///
    /// Returns `Ok(None)` once the peer has finished sending (a QUIC `FIN`).
    ///
    /// Not polling this is how hyper-util applies backpressure back to the peer: an
    /// unread stream stops draining the QUIC flow-control window, so the peer
    /// stops sending. Implementations must therefore only release flow-control
    /// credit for data actually returned from here.
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamError>>;

    /// Ask the peer to stop sending on this stream, with an error code.
    fn stop_sending(&mut self, error_code: u64);

    /// The ID of this stream.
    fn recv_id(&self) -> StreamId;
}

/// A bidirectional QUIC stream that can be split into its two halves.
///
/// hyper-util needs this to hand a request body to a
/// [`Service`](hyper::service::Service) while it is still writing the response
/// on the same stream.
pub trait BidiStream<B: Buf>: SendStream<B> + RecvStream {
    /// The send half.
    type SendStream: SendStream<B>;

    /// The receive half.
    type RecvStream: RecvStream;

    /// Split this stream into its send and receive halves.
    fn split(self) -> (Self::SendStream, Self::RecvStream);
}

/// The identifier of a QUIC stream.
///
/// See [RFC 9000 §2.1].
///
/// [RFC 9000 §2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// The largest value a stream ID may have.
    ///
    /// Stream IDs are QUIC variable-length integers, so they are capped at
    /// 2^62 - 1.
    pub const MAX: u64 = u64::MAX >> 2;

    /// Create a `StreamId` from its wire value.
    ///
    /// Returns `None` if the value is too large to be a valid stream ID.
    pub fn new(id: u64) -> Option<Self> {
        if id > Self::MAX {
            None
        } else {
            Some(StreamId(id))
        }
    }

    /// The wire value of this stream ID.
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Data queued for transmission on a QUIC stream.
///
/// hyper-util hands these to [`SendStream::send_data`]. A `WriteBuf` is just a
/// [`Buf`]; write its bytes to the stream in order. It exists so that the
/// HTTP/3 frame header and the body bytes it describes can travel together
/// without being copied into one contiguous buffer first.
///
/// # Stability
///
/// This type is opaque, but its *contents* are produced by the HTTP/3
/// implementation hyper-util builds on, so its size and the exact byte
/// sequence it yields track that implementation rather than hyper-util's own
/// versioning. Its
/// public shape — an opaque `Buf` — is what backends depend on, and that is
/// what will be kept. Backends must not assume anything about the length or
/// framing of what they read out of it.
pub struct WriteBuf<B> {
    inner: h3::quic::WriteBuf<B>,
}

impl<B: Buf> WriteBuf<B> {
    // Only hyper-util constructs these, and only when it is actually driving a
    // client or server connection.
    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn from_h3(inner: h3::quic::WriteBuf<B>) -> Self {
        WriteBuf { inner }
    }
}

impl<B: Buf> Buf for WriteBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.inner.chunk()
    }

    #[inline]
    fn chunks_vectored<'data>(&'data self, dst: &mut [std::io::IoSlice<'data>]) -> usize {
        self.inner.chunks_vectored(dst)
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        self.inner.advance(cnt);
    }
}

impl<B: Buf> fmt::Debug for WriteBuf<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteBuf")
            .field("remaining", &self.remaining())
            .finish()
    }
}

/// An error on a QUIC connection.
///
/// The variants are the distinctions HTTP/3 actually acts on. Anything else a
/// transport wants to report belongs in [`Other`](ConnectionError::Other).
#[derive(Clone)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The peer closed the connection with an application error code.
    ///
    /// For HTTP/3 this is an [RFC 9114 §8.1] code; `H3_NO_ERROR` (`0x100`)
    /// means the peer closed cleanly.
    ///
    /// [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
    ApplicationClosed {
        /// The error code sent by the peer.
        error_code: u64,
    },
    /// The connection's idle timeout expired.
    ///
    /// This is the *transport's* timeout, not hyper-util's; it never times a
    /// connection out on its own. A peer that expects to go dark for a long
    /// time should be configured with a correspondingly long idle timeout, or
    /// should keep the connection alive with QUIC PING frames.
    TimedOut,
    /// The transport implementation itself failed.
    ///
    /// hyper-util closes the connection with `H3_INTERNAL_ERROR`.
    Internal(String),
    /// Any other transport error, such as a QUIC protocol violation.
    Other(Arc<dyn StdError + Send + Sync>),
}

impl fmt::Debug for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationClosed { error_code } => f
                .debug_struct("ApplicationClosed")
                .field("error_code", &format_args!("{error_code:#x}"))
                .finish(),
            Self::TimedOut => f.write_str("TimedOut"),
            Self::Internal(msg) => f.debug_tuple("Internal").field(msg).finish(),
            Self::Other(err) => f.debug_tuple("Other").field(err).finish(),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationClosed { error_code } => {
                write!(f, "connection closed by peer with code {error_code:#x}")
            }
            Self::TimedOut => f.write_str("connection timed out"),
            Self::Internal(msg) => write!(f, "quic transport error: {msg}"),
            Self::Other(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl StdError for ConnectionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Other(err) => Some(&**err),
            _ => None,
        }
    }
}

/// An error on a single QUIC stream.
#[non_exhaustive]
pub enum StreamError {
    /// The whole connection failed, taking this stream with it.
    Connection(ConnectionError),
    /// The peer terminated this stream, without ending the connection.
    ///
    /// This is a `RESET_STREAM` from the peer's sending side, or a
    /// `STOP_SENDING` for its receiving side.
    Reset {
        /// The error code sent by the peer.
        error_code: u64,
    },
    /// Any other error on this stream.
    ///
    /// HTTP/3 treats this the same as [`Reset`](StreamError::Reset).
    Other(Box<dyn StdError + Send + Sync>),
}

impl fmt::Debug for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => f.debug_tuple("Connection").field(err).finish(),
            Self::Reset { error_code } => f
                .debug_struct("Reset")
                .field("error_code", &format_args!("{error_code:#x}"))
                .finish(),
            Self::Other(err) => f.debug_tuple("Other").field(err).finish(),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => fmt::Display::fmt(err, f),
            Self::Reset { error_code } => {
                write!(f, "stream reset by peer with code {error_code:#x}")
            }
            Self::Other(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl StdError for StreamError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Reset { .. } => None,
            Self::Other(err) => Some(&**err),
        }
    }
}

impl From<ConnectionError> for StreamError {
    fn from(err: ConnectionError) -> Self {
        StreamError::Connection(err)
    }
}
