//! Adapters from [`hyper_util::rt::quic`](crate::rt::quic) to `h3::quic`.
//!
//! The public QUIC abstraction deliberately does not mention `h3`: `h3` is a
//! `0.0.x` private dependency, and hyper-util's semver-bound API has to outlive
//! it. These newtypes are the only place the two meet.
//!
//! Every type here is a `#[repr(transparent)]`-shaped wrapper with no state of
//! its own, so nothing is boxed, buffered or copied on the way through — which
//! matters, because a wrapper is created per QUIC stream, and a QUIC stream is
//! created per request.

use std::task::{Context, Poll};

use bytes::Buf;

use crate::rt::quic;

// ===== error mapping =====
//
// The variants line up one for one. This is on purpose: HTTP/3 behaves
// differently for each class (a clean `H3_NO_ERROR` close is not a failure, a
// stream reset is not a connection failure), so collapsing them into an opaque
// error would silently degrade the protocol.

fn conn_err(err: quic::ConnectionError) -> h3::quic::ConnectionErrorIncoming {
    match err {
        quic::ConnectionError::ApplicationClosed { error_code } => {
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }
        }
        quic::ConnectionError::TimedOut => h3::quic::ConnectionErrorIncoming::Timeout,
        quic::ConnectionError::Internal(msg) => {
            h3::quic::ConnectionErrorIncoming::InternalError(msg)
        }
        quic::ConnectionError::Other(err) => h3::quic::ConnectionErrorIncoming::Undefined(err),
    }
}

fn stream_err(err: quic::StreamError) -> h3::quic::StreamErrorIncoming {
    match err {
        quic::StreamError::Connection(err) => {
            h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: conn_err(err),
            }
        }
        quic::StreamError::Reset { error_code } => {
            h3::quic::StreamErrorIncoming::StreamTerminated { error_code }
        }
        quic::StreamError::Other(err) => h3::quic::StreamErrorIncoming::Unknown(err),
    }
}

/// Both sides cap stream IDs at the QUIC varint maximum (2^62 - 1), and
/// [`quic::StreamId`] can only be built through a constructor that enforces it,
/// so this conversion cannot fail.
fn stream_id(id: quic::StreamId) -> h3::quic::StreamId {
    h3::quic::StreamId::try_from(id.into_inner())
        .expect("hyper_util::rt::quic::StreamId is always a valid QUIC stream id")
}

// ===== connection =====

/// Wraps a [`quic::Connection`] so `h3` can drive it.
pub(crate) struct Conn<Q>(pub(crate) Q);

impl<Q, B> h3::quic::Connection<B> for Conn<Q>
where
    Q: quic::Connection<B>,
    B: Buf,
{
    type RecvStream = RecvStream<Q::RecvStream>;
    type OpenStreams = OpenStreams<Q::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::quic::ConnectionErrorIncoming>> {
        match self.0.poll_accept_recv_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(RecvStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(conn_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::ConnectionErrorIncoming>> {
        match self.0.poll_accept_bidirectional_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(BidiStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(conn_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams(self.0.opener())
    }
}

impl<Q, B> h3::quic::OpenStreams<B> for Conn<Q>
where
    Q: quic::Connection<B>,
    B: Buf,
{
    type BidiStream = BidiStream<Q::BidiStream>;
    type SendStream = SendStream<Q::SendStream>;

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        match self.0.poll_open_send_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(SendStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(stream_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        match self.0.poll_open_bidirectional_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(BidiStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(stream_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.0.close(code.value(), reason);
    }
}

/// Wraps a [`quic::OpenStreams`] handle so `h3` can open its control and QPACK
/// streams while the connection is busy accepting.
pub(crate) struct OpenStreams<O>(O);

/// h3's client `SendRequest` is a cloneable handle, which requires the opener
/// underneath it to be one too.
impl<O: Clone> Clone for OpenStreams<O> {
    fn clone(&self) -> Self {
        OpenStreams(self.0.clone())
    }
}

impl<O, B> h3::quic::OpenStreams<B> for OpenStreams<O>
where
    O: quic::OpenStreams<B>,
    B: Buf,
{
    type BidiStream = BidiStream<O::BidiStream>;
    type SendStream = SendStream<O::SendStream>;

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        match self.0.poll_open_send_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(SendStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(stream_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        match self.0.poll_open_bidirectional_stream(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(BidiStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(stream_err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.0.close(code.value(), reason);
    }
}

// ===== streams =====

/// Wraps a bidirectional [`quic`] stream.
pub(crate) struct BidiStream<S>(S);

/// Wraps the send half of a [`quic`] stream.
pub(crate) struct SendStream<S>(S);

/// Wraps the receive half of a [`quic`] stream.
pub(crate) struct RecvStream<S>(pub(crate) S);

macro_rules! impl_send_stream {
    ($ty:ident) => {
        impl<S, B> h3::quic::SendStream<B> for $ty<S>
        where
            S: quic::SendStream<B>,
            B: Buf,
        {
            fn poll_ready(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
                self.0.poll_ready(cx).map(|res| res.map_err(stream_err))
            }

            fn send_data<T: Into<h3::quic::WriteBuf<B>>>(
                &mut self,
                data: T,
            ) -> Result<(), h3::quic::StreamErrorIncoming> {
                self.0
                    .send_data(quic::WriteBuf::from_h3(data.into()))
                    .map_err(stream_err)
            }

            fn poll_finish(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
                self.0.poll_finish(cx).map(|res| res.map_err(stream_err))
            }

            fn reset(&mut self, reset_code: u64) {
                self.0.reset(reset_code);
            }

            fn send_id(&self) -> h3::quic::StreamId {
                stream_id(self.0.send_id())
            }
        }
    };
}

macro_rules! impl_recv_stream {
    ($ty:ident) => {
        impl<S> h3::quic::RecvStream for $ty<S>
        where
            S: quic::RecvStream,
        {
            type Buf = S::Buf;

            fn poll_data(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
                self.0.poll_data(cx).map(|res| res.map_err(stream_err))
            }

            fn stop_sending(&mut self, error_code: u64) {
                self.0.stop_sending(error_code);
            }

            fn recv_id(&self) -> h3::quic::StreamId {
                stream_id(self.0.recv_id())
            }
        }
    };
}

impl_send_stream!(BidiStream);
impl_send_stream!(SendStream);
impl_recv_stream!(BidiStream);
impl_recv_stream!(RecvStream);

impl<S, B> h3::quic::BidiStream<B> for BidiStream<S>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    type SendStream = SendStream<S::SendStream>;
    type RecvStream = RecvStream<S::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.0.split();
        (SendStream(send), RecvStream(recv))
    }
}
