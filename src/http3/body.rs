//! The body of an HTTP/3 request or response.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};

use super::{Error, TaskGuard};

/// A body received over HTTP/3: a request body on a server, a response body on
/// a client.
///
/// This is the HTTP/3 counterpart of [`hyper::body::Incoming`]. hyper does not
/// let other crates construct that type, so HTTP/3 has its own — which any
/// framework that is generic over its body type, Axum included, accepts as-is.
///
/// It reads straight from the QUIC stream rather than from a channel filled by
/// a background task. So a body that is not being polled leaves its data in
/// the transport's receive window, and the peer stops sending: QUIC's flow
/// control *is* the backpressure, without anything here modelling it.
///
/// Dropping a body before reading it to the end asks the peer to stop sending
/// it.
pub struct Incoming {
    recv: Box<dyn RecvBody>,
    /// What `content-length` says is still to come, if it said anything.
    remaining: Option<u64>,
}

impl Incoming {
    pub(crate) fn new(recv: Box<dyn RecvBody>, content_length: Option<u64>) -> Self {
        Incoming {
            recv,
            remaining: content_length,
        }
    }
}

impl Body for Incoming {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let frame = ready!(self.recv.poll_frame(cx));
        if let (Some(Ok(frame)), Some(remaining)) = (&frame, &mut self.remaining) {
            if let Some(data) = frame.data_ref() {
                *remaining = remaining.saturating_sub(data.len() as u64);
            }
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        // Deliberately not consulting `remaining`: HTTP/3 delimits with the
        // QUIC stream's FIN, and a zero-length body can still be followed by
        // trailers. Only the stream knows when it has ended.
        self.recv.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        match self.remaining {
            Some(remaining) => SizeHint::with_exact(remaining),
            None => SizeHint::default(),
        }
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

/// The receiving half of an HTTP/3 request or response body.
///
/// [`Incoming`] is a concrete type, but an h3 stream is generic over the QUIC
/// backend, so the two meet behind this trait.
pub(crate) trait RecvBody: Send + Sync + 'static {
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>>;

    fn is_end_stream(&self) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecvState {
    Data,
    Trailers,
    Done,
}

/// Convert whatever `Buf` the backend produced into `Bytes`.
///
/// For a backend that already hands out `Bytes` — which is every backend worth
/// having — `copy_to_bytes` is a refcount bump, not a copy.
fn to_bytes(mut buf: impl Buf) -> Bytes {
    buf.copy_to_bytes(buf.remaining())
}

/// Generate a [`RecvBody`] over one of h3's two `RequestStream` types.
///
/// `h3::server::RequestStream` and `h3::client::RequestStream` have the same
/// receive API but are distinct types, and neither exposes a shared trait for
/// it, so the implementation is generated for each.
macro_rules! recv_body {
    ($name:ident, $stream:ty) => {
        pub(crate) struct $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            stream: $stream,
            state: RecvState,
            /// Keeps the connection alive while this body is still readable.
            _guard: std::sync::Arc<TaskGuard>,
        }

        impl<S, B> $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            pub(crate) fn new(stream: $stream, guard: std::sync::Arc<TaskGuard>) -> Self {
                Self {
                    stream,
                    state: RecvState::Data,
                    _guard: guard,
                }
            }
        }

        impl<S, B> RecvBody for $name<S, B>
        where
            S: h3::quic::RecvStream + Send + Sync + 'static,
            B: Buf + Send + Sync + 'static,
        {
            fn poll_frame(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
                if self.state == RecvState::Data {
                    match ready!(self.stream.poll_recv_data(cx)) {
                        Ok(Some(buf)) => return Poll::Ready(Some(Ok(Frame::data(to_bytes(buf))))),
                        Ok(None) => self.state = RecvState::Trailers,
                        Err(err) => {
                            self.state = RecvState::Done;
                            // An early response resets the request stream with
                            // `H3_NO_ERROR`. Like HTTP/2's `RST_STREAM(NO_ERROR)`,
                            // that ends the body, it does not fail it.
                            return Poll::Ready(if err.is_h3_no_error() {
                                None
                            } else {
                                Some(Err(Error::stream(err)))
                            });
                        }
                    }
                }

                if self.state == RecvState::Trailers {
                    let trailers = ready!(self.stream.poll_recv_trailers(cx));
                    self.state = RecvState::Done;
                    return Poll::Ready(match trailers {
                        Ok(Some(map)) => Some(Ok(Frame::trailers(map))),
                        Ok(None) => None,
                        Err(err) if err.is_h3_no_error() => None,
                        Err(err) => Some(Err(Error::stream(err))),
                    });
                }

                Poll::Ready(None)
            }

            fn is_end_stream(&self) -> bool {
                self.state == RecvState::Done
            }
        }

        impl<S, B> Drop for $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            fn drop(&mut self) {
                if self.state != RecvState::Done {
                    // The body was dropped without being read to the end —
                    // usually a handler that ignored the request body. Tell the
                    // peer to stop sending rather than letting it push bytes at
                    // a window nobody will ever drain.
                    //
                    // `H3_NO_ERROR` is the code the spec asks for here, not a
                    // stand-in for a cancellation code: RFC 9114 §4.1 says
                    // "H3_NO_ERROR SHOULD be used when requesting that the
                    // client stop sending on the request stream". Nothing went
                    // wrong; the rest of the body is simply not wanted.
                    self.stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                }
            }
        }
    };
}

#[cfg(feature = "server")]
recv_body!(ServerRecvBody, h3::server::RequestStream<S, B>);
#[cfg(feature = "client")]
recv_body!(ClientRecvBody, h3::client::RequestStream<S, B>);
