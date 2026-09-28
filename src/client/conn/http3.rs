//! HTTP/3 client connections.
//!
//! HTTP/3 runs over QUIC, which multiplexes streams in the transport itself
//! rather than on top of a single byte stream. So unlike hyper's `http1` and
//! `http2` connections, which are handed something that implements
//! [`Read`](hyper::rt::Read) + [`Write`](hyper::rt::Write), this module is
//! handed a whole QUIC connection: anything implementing
//! [`hyper_util::rt::quic::Connection`](crate::rt::quic::Connection).
//!
//! Responses come back as `Response<`[`Incoming`]`>`.
//!
//! This module requires the `http3` and `client` features. `http3` is
//! **experimental** and not part of `full`.
//!
//! # ALPN
//!
//! HTTP/3 is identified by the ALPN token `h3` ([RFC 9114 §3.1]), negotiated
//! by the QUIC layer's TLS configuration. That happens below anything this
//! module can see, so hyper-util cannot check it or set it for you: a peer that
//! offers a different token fails the QUIC handshake, and the connection
//! never reaches [`handshake`]. Configure it wherever your QUIC
//! backend takes its TLS settings — for quinn, `rustls`'s
//! `alpn_protocols`; see the `http3_client` example.
//!
//! [RFC 9114 §3.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
//!
//! # Connection migration
//!
//! A QUIC connection survives the client changing network. If the device drops
//! Wi-Fi and comes back on cellular, the QUIC Connection ID still identifies
//! the session, so the same [`SendRequest`] keeps working and in-flight
//! requests continue where they left off — no new handshake, no lost request.
//! Nothing here helps or hinders this; it simply never assumes the peer
//! address is stable, and never imposes a timeout of its own. How long a
//! connection may stay dark before the transport gives up is the QUIC
//! implementation's `max_idle_timeout`. When it does, errors report
//! [`is_timeout`](crate::http3::Error::is_timeout).

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::Body;
use hyper::rt::Executor;
use pin_project_lite::pin_project;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace};

pub use crate::http3::client::TrySendError;
use crate::http3::client::{ClientTask, ClientTx, Config};
use crate::http3::{Error, Incoming, Task};
use crate::rt::quic;

/// The sender side of an established connection.
pub struct SendRequest<B> {
    tx: ClientTx<B>,
}

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> SendRequest<B> {
        SendRequest {
            tx: self.tx.clone(),
        }
    }
}

pin_project! {
    /// A future that processes all HTTP/3 state for the QUIC connection.
    ///
    /// In most cases, this should just be spawned into an executor, so that it
    /// can process incoming and outgoing messages, notice hangups, and the like.
    ///
    /// Instances of this type are typically created via the [`handshake`] function.
    ///
    /// # Drop behavior
    ///
    /// Dropping the `Connection` closes the underlying QUIC connection. Any
    /// in-flight requests that have not received a response are interrupted. If
    /// graceful shutdown is desired, drop every [`SendRequest`] and poll this
    /// future to completion instead.
    #[must_use = "futures do nothing unless polled"]
    pub struct Connection<Q, B, E>
    where
        Q: quic::Connection<B::Data>,
        B: Body,
    {
        inner: ClientTask<Q, B, E>,
    }
}

/// A builder to configure an HTTP/3 connection.
///
/// After setting options, the builder is used to create a handshake future.
///
/// **Note**: The default values of options are *not considered stable*. They
/// are subject to change at any time.
#[derive(Clone, Debug)]
pub struct Builder<Ex> {
    pub(super) exec: Ex,
    h3_builder: Config,
}

/// Returns a handshake future over some QUIC connection.
///
/// This is a shortcut for `Builder::new(exec).handshake(quic)`.
///
/// # Errors
///
/// Returns an error if the HTTP/3 handshake fails — that is, if the control
/// and QPACK streams could not be established over the QUIC connection.
pub async fn handshake<E, Q, B>(
    exec: E,
    quic: Q,
) -> Result<(SendRequest<B>, Connection<Q, B, E>), Error>
where
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Clone + Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Executor<Task> + Clone + Send + 'static,
{
    Builder::new(exec).handshake(quic).await
}

// ===== impl SendRequest =====

impl<B> SendRequest<B> {
    /// Polls to determine whether this sender can be used yet for a request.
    ///
    /// If the associated connection is closed, this returns an Error.
    pub fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.is_closed() {
            Poll::Ready(Err(Error::canceled_with("connection closed")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Waits until the connection is ready to take a request.
    ///
    /// # Errors
    ///
    /// If the associated connection is closed, this returns an Error.
    pub async fn ready(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Checks if the connection is currently ready to send a request.
    ///
    /// # Note
    ///
    /// This is mostly a hint. Due to inherent latency of networks, it is
    /// possible that even after checking this is ready, sending a request
    /// may still fail because the connection was closed in the meantime.
    pub fn is_ready(&self) -> bool {
        !self.is_closed()
    }

    /// Checks if the connection side has been closed.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl<B> SendRequest<B>
where
    B: Body + 'static,
{
    /// Sends a `Request` on the associated connection.
    ///
    /// Returns a future that if successful, yields the `Response`.
    ///
    /// The request body is uploaded concurrently with reading the response, so
    /// a server that answers early — a `413` to a large upload, say — is heard
    /// immediately rather than after the body finishes.
    ///
    /// # Cancel safety
    ///
    /// Dropping the returned future is the supported way to cancel an
    /// in-flight HTTP/3 request. Like HTTP/2, only that request's QUIC stream
    /// is reset; the shared connection stays usable for other in-flight and
    /// future requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is not ready or if an error occurs while
    /// processing the request.
    pub fn send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> {
        let sent = self.try_send_request(req);
        async move { sent.await.map_err(TrySendError::into_error) }
    }

    /// Sends a `Request` on the associated connection.
    ///
    /// Returns a future that if successful, yields the `Response`.
    ///
    /// # Errors
    ///
    /// If the request never reached the wire — the connection was already
    /// closed, or the peer had sent GOAWAY so no stream could be opened for
    /// it — the request is returned as part of the error, so it can be retried
    /// on another connection.
    pub fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, TrySendError<Request<B>>>> {
        let (cb, rx) = oneshot::channel();
        let sent = self.tx.send((req, cb));
        async move {
            match sent {
                Ok(()) => match rx.await {
                    Ok(result) => result,
                    // The connection task always answers, or hands the request
                    // back when it shuts down; only a panic in it gets here.
                    Err(_) => Err(TrySendError::new(
                        Error::canceled_with("connection task ended without a response"),
                        None,
                    )),
                },
                Err(mpsc::error::SendError((req, _cb))) => {
                    debug!("connection was not ready");
                    Err(TrySendError::new(
                        Error::canceled_with("connection was not ready"),
                        Some(req),
                    ))
                }
            }
        }
    }
}

impl<B> fmt::Debug for SendRequest<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRequest").finish()
    }
}

// ===== impl Connection =====

impl<Q, B, E> fmt::Debug for Connection<Q, B, E>
where
    Q: quic::Connection<B::Data>,
    B: Body,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<Q, B, E> Future for Connection<Q, B, E>
where
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Clone + Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Executor<Task> + Clone + Send + 'static,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll_task(cx)
    }
}

// ===== impl Builder =====

impl<Ex> Builder<Ex> {
    /// Creates a new connection builder.
    ///
    /// This starts with the default options. Each request runs as its own
    /// [`Task`] on `exec`.
    pub fn new(exec: Ex) -> Self {
        Self {
            exec,
            h3_builder: Config::default(),
        }
    }

    /// Set the maximum size of a received header field section.
    ///
    /// This is advertised to the peer in `SETTINGS`; see the
    /// [header size constraints] section of RFC 9114.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, max: u64) -> &mut Self {
        self.h3_builder.max_field_section_size = Some(max);
        self
    }

    /// Set whether to send "grease" frames and settings.
    ///
    /// See [RFC 9114 §7.2.8].
    ///
    /// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.send_grease = Some(enabled);
        self
    }

    /// Set whether the extended CONNECT protocol is enabled.
    pub fn enable_extended_connect(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.enable_extended_connect = Some(enabled);
        self
    }

    /// Set whether HTTP/3 datagrams are enabled.
    ///
    /// See [RFC 9297].
    ///
    /// [RFC 9297]: https://www.rfc-editor.org/rfc/rfc9297.html
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.enable_datagram = Some(enabled);
        self
    }

    /// Constructs a connection with the configured options and QUIC connection.
    ///
    /// Note, if [`Connection`] is not `await`-ed, [`SendRequest`] will
    /// do nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP/3 handshake fails.
    pub fn handshake<Q, B>(
        &self,
        quic: Q,
    ) -> impl Future<Output = Result<(SendRequest<B>, Connection<Q, B, Ex>), Error>>
    where
        Q: quic::Connection<B::Data> + Send + 'static,
        Q::BidiStream: Send + 'static,
        Q::SendStream: Send + 'static,
        Q::RecvStream: Send + 'static,
        Q::OpenStreams: Clone + Send + 'static,
        <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
        <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
        B: Body + Send + 'static,
        B::Data: Send + Sync + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
        Ex: Executor<Task> + Clone + Send + 'static,
    {
        let opts = self.h3_builder.clone();
        let exec = self.exec.clone();

        async move {
            trace!("client http3 handshake");
            let (tx, rx) = mpsc::unbounded_channel();
            let task = crate::http3::client::handshake(quic, rx, &opts, exec).await?;
            Ok((SendRequest { tx }, Connection { inner: task }))
        }
    }
}
