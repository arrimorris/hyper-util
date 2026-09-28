//! The HTTP/3 client connection driver.
//!
//! The shape mirrors hyper's HTTP/2 client. Requests arrive over a channel,
//! which is also what keeps the QUIC-backend type parameters out of the public
//! [`SendRequest`](crate::client::conn::http3::SendRequest): everything
//! generic stays inside [`ClientTask`].

use std::error::Error as StdError;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Buf;
use http::{Request, Response, Version};
use http_body::Body;
use hyper::rt::Executor;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace};

use super::body::ClientRecvBody;
use super::{
    Error, Incoming, MessageKind, Task, TaskGuard, content_length, glue,
    set_content_length_if_missing, strip_connection_headers,
};
use crate::rt::quic;

// ===== the request channel =====

/// Where a request's outcome is delivered. Carrying the request back on
/// failure is what lets a caller retry it elsewhere.
pub(crate) type Callback<B> = oneshot::Sender<Result<Response<Incoming>, TrySendError<Request<B>>>>;

/// A request on its way from a `SendRequest` to the connection task.
pub(crate) type Envelope<B> = (Request<B>, Callback<B>);

pub(crate) type ClientTx<B> = mpsc::UnboundedSender<Envelope<B>>;
type ClientRx<B> = mpsc::UnboundedReceiver<Envelope<B>>;

/// An error returned by
/// [`SendRequest::try_send_request`](crate::client::conn::http3::SendRequest::try_send_request).
///
/// When the request never reached the wire — the connection had already
/// closed, or the peer had sent GOAWAY so no stream could be opened for it —
/// the request is handed back, unspent, so the caller can send it elsewhere.
pub struct TrySendError<T> {
    error: Error,
    message: Option<T>,
}

impl<T> TrySendError<T> {
    pub(crate) fn new(error: Error, message: Option<T>) -> Self {
        TrySendError { error, message }
    }

    /// The error that occurred.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Consumes this to return the inner error.
    pub fn into_error(self) -> Error {
        self.error
    }

    /// The request, if it was never sent.
    pub fn message(&self) -> Option<&T> {
        self.message.as_ref()
    }

    /// Take the request back out, if it was never sent.
    pub fn take_message(&mut self) -> Option<T> {
        self.message.take()
    }
}

impl<T> fmt::Debug for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrySendError")
            .field("error", &self.error)
            .field("message", &self.message.as_ref().map(|_| ".."))
            .finish()
    }
}

impl<T> fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl<T> StdError for TrySendError<T> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.error)
    }
}

/// Settings for an HTTP/3 client connection.
#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    pub(crate) max_field_section_size: Option<u64>,
    pub(crate) send_grease: Option<bool>,
    pub(crate) enable_extended_connect: Option<bool>,
    pub(crate) enable_datagram: Option<bool>,
}

impl Config {
    fn h3_builder(&self) -> h3::client::Builder {
        let mut builder = h3::client::builder();
        if let Some(size) = self.max_field_section_size {
            builder.max_field_section_size(size);
        }
        if let Some(grease) = self.send_grease {
            builder.send_grease(grease);
        }
        if let Some(enabled) = self.enable_extended_connect {
            builder.enable_extended_connect(enabled);
        }
        if let Some(enabled) = self.enable_datagram {
            builder.enable_datagram(enabled);
        }
        builder
    }
}

type Opener<Q, B> = <glue::Conn<Q> as h3::quic::Connection<B>>::OpenStreams;

/// Complete the HTTP/3 handshake over a QUIC connection.
pub(crate) async fn handshake<Q, B, E>(
    quic: Q,
    req_rx: ClientRx<B>,
    config: &Config,
    exec: E,
) -> Result<ClientTask<Q, B, E>, Error>
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
    // Taken before `quic` is handed to h3, which is the last chance to hold a
    // handle onto the connection.
    let closer = quic.opener();

    let (h3_conn, send_request) = config
        .h3_builder()
        .build(glue::Conn(quic))
        .await
        .map_err(|err| Error::from_connection(err).unwrap_or_else(Error::canceled))?;

    let (tasks_tx, tasks_rx) = mpsc::unbounded_channel();

    Ok(ClientTask {
        h3: h3_conn,
        send_request,
        req_rx,
        exec,
        closing: false,
        inflight: 0,
        closer,
        tasks_tx,
        tasks_rx,
    })
}

/// The future that drives an HTTP/3 client connection.
pub(crate) struct ClientTask<Q, B, E>
where
    Q: quic::Connection<B::Data>,
    B: Body,
{
    h3: h3::client::Connection<glue::Conn<Q>, B::Data>,
    send_request: h3::client::SendRequest<Opener<Q, B::Data>, B::Data>,
    req_rx: ClientRx<B>,
    exec: E,
    closing: bool,
    /// Requests that have been dispatched but are not finished with the
    /// connection yet. A request stays counted until its exchange, its upload
    /// and its response body have all been dropped.
    inflight: usize,
    /// Closes the QUIC connection when this task goes away.
    ///
    /// h3's *server* `Connection` closes with `H3_NO_ERROR` in its own `Drop`;
    /// its client counterpart does not. Dropping the last `SendRequest` only
    /// records the code and wakes the driver, and `poll_close` never reads it
    /// back — so on a clean exit nothing emits it and the transport closes
    /// implicitly with whatever code it picks. quinn picks 0, which the peer
    /// reads as a real error rather than a hang-up. See RFC 9114 §5.2.
    closer: Q::OpenStreams,
    tasks_tx: mpsc::UnboundedSender<()>,
    tasks_rx: mpsc::UnboundedReceiver<()>,
}

impl<Q, B, E> ClientTask<Q, B, E>
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
    pub(crate) fn poll_task(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        loop {
            // Pick up any requests handed over by a `SendRequest`.
            if !self.closing {
                match self.req_rx.poll_recv(cx) {
                    Poll::Ready(Some((req, cb))) => {
                        self.dispatch(req, cb);
                        continue;
                    }
                    Poll::Ready(None) => {
                        trace!("http3 client dropped all senders");
                        self.closing = true;
                        continue;
                    }
                    Poll::Pending => {}
                }
            }

            // Reap finished requests. Dropping every `SendRequest` means "no
            // more requests", not "abandon the responses I am still reading",
            // so the connection only ends once nothing is in flight.
            while let Poll::Ready(Some(())) = self.tasks_rx.poll_recv(cx) {
                self.inflight -= 1;
            }
            if self.closing && self.inflight == 0 {
                trace!("http3 client connection idle, closing");
                return Poll::Ready(Ok(()));
            }

            // Drive the connection itself. This resolves only when the QUIC
            // connection ends — including when it has simply been quiet for a
            // long time and the transport's idle timeout finally fires.
            let err = ready!(self.h3.poll_close(cx));
            return Poll::Ready(match Error::from_connection(err) {
                Some(err) => Err(err),
                None => Ok(()),
            });
        }
    }

    fn dispatch(&mut self, req: Request<B>, cb: Callback<B>) {
        let send_request = self.send_request.clone();
        let exec = self.exec.clone();

        self.inflight += 1;
        let guard = Arc::new(TaskGuard::new(self.tasks_tx.clone()));

        self.exec.execute(Task::new(async move {
            exchange(send_request, req, cb, exec, guard).await;
        }));
    }
}

impl<Q, B, E> Drop for ClientTask<Q, B, E>
where
    Q: quic::Connection<B::Data>,
    B: Body,
{
    fn drop(&mut self) {
        // Requests still queued never reached the wire. Hand each one back
        // rather than letting it vanish with the channel, so a caller using
        // `try_send_request` can send it elsewhere.
        self.req_rx.close();
        while let Ok((req, cb)) = self.req_rx.try_recv() {
            let _ = cb.send(Err(TrySendError::new(
                Error::canceled_with("connection closed before the request was sent"),
                Some(req),
            )));
        }

        // Mirrors `h3::server::Connection`'s own `Drop`. Doing it here rather
        // than on the way out of `poll_task` also covers the caller simply
        // dropping the connection future. A second close is a no-op, so the
        // error paths that h3 has already closed are unaffected.
        quic::OpenStreams::close(&mut self.closer, h3::error::Code::H3_NO_ERROR.value(), b"");
    }
}

async fn exchange<O, B, E>(
    mut send_request: h3::client::SendRequest<O, B::Data>,
    req: Request<B>,
    mut cb: Callback<B>,
    exec: E,
    guard: Arc<TaskGuard>,
) where
    O: h3::quic::OpenStreams<B::Data> + Clone + Send + 'static,
    O::BidiStream: h3::quic::BidiStream<B::Data> + Send + 'static,
    <O::BidiStream as h3::quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <O::BidiStream as h3::quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Buf + Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Executor<Task> + Clone + Send + 'static,
{
    let (mut parts, body) = req.into_parts();

    // Everything `send_request` below can fail on — the peer having sent
    // GOAWAY, opening the QUIC stream, encoding the header block — happens
    // before a single byte of this request reaches the wire. So unlike
    // HTTP/2, where the head is on a shared connection by the time anything
    // can go wrong, HTTP/3 can always hand the request back for the caller to
    // retry elsewhere. That is what `TrySendError::take_message` is for, and
    // it is what lets a pool survive the peer going away mid-flight instead
    // of failing the request outright.
    //
    // Taken before the rewrites below so what comes back is the caller's own
    // request, not hyper's HTTP/3 rendering of it — the retry may well go out
    // over a different protocol.
    let retry = parts.clone();

    strip_connection_headers(&mut parts.headers, MessageKind::Request);
    if let Some(len) = body.size_hint().exact() {
        if len != 0 || method_has_defined_payload_semantics(&parts.method) {
            set_content_length_if_missing(&mut parts.headers, len);
        }
    }
    parts.version = Version::HTTP_3;

    let stream = match send_request
        .send_request(Request::from_parts(parts, ()))
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            let _ = cb.send(Err(TrySendError::new(
                Error::stream(err),
                Some(Request::from_parts(retry, body)),
            )));
            return;
        }
    };

    // Split so the request body can keep uploading while the response is
    // read. A server that rejects a large upload early — say a `413` — is
    // heard immediately instead of after the whole body has gone out.
    let (mut send, mut recv) = stream.split();

    // Lets this task tell the upload to stop if the caller gives up. Sending
    // means "cancelled"; the sender simply being dropped means this task
    // finished normally and the upload should carry on.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

    let upload_guard = Arc::clone(&guard);
    exec.execute(Task::new(async move {
        let _guard = upload_guard;
        let outcome = {
            let mut pump = std::pin::pin!(send_body(&mut send, body));
            let mut cancel = cancel_rx;
            let mut watching = true;
            poll_fn(|cx| {
                if watching {
                    match Pin::new(&mut cancel).poll(cx) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Upload::Cancelled),
                        // The request task is done with us; keep uploading.
                        Poll::Ready(Err(_)) => watching = false,
                        Poll::Pending => {}
                    }
                }
                pump.as_mut().poll(cx).map(Upload::Finished)
            })
            .await
        };

        match outcome {
            Upload::Cancelled => send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED),
            Upload::Finished(Err(err)) => {
                debug!("http3 error sending request body: {}", err);
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            }
            Upload::Finished(Ok(())) => {
                if let Err(err) = send.finish().await {
                    debug!("http3 error finishing request: {}", err);
                }
            }
        }
    }));

    // Wait for the response head, but give up the moment the caller drops the
    // future it is waiting on. Dropping an in-flight request is how hyper
    // cancels one, and on HTTP/3 — as on HTTP/2 — that must reset this single
    // stream rather than leaving the peer streaming a response into the void.
    let received = {
        let mut response = std::pin::pin!(recv.recv_response());
        poll_fn(|cx| {
            // Cancellation is checked first on purpose. If the caller drops
            // the future in the same wake-up that the response head lands,
            // the head is discarded rather than delivered to nobody — the
            // caller said it no longer wants this. Do not "fix" this by
            // preferring the response.
            if cb.poll_closed(cx).is_ready() {
                return Poll::Ready(None);
            }
            response.as_mut().poll(cx).map(Some)
        })
        .await
    };

    let head = match received {
        Some(Ok(head)) => head,
        Some(Err(err)) => {
            let _ = cb.send(Err(TrySendError::new(Error::stream(err), None)));
            return;
        }
        None => {
            trace!("http3 request canceled by caller");
            let _ = cancel_tx.send(());
            recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return;
        }
    };

    let content_length = content_length(head.headers());
    let mut res =
        head.map(|()| Incoming::new(Box::new(ClientRecvBody::new(recv, guard)), content_length));
    *res.version_mut() = Version::HTTP_3;

    let _ = cb.send(Ok(res));
}

/// How the request-body upload ended.
enum Upload {
    /// The caller dropped the request before the response arrived.
    Cancelled,
    Finished(Result<(), Error>),
}

/// Pump a request body onto a request stream.
///
/// `send_data` awaits the QUIC stream's flow-control window before the next
/// frame is polled off the body, so a server that stops reading stops the
/// upload being produced rather than having it pile up in memory.
async fn send_body<S, B, Bd>(
    send: &mut h3::client::RequestStream<S, B>,
    body: Bd,
) -> Result<(), Error>
where
    S: h3::quic::SendStream<B>,
    B: Buf,
    Bd: Body<Data = B>,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let mut body = std::pin::pin!(body);

    loop {
        let frame = match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            Some(Ok(frame)) => frame,
            Some(Err(err)) => return Err(Error::body(err)),
            None => return Ok(()),
        };

        match frame.into_data() {
            Ok(data) => {
                if data.has_remaining() {
                    send.send_data(data).await.map_err(Error::stream)?;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers).await.map_err(Error::stream)?;
                    return Ok(());
                }
                // Frame kinds HTTP/3 has no way to send are skipped.
            }
        }
    }
}

/// Methods whose requests carry a body with defined meaning, and so get a
/// `content-length: 0` when their body is known to be empty.
fn method_has_defined_payload_semantics(method: &http::Method) -> bool {
    !matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::DELETE | http::Method::CONNECT
    )
}
