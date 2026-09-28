//! The HTTP/3 server connection driver.
//!
//! The shape mirrors hyper's HTTP/2 server: one future drives the connection,
//! accepting QUIC streams and handing each to the executor as its own task, so
//! a slow request body never blocks the ones next to it.

use std::error::Error as StdError;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Buf;
use http::{Request, Response, Version};
use http_body::Body;
use hyper::rt::Executor;
use hyper::service::Service;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::body::ServerRecvBody;
use super::{
    Error, Incoming, MessageKind, Task, TaskGuard, content_length, glue,
    set_content_length_if_missing, strip_connection_headers,
};
use crate::rt::quic;

/// Settings for an HTTP/3 server connection.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) max_field_section_size: Option<u64>,
    pub(crate) send_grease: Option<bool>,
    pub(crate) enable_extended_connect: Option<bool>,
    pub(crate) enable_datagram: Option<bool>,
    pub(crate) date_header: bool,
    pub(crate) max_late_requests: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_field_section_size: None,
            send_grease: None,
            enable_extended_connect: None,
            enable_datagram: None,
            date_header: true,
            max_late_requests: 0,
        }
    }
}

impl Config {
    fn h3_builder(&self) -> h3::server::Builder {
        let mut builder = h3::server::builder();
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

type H3Conn<Q, B> = h3::server::Connection<glue::Conn<Q>, B>;

/// h3's handshake (opening the control stream and sending SETTINGS) is only
/// available as an `async fn`, and it is emphatically not cancel-safe —
/// restarting it would open a second control stream. So it is driven as a
/// single boxed future, once per connection.
type Handshaking<Q, B> =
    Pin<Box<dyn Future<Output = Result<H3Conn<Q, B>, h3::error::ConnectionError>> + Send>>;

/// Likewise for sending GOAWAY. The connection is moved into the future and
/// handed back when it resolves, so the write is never cancelled part-way and
/// the frame cannot be left half-queued.
type GoingAway<Q, B> = Pin<
    Box<dyn Future<Output = (Box<H3Conn<Q, B>>, Result<(), h3::error::ConnectionError>)> + Send>,
>;

enum State<Q, B>
where
    Q: quic::Connection<B>,
    B: Buf,
{
    Handshaking(Handshaking<Q, B>),
    /// Boxed so a large `h3::server::Connection` does not inflate every
    /// variant of this enum.
    Accepting(Box<H3Conn<Q, B>>),
    GoingAway(GoingAway<Q, B>),
    Done,
}

/// The future that drives an HTTP/3 server connection.
pub(crate) struct Server<Q, S, B, E>
where
    Q: quic::Connection<B>,
    B: Buf,
{
    state: State<Q, B>,
    service: S,
    exec: E,
    config: Config,
    /// Set when the user asks for a graceful shutdown.
    goaway_requested: bool,
    /// Set once GOAWAY has actually been written.
    goaway_sent: bool,
    /// Requests accepted but not yet finished with the connection.
    ///
    /// A request stays counted until its task has ended *and* its body has
    /// been dropped, which are not the same moment: a service may answer
    /// early and go on reading the upload.
    ///
    /// h3 keeps this bookkeeping to itself, so the driver keeps its own. Counting
    /// rather than watching for the last sender to drop is what lets requests
    /// accepted *after* GOAWAY — the `max_late_requests` window — still hold
    /// the connection open.
    inflight: usize,
    tasks_tx: mpsc::UnboundedSender<()>,
    tasks_rx: mpsc::UnboundedReceiver<()>,
}

impl<Q, S, B, E> Server<Q, S, B, E>
where
    Q: quic::Connection<B> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
{
    pub(crate) fn new(quic: Q, service: S, config: Config, exec: E) -> Self {
        let builder = config.h3_builder();
        let handshake = Box::pin(async move { builder.build(glue::Conn(quic)).await });
        let (tasks_tx, tasks_rx) = mpsc::unbounded_channel();

        Server {
            state: State::Handshaking(handshake),
            service,
            exec,
            config,
            goaway_requested: false,
            goaway_sent: false,
            inflight: 0,
            tasks_tx,
            tasks_rx,
        }
    }

    /// Start a graceful shutdown: send GOAWAY, then finish answering the
    /// requests that were already accepted before resolving.
    pub(crate) fn graceful_shutdown(&mut self) {
        self.goaway_requested = true;
    }
}

impl<Q, S, B, E, Bd> Server<Q, S, B, E>
where
    Q: quic::Connection<B> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
    S: Service<Request<Incoming>, Response = Response<Bd>> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
    Bd: Body<Data = B> + Send + 'static,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Executor<Task>,
{
    pub(crate) fn poll_server(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        loop {
            // Drive the states that own a future first. Each arm either
            // advances `self.state` and loops, or returns.
            match &mut self.state {
                State::Handshaking(handshake) => {
                    let result = ready!(handshake.as_mut().poll(cx));
                    match result {
                        Ok(conn) => {
                            trace!("http3 handshake complete");
                            self.state = State::Accepting(Box::new(conn));
                        }
                        Err(err) => {
                            self.state = State::Done;
                            return Poll::Ready(finish(err));
                        }
                    }
                    continue;
                }
                State::GoingAway(fut) => {
                    let (conn, result) = ready!(fut.as_mut().poll(cx));
                    self.goaway_sent = true;
                    if let Err(err) = result {
                        self.state = State::Done;
                        return Poll::Ready(finish(err));
                    }
                    trace!("http3 sent GOAWAY");
                    self.state = State::Accepting(conn);
                    continue;
                }
                State::Done => return Poll::Ready(Ok(())),
                State::Accepting(_) => {}
            }

            if self.goaway_requested && !self.goaway_sent {
                let State::Accepting(mut conn) = std::mem::replace(&mut self.state, State::Done)
                else {
                    unreachable!("state was just matched as Accepting");
                };
                let max_late = self.config.max_late_requests;
                self.state = State::GoingAway(Box::pin(async move {
                    let result = conn.shutdown(max_late).await;
                    (conn, result)
                }));
                continue;
            }

            match self.poll_accept(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    if !self.goaway_sent {
                        // Answer the peer's GOAWAY with our own before going.
                        self.goaway_requested = true;
                        continue;
                    }
                    // No more requests are coming, but that is not the same as
                    // being finished: fall through to the drain below so the
                    // ones already accepted still get to answer. h3 decides
                    // "no more requests" from its own bookkeeping, which is
                    // not ours — it stops tracking a request when both
                    // halves of its stream drop, while this keeps counting
                    // until the task around them is gone, and it never learns
                    // about a request whose head failed to parse. Ending here
                    // would cut those short.
                }
                Poll::Ready(Err(err)) => {
                    self.state = State::Done;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {}
            }

            // Reap finished requests.
            while let Poll::Ready(Some(())) = self.tasks_rx.poll_recv(cx) {
                self.inflight -= 1;
            }

            // GOAWAY is out; the connection is finished once every request it
            // accepted — including any inside the `max_late_requests` window —
            // has been answered.
            if self.goaway_sent && self.inflight == 0 {
                trace!("http3 graceful shutdown complete");
                self.state = State::Done;
                return Poll::Ready(Ok(()));
            }

            return Poll::Pending;
        }
    }

    /// Accept at most one request stream.
    ///
    /// `Ok(true)` means a request was dispatched and the caller should loop
    /// again; `Ok(false)` means the connection has no more requests coming.
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        let State::Accepting(conn) = &mut self.state else {
            unreachable!("poll_accept called outside of Accepting");
        };

        let stream = match ready!(conn.poll_accept_request_stream(cx)) {
            Ok(Some(stream)) => stream,
            Ok(None) => return Poll::Ready(Ok(false)),
            Err(err) => return Poll::Ready(finish(err).map(|()| false)),
        };

        let resolver = conn.create_resolver(h3::frame::FrameStream::new(
            h3::stream::BufRecvStream::new(stream),
        ));
        suppress_further_grease(conn);

        let service = self.service.clone();
        let date_header = self.config.date_header;

        self.inflight += 1;
        // Shared with the request body, so a service that answers early and
        // goes on reading the upload still holds the connection open. Dropping
        // the last clone is what tells the connection future that a graceful
        // shutdown may complete.
        let guard = Arc::new(TaskGuard::new(self.tasks_tx.clone()));

        self.exec.execute(Task::new(serve_stream(
            resolver,
            service,
            date_header,
            guard,
        )));

        Poll::Ready(Ok(true))
    }
}

/// Send the GREASE frame on the first request of a connection only.
///
/// h3 seeds this flag from its builder's `send_grease`, copies it into every
/// `RequestResolver`, and emits the frame from `RequestStream::finish`. The
/// "once per connection" part comes from `Connection::accept` clearing the
/// connection-level flag immediately after it builds the first resolver.
/// hyper-util drives the poll-based accept path instead of `accept`, so it has to
/// clear the flag too; otherwise every response would carry a GREASE frame and
/// pay for an extra frame write.
///
/// This is the one place hyper-util touches a *field* of h3's `Connection` rather
/// than calling a method, and h3 marks that field as a deliberate, temporary
/// break in its own encapsulation. Written against h3 0.0.8.
///
/// Fixed upstream in h3 #362 (merged 2026-09-19, after 0.0.8): the clear
/// moved out of `Connection::accept` and into `create_resolver_internal`,
/// which every caller goes through, so the public `create_resolver` is
/// correct on its own. Delete this function on the first h3 release that
/// contains that change. Nothing at the call site needs to change —
/// `create_resolver` now takes `&mut self`, and this already calls it
/// through one.
///
/// `grease_is_sent_once_per_connection` in `tests/http3.rs` is the gate:
/// it fails if this is deleted on an h3 that still needs it, and passes
/// without it on one that has #362. Leaving this in after the bump is
/// harmless, just redundant.
fn suppress_further_grease<C, B>(conn: &mut h3::server::Connection<C, B>)
where
    C: h3::quic::Connection<B>,
    B: Buf,
{
    conn.inner.send_grease_frame = false;
}

/// A connection that ended with `H3_NO_ERROR` ended cleanly.
fn finish(err: h3::error::ConnectionError) -> Result<(), Error> {
    match Error::from_connection(err) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

async fn serve_stream<C, B, S, Bd>(
    resolver: h3::server::RequestResolver<C, B>,
    service: S,
    date_header: bool,
    guard: Arc<TaskGuard>,
) where
    C: h3::quic::Connection<B>,
    C::BidiStream: h3::quic::BidiStream<B>,
    <C::BidiStream as h3::quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
    S: Service<Request<Incoming>, Response = Response<Bd>>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    Bd: Body<Data = B>,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let (head, stream) = match resolver.resolve_request().await {
        Ok(req) => req,
        Err(err) => {
            debug!("http3 error reading request head: {}", err);
            return;
        }
    };

    // Split so the request body can be read while the response is written.
    // This is why `rt::quic::BidiStream` exists.
    let (mut send, recv) = stream.split();

    let content_length = content_length(head.headers());
    // The body carries a clone of the guard: the response finishing does not
    // mean the exchange has. A service may answer early and keep draining the
    // upload in the background, and the request stream is genuinely still open
    // — h3 counts it too, because both halves hold its `RequestEnd`.
    let mut req = head.map(|()| {
        Incoming::new(
            Box::new(ServerRecvBody::new(recv, Arc::clone(&guard))),
            content_length,
        )
    });
    *req.version_mut() = Version::HTTP_3;

    let res = match service.call(req).await {
        Ok(res) => res,
        Err(err) => {
            warn!("http3 service errored: {}", Error::service(err));
            send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            return;
        }
    };

    let (mut head, body) = res.into_parts();
    strip_connection_headers(&mut head.headers, MessageKind::Response);

    // Same as the HTTP/2 server: a body that knows its exact size gets a
    // `content-length` if the service did not set one.
    if !body.is_end_stream() {
        if let Some(len) = body.size_hint().exact() {
            set_content_length_if_missing(&mut head.headers, len);
        }
    }
    if date_header && !head.headers.contains_key(http::header::DATE) {
        if let Some(date) = cached_date() {
            head.headers.insert(http::header::DATE, date);
        }
    }

    if let Err(err) = send.send_response(Response::from_parts(head, ())).await {
        debug!("http3 error sending response: {}", err);
        return;
    }

    if let Err(err) = send_body(&mut send, body).await {
        debug!("http3 error sending response body: {}", err);
        send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        return;
    }

    if let Err(err) = send.finish().await {
        debug!("http3 error finishing response: {}", err);
    }
}

/// Pump a response body onto a request stream.
///
/// `send_data` awaits the QUIC stream's flow-control window before the next
/// frame is polled off the body, so a peer that stops reading stops the body
/// being produced rather than having it pile up in memory.
async fn send_body<S, B, Bd>(
    send: &mut h3::server::RequestStream<S, B>,
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

/// The current time as a `date` header value, formatted at most once a second
/// per thread.
fn cached_date() -> Option<http::HeaderValue> {
    use std::cell::RefCell;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct Cached {
        value: Option<http::HeaderValue>,
        next_update: SystemTime,
    }

    thread_local!(static CACHED: RefCell<Cached> = const {
        RefCell::new(Cached { value: None, next_update: UNIX_EPOCH })
    });

    CACHED.with(|cached| {
        let mut cached = cached.borrow_mut();
        let now = SystemTime::now();
        if now >= cached.next_update {
            cached.value = http::HeaderValue::from_str(&httpdate::fmt_http_date(now)).ok();
            let into_second = now
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            cached.next_update =
                now + Duration::from_secs(1) - Duration::from_nanos(u64::from(into_second));
        }
        cached.value.clone()
    })
}
