//! A [`hyper_util::rt::quic`] implementation backed by [quinn].
//!
//! This is dev-only: it exists so the HTTP/3 tests and examples run against a
//! real QUIC stack rather than a mock. It is also the worked example of what
//! implementing `rt::quic` actually costs — about three hundred lines of
//! mechanical forwarding, no protocol knowledge required. Whether a published
//! version belongs here behind a feature, or alongside `h3-quinn`, is an open
//! question.
//!
//! [quinn]: https://docs.rs/quinn

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_util::stream::{self, Stream, StreamExt};
use hyper_util::rt::quic;
use quinn::{AcceptBi, AcceptUni, OpenBi, OpenUni, VarInt};
use tokio_util::sync::ReusableBoxFuture;

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

// ===== error mapping =====

fn conn_error(err: quinn::ConnectionError) -> quic::ConnectionError {
    match err {
        // The peer closed the connection at the application layer. For HTTP/3
        // this carries the RFC 9114 error code, and `H3_NO_ERROR` here means a
        // clean shutdown — which is exactly why this variant has to survive the
        // trip rather than being flattened into an opaque error.
        quinn::ConnectionError::ApplicationClosed(close) => {
            quic::ConnectionError::ApplicationClosed {
                error_code: close.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => quic::ConnectionError::TimedOut,
        other => quic::ConnectionError::Other(Arc::new(other)),
    }
}

fn read_error(err: quinn::ReadError) -> quic::StreamError {
    match err {
        quinn::ReadError::Reset(code) => quic::StreamError::Reset {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(err) => quic::StreamError::Connection(conn_error(err)),
        other => quic::StreamError::Other(Box::new(other)),
    }
}

fn write_error(err: quinn::WriteError) -> quic::StreamError {
    match err {
        quinn::WriteError::Stopped(code) => quic::StreamError::Reset {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(err) => quic::StreamError::Connection(conn_error(err)),
        other => quic::StreamError::Other(Box::new(other)),
    }
}

fn stream_id(id: quinn::StreamId) -> quic::StreamId {
    let raw: u64 = id.into();
    quic::StreamId::new(raw).expect("quinn stream ids are QUIC varints")
}

// ===== connection =====

/// Bytes written per stream, keyed by stream id.
///
/// Test instrumentation only, for asserting on what went over the wire that
/// hyper's API never surfaces — frames the peer skips, like GREASE.
pub type SentBytes = Arc<Mutex<BTreeMap<u64, usize>>>;

/// A QUIC connection backed by quinn.
pub struct Connection {
    conn: quinn::Connection,
    sent: Option<SentBytes>,
    incoming_bi: BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output>,
    incoming_uni: BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output>,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl Connection {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn: conn.clone(),
            incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_bi().await, conn))
            })),
            incoming_uni: Box::pin(stream::unfold(conn, |conn| async {
                Some((conn.accept_uni().await, conn))
            })),
            opening_bi: None,
            opening_uni: None,
            sent: None,
        }
    }

    /// Record the bytes written on every bidirectional stream this side
    /// accepts — on a server, one entry per request.
    pub fn count_sent_bytes(mut self, sent: SentBytes) -> Self {
        self.sent = Some(sent);
        self
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_bidirectional_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::ConnectionError>> {
        let (send, recv) = match self.incoming_bi.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(pair))) => pair,
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(conn_error(err))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(quic::ConnectionError::Internal(
                    "quinn accept stream ended".to_owned(),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        let mut send = SendStream::new(send);
        send.sent = self.sent.clone();
        Poll::Ready(Ok(BidiStream {
            send,
            recv: RecvStream::new(recv),
        }))
    }

    fn poll_accept_recv_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionError>> {
        let recv = match self.incoming_uni.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(recv))) => recv,
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(conn_error(err))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(quic::ConnectionError::Internal(
                    "quinn accept stream ended".to_owned(),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RecvStream::new(recv)))
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = SendStream<B>;

    fn poll_open_bidirectional_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamError>> {
        let conn = self.conn.clone();
        poll_open_bi(&mut self.opening_bi, conn, cx)
    }

    fn poll_open_send_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamError>> {
        let conn = self.conn.clone();
        poll_open_uni(&mut self.opening_uni, conn, cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.conn
            .close(VarInt::from_u64(code).unwrap_or(VarInt::MAX), reason);
    }
}

/// A handle for opening streams on an existing connection.
pub struct OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        // The in-progress open futures are not shared; a fresh handle simply
        // starts its own.
        Self {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;
    type SendStream = SendStream<B>;

    fn poll_open_bidirectional_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamError>> {
        let conn = self.conn.clone();
        poll_open_bi(&mut self.opening_bi, conn, cx)
    }

    fn poll_open_send_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamError>> {
        let conn = self.conn.clone();
        poll_open_uni(&mut self.opening_uni, conn, cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.conn
            .close(VarInt::from_u64(code).unwrap_or(VarInt::MAX), reason);
    }
}

fn poll_open_bi<B: Buf>(
    slot: &mut Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    conn: quinn::Connection,
    cx: &mut Context<'_>,
) -> Poll<Result<BidiStream<B>, quic::StreamError>> {
    let opening = slot.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn, |conn| async {
            Some((conn.open_bi().await, conn))
        }))
    });
    let (send, recv) = match opening.poll_next_unpin(cx) {
        Poll::Ready(Some(Ok(pair))) => pair,
        Poll::Ready(Some(Err(err))) => {
            return Poll::Ready(Err(quic::StreamError::Connection(conn_error(err))));
        }
        Poll::Ready(None) => {
            return Poll::Ready(Err(quic::StreamError::Connection(
                quic::ConnectionError::Internal("quinn open stream ended".to_owned()),
            )));
        }
        Poll::Pending => return Poll::Pending,
    };
    Poll::Ready(Ok(BidiStream {
        send: SendStream::new(send),
        recv: RecvStream::new(recv),
    }))
}

fn poll_open_uni<B: Buf>(
    slot: &mut Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
    conn: quinn::Connection,
    cx: &mut Context<'_>,
) -> Poll<Result<SendStream<B>, quic::StreamError>> {
    let opening = slot.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn, |conn| async {
            Some((conn.open_uni().await, conn))
        }))
    });
    let send = match opening.poll_next_unpin(cx) {
        Poll::Ready(Some(Ok(send))) => send,
        Poll::Ready(Some(Err(err))) => {
            return Poll::Ready(Err(quic::StreamError::Connection(conn_error(err))));
        }
        Poll::Ready(None) => {
            return Poll::Ready(Err(quic::StreamError::Connection(
                quic::ConnectionError::Internal("quinn open stream ended".to_owned()),
            )));
        }
        Poll::Pending => return Poll::Pending,
    };
    Poll::Ready(Ok(SendStream::new(send)))
}

// ===== streams =====

/// A bidirectional QUIC stream.
pub struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamError>> {
        self.send.poll_ready(cx)
    }

    fn send_data(&mut self, data: quic::WriteBuf<B>) -> Result<(), quic::StreamError> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamError>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamError>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> quic::StreamId {
        self.recv.recv_id()
    }
}

/// The send half of a QUIC stream.
pub struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    /// Buffered by `send_data` and drained by `poll_ready`, which is the
    /// contract `hyper_util::rt::quic::SendStream` describes.
    writing: Option<quic::WriteBuf<B>>,
    sent: Option<SentBytes>,
}

impl<B: Buf> SendStream<B> {
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
            sent: None,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamError>> {
        if let Some(data) = &mut self.writing {
            while data.has_remaining() {
                let written = match Pin::new(&mut self.stream).poll_write(cx, data.chunk()) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(write_error(err))),
                    // The peer's flow-control window is full. Staying pending
                    // here is what propagates backpressure up into `Body`.
                    Poll::Pending => return Poll::Pending,
                };
                data.advance(written);
                if let Some(sent) = &self.sent {
                    let id: u64 = self.stream.id().into();
                    *sent.lock().unwrap().entry(id).or_default() += written;
                }
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data(&mut self, data: quic::WriteBuf<B>) -> Result<(), quic::StreamError> {
        if self.writing.is_some() {
            return Err(quic::StreamError::Connection(
                quic::ConnectionError::Internal(
                    "send_data called before the previous buffer was flushed".to_owned(),
                ),
            ));
        }
        self.writing = Some(data);
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamError>> {
        // Flush whatever `send_data` queued before signalling the FIN. quinn
        // finishes the stream at the current write offset, so finishing with
        // bytes still buffered here would truncate the stream and the peer
        // would never learn it was short.
        if self.writing.is_some() {
            match self.poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(match self.stream.finish() {
            Ok(()) => Ok(()),
            // Already finished or reset; either way there is nothing left to do.
            Err(_closed) => Ok(()),
        })
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
    }

    fn send_id(&self) -> quic::StreamId {
        stream_id(self.stream.id())
    }
}

type ReadChunk = (
    quinn::RecvStream,
    Result<Option<quinn::Chunk>, quinn::ReadError>,
);

/// The receive half of a QUIC stream.
pub struct RecvStream {
    stream: Option<quinn::RecvStream>,
    id: quinn::StreamId,
    reading: ReusableBoxFuture<'static, ReadChunk>,
    /// Set when `stop_sending` is called while a read owns the stream.
    pending_stop: Option<u64>,
}

impl RecvStream {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            id: stream.id(),
            stream: Some(stream),
            // Allocates lazily, on the first read.
            reading: ReusableBoxFuture::new(async { unreachable!() }),
            pending_stop: None,
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamError>> {
        if let Some(mut stream) = self.stream.take() {
            self.reading.set(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            });
        }

        let (stream, chunk) = match self.reading.poll(cx) {
            Poll::Ready(res) => res,
            Poll::Pending => return Poll::Pending,
        };
        self.stream = Some(stream);

        // A stop requested mid-read could not be applied then; apply it now
        // that the stream is back in hand.
        if let Some(code) = self.pending_stop.take() {
            self.stop_sending(code);
        }

        Poll::Ready(match chunk {
            // Handing back `Bytes` straight from quinn is what keeps the read
            // path copy-free all the way into `hyper_util::http3::Incoming`.
            Ok(chunk) => Ok(chunk.map(|c| c.bytes)),
            Err(err) => Err(read_error(err)),
        })
    }

    fn stop_sending(&mut self, error_code: u64) {
        match self.stream.as_mut() {
            Some(stream) => {
                let _ = stream.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::MAX));
            }
            // A read is in flight and owns the stream, so it cannot be stopped
            // right now. Remember the code for the next `poll_data`.
            //
            // If there is no next poll — the usual case, an abandoned body —
            // quinn's own `RecvStream::drop` still sends `STOP_SENDING`, just
            // with code 0 rather than the code asked for here. The peer stops
            // either way; only the code differs.
            None => self.pending_stop = Some(error_code),
        }
    }

    fn recv_id(&self) -> quic::StreamId {
        stream_id(self.id)
    }
}
