// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The **read half** of a request stream.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Body, Frame};

use super::StreamRef;
use crate::{
    h3::{
        client::{
            app::{Http3ClientApp, ResponseHead, ResponseHeadState},
            error::RequestError,
        },
        common::{H3Error, ReadState, read::poll_read_frame},
    },
    quic::connection::{QuicScionConn, WeakConnectionHandle},
};

/// A future resolving to the response of a request issued via `initiate_request`.
///
/// It resolves once the response head has arrived, yielding an `http::Response`
/// whose body is the streaming [`H3ResponseBody`]. It owns the stream's read-side
/// guard: dropped before the head arrives it stops the read side; on success the
/// guard is handed to the response body, which continues to own it.
pub struct ResponseFut {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    /// The read-side guard, taken when the head arrives and moved into the
    /// response body. `None` once the future has resolved.
    read_guard: Option<ReadGuard>,
}

impl ResponseFut {
    pub(crate) fn new(read_guard: ReadGuard) -> Self {
        Self {
            handle: read_guard.handle(),
            stream_id: read_guard.stream_id(),
            read_guard: Some(read_guard),
        }
    }
}

impl Future for ResponseFut {
    type Output = Result<http::Response<H3ResponseBody>, RequestError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match poll_head(&this.handle, this.stream_id, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(head)) => {
                let guard = this
                    .read_guard
                    .take()
                    .expect("ResponseFut polled after completion");
                Poll::Ready(Ok(head_into_response(head, H3ResponseBody::new(guard))))
            }
            Poll::Ready(Err(err)) => {
                // The read side is already gone (reset or connection close); mark
                // the guard done so its drop does not signal STOP_SENDING on a
                // dead stream.
                if let Some(guard) = this.read_guard.as_mut() {
                    guard.mark_done();
                }
                Poll::Ready(Err(err))
            }
        }
    }
}

/// Assembles an `http::Response` from a routed head and the streaming body.
fn head_into_response(head: ResponseHead, body: H3ResponseBody) -> http::Response<H3ResponseBody> {
    let mut response = http::Response::builder()
        .status(head.status)
        .body(body)
        .expect("status is valid");
    *response.headers_mut() = head.headers;
    response
}

/// The streaming body of an HTTP/3 response.
///
/// The body owns the stream's read-side guard: dropping it before end-of-stream
/// signals `STOP_SENDING` (cancelling the read side); dropping it after a clean
/// end is a no-op. Either way the shared per-stream bookkeeping is released once
/// the last reference (read or write half) drops.
pub struct H3ResponseBody {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    /// Read-side lifetime guard; its `done` flag suppresses `STOP_SENDING` once
    /// the body has finished cleanly, and its drop tears the read side down.
    read_guard: ReadGuard,
}

impl H3ResponseBody {
    pub(crate) fn new(read_guard: ReadGuard) -> Self {
        Self {
            handle: read_guard.handle(),
            stream_id: read_guard.stream_id(),
            read_guard,
        }
    }

    /// Returns a future that resolves to the next frame of the response body, or
    /// `None` if the body has finished (EOF, trailers, or an error already observed).
    pub async fn next_frame(&mut self) -> Option<Result<Frame<Bytes>, H3Error>> {
        futures::future::poll_fn(|cx| poll_read_frame(&self.handle, self.stream_id, cx)).await
    }

    /// Copies the entire response body into `buffer`, returning the collected data and any trailing
    /// headers.
    ///
    /// `max_size`, if set, caps the total body size accepted; a body exceeding it is rejected
    /// rather than partially copied.
    ///
    /// Returns Ok((written, trailers)) if the body was successfully collected, where `written` is
    /// the number of bytes written to the buffer and `trailers` is an optional `HeaderMap`
    /// containing any trailing headers.
    ///
    /// Returns [`CollectError::BufferTooSmall`] if `buffer` runs out of spare capacity,
    /// [`CollectError::TooLarge`] if the body exceeds `max_size`, or [`CollectError::H3`] if the
    /// underlying connection encounters an error.
    pub async fn collect_to_buf(
        mut self,
        buffer: &mut impl BufMut,
        max_size: Option<usize>,
    ) -> Result<(usize, Option<HeaderMap>), CollectError> {
        let mut written = 0;

        while let Some(frame) = self.next_frame().await {
            let frame = frame?;

            if frame.is_data() {
                let chunk = frame.into_data().expect("frame is data");
                if chunk.len() > buffer.remaining_mut() {
                    return Err(CollectError::BufferTooSmall);
                }

                if let Some(max) = max_size
                    && written + chunk.len() > max
                {
                    return Err(CollectError::TooLarge);
                }

                buffer.put_slice(&chunk);
                written += chunk.len();
            } else if frame.is_trailers() {
                let trailers = frame.into_trailers().expect("frame is trailers");
                // Got trailers, well-formed response body is complete. Return the collected data
                // and the trailers.
                return Ok((written, Some(trailers)));
            } else {
                // There are no other frame types as of now, but if there are in the future, we
                // should handle them appropriately.
                debug_assert!(false, "Unexpected frame type in response body: {:?}", frame);
            }
        }

        Ok((written, None))
    }

    /// Collects the entire response body into a `BytesMut` buffer, returning the collected data and
    /// any trailing headers.
    ///
    /// Returns Ok((data, trailers)) if the body was successfully collected, where `data` is a
    /// `BytesMut` buffer containing the collected data and `trailers` is an optional `HeaderMap`
    /// containing any trailing headers.
    ///
    /// Returns an error if the body exceeds the given `max_size` or the underlying connection
    /// encounters an error.
    pub async fn bytes(
        self,
        max_size: Option<usize>,
    ) -> Result<(BytesMut, Option<HeaderMap>), CollectError> {
        let mut buffer = BytesMut::new();
        let (_written, trailers) = self.collect_to_buf(&mut buffer, max_size).await?;
        Ok((buffer, trailers))
    }

    /// Collects the entire response body into a `String`, returning the collected data and any
    /// trailing headers.
    ///
    /// Returns Ok((data, trailers)) if the body was successfully collected, where `data` is a
    /// `String` containing the collected data and `trailers` is an optional `HeaderMap` containing
    /// any trailing headers.
    ///
    /// Returns an error if the body exceeds the given `max_size`, the underlying connection
    /// encounters an error, or if the collected data is not valid UTF-8.
    pub async fn text(
        self,
        max_size: Option<usize>,
    ) -> Result<(String, Option<HeaderMap>), CollectToStringError> {
        let (bytes, trailers) = match self.bytes(max_size).await {
            Ok(result) => result,
            Err(e) => {
                match e {
                    CollectError::H3(h3_err) => return Err(CollectToStringError::H3(h3_err)),
                    CollectError::TooLarge => return Err(CollectToStringError::TooLarge),
                    CollectError::BufferTooSmall => {
                        unreachable!(
                            "BytesMut grows automatically, cannot be BufferTooSmall in collect_to_bytes"
                        )
                    }
                }
            }
        };
        let string = String::from_utf8(bytes.into())?;

        Ok((string, trailers))
    }
}

/// An error that can occur while collecting the response body into a buffer.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// An error that occurred while reading the response body.
    #[error(transparent)]
    H3(#[from] H3Error),
    /// The provided buffer was too small to hold the response body.
    #[error("the provided buffer was too small to hold the response body")]
    BufferTooSmall,
    /// The response body exceeded the maximum size specified.
    #[error("response body exceeded maximum size")]
    TooLarge,
}

/// An error that can occur while collecting the response body into a string.
#[derive(Debug, thiserror::Error)]
pub enum CollectToStringError {
    /// An error that occurred while reading the response body.
    #[error(transparent)]
    H3(#[from] H3Error),
    /// The response body exceeded the maximum size specified.
    #[error("response body exceeded maximum size")]
    TooLarge,
    /// The response body did not contain valid UTF-8.
    #[error("response body did not contain valid UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl Body for H3ResponseBody {
    type Data = Bytes;
    type Error = H3Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.read_guard.is_done() {
            return Poll::Ready(None);
        }
        let res = poll_read_frame(&this.handle, this.stream_id, cx);
        if let Poll::Ready(ready) = &res {
            match ready {
                // EOF, an error, or a trailing header section all terminate the
                // body: the stream is finished on the read side, so suppress the
                // STOP_SENDING-on-drop.
                None => this.read_guard.mark_done(),
                Some(Err(_)) => this.read_guard.mark_done(),
                Some(Ok(frame)) if frame.is_trailers() => this.read_guard.mark_done(),
                Some(Ok(_)) => {}
            }
        }
        res
    }
}

/// The read-side lifetime guard for a client stream. While held it keeps the
/// shared [`StreamRef`] alive; dropped before the read side has finished cleanly
/// (EOF, trailers, or an error already observed) it signals `STOP_SENDING`.
pub(crate) struct ReadGuard {
    stream_ref: Arc<StreamRef>,
    done: bool,
}

impl ReadGuard {
    pub(crate) fn new(stream_ref: Arc<StreamRef>) -> Self {
        Self {
            stream_ref,
            done: false,
        }
    }

    /// A weak handle to the owning connection.
    pub(crate) fn handle(&self) -> WeakConnectionHandle<Http3ClientApp> {
        self.stream_ref.handle()
    }

    /// The stream this guard governs.
    pub(crate) fn stream_id(&self) -> u64 {
        self.stream_ref.stream_id()
    }

    /// Whether the read side has reached a terminal state.
    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Marks the read side finished cleanly, suppressing `STOP_SENDING` on drop.
    pub(crate) fn mark_done(&mut self) {
        self.done = true;
    }
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        if !self.done {
            shutdown_read(&self.stream_ref.handle(), self.stream_ref.stream_id());
        }
    }
}

/// Shuts down the *read* side of `stream_id`: discards any unread body and, if
/// the read side has not already finished, signals `STOP_SENDING`. Touches only
/// the QUIC stream, not the per-stream bookkeeping maps (those are released by
/// [`StreamRef`] once the last reference drops).
fn shutdown_read(handle: &WeakConnectionHandle<Http3ClientApp>, stream_id: u64) {
    let Some(handle) = handle.upgrade() else {
        return;
    };
    let mut guard = handle.lock_recovering();
    let _ = guard
        .inner
        .stream_shutdown(stream_id, squiche::Shutdown::Read, 0);
    drop(guard);
    handle.notify();
}

/// Polls the response-head slot for `stream_id`, registering a waker when the
/// head has not yet arrived. Drives the request [`ResponseFut`]; it performs no
/// stream teardown of its own (the caller's guard owns the read side).
pub(crate) fn poll_head(
    handle: &WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    cx: &mut Context<'_>,
) -> Poll<Result<ResponseHead, RequestError>> {
    let Some(handle) = handle.upgrade() else {
        return Poll::Ready(Err(RequestError::ConnectionClosed));
    };
    let mut guard = handle.lock();
    let QuicScionConn { app, .. } = &mut *guard;
    let Http3ClientApp {
        response_heads,
        streams,
        locally_closed,
        ..
    } = app;
    let Some(slot) = response_heads.get_mut(&stream_id) else {
        return Poll::Ready(Err(RequestError::ConnectionClosed));
    };

    match slot.state {
        ResponseHeadState::Arrived(_) => {
            let ResponseHeadState::Arrived(head) =
                std::mem::replace(&mut slot.state, ResponseHeadState::Done)
            else {
                unreachable!("just matched Arrived")
            };
            Poll::Ready(Ok(head))
        }
        ResponseHeadState::Waiting => {
            // A reset or a connection close before the head means the request
            // faulted.
            match streams.get(&stream_id) {
                Some(st) => {
                    // `locally_closed` implies `Closed` on every open stream (see
                    // the field's docs).
                    match st.read_state {
                        ReadState::Closed if *locally_closed => {
                            return Poll::Ready(Err(RequestError::LocallyClosed));
                        }
                        ReadState::Closed => {
                            return Poll::Ready(Err(RequestError::ConnectionClosed));
                        }
                        ReadState::Reset(code) => {
                            return Poll::Ready(Err(RequestError::Reset(code)));
                        }
                        // The stream is still open, so the head may yet arrive:
                        // fall through and register a waker.
                        ReadState::Streaming | ReadState::Trailers(_) | ReadState::Eof => {}
                    }
                }
                None => {
                    return Poll::Ready(Err(RequestError::ConnectionClosed));
                }
            }
            slot.waker = Some(cx.waker().clone());
            Poll::Pending
        }
        ResponseHeadState::Done => {
            // Polled again after the head was already delivered.
            Poll::Ready(Err(RequestError::ConnectionClosed))
        }
    }
}
