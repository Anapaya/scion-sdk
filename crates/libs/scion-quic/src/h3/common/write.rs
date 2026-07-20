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

//! The shared write-side machinery: capacity-blocked frame senders and the
//! body pump that streams an `http_body::Body` out as DATA frames.

use std::{future::poll_fn, task::Poll};

use bytes::{Buf, Bytes};
use http_body::Body;
use squiche::h3::Header;

use crate::{
    h3::common::{H3App, H3Error, headers::header_map_to_h3},
    quic::connection::{QuicScionConn, WeakConnectionHandle},
};

/// Sends a leading header section on `stream_id` (the server's response head),
/// retrying while the stream is blocked.
pub(crate) async fn send_headers<A: H3App>(
    handle: &WeakConnectionHandle<A>,
    stream_id: u64,
    headers: Vec<Header>,
) -> Result<(), H3Error> {
    poll_fn(|cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        let (h3, streams) = app.h3_streams();
        let Some(h3) = h3 else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        match h3.send_response(inner, stream_id, &headers, false) {
            Ok(()) => {
                drop(guard);
                handle.notify();
                Poll::Ready(Ok(()))
            }
            Err(squiche::h3::Error::StreamBlocked) => {
                let Some(st) = streams.get_mut(&stream_id) else {
                    // No entry means the stream was already torn down; bail
                    // instead of resurrecting it with a waker nobody will wake.
                    return Poll::Ready(Err(H3Error::ConnectionClosed));
                };
                st.write_waker = Some(cx.waker().clone());
                drop(guard);
                handle.notify();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(H3Error::H3(err))),
        }
    })
    .await
}

/// Sends `bytes` (and optionally a FIN) on `stream_id`, retrying across stream
/// capacity blocks (the QUIC window provides backpressure).
pub(crate) async fn send_data<A: H3App>(
    handle: &WeakConnectionHandle<A>,
    stream_id: u64,
    mut bytes: Bytes,
    fin: bool,
) -> Result<(), H3Error> {
    poll_fn(move |cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        let (h3, streams) = app.h3_streams();
        let Some(h3) = h3 else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };

        loop {
            if bytes.is_empty() && !fin {
                drop(guard);
                handle.notify();
                return Poll::Ready(Ok(()));
            }
            match h3.send_body(inner, stream_id, bytes.as_ref(), fin) {
                Ok(written) => {
                    bytes.advance(written);
                    if bytes.is_empty() {
                        // All data (and the FIN, if any) was accepted.
                        drop(guard);
                        handle.notify();
                        return Poll::Ready(Ok(()));
                    }
                    // Partial write; loop to send the remainder.
                }
                Err(squiche::h3::Error::Done) | Err(squiche::h3::Error::StreamBlocked) => {
                    let Some(st) = streams.get_mut(&stream_id) else {
                        // No entry means the stream was already torn down; bail
                        // instead of resurrecting it with a waker nobody will wake.
                        return Poll::Ready(Err(H3Error::ConnectionClosed));
                    };
                    st.write_waker = Some(cx.waker().clone());
                    drop(guard);
                    handle.notify();
                    return Poll::Pending;
                }
                Err(err) => return Poll::Ready(Err(H3Error::H3(err))),
            }
        }
    })
    .await
}

/// Sends a trailing header section (closing the stream with a FIN), retrying
/// while the stream is blocked.
pub(crate) async fn send_trailers<A: H3App>(
    handle: &WeakConnectionHandle<A>,
    stream_id: u64,
    trailers: Vec<Header>,
) -> Result<(), H3Error> {
    poll_fn(|cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        let (h3, streams) = app.h3_streams();
        let Some(h3) = h3 else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        match h3.send_additional_headers(inner, stream_id, &trailers, true, true) {
            Ok(()) => {
                drop(guard);
                handle.notify();
                Poll::Ready(Ok(()))
            }
            Err(squiche::h3::Error::StreamBlocked) => {
                let Some(st) = streams.get_mut(&stream_id) else {
                    // No entry means the stream was already torn down; bail
                    // instead of resurrecting it with a waker nobody will wake.
                    return Poll::Ready(Err(H3Error::ConnectionClosed));
                };
                st.write_waker = Some(cx.waker().clone());
                drop(guard);
                handle.notify();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(H3Error::H3(err))),
        }
    })
    .await
}

/// Streams a body out on `stream_id` as HTTP/3 DATA frames, finishing with a FIN
/// or a trailing header section. The leading head must already have been sent
/// (`send_response` on the server, `send_request` on the client).
///
/// Returns `true` if the body finished cleanly (a FIN or trailing section was
/// sent), or `false` if it was aborted partway (the caller should reset the
/// stream).
pub(crate) async fn pump_body<A, B>(
    handle: &WeakConnectionHandle<A>,
    stream_id: u64,
    body: B,
) -> bool
where
    A: H3App + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Send,
{
    let mut body = std::pin::pin!(body);
    let mut trailers_sent = false;
    loop {
        match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            Some(Ok(frame)) => {
                match frame.into_data() {
                    Ok(mut data) => {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if let Err(err) = send_data(handle, stream_id, bytes, false).await {
                            tracing::debug!(?err, stream_id, "failed to send body data");
                            return false;
                        }
                    }
                    Err(non_data) => {
                        // A trailing header section terminates the message: it carries
                        // the FIN, so it must be the last frame sent. Other (unknown)
                        // frame kinds are ignored.
                        if let Ok(map) = non_data.into_trailers() {
                            let trailers = header_map_to_h3(&map);
                            if !trailers.is_empty() {
                                if let Err(err) = send_trailers(handle, stream_id, trailers).await {
                                    tracing::debug!(?err, stream_id, "failed to send trailers");
                                    return false;
                                }
                                trailers_sent = true;
                                break;
                            }
                        }
                    }
                }
            }
            Some(Err(_err)) => {
                tracing::debug!(stream_id, "body errored before completion");
                return false;
            }
            None => break,
        }
    }

    if trailers_sent {
        // The trailing header section already finished the stream with a FIN.
        true
    } else {
        // Finish the stream with an empty, FIN-bearing body frame.
        send_data(handle, stream_id, Bytes::new(), true)
            .await
            .is_ok()
    }
}
