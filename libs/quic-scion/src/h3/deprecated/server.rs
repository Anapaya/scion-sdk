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

//! HTTP/3 server over SCION transport.

use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::{Stream, StreamExt};
use squiche::h3;
use tokio::{
    sync::{Mutex, Notify},
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::{
    UDP_PACKET_BUFFER_SIZE,
    h3::deprecated::request::{H3Headers, H3Request},
    quic::server::{QuicServer, QuicServerConnection},
};

#[derive(Debug, thiserror::Error)]
enum HandshakeErrors {
    #[error("timeout waiting for handshake")]
    Timeout,
    #[error("ALPN mismatch")]
    AlpnMismatch,
    #[error("H3 connection error: {0}")]
    H3ConnectionError(squiche::h3::Error),
    #[error("connection closed")]
    ConnectionClosed,
}

/// HTTP/3 server.
pub struct H3Server {
    quic_server: QuicServer,
    handshakes_in_progress: JoinSet<Result<H3ServerConnection, HandshakeErrors>>,
}

impl H3Server {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const MAX_CONCURRENT_HANDSHAKES: usize = 200;

    /// Creates a new HTTP/3 server.
    pub fn new(quic_server: QuicServer) -> Self {
        Self {
            quic_server,
            handshakes_in_progress: JoinSet::new(),
        }
    }

    /// Accepts the next incoming H3 connection.
    pub async fn accept(&mut self) -> Option<H3ServerConnection> {
        loop {
            tokio::select! {
                accept_res = self.quic_server.accept() => {
                    match accept_res {
                        Some(quic_conn) => {
                            tracing::debug!("Accepted new QUIC connection, spawning handshake future");
                            if self.handshakes_in_progress.len() >= Self::MAX_CONCURRENT_HANDSHAKES {
                                tracing::warn!(max= Self::MAX_CONCURRENT_HANDSHAKES, "Too many concurrent handshakes in progress, rejecting new connection");
                                continue;
                            }
                            self.handshakes_in_progress.spawn(handshake(quic_conn, Self::HANDSHAKE_TIMEOUT));
                        }
                        None => {
                            tracing::trace!("No more QUIC connections to accept");
                            return None;
                        }
                    }
                }
                Some(handshake_res) = self.handshakes_in_progress.join_next() => {
                    let in_progress = self.handshakes_in_progress.len();
                    match handshake_res {
                        Ok(Ok(h3_conn)) => {
                            tracing::debug!(in_progress, "Handshake successful, returning new H3 connection");
                            return Some(h3_conn);
                        }
                        Ok(Err(err)) => {
                            tracing::debug!(in_progress, ?err, "Handshake failed for QUIC connection");
                        }
                        Err(err) => {
                            tracing::error!(in_progress, ?err, "Handshake task panicked");
                        }
                    }
                }
            }
        }

        async fn handshake(
            conn: QuicServerConnection,
            max_wait: Duration,
        ) -> Result<H3ServerConnection, HandshakeErrors> {
            let h3_conn = {
                // Wait until the connection is established
                match conn.wait_established(max_wait).await {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::error!("Timed out waiting for QUIC connection to be established");
                        return Err(HandshakeErrors::Timeout);
                    }
                }

                if !conn.conn.lock().await.is_established() {
                    tracing::error!(
                        "QUIC connection was not established after waiting, closing connection"
                    );
                    return Err(HandshakeErrors::ConnectionClosed);
                }

                let mut conn_locked = conn.conn.lock().await;
                tracing::trace!("QUIC connection established, checking ALPN");

                // Check ALPN
                let alpn = conn_locked.application_proto().to_vec();

                // Check if the the application protocol of the connection is H3
                if alpn != b"h3" {
                    // TODO: close connection?
                    tracing::error!(?alpn, "Connection ALPN is not h3");
                    return Err(HandshakeErrors::AlpnMismatch);
                }

                // Create H3 config
                let h3_config =
                    squiche::h3::Config::new().expect("default H3 config should be valid");
                match squiche::h3::Connection::with_transport(&mut conn_locked, &h3_config) {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::error!(?err, "Failed to create H3 connection");
                        return Err(HandshakeErrors::H3ConnectionError(err));
                    }
                }
            };

            Ok(H3ServerConnection {
                quic_h3_conn: QuicH3Connection {
                    quic_conn: conn,
                    h3_conn: Arc::new(Mutex::new(h3_conn)),
                },
                partial_requests: HashMap::new(),
                buffer: vec![0u8; UDP_PACKET_BUFFER_SIZE],
            })
        }
    }
}

#[derive(Clone)]
struct QuicH3Connection {
    quic_conn: QuicServerConnection,
    h3_conn: Arc<Mutex<squiche::h3::Connection>>,
}

impl QuicH3Connection {
    /// Acquires the locks for both the QUIC and H3 connections.
    ///
    /// Ensures lock ordering to prevent deadlocks and includes a timeout for the H3 lock to avoid
    /// waiting indefinitely.
    pub async fn get_locked(
        &self,
    ) -> (
        tokio::sync::MutexGuard<'_, squiche::Connection>,
        tokio::sync::MutexGuard<'_, squiche::h3::Connection>,
    ) {
        loop {
            // Quic is more contended, so we acquire that lock first
            let quic_guard = self.quic_conn.conn.lock().await;
            let h3_guard =
                match timeout(std::time::Duration::from_secs(1), self.h3_conn.lock()).await {
                    Ok(guard) => guard,
                    Err(_) => {
                        tracing::error!("Timed out waiting for H3 connection lock, retrying");
                        tokio::task::yield_now().await;
                        continue;
                    }
                };

            return (quic_guard, h3_guard);
        }
    }
}

/// A connection on the HTTP/3 server.
pub struct H3ServerConnection {
    quic_h3_conn: QuicH3Connection,
    partial_requests: HashMap<u64, H3Request>,
    buffer: Vec<u8>,
}

/// Closes the stream and cleans up any state associated with the stream.
///
/// Shuts down both the read and write side of the stream.
///
/// Note: Currently a macro because of borrowing issues on the QUIC connection.
macro_rules! close_stream {
    ($self:expr, $quic:expr, $stream_id:expr, $error_code:expr) => {{
        tracing::debug!(
            stream_id = $stream_id,
            "closing stream and cleaning up state"
        );
        match $quic.stream_shutdown($stream_id, squiche::Shutdown::Read, $error_code) {
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(
                    ?err,
                    stream_id = $stream_id,
                    "Error shutting down stream for reading when closing stream"
                );
            }
        }
        match $quic.stream_shutdown($stream_id, squiche::Shutdown::Write, $error_code) {
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(
                    ?err,
                    stream_id = $stream_id,
                    "Error shutting down stream for writing when closing stream"
                );
            }
        }

        $self.partial_requests.remove(&$stream_id);
    }};
}

impl H3ServerConnection {
    /// Polls the H3 connection until a new H3 request is received.
    #[tracing::instrument(skip_all, fields(scid = tracing::field::Empty))]
    pub async fn handle_request(&mut self) -> Option<(H3Request, H3ResponseSender)> {
        {
            let quic = self.quic_h3_conn.quic_conn.conn.lock().await;
            tracing::Span::current().record("scid", tracing::field::debug(quic.source_id()));
        }

        loop {
            tokio::task::coop::consume_budget().await;
            // Process H3
            let event = {
                let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
                h3.poll(&mut quic)
            };

            match event {
                Ok((
                    stream_id,
                    squiche::h3::Event::Headers {
                        list: headers,
                        more_frames,
                    },
                )) => {
                    tracing::debug!(?stream_id, "Received H3 request headers");

                    let headers: H3Headers = match headers.try_into() {
                        Ok(headers) => headers,
                        Err(err) => {
                            tracing::warn!(?err, ?stream_id, "Failed to parse H3 request headers");
                            continue;
                        }
                    };

                    let req = H3Request {
                        headers,
                        body: None,
                    };

                    match more_frames {
                        true => {
                            match self.partial_requests.entry(stream_id) {
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    entry.insert(req);
                                }
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    tracing::warn!(
                                        ?stream_id,
                                        "Received headers for stream with existing partial request, ignoring new headers"
                                    );
                                }
                            }
                            continue;
                        }
                        false => {
                            let sender = H3ResponseSender {
                                stream_id,
                                quic_h3_conn: self.quic_h3_conn.clone(),
                                quic_tx_notify: self.quic_h3_conn.quic_conn.quic_tx_notif.clone(),
                            };
                            return Some((req, sender));
                        }
                    }
                }
                Ok((stream_id, squiche::h3::Event::Data)) => {
                    tracing::debug!(?stream_id, "Receiving H3 request body");
                    if let Some(req) = self.partial_requests.get_mut(&stream_id) {
                        let res = {
                            let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
                            h3.recv_body(&mut quic, stream_id, &mut self.buffer)
                        };
                        match res {
                            Ok(read) => {
                                // XXX(bunert): This forces the entire body to be buffered in
                                // memory. For large responses we need a streaming body interface
                                // and send the inbound body frames to the handler similar to
                                // tokio-quiche InboundFrame.
                                req.body
                                    .get_or_insert_with(Vec::new)
                                    .extend_from_slice(&self.buffer[..read]);
                            }
                            Err(squiche::h3::Error::Done) => continue,
                            Err(err) => {
                                tracing::warn!(
                                    ?err,
                                    ?stream_id,
                                    "Error receiving H3 request body on stream"
                                );
                                return None;
                            }
                        }
                    }
                }
                Ok((stream_id, squiche::h3::Event::Finished)) => {
                    tracing::debug!(?stream_id, "Finished receiving H3 request");

                    // Finished receiving the request, close Read side of the stream
                    {
                        let (mut quic, _) = self.quic_h3_conn.get_locked().await;
                        match quic.stream_shutdown(stream_id, squiche::Shutdown::Read, 0) {
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    ?err,
                                    ?stream_id,
                                    "Error shutting down stream for reading after receiving Finished event"
                                );
                            }
                        }
                    }

                    if let Some(req) = self.partial_requests.remove(&stream_id) {
                        let sender = H3ResponseSender {
                            stream_id,
                            quic_h3_conn: self.quic_h3_conn.clone(),
                            quic_tx_notify: self.quic_h3_conn.quic_conn.quic_tx_notif.clone(),
                        };
                        return Some((req, sender));
                    }
                }
                Ok((_stream_id, squiche::h3::Event::GoAway)) => {
                    tracing::warn!("Received GOAWAY from client, closing H3 connection");
                    return None;
                }
                Ok((stream_id, squiche::h3::Event::Reset(_))) => {
                    tracing::debug!(
                        ?stream_id,
                        "Received Reset for stream, cleaning up stream state"
                    );
                    self.partial_requests.remove(&stream_id);

                    // Stream was reset, close both read and write side of the stream to ensure all
                    // resources are cleaned up.
                    let (mut quic, _) = self.quic_h3_conn.get_locked().await;
                    close_stream!(self, quic, stream_id, 0);
                }
                Ok((_stream_id, squiche::h3::Event::PriorityUpdate)) => {
                    tracing::warn!("Received PRIORITY_UPDATE, ignoring");
                }
                Err(squiche::h3::Error::Done) => {
                    // Check if any streams are to be cleaned up.
                    {
                        let (mut quic, _h3) = self.quic_h3_conn.get_locked().await;
                        // Eagerly check if any writeable streams are blocked
                        for stream_id in quic.writable() {
                            tracing::trace!(?stream_id, "H3 stream is writable, processing events");
                            match quic.stream_capacity(stream_id) {
                                Ok(_) => {}
                                Err(squiche::Error::StreamStopped(e)) => {
                                    tracing::debug!(
                                        ?e,
                                        ?stream_id,
                                        "Stream is stopped, closing stream and cleaning up state"
                                    );
                                    close_stream!(self, quic, stream_id, 0);
                                }
                                Err(err) => {
                                    tracing::trace!(
                                        ?err,
                                        ?stream_id,
                                        "Failed to get stream capacity for writable stream"
                                    );
                                }
                            }
                        }
                    }

                    // Sleep until new data
                    // Since we are using notify_one, this will trigger on old notifications which
                    // might cause some unnecessary wakeups.
                    self.quic_h3_conn.quic_conn.quic_rx_notif.notified().await;
                }
                Err(err) => {
                    tracing::error!(?err, "H3 connection error, closing connection");
                    return None;
                }
            }
        }
    }
}
/// Sender for HTTP/3 response.
pub struct H3ResponseSender {
    stream_id: u64,
    quic_h3_conn: QuicH3Connection,
    quic_tx_notify: Arc<Notify>,
}

impl H3ResponseSender {
    /// Sends the response.
    pub async fn send_response(
        &mut self,
        status: http::StatusCode,
        response_headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<(), squiche::h3::Error> {
        let mut headers = vec![squiche::h3::Header::new(
            b":status",
            status.as_u16().to_string().as_bytes(),
        )];

        for (name, value) in response_headers.iter() {
            headers.push(squiche::h3::Header::new(
                name.as_str().as_bytes(),
                value.as_bytes(),
            ));
        }

        let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;

        h3.send_response(&mut quic, self.stream_id, &headers, false)?;
        h3.send_body(&mut quic, self.stream_id, body, true)?;

        // Notify that there is new data to send. Can we get rid of that?
        self.quic_tx_notify.notify_one();

        Ok(())
    }

    /// Sends a streaming response, where the body is sent in chunks from the provided stream.
    pub async fn send_streaming_response<
        StreamData: AsRef<[u8]>,
        StreamError: std::error::Error,
    >(
        &mut self,
        status: http::StatusCode,
        response_headers: &http::HeaderMap,
        stream: impl futures::Stream<Item = Result<StreamData, StreamError>> + Unpin,
    ) -> Result<(), StreamingResponseError<StreamError>> {
        match write_streaming(self, status, response_headers, stream).await {
            Ok(_) => {}
            Err(err) => {
                tracing::error!(?err, "Error sending streaming response");
            }
        }

        // Always try to finish the stream, even if there was an error sending the body frames.
        let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
        loop {
            match h3.send_body(&mut quic, self.stream_id, &[], true) {
                Ok(_) => {
                    self.quic_tx_notify.notify_one();
                    return Ok(());
                }
                // Stream blocked
                Err(h3::Error::Done) | Err(h3::Error::StreamBlocked) => {
                    drop(h3);
                    drop(quic);

                    // This is bad, but there is currently no way for us to be notified when the
                    // stream is unblocked.
                    sleep(std::time::Duration::from_millis(5)).await;

                    let (fresh_quic, fresh_h3) = self.quic_h3_conn.get_locked().await;
                    quic = fresh_quic;
                    h3 = fresh_h3;
                }
                Err(err) => {
                    // If we fail to send the final body frame, we close the stream.
                    let _ = quic.stream_shutdown(self.stream_id, squiche::Shutdown::Write, 500);
                    return Err(err.into());
                }
            }
        }

        async fn write_streaming<StreamData: AsRef<[u8]>, StreamError: std::error::Error>(
            this: &mut H3ResponseSender,
            status: http::StatusCode,
            response_headers: &http::HeaderMap,
            mut stream: impl Stream<Item = Result<StreamData, StreamError>> + Unpin,
        ) -> Result<(), StreamingResponseError<StreamError>> {
            let mut headers = vec![squiche::h3::Header::new(
                b":status",
                status.as_u16().to_string().as_bytes(),
            )];
            for (name, value) in response_headers.iter() {
                headers.push(squiche::h3::Header::new(
                    name.as_str().as_bytes(),
                    value.as_bytes(),
                ));
            }
            // Send headers
            loop {
                let (mut quic, mut h3) = this.quic_h3_conn.get_locked().await;
                match h3.send_response(&mut quic, this.stream_id, &headers, false) {
                    Ok(_) => {
                        this.quic_tx_notify.notify_one();
                        break;
                    }
                    Err(squiche::h3::Error::StreamBlocked) => {
                        drop(h3);
                        drop(quic);
                        // This is bad, but there is currently no way for us to be notified when the
                        // stream is unblocked.
                        sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(err) => return Err(err.into()),
                }
            }

            // Send body frames
            while let Some(stream_res) = stream.next().await {
                let chunk = match stream_res {
                    Ok(data) => data,
                    Err(err) => {
                        return Err(StreamingResponseError::StreamError(err));
                    }
                };

                let mut chunk_slice = chunk.as_ref();

                let (mut quic, mut h3) = this.quic_h3_conn.get_locked().await;
                loop {
                    match h3.send_body(&mut quic, this.stream_id, chunk_slice, false) {
                        Ok(written) => {
                            this.quic_tx_notify.notify_one();

                            if written == chunk_slice.len() {
                                break;
                            } else {
                                // Partial write, update the chunk slice and try again
                                chunk_slice = &chunk_slice[written..];
                                drop(h3);
                                drop(quic);

                                // This is bad, but there is currently no way for us to be notified
                                // when the stream is unblocked.
                                sleep(std::time::Duration::from_millis(5)).await;

                                let (fresh_quic, fresh_h3) = this.quic_h3_conn.get_locked().await;
                                quic = fresh_quic;
                                h3 = fresh_h3;
                            }
                        }
                        Err(h3::Error::Done) | Err(h3::Error::StreamBlocked) => {
                            drop(h3);
                            drop(quic);

                            // This is bad, but there is currently no way for us to be notified when
                            // the stream is unblocked.
                            sleep(std::time::Duration::from_millis(5)).await;

                            let (fresh_quic, fresh_h3) = this.quic_h3_conn.get_locked().await;
                            quic = fresh_quic;
                            h3 = fresh_h3;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }

            Ok(())
        }
    }
}

/// Errors that can occur when sending a streaming response.
#[derive(Debug, thiserror::Error)]
pub enum StreamingResponseError<T: std::error::Error> {
    /// Error returned by the response body stream.
    #[error("Error from response body stream: {0}")]
    StreamError(T),
    /// Error returned by the H3 layer.
    #[error("H3 error: {0}")]
    H3Error(#[from] squiche::h3::Error),
}
