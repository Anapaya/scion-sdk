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

use std::{collections::HashMap, sync::Arc};

use futures::StreamExt;
use squiche::h3;
use tokio::{
    sync::{Mutex, Notify},
    time::{sleep, timeout},
};

use crate::{
    UDP_PACKET_BUFFER_SIZE,
    h3::request::{H3Headers, H3Request},
    quic::server::{QuicServer, QuicServerConnection},
};

/// HTTP/3 server.
pub struct H3Server {
    quic_server: QuicServer,
}

impl H3Server {
    /// Creates a new HTTP/3 server.
    pub fn new(quic_server: QuicServer) -> Self {
        Self { quic_server }
    }

    /// Accepts the next incoming H3 connection.
    pub async fn accept(&mut self) -> Option<H3ServerConnection> {
        let conn = match self.quic_server.accept().await {
            Some(quic_conn) => quic_conn,
            None => return None,
        };

        let h3_conn = {
            // Wait until the connection is established
            conn.wait_established().await;
            let mut conn_locked = conn.conn.lock().await;

            // Check ALPN
            let alpn = conn_locked.application_proto().to_vec();

            // Check if the the application protocol of the connection is H3
            if alpn != b"h3" {
                // TODO: close connection?
                tracing::error!(?alpn, "Connection ALPN is not h3");
                return None;
            }

            // Create H3 config
            let h3_config = squiche::h3::Config::new().expect("default H3 config should be valid");
            match squiche::h3::Connection::with_transport(&mut conn_locked, &h3_config) {
                Ok(c) => c,
                Err(err) => {
                    tracing::error!(?err, "Failed to create H3 connection");
                    return None;
                }
            }
        };

        Some(H3ServerConnection {
            quic_h3_conn: QuicH3Connection {
                quic_conn: conn,
                h3_conn: Arc::new(Mutex::new(h3_conn)),
            },
            partial_requests: HashMap::new(),
            buffer: vec![0u8; UDP_PACKET_BUFFER_SIZE],
        })
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

impl H3ServerConnection {
    /// Polls the H3 connection until a new H3 request is received.
    pub async fn handle_request(&mut self) -> Option<(H3Request, H3ResponseSender)> {
        loop {
            tokio::task::coop::consume_budget().await;
            // Process H3

            // Grab notification before acquiring locks to avoid missing any.
            let tx_notif = self.quic_h3_conn.quic_conn.quic_rx_notif.notified();

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
                            self.partial_requests.insert(stream_id, req);
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
                    self.partial_requests.remove(&stream_id);
                }
                Ok((_stream_id, squiche::h3::Event::PriorityUpdate)) => {
                    tracing::warn!("Received PRIORITY_UPDATE, ignoring");
                }
                Err(squiche::h3::Error::Done) => {
                    // Sleep until new data arrives.
                    tx_notif.await;
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
        mut stream: impl futures::Stream<Item = Result<StreamData, StreamError>> + Unpin,
    ) -> Result<(), StreamingResponseError<StreamError>> {
        let headers = vec![squiche::h3::Header::new(
            b":status",
            status.as_u16().to_string().as_bytes(),
        )];

        // Send headers
        loop {
            let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
            match h3.send_response(&mut quic, self.stream_id, &headers, false) {
                Ok(_) => {
                    self.quic_tx_notify.notify_one();
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
                    let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
                    // Finish the stream with an empty body.
                    h3.send_body(&mut quic, self.stream_id, &[], true)?;
                    self.quic_tx_notify.notify_one();
                    return Err(StreamingResponseError::StreamError(err));
                }
            };

            let mut chunk_slice = chunk.as_ref();

            let (mut quic, mut h3) = self.quic_h3_conn.get_locked().await;
            loop {
                match h3.send_body(&mut quic, self.stream_id, chunk_slice, false) {
                    Ok(written) => {
                        self.quic_tx_notify.notify_one();

                        if written == chunk_slice.len() {
                            break;
                        } else {
                            // Partial write, update the chunk slice and try again
                            chunk_slice = &chunk_slice[written..];
                            drop(h3);
                            drop(quic);

                            // This is bad, but there is currently no way for us to be notified when
                            // the stream is unblocked.
                            sleep(std::time::Duration::from_millis(5)).await;

                            let (fresh_quic, fresh_h3) = self.quic_h3_conn.get_locked().await;
                            quic = fresh_quic;
                            h3 = fresh_h3;
                        }
                    }
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
                    Err(err) => return Err(err.into()),
                }
            }
        }

        // Stream exhausted finish the response
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
                Err(err) => return Err(err.into()),
            }
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
