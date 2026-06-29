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

//! QUIC/SCION Connection driver

use std::{
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Instant,
};

use sciparse::{address::socket_addr::ScionSocketAddr, identifier::isd_asn::IsdAsn};
use squiche::{Connection, SendInfo};
use tokio::sync::Notify;

use crate::{
    app::{NoApp, QuicScionApplication, Wakeups},
    socket::{BoxedSocketError, GenericScionUdpSocket},
};

/// A driver for a single established SCION QUIC connection.
///
/// The connection driver is responsible for ...
///
/// * ... managing connection timeouts.
/// * ... dispatching outgoing packets.
/// * ... signalling readers/writers upon state change.
///
/// It operates on the shared [`ConnectionHandle`] it is created with: inbound
/// packets are fed into the connection by other tasks (which then call
/// [`ConnectionHandle::notify`]), while the driver flushes outbound packets and
/// drives the connection's timers until it is closed.
pub struct QuicScionConnDriver<A = NoApp> {
    conn_handle: ConnectionHandle<A>,
    socket: Arc<dyn GenericScionUdpSocket>,
}

impl<A: QuicScionApplication> QuicScionConnDriver<A> {
    /// Create a new connection driver.
    ///
    /// ## Parameters
    ///
    /// * `conn_handle` handle to the connection to drive.
    /// * `socket` is used to dispatch outgoing packets.
    pub fn new(conn_handle: ConnectionHandle<A>, socket: Arc<dyn GenericScionUdpSocket>) -> Self {
        Self {
            conn_handle,
            socket,
        }
    }

    /// Drive the QUIC SCION connection until it is closed.
    ///
    /// ## Return value
    ///
    /// Returns either `Ok(())` once the connection is closed, or the first
    /// error returned while sending a packet on the socket.
    pub async fn run(&self) -> Result<(), BoxedSocketError> {
        // Ensure that we drive the loop at least once.
        self.conn_handle.notify();
        let mut closed = false;
        // For specific load patterns, dispatching multiple packets in a
        // single loop iteration is beneficial. For as long as we don't need
        // that optimization, we keep the state space simple and only buffer
        // a single packet.

        /* BEGIN bookkeeping */
        // Some of these variables are initialized to default values here and
        // updated in the loop.
        let mut send_buf = Box::new([0u8; 65535]);
        let mut transmit_size = 0usize;
        let mut send_to =
            ScionSocketAddr::from_std(IsdAsn::from_u64(0), "0.0.0.0:0".parse().unwrap());

        let start_time = Instant::now();
        let timeout = tokio::time::sleep_until(start_time.into());
        tokio::pin!(timeout);
        let mut timeout_fired = false;
        let mut timeout_inst: Option<Instant> = None;
        {
            // Hand the application a (weak) handle to its own connection so it
            // can build bodies / spawn tasks that access the connection, then
            // arm the initial timeout.
            let handle = self.conn_handle.clone();
            let mut conn = handle.lock();
            conn.app.bind(&handle);
            Self::set_timeout(
                &mut timeout_inst,
                &mut timeout,
                conn.inner.timeout_instant(),
            );
        }
        /* END bookkeeping */

        let mut wakeups = Wakeups::default();
        while !closed {
            // We assume that .send_to is cancel-safe.
            let send = async {
                self.socket
                    .send_to(&send_buf[..transmit_size], send_to)
                    .await
            };
            let notified = self.conn_handle.notified();
            tokio::select! {
                /* BEGIN I/O */
                biased;
                res = send, if transmit_size > 0 => {
                    res?;
                    transmit_size = 0;
                },
                // We bias towards sending packets before checking the timeout,
                // before dealing with notifications.
                _ = (&mut timeout), if timeout_inst.is_some() => {
                    timeout_fired = true;
                },
                _ = notified => {},
                /* END I/O */
            }

            {
                /* BEGIN critical section */
                let mut conn = self.conn_handle.lock();
                if timeout_fired {
                    conn.inner.on_timeout();
                    timeout_fired = false;
                }
                // Step the application state machine in lockstep with the
                // connection: after timeouts are processed, before packets are
                // flushed.
                conn.update_app(&mut wakeups);
                if transmit_size == 0 {
                    // We only break the loop if the transmit buffer is empty.
                    closed = conn.inner.is_closed();
                    if closed {
                        conn.on_closed(&mut wakeups);
                    }
                    match conn.send(send_buf.as_mut()) {
                        // Pacing is currently ignored.
                        Ok((n, s)) => {
                            transmit_size = n;
                            send_to = s.to;
                        }
                        Err(squiche::Error::Done) => {}
                        Err(err) => {
                            tracing::error!(?err, "error on calling send on connection");
                        }
                    }
                }
                Self::set_timeout(
                    &mut timeout_inst,
                    &mut timeout,
                    conn.inner.timeout_instant(),
                );
                /* END critical section */
            }
            // Fire consumer wakeups after the connection lock is dropped so the
            // woken tasks don't immediately bounce off the mutex.
            wakeups.fire();
        }
        Ok(())
    }

    /// (Re)arms `timeout` to fire at `new_timeout`, keeping `timeout_inst` in
    /// sync with the connection's next timeout instant.
    #[inline]
    fn set_timeout(
        timeout_inst: &mut Option<Instant>,
        timeout: &mut Pin<&mut tokio::time::Sleep>,
        new_timeout: Option<Instant>,
    ) {
        *timeout_inst = new_timeout;
        if let Some(t) = &timeout_inst {
            timeout.as_mut().reset((*t).into());
        }
    }
}

/// A cloneable handle to a [`QuicScionConn`].
///
/// The handle is shared between the connection's [`QuicScionConnDriver`], the
/// endpoint that routes inbound packets to it, and any readers/writers. All
/// access to the connection state goes through [`Self::lock`]; state changes
/// are announced to the driver via [`Self::notify`].
pub struct ConnectionHandle<A = NoApp> {
    conn: Arc<Mutex<QuicScionConn<A>>>,
    notify: Arc<Notify>,
}

// Manual `Clone` impl: cloning a handle only clones the shared `Arc`s, so it
// must not require `A: Clone` (which `#[derive(Clone)]` would impose).
impl<A> Clone for ConnectionHandle<A> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<A> ConnectionHandle<A> {
    /// Creates a new handle owning `conn`, using `notify` to signal its driver.
    pub fn new(notify: Notify, conn: QuicScionConn<A>) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            notify: Arc::new(notify),
        }
    }

    /// Locks the connection, returning a guard for exclusive access to its
    /// [`QuicScionConn`] state.
    ///
    /// Panics if the underlying mutex was poisoned.
    pub fn lock(&self) -> MutexGuard<'_, QuicScionConn<A>> {
        self.conn.lock().unwrap()
    }

    /// Like [`Self::lock`], but recovers the guard if the mutex was poisoned by
    /// a panic elsewhere instead of panicking.
    ///
    /// Intended for best-effort cleanup paths that run from a `Drop` guard,
    /// where panicking again (e.g. on a poisoned lock) would abort the process
    /// during unwinding. The recovered state may be inconsistent, so this must
    /// only be used for teardown, never for normal operation.
    pub fn lock_recovering(&self) -> MutexGuard<'_, QuicScionConn<A>> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Wakes the connection's driver so it can make progress (for example, to
    /// flush packets queued after feeding in inbound data).
    pub fn notify(&self) {
        self.notify.notify_one();
    }

    /// Returns a future that completes the next time [`Self::notify`] is
    /// called.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    /// Returns a weak handle that does not keep the connection alive.
    ///
    /// Application state machines use this to reference their own connection
    /// (for example, from spawned tasks or response bodies) without forming an
    /// `Arc` cycle through the connection's stored application state.
    pub fn downgrade(&self) -> WeakConnectionHandle<A> {
        WeakConnectionHandle {
            conn: Arc::downgrade(&self.conn),
            notify: self.notify.clone(),
        }
    }
}

/// A weak counterpart to [`ConnectionHandle`].
///
/// Holds a weak reference to the connection, so it does not keep it alive.
/// [`Self::upgrade`] returns a live [`ConnectionHandle`] while the connection
/// still exists.
pub struct WeakConnectionHandle<A = NoApp> {
    conn: Weak<Mutex<QuicScionConn<A>>>,
    notify: Arc<Notify>,
}

impl<A> Clone for WeakConnectionHandle<A> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<A> WeakConnectionHandle<A> {
    /// Upgrades to a strong [`ConnectionHandle`], or returns `None` if the
    /// connection has already been dropped.
    pub fn upgrade(&self) -> Option<ConnectionHandle<A>> {
        Some(ConnectionHandle {
            conn: self.conn.upgrade()?,
            notify: self.notify.clone(),
        })
    }
}

/// The state of a SCION QUIC connection.
pub struct QuicScionConn<A = NoApp> {
    /// Source/Dest ISD-ASN pair oriented from the server to the client.
    pub asn_pair: IsdAsnPair,
    /// QUIC Connection.
    pub inner: Connection,
    /// Application protocol driven in lockstep with the connection.
    pub app: A,
}

impl<A> QuicScionConn<A> {
    /// Writes the next queued outgoing packet into `send_buf`, returning its
    /// length and the SCION send information for it.
    pub fn send(&mut self, send_buf: &mut [u8]) -> squiche::Result<(usize, ScionSendInfo)> {
        self.inner
            .send(send_buf)
            .map(|(n, s)| (n, ScionSendInfo::from_squiche(s, self.asn_pair.clone())))
    }
}

impl<A: QuicScionApplication> QuicScionConn<A> {
    /// Steps the application state machine, collecting consumer wakeups.
    fn update_app(&mut self, wakeups: &mut Wakeups) {
        self.app.update(&mut self.inner, wakeups);
    }

    /// Signals the application that the connection has been closed.
    fn on_closed(&mut self, wakeups: &mut Wakeups) {
        self.app.on_closed(wakeups);
    }
}

/// A source/destination pair of ISD-ASN identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsdAsnPair {
    /// Source ISD-ASN.
    pub from: IsdAsn,
    /// Target ISD-ASN.
    pub to: IsdAsn,
}

/// The equivalent of `squiche::SendInfo` for SCION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScionSendInfo {
    /// The source of a packet to be sent.
    pub from: ScionSocketAddr,
    /// The destination of a packet to be sent.
    pub to: ScionSocketAddr,
    /// The instant at which a packet should be sent.
    pub at: Instant,
}

impl ScionSendInfo {
    /// Builds a [`ScionSendInfo`] from a pair of [`ScionSocketAddr`]s.
    pub fn new(from: ScionSocketAddr, to: ScionSocketAddr, at: Instant) -> Self {
        Self { from, to, at }
    }

    /// Builds a [`ScionSendInfo`] from a `squiche::SendInfo` and the
    /// connection's [`IsdAsnPair`].
    pub fn from_squiche(send_info: SendInfo, asn_pair: IsdAsnPair) -> Self {
        ScionSendInfo {
            from: ScionSocketAddr::from_std(asn_pair.from, send_info.from),
            to: ScionSocketAddr::from_std(asn_pair.to, send_info.to),
            at: send_info.at,
        }
    }
}
