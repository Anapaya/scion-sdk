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

//! Application protocols driven in lockstep with a QUIC/SCION connection.
//!
//! The connection driver is protocol-agnostic: it manages timeouts and flushes
//! packets, then delegates application-level progress to a
//! [`QuicScionApplication`]. The application steps its state machine once per
//! driver iteration and collects the readers/writers to wake into a [`Wakeups`]
//! batch, which the driver fires after releasing the connection lock.

use crate::quic::connection::ConnectionHandle;

/// Deferred consumer wakeups, opaque to the driver. Fired *after* the
/// connection lock is dropped so woken tasks don't bounce off the mutex.
#[derive(Default)]
pub struct Wakeups {
    wakers: Vec<std::task::Waker>,
}

impl Wakeups {
    /// Schedules a waker to be fired after the connection lock is dropped.
    pub fn schedule(&mut self, w: std::task::Waker) {
        self.wakers.push(w);
    }

    // postcondition: self.wakers is empty
    pub(crate) fn fire(&mut self) {
        while let Some(w) = self.wakers.pop() {
            w.wake();
        }
    }
}

/// An application protocol driven in lockstep with a QUIC connection.
pub trait QuicScionApplication: Send {
    /// Shared, connection-independent configuration handed to
    /// [`Self::on_established`] when constructing the application for a new
    /// connection (for example, an HTTP/3 config plus the service to run).
    type Config;

    /// Called once when the connection has been established, constructing the
    /// application state for it.
    ///
    /// This is where application-level setup happens: e.g. creating an
    /// `squiche::h3::Connection` on top of the transport, checking the
    /// negotiated ALPN, or initializing per-connection state. If the
    /// connection is unacceptable (for example, an unsupported ALPN), the
    /// implementation may close `conn`; the returned application will then
    /// simply observe the connection being torn down.
    ///
    /// * `conn` is the freshly established QUIC connection.
    /// * `config` is the shared configuration provided to the endpoint driver.
    fn on_established(conn: &mut squiche::Connection, config: &Self::Config) -> Self
    where
        Self: Sized;

    /// Called once, right after [`Self::on_established`], to give the
    /// application a handle to its own connection.
    ///
    /// The application typically downgrades this to a
    /// [`WeakConnectionHandle`](crate::quic::connection::WeakConnectionHandle)
    /// and stores it, so spawned tasks and response/request bodies can access
    /// the connection without forming an `Arc` cycle. The default does nothing.
    fn bind(&mut self, handle: &ConnectionHandle<Self>)
    where
        Self: Sized,
    {
        let _ = handle;
    }

    /// Advance the app state machine. Called once per driver iteration,
    /// *after* `on_timeout()` and *before* `send()`. Drains app events,
    /// performs flow-controlled reads/writes against `conn`, and collects
    /// consumer wakers into `wakeups`.
    fn update(&mut self, conn: &mut squiche::Connection, wakeups: &mut Wakeups);

    /// Called once when the connection is closed, to fault pending work.
    fn on_closed(&mut self, wakeups: &mut Wakeups);
}

/// Plain-QUIC: no application layer.
pub struct NoApp;
impl QuicScionApplication for NoApp {
    type Config = ();
    fn on_established(_conn: &mut squiche::Connection, _config: &()) -> Self {
        NoApp
    }
    fn update(&mut self, _: &mut squiche::Connection, _: &mut Wakeups) {}
    fn on_closed(&mut self, _: &mut Wakeups) {}
}
