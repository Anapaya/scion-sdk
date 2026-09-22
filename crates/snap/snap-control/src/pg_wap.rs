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

//! PathGuard WAP SNAP extension.
//!
//! The WAP control plane is assembled from four components:
//!
//! * [`grants::GrantManager`] - Manages which client IPs are authorized for which targets and
//!   segments, and when those authorizations expire.
//! * [`segments::SegmentManager`] -  Keeps public segments for the (src, dst) pairs in use fresh.
//! * [`paths::PathManager`] -  Combines public and granted segments into the single best path, and
//!   reports which segments it used.
//! * [`uplinks::UplinkManager`] - Creates and manages one uplink per (path, WAG) pair, multiplexes
//!   SNI streams over it, refreshes its path, cleans it when unused or closed.
//!
//! Clients reach the control plane over the Connect RPC API in [`crpc`], which is where the
//! authorizations that [`grants::GrantManager`] hands out come from.
//!
//! ## Time
//!
//! Every operation that depends on the current time takes it as a `now: SystemTime` argument, so
//! all the decisions taken while serving one connection can be made against a single timestamp
//! instead of drifting apart as the clock moves under them.
//!
//! The `run` maintenance loops are the exception: they own their cadence, so they read the wall
//! clock themselves.

use crate::pg_wap::{
    grants::GrantManager,
    paths::PathManager,
    segments::SegmentManager,
    uplinks::{UplinkEstablisher, UplinkManager},
};

pub mod crpc;
pub mod grants;
pub mod paths;
pub mod segments;
pub mod sni;
pub mod uplinks;

#[cfg(test)]
mod test_util;

/// The WAP control plane
pub struct WapControlPlane<EstablisherType: UplinkEstablisher> {
    /// Decides which client IP may reach which target over which private segments.
    pub grant: GrantManager,
    /// Public segments for all (src, dst) pairs currently in use.
    pub segments: SegmentManager,
    /// Combines public and granted segments into paths.
    pub paths: PathManager,
    /// Uplinks towards the WAGs, keyed by the (path, WAG) pair they were established for.
    pub uplinks: UplinkManager<EstablisherType>,
}
impl<T: UplinkEstablisher> WapControlPlane<T> {
    /// Creates a new WAP control plane.
    pub fn new(
        grant: GrantManager,
        segments: SegmentManager,
        paths: PathManager,
        uplinks: UplinkManager<T>,
    ) -> Self {
        Self {
            grant,
            segments,
            paths,
            uplinks,
        }
    }

    /// Runs the maintenance loops of every component that has one.
    ///
    /// Never returns, unless one of the loops panics.
    pub async fn run(&self) {
        tokio::join!(self.grant.run(), self.segments.run(), self.uplinks.run());
    }
}

impl<T: UplinkEstablisher> Clone for WapControlPlane<T> {
    fn clone(&self) -> Self {
        Self {
            grant: self.grant.clone(),
            segments: self.segments.clone(),
            paths: self.paths.clone(),
            uplinks: self.uplinks.clone(),
        }
    }
}
