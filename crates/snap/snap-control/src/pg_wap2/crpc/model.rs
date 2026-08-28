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

//! Models of the WAP control plane API, and the trait that serves them.
//!
//! There is one model per message of the `anapaya.wap.v1.WapControl` service. A model is the
//! parsed and validated form of its message: domains are [`CustomerDomain`]s, segments are
//! [`SignedPathSegment`]s and timestamps are [`SystemTime`]s, so a
//! [`ControlServiceAPIHandler`] never sees an unvalidated string or an untyped number.

use std::{collections::BTreeMap, net::IpAddr, time::SystemTime};

use sciparse::segment::SignedPathSegment;

use crate::pg_wap2::sni::CustomerDomain;

/// A request to authorize a client for a set of targets.
///
/// The model of `anapaya.wap.v1.AuthorizeTargetsRequest`.
#[derive(Debug)]
pub struct AuthorizeTargetsRequest {
    /// The targets to authorize, with the private segments granted towards each of them.
    ///
    /// The key is the customer domain of the target, i.e. the part of the SNI that follows the
    /// WAP ID and the namespace. A client cannot know the WAP ID it has to use before it has the
    /// response to this request, and grants are held per customer domain, see
    /// [`AuthService::authorize`](crate::pg_wap2::auth::AuthService::authorize).
    pub targets: BTreeMap<CustomerDomain, AuthSegments>,
}

/// The private segments granted towards one target.
///
/// The model of `anapaya.wap.v1.AuthSegments`. The segments a client grants here are the ones
/// the WAP cannot look up itself, typically because they come from a Hidden Segment Directory.
///
/// The three kinds are kept apart because that is how a client obtains them. The grants they turn
/// into only distinguish core from non-core segments, see
/// [`GrantedSegmentId`](crate::pg_wap2::auth::GrantedSegmentId).
#[derive(Debug, Default)]
pub struct AuthSegments {
    /// The up segments granted for the target.
    pub up_segments: Vec<SignedPathSegment>,
    /// The down segments granted for the target.
    pub down_segments: Vec<SignedPathSegment>,
    /// The core segments granted for the target.
    pub core_segments: Vec<SignedPathSegment>,
}

impl AuthSegments {
    /// The number of segments granted here, over all three kinds.
    pub fn count(&self) -> usize {
        self.up_segments.len() + self.down_segments.len() + self.core_segments.len()
    }
}

/// The grant handed out in response to an [`AuthorizeTargetsRequest`].
///
/// The model of `anapaya.wap.v1.AuthorizeTargetsResponse`.
#[derive(Debug)]
pub struct AuthorizeTargetsResponse {
    /// The IP address the grant was handed out for, reflected back to the client.
    pub client_ip: IpAddr,
    /// The ID of the WAP that handled the request.
    ///
    /// The grant is only valid on this WAP, so the client has to address it in the SNI of the
    /// data plane connections that follow, see [`WapSNI`](crate::pg_wap2::sni::WapSNI).
    pub wap_id: String,
    /// The port the data plane of that WAP listens on.
    pub data_plane_port: u16,
    /// When the grant expires, i.e. by when the client has to have authorized again.
    pub expiry_time: SystemTime,
}

/// The failures a [`ControlServiceAPIHandler`] reports.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizeTargetsError {
    /// The client has to send a different request.
    #[error("{0}")]
    InvalidRequest(String),
    /// The client is over a grant limit.
    #[error("{0}")]
    LimitReached(String),
    /// Internal error. The endpoint logs it and returns a fixed message.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Serves the requests of the `anapaya.wap.v1.WapControl` service.
///
/// Implemented by the WAP control plane and served by
/// [`nest_crpc_api`](super::api::nest_crpc_api).
pub trait ControlServiceAPIHandler: Send + Sync {
    /// Authorizes `client_ip` for the targets and segments of `request`, as of `now`.
    ///
    /// `client_ip` is the address the request arrived from, not one the request itself names, so a
    /// client cannot ask for a grant on somebody else's address.
    ///
    /// Grants are additive and are never shortened, so a client refreshes its authorization by
    /// calling this again before the returned expiry, see
    /// [`AuthService::authorize`](crate::pg_wap2::auth::AuthService::authorize).
    ///
    /// Returned error carries an HTTP status code and a human-readable message.
    fn authorize_targets(
        &self,
        client_ip: IpAddr,
        request: AuthorizeTargetsRequest,
        now: SystemTime,
    ) -> Result<AuthorizeTargetsResponse, AuthorizeTargetsError>;
}
