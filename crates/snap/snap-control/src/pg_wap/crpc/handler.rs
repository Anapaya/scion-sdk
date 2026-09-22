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

//! The handler that serves the WAP control API.

use std::{net::IpAddr, time::SystemTime};

use crate::pg_wap::{
    crpc::model::{
        AuthorizeTargetsError, AuthorizeTargetsRequest, AuthorizeTargetsResponse,
        ControlServiceAPIHandler,
    },
    grants::{AuthorizeError, GrantManager},
};

/// Serves the `anapaya.wap.v1.WapControl` service of one WAP.
///
/// A grant is only valid on the WAP that handed it out, so every response carries the identity of
/// this WAP next to the grant: the id the client addresses it with in the SNI, and the port its
/// data plane listens on.
pub struct WapControlHandler {
    /// Hands out the grants this handler reports.
    grant: GrantManager,
    /// The id of this WAP.
    wap_id: String,
    /// The port the data plane of this WAP listens on.
    data_plane_port: u16,
}

impl WapControlHandler {
    /// Creates a handler that grants on `grant` and reports this WAP as `wap_id`.
    ///
    /// `data_plane_port` is the port the WAP TCP proxy listens on, so take it from the address the
    /// proxy binds.
    pub fn new(grant: GrantManager, wap_id: String, data_plane_port: u16) -> Self {
        Self {
            grant,
            wap_id,
            data_plane_port,
        }
    }
}

impl ControlServiceAPIHandler for WapControlHandler {
    fn authorize_targets(
        &self,
        client_ip: IpAddr,
        request: AuthorizeTargetsRequest,
        now: SystemTime,
    ) -> Result<AuthorizeTargetsResponse, AuthorizeTargetsError> {
        let expiry_time = self
            .grant
            .authorize(client_ip, request.targets, now)
            .map_err(|err| {
                let message = err.to_string();

                match err {
                    // The request is over a limit on its own, so it never fits. The client has to
                    // ask for less.
                    AuthorizeError::TooManySegmentsInRequest { .. }
                    | AuthorizeError::TooManyTargetsInRequest { .. }
                    | AuthorizeError::TooManySegmentsForTarget { .. }
                    | AuthorizeError::TooManyTargetsForIp { .. } => {
                        AuthorizeTargetsError::InvalidRequest(message)
                    }
                    // Grants that are in use hold the room the request needs. The same request
                    // fits once they are gone.
                    AuthorizeError::TargetGrantLimitReached { .. }
                    | AuthorizeError::IpTargetLimitReached { .. } => {
                        AuthorizeTargetsError::LimitReached(message)
                    }
                }
            })?;

        Ok(AuthorizeTargetsResponse {
            client_ip,
            wap_id: self.wap_id.clone(),
            data_plane_port: self.data_plane_port,
            expiry_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::Ipv4Addr,
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;
    use crate::pg_wap::{
        crpc::model::AuthSegments, grants::GrantManagerConfig, sni::CustomerDomain,
    };

    const GRANT_DURATION: Duration = Duration::from_secs(100);
    const WAP_ID: &str = "wap-1";
    const DATA_PLANE_PORT: u16 = 8443;

    /// A handler over a grant manager that grants for [`GRANT_DURATION`], with `max_targets` per
    /// request.
    fn handler(max_targets: usize) -> WapControlHandler {
        let grant = GrantManager::new(GrantManagerConfig {
            grant_duration: GRANT_DURATION,
            max_targets_per_request: max_targets,
            ..GrantManagerConfig::default()
        })
        .expect("a valid GrantManagerConfig");

        WapControlHandler::new(grant, WAP_ID.to_owned(), DATA_PLANE_PORT)
    }

    /// A request for `count` targets, each without private segments.
    fn request(count: usize) -> AuthorizeTargetsRequest {
        AuthorizeTargetsRequest {
            targets: (0..count)
                .map(|i| {
                    (
                        CustomerDomain::new(format!("target{i}.example.com"))
                            .expect("a valid domain"),
                        AuthSegments::default(),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn response_carries_the_wap_and_the_granted_expiry() {
        let client_ip = Ipv4Addr::new(192, 0, 2, 1).into();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        let response = handler(10)
            .authorize_targets(client_ip, request(1), now)
            .expect("the grant fits");

        assert_eq!(response.client_ip, client_ip);
        assert_eq!(response.wap_id, WAP_ID);
        assert_eq!(response.data_plane_port, DATA_PLANE_PORT);
        assert_eq!(response.expiry_time, now + GRANT_DURATION);
    }

    #[test]
    fn a_request_over_a_limit_is_invalid() {
        let err = handler(1)
            .authorize_targets(
                Ipv4Addr::new(192, 0, 2, 1).into(),
                request(2),
                SystemTime::now(),
            )
            .expect_err("two targets do not fit");

        assert!(matches!(err, AuthorizeTargetsError::InvalidRequest(_)));
    }
}
