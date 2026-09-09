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

//! Translation between the protobuf messages of the WAP control service and their
//! [`model`](super::model)s.

use std::{collections::BTreeMap, time::UNIX_EPOCH};

use scion_protobuf::proto::control_plane::v1 as buffa_cp;
use sciparse::{rpc::FromRpcError, segment::SignedPathSegment};

use crate::{
    pg_wap2::{
        crpc::model,
        sni::{CustomerDomain, SniFormatError},
    },
    proto::anapaya::wap::v1 as rpc,
};

/// Returned when a request cannot be turned into its model.
///
/// Everything this covers is a property of the request alone, so it always means the client has
/// to send a different request rather than send this one again.
#[derive(thiserror::Error, Debug)]
pub enum ConvertError {
    /// The request authorizes nothing, which is never what the client wants.
    #[error("the request does not name a target")]
    NoTargets,
    /// A key of the target map is not a domain name.
    #[error("the target {target:?} is not a valid domain: {source}")]
    InvalidTarget {
        /// The target as it arrived.
        target: String,
        /// Why it is not a domain name.
        source: SniFormatError,
    },
    /// A granted segment could not be parsed.
    #[error("a {kind} segment granted for the target {target:?} is unusable: {source}")]
    InvalidSegment {
        /// The target the segment was granted for.
        target: String,
        /// Whether the segment was granted as an up, down or core segment.
        kind: &'static str,
        /// Why the segment could not be parsed.
        source: FromRpcError,
    },
}

impl rpc::AuthorizeTargetsRequest {
    /// Builds the model of this request.
    pub fn try_into_model(self) -> Result<model::AuthorizeTargetsRequest, ConvertError> {
        if self.targets.is_empty() {
            return Err(ConvertError::NoTargets);
        }

        let mut targets = BTreeMap::new();
        for (target, segments) in self.targets {
            let segments = segments.try_into_model(&target)?;
            let domain = CustomerDomain::new(target.clone())
                .map_err(|source| ConvertError::InvalidTarget { target, source })?;

            targets.insert(domain, segments);
        }

        Ok(model::AuthorizeTargetsRequest { targets })
    }
}

impl rpc::AuthSegments {
    /// Builds the model of the segments granted for `target`, which names them in the errors.
    ///
    /// A single unusable segment fails the whole request: the client granted it because it expects
    /// the WAP to be able to use it, so silently dropping it would hand out an authorization that
    /// cannot carry the traffic it was asked for.
    fn try_into_model(self, target: &str) -> Result<model::AuthSegments, ConvertError> {
        let Self {
            up_segments,
            down_segments,
            core_segments,
            ..
        } = self;

        Ok(model::AuthSegments {
            up_segments: parse_segments(target, "up", up_segments)?,
            down_segments: parse_segments(target, "down", down_segments)?,
            core_segments: parse_segments(target, "core", core_segments)?,
        })
    }
}

fn parse_segments(
    target: &str,
    kind: &'static str,
    segments: Vec<buffa_cp::PathSegment>,
) -> Result<Vec<SignedPathSegment>, ConvertError> {
    segments
        .into_iter()
        .map(|segment| {
            SignedPathSegment::try_from_rpc(segment).map_err(|source| {
                ConvertError::InvalidSegment {
                    target: target.to_owned(),
                    kind,
                    source,
                }
            })
        })
        .collect()
}

impl From<model::AuthorizeTargetsResponse> for rpc::AuthorizeTargetsResponse {
    fn from(response: model::AuthorizeTargetsResponse) -> Self {
        Self {
            client_ip: response.client_ip.to_string(),
            wap_id: response.wap_id,
            data_plane_port: u32::from(response.data_plane_port),
            // An expiry before the epoch cannot be expressed on the wire, and a `0` is as good a
            // stand-in as any: it is in the past either way.
            expiry_time: response
                .expiry_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::pg_wap2::test_util::{client_ip, core_segment, down_segment, sni, up_segment};

    /// A request granting `segments` for the customer domain of [`sni`].
    fn request(segments: rpc::AuthSegments) -> rpc::AuthorizeTargetsRequest {
        rpc::AuthorizeTargetsRequest {
            targets: [(sni().customer_domain().as_str().to_owned(), segments)]
                .into_iter()
                .collect(),
        }
    }

    fn fingerprints(segments: &[SignedPathSegment]) -> Vec<sciparse::segment::SegmentFp> {
        segments
            .iter()
            .map(SignedPathSegment::fingerprint)
            .collect()
    }

    #[test]
    fn a_target_is_keyed_by_its_customer_domain_and_keeps_its_segments_grouped() {
        let (up, down, core) = (up_segment(0), down_segment(0), core_segment(0));

        let converted = request(rpc::AuthSegments {
            up_segments: vec![up.clone().into_rpc()],
            down_segments: vec![down.clone().into_rpc()],
            core_segments: vec![core.clone().into_rpc()],
        })
        .try_into_model()
        .expect("the request is convertible");

        assert_eq!(
            converted.targets.keys().collect::<Vec<_>>(),
            vec![&CustomerDomain::from(sni().customer_domain())]
        );

        let granted = converted
            .targets
            .get(sni().customer_domain().as_str())
            .expect("the target is in the request");
        assert_eq!(fingerprints(&granted.up_segments), fingerprints(&[up]));
        assert_eq!(fingerprints(&granted.down_segments), fingerprints(&[down]));
        assert_eq!(fingerprints(&granted.core_segments), fingerprints(&[core]));
    }

    #[test]
    fn a_request_without_targets_is_not_convertible() {
        let err = rpc::AuthorizeTargetsRequest::default()
            .try_into_model()
            .expect_err("a request without targets is rejected");

        assert!(matches!(err, ConvertError::NoTargets), "got {err}");
    }

    #[test]
    fn a_target_that_is_not_a_domain_is_not_convertible() {
        let err = rpc::AuthorizeTargetsRequest {
            targets: [("not a domain".to_owned(), rpc::AuthSegments::default())]
                .into_iter()
                .collect(),
        }
        .try_into_model()
        .expect_err("a target that is not a domain is rejected");

        assert!(
            matches!(err, ConvertError::InvalidTarget { .. }),
            "got {err}"
        );
    }

    #[test]
    fn a_segment_that_cannot_be_parsed_is_not_convertible() {
        let err = request(rpc::AuthSegments {
            up_segments: vec![buffa_cp::PathSegment {
                segment_info: vec![0xff, 0xff],
                as_entries: Vec::new(),
            }],
            ..rpc::AuthSegments::default()
        })
        .try_into_model()
        .expect_err("an unparseable segment is rejected");

        assert!(
            matches!(err, ConvertError::InvalidSegment { kind: "up", .. }),
            "got {err}"
        );
    }

    #[test]
    fn a_response_carries_the_expiry_as_seconds_since_the_epoch() {
        let response = rpc::AuthorizeTargetsResponse::from(model::AuthorizeTargetsResponse {
            client_ip: client_ip(),
            wap_id: "wap-1".to_owned(),
            data_plane_port: 8443,
            expiry_time: UNIX_EPOCH + Duration::from_secs(1_800),
        });

        assert_eq!(
            response,
            rpc::AuthorizeTargetsResponse {
                client_ip: client_ip().to_string(),
                wap_id: "wap-1".to_owned(),
                data_plane_port: 8443,
                expiry_time: 1_800,
            }
        );
    }

    #[test]
    fn an_expiry_before_the_epoch_becomes_zero() {
        let response = rpc::AuthorizeTargetsResponse::from(model::AuthorizeTargetsResponse {
            client_ip: client_ip(),
            wap_id: "wap-1".to_owned(),
            data_plane_port: 8443,
            expiry_time: SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        });

        assert_eq!(response.expiry_time, 0);
    }
}
