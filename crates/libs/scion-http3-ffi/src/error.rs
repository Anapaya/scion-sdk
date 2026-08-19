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

//! The error taxonomy that crosses the boundary, and the mapping onto it.
//!
//! [`ScionHttp3Error`] mirrors [`scion_http3::Error`] one for one, so that the foreign sealed
//! hierarchy above it is a rename rather than a reinterpretation. This module holds the whole
//! mapping; no other layer, in any language, decides what an error means.

use std::{error::Error as StdError, fmt::Write as _, time::Duration};

use scion_http3::{BuildRequestError, TimeoutPhase as Http3TimeoutPhase};

/// Short name for [`ScionHttp3Error`] within the crate. The exported type needs the prefix, because
/// UniFFI turns a Rust `Error` suffix into a foreign `Exception` one and an unprefixed one would
/// collide with the platform's own.
pub(crate) type Error = ScionHttp3Error;

/// The phase of a request in which a deadline expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TimeoutPhase {
    /// Establishing a connection to the origin.
    Connect,
    /// Waiting for the response head.
    Request,
    /// Collecting the response body.
    Body,
    /// A phase this version of the bindings does not know about.
    ///
    /// [`scion_http3::TimeoutPhase`] is `#[non_exhaustive]`, so a newer client can name a phase
    /// this enum cannot. Reporting that plainly beats picking the nearest-looking neighbour.
    Other,
}

impl From<Http3TimeoutPhase> for TimeoutPhase {
    fn from(phase: Http3TimeoutPhase) -> Self {
        match phase {
            Http3TimeoutPhase::Connect => TimeoutPhase::Connect,
            Http3TimeoutPhase::Request => TimeoutPhase::Request,
            Http3TimeoutPhase::Body => TimeoutPhase::Body,
            other => {
                debug_assert!(false, "unmapped scion_http3::TimeoutPhase: {other:?}");
                TimeoutPhase::Other
            }
        }
    }
}

/// Any failure an exported operation can report.
///
/// Every variant carries `retryable`, taken from [`scion_http3::Error::is_retryable`] and never
/// re-derived here, and `detail`, which is the error's own message followed by its whole source
/// chain. `detail` is not decoration: several variants say almost nothing on their own
/// (`Connect`'s message is just the origin it failed to reach), and the causes that make them
/// actionable live in sources the foreign side cannot walk.
///
/// The field is called `detail` rather than `message` deliberately: at least one target's generated
/// error class declares `message` itself (Kotlin's does), and a field of that name does not compile
/// there. The name is shared, so the tightest constraint decides it.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ScionHttp3Error {
    /// Building SCION connectivity (the stack or the resolver) failed.
    #[error("failed to build SCION connectivity: {detail}")]
    StackBuild {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// SCION name resolution failed for the request's host.
    #[error("SCION name resolution failed for {host}: {detail}")]
    Resolution {
        /// The host that failed to resolve.
        host: String,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// No connection to the origin could be established.
    #[error("could not connect to {host}:{port}: {detail}")]
    Connect {
        /// The origin's host.
        host: String,
        /// The origin's port.
        port: u16,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The TLS layer rejected the origin.
    #[error("TLS failure connecting to {host}: {detail}")]
    Tls {
        /// The origin's host.
        host: String,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The peer reset the request stream.
    #[error("stream reset by peer (code {code})")]
    StreamReset {
        /// The HTTP/3 application error code carried by the reset.
        code: u64,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// An HTTP/3 protocol violation occurred on an established connection.
    #[error("HTTP/3 protocol error: {detail}")]
    Protocol {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The peer's concurrent-stream limit is exhausted; the request was never sent.
    #[error("peer's concurrent stream limit reached")]
    ConnectionLimit {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The response body exceeded the limit the request carried.
    #[error("response body exceeded {limit} bytes")]
    BodyTooLarge {
        /// The limit that was exceeded.
        limit: u64,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// A deadline expired.
    #[error("{phase:?} timed out after {timeout_ms} ms")]
    Timeout {
        /// The phase of the request that timed out.
        phase: TimeoutPhase,
        /// The deadline that expired, in milliseconds.
        timeout_ms: u64,
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The request is invalid, and no I/O was attempted.
    #[error("invalid request: {detail}")]
    InvalidRequest {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// The client has been shut down.
    #[error("client is closed")]
    Closed {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
    /// A failure with no counterpart in the taxonomy above.
    ///
    /// Either a failure of the bindings themselves (the runtime could not be built, a foreign
    /// callback failed), or a [`scion_http3::Error`] variant added after these bindings were
    /// generated: the taxonomy is `#[non_exhaustive]`, so that is possible without a compile
    /// error here. Debug builds assert instead, so the gap surfaces in a test run rather than in
    /// an application.
    #[error("{detail}")]
    Internal {
        /// Whether retrying may succeed.
        retryable: bool,
        /// The error and its source chain.
        detail: String,
    },
}

impl ScionHttp3Error {
    /// A failure of the bindings rather than of a request.
    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        ScionHttp3Error::Internal {
            retryable: false,
            detail: detail.into(),
        }
    }

    /// A request the bindings rejected before `scion-http3` ever saw it: an address, a header name
    /// or a method that does not parse.
    pub(crate) fn invalid_request(detail: impl Into<String>) -> Self {
        ScionHttp3Error::InvalidRequest {
            retryable: false,
            detail: detail.into(),
        }
    }

    /// Whether retrying the operation may succeed, whatever the variant.
    ///
    /// Only the tests need this on the Rust side: `retryable` crosses the boundary as a field of
    /// each variant, and the foreign hierarchy reads it in a `when` over its sealed classes, which
    /// is also what makes a new variant a compile error there.
    #[cfg(test)]
    pub(crate) fn retryable(&self) -> bool {
        match self {
            ScionHttp3Error::StackBuild { retryable, .. }
            | ScionHttp3Error::Resolution { retryable, .. }
            | ScionHttp3Error::Connect { retryable, .. }
            | ScionHttp3Error::Tls { retryable, .. }
            | ScionHttp3Error::StreamReset { retryable, .. }
            | ScionHttp3Error::Protocol { retryable, .. }
            | ScionHttp3Error::ConnectionLimit { retryable, .. }
            | ScionHttp3Error::BodyTooLarge { retryable, .. }
            | ScionHttp3Error::Timeout { retryable, .. }
            | ScionHttp3Error::InvalidRequest { retryable, .. }
            | ScionHttp3Error::Closed { retryable, .. }
            | ScionHttp3Error::Internal { retryable, .. } => *retryable,
        }
    }
}

impl From<scion_http3::Error> for ScionHttp3Error {
    fn from(error: scion_http3::Error) -> Self {
        use scion_http3::Error as Source;

        // Taken once, from the crate that owns the classification. Deriving it per variant here
        // would be a second opinion, and the two would drift.
        let retryable = error.is_retryable();
        let detail = detail(&error);

        match error {
            Source::StackBuild { .. } => ScionHttp3Error::StackBuild { retryable, detail },
            Source::Resolution { host, .. } => {
                ScionHttp3Error::Resolution {
                    host,
                    retryable,
                    detail,
                }
            }
            Source::Connect { host, port, .. } => {
                ScionHttp3Error::Connect {
                    host,
                    port,
                    retryable,
                    detail,
                }
            }
            Source::Tls { host, .. } => {
                ScionHttp3Error::Tls {
                    host,
                    retryable,
                    detail,
                }
            }
            Source::StreamReset { code } => {
                ScionHttp3Error::StreamReset {
                    code,
                    retryable,
                    detail,
                }
            }
            Source::Protocol { .. } => ScionHttp3Error::Protocol { retryable, detail },
            Source::ConnectionLimit => ScionHttp3Error::ConnectionLimit { retryable, detail },
            Source::BodyTooLarge { limit } => {
                ScionHttp3Error::BodyTooLarge {
                    limit: u64::try_from(limit).unwrap_or(u64::MAX),
                    retryable,
                    detail,
                }
            }
            Source::Timeout { phase, timeout } => {
                ScionHttp3Error::Timeout {
                    phase: phase.into(),
                    timeout_ms: millis(timeout),
                    retryable,
                    detail,
                }
            }
            // Upstream produces this only from `Response::text`, and nothing exported here calls
            // it: response bodies cross as bytes. Reaching this arm therefore means this crate
            // started collecting text somewhere, which is a bug in it rather than something a
            // caller can act on, so it is not a variant of its own in the foreign taxonomy.
            Source::InvalidBody { .. } => ScionHttp3Error::Internal { retryable, detail },
            Source::InvalidRequest { .. } => ScionHttp3Error::InvalidRequest { retryable, detail },
            Source::Closed => ScionHttp3Error::Closed { retryable, detail },
            // `scion_http3::Error` is `#[non_exhaustive]`, so the compiler cannot hold this table
            // to the taxonomy. Reporting an unmapped variant as itself, loudly in debug builds,
            // beats filing it under whichever existing variant looked closest.
            other => {
                debug_assert!(false, "unmapped scion_http3::Error: {other:?}");
                ScionHttp3Error::Internal { retryable, detail }
            }
        }
    }
}

impl From<BuildRequestError> for ScionHttp3Error {
    /// Goes through `scion-http3`'s own conversion, so the two crates cannot disagree about what a
    /// malformed request is.
    fn from(error: BuildRequestError) -> Self {
        scion_http3::Error::from(error).into()
    }
}

/// Renders an error as its own message followed by every message in its source chain.
fn detail(error: &(dyn StdError + 'static)) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        // Writing to a String cannot fail.
        let _ = write!(rendered, ": {cause}");
        source = cause.source();
    }
    rendered
}

/// Milliseconds, saturating rather than wrapping: `Duration::MAX` is a legal request timeout and
/// means "no deadline", which must not come back as a small number.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::string::FromUtf8Error;

    use scion_http3::Error as Source;

    use super::*;

    fn utf8_error() -> FromUtf8Error {
        String::from_utf8(vec![0xff]).expect_err("0xff is not valid UTF-8")
    }

    /// Every arm of the taxonomy, in one place, because the compiler cannot check this table:
    /// `scion_http3::Error` is `#[non_exhaustive]`, so the mapping needs a catch-all and a missing
    /// arm is silently absorbed by it. A new variant upstream fails here, or, if nobody adds it to
    /// this list, at the `debug_assert!` in the mapping itself.
    #[test]
    fn every_variant_maps_to_its_counterpart() {
        let cases: Vec<(Source, ScionHttp3Error)> = vec![
            (
                Source::StackBuild {
                    retryable: true,
                    source: "discovery failed".into(),
                },
                ScionHttp3Error::StackBuild {
                    retryable: true,
                    detail: String::new(),
                },
            ),
            (
                Source::Connect {
                    host: "example.org".into(),
                    port: 443,
                    source: "no route".into(),
                },
                ScionHttp3Error::Connect {
                    host: "example.org".into(),
                    port: 443,
                    retryable: true,
                    detail: String::new(),
                },
            ),
            (
                Source::Tls {
                    host: "example.org".into(),
                    source: "alpn mismatch".into(),
                },
                ScionHttp3Error::Tls {
                    host: "example.org".into(),
                    retryable: false,
                    detail: String::new(),
                },
            ),
            (
                Source::StreamReset { code: 0x10c },
                ScionHttp3Error::StreamReset {
                    code: 0x10c,
                    retryable: true,
                    detail: String::new(),
                },
            ),
            (
                Source::Protocol {
                    source: "frame on the wrong stream".into(),
                },
                ScionHttp3Error::Protocol {
                    retryable: false,
                    detail: String::new(),
                },
            ),
            (
                Source::ConnectionLimit,
                ScionHttp3Error::ConnectionLimit {
                    retryable: true,
                    detail: String::new(),
                },
            ),
            (
                Source::BodyTooLarge { limit: 16 },
                ScionHttp3Error::BodyTooLarge {
                    limit: 16,
                    retryable: false,
                    detail: String::new(),
                },
            ),
            (
                Source::Timeout {
                    phase: Http3TimeoutPhase::Body,
                    timeout: Duration::from_millis(1500),
                },
                ScionHttp3Error::Timeout {
                    phase: TimeoutPhase::Body,
                    timeout_ms: 1500,
                    retryable: true,
                    detail: String::new(),
                },
            ),
            // Unreachable across this boundary, so it maps onto Internal rather than a variant of
            // its own; the mapping is still asserted so the collapse is deliberate and visible.
            (
                Source::InvalidBody {
                    source: utf8_error(),
                },
                ScionHttp3Error::Internal {
                    retryable: false,
                    detail: String::new(),
                },
            ),
            (
                Source::InvalidRequest {
                    reason: "no host".into(),
                },
                ScionHttp3Error::InvalidRequest {
                    retryable: false,
                    detail: String::new(),
                },
            ),
            (
                Source::Closed,
                ScionHttp3Error::Closed {
                    retryable: false,
                    detail: String::new(),
                },
            ),
        ];

        for (source, expected) in cases {
            let rendered = source.to_string();
            let mapped = ScionHttp3Error::from(source);
            assert_eq!(
                std::mem::discriminant(&mapped),
                std::mem::discriminant(&expected),
                "{rendered} mapped to {mapped:?}"
            );
            assert_eq!(
                mapped.retryable(),
                expected.retryable(),
                "{rendered} mapped to the wrong retryability"
            );
            assert!(!detail_of(&mapped).is_empty(), "{rendered} lost its detail");
        }
    }

    /// The `Resolution` arm carries the host, and its retryability follows the resolver rather
    /// than the variant: a failed lookup may succeed later, a host without records will not.
    #[test]
    fn resolution_carries_the_host_and_the_resolvers_verdict() {
        let mapped = ScionHttp3Error::from(Source::Resolution {
            host: "chat.example.org".into(),
            retryable: false,
            source: scion_http3::scion_stack::resolver::ResolveError::NoValidEntries {
                domain: "chat.example.org".to_string(),
                invalid_entries: vec![],
            },
        });
        let ScionHttp3Error::Resolution {
            host, retryable, ..
        } = &mapped
        else {
            panic!("mapped to {mapped:?}");
        };
        assert_eq!(host, "chat.example.org");
        assert!(!retryable);
    }

    /// The whole point of `detail`: `Connect`'s own message names only the origin, so without the
    /// chain a caller is told that connecting failed and nothing else.
    #[test]
    fn detail_carries_the_source_chain() {
        let mapped = ScionHttp3Error::from(Source::Connect {
            host: "example.org".into(),
            port: 443,
            source: "all 2 connection attempt(s) failed".into(),
        });
        assert!(
            detail_of(&mapped).contains("all 2 connection attempt(s) failed"),
            "detail was {:?}",
            detail_of(&mapped)
        );
    }

    /// A malformed request must arrive as the same taxonomy the request path uses, not as a
    /// second, parallel one.
    #[test]
    fn build_failures_arrive_as_invalid_request() {
        let mapped = ScionHttp3Error::from(BuildRequestError::UnsupportedScheme {
            scheme: "http".into(),
        });
        assert!(matches!(mapped, ScionHttp3Error::InvalidRequest { .. }));
        assert!(detail_of(&mapped).contains("http"));
    }

    /// A timeout too large to represent means "no deadline"; it must not come back as a small one.
    #[test]
    fn an_unrepresentable_timeout_saturates() {
        let mapped = ScionHttp3Error::from(Source::Timeout {
            phase: Http3TimeoutPhase::Request,
            timeout: Duration::MAX,
        });
        let ScionHttp3Error::Timeout { timeout_ms, .. } = mapped else {
            panic!("mapped to {mapped:?}");
        };
        assert_eq!(timeout_ms, u64::MAX);
    }

    fn detail_of(error: &ScionHttp3Error) -> &str {
        match error {
            ScionHttp3Error::StackBuild { detail, .. }
            | ScionHttp3Error::Resolution { detail, .. }
            | ScionHttp3Error::Connect { detail, .. }
            | ScionHttp3Error::Tls { detail, .. }
            | ScionHttp3Error::StreamReset { detail, .. }
            | ScionHttp3Error::Protocol { detail, .. }
            | ScionHttp3Error::ConnectionLimit { detail, .. }
            | ScionHttp3Error::BodyTooLarge { detail, .. }
            | ScionHttp3Error::Timeout { detail, .. }
            | ScionHttp3Error::InvalidRequest { detail, .. }
            | ScionHttp3Error::Closed { detail, .. }
            | ScionHttp3Error::Internal { detail, .. } => detail,
        }
    }
}
