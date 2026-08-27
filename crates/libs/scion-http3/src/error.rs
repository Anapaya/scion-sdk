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

//! The error taxonomy of the HTTP/3 client.
//!
//! All request-path operations ([`Client::request`](crate::Client::request)
//! and friends, and body collection on [`Response`](crate::Response)) share
//! one failure domain and therefore one error type, [`Error`]: whatever the
//! operation, the caller's decisions are the same, i.e., retry, fix the request,
//! or give up, and [`Error::is_retryable`] answers the first one directly.
//! Constructing a [`Request`](crate::Request) is the exception. It fails with
//! the more specific [`BuildRequestError`] before any I/O happens.

use std::{borrow::Cow, error::Error as StdError, fmt, time::Duration};

use scion_quic::{
    h3::client::{
        CollectError, CollectToStringError, EstablishError, RequestError as H3RequestError,
    },
    reexport::squiche,
};
use scion_stack::{resolver::ResolveError, stack::ScionSocketBindError};

/// The phase of a request during which a timeout fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutPhase {
    /// Establishing a connection to the origin (bounded by
    /// [`Config::with_connect_timeout`](crate::Config::with_connect_timeout)).
    Connect,
    /// Waiting for the response head (bounded by
    /// [`Config::with_request_timeout`](crate::Config::with_request_timeout)
    /// or the per-request override).
    Request,
    /// Collecting the response body (bounded by the remainder of the request
    /// timeout).
    ///
    /// That remainder shrinks while the caller holds the
    /// [`Response`](crate::Response), so this can also mean "the response was
    /// held too long before being collected" rather than "the body was slow".
    Body,
}

impl fmt::Display for TimeoutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutPhase::Connect => write!(f, "connect"),
            TimeoutPhase::Request => write!(f, "request"),
            TimeoutPhase::Body => write!(f, "response body collection"),
        }
    }
}

/// Any failure on the request path.
///
/// The variants follow the phases of a request: building connectivity,
/// resolving the origin, connecting to it, and exchanging the request and
/// response. [`is_retryable`](Self::is_retryable) classifies each error once,
/// so callers branch on that instead of re-deriving the answer from the
/// variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Building SCION connectivity (the stack or the resolver) failed.
    #[error("failed to build SCION connectivity")]
    StackBuild {
        /// Whether retrying may succeed (all underlying failures were
        /// transient).
        retryable: bool,
        /// The underlying cause.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// SCION name resolution for the origin's host failed: the DNS lookup
    /// itself failed, or the host has no valid TSAR TXT records.
    #[error("SCION name resolution failed for {host}")]
    Resolution {
        /// The host that failed to resolve.
        host: String,
        /// Whether retrying may succeed (the lookup failed, as opposed to the
        /// host having no valid records).
        retryable: bool,
        /// The underlying resolver error.
        #[source]
        source: ResolveError,
    },
    /// No connection to the origin could be established: every candidate
    /// address failed with a socket, QUIC, or handshake error.
    #[error("could not connect to {host}:{port}")]
    Connect {
        /// The origin's host.
        host: String,
        /// The origin's port.
        port: u16,
        /// The underlying cause(s).
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The TLS layer rejected the origin: every candidate negotiated an ALPN
    /// other than HTTP/3.
    ///
    /// A certificate that fails to validate does *not* land here: the transport
    /// reports it as a failed handshake, indistinguishable from an unreachable
    /// peer, so it surfaces as [`Connect`](Self::Connect).
    #[error("TLS failure connecting to {host}")]
    Tls {
        /// The origin's host (the certificate-validation identity).
        host: String,
        /// The underlying cause.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The peer reset the request stream.
    #[error("stream reset by peer (code {code})")]
    StreamReset {
        /// The HTTP/3 application error code carried by the reset.
        code: u64,
    },
    /// An HTTP/3 protocol violation occurred on an established connection.
    #[error("HTTP/3 protocol error")]
    Protocol {
        /// The underlying cause.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The peer's concurrent-stream limit is exhausted; the request was never
    /// sent.
    #[error("peer's concurrent stream limit reached")]
    ConnectionLimit,
    /// The response body exceeded the size limit passed to
    /// [`Response::bytes`](crate::Response::bytes) or
    /// [`Response::text`](crate::Response::text).
    #[error("response body exceeded {limit} bytes")]
    BodyTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A deadline expired.
    #[error("{phase} timed out after {timeout:?}")]
    Timeout {
        /// The phase of the request that timed out.
        phase: TimeoutPhase,
        /// The deadline that expired.
        timeout: Duration,
    },
    /// The response body is not valid UTF-8 (only from
    /// [`Response::text`](crate::Response::text)).
    #[error("response body is not valid UTF-8")]
    InvalidBody {
        /// The underlying UTF-8 error.
        #[source]
        source: std::string::FromUtf8Error,
    },
    /// The request is invalid (malformed URL, unsupported scheme, missing
    /// host, or an invalid header).
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// What is wrong with the request.
        reason: Cow<'static, str>,
    },
    /// The client has been closed with [`Client::close`](crate::Client::close).
    #[error("client is closed")]
    Closed,
}

impl Error {
    /// Whether retrying the request may succeed.
    ///
    /// Transient conditions (connectivity, timeouts, stream resets, stream
    /// limits) are retryable. Deterministic ones (TLS rejection, protocol
    /// violations, invalid requests, oversized bodies, a closed client) are
    /// not. For [`StackBuild`](Self::StackBuild) and
    /// [`Resolution`](Self::Resolution) the answer is decided when the error
    /// is constructed, from the transience of the underlying failures.
    ///
    /// A retryable error never implies the request did not reach the server:
    /// only the caller knows whether its request is idempotent.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::StackBuild { retryable, .. } | Error::Resolution { retryable, .. } => *retryable,
            Error::Connect { .. }
            | Error::StreamReset { .. }
            | Error::ConnectionLimit
            | Error::Timeout { .. } => true,
            Error::Tls { .. }
            | Error::Protocol { .. }
            | Error::BodyTooLarge { .. }
            | Error::InvalidBody { .. }
            | Error::InvalidRequest { .. }
            | Error::Closed => false,
        }
    }

    /// Maps a transport-level request error to the taxonomy, attributing
    /// connection-level failures to `host:port`.
    pub(crate) fn from_h3_request_error(host: &str, port: u16, err: H3RequestError) -> Error {
        match err {
            H3RequestError::Establish(e) => {
                Error::from_attempt_errors(host, port, vec![AttemptError::Establish(e)])
            }
            H3RequestError::Reset(code) => Error::StreamReset { code },
            // Both shapes mean the same thing to the caller: the peer's
            // concurrent-stream limit has no room for this request.
            H3RequestError::StreamBlocked
            | H3RequestError::H3(squiche::h3::Error::TransportError(squiche::Error::StreamLimit)) => {
                Error::ConnectionLimit
            }
            H3RequestError::H3(_) => {
                Error::Protocol {
                    source: Box::new(err),
                }
            }
            H3RequestError::ConnectionClosed | H3RequestError::LocallyClosed => {
                Error::Connect {
                    host: host.to_string(),
                    port,
                    source: Box::new(err),
                }
            }
        }
    }

    /// Maps the failures of an attempt sequence to the taxonomy: TLS-level
    /// rejections become [`Error::Tls`], everything else [`Error::Connect`].
    ///
    /// The classification is deliberately unanimous rather than "any": one
    /// candidate rejecting the ALPN says nothing about the others, which may
    /// have failed for transient reasons and may well work on a retry. Only
    /// when *every* candidate rejected us is the failure deterministic, and
    /// therefore not worth retrying.
    pub(crate) fn from_attempt_errors(host: &str, port: u16, errors: Vec<AttemptError>) -> Error {
        // XXX(shitz): A chain that fails against the trust anchors should be an
        // `Error::Tls` too, but cannot be recognized here: scion-quic's
        // handshake loop discards the cause and reports
        // `EstablishError::Handshake`, which is what an unreachable peer also
        // produces. Such failures are therefore reported as retryable
        // `Error::Connect`. A chain that a caller-supplied verifier refuses is
        // recognized, because that path keeps its cause.
        let all_tls = !errors.is_empty()
            && errors.iter().all(|e| {
                matches!(
                    e,
                    AttemptError::Establish(
                        EstablishError::AlpnMismatch | EstablishError::CertificateRejected(_)
                    )
                )
            });
        let source = Box::new(AllAttemptsFailed { errors });
        if all_tls {
            Error::Tls {
                host: host.to_string(),
                source,
            }
        } else {
            Error::Connect {
                host: host.to_string(),
                port,
                source,
            }
        }
    }

    /// Maps a resolver error to [`Error::Resolution`], taking retryability from
    /// the resolver's own classification: a failed lookup may succeed later, a
    /// host without valid TSAR records will not.
    pub(crate) fn from_resolve_error(host: &str, err: ResolveError) -> Error {
        let retryable = err.is_transient();
        Error::Resolution {
            host: host.to_string(),
            retryable,
            source: err,
        }
    }

    /// Maps a body-collection error to the taxonomy.
    pub(crate) fn from_collect_error(err: CollectError, limit: Option<usize>) -> Error {
        match err {
            CollectError::TooLarge => {
                Error::BodyTooLarge {
                    limit: limit.unwrap_or(usize::MAX),
                }
            }
            _ => {
                Error::Protocol {
                    source: Box::new(err),
                }
            }
        }
    }

    /// Maps a body-to-string collection error to the taxonomy.
    pub(crate) fn from_collect_to_string_error(
        err: CollectToStringError,
        limit: Option<usize>,
    ) -> Error {
        match err {
            CollectToStringError::TooLarge => {
                Error::BodyTooLarge {
                    limit: limit.unwrap_or(usize::MAX),
                }
            }
            CollectToStringError::Utf8(source) => Error::InvalidBody { source },
            CollectToStringError::H3(_) => {
                Error::Protocol {
                    source: Box::new(err),
                }
            }
        }
    }
}

impl From<BuildRequestError> for Error {
    /// An invalid request is an [`Error::InvalidRequest`], so the convenience
    /// entry points ([`Client::get`](crate::Client::get),
    /// [`Client::post`](crate::Client::post)) report builder failures through
    /// the same taxonomy as the rest of the request path.
    fn from(error: BuildRequestError) -> Self {
        Error::InvalidRequest {
            reason: error.to_string().into(),
        }
    }
}

/// One failed connection attempt: binding the socket, or establishing the
/// connection over it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AttemptError {
    /// Binding a fresh socket for the attempt failed.
    #[error("binding a socket failed")]
    Bind(#[source] ScionSocketBindError),
    /// Establishing the connection failed.
    #[error("establishing the connection failed")]
    Establish(#[source] EstablishError),
}

/// Aggregate of the failures of one attempt sequence, in completion order.
/// The [`Error::Connect`] / [`Error::Tls`] source when every candidate
/// failed.
#[derive(Debug)]
struct AllAttemptsFailed {
    errors: Vec<AttemptError>,
}

impl fmt::Display for AllAttemptsFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "all {} connection attempt(s) failed: ",
            self.errors.len()
        )?;
        for (i, err) in self.errors.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

impl StdError for AllAttemptsFailed {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.errors.first().map(|e| e as &(dyn StdError + 'static))
    }
}

/// A [`Request`](crate::Request) could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildRequestError {
    /// No URL was provided to the builder.
    #[error("no URL was provided")]
    MissingUrl,
    /// The URL could not be parsed.
    #[error("invalid URL")]
    InvalidUrl {
        /// The underlying parse error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The URL's scheme is not `https`. This is an HTTP/3-only client;
    /// requests are never sent over cleartext or fall back to TCP.
    #[error("unsupported URL scheme `{scheme}`, only `https` is supported")]
    UnsupportedScheme {
        /// The offending scheme.
        scheme: String,
    },
    /// The URL has no host.
    #[error("URL has no host")]
    MissingHost,
    /// The URL contains userinfo (`user:password@host`). HTTP/3 forbids
    /// userinfo in `:authority` (RFC 9114 §4.3.1), and sending it would leak
    /// the credentials on the wire; pass credentials in an `authorization`
    /// header instead.
    #[error("URL must not contain userinfo (credentials)")]
    UserinfoNotAllowed,
    /// A header name or value is invalid.
    #[error("invalid header")]
    InvalidHeader {
        /// The underlying cause.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// An empty target list was provided. Targets assert "resolution returned
    /// exactly this", and an empty resolution result is an error, not a
    /// wildcard.
    #[error("target list must not be empty")]
    EmptyTargets,
}

#[cfg(test)]
mod tests {
    use scion_quic::quic::cert_verifier::CertRejected;

    use super::*;

    #[test]
    fn retryable_classification() {
        let retryable = [
            Error::StackBuild {
                retryable: true,
                source: "boom".into(),
            },
            Error::Connect {
                host: "example.org".into(),
                port: 443,
                source: "boom".into(),
            },
            Error::StreamReset { code: 0x10c },
            Error::ConnectionLimit,
            Error::Timeout {
                phase: TimeoutPhase::Request,
                timeout: Duration::from_secs(1),
            },
        ];
        for err in retryable {
            assert!(err.is_retryable(), "{err}");
        }

        let not_retryable = [
            Error::StackBuild {
                retryable: false,
                source: "boom".into(),
            },
            Error::Tls {
                host: "example.org".into(),
                source: "boom".into(),
            },
            Error::Protocol {
                source: "boom".into(),
            },
            Error::BodyTooLarge { limit: 16 },
            Error::InvalidRequest {
                reason: "bad".into(),
            },
            Error::Closed,
        ];
        for err in not_retryable {
            assert!(!err.is_retryable(), "{err}");
        }
    }

    #[test]
    fn resolution_retryability_follows_failure_kind() {
        let lookup = Error::from_resolve_error(
            "example.org",
            ResolveError::DnsLookup("timed out".to_string()),
        );
        assert!(lookup.is_retryable());

        let no_entries = Error::from_resolve_error(
            "example.org",
            ResolveError::NoValidEntries {
                domain: "example.org".to_string(),
                invalid_entries: vec![],
            },
        );
        assert!(!no_entries.is_retryable());
    }

    #[test]
    fn establish_errors_map_to_tls_only_when_uniform() {
        let tls = Error::from_attempt_errors(
            "example.org",
            443,
            vec![
                AttemptError::Establish(EstablishError::AlpnMismatch),
                AttemptError::Establish(EstablishError::AlpnMismatch),
            ],
        );
        assert!(matches!(tls, Error::Tls { .. }));

        let mixed = Error::from_attempt_errors(
            "example.org",
            443,
            vec![
                AttemptError::Establish(EstablishError::AlpnMismatch),
                AttemptError::Establish(EstablishError::Handshake),
            ],
        );
        assert!(matches!(mixed, Error::Connect { .. }));
    }

    #[test]
    fn a_rejected_certificate_is_a_tls_error() {
        // A verifier that refuses the chain refuses it again on a retry, so the
        // failure is deterministic rather than a connect failure to retry.
        let rejected = Error::from_attempt_errors(
            "example.org",
            443,
            vec![AttemptError::Establish(
                EstablishError::CertificateRejected(CertRejected::new("not the pinned server")),
            )],
        );
        assert!(matches!(rejected, Error::Tls { .. }));
        assert!(!rejected.is_retryable());
        assert!(rejected.to_string().contains("example.org"));
    }

    #[test]
    fn stream_level_request_errors_do_not_become_connect() {
        let reset = Error::from_h3_request_error("example.org", 443, H3RequestError::Reset(7));
        assert!(matches!(reset, Error::StreamReset { code: 7 }));

        let blocked =
            Error::from_h3_request_error("example.org", 443, H3RequestError::StreamBlocked);
        assert!(matches!(blocked, Error::ConnectionLimit));
    }
}
