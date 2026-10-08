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

//! Requests through a `CONNECT` tunnel to a PathGuard WebGateway.
//!
//! scion-http3 opens the tunnel over HTTP/3 to the gateway. The gateway sits
//! at the SCION address of the request host, so the engine dials that host
//! at the gateway port. The `CONNECT` authority is the request host and port.
//! The gateway picks the backend by that authority and splices the tunnel to
//! a TCP connection. TLS to the origin runs end to end inside the tunnel, with
//! BoringSSL through hyper-boring. hyper speaks HTTP/1.1 on top.
//!
//! The QUIC connection does not verify the gateway. The TLS session inside the
//! tunnel authenticates the origin.

use std::{
    collections::HashMap,
    fmt, io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use boring::{
    ssl::{NameType, SslAlert, SslConnector, SslMethod, SslVerifyError, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use http_body_util::{BodyExt, Full, Limited};
use hyper_boring::v1::HttpsConnector;
use hyper_util::{
    client::legacy::{
        Client as HyperClient,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo},
};
use scion_http3::{
    Authority, Client, Tunnel,
    bytes::Bytes,
    http::Uri,
    scion_quic::quic::cert_verifier::{CertVerifier, PeerCertificates},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

use super::{Request, Transport, classify_with_message, convert_headers};
use crate::{
    engine::describe_error,
    ffi::types::{CoreError, CoreHttpVersion, CoreResponse},
};

/// Where the tunnels go.
#[derive(Clone)]
pub(crate) struct GatewayConfig {
    /// The port of the gateway.
    pub(crate) port: u16,
}

impl GatewayConfig {
    /// The gateway to dial and the `CONNECT` authority for `uri`.
    fn authorities(&self, uri: &Uri) -> Result<(Authority, Authority), String> {
        // Find the target host and port.
        let host = uri.host().ok_or("the URL has no host")?;
        let port = match (uri.port_u16(), uri.scheme_str()) {
            (Some(port), _) => port,
            (None, Some("http")) => 80,
            (None, _) => 443,
        };

        // Build both authorities.
        let bad = |error| format!("bad gateway authority: {error}");
        let proxy = Authority::new(host, self.port).map_err(bad)?;
        let target = Authority::new(host, port).map_err(bad)?;
        Ok((proxy, target))
    }
}

/// How the TLS session inside the tunnel authenticates the origin.
pub(crate) enum OriginTrust {
    /// The CAs of the device, through the same verifier as HTTP/3.
    Platform(Arc<dyn CertVerifier>),
    /// These anchors alone.
    Anchors(Vec<u8>),
    /// No check. For tests only.
    None,
}

/// Sends requests through tunnels to a WebGateway.
pub(crate) struct ConnectTransport {
    /// Opens the tunnels.
    tunnels: Arc<Client>,
    hyper: HyperClient<HttpsConnector<TunnelConnector>, Full<Bytes>>,
    rejections: Rejections,
    request_timeout: Duration,
    max_body_bytes: usize,
}

impl ConnectTransport {
    /// The QUIC config of `tunnels` has to skip the peer check.
    pub(crate) fn new(
        tunnels: Arc<Client>,
        gateway: GatewayConfig,
        trust: OriginTrust,
        idle_timeout: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<Self, CoreError> {
        // Set up TLS over the tunnels.
        let rejections = Rejections::default();
        let tls = tls_connector(trust, rejections.clone())?;
        let https = HttpsConnector::with_connector(
            TunnelConnector {
                client: tunnels.clone(),
                gateway,
            },
            tls,
        )
        .map_err(|error| CoreError::invalid(format!("cannot set up TLS: {error}")))?;

        // Set up the HTTP client.
        let hyper = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(idle_timeout)
            .build(https);

        Ok(ConnectTransport {
            tunnels,
            hyper,
            rejections,
            request_timeout,
            max_body_bytes,
        })
    }
}

#[async_trait]
impl Transport for ConnectTransport {
    async fn send(&self, request: Request) -> Result<CoreResponse, CoreError> {
        // Unpack the request.
        let host = request.host().to_owned();
        let Request {
            http,
            timeout: override_timeout,
        } = request;
        let request = http.map(Full::new);
        let max_body_bytes = self.max_body_bytes;

        // Send it and collect the response.
        let exchange = async {
            // Send the request.
            let response = self
                .hyper
                .request(request)
                .await
                .map_err(|error| self.classify(&host, &error))?;

            // Collect the response.
            let status = response.status().as_u16();
            let headers = convert_headers(response.headers());
            let body = Limited::new(response.into_body(), max_body_bytes)
                .collect()
                .await
                .map_err(|error| body_error(&*error, max_body_bytes))?
                .to_bytes();

            Ok(CoreResponse {
                status,
                version: CoreHttpVersion::Http11,
                headers,
                body: body.to_vec(),
            })
        };

        let timeout = override_timeout.unwrap_or(self.request_timeout);
        let response = tokio::time::timeout(timeout, exchange)
            .await
            .unwrap_or_else(|_| {
                Err(CoreError::Timeout {
                    message: format!("no response within {timeout:?}"),
                })
            });
        return response;

        fn body_error(
            error: &(dyn std::error::Error + Send + Sync + 'static),
            limit: usize,
        ) -> CoreError {
            if error.is::<http_body_util::LengthLimitError>() {
                CoreError::BodyTooLarge {
                    message: format!("the body is larger than {limit} bytes"),
                }
            } else {
                CoreError::Protocol {
                    message: describe_error(error),
                }
            }
        }
    }

    async fn close(&self) {
        self.tunnels.close().await;
    }
}

impl ConnectTransport {
    fn classify(&self, host: &str, error: &hyper_util::client::legacy::Error) -> CoreError {
        // Start with the full error chain.
        let mut message = describe_error(error);

        // Classify by the first known cause.
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            // The tunnel itself failed. scion-http3 says why.
            if let Some(tunnel) = cause.downcast_ref::<scion_http3::Error>() {
                return classify_with_message(tunnel, message);
            }

            // TLS failed. Add the reason of the verifier.
            if cause.is::<tokio_boring::HandshakeError<TunnelStream>>() {
                if let Some(reason) = self.rejections.take(host) {
                    message.push_str(": ");
                    message.push_str(&reason);
                }
                return CoreError::Tls { message };
            }

            source = cause.source();
        }

        // No known cause. Use the hyper error kind.
        if error.is_connect() {
            return CoreError::Connect { message };
        }
        CoreError::Protocol { message }
    }
}

/// The TLS client for the origin. ALPN offers HTTP/1.1 only.
fn tls_connector(
    trust: OriginTrust,
    rejections: Rejections,
) -> Result<boring::ssl::SslConnectorBuilder, CoreError> {
    let setup = |error: boring::error::ErrorStack| {
        CoreError::invalid(format!("cannot set up TLS: {error}"))
    };

    // Offer HTTP/1.1 only.
    let mut tls = SslConnector::builder(SslMethod::tls()).map_err(setup)?;
    tls.set_alpn_protos(b"\x08http/1.1").map_err(setup)?;

    match trust {
        OriginTrust::None => tls.set_verify(SslVerifyMode::NONE),
        OriginTrust::Anchors(pem) => {
            // Parse the anchors.
            let certificates = X509::stack_from_pem(&pem)
                .map_err(|error| CoreError::invalid(format!("bad origin anchors: {error}")))?;
            if certificates.is_empty() {
                return Err(CoreError::invalid(
                    "the origin anchors hold no certificate".into(),
                ));
            }

            // Trust only the anchors.
            let mut store = X509StoreBuilder::new().map_err(setup)?;
            for certificate in certificates {
                store.add_cert(certificate).map_err(setup)?;
            }
            tls.set_cert_store_builder(store);
        }
        OriginTrust::Platform(verifier) => {
            tls.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                // Collect the chain as DER.
                let chain: Vec<Vec<u8>> = ssl
                    .peer_cert_chain()
                    .into_iter()
                    .flatten()
                    .filter_map(|certificate| certificate.to_der().ok())
                    .collect();
                let borrowed_chain: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
                if borrowed_chain.is_empty() {
                    return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                }

                // Ask the platform verifier.
                let server_name = ssl.servername(NameType::HOST_NAME);
                verifier
                    .verify(&PeerCertificates::new(&borrowed_chain, server_name))
                    .map_err(|rejected| {
                        rejections.record(server_name.unwrap_or_default(), &rejected);
                        SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
                    })
            });
        }
    }

    Ok(tls)
}

/// The reason the platform verifier gave for the last rejection, per host.
///
/// BoringSSL reports only a failed handshake. This carries the reason to the
/// error of the request.
#[derive(Clone, Default)]
struct Rejections(Arc<Mutex<HashMap<String, String>>>);

impl Rejections {
    fn record(&self, host: &str, rejected: &dyn std::error::Error) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(host.to_owned(), describe_error(rejected));
    }

    fn take(&self, host: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(host)
    }
}

/// Opens a tunnel to the gateway for each new connection of hyper.
#[derive(Clone)]
struct TunnelConnector {
    client: Arc<Client>,
    gateway: GatewayConfig,
}

impl Service<Uri> for TunnelConnector {
    type Response = TokioIo<TunnelStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let client = self.client.clone();
        let authorities = self.gateway.authorities(&uri);

        Box::pin(async move {
            let (proxy, target) = authorities?;
            let tunnel = client.connect_via(&proxy, &target).await?;
            Ok(TokioIo::new(TunnelStream(tunnel)))
        })
    }
}

/// A [`Tunnel`] as hyper-boring wants it.
struct TunnelStream(Tunnel);

impl Connection for TunnelStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl fmt::Debug for TunnelStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TunnelStream").field(&self.0).finish()
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    //! Tests of the bridge from BoringSSL to the platform verifier.
    //!
    //! With [`OriginTrust::Platform`], [`tls_connector`] replaces the
    //! certificate check of BoringSSL with a callback. The callback hands the
    //! chain and the server name to a [`CertVerifier`](super::CertVerifier).
    //! These tests put a stand-in verifier in place of the platform one, so
    //! that they do not depend on the CAs of the machine. They run one
    //! handshake against a local BoringSSL server and check what the
    //! stand-in receives and what its verdict does.
    //!
    //! `thePlatformTrustRejectsTheTestCa` in `WebGatewayTest` runs the real
    //! platform verifier through a tunnel.

    use std::sync::{Arc, Mutex};

    use boring::{
        pkey::PKey,
        ssl::{SslAcceptor, SslMethod},
        x509::X509,
    };
    use scion_http3::scion_quic::quic::cert_verifier::{CertRejected, PeerCertificates};

    use super::{OriginTrust, Rejections, tls_connector};

    /// The host that the client connects to, and the name in the leaf.
    const HOST: &str = "localhost";

    /// The certificates of the test server, as DER.
    struct Chain {
        /// A self-signed CA.
        ca: Vec<u8>,
        /// The certificate of the server for [`HOST`], signed by the CA.
        leaf: Vec<u8>,
        /// The private key of the leaf.
        leaf_key: Vec<u8>,
    }

    impl Chain {
        fn generate() -> Self {
            // Create the CA.
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca =
                rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
                    .unwrap();

            // Create the leaf.
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let leaf = rcgen::CertificateParams::new(vec![HOST.to_owned()])
                .unwrap()
                .signed_by(&leaf_key, &ca)
                .unwrap();

            Chain {
                ca: ca.der().to_vec(),
                leaf: leaf.der().to_vec(),
                leaf_key: leaf_key.serialize_der(),
            }
        }
    }

    /// What the stand-in verifier received.
    struct Seen {
        chain: Vec<Vec<u8>>,
        server_name: Option<String>,
    }

    /// Runs one TLS handshake between a client from [`tls_connector`] with
    /// `trust`, and a server that sends the leaf and the CA of `chain`.
    /// Returns whether the client accepted the server.
    async fn handshake(chain: &Chain, trust: OriginTrust, rejections: Rejections) -> bool {
        // The server sends the leaf first, then the CA, as a real server does.
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_der(&chain.leaf).unwrap())
            .unwrap();
        acceptor
            .add_extra_chain_cert(X509::from_der(&chain.ca).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_der(&chain.leaf_key).unwrap())
            .unwrap();
        let acceptor = acceptor.build();

        // The client is the one that the engine uses inside a tunnel.
        let connector = tls_connector(trust, rejections).unwrap().build();

        // An in-memory stream stands in for the tunnel.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server =
            tokio::spawn(async move { tokio_boring::accept(&acceptor, server).await.is_ok() });
        // hyper-boring connects the same way: it sends the host as SNI.
        let client = tokio_boring::connect(connector.configure().unwrap(), HOST, client).await;
        // The server only has to finish. It fails if the client rejects it.
        let _ = server.await;
        client.is_ok()
    }

    /// The verifier must get the leaf first and the host as the name. It
    /// reads the first certificate as the leaf and checks the name against
    /// it, so a different order or a missing name breaks every request.
    #[tokio::test]
    async fn platform_trust_sees_the_leaf_first_and_the_request_host() {
        // Record what the verifier gets.
        let chain = Chain::generate();
        let seen = Arc::new(Mutex::new(None));
        let record = Arc::clone(&seen);
        let verifier = move |peer: &PeerCertificates<'_>| {
            *record.lock().unwrap() = Some(Seen {
                chain: peer.chain().iter().map(|der| der.to_vec()).collect(),
                server_name: peer.server_name().map(str::to_owned),
            });
            Ok(())
        };

        let accepted = handshake(
            &chain,
            OriginTrust::Platform(Arc::new(verifier)),
            Rejections::default(),
        )
        .await;

        // Check the chain order and the name.
        assert!(accepted);
        let seen = seen.lock().unwrap().take().expect("the verifier ran");
        assert_eq!(seen.chain, vec![chain.leaf.clone(), chain.ca.clone()]);
        assert_eq!(seen.server_name.as_deref(), Some(HOST));
    }

    /// A rejection of the verifier must fail the handshake. Its reason must
    /// reach [`Rejections`], which puts it into the error of the request.
    #[tokio::test]
    async fn a_platform_rejection_fails_the_handshake_with_its_reason() {
        // Reject every chain.
        let chain = Chain::generate();
        let rejections = Rejections::default();
        let verifier =
            |_: &PeerCertificates<'_>| Err(CertRejected::new("the platform does not trust it"));

        let accepted = handshake(
            &chain,
            OriginTrust::Platform(Arc::new(verifier)),
            rejections.clone(),
        )
        .await;

        // Check that the reason arrives.
        assert!(!accepted);
        let reason = rejections.take(HOST).expect("the rejection is recorded");
        assert!(
            reason.contains("the platform does not trust it"),
            "{reason}"
        );
    }
}
