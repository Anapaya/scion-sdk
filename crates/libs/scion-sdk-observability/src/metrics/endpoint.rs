// Copyright 2025 Anapaya Systems
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
//! HTTP endpoint to expose prometheus metrics.

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::State,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
    routing::get,
};
use prometheus::{Encoder, IntCounterVec, TextEncoder};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::{
    BoxError, ServiceBuilder,
    limit::GlobalConcurrencyLimitLayer,
    load_shed::error::Overloaded,
    timeout::{TimeoutLayer, error::Elapsed},
};

use crate::metrics::registry::MetricsRegistry;

const METRICS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_REQUESTS: usize = 32;

/// Prometheus metrics for the HTTP endpoint.
#[derive(Clone)]
pub struct PrometheusHttpEndpointMetrics {
    requests_total: IntCounterVec,
}

impl PrometheusHttpEndpointMetrics {
    /// Creates a new [`PrometheusHttpEndpointMetrics`] instance with the given metrics registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests_total: metrics_registry.int_counter_vec(
                "metrics_endpoint_requests_total",
                "Total number of requests for the /metrics endpoint.",
                &["protocol"],
            ),
        }
    }
}

/// Expose prometheus metrics over HTTP. The HTTP server will respond to a GET request for the
/// /metrics path with the textual representation of the prometheus metrics.
pub async fn start(
    cancellation_token: CancellationToken,
    listener: TcpListener,
    metrics_registry: MetricsRegistry,
) -> std::io::Result<()> {
    let metrics = PrometheusHttpEndpointMetrics::new(&metrics_registry);
    let metrics_service = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(map_box_error_to_response))
                .load_shed()
                .layer(TimeoutLayer::new(METRICS_TIMEOUT))
                .layer(GlobalConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS)),
        )
        .with_state((metrics_registry.clone(), metrics.clone()))
        .into_make_service();

    tracing::info!(addr=?listener.local_addr(), "Starting metrics endpoint");
    if let Err(e) = axum::serve(listener, metrics_service)
        .with_graceful_shutdown(cancellation_token.cancelled_owned())
        .await
    {
        tracing::error!(err=%e, "Metrics endpoint server unexpectedly stopped");
    } else {
        tracing::info!("Metrics endpoint server stopped gracefully");
    }
    Ok(())
}

async fn metrics_endpoint(
    State((metrics_registry, metrics)): State<(MetricsRegistry, PrometheusHttpEndpointMetrics)>,
    _req: Request<Body>,
) -> impl IntoResponse {
    metrics.requests_total.with_label_values(&["http"]).inc();
    let encoder = TextEncoder::new();
    let mf = metrics_registry.registry().gather();
    let mut buffer = Vec::with_capacity(mf.len() * 20);
    encoder.encode(&mf, &mut buffer).expect("never fails");

    Response::new(Body::from(buffer))
}

async fn map_box_error_to_response(err: BoxError) -> (StatusCode, String) {
    if err.is::<Overloaded>() {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "The service is overloaded.".to_string(),
        )
    } else if err.is::<Elapsed>() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "Request took longer than the deadline.".to_string(),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unexpected error: {err}"),
        )
    }
}
