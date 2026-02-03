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
//! Observability crate for logging and prometheus metrics.

use std::{
    io::{IsTerminal, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use http::Request;
use rand::{RngCore, SeedableRng, rng};
use rand_chacha::ChaChaRng;
use tower_http::{
    LatencyUnit,
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{DefaultOnFailure, DefaultOnResponse, MakeSpan, TraceLayer},
};
use tracing::Span;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{EnvFilter, Registry, fmt::time::UtcTime, prelude::*};

pub mod metrics;
pub mod prometheus_json;

/// Environment variable to define the log level.
pub const LOG_LEVEL_ENV: &str = "RUST_LOG";

/// Setup logging using the tracing library. Log output format is json.
///
/// # Arguments
///
/// * `log_dir`: If provided, logs are written to a file that carries the name of the current
///   executable in this directory.
/// * `log_to_stderr`: If true, logs will additionally printed to stderr.
pub fn setup_tracing<P: AsRef<Path>>(log_dir: Option<P>, log_to_stderr: bool) -> Vec<WorkerGuard> {
    // Setup log tracer to forward log records to tracing subscriber, this is required to capture
    // logs from dependencies such as squiche.
    tracing_log::LogTracer::init().expect("Failed to set log tracer");

    let log_level =
        EnvFilter::try_from_env(LOG_LEVEL_ENV).unwrap_or_else(|_| EnvFilter::new("info"));

    let mut guards = vec![];
    let mut layers = vec![JsonStorageLayer.boxed()];

    if let Some(log_dir) = log_dir {
        let log_file = tracing_appender::rolling::never(
            log_dir.as_ref(),
            format!("{}.log", extract_exec_name()),
        );
        let (non_blocking_writer, file_guard) = tracing_appender::non_blocking(log_file);
        let file_logger = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(UtcTime::rfc_3339())
            .with_writer(non_blocking_writer)
            .with_filter(tracing::level_filters::LevelFilter::DEBUG);
        layers.push(file_logger.boxed());
        guards.push(file_guard);
    }

    if log_to_stderr {
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(std::io::stderr());
        let stderr_logger = tracing_subscriber::fmt::layer()
            // Enable colors if the stderr is a terminal.
            .with_ansi(std::io::stderr().is_terminal())
            .with_timer(UtcTime::rfc_3339())
            .with_writer(non_blocking_writer)
            .with_filter(log_level);
        layers.push(stderr_logger.boxed());
        guards.push(guard);
    }

    // global subscriber
    let subscriber = Registry::default().with(layers);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    tracing::debug!("Logging initialized!");
    guards
}

#[allow(unused)]
fn json_formatted_layer<W: Write + Send + 'static>(
    w: W,
) -> (BunyanFormattingLayer<NonBlocking>, WorkerGuard) {
    let app_name = env!("CARGO_PKG_NAME").to_string();
    let (non_blocking_writer, guard) = tracing_appender::non_blocking(w);
    (
        BunyanFormattingLayer::new(app_name, non_blocking_writer),
        guard,
    )
}

/// Trace layer that logs at info level and uses random span ids.
pub fn info_trace_layer() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>, RandomSpans> {
    let lvl = tracing::Level::INFO;
    let trace_id_seed = rng().next_u64();
    let latency_unit = LatencyUnit::Nanos;

    TraceLayer::new_for_http()
        .make_span_with(RandomSpans::new(trace_id_seed))
        .on_failure(
            DefaultOnFailure::new()
                .latency_unit(latency_unit)
                .level(lvl),
        )
        .on_response(
            DefaultOnResponse::new()
                .latency_unit(latency_unit)
                .level(lvl),
        )
}

/// Random span generator.
#[derive(Clone)]
pub struct RandomSpans {
    counter: Arc<Mutex<ChaChaRng>>,
}

impl RandomSpans {
    fn new(seed: u64) -> Self {
        Self {
            counter: Arc::new(Mutex::new(ChaChaRng::seed_from_u64(seed))),
        }
    }
}

impl<B> MakeSpan<B> for RandomSpans {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let cur = self.counter.lock().unwrap().next_u64();
        let span_id = format!("{cur:016x}");
        tracing::span!(
            tracing::Level::INFO,
            "request",
            span_id = span_id,
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
        )
    }
}

/// Extract the name of the executable that is currently running.
fn extract_exec_name() -> String {
    let exec_path = std::env::current_exe().expect("Failed to get the current executable path");
    exec_path
        .file_stem()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .expect("Failed to extract program name")
}
