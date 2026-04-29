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
    fmt,
    io::{IsTerminal, Write},
    str::FromStr,
    sync::{Arc, Mutex},
};

use chacha20::ChaCha20Rng;
use http::Request;
use rand::{Rng, SeedableRng, rng};
use tower_http::{
    LatencyUnit,
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{DefaultOnFailure, DefaultOnResponse, MakeSpan, TraceLayer},
};
use tracing::Span;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt::time::UtcTime, prelude::*};

pub mod metrics;
pub mod prometheus_json;

pub use tracing_subscriber;

/// Environment variable to define the log level.
pub const LOG_LEVEL_ENV: &str = "RUST_LOG";

/// Selects where log lines are written.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Write to stderr.
    #[default]
    Stderr,
    /// Write to stdout.
    Stdout,
}

impl FromStr for LogOutput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stdout" => Ok(LogOutput::Stdout),
            "stderr" => Ok(LogOutput::Stderr),
            _ => {
                Err(format!(
                    "Invalid log output: '{}', expected 'stdout' or 'stderr'",
                    s
                ))
            }
        }
    }
}

impl fmt::Display for LogOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogOutput::Stdout => write!(f, "stdout"),
            LogOutput::Stderr => write!(f, "stderr"),
        }
    }
}

/// Selects the log line format.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text, with ANSI colours when the output is a terminal.
    #[default]
    Text,
    /// Newline-delimited JSON.
    Json,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            _ => {
                Err(format!(
                    "Invalid log format: '{}', expected 'text' or 'json'",
                    s
                ))
            }
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogFormat::Text => write!(f, "text"),
            LogFormat::Json => write!(f, "json"),
        }
    }
}

/// Configuration for tracing setup.
pub struct TracingConfig {
    /// Console output sink. `None` disables console logging.
    console_output: Option<LogOutput>,
    console_format: LogFormat,
    directives: Vec<String>,
    extra_layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            // Default: human-readable text → stderr (preserves existing behaviour).
            console_output: Some(LogOutput::Stderr),
            console_format: LogFormat::Text,
            directives: Vec::new(),
            extra_layers: Vec::new(),
        }
    }
}

impl TracingConfig {
    /// Create a new tracing configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set where console log lines are written.
    /// Call with the desired [`LogOutput`] variant. To disable console logging
    /// entirely pass `None` directly via `TracingConfig { console_output: None, .. }`
    /// or build the config manually.
    pub fn with_output(mut self, output: LogOutput) -> Self {
        self.console_output = Some(output);
        self
    }

    /// Set the console log format.
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.console_format = format;
        self
    }

    /// Add an additional tracing directive.
    pub fn add_directive<S: Into<String>>(mut self, directive: S) -> Self {
        self.directives.push(directive.into());
        self
    }

    /// Add multiple tracing directives.
    pub fn add_directives<I, S>(mut self, directives: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for directive in directives {
            self.directives.push(directive.as_ref().to_string());
        }
        self
    }

    /// Add a custom tracing layer.
    pub fn with_layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Registry> + Send + Sync + 'static,
    {
        self.extra_layers.push(layer.boxed());
        self
    }

    /// Initialize tracing using this configuration.
    ///
    /// The tracing directives from the configuration are applied to all layers.
    pub fn init(self) -> Result<Vec<WorkerGuard>, TracingSetupError> {
        // Setup log tracer to forward log records to tracing subscriber, this is required to
        // capture logs from dependencies such as squiche.
        tracing_log::LogTracer::init().map_err(|err| {
            TracingSetupError {
                message: format!("Failed to initialize log tracer: {err}"),
            }
        })?;

        let TracingConfig {
            console_output,
            console_format,
            directives,
            extra_layers,
        } = self;

        // Closure that builds a fresh EnvFilter with all configured directives applied.
        // Called once per logger so that each layer gets its own independent filter
        // (EnvFilter does not implement Clone).
        let make_filter = |directives: &[String]| -> Result<EnvFilter, TracingSetupError> {
            let mut filter =
                EnvFilter::try_from_env(LOG_LEVEL_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
            for d in directives {
                filter = filter.add_directive(
                    d.parse::<tracing_subscriber::filter::Directive>()
                        .map_err(|_| {
                            TracingSetupError {
                                message: format!("Invalid log directive: {d}"),
                            }
                        })?,
                );
            }
            Ok(filter)
        };

        let mut guards = vec![];
        let mut layers = vec![JsonStorageLayer.boxed()];

        if let Some(output) = console_output {
            match (output, &console_format) {
                (LogOutput::Stdout, LogFormat::Json) => {
                    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .with_timer(UtcTime::rfc_3339())
                            .with_writer(writer)
                            .with_filter(make_filter(&directives)?)
                            .boxed(),
                    );
                    guards.push(guard);
                }
                (LogOutput::Stdout, LogFormat::Text) => {
                    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(std::io::stdout().is_terminal())
                            .with_timer(UtcTime::rfc_3339())
                            .with_writer(writer)
                            .with_filter(make_filter(&directives)?)
                            .boxed(),
                    );
                    guards.push(guard);
                }
                (LogOutput::Stderr, LogFormat::Json) => {
                    let (writer, guard) = tracing_appender::non_blocking(std::io::stderr());
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .with_timer(UtcTime::rfc_3339())
                            .with_writer(writer)
                            .with_filter(make_filter(&directives)?)
                            .boxed(),
                    );
                    guards.push(guard);
                }
                (LogOutput::Stderr, LogFormat::Text) => {
                    let (writer, guard) = tracing_appender::non_blocking(std::io::stderr());
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(std::io::stderr().is_terminal())
                            .with_timer(UtcTime::rfc_3339())
                            .with_writer(writer)
                            .with_filter(make_filter(&directives)?)
                            .boxed(),
                    );
                    guards.push(guard);
                }
            }
        }

        // add any additionally configured layers
        for layer in extra_layers {
            layers.push(layer.with_filter(make_filter(&directives)?).boxed());
        }

        // global subscriber
        let subscriber = Registry::default().with(layers);
        tracing::subscriber::set_global_default(subscriber).map_err(|err| {
            TracingSetupError {
                message: format!("Failed to set global tracing subscriber: {err}"),
            }
        })?;

        tracing::debug!("Logging initialized!");
        Ok(guards)
    }
}

/// Error returned when tracing setup fails.
#[derive(Debug)]
pub struct TracingSetupError {
    message: String,
}

impl fmt::Display for TracingSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TracingSetupError {}

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
    counter: Arc<Mutex<ChaCha20Rng>>,
}

impl RandomSpans {
    fn new(seed: u64) -> Self {
        Self {
            counter: Arc::new(Mutex::new(ChaCha20Rng::seed_from_u64(seed))),
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
