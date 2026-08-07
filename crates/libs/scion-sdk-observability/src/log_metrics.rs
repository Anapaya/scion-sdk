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
//! Metrics for emitted log entries.

use prometheus::IntCounter;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::metrics::registry::MetricsRegistry;

/// Name of the counter of emitted log entries.
pub const LOG_ENTRIES_METRIC: &str = "rust_log_emitted_entries_total";

const LOG_ENTRIES_HELP: &str = "Total number of log entries emitted.";

/// Tracing layer counting emitted log entries by level, into [`LOG_ENTRIES_METRIC`].
///
/// The layer can be enabled for the [`TracingConfig`](crate::TracingConfig) using
/// [`crate::TracingConfig::with_log_metrics`].
///
/// Trace entries are omitted.
#[derive(Debug, Clone)]
pub struct LogEntriesLayer {
    debug: IntCounter,
    info: IntCounter,
    warn: IntCounter,
    error: IntCounter,
}

impl LogEntriesLayer {
    /// Create the layer, registering the counter of emitted log entries with `registry` and
    /// resolving the per-level series.
    ///
    /// ## Panics
    ///
    /// if `registry` already exposes a metric named [`LOG_ENTRIES_METRIC`], i.e. if a layer was
    /// already created for it.
    pub fn new(registry: &MetricsRegistry) -> Self {
        let entries = registry.int_counter_vec(LOG_ENTRIES_METRIC, LOG_ENTRIES_HELP, &["level"]);
        let counter = |level: &str| entries.with_label_values(&[level]);
        Self {
            debug: counter("debug"),
            info: counter("info"),
            warn: counter("warn"),
            error: counter("error"),
        }
    }

    /// The counter for `level`, or `None` if entries at that level are not counted.
    fn counter(&self, level: &Level) -> Option<&IntCounter> {
        match *level {
            Level::TRACE => None,
            Level::DEBUG => Some(&self.debug),
            Level::INFO => Some(&self.info),
            Level::WARN => Some(&self.warn),
            Level::ERROR => Some(&self.error),
        }
    }
}

impl<S: Subscriber> Layer<S> for LogEntriesLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if let Some(counter) = self.counter(event.metadata().level()) {
            counter.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use prometheus::{Encoder, TextEncoder};
    use tracing_subscriber::{EnvFilter, Layer, Registry, prelude::*};

    use super::*;

    /// Run `emit` under `layer`, filtered at `directive`.
    fn with_layer(layer: LogEntriesLayer, directive: &str, emit: impl FnOnce()) {
        let subscriber =
            Registry::default().with(layer.with_filter(EnvFilter::new(directive)).boxed());
        tracing::subscriber::with_default(subscriber, emit);
    }

    /// Counting is per level, the log filter decides what counts as emitted, and trace entries are
    /// never counted.
    #[test]
    fn counts_emitted_entries_by_level() {
        let layer = LogEntriesLayer::new(&MetricsRegistry::new());

        with_layer(layer.clone(), "info", || {
            tracing::info!("one");
            tracing::info!("two");
            tracing::warn!("three");
            tracing::error!("four");
            // Below the filter, hence not emitted and not counted.
            tracing::debug!("five");
        });
        // Emitted, but trace entries are deliberately not counted, in any of the series.
        with_layer(layer.clone(), "trace", || tracing::trace!("six"));

        assert_eq!(layer.info.get(), 2);
        assert_eq!(layer.warn.get(), 1);
        assert_eq!(layer.error.get(), 1);
        assert_eq!(layer.debug.get(), 0);
    }

    /// Creating the layer exposes a series per level on the registry, even before anything is
    /// logged.
    #[test]
    fn registers_a_series_per_level() {
        let registry = MetricsRegistry::new();
        let _layer = LogEntriesLayer::new(&registry);

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.registry().gather(), &mut buffer)
            .unwrap();
        let exposition = String::from_utf8(buffer).unwrap();

        for level in ["debug", "info", "warn", "error"] {
            let series = format!("{LOG_ENTRIES_METRIC}{{level=\"{level}\"}}");
            assert!(
                exposition.contains(&series),
                "missing series {series} in: {exposition}"
            );
        }
        assert!(
            !exposition.contains("level=\"trace\""),
            "trace entries are not counted, so no series is exposed for them: {exposition}"
        );
    }
}
