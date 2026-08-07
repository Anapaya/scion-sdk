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
//! End-to-end test of the log entry counter: the registry that serves `/metrics` is built at
//! startup and handed to the tracing setup, which registers the counter on it.

use scion_sdk_observability::{TracingConfig, log_metrics, metrics::registry::MetricsRegistry};

#[test]
fn tracing_config_counts_entries_into_the_given_registry() {
    let metrics = MetricsRegistry::new();

    let _guards = TracingConfig::new()
        .with_log_metrics(&metrics)
        // Pin the level, so that the counter does not depend on `RUST_LOG` in the environment.
        .add_directive("info")
        .init()
        .expect("tracing initialized");

    tracing::info!("counted at info");
    tracing::error!("counted at error");
    tracing::debug!("below the configured level, not counted");

    let exposition = metrics.gather_json(false).expect("metrics gathered");

    assert!(
        exposition.contains(log_metrics::LOG_ENTRIES_METRIC),
        "log entry counter is not exposed by the registry: {exposition}"
    );
    for (level, count) in [("info", "1.0"), ("error", "1.0"), ("debug", "0.0")] {
        let series = format!(
            r#""{}{{level={level}}}":{count}"#,
            log_metrics::LOG_ENTRIES_METRIC
        );
        assert!(
            exposition.contains(&series),
            "expected {series} in: {exposition}"
        );
    }
}
