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
//! Prometheus metric registry.

use prometheus::{
    Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, core::Collector,
};

use crate::prometheus_json::PrometheusJsonEncoder;

/// Register and collect metrics of one or more components.
///
/// ## Designated use case
///
/// When initializing a component, the caller is responsible to build the component's metrics based
/// on the desired `MetricsRegistry`. The component specific metrics uses the provided
/// `MetricsRegistry` to register its metrics. This approach allows the caller to control the
/// metrics namespace, add prefixes, or attach labels to the registry, ensuring consistent metric
/// naming and scoping across the application.
#[derive(Debug, Clone)]
pub struct MetricsRegistry {
    registry: prometheus::Registry,
}

impl MetricsRegistry {
    /// Use prometheus' default registry and register process metrics. As a
    /// result, this registry will 'point' to the global registry.
    pub fn new_global() -> Self {
        let registry = prometheus::default_registry().clone();

        #[cfg(target_os = "linux")]
        registry
            .register(Box::new(
                prometheus::process_collector::ProcessCollector::for_self(),
            ))
            // As we are dealing with global state here, another instance of
            // `MetricsRegistry` might already have registered the process
            // collector => don't panic.
            .ok();

        Self::new_with_registry(registry)
    }

    /// Create a new metrics registry with the given prometheus registry.
    pub fn new_with_registry(registry: prometheus::Registry) -> Self {
        Self { registry }
    }

    /// Create a new metrics registry with no collectors pre-registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create and register a histogram with specified options.
    pub fn histogram<S: Into<String>>(&self, name: S, help: S, buckets: Vec<f64>) -> Histogram {
        self.register_collector(
            Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets)).unwrap(),
        )
    }

    /// Create and register a `HistogramVec`
    pub fn histogram_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        buckets: Vec<f64>,
        label_names: &[&str],
    ) -> HistogramVec {
        self.register_collector(
            HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), label_names)
                .unwrap(),
        )
    }

    /// Create and register an `IntGauge`.
    pub fn int_gauge<S: Into<String>>(&self, name: S, help: S) -> IntGauge {
        self.register_collector(IntGauge::new(name, help).unwrap())
    }

    /// Create and register an `IntGaugeVec`.
    pub fn int_gauge_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        label_names: &[&str],
    ) -> IntGaugeVec {
        self.register_collector(IntGaugeVec::new(Opts::new(name, help), label_names).unwrap())
    }

    /// Create and register a `Gauge`.
    pub fn gauge<S: Into<String>>(&self, name: S, help: S) -> Gauge {
        self.register_collector(Gauge::new(name, help).unwrap())
    }

    /// Create and register a `GaugeVec`.
    pub fn gauge_vec<S: Into<String>>(&self, name: S, help: S, label_names: &[&str]) -> GaugeVec {
        self.register_collector(GaugeVec::new(Opts::new(name, help), label_names).unwrap())
    }

    /// Create and register an `IntCounter`.
    pub fn int_counter<S: Into<String>>(&self, name: S, help: S) -> IntCounter {
        self.register_collector(IntCounter::new(name, help).unwrap())
    }

    /// Create and register an `IntCounterVec`.
    pub fn int_counter_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        label_names: &[&str],
    ) -> IntCounterVec {
        self.register_collector(IntCounterVec::new(Opts::new(name, help), label_names).unwrap())
    }

    pub(crate) fn registry(&self) -> &prometheus::Registry {
        &self.registry
    }

    /// Gather metrics and encode them in JSON format.
    pub fn gather_json(&self, pretty: bool) -> Result<String, Box<dyn std::error::Error>> {
        let metric_families = self.registry.gather();
        let encoder = PrometheusJsonEncoder::new(pretty);
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    fn register_collector<C: 'static + Collector + Clone>(&self, c: C) -> C {
        self.registry.register(Box::new(C::clone(&c))).unwrap();
        c
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        let registry = prometheus::Registry::new();
        Self { registry }
    }
}
