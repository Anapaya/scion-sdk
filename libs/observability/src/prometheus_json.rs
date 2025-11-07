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

//! A Prometheus encoder that outputs metrics in JSON format.

use std::collections::BTreeMap;

use serde::Serialize;

/// A Prometheus encoder that outputs metrics in JSON format.
pub struct PrometheusJsonEncoder {
    pretty: bool,
}
impl PrometheusJsonEncoder {
    /// Creates a new `PrometheusJsonEncoder`.
    /// If `pretty` is true, the output JSON will be pretty-printed.
    pub fn new(pretty: bool) -> Self {
        PrometheusJsonEncoder { pretty }
    }
}

impl prometheus::Encoder for PrometheusJsonEncoder {
    fn encode<W: std::io::Write>(
        &self,
        metrics: &[prometheus::proto::MetricFamily],
        writer: &mut W,
    ) -> prometheus::Result<()> {
        let mut collected: BTreeMap<String, MetricType> = BTreeMap::new();

        for metric_family in metrics {
            for metric in metric_family.get_metric() {
                let family_name = metric_family.name();
                let family_type = metric_family.get_field_type();
                let label_names: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|lp| format!("{}={}", lp.name(), lp.value()))
                    .collect();

                let metric_name = if label_names.is_empty() {
                    family_name.to_string()
                } else {
                    format!("{}{{{}}}", family_name, label_names.join(","))
                };

                match family_type {
                    prometheus::proto::MetricType::COUNTER => {
                        collected.insert(
                            metric_name,
                            MetricType::Counter(Counter(metric.get_counter().value)),
                        );
                    }
                    prometheus::proto::MetricType::GAUGE => {
                        collected.insert(
                            metric_name,
                            MetricType::Gauge(Gauge(metric.get_gauge().value)),
                        );
                    }
                    prometheus::proto::MetricType::HISTOGRAM => {
                        let histogram = metric.get_histogram();
                        let mut bucket_map: BTreeMap<String, u64> = BTreeMap::new();

                        let mut lower = "-Inf".to_string();
                        let mut last_cumulative = 0;
                        for bucket in histogram.get_bucket() {
                            let bucket_name = match bucket.upper_bound {
                                None => format!("({lower}, +Inf)"),
                                Some(upper) => {
                                    let fmt = format!("({lower}, {upper})");
                                    lower = format!("{upper}");
                                    fmt
                                }
                            };
                            let cumulative_count = bucket.cumulative_count();
                            bucket_map.insert(bucket_name, cumulative_count - last_cumulative);
                            last_cumulative = cumulative_count;
                        }

                        bucket_map.insert(
                            format!("({lower}, +Inf)"),
                            histogram.sample_count() - last_cumulative,
                        );

                        collected.insert(
                            metric_name,
                            MetricType::Histogram(Histogram {
                                samples: histogram.sample_count(),
                                sum: histogram.sample_sum(),
                                buckets: bucket_map,
                            }),
                        );
                    }
                    prometheus::proto::MetricType::SUMMARY
                    | prometheus::proto::MetricType::UNTYPED => {
                        // Not supported
                    }
                }
            }
        }

        if self.pretty {
            serde_json::to_writer_pretty(writer, &collected).map_err(|e| {
                prometheus::Error::Msg(format!("Failed to write metrics as pretty JSON: {e}"))
            })
        } else {
            serde_json::to_writer(writer, &collected).map_err(|e| {
                prometheus::Error::Msg(format!("Failed to write metrics as JSON: {e}"))
            })
        }
    }

    fn format_type(&self) -> &str {
        "json"
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum MetricType {
    Counter(Counter),
    Gauge(Gauge),
    Histogram(Histogram),
}

#[derive(Serialize)]
struct Gauge(Option<f64>);
#[derive(Serialize)]
struct Counter(Option<f64>);

#[derive(Serialize)]
struct Histogram {
    samples: u64,
    sum: f64,
    buckets: BTreeMap<String, u64>,
}

#[cfg(test)]
mod test {
    use prometheus::{Encoder, Registry};

    use super::*;

    #[test]
    fn encoder_formats_metrics_as_json() {
        let registry = Registry::new();
        let counter = prometheus::Counter::new("test_counter", "A test counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        counter.inc_by(42.0);

        let gauge = prometheus::Gauge::new("test_gauge", "A test gauge").unwrap();
        registry.register(Box::new(gauge.clone())).unwrap();
        gauge.set(3.11);

        let histogram = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new("test_histogram", "A test histogram")
                .buckets(vec![0.1, 0.11, 0.21, 0.99102, 1.0, 10.0, 100.0]),
        )
        .unwrap();

        registry.register(Box::new(histogram.clone())).unwrap();
        histogram.observe(0.5);
        histogram.observe(0.5);
        histogram.observe(0.5);
        histogram.observe(0.5);
        histogram.observe(5.0);
        histogram.observe(50.0);
        histogram.observe(500.0);

        let counter_vec = prometheus::CounterVec::new(
            prometheus::Opts::new("test_counter_vec", "A test counter vec"),
            &["label"],
        )
        .unwrap();
        registry.register(Box::new(counter_vec.clone())).unwrap();
        counter_vec.with_label_values(&["a"]).inc_by(7.0);
        counter_vec.with_label_values(&["b"]).inc_by(11.0);
        counter_vec.with_label_values(&["c"]).inc_by(13.0);

        let encoder = PrometheusJsonEncoder::new(false);
        let mut buffer = Vec::new();
        encoder.encode(&registry.gather(), &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        println!("{output}");
        assert_eq!(
            output,
            r#"{"test_counter":42.0,"test_counter_vec{label=a}":7.0,"test_counter_vec{label=b}":11.0,"test_counter_vec{label=c}":13.0,"test_gauge":3.11,"test_histogram":{"samples":7,"sum":557.0,"buckets":{"(-Inf, 0.1)":0,"(0.1, 0.11)":0,"(0.11, 0.21)":0,"(0.21, 0.99102)":4,"(0.99102, 1)":0,"(1, 10)":1,"(10, 100)":1,"(100, +Inf)":1}}}"#
        );
    }
}
