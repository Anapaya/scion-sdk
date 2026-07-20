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
//! Event formatter that collapses runs of identical log events.
//!
//! Inspired by <https://github.com/kika/tracing-dedup>. The only difference is the support for the
//! '[crate::LogFormat]' for the repeat summary.

use std::{fmt, sync::Mutex};

use tracing::{Event, Subscriber, field::Field};
use tracing_subscriber::{
    fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
    registry::LookupSpan,
};

use crate::LogFormat;

/// A [`FormatEvent`] wrapper that suppresses consecutive identical events.
///
/// When the same event (same message, level and target) is emitted multiple
/// times in a row, only the first occurrence is written. Once a different event
/// arrives, a summary of the form `previous message repeated N times` is
/// emitted before the new event is formatted by the wrapped `inner` formatter.
///
/// The summary is rendered according to the configured [`LogFormat`] so that it
/// matches the inner formatter's output: a plain line for [`LogFormat::Text`],
/// or a standalone JSON object for [`LogFormat::Json`]. Use
/// [`with_format`](Self::with_format) to keep JSON output valid.
pub struct DeduplicatingFormatter<F> {
    inner: F,
    format: LogFormat,
    state: Mutex<DeduplicationState>,
}

impl<F> DeduplicatingFormatter<F> {
    /// Wrap an existing event formatter with consecutive-duplicate suppression.
    ///
    /// The summary defaults to [`LogFormat::Text`]; use
    /// [`with_format`](Self::with_format) for JSON output.
    pub fn new(inner: F) -> Self {
        Self {
            inner,
            format: LogFormat::default(),
            state: Mutex::new(DeduplicationState {
                last_event: None,
                repeat_count: 0,
            }),
        }
    }

    /// Set the format used to render the repeat summary.
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Write the repeat summary for `prev`, which was emitted `repeated` times.
    fn write_summary(
        &self,
        writer: &mut Writer<'_>,
        prev: &EventKey,
        repeated: usize,
    ) -> fmt::Result {
        let message = format!("previous message repeated {repeated} times");
        match self.format {
            LogFormat::Text => writeln!(writer, "{message}"),
            LogFormat::Json => {
                // Build via serde_json so the line is guaranteed to be valid,
                // properly escaped JSON. Mirrors the level/target/message shape
                // of the surrounding JSON log lines (timestamp is omitted as no
                // clock is available here).
                let obj = serde_json::json!({
                    "level": prev.level.as_str(),
                    "target": prev.target,
                    "fields": { "message": message },
                });
                writeln!(writer, "{obj}")
            }
        }
    }
}

#[derive(Eq, PartialEq)]
struct EventKey {
    message: String,
    level: tracing::Level,
    target: String,
}

struct DeduplicationState {
    last_event: Option<EventKey>,
    repeat_count: usize,
}

impl<S, N, F> FormatEvent<S, N> for DeduplicatingFormatter<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let key = EventKey {
            message: visitor.message,
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
        };

        let mut state = self.state.lock().expect("lock poisoned");

        match &state.last_event {
            Some(last) if *last == key => {
                // Same event: suppress it and increment counter
                state.repeat_count += 1;
                return Ok(()); // Skip this event
            }
            _ => {
                // Different event: flush the repeat summary for the previous
                // event (still stored in `last_event`) before recording the new
                // one.
                if state.repeat_count > 0
                    && let Some(prev) = &state.last_event
                {
                    let repeated = state.repeat_count + 1;
                    self.write_summary(&mut writer, prev, repeated)?;
                }
                state.last_event = Some(key);
                state.repeat_count = 0;
            }
        }

        drop(state);

        // Format the event using the inner formatter
        self.inner.format_event(ctx, writer, event)
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use tracing::subscriber::with_default;
    use tracing_subscriber::{
        Registry,
        fmt::{MakeWriter, format::Format},
        prelude::*,
    };

    use super::DeduplicatingFormatter;
    use crate::LogFormat;

    /// A `MakeWriter` that appends everything written to a shared buffer.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn subscriber(buf: SharedBuf) -> impl tracing::Subscriber {
        let fmt = Format::default().without_time().with_ansi(false);
        let layer = tracing_subscriber::fmt::layer()
            .event_format(DeduplicatingFormatter::new(fmt))
            .with_writer(buf);
        Registry::default().with(layer)
    }

    #[test]
    fn collapses_consecutive_identical_events() {
        let buf = SharedBuf::default();
        with_default(subscriber(buf.clone()), || {
            tracing::info!("hello");
            tracing::info!("hello");
            tracing::info!("hello");
            tracing::info!("world");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();

        // First "hello" is printed, the next two are collapsed, then the
        // summary is flushed when "world" arrives, followed by "world".
        assert_eq!(lines.len(), 3, "unexpected output:\n{out}");
        assert!(lines[0].contains("hello"));
        assert_eq!(lines[1], "previous message repeated 3 times");
        assert!(lines[2].contains("world"));
    }

    #[test]
    fn distinct_messages_are_all_emitted() {
        let buf = SharedBuf::default();
        with_default(subscriber(buf.clone()), || {
            tracing::info!("a");
            tracing::info!("b");
            tracing::info!("c");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 3, "unexpected output:\n{out}");
        assert!(!out.contains("repeated"));
    }

    #[test]
    fn json_summary_is_valid_json() {
        let buf = SharedBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(buf.clone())
            .event_format(
                DeduplicatingFormatter::new(Format::default().json()).with_format(LogFormat::Json),
            );
        let sub = Registry::default().with(layer);
        with_default(sub, || {
            tracing::info!("dup");
            tracing::info!("dup");
            tracing::info!("other");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        // Every emitted line must parse as JSON, including the repeat summary.
        for line in out.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("line is not valid JSON ({e}): {line}"));
        }
        assert!(out.contains("previous message repeated 2 times"));
    }

    #[test]
    fn same_message_different_level_is_not_deduplicated() {
        let buf = SharedBuf::default();
        with_default(subscriber(buf.clone()), || {
            tracing::info!("same");
            tracing::warn!("same");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 2, "unexpected output:\n{out}");
        assert!(!out.contains("repeated"));
    }
}
