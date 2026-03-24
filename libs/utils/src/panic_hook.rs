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

// Copyright 2026 Anapaya Systems
//! Panic hook that logs full panic details via the tracing framework.

/// Installs a panic hook that logs the full panic location and message via
/// [`tracing::error!`].
///
/// The previous hook is preserved and called after logging, so the default
/// Rust behaviour (print to stderr, optionally abort) is retained.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log_panic(info);
        prev(info);
    }));
}

fn log_panic(info: &std::panic::PanicHookInfo<'_>) {
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
    let location = location.as_deref().unwrap_or("<unknown location>");

    let payload = info.payload();
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        *s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    };

    tracing::error!(location, message = msg, "Unexpected panic occurred");
}
