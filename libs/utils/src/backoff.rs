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
//! Backoff utility functions.

use std::time::Duration;

/// Returns a function that implements exponential backoff.
///
/// # Arguments
///
/// * `minimum_delay` - The minimum delay in seconds.
/// * `maximum_delay` - The maximum delay in seconds.
/// * `factor` - The factor to multiply the delay by.
/// * `jitter` - The jitter to add to the delay.
///
/// # Returns
/// A function that takes the current attempt and sleeps for the appropriate duration.
/// If attempt is 0, the minimum delay is used.
pub fn exponential_backoff(
    minimum_delay_secs: f32,
    maximum_delay_secs: f32,
    factor: f32,
    jitter_secs: f32,
) -> impl Fn(i32) -> Duration + Send + Sync {
    move |attempt: i32| {
        let backoff = minimum_delay_secs * factor.powi(attempt);
        let backoff = backoff + rand::random::<f32>() * jitter_secs;
        Duration::from_secs_f32(backoff.min(maximum_delay_secs))
    }
}
