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

/// Configuration for exponential backoff.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// Minimum delay before retrying.
    pub minimum_delay_secs: f32,
    /// Maximum delay for a retry.
    pub maximum_delay_secs: f32,
    /// Factor by which to increase the delay.
    pub factor: f32,
    /// Jitter to add to the delay.
    pub jitter_secs: f32,
}

/// Exponential backoff
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
}
impl ExponentialBackoff {
    /// Creates a new [`ExponentialBackoff`].
    pub fn new(
        minimum_delay_secs: f32,
        maximum_delay_secs: f32,
        factor: f32,
        jitter_secs: f32,
    ) -> Self {
        Self {
            config: BackoffConfig {
                minimum_delay_secs,
                maximum_delay_secs,
                factor,
                jitter_secs,
            },
        }
    }

    /// Creates a new [`ExponentialBackoff`] from the given configuration.
    pub fn new_from_config(config: BackoffConfig) -> Self {
        Self { config }
    }

    /// Returns the backoff duration for the given attempt.
    pub fn duration(&self, attempt: u32) -> Duration {
        let backoff = self.config.minimum_delay_secs * self.config.factor.powi(attempt as i32);
        let backoff = backoff + rand::random::<f32>() * self.config.jitter_secs;
        Duration::from_secs_f32(backoff.min(self.config.maximum_delay_secs))
    }
}
