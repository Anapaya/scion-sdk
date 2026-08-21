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
    /// Maximum delay for a retry, before jitter.
    pub maximum_delay_secs: f32,
    /// Factor by which to increase the delay.
    pub factor: f32,
    /// Upper bound of the random jitter added on top of every delay.
    ///
    /// Spreads out clients that failed at the same moment, e.g. because the server they were
    /// talking to restarted.
    pub jitter_secs: f32,
}

/// Exponential backoff
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
}
impl ExponentialBackoff {
    /// Creates a new [`ExponentialBackoff`].
    pub const fn new(
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
    ///
    /// Attempt 0 waits `minimum_delay_secs` and every attempt after it multiplies that by
    /// `factor`, up to `maximum_delay_secs`. Jitter is then added on top of that capped delay, so a
    /// delay can exceed `maximum_delay_secs` by up to `jitter_secs`. Capping first is what keeps
    /// the jitter working: applied to the sum instead, it would be truncated away as soon as the
    /// delay reached the cap, and every client that failed together would retry in lockstep from
    /// there on, which is the case the jitter exists for.
    ///
    /// The jitter is also never larger than the delay it perturbs, so that the short delays of the
    /// first few attempts are governed by `minimum_delay_secs` rather than dominated by it.
    pub fn duration(&self, attempt: u32) -> Duration {
        let delay = (self.config.minimum_delay_secs * self.config.factor.powi(attempt as i32))
            .min(self.config.maximum_delay_secs);
        let jitter = self.config.jitter_secs.min(delay) * rand::random::<f32>();
        Duration::from_secs_f32(delay + jitter)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ExponentialBackoff;

    const MIN: f32 = 1.0;
    const MAX: f32 = 60.0;
    const FACTOR: f32 = 2.0;
    const JITTER: f32 = 5.0;

    fn backoff() -> ExponentialBackoff {
        ExponentialBackoff::new(MIN, MAX, FACTOR, JITTER)
    }

    #[test]
    fn the_first_attempt_waits_the_minimum_delay() {
        let delay = backoff().duration(0);
        assert!(
            delay >= Duration::from_secs_f32(MIN) && delay < Duration::from_secs_f32(2.0 * MIN),
            "delay {delay:?} is not the minimum delay perturbed by at most itself",
        );
    }

    #[test]
    fn the_delay_grows_by_the_factor_until_it_reaches_the_cap() {
        let backoff = backoff();
        let mut previous = Duration::ZERO;
        for attempt in 0..20 {
            let delay = backoff.duration(attempt);
            let base = (MIN * FACTOR.powi(attempt as i32)).min(MAX);
            assert!(
                delay >= Duration::from_secs_f32(base)
                    && delay <= Duration::from_secs_f32(base + JITTER.min(base)),
                "delay {delay:?} at attempt {attempt} is not {base}s perturbed by at most \
                 min({JITTER}, {base})s",
            );
            previous = delay.max(previous);
        }
        assert!(
            previous >= Duration::from_secs_f32(MAX),
            "the delay should reach the cap within 20 attempts, got {previous:?}",
        );
    }

    /// The regression this guards: with the cap applied to delay plus jitter, every saturated
    /// client retries at exactly `maximum_delay_secs` and the jitter stops spreading them out.
    #[test]
    fn the_jitter_still_spreads_clients_once_the_delay_is_capped() {
        let backoff = backoff();
        let saturated = 30;
        let distinct = (0..50)
            .map(|_| backoff.duration(saturated))
            .collect::<std::collections::HashSet<_>>();
        assert!(
            distinct.len() > 1,
            "50 clients at the cap all drew the same delay: {distinct:?}",
        );
        for delay in distinct {
            assert!(
                delay >= Duration::from_secs_f32(MAX)
                    && delay <= Duration::from_secs_f32(MAX + JITTER),
                "capped delay {delay:?} is outside [{MAX}s, {MAX}s + {JITTER}s]",
            );
        }
    }

    #[test]
    fn a_zero_jitter_config_is_deterministic() {
        let backoff = ExponentialBackoff::new(MIN, MAX, FACTOR, 0.0);
        assert_eq!(backoff.duration(3), backoff.duration(3));
        assert_eq!(backoff.duration(3), Duration::from_secs_f32(8.0));
    }
}
