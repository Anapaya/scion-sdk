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

//! Staggered, Happy-Eyeballs-style attempts (RFC 8305).

use std::{fmt::Debug, future::Future, time::Duration};

use futures::StreamExt;

/// Runs `attempts` with staggered starts and returns the first success.
///
/// The first attempt starts immediately; each further attempt starts `delay`
/// after the previous one or immediately, if every attempt started so far
/// has already failed. The first success wins and all other in-flight
/// attempts are cancelled by drop. If every attempt fails, the errors are
/// returned in completion order.
///
/// Attempts are taken from the iterator lazily: an attempt that never starts
/// does no work. Dropping the returned future drops all in-flight attempts.
///
/// Failures are traced as they happen. A race that ends in success discards its
/// errors, so this is the only place a candidate that lost is visible.
pub(crate) async fn staggered_first_ok<T, E: Debug>(
    attempts: impl IntoIterator<Item = impl Future<Output = Result<T, E>>>,
    delay: Duration,
) -> Result<T, Vec<E>> {
    let mut pending = attempts.into_iter();
    let mut in_flight = futures::stream::FuturesUnordered::new();
    let mut errors = Vec::new();

    match pending.next() {
        Some(first) => in_flight.push(first),
        None => return Err(errors),
    }
    let mut pending = pending.peekable();

    loop {
        let has_more = pending.peek().is_some();
        tokio::select! {
            biased;
            completed = in_flight.next() => {
                match completed {
                    Some(Ok(winner)) => return Ok(winner),
                    Some(Err(e)) => {
                        tracing::trace!(attempt = errors.len(), error = ?e, "Connection attempt failed");
                        errors.push(e);
                        if in_flight.is_empty() {
                            // Everything started so far has failed: don't sit
                            // out the stagger, start the next candidate now.
                            match pending.next() {
                                Some(next) => in_flight.push(next),
                                None => return Err(errors),
                            }
                        }
                    }
                    // `in_flight` is checked non-empty above and refilled on
                    // failure, so the stream never runs dry here.
                    None => unreachable!("in_flight is never polled while empty"),
                }
            }
            () = tokio::time::sleep(delay), if has_more => {
                if let Some(next) = pending.next() {
                    in_flight.push(next);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    const DELAY: Duration = Duration::from_millis(250);

    /// An attempt that marks itself started, waits, and resolves.
    fn attempt(
        started: &Arc<AtomicUsize>,
        wait: Duration,
        result: Result<u32, u32>,
    ) -> impl Future<Output = Result<u32, u32>> + use<> {
        let started = started.clone();
        async move {
            started.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(wait).await;
            result
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fast_success_starts_only_one_attempt() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![
            attempt(&started, Duration::from_millis(10), Ok(1)),
            attempt(&started, Duration::ZERO, Ok(2)),
        ];
        let winner = staggered_first_ok(attempts, DELAY).await.unwrap();
        assert_eq!(winner, 1);
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_attempt_triggers_staggered_second() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![
            attempt(&started, Duration::from_secs(60), Ok(1)),
            attempt(&started, Duration::from_millis(10), Ok(2)),
        ];
        let start = tokio::time::Instant::now();
        let winner = staggered_first_ok(attempts, DELAY).await.unwrap();
        assert_eq!(winner, 2);
        assert_eq!(started.load(Ordering::SeqCst), 2);
        // The second attempt only started after the stagger delay.
        assert!(start.elapsed() >= DELAY + Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn fast_failure_starts_next_attempt_immediately() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![
            attempt(&started, Duration::from_millis(1), Err(1)),
            attempt(&started, Duration::from_millis(1), Ok(2)),
        ];
        let start = tokio::time::Instant::now();
        let winner = staggered_first_ok(attempts, DELAY).await.unwrap();
        assert_eq!(winner, 2);
        // Both ran back to back, without waiting out the stagger.
        assert!(start.elapsed() < DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn all_failures_are_aggregated_in_completion_order() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![
            attempt(&started, Duration::from_millis(1), Err(1)),
            attempt(&started, Duration::from_millis(1), Err(2)),
            attempt(&started, Duration::from_millis(1), Err(3)),
        ];
        let errors = staggered_first_ok(attempts, DELAY).await.unwrap_err();
        assert_eq!(errors, vec![1, 2, 3]);
        assert_eq!(started.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn success_cancels_the_losing_attempt() {
        type BoxedAttempt = std::pin::Pin<Box<dyn Future<Output = Result<u32, u32>>>>;
        struct DropFlag(Arc<AtomicUsize>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let flag = DropFlag(dropped.clone());
        let loser = async move {
            let _flag = flag;
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(1)
        };
        let winner_started = Arc::new(AtomicUsize::new(0));
        let attempts: Vec<BoxedAttempt> = vec![
            Box::pin(loser),
            Box::pin(attempt(&winner_started, Duration::from_millis(1), Ok(2))),
        ];
        let winner = staggered_first_ok(attempts, DELAY).await.unwrap();
        assert_eq!(winner, 2);
        // The hung attempt was dropped (cancelled) when the winner returned.
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn no_attempts_fails_with_no_errors() {
        let attempts: Vec<std::future::Ready<Result<u32, u32>>> = vec![];
        let errors = staggered_first_ok(attempts, DELAY).await.unwrap_err();
        assert!(errors.is_empty());
    }
}
