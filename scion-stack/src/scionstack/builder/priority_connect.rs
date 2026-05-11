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

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::sync::watch;

/// Tries to apply f to items across priority groups concurrently.
///
/// Groups are tried in order of priority: items in group 0 start immediately,
/// items in group `k` start after `k * per_group_delay` **or** as soon as
/// group `k-1` is fully exhausted (all items resolved, regardless of outcome),
/// whichever comes first.
///
/// Returns the first successful result together with the item that produced it.
/// If every item fails, returns all `(item, error)` pairs.
pub(super) async fn try_priority_groups<Item, T, E, F, Fut>(
    groups: Vec<Vec<Item>>,
    f: F,
    per_group_delay: Duration,
) -> Result<(Item, T), Vec<(Item, E)>>
where
    Item: Clone + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
    F: Fn(Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
{
    // Only consider non-empty groups.
    let groups: Vec<Vec<Item>> = groups
        .into_iter()
        .filter(|group| !group.is_empty())
        .collect();

    // One watch channel per group; flips to true when all items in that group
    // have completed (success or failure).
    let group_done: Vec<Arc<watch::Sender<bool>>> = (0..groups.len())
        .map(|_| Arc::new(watch::Sender::new(false)))
        .collect();

    let mut futures: FuturesUnordered<_> = FuturesUnordered::new();

    for (group_idx, group) in groups.into_iter().enumerate() {
        let remaining = Arc::new(AtomicUsize::new(group.len()));
        let my_done_tx = group_done[group_idx].clone();
        let prev_done_rx = (group_idx > 0).then(|| group_done[group_idx - 1].subscribe());
        let delay = per_group_delay * group_idx as u32;

        for item in group {
            let f = f.clone();
            let remaining = remaining.clone();
            let my_done_tx = my_done_tx.clone();
            let mut prev_done_rx = prev_done_rx.clone();

            futures.push(async move {
                // Wait for either the staggered delay or the previous group to
                // be fully exhausted — whichever fires first.
                if let Some(ref mut rx) = prev_done_rx {
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = rx.wait_for(|&done| done) => {}
                    }
                }

                let item_for_call = item.clone();
                let result = f(item_for_call).await;

                // Signal group exhaustion after the last item in the group
                // completes (regardless of whether it succeeded or failed).
                if remaining.fetch_sub(1, Ordering::Relaxed) == 1 {
                    let _ = my_done_tx.send(true);
                }

                (item, result)
            });
        }
    }

    let mut errors = Vec::new();
    while let Some((item, result)) = futures.next().await {
        match result {
            Ok(value) => return Ok((item, value)),
            Err(e) => errors.push((item, e)),
        }
    }
    Err(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    /// Describes the behaviour of a single fake API endpoint.
    #[derive(Clone)]
    enum Outcome {
        /// Succeed after the given delay.
        Ok(Duration),
        /// Fail after the given delay.
        Err(Duration),
    }

    /// Succeed after `ms` milliseconds. Use `ok_after(0)` for an immediate success.
    fn ok_after(ms: u64) -> Outcome {
        Outcome::Ok(Duration::from_millis(ms))
    }

    /// Fail after `ms` milliseconds. Use `err_after(0)` for an immediate failure.
    fn err_after(ms: u64) -> Outcome {
        Outcome::Err(Duration::from_millis(ms))
    }

    /// Runs `try_priority_groups` with the given specs and returns either the
    /// winning item tag or the list of failed item tags.
    ///
    /// Items are labelled `"gXaY"` (group X, API Y within the group) so
    /// assertions can pinpoint the winner.
    async fn run_groups(
        specs: Vec<Vec<Outcome>>,
        per_group_delay_ms: u64,
    ) -> Result<String, Vec<String>> {
        let groups: Vec<Vec<(String, Outcome)>> = specs
            .into_iter()
            .enumerate()
            .map(|(g, apis)| {
                apis.into_iter()
                    .enumerate()
                    .map(|(a, outcome)| (format!("g{g}a{a}"), outcome))
                    .collect()
            })
            .collect();

        let result = try_priority_groups(
            groups,
            |(tag, outcome)| {
                async move {
                    match outcome {
                        Outcome::Ok(delay) => {
                            tokio::time::sleep(delay).await;
                            Ok(tag)
                        }
                        Outcome::Err(delay) => {
                            tokio::time::sleep(delay).await;
                            Err(tag)
                        }
                    }
                }
            },
            Duration::from_millis(per_group_delay_ms),
        )
        .await;

        match result {
            Ok((_item, winner)) => Ok(winner),
            Err(errors) => Err(errors.into_iter().map(|(_item, tag)| tag).collect()),
        }
    }

    // ---------------------------------------------------------------------------
    // Single-item groups
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn group0_wins() {
        tokio::time::pause();
        let result = run_groups(vec![vec![ok_after(0)], vec![ok_after(0)]], 500).await;
        assert_eq!(result.unwrap(), "g0a0");
    }

    #[tokio::test]
    async fn group1_wins_when_group0_fails_fast() {
        tokio::time::pause();
        // Group 0 fails immediately → watch fires → group 1 starts without
        // waiting for the full per-group delay.
        let result = run_groups(vec![vec![err_after(0)], vec![ok_after(0)]], 500).await;
        assert_eq!(result.unwrap(), "g1a0");
    }

    #[tokio::test]
    async fn group1_wins_when_group0_is_slow() {
        tokio::time::pause();
        let fut = tokio::spawn(run_groups(
            vec![vec![err_after(10_000)], vec![ok_after(0)]],
            500,
        ));
        // Advance past the per-group delay so group 1 wakes up.
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(fut.await.unwrap().unwrap(), "g1a0");
    }

    #[tokio::test]
    async fn all_groups_fail() {
        tokio::time::pause();
        let mut errors = run_groups(vec![vec![err_after(0)], vec![err_after(0)]], 500)
            .await
            .unwrap_err();
        errors.sort();
        assert_eq!(errors, &["g0a0", "g1a0"]);
    }

    #[tokio::test]
    async fn group2_wins_when_groups01_fail_fast() {
        tokio::time::pause();
        let result = run_groups(
            vec![vec![err_after(0)], vec![err_after(0)], vec![ok_after(0)]],
            500,
        )
        .await;
        assert_eq!(result.unwrap(), "g2a0");
    }

    #[tokio::test]
    async fn group2_wins_when_groups01_are_slow() {
        tokio::time::pause();
        let fut = tokio::spawn(run_groups(
            vec![
                vec![err_after(10_000)],
                vec![err_after(10_000)],
                vec![ok_after(0)],
            ],
            500,
        ));
        // Advance past two per-group delays (500ms each) so group 2 wakes up.
        tokio::time::advance(Duration::from_millis(1000)).await;
        assert_eq!(fut.await.unwrap().unwrap(), "g2a0");
    }

    // ---------------------------------------------------------------------------
    // Multi-item groups
    // Each group gains an extra err_after(0) item to verify:
    //   - within-group parallelism works correctly, and
    //   - a fast-failing sibling does not prematurely fire the "group exhausted" watch signal while
    //     a slow sibling is still in flight.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn group0_wins_multi() {
        tokio::time::pause();
        let result = run_groups(
            vec![
                vec![ok_after(0), err_after(0)],
                vec![ok_after(0), err_after(0)],
            ],
            500,
        )
        .await;
        assert_eq!(result.unwrap(), "g0a0");
    }

    #[tokio::test]
    async fn group1_wins_when_group0_fails_fast_multi() {
        tokio::time::pause();
        let result = run_groups(
            vec![
                vec![err_after(0), err_after(0)],
                vec![ok_after(0), err_after(0)],
            ],
            500,
        )
        .await;
        assert_eq!(result.unwrap(), "g1a0");
    }

    #[tokio::test]
    async fn group1_wins_when_group0_is_slow_multi() {
        tokio::time::pause();
        // Group 0 has one very slow item and one immediate failure.
        // The fast failure alone must NOT fire the watch; the group is only
        // exhausted when the slow item also completes.
        let fut = tokio::spawn(run_groups(
            vec![
                vec![err_after(10_000), err_after(0)],
                vec![ok_after(0), err_after(0)],
            ],
            500,
        ));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(fut.await.unwrap().unwrap(), "g1a0");
    }

    #[tokio::test]
    async fn all_groups_fail_multi() {
        tokio::time::pause();
        let mut errors = run_groups(
            vec![
                vec![err_after(0), err_after(0)],
                vec![err_after(0), err_after(0)],
            ],
            500,
        )
        .await
        .unwrap_err();
        errors.sort();
        assert_eq!(errors, &["g0a0", "g0a1", "g1a0", "g1a1"]);
    }

    #[tokio::test]
    async fn group2_wins_when_groups01_fail_fast_multi() {
        tokio::time::pause();
        let result = run_groups(
            vec![
                vec![err_after(0), err_after(0)],
                vec![err_after(0), err_after(0)],
                vec![ok_after(0), err_after(0)],
            ],
            500,
        )
        .await;
        assert_eq!(result.unwrap(), "g2a0");
    }

    #[tokio::test]
    async fn group2_wins_when_groups01_are_slow_multi() {
        tokio::time::pause();
        // Groups 0 and 1 each have one very slow item and one immediate failure.
        // Group 2 starts only after both preceding groups are fully exhausted
        // (via delay, since the slow items prevent the watch from firing early).
        let fut = tokio::spawn(run_groups(
            vec![
                vec![err_after(10_000), err_after(0)],
                vec![err_after(10_000), err_after(0)],
                vec![ok_after(0), err_after(0)],
            ],
            500,
        ));
        tokio::time::advance(Duration::from_millis(1000)).await;
        assert_eq!(fut.await.unwrap().unwrap(), "g2a0");
    }
}
