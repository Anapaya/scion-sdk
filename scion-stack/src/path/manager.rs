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

//! Multipath manager for SCION path selection.
//!
//! Runs one task per (src,dst) pair. Each task fetches paths, filters them, applies issue
//! penalties, ranks candidates, and picks an active path.
//!
//! Tasks track expiry, refetch intervals, backoff after failures, and drop entries that go
//! idle. The Active path for a (src,dst) pair is exposed lock-free via `ArcSwap`.
//!
//! All path data comes from the provided `PathFetcher`. Issue reports feed
//! into reliability scoring and can trigger immediate re-ranking.
//!
//! ## Issue Handling & Penalties
//!
//! Incoming issues are applied to cached paths immediately and can trigger an active-path
//! switch. Issues are cached with a timestamp and applied to newly fetched paths.
//!
//! Penalties on individual paths and individual cached issues decay over time. Allowing paths
//! to recover.
//!
//! ## Active Path Switching
//!
//! If no active path exists, the highest-ranked valid path is selected.
//! Active path is replaced when it expires, nears expiry, or falls behind the best candidate
//! by a configured score margin.

// Internal:
//
// ## Core components
//
// MultiPathManager: Central entry point. Holds configuration, the global issue manager, and a
// concurrent map from (src, dst) to worker. Spawns a worker on first access and provides lock-free
// reads to workers.
//
// PathSet: Per-tuple worker. Fetches paths, filters them, applies issue penalties, ranks
// candidates, and maintains an active path. Runs a periodic maintenance loop handling refetch,
// backoff, and idle shutdown.
//
// PathIssueManager:  Global issue cache and broadcast system. Deduplicates issues and notifies all
// workers of incoming issues.
//
// IssueKind / IssueMarker: Describe concrete path problems (SCMP, socket errors). Compute the
// affected hop or full path, assign a penalty, and support deduplication and decay.

//XXX(ake): will remove in next PR moving multipath_manager into this file, left here to make
// review easier
pub use super::multipath_manager::*;
