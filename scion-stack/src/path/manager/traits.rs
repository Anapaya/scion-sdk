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

use std::{io, time::Duration};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use scion_proto::{address::IsdAsn, path::Path};
use thiserror::Error;

use crate::types::ResFut;

/// Trait for active path management with async interface.
pub trait PathManager: SyncPathManager {
    /// Returns a path to the destination from the path cache or requests a new path from the
    /// SCION Control Plane.
    fn path_wait(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> impl ResFut<'_, Path<Bytes>, PathWaitError>;

    /// Returns a path to the destination from the path cache or requests a new path from the
    /// SCION Control Plane, with a maximum wait time.
    fn path_timeout(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
        timeout: Duration,
    ) -> impl ResFut<'_, Path<Bytes>, PathWaitTimeoutError> {
        let fut = self.path_wait(src, dst, now);
        async move {
            match tokio::time::timeout(timeout, fut).await {
                Ok(result) => {
                    result.map_err(|e| {
                        match e {
                            PathWaitError::FetchFailed(msg) => {
                                PathWaitTimeoutError::FetchFailed(msg)
                            }
                            PathWaitError::NoPathFound => PathWaitTimeoutError::NoPathFound,
                        }
                    })
                }
                Err(_) => Err(PathWaitTimeoutError::Timeout),
            }
        }
    }
}

/// Path wait errors.
#[derive(Debug, Clone, Error)]
pub enum PathWaitError {
    /// Path fetch failed.
    #[error("path fetch failed: {0}")]
    FetchFailed(String),
    /// No path found.
    #[error("no path found")]
    NoPathFound,
}

/// Path wait errors.
#[derive(Debug, Clone, Error)]
pub enum PathWaitTimeoutError {
    /// Path fetch failed.
    #[error("path fetch failed: {0}")]
    FetchFailed(String),
    /// No path found.
    #[error("no path found")]
    NoPathFound,
    /// Waiting for path timed out
    #[error("waiting for path timed out")]
    Timeout,
}

/// Trait for active path management with sync interface. Implementors of this trait should be
/// able to be used in sync and async context. The functions must not block.
pub trait SyncPathManager {
    /// Add a path to the path cache. This can be used to register reverse paths.
    fn register_path(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>, path: Path<Bytes>);

    /// Returns a path to the destination from the path cache.
    /// If the path is not in the cache, it returns Ok(None), possibly causing the path to be
    /// fetched in the background. If the cache is locked an io error WouldBlock is
    /// returned.
    fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> io::Result<Option<Path<Bytes>>>;
}

/// Trait for prefetching paths in the path manager.
pub trait PathPrefetcher {
    /// Prefetch a paths for the given source and destination.
    fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn);
}
