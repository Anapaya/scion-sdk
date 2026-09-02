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

//! The cancellation handle for a binding that cannot cancel by dropping the exported future.
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

/// A one-shot cancellation for one call to
/// [`execute_cancellable`](crate::ScionHttp3Client::execute_cancellable).
///
/// One handle serves one request: a request given a handle that has already fired is cancelled
/// before anything reaches the network. Create a handle per call.
///
/// Dropping a handle cancels nothing. A request whose caller stopped holding the handle runs to
/// completion, which is what dropping one means.
#[derive(Debug, Default, uniffi::Object)]
pub struct CancelHandle {
    token: CancellationToken,
}

#[uniffi::export]
impl CancelHandle {
    /// Creates a handle that has not fired.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(CancelHandle::default())
    }

    /// Cancels the request this handle was passed to.
    ///
    /// Returns immediately and never fails. The request it cancels then completes with
    /// [`Cancelled`](crate::ScionHttp3Error::Cancelled). Calling it a second time
    /// or calling it once the request has finished is a noop.
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

impl CancelHandle {
    /// The token a request awaits, cloned so the request outlives the handle.
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_handle_has_not_fired() {
        assert!(!CancelHandle::new().token().is_cancelled());
    }

    #[test]
    fn cancelling_twice_is_the_same_as_once() {
        let handle = CancelHandle::new();

        handle.cancel();
        handle.cancel();

        assert!(handle.token().is_cancelled());
    }

    /// A caller that drops it without firing must not cancel the request it was holding it for.
    #[test]
    fn dropping_the_handle_cancels_nothing() {
        let handle = CancelHandle::new();
        // As the request holds it: taken before the handle goes away.
        let token = handle.token();

        drop(handle);

        assert!(
            !token.is_cancelled(),
            "dropping the handle cancelled the request"
        );
    }
}
