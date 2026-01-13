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
//! Common SCION stack types.

use std::{
    future::Future,
    sync::{Arc, RwLock, Weak},
};

/// A future that resolves to a Result.
pub trait ResFut<'a, R, E>: Future<Output = Result<R, E>> + Send + 'a {}
impl<'a, R, E, T: Future<Output = Result<R, E>> + Send + 'a> ResFut<'a, R, E> for T {}

/// A list of subscribers held as weak references.
///
/// This type is useful for implementing observer/listener patterns where:
/// - Subscribers register to receive notifications
/// - The registry doesn't keep subscribers alive (weak references)
/// - Dead subscribers are cleaned up during registration
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use scion_stack::types::Subscribers;
///
/// trait EventReceiver: Send + Sync {
///     fn on_event(&self, data: &str);
/// }
///
/// struct MyReceiver;
/// impl EventReceiver for MyReceiver {
///     fn on_event(&self, data: &str) {
///         println!("Received: {}", data);
///     }
/// }
///
/// let subscribers: Subscribers<dyn EventReceiver> = Subscribers::new();
/// let receiver: Arc<dyn EventReceiver> = Arc::new(MyReceiver);
///
/// subscribers.register(receiver.clone());
///
/// subscribers.for_each(|r| r.on_event("hello"));
/// drop(receiver);
/// ```
pub struct Subscribers<T: ?Sized + Send + Sync + 'static> {
    receivers: Arc<RwLock<Vec<Weak<T>>>>,
}

impl<T: ?Sized + Send + Sync + 'static> Clone for Subscribers<T> {
    fn clone(&self) -> Self {
        Self {
            receivers: Arc::clone(&self.receivers),
        }
    }
}

impl<T: ?Sized + Send + Sync + 'static> Subscribers<T> {
    /// Creates a new empty set of subscribers.
    pub fn new() -> Self {
        Self {
            receivers: Arc::new(RwLock::new(vec![])),
        }
    }

    /// Register a subscriber. The subscriber is held as a weak reference
    /// and will be automatically removed when dropped.
    pub fn register(&self, subscriber: Arc<T>) {
        let weak = Arc::downgrade(&subscriber);
        let mut receivers = self.receivers.write().expect("lock poisoned");
        // Remove dead weak references while we're at it
        receivers.retain(|r| r.strong_count() > 0);
        receivers.push(weak);
    }

    /// Execute a closure for each live subscriber.
    pub fn for_each(&self, mut f: impl FnMut(&T)) {
        let receivers = self.receivers.read().expect("lock poisoned");
        for receiver in receivers.iter() {
            if let Some(receiver) = receiver.upgrade() {
                f(&*receiver);
            }
        }
    }
}

impl<T: ?Sized + Send + Sync + 'static> Default for Subscribers<T> {
    fn default() -> Self {
        Self::new()
    }
}
