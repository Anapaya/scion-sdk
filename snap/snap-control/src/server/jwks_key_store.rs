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
//! JWKS-based key store for SNAP token verification.
//!
//! Keys are populated by a background worker that fetches the JWKS endpoint
//! periodically and on demand. Use [`JwksKeyStore::get_key`] for a synchronous
//! O(1) cache lookup on the happy path, and [`JwksKeyStore::await_key`] to wait
//! for a key that is not yet cached.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
    time::Duration,
};

use jsonwebtoken::{
    DecodingKey,
    jwk::{Jwk, JwkSet},
};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use url::Url;

/// A cache entry holding a decoded verification key alongside metadata for
/// observability and change detection.
struct KeyEntry {
    decoding_key: DecodingKey,
    /// Raw JWK used to detect key-material changes across refreshes.
    jwk: Jwk,
    /// Wall-clock time at which this entry was first inserted into the cache.
    first_seen: chrono::DateTime<chrono::Utc>,
    /// Wall-clock time at which the key material was last updated.
    /// Equals `first_seen` for keys that have never changed.
    last_updated: chrono::DateTime<chrono::Utc>,
    /// Number of times the key material has changed since first insertion.
    /// Zero at insertion; only incremented when the JWK differs from the stored one.
    version: u64,
}

type KeyId = String;

/// A key cache populated asynchronously from a JWKS endpoint.
///
/// # Architecture
///
/// On creation, a background worker task is spawned that fetches the JWKS endpoint:
/// - **periodically**, on a configurable interval (e.g. every 5 minutes), and
/// - **on demand**, when [`await_key`](JwksKeyStore::await_key) signals it via a [`Notify`].
///
/// Because the background worker is a single task, exactly one JWKS HTTP request
/// can be in flight at a time.
///
/// ## API
///
/// * [`get_key`](JwksKeyStore::get_key) — synchronous O(1) read-lock lookup. Never blocks; never
///   triggers a network request.
/// * [`await_key`](JwksKeyStore::await_key) — async; signals the worker and waits for one fetch
///   cycle to complete before returning the resolved key (or `None`).
#[derive(Clone)]
pub struct JwksKeyStore {
    jwks_url: Url,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<KeyId, KeyEntry>>>,
    /// Signals the background worker to start a fetch immediately.
    fetch_notify: Arc<Notify>,
    /// Write side of the fetch-generation watch channel. The background worker
    /// increments this after every fetch cycle (success or failure) so that
    /// `await_key` callers can observe that a fetch has completed.
    fetch_generation_tx: Arc<watch::Sender<u64>>,
    /// A receiver kept alive so that the watch channel remains open for the
    /// lifetime of this store. Cloned by `await_key` to subscribe.
    fetch_generation_rx: watch::Receiver<u64>,
}

impl fmt::Debug for JwksKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cache = self.cache.read().unwrap();
        let mut map = f.debug_map();
        for (kid, entry) in cache.iter() {
            map.entry(kid, &EntryDebug(entry));
        }
        map.finish()
    }
}

/// Helper to format a single [`KeyEntry`] in the [`JwksKeyStore`] `Debug` output.
struct EntryDebug<'a>(&'a KeyEntry);

impl fmt::Debug for EntryDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.0;
        f.debug_struct("KeyEntry")
            .field("decoding_key", &e.jwk)
            .field("first_seen", &e.first_seen)
            .field("last_updated", &e.last_updated)
            .field("version", &e.version)
            .finish()
    }
}

impl JwksKeyStore {
    /// Creates a new `JwksKeyStore` and starts its background refresh worker.
    ///
    /// * `refresh_interval` — how often the background worker refreshes the JWKS unconditionally.
    ///   Use a very large value to disable periodic refreshing and rely solely on demand-driven
    ///   fetches via [`await_key`](JwksKeyStore::await_key).
    /// * `cancellation_token` — signals the background worker to exit gracefully.
    pub fn new(
        jwks_url: Url,
        refresh_interval: Duration,
        cancellation_token: CancellationToken,
    ) -> Self {
        let (fetch_generation_tx, fetch_generation_rx) = watch::channel(0u64);
        let store = Self {
            jwks_url,
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            fetch_notify: Arc::new(Notify::new()),
            fetch_generation_tx: Arc::new(fetch_generation_tx),
            fetch_generation_rx,
        };
        let bg = store.clone();
        tokio::spawn(async move {
            bg.background_loop(refresh_interval, cancellation_token)
                .await;
        });
        store
    }

    /// Returns the `DecodingKey` for `kid` if it is already in the cache.
    ///
    /// This is a synchronous, non-blocking read-lock lookup. It never triggers
    /// any network activity. Use [`await_key`](JwksKeyStore::await_key) to wait
    /// for a key that is not yet cached.
    pub fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        self.cache
            .read()
            .unwrap()
            .get(kid)
            .map(|e| e.decoding_key.clone())
    }

    /// Returns the `DecodingKey` for `kid`, waiting for a JWKS fetch if needed.
    ///
    /// # Behaviour
    ///
    /// 1. Subscribes to the fetch-generation watch **before** the initial cache check to avoid the
    ///    race where a fetch completes between the cache miss and the subscription.
    /// 2. Returns immediately if the key is already cached ([`get_key`] fast path).
    /// 3. Signals the background worker to start an immediate fetch.
    /// 4. Waits for the background worker to complete exactly one fetch cycle.
    /// 5. Returns the key if found in the cache, or `None` if the `kid` is absent from the JWKS
    ///    response or the endpoint could not be reached.
    ///
    /// [`get_key`]: JwksKeyStore::get_key
    pub async fn await_key(&self, kid: &str) -> Option<DecodingKey> {
        // Step 1: subscribe before checking the cache to close the race window.
        let mut rx = self.fetch_generation_rx.clone();

        // Step 2: fast path — key already in cache.
        if let Some(key) = self.get_key(kid) {
            return Some(key);
        }

        // Step 3: wake the background worker for an immediate fetch.
        self.fetch_notify.notify_one();

        // Step 4: wait for one complete fetch cycle.
        // Err means the sender was dropped (shutdown in progress); treat as miss.
        let _ = rx.changed().await;

        // Step 5: re-check the cache after the fetch.
        self.get_key(kid)
    }

    /// Runs the background refresh loop until cancelled.
    ///
    /// Wakes on the periodic timer or on a signal from [`await_key`](JwksKeyStore::await_key),
    /// then fetches the JWKS and increments the generation counter.
    async fn background_loop(self, refresh_interval: Duration, ct: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = ct.cancelled() => break,
                _ = tokio::time::sleep(refresh_interval) => {},
                _ = self.fetch_notify.notified() => {},
            }
            self.do_fetch().await;
            // Always increment, even on failure, so await_key callers can proceed
            // and receive a definitive answer rather than hanging.
            self.fetch_generation_tx.send_modify(|g| *g += 1);
        }
    }

    /// Fetches the JWKS endpoint and merges the returned keys into the cache.
    ///
    /// On a network or HTTP error the warning is logged and the cache is left
    /// unchanged. Individual keys that cannot be parsed are skipped with a warning
    /// rather than aborting the entire update, so that one malformed key cannot
    /// block the rest.
    ///
    /// The per-entry `version` and `last_updated` fields are bumped only when the
    /// key material actually changes, so they remain stable for long-lived keys.
    async fn do_fetch(&self) {
        let jwks: JwkSet = match self
            .client
            .get(self.jwks_url.clone())
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Err(e) => {
                tracing::warn!(url = %self.jwks_url, error = %e, "failed to fetch JWKS");
                return;
            }
            Ok(resp) => {
                match resp.json().await {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::warn!(
                            url = %self.jwks_url,
                            error = %e,
                            "failed to parse JWKS response"
                        );
                        return;
                    }
                }
            }
        };

        let now = chrono::Utc::now();
        let mut cache = self.cache.write().unwrap();
        for jwk in &jwks.keys {
            let Some(kid) = &jwk.common.key_id else {
                continue;
            };
            let key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(
                        %kid,
                        error = %e,
                        "skipping JWKS key: failed to build decoding key"
                    );
                    continue;
                }
            };
            match cache.get_mut(kid.as_str()) {
                Some(entry) => {
                    if &entry.jwk != jwk {
                        tracing::debug!(%kid, version = entry.version + 1, "JWKS key material changed");
                        entry.decoding_key = key;
                        entry.jwk = jwk.clone();
                        entry.last_updated = now;
                        entry.version += 1;
                    }
                }
                None => {
                    tracing::debug!(%kid, "caching new JWKS key");
                    cache.insert(
                        kid.clone(),
                        KeyEntry {
                            decoding_key: key,
                            jwk: jwk.clone(),
                            first_seen: now,
                            last_updated: now,
                            version: 0,
                        },
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{Json, Router, routing::get};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use scion_sdk_token_validator::validator::insecure_const_ed25519_signing_key;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    use super::JwksKeyStore;

    /// Builds a JWKS JSON value using the shared test signing key for the given kid.
    fn test_jwks_json(kid: &str) -> serde_json::Value {
        let signing_key = insecure_const_ed25519_signing_key();
        let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
        serde_json::json!({
            "keys": [{
                "kid": kid,
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "crv": "Ed25519",
                "x": x
            }]
        })
    }

    /// Starts an axum test HTTP server serving the given body from
    /// `GET /.well-known/jwks.json`. Returns the URL and a request counter.
    async fn start_jwks_server(
        body: serde_json::Value,
        delay: Option<Duration>,
    ) -> (Url, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = {
            let counter = counter.clone();
            Router::new().route(
                "/.well-known/jwks.json",
                get(move || {
                    let body = body.clone();
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if let Some(d) = delay {
                            tokio::time::sleep(d).await;
                        }
                        Json(body)
                    }
                }),
            )
        };

        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let url = format!("http://{}/.well-known/jwks.json", addr)
            .parse()
            .unwrap();
        (url, counter)
    }

    /// Creates a store with a 1-hour refresh interval (tests drive fetches via `await_key`).
    fn make_store(url: Url) -> (JwksKeyStore, CancellationToken) {
        let ct = CancellationToken::new();
        let store = JwksKeyStore::new(url, Duration::from_secs(3600), ct.clone());
        (store, ct)
    }

    #[tokio::test]
    async fn cache_miss_triggers_fetch() {
        let kid = "test-kid-1";
        let (url, counter) = start_jwks_server(test_jwks_json(kid), None).await;
        let (store, _ct) = make_store(url);

        let result = store.await_key(kid).await;
        assert!(result.is_some(), "expected key for known kid");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "expected exactly one fetch"
        );
    }

    #[tokio::test]
    async fn cache_hit_avoids_second_fetch() {
        let kid = "test-kid-2";
        let (url, counter) = start_jwks_server(test_jwks_json(kid), None).await;
        let (store, _ct) = make_store(url);

        store.await_key(kid).await.unwrap();
        let result = store.get_key(kid); // second lookup: synchronous fast path
        assert!(result.is_some(), "second lookup should hit the cache");
        assert_eq!(counter.load(Ordering::SeqCst), 1, "expected only one fetch");
    }

    #[tokio::test]
    async fn unknown_kid_returns_none_after_fetch() {
        let (url, _) = start_jwks_server(test_jwks_json("other-kid"), None).await;
        let (store, _ct) = make_store(url);

        let result = store.await_key("not-present").await;
        assert!(result.is_none(), "unknown kid should return None");
    }

    #[tokio::test]
    async fn fetch_failure_returns_none() {
        // Use a port that is not listening.
        let url: Url = "http://127.0.0.1:19999/.well-known/jwks.json"
            .parse()
            .unwrap();
        let (store, _ct) = make_store(url);

        let result = store.await_key("any-kid").await;
        assert!(result.is_none(), "fetch failure should return None");
    }

    #[tokio::test]
    async fn concurrent_requests_for_same_kid_trigger_single_fetch() {
        let kid = "test-kid-concurrent";
        // Add a delay so all concurrent callers are waiting on the watch when
        // the single background fetch completes.
        let (url, counter) =
            start_jwks_server(test_jwks_json(kid), Some(Duration::from_millis(50))).await;
        let ct = CancellationToken::new();
        let store = Arc::new(JwksKeyStore::new(
            url,
            Duration::from_secs(3600),
            ct.clone(),
        ));

        let handles: Vec<_> = (0..5)
            .map(|_| {
                let store = store.clone();
                let kid = kid.to_string();
                tokio::spawn(async move { store.await_key(&kid).await })
            })
            .collect();

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_some(), "all concurrent requests must succeed");
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "expected exactly one JWKS fetch despite concurrent requests"
        );
    }

    #[tokio::test]
    async fn periodic_refresh_fetches_on_interval() {
        let kid = "refresh-kid";
        let (url, counter) = start_jwks_server(test_jwks_json(kid), None).await;
        let ct = CancellationToken::new();
        // Use a very short interval to verify periodic refreshing.
        let _store = JwksKeyStore::new(url, Duration::from_millis(30), ct.clone());

        // Allow time for several periodic refresh cycles.
        tokio::time::sleep(Duration::from_millis(150)).await;
        ct.cancel();

        assert!(
            counter.load(Ordering::SeqCst) >= 2,
            "expected at least two periodic fetches, got {}",
            counter.load(Ordering::SeqCst)
        );
    }
}
