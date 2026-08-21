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

package com.anapaya.scion.http3

import android.content.Context
import com.anapaya.scion.http3.internal.AndroidClock
import com.anapaya.scion.http3.internal.AndroidDebugGuard
import com.anapaya.scion.http3.internal.AndroidLog
import com.anapaya.scion.http3.internal.AndroidSystemTrustStore
import com.anapaya.scion.http3.internal.CachingTrustStore
import com.anapaya.scion.http3.internal.ClientSettings
import com.anapaya.scion.http3.internal.ConnectivityNetworkMonitor
import com.anapaya.scion.http3.internal.Http3Backend
import com.anapaya.scion.http3.internal.Http3BackendFactory
import com.anapaya.scion.http3.internal.LibraryLog
import com.anapaya.scion.http3.internal.NetworkIdentity
import com.anapaya.scion.http3.internal.NetworkMonitor
import com.anapaya.scion.http3.internal.StalenessTracker
import com.anapaya.scion.http3.internal.SystemTrustStore
import com.anapaya.scion.http3.internal.UniffiHttp3BackendFactory
import com.anapaya.scion.http3.internal.toFfi
import com.anapaya.scion.http3.internal.toPublic
import com.anapaya.scion.http3.internal.warnIfVerificationDisabled
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

/**
 * An HTTP client that sends its requests over SCION.
 *
 * Build one with [Builder], keep it for the life of the application, and close it when the
 * application is done with it. It is thread-safe, it is safe to call from any dispatcher, and it
 * holds the connections every request reuses, so building one per request would throw away the
 * connection each time and be far slower than it looks.
 *
 * ```kotlin
 * val client = ScionHttp3Client.Builder(context)
 *     .endhostApi("https://endhost-api.example.org")
 *     .authToken(token)
 *     .build()
 *
 * val rooms = client.get("https://chat.example.org/rooms").use { it.body.string() }
 * ```
 *
 * Building a client does no work: no network traffic, no disk, no threads. The first request
 * establishes connectivity, which is also when a mistake in the configuration first shows up.
 *
 * Requests are ordinary `suspend` functions and cancel the way any other does. Cancelling one resets
 * its HTTP/3 stream and leaves the connection usable.
 *
 * The client watches for network changes on its own. After the device moves between Wi-Fi and
 * cellular, connectivity is rebuilt on the next request; nothing has to be called for that to
 * happen. Requests that were in flight when the network went away do fail, and they are marked
 * [ScionHttp3Exception.isRetryable] so an idempotent request can be sent again.
 */
public class ScionHttp3Client internal constructor(
    private val settings: ClientSettings,
    private val backends: Http3BackendFactory,
    private val monitor: NetworkMonitor,
    private val staleness: StalenessTracker,
    private val log: LibraryLog,
) : Closeable {
    private val creation = Mutex()
    private val closed = AtomicBoolean(false)

    // Atomic rather than volatile so that closing and publishing cannot both release the same
    // backend: whichever of the two takes it out with getAndSet is the one that closes it.
    private val backend = AtomicReference<Http3Backend?>(null)

    // The token in force, which is not always the one the client was built with. Held here as well as
    // in the stack because a renewal can arrive before there is a stack to tell, and a token dropped
    // on the floor would be found missing much later, as a rejected request.
    private val authToken = AtomicReference(settings.authToken)

    /** Whether [close] or [shutdown] has been called. */
    public val isClosed: Boolean get() = closed.get()

    /** A call that will send [request] when it is executed. */
    public fun newCall(request: ScionHttp3Request): ScionHttp3Call =
        ScionHttp3Call(request) { send(it) }

    /**
     * `GET [url]`, with the client's own timeouts.
     *
     * The response holds its body, so close it when done, or read the body inside `use { }`.
     *
     * @throws ScionHttp3Exception if the request does not produce a response.
     */
    public suspend fun get(url: String): ScionHttp3Response =
        send(
            ScionHttp3Request
                .Builder()
                .url(url)
                .get()
                .build(),
        )

    /**
     * `POST [url]` with [body].
     *
     * @throws ScionHttp3Exception if the request does not produce a response.
     */
    public suspend fun post(
        url: String,
        body: ScionHttp3RequestBody,
    ): ScionHttp3Response =
        send(
            ScionHttp3Request
                .Builder()
                .url(url)
                .post(body)
                .build(),
        )

    /**
     * Establishes connectivity to [url]'s origin before a request needs it.
     *
     * Optional, and only worth it when the first request's latency matters and its URL is known
     * early: a splash screen can warm up the origin the first screen will call.
     *
     * @throws ScionHttp3Exception if connectivity cannot be established.
     */
    public suspend fun warmUp(url: String): Unit = withBackend { it.warmUp(url) }

    /**
     * Marks connectivity stale, so the next request rebuilds it.
     *
     * Returns immediately and does no work of its own; nothing is rebuilt until there is a request
     * to rebuild for, and a client that has not connected yet does nothing at all.
     *
     * Calling this is not usually necessary, since network changes are noticed without it. It is here
     * for what the library cannot see: a VPN going up, a captive portal being signed into, or an
     * application that knows more about its own connectivity than the platform reports.
     */
    public fun reset() {
        if (closed.get()) return
        staleness.onManualReset()
        resetQuietly(backend.get() ?: return)
    }

    /**
     * Replaces the token requests authenticate with.
     *
     * Takes effect on the next request, and keeps the connections already established. Ignored by a
     * closed client, as [reset] is.
     *
     * @throws IllegalStateException if the client was built without `authToken`. There is then
     *   nothing reading a token, so there is nothing to replace: build a client with one instead.
     */
    public fun setAuthToken(token: String) {
        require(token.isNotEmpty()) { "an auth token cannot be empty" }
        checkNotNull(settings.authToken) {
            "this client was built without an authToken, so there is no token to replace. " +
                "Pass one to ScionHttp3Client.Builder.authToken() instead."
        }
        if (closed.get()) {
            log.debug("ignoring a token renewal on a client that is already closed")
            return
        }
        authToken.set(token)
        // A client that has not connected yet has nothing to tell; the token it is holding now is
        // what the stack will be built with.
        val backend = backend.get() ?: return
        try {
            backend.setAuthToken(token)
        } catch (e: FfiException) {
            throw e.toPublic()
        }
    }

    /**
     * Closes the client and stops watching for network changes.
     *
     * Idempotent. Requests already in flight are faulted rather than awaited; use [shutdown] to let
     * the pool close gracefully. Anything issued afterwards fails with
     * [ScionHttp3Exception.Closed], and a closed client cannot be reopened.
     */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        monitor.stop()
        backend.getAndSet(null)?.close()
    }

    /**
     * Closes the connection pool gracefully, then the client.
     *
     * Waits for each connection to tell its peer it is going away, which is the polite thing to do
     * and lets a server release its own state promptly. Requests still in flight are faulted while
     * this runs rather than awaited.
     *
     * Idempotent, and a no-op once [close] has been called: closing cannot be undone, so there is
     * nothing left to shut down gracefully.
     */
    public suspend fun shutdown() {
        if (!closed.compareAndSet(false, true)) return
        monitor.stop()
        // Read after the flag is set, never before: a first request publishing a backend in between
        // would otherwise leave its runtime and its connections behind, with the client marked closed
        // and nothing holding a reference to them any more.
        val backend = backend.getAndSet(null) ?: return
        backend.shutdown()
        backend.close()
    }

    private suspend fun send(request: ScionHttp3Request): ScionHttp3Response =
        withBackend { it.execute(request.toFfi()).toPublic(request) }

    /**
     * Runs [block] against the backend, with everything every caller of it owes the stack.
     *
     * Building the backend is inside the mapped region deliberately. The Rust constructor is fallible
     * too, over what only it can judge, such as an outbound address that parses as text here and not
     * as an address there. Building it outside would let that reach the caller as the generated
     * exception, which is neither this library's type nor an `IOException`, and every arm of the
     * public hierarchy promises otherwise.
     */
    private suspend fun <T> withBackend(block: suspend (Http3Backend) -> T): T {
        try {
            val backend = backend()
            // Quietly: a close racing this request destroys the handle, and the request that follows
            // reports that as Closed. An exception from the marking itself would say nothing useful.
            if (staleness.onUseAttempt { monitor.currentIdentity() }) resetQuietly(backend)
            // Called directly, on the caller's dispatcher. The work happens on the runtime the stack
            // owns, so moving to Dispatchers.IO would only add a thread hop, and wrapping the call
            // in anything at all risks breaking the cancellation that reaches the HTTP/3 stream.
            return block(backend)
        } catch (e: FfiException) {
            // Only the stack's own failures. Never `catch (e: Exception)`, which would swallow the
            // CancellationException that a cancelled request is reported with.
            throw e.toPublic()
        } catch (e: IllegalStateException) {
            if (!closed.get()) throw e
            throw closedException(e)
        } finally {
            staleness.onUseComplete()
        }
    }

    /**
     * The backend, built on first use.
     *
     * Not built in [Builder.build] on purpose: constructing it starts the runtime that carries every
     * request, and reading the platform's trust anchors touches the disk. Neither belongs on the
     * thread that builds the client, which is usually the main thread inside `Application.onCreate`.
     */
    private suspend fun backend(): Http3Backend {
        requireOpen()
        backend.get()?.let { return it }
        return creation.withLock {
            backend.get()?.let { return@withLock it }
            val created = withContext(Dispatchers.IO) { backends.create(settings) }
            // Everything between building and publishing the backend has to hand it back on
            // failure. Otherwise, connections and the runtime would leak.
            try {
                // A token renewed before the first request went into the field rather than into a
                // stack that did not exist. This is where it catches up.
                authToken.get()?.takeIf { it != settings.authToken }?.let {
                    created.setAuthToken(
                        it,
                    )
                }
                monitor.start(::observe)
            } catch (e: Throwable) {
                created.close()
                throw e
            }
            backend.set(created)
            // Checked after publishing, and not before: close() does not take this lock, so it can
            // run at any point above, and checking before the store would leave a window where it
            // finds no backend to close while this goes on to publish one on a closed client, with a
            // network callback registered for the life of the process. Whichever of the two takes the
            // backend out closes it, so it is released exactly once either way.
            if (closed.get()) {
                monitor.stop()
                backend.getAndSet(null)?.close()
                throw closedException()
            }
            created
        }
    }

    private fun observe(identity: NetworkIdentity) {
        try {
            staleness.observe(identity)
        } catch (e: RuntimeException) {
            log.warn("ignoring a network observation that could not be handled: $e")
        }
    }

    private fun resetQuietly(backend: Http3Backend) {
        try {
            backend.reset()
        } catch (e: IllegalStateException) {
            // The handle was destroyed by a close that raced this call. Nothing to rebuild.
            log.debug("ignoring a reset of a client that is already closed ($e)")
        }
    }

    private fun requireOpen() {
        if (closed.get()) throw closedException()
    }

    private fun closedException(cause: Throwable? = null): ScionHttp3Exception =
        ScionHttp3Exception.Closed(
            isRetryable = false,
            detail = "this ScionHttp3Client is closed. Build another one to make requests again.",
            cause = cause,
        )

    /**
     * Collects what a client needs, and builds it.
     *
     * Two settings cover the common case: where the endhost API is, and the token for it. Everything
     * else has a default that comes from the SCION stack itself rather than from this library, so an
     * unset setting is not a value restated here that could drift from the real one.
     *
     * @param context any context; only its application context is kept, so passing an `Activity`
     *   does not hold on to it. It is required rather than optional because two things genuinely
     *   need it: reading the device's trust anchors, and watching for network changes.
     */
    public class Builder(
        context: Context,
    ) {
        private val context: Context = context.applicationContext ?: context

        private var endhostApi: String? = null
        private var authToken: String? = null
        private var preferredUnderlay: PreferredUnderlay? = null
        private var snap: SnapConfig? = null
        private var udp: UdpConfig? = null
        private var trust: TrustAnchors = TrustAnchors.systemDefault()
        private var connectTimeoutMillis: Long? = null
        private var requestTimeoutMillis: Long? = null
        private var idleConnectionTimeoutMillis: Long? = null
        private var connectionAttemptDelayMillis: Long? = null
        private var maxOrigins: Int? = null
        private var maxResponseBodyBytes: Long? = null
        private var networkMonitor: NetworkMonitor? = null

        /**
         * Where the client discovers SCION connectivity. Required.
         *
         * This, and not a choice of transport, is what points the client at a network: the endhost
         * API reports what is available and the client uses it.
         */
        public fun endhostApi(url: String): Builder {
            endhostApi = url
            return this
        }

        /**
         * The token for the endhost API and, unless [snap] overrides it, the SNAP control plane.
         */
        public fun authToken(token: String): Builder {
            authToken = token
            return this
        }

        /**
         * Which transport to favor among those the endhost API offers.
         *
         * A preference applied to what is available, not a selection. Leave it unset unless there is
         * a reason to prefer one.
         */
        public fun preferredUnderlay(underlay: PreferredUnderlay): Builder {
            preferredUnderlay = underlay
            return this
        }

        /** Settings for the SNAP transport, when its defaults do not fit. */
        public fun snap(config: SnapConfig): Builder {
            snap = config
            return this
        }

        /** Settings for the UDP transport, when its defaults do not fit. */
        public fun udp(config: UdpConfig): Builder {
            udp = config
            return this
        }

        /** Which authorities a server certificate is checked against. Defaults to the device's. */
        public fun trust(anchors: TrustAnchors): Builder {
            trust = anchors
            return this
        }

        /** How long establishing connectivity to an origin may take. */
        public fun connectTimeout(timeout: Duration): Builder =
            connectTimeoutMillis(timeout.inWholeMilliseconds)

        /** As [connectTimeout], in milliseconds, for Java callers. */
        public fun connectTimeoutMillis(millis: Long): Builder {
            connectTimeoutMillis = millis
            return this
        }

        /**
         * How long a whole request may take, from sending it to holding its body.
         *
         * Override it for one request with [ScionHttp3Request.Builder.requestTimeout].
         */
        public fun requestTimeout(timeout: Duration): Builder =
            requestTimeoutMillis(timeout.inWholeMilliseconds)

        /** As [requestTimeout], in milliseconds, for Java callers. */
        public fun requestTimeoutMillis(millis: Long): Builder {
            requestTimeoutMillis = millis
            return this
        }

        /** How long an unused connection is kept before it is closed. */
        public fun idleConnectionTimeout(timeout: Duration): Builder =
            idleConnectionTimeoutMillis(timeout.inWholeMilliseconds)

        /** As [idleConnectionTimeout], in milliseconds, for Java callers. */
        public fun idleConnectionTimeoutMillis(millis: Long): Builder {
            idleConnectionTimeoutMillis = millis
            return this
        }

        /**
         * How long to wait before trying the next of an origin's addresses.
         *
         * An origin can have several addresses, which are tried in a staggered race rather than one
         * after another. This is the stagger.
         */
        public fun connectionAttemptDelay(delay: Duration): Builder =
            connectionAttemptDelayMillis(delay.inWholeMilliseconds)

        /** As [connectionAttemptDelay], in milliseconds, for Java callers. */
        public fun connectionAttemptDelayMillis(millis: Long): Builder {
            connectionAttemptDelayMillis = millis
            return this
        }

        /**
         * How many origins the client keeps connections for.
         *
         * Origins, not connections: an application talking to two hosts needs two, however many
         * requests it makes.
         */
        public fun maxOrigins(origins: Int): Builder {
            maxOrigins = origins
            return this
        }

        /**
         * The largest response body to collect, in bytes.
         *
         * This is what bounds the memory a response can cost, since the body is collected before the
         * response is handed over. Override it for one request with
         * [ScionHttp3Request.Builder.maxResponseBody].
         */
        public fun maxResponseBody(bytes: Long): Builder {
            maxResponseBodyBytes = bytes
            return this
        }

        /**
         * Watches the network through [monitor] instead of through `ConnectivityManager`.
         */
        internal fun networkMonitor(monitor: NetworkMonitor): Builder {
            networkMonitor = monitor
            return this
        }

        /**
         * Builds the client. Performs no I/O.
         *
         * @throws IllegalArgumentException if a setting cannot be right: no endhost API, a URL that
         *   is not one, a timeout that is not positive. Whatever only the SCION stack can judge is
         *   reported by the first request instead.
         */
        public fun build(): ScionHttp3Client {
            val settings =
                ClientSettings(
                    endhostApiUrl = endhostApi.orEmpty(),
                    trust = trust,
                    authToken = authToken,
                    preferredUnderlay = preferredUnderlay,
                    snap = snap,
                    udp = udp,
                    connectTimeoutMillis = connectTimeoutMillis,
                    requestTimeoutMillis = requestTimeoutMillis,
                    idleConnectionTimeoutMillis = idleConnectionTimeoutMillis,
                    connectionAttemptDelayMillis = connectionAttemptDelayMillis,
                    maxOrigins = maxOrigins,
                    maxResponseBodyBytes = maxResponseBodyBytes,
                )
            warnIfVerificationDisabled(trust, AndroidDebugGuard(context), AndroidLog)
            return ScionHttp3Client(
                settings = settings,
                backends = UniffiHttp3BackendFactory(sharedTrustStore),
                monitor = networkMonitor ?: ConnectivityNetworkMonitor(context, AndroidLog),
                staleness =
                    StalenessTracker(
                        clock = AndroidClock,
                        idleThresholdMillis = settings.idleThresholdMillis,
                        log = AndroidLog,
                    ),
                log = AndroidLog,
            )
        }

        private companion object {
            /**
             * Read once per process, and shared by every client built in it.
             *
             * The anchors are the same for every client, and reading them costs a few hundred
             * certificates worth of parsing, so a second client should not pay for it again.
             */
            private val sharedTrustStore: SystemTrustStore =
                CachingTrustStore(AndroidSystemTrustStore())
        }
    }
}
