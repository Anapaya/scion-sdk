// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.ClientSettings
import com.anapaya.scion.http3.internal.DebugGuard
import com.anapaya.scion.http3.internal.Http3Backend
import com.anapaya.scion.http3.internal.Http3BackendFactory
import com.anapaya.scion.http3.internal.LibraryLog
import com.anapaya.scion.http3.internal.MonotonicClock
import com.anapaya.scion.http3.internal.NetworkIdentity
import com.anapaya.scion.http3.internal.NetworkMonitor
import com.anapaya.scion.http3.internal.PemEncoder
import com.anapaya.scion.http3.internal.StalenessTracker
import com.anapaya.scion.http3.internal.SystemTrustStore
import com.anapaya.scion.http3.uniffi.Header
import com.anapaya.scion.http3.uniffi.HttpRequest
import com.anapaya.scion.http3.uniffi.HttpResponse
import kotlinx.coroutines.CompletableDeferred
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

// What the unit tier stands on.
//
// These fakes replace the two things a desktop JVM does not have: the native library the generated
// bindings call, and the Android framework. Everything above them is the real code.
//
// What that buys, and what it does not, is worth being precise about. It shows that the decisions
// this library makes are the right ones *given* that the stack and the framework behave as modelled
// here. It cannot show that they do behave that way. Whether a cancelled call really reaches the
// Rust future, and whether the timeouts and error arms mean what they say, is covered by
// `scion-http3-jvm-test` against a real library and a real SCION topology; whether
// `ConnectivityManager` delivers what `ConnectivityNetworkMonitor` assumes is covered by the
// instrumented tests on an emulator.
//
// So the fakes are kept deliberately dumb. [FakeBackend] answers with what it was told to answer
// with and keeps no connection state of its own, because a fake that started modelling the stack
// would drift from it, and tests would then pass against a model nobody maintains.

/** Records what reached the FFI, and answers with whatever the test set up. */
internal class FakeBackend : Http3Backend {
    val requests: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
    val warmedUp: MutableList<String> = Collections.synchronizedList(mutableListOf())
    val tokens: MutableList<String> = Collections.synchronizedList(mutableListOf())

    val resets = AtomicInteger(0)
    val shutdowns = AtomicInteger(0)
    val closes = AtomicInteger(0)

    /** What [execute] answers with. */
    var response: HttpResponse = response(status = 200)

    /** Thrown from [execute] instead of answering, when set. */
    var failure: Throwable? = null

    /** When set, [execute] suspends on this until the test completes it. */
    var gate: CompletableDeferred<Unit>? = null

    /** Set while a suspended [execute] is cancelled, which is what proves cancellation arrived. */
    @Volatile
    var executeWasCancelled: Boolean = false

    /** When true, [reset] throws as the generated bindings do for a destroyed handle. */
    var resetThrows: Boolean = false

    /** Thrown from [setAuthToken] instead of recording it, as the stack does without a token. */
    var setAuthTokenFailure: Throwable? = null

    /**
     * Makes every call throw the way the generated bindings do once the handle is destroyed.
     *
     * Set by [close] as well, so that the fake keeps the property the real one has: a call reaching
     * a destroyed handle fails rather than quietly succeeding.
     */
    @Volatile
    var destroyed: Boolean = false

    override suspend fun execute(request: HttpRequest): HttpResponse {
        requests += request
        gate?.let {
            try {
                it.await()
            } catch (e: kotlinx.coroutines.CancellationException) {
                executeWasCancelled = true
                throw e
            }
        }
        // After the gate, not before it: a close destroys the handle while a call is already inside
        // it, and that is the window worth being able to reproduce.
        requireLive()
        failure?.let { throw it }
        return response
    }

    override suspend fun warmUp(url: String) {
        requireLive()
        warmedUp += url
        failure?.let { throw it }
    }

    override fun reset() {
        resets.incrementAndGet()
        if (resetThrows) throw IllegalStateException("handle already destroyed")
    }

    override fun setAuthToken(token: String) {
        setAuthTokenFailure?.let { throw it }
        tokens += token
    }

    override suspend fun shutdown() {
        requireLive()
        shutdowns.incrementAndGet()
    }

    override fun close() {
        closes.incrementAndGet()
        destroyed = true
    }

    private fun requireLive() {
        // The wording the generated bindings use, so a test asserting on it is asserting on what a
        // caller would really see.
        check(!destroyed) { "ScionHttp3Client object has already been destroyed" }
    }
}

/** Hands out a backend, and counts how often it was asked for one. */
internal class FakeBackendFactory(
    val backend: FakeBackend = FakeBackend(),
) : Http3BackendFactory {
    val creations = AtomicInteger(0)
    val settings: MutableList<ClientSettings> = Collections.synchronizedList(mutableListOf())

    /** Runs while a backend is being built, for testing what a concurrent close does. */
    var whileCreating: (() -> Unit)? = null

    /** Thrown instead of building one, as the Rust constructor can. */
    var failure: Throwable? = null

    override fun create(settings: ClientSettings): Http3Backend {
        this.settings += settings
        creations.incrementAndGet()
        whileCreating?.invoke()
        failure?.let { throw it }
        return backend
    }
}

/** A clock the test moves by hand. */
internal class FakeClock(
    var nowMillis: Long = 1_000,
) : MonotonicClock {
    override fun elapsedRealtimeMillis(): Long = nowMillis

    fun advance(millis: Long) {
        nowMillis += millis
    }
}

/** A monitor whose observations and probe answers the test controls. */
internal class FakeNetworkMonitor(
    var current: NetworkIdentity? = null,
) : NetworkMonitor {
    private var observer: ((NetworkIdentity) -> Unit)? = null

    var starts: Int = 0
        private set
    var stops: Int = 0
        private set

    /** Thrown by [currentIdentity] when set, as a framework call can. */
    var probeThrows: RuntimeException? = null

    override fun start(onObserved: (NetworkIdentity) -> Unit) {
        starts++
        observer = onObserved
    }

    override fun currentIdentity(): NetworkIdentity? {
        probeThrows?.let { throw it }
        return current
    }

    override fun stop() {
        stops++
    }

    /** Delivers an observation the way the framework would. */
    fun observe(identity: NetworkIdentity) {
        val observer = requireNotNull(observer) { "the monitor was never started" }
        observer(identity)
    }
}

/** Answers with a fixed bundle, and counts how often it was asked. */
internal class FakeTrustStore(
    private val pem: ByteArray = "-----BEGIN CERTIFICATE-----\n".toByteArray(),
) : SystemTrustStore {
    val reads = AtomicInteger(0)

    override fun anchorsPem(): ByteArray {
        reads.incrementAndGet()
        return pem
    }
}

internal class FakeDebugGuard(
    private val debuggable: Boolean,
) : DebugGuard {
    override fun isDebuggable(): Boolean = debuggable
}

/** Keeps what was logged, so a test can assert that something was said and how loudly. */
internal class RecordingLog : LibraryLog {
    val errors: MutableList<String> = mutableListOf()
    val warnings: MutableList<String> = mutableListOf()
    val debugs: MutableList<String> = mutableListOf()

    override fun error(message: String) {
        errors += message
    }

    override fun warn(message: String) {
        warnings += message
    }

    override fun debug(message: String) {
        debugs += message
    }
}

// Builders for the fixtures every test needs, so that a test says only what it is actually about.

internal fun settings(
    endhostApiUrl: String = "https://endhost-api.example.org",
    trust: TrustAnchors = TrustAnchors.systemDefault(),
    idleConnectionTimeoutMillis: Long? = null,
    authToken: String? = null,
): ClientSettings =
    ClientSettings(
        endhostApiUrl = endhostApiUrl,
        trust = trust,
        idleConnectionTimeoutMillis = idleConnectionTimeoutMillis,
        authToken = authToken,
    )

internal fun response(
    status: Int = 200,
    headers: List<Header> = emptyList(),
    body: ByteArray = ByteArray(0),
    trailers: List<Header> = emptyList(),
): HttpResponse =
    HttpResponse(
        status = status.toUShort(),
        headers = headers,
        body = body,
        trailers = trailers,
    )

internal fun identity(
    handle: Long = 100,
    interfaceName: String? = "wlan0",
    addresses: Set<String> = setOf("192.168.1.10/24"),
    validated: Boolean = true,
): NetworkIdentity = NetworkIdentity(handle, interfaceName, addresses, validated)

/** A client wired to fakes, which is how every lifecycle and staleness test builds one. */
internal fun client(
    factory: FakeBackendFactory = FakeBackendFactory(),
    monitor: FakeNetworkMonitor = FakeNetworkMonitor(),
    clock: FakeClock = FakeClock(),
    log: RecordingLog = RecordingLog(),
    settings: ClientSettings = settings(),
    idleThresholdMillis: Long = settings.idleThresholdMillis,
): ScionHttp3Client =
    ScionHttp3Client(
        settings = settings,
        backends = factory,
        monitor = monitor,
        staleness = StalenessTracker(clock, idleThresholdMillis, log),
        log = log,
    )

internal fun request(
    url: String = "https://example.org/hello",
    build: ScionHttp3Request.Builder.() -> Unit = {},
): ScionHttp3Request =
    ScionHttp3Request
        .Builder()
        .url(url)
        .apply(build)
        .build()

/**
 * The host JVM's own certificate authorities.
 *
 * The only real certificates available to a unit test, and enough for what the trust-anchor tests
 * need: something that genuinely parses, and that a round-trip can be checked against. It is also
 * exactly what the production code reads on a desktop JVM, since it reads the platform's anchors
 * through plain JDK API.
 */
internal fun platformAnchors(limit: Int = 3): List<X509Certificate> {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(null as KeyStore?)
    return factory.trustManagers
        .filterIsInstance<X509TrustManager>()
        .flatMap { it.acceptedIssuers.asList() }
        .take(limit)
}

/** A PEM bundle that really parses, for the tests that need one to hand. */
internal val validPem: ByteArray by lazy { PemEncoder.encode(platformAnchors(limit = 1)) }

/** Bytes written as the numbers they are read as, rather than as signed Kotlin literals. */
internal fun bytesOf(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
