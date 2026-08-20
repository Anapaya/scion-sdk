// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.CachingTrustStore
import com.anapaya.scion.http3.internal.ClientSettings
import com.anapaya.scion.http3.internal.StalenessTracker
import com.anapaya.scion.http3.internal.SystemTrustStore
import com.anapaya.scion.http3.internal.warnIfVerificationDisabled
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.IOException

/**
 * What building a client does, and above all what it does not do.
 *
 * "Construction performs no I/O" is a promise about an application's startup path: a client is built
 * in `Application.onCreate`, on the main thread, and starting a runtime or reading a few hundred
 * certificates there is a dropped frame at best. It is also the promise a well-meaning change breaks
 * most easily, by validating something eagerly that needs the stack to validate it.
 */
class ClientConstructionTest {
    @Test
    fun `building a client builds no backend and asks nothing of the platform`() {
        val factory = FakeBackendFactory()
        val monitor = FakeNetworkMonitor()
        val trustStore = FakeTrustStore()

        client(factory = factory, monitor = monitor)

        assertEquals(0, factory.creations.get(), "no runtime, no threads, no rustls provider")
        assertEquals(0, trustStore.reads.get(), "and no disk read for the trust anchors")
        assertEquals(0, monitor.starts, "and no callback registered with the framework")
    }

    @Test
    fun `the first request builds the backend, and only one of them does`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)

            coroutineScope {
                List(8) { async { client.get("https://example.org/hello") } }.awaitAll()
            }

            assertEquals(
                1,
                factory.creations.get(),
                "eight requests on a cold client must not race into eight stacks",
            )
            assertEquals(8, factory.backend.requests.size)
        }

    @Test
    fun `the monitor starts with the backend, not before it`(): Unit =
        runBlocking {
            val monitor = FakeNetworkMonitor()
            val client = client(monitor = monitor)
            assertEquals(0, monitor.starts)

            client.get("https://example.org/hello")

            assertEquals(1, monitor.starts, "there is nothing to mark stale until there is a stack")
        }

    @Test
    fun `a backend built while close ran is closed rather than published`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            factory.whileCreating = { client.close() }

            assertThrows<ScionHttp3Exception.Closed> { client.get("https://example.org/hello") }

            assertEquals(
                1,
                factory.backend.closes.get(),
                "a stack nobody can reach still owns a runtime, which nothing else would close",
            )
        }

    @Test
    fun `a backend that cannot be built fails as this library's own exception`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            // What the Rust constructor rejects, over what only it can judge: an outbound address
            // that is text here and an address there.
            factory.failure =
                com.anapaya.scion.http3.uniffi.ScionHttp3Exception.InvalidRequest(
                    retryable = false,
                    detail = "invalid outbound IP: not-an-ip",
                )
            val client = client(factory = factory)

            val failure =
                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.get(
                        "https://example.org/x",
                    )
                }

            assertEquals("invalid outbound IP: not-an-ip", failure.detail)
            assertInstanceOf(
                IOException::class.java,
                failure,
                "building the stack happens on the first request, so its failures are request " +
                    "failures and have to arrive as ones",
            )
        }

    @Test
    fun `a backend that cannot be built is not remembered as built`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.failure =
                com.anapaya.scion.http3.uniffi.ScionHttp3Exception.StackBuild(
                    retryable = true,
                    detail = "the endhost API could not be reached",
                )
            val client = client(factory = factory)

            assertThrows<ScionHttp3Exception.Connectivity> { client.get("https://example.org/a") }
            factory.failure = null
            client.get("https://example.org/b")

            assertEquals(
                2,
                factory.creations.get(),
                "a retryable failure has to leave the client able to try again",
            )
        }

    @Test
    fun `a platform with no trust anchors fails the request rather than the process`(): Unit =
        runBlocking {
            val store = CachingTrustStore(SystemTrustStore { ByteArray(0) })
            val factory =
                FakeBackendFactory().also { fake ->
                    fake.whileCreating = { store.anchorsPem() }
                }
            val client = client(factory = factory)

            val failure =
                assertThrows<ScionHttp3Exception.Connectivity> {
                    client.get(
                        "https://example.org/x",
                    )
                }

            assertTrue(failure.detail.contains("TrustAnchors.pinned()"))
        }

    @Test
    fun `endhostApi is required, and says what it is for`() {
        val failure =
            assertThrows<IllegalArgumentException> {
                ClientSettings(
                    "",
                    TrustAnchors.systemDefault(),
                )
            }
        assertTrue(failure.message!!.contains("endhostApi is required"))
        assertTrue(
            failure.message!!.contains("10.0.2.2"),
            "the message is where someone stuck on their first client will look",
        )
    }

    @Test
    fun `an endhostApi that cannot be a URL is rejected`() {
        assertThrows<IllegalArgumentException> {
            settings(
                endhostApiUrl = "endhost-api.example.org",
            )
        }
        assertThrows<IllegalArgumentException> {
            settings(
                endhostApiUrl = "ftp://endhost.example.org",
            )
        }
        assertThrows<IllegalArgumentException> { settings(endhostApiUrl = "https://") }
    }

    @Test
    fun `a plaintext endhostApi is allowed, because PocketSCION is plaintext`() {
        settings(endhostApiUrl = "http://10.0.2.2:8041")
    }

    @Test
    fun `settings that cannot be right are rejected`() {
        assertThrows<IllegalArgumentException> {
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
                connectTimeoutMillis = 0,
            )
        }
        assertThrows<IllegalArgumentException> {
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
                maxOrigins = 0,
            )
        }
        assertThrows<IllegalArgumentException> {
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
                authToken = "",
            )
        }
    }

    @Test
    fun `disabling verification is loud, and louder in a release build`() {
        val debuggable = RecordingLog()
        warnIfVerificationDisabled(
            TrustAnchors.insecureNoVerify(),
            FakeDebugGuard(debuggable = true),
            debuggable,
        )
        assertEquals(1, debuggable.errors.size)
        assertTrue(debuggable.errors.single().contains("DISABLED"))

        val release = RecordingLog()
        warnIfVerificationDisabled(
            TrustAnchors.insecureNoVerify(),
            FakeDebugGuard(debuggable = false),
            release,
        )
        assertEquals(2, release.errors.size, "a release build gets told twice, and told why")
        assertTrue(release.errors.any { it.contains("not debuggable") })
        assertTrue(release.errors.any { it.contains("TrustAnchors.pinned()") })
    }

    @Test
    fun `the ordinary trust anchors say nothing at all`() {
        val log = RecordingLog()
        warnIfVerificationDisabled(TrustAnchors.systemDefault(), FakeDebugGuard(false), log)
        warnIfVerificationDisabled(
            TrustAnchors.pinned(validPem),
            FakeDebugGuard(false),
            log,
        )
        assertTrue(log.errors.isEmpty())
    }

    @Test
    fun `the idle gap is derived from the configured idle connection timeout`() {
        assertEquals(50_000, settings().idleThresholdMillis)
        assertEquals(
            StalenessTracker.idleThresholdFor(90_000),
            settings(idleConnectionTimeoutMillis = 90_000).idleThresholdMillis,
        )
    }
}
