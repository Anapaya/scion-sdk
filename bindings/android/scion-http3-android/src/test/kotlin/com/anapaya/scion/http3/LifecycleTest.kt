// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The properties whose absence is a crash or a hang rather than a wrong answer.
 *
 * Two of them are worth naming. A network callback runs on a thread the framework owns, and an
 * exception escaping it takes the whole process with it, so "a callback after close does nothing"
 * is a crash test. And a `catch` one word too broad would swallow the `CancellationException` that
 * carries a cancelled request, turning every cancelled coroutine into a silently completed one; the
 * cancellation test here is what stands in the way of that.
 */
class LifecycleTest {
    @Test
    fun `close stops the monitor and releases the backend, once`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val client = client(factory = factory, monitor = monitor)
            client.get("https://example.org/hello")

            client.close()
            client.close()

            assertEquals(1, monitor.stops, "unregistering twice is an error in the framework")
            assertEquals(1, factory.backend.closes.get())
            assertTrue(client.isClosed)
        }

    @Test
    fun `closing a client that was never used releases nothing and still stops watching`() {
        val factory = FakeBackendFactory()
        val monitor = FakeNetworkMonitor()
        val client = client(factory = factory, monitor = monitor)

        client.close()

        assertEquals(0, factory.creations.get())
        assertEquals(0, factory.backend.closes.get())
        assertEquals(1, monitor.stops)
    }

    @Test
    fun `a request after close fails as closed without touching the FFI`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.close()

            val failure =
                assertThrows<ScionHttp3Exception.Closed> { client.get("https://example.org/x") }

            assertEquals(0, factory.creations.get())
            assertTrue(failure.message!!.contains("Build another one"))
            assertTrue(!failure.isRetryable, "retrying a closed client will not help")
        }

    @Test
    fun `shutdown closes the pool before releasing the handle`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.get("https://example.org/hello")

            client.shutdown()

            assertEquals(1, factory.backend.shutdowns.get())
            assertEquals(1, factory.backend.closes.get())
        }

    @Test
    fun `shutdown after close does nothing`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.get("https://example.org/hello")

            client.close()
            client.shutdown()

            assertEquals(
                0,
                factory.backend.shutdowns.get(),
                "the handle is gone, and asking a released handle to close its pool would throw",
            )
            assertEquals(1, factory.backend.closes.get())
        }

    @Test
    fun `shutting down an unused client releases nothing and still stops watching`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val client = client(factory = factory, monitor = monitor)

            client.shutdown()

            assertEquals(0, factory.creations.get())
            assertEquals(0, factory.backend.shutdowns.get())
            assertEquals(1, monitor.stops)
            assertTrue(client.isClosed)
        }

    @Test
    fun `a shutdown racing the first request still closes the pool it finds`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            // Shutting down from inside the construction the first request triggers, which is the
            // window where reading the handle too early would leave a runtime nobody closes.
            factory.whileCreating = { runBlocking { client.shutdown() } }

            assertThrows<ScionHttp3Exception.Closed> { client.get("https://example.org/x") }

            assertEquals(
                1,
                factory.backend.closes.get(),
                "the backend was built, so something has to release it, whichever side got there",
            )
        }

    @Test
    fun `a backend published onto a closing client is closed exactly once`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            factory.whileCreating = { client.close() }

            assertThrows<ScionHttp3Exception.Closed> { client.get("https://example.org/x") }

            assertEquals(
                1,
                factory.backend.closes.get(),
                "closing and publishing race over one handle, and both releasing it would " +
                    "destroy it twice",
            )
        }

    @Test
    fun `a network observation after close neither resets nor throws`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)
            client.get("https://example.org/hello")
            monitor.observe(identity(handle = 1))

            client.close()
            clock.advance(10_000)
            monitor.observe(identity(handle = 2, interfaceName = "rmnet0"))

            assertEquals(0, factory.backend.resets.get())
        }

    @Test
    fun `reset on a closed client is ignored`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.get("https://example.org/hello")
            client.close()

            client.reset()

            assertEquals(0, factory.backend.resets.get())
        }

    @Test
    fun `a reset whose handle was released is absorbed`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.resetThrows = true
            val client = client(factory = factory)
            client.get("https://example.org/hello")

            client.reset()

            assertEquals(1, factory.backend.resets.get())
        }

    @Test
    fun `reset before the first request does nothing`() {
        val factory = FakeBackendFactory()
        val client = client(factory = factory)

        client.reset()

        assertEquals(0, factory.creations.get(), "there is no connectivity to rebuild yet")
    }

    @Test
    fun `close returns while a request is still in flight`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val gate = CompletableDeferred<Unit>()
            factory.backend.gate = gate
            val client = client(factory = factory)

            // runCatching because closing faults the request rather than awaiting it, which is
            // what close() documents; what this test is about is that close() does not wait for it.
            val request =
                async(
                    Dispatchers.Default,
                ) { runCatching { client.get("https://example.org/slow") } }
            while (factory.backend.requests.isEmpty()) delay(1)

            withTimeout(2_000) { client.close() }

            assertEquals(1, factory.backend.closes.get())
            gate.complete(Unit)
            assertInstanceOf(
                ScionHttp3Exception.Closed::class.java,
                request.await().exceptionOrNull(),
            )
        }

    @Test
    fun `cancelling a call cancels the request rather than completing it`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.gate = CompletableDeferred()
            val client = client(factory = factory)

            val call = launch(Dispatchers.Default) { client.get("https://example.org/endless") }
            while (factory.backend.requests.isEmpty()) delay(1)
            call.cancel()
            withTimeout(2_000) { call.join() }

            assertTrue(
                factory.backend.executeWasCancelled,
                "the cancellation has to reach the FFI, which is what resets the HTTP/3 " +
                    "stream. A catch of Exception anywhere above would swallow it and leave " +
                    "the stream open.",
            )
            assertTrue(call.isCancelled)
        }

    @Test
    fun `a stack failure arrives as the library's own exception`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.failure =
                com.anapaya.scion.http3.uniffi.ScionHttp3Exception.Tls(
                    host = "chat.example.org",
                    retryable = false,
                    detail = "certificate rejected",
                )
            val client = client(factory = factory)

            val failure =
                assertThrows<ScionHttp3Exception.Tls> { client.get("https://chat.example.org/x") }

            assertEquals("chat.example.org", failure.host)
            assertEquals("certificate rejected", failure.detail)
        }

    @Test
    fun `a request in flight when close destroys the handle reports it as closed`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val gate = CompletableDeferred<Unit>()
            factory.backend.gate = gate
            val client = client(factory = factory)

            // The real window, which no assertion could reach while the fake only counted closes:
            // the request already holds the backend, and the handle is destroyed under it. The
            // generated bindings throw an IllegalStateException from there, which is neither this
            // library's type nor an IOException.
            val call =
                async(Dispatchers.Default) { runCatching { client.get("https://example.org/a") } }
            while (factory.backend.requests.isEmpty()) delay(1)
            client.close()
            gate.complete(Unit)

            val failure = call.await().exceptionOrNull()
            assertInstanceOf(
                ScionHttp3Exception.Closed::class.java,
                failure,
                "close() promises that anything issued afterwards fails as Closed, and the class " +
                    "promises an IOException",
            )
        }

    @Test
    fun `an IllegalStateException from an open client is not dressed up as closed`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.get("https://example.org/a")
            factory.backend.destroyed = true

            // No close(), so this is a bug rather than a race, and has to travel as one.
            assertThrows<IllegalStateException> { client.get("https://example.org/b") }
        }

    @Test
    fun `a backend whose token catch-up fails is closed rather than left behind`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.setAuthTokenFailure = IllegalStateException("no token to replace")
            val client = client(factory = factory, settings = settings(authToken = "first"))
            client.setAuthToken("second")

            assertThrows<IllegalStateException> { client.get("https://example.org/a") }

            assertEquals(
                1,
                factory.backend.closes.get(),
                "it was built, so it owns a runtime; failing to finish setting it up cannot " +
                    "leave that unreachable",
            )
        }

    @Test
    fun `a renewed token reaches the stack`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory, settings = settings(authToken = "first"))
            client.get("https://example.org/a")

            client.setAuthToken("second")

            assertEquals(listOf("second"), factory.backend.tokens)
        }

    @Test
    fun `a token renewed before the first request is not lost`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory, settings = settings(authToken = "first"))

            client.setAuthToken("second")
            client.get("https://example.org/a")

            assertEquals(
                listOf("second"),
                factory.backend.tokens,
                "the stack did not exist when the token was renewed, so the client had to " +
                    "hold it and hand it over once there was something to hand it to",
            )
        }

    @Test
    fun `renewing a token on a closed client is ignored`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory, settings = settings(authToken = "first"))
            client.get("https://example.org/a")
            client.close()

            client.setAuthToken("second")

            assertEquals(
                emptyList<String>(),
                factory.backend.tokens,
                "a closed client has nothing to tell, and saying so by throwing would make a " +
                    "state push behave unlike reset()",
            )
        }

    @Test
    fun `renewing a token on a client built without one is refused`() {
        val client = client(settings = settings(authToken = null))

        val failure = assertThrows<IllegalStateException> { client.setAuthToken("second") }

        assertTrue(failure.message!!.contains("Builder.authToken()"))
    }

    @Test
    fun `an empty token is refused`() {
        val client = client(settings = settings(authToken = "first"))
        assertThrows<IllegalArgumentException> { client.setAuthToken("") }
    }

    @Test
    fun `warmUp rebuilds connectivity that went stale, like a request does`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)
            client.warmUp("https://example.org")
            monitor.observe(identity(handle = 1))

            clock.advance(10_000)
            monitor.observe(identity(handle = 2, interfaceName = "rmnet0"))
            client.warmUp("https://example.org")

            assertEquals(1, factory.backend.resets.get())
            assertEquals(2, factory.backend.warmedUp.size)
        }

    @Test
    fun `warmUp reaches the backend`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)

            client.warmUp("https://example.org")

            assertEquals(listOf("https://example.org"), factory.backend.warmedUp)
        }
}
