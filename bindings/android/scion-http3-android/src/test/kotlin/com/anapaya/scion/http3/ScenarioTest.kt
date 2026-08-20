// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The staleness machinery driven through the public API, as a device would drive it.
 *
 * The unit tests of [com.anapaya.scion.http3.internal.StalenessTracker] check the rules; these check
 * that the client is wired to them. That is a different failure: every rule can be right while the
 * client asks about them in the wrong order, resets a backend it just built, or resets twice for one
 * change. None of that shows up in a test of the tracker alone.
 */
class ScenarioTest {
    @Test
    fun `an application resumed on a different network rebuilds once, then succeeds`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)

            // On Wi-Fi, one request, so there is connectivity worth invalidating.
            val wifi = identity(handle = 1)
            monitor.current = wifi
            client.get("https://chat.example.org/rooms").use { it.body.bytes() }
            monitor.observe(wifi)
            assertEquals(0, factory.backend.resets.get())

            // The device moves to cellular while the application is in the background.
            clock.advance(30_000)
            val cellular =
                identity(handle = 2, interfaceName = "rmnet0", addresses = setOf("10.9.8.7/30"))
            monitor.current = cellular
            monitor.observe(cellular)

            val response = client.get("https://chat.example.org/rooms")

            assertEquals(1, factory.backend.resets.get(), "one change, one rebuild")
            assertTrue(response.isSuccessful, "and the request still goes through afterwards")
            assertEquals(2, factory.backend.requests.size)
            assertEquals(1, factory.creations.get(), "the stack is rebuilt below the FFI, not here")
        }

    @Test
    fun `two requests after one change still rebuild once`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)
            client.get("https://example.org/a")
            monitor.observe(identity(handle = 1))

            clock.advance(10_000)
            monitor.observe(identity(handle = 2, interfaceName = "rmnet0"))
            client.get("https://example.org/b")
            client.get("https://example.org/c")

            assertEquals(1, factory.backend.resets.get())
        }

    @Test
    fun `a manual reset is not repeated by the next request`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)
            client.get("https://example.org/a")
            monitor.observe(identity(handle = 1))

            clock.advance(10_000)
            monitor.observe(identity(handle = 2, interfaceName = "rmnet0"))
            client.reset()
            client.get("https://example.org/b")

            assertEquals(1, factory.backend.resets.get(), "the application's reset was the rebuild")
        }

    @Test
    fun `a long-idle application checks the network itself and rebuilds when it moved`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client =
                client(
                    factory = factory,
                    monitor = monitor,
                    clock = clock,
                    settings = settings(idleConnectionTimeoutMillis = 25_000),
                )
            monitor.current = identity(handle = 1)
            client.get("https://example.org/a")
            monitor.observe(identity(handle = 1))

            // Dozed for ten minutes, and moved network without a callback surviving it.
            clock.advance(600_000)
            monitor.current = identity(handle = 2, interfaceName = "rmnet0")
            client.get("https://example.org/b")

            assertEquals(1, factory.backend.resets.get())
        }

    @Test
    fun `a brief loss that recovers onto the same network costs nothing`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val monitor = FakeNetworkMonitor()
            val clock = FakeClock()
            val client = client(factory = factory, monitor = monitor, clock = clock)
            val home = identity(handle = 1)
            monitor.current = home
            client.get("https://example.org/a")
            monitor.observe(home)

            clock.advance(200)
            monitor.observe(home)
            clock.advance(200)
            client.get("https://example.org/b")

            assertEquals(0, factory.backend.resets.get())
        }

    @Test
    fun `the shorthands send what the long form sends`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)

            client.get("https://example.org/rooms")
            client.newCall(request("https://example.org/rooms")).execute()

            val (shorthand, longForm) = factory.backend.requests
            assertEquals(longForm, shorthand)
        }

    @Test
    fun `a response body reads as text through the shorthand`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.response = response(body = """{"rooms":[]}""".toByteArray())
            val client = client(factory = factory)

            val text = client.get("https://example.org/rooms").use { it.body.string() }

            assertEquals("""{"rooms":[]}""", text)
        }
}
