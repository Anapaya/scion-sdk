// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

/**
 * [ScionHttp3Tunnel] over a fake tunnel.
 */
class TunnelTest {
    @Test
    fun `opening a tunnel hands the authority to the stack`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)

            val tunnel = client.openTunnel("chat.example.org", 5222)

            assertEquals(listOf("chat.example.org:5222"), factory.backend.authorities)
            assertFalse(tunnel.isClosed)
        }

    @Test
    fun `an authority that does not parse is refused before the stack sees it`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)

            assertThrows<IllegalArgumentException> { client.openTunnel("chat.example.org", 0) }
            assertThrows<IllegalArgumentException> { client.openTunnel("", 5222) }
            assertTrue(factory.backend.authorities.isEmpty())
        }

    @Test
    fun `a refused tunnel reports the status the gateway answered with`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            factory.backend.failure = FfiException.TunnelRefused(502u, true, "bad gateway")
            val client = client(factory = factory)

            val e =
                assertThrows<ScionHttp3Exception.TunnelRefused> {
                    client.openTunnel("chat.example.org", 5222)
                }
            assertEquals(502, e.status)
            assertTrue(e.isRetryable)
        }

    @Test
    fun `a closed client opens nothing`(): Unit =
        runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            client.close()

            assertThrows<ScionHttp3Exception.Closed> { client.openTunnel("chat.example.org", 5222) }
            assertTrue(factory.backend.authorities.isEmpty())
        }

    @Test
    fun `reads and writes pass through as they are`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            fake.reads += bytesOf(1, 2, 3)
            val tunnel = ScionHttp3Tunnel(fake)

            assertArrayEquals(bytesOf(1, 2, 3), tunnel.read(16))
            tunnel.write(bytesOf(4, 5))

            assertEquals(listOf(16), fake.maxima)
            assertArrayEquals(bytesOf(4, 5), fake.written.single())
        }

    @Test
    fun `an empty read is the end of the stream`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            fake.reads += ByteArray(0)

            assertEquals(0, ScionHttp3Tunnel(fake).read(16).size)
        }

    @Test
    fun `a read of nothing is refused before it reaches the stack`(): Unit =
        runBlocking {
            val fake = FakeTunnel()

            assertThrows<IllegalArgumentException> { ScionHttp3Tunnel(fake).read(0) }
            assertTrue(fake.maxima.isEmpty())
        }

    @Test
    fun `an empty write does not reach the stack`(): Unit =
        runBlocking {
            val fake = FakeTunnel()

            ScionHttp3Tunnel(fake).write(ByteArray(0))

            assertTrue(fake.written.isEmpty())
        }

    @Test
    fun `tunnel failures become their public arms`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            fake.reads += FfiException.TunnelReset(true, "d")
            fake.reads += FfiException.TunnelDisconnected(true, "d")
            fake.writeFailure = FfiException.TunnelClosed(false, "d")
            val tunnel = ScionHttp3Tunnel(fake)

            assertThrows<ScionHttp3Exception.TunnelReset> { tunnel.read(1) }
            assertThrows<ScionHttp3Exception.TunnelDisconnected> { tunnel.read(1) }
            assertThrows<ScionHttp3Exception.TunnelClosed> { tunnel.write(bytesOf(1)) }
            assertFalse(tunnel.isClosed, "a failure the stack reports is not a close on this side")
        }

    @Test
    fun `shutting the write direction down reaches the stack`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            tunnel.shutdownWrite()

            assertEquals(1, fake.shutdownWrites.get())
            assertThrows<ScionHttp3Exception.TunnelClosed> { tunnel.write(bytesOf(1)) }
        }

    @Test
    fun `cancelling a pending read closes the tunnel`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            val reading = launch { tunnel.read(16) }
            awaitPending(fake)
            reading.cancel()
            reading.join()

            assertTrue(tunnel.isClosed, "the dropped read may have lost bytes")
            assertEquals(1, fake.aborts.get())
            assertEquals(1, fake.closes.get())
        }

    @Test
    fun `a caller's timeout is a cancellation too`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            assertThrows<kotlinx.coroutines.TimeoutCancellationException> {
                withTimeout(50) { tunnel.read(16) }
            }

            assertTrue(tunnel.isClosed)
        }

    @Test
    fun `an elapsed deadline is reported as nothing and leaves the tunnel open`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            assertNull(tunnel.readWithin(16, timeoutMillis = 50))

            assertFalse(tunnel.isClosed)
            assertEquals(0, fake.aborts.get())
            assertEquals(1, fake.cancelsCreated.get())
            assertFalse(fake.isReadPending)

            // Still usable, and the next read is a fresh call with a fresh cancellation.
            fake.reads += bytesOf(7)
            assertArrayEquals(bytesOf(7), tunnel.readWithin(16, timeoutMillis = 50))
            assertEquals(2, fake.cancelsCreated.get())
        }

    @Test
    fun `a read that completes within its deadline returns its bytes`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            fake.reads += bytesOf(9)

            assertArrayEquals(bytesOf(9), ScionHttp3Tunnel(fake).readWithin(16, 10_000))
        }

    @Test
    fun `a deadline of zero waits without one`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            // Caught inside the child: a failing child would otherwise take the test scope down
            // before the assertion runs.
            val reading = async { runCatching { tunnel.readWithin(16, timeoutMillis = 0) } }
            awaitPending(fake)
            assertTrue(reading.isActive)
            tunnel.close()

            assertInstanceOf(
                ScionHttp3Exception.TunnelClosed::class.java,
                reading.await().exceptionOrNull(),
            )
            assertEquals(0, fake.cancelsCreated.get())
        }

    @Test
    fun `close resets then releases, once, and later calls fail without the stack`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            tunnel.close()
            tunnel.close()

            assertTrue(tunnel.isClosed)
            assertEquals(1, fake.aborts.get())
            assertEquals(1, fake.closes.get())
            assertThrows<ScionHttp3Exception.TunnelClosed> { tunnel.read(1) }
            assertThrows<ScionHttp3Exception.TunnelClosed> { tunnel.write(bytesOf(1)) }
            assertTrue(fake.maxima.isEmpty())
            assertTrue(fake.written.isEmpty())
        }

    @Test
    fun `closing from another coroutine ends a blocked read as closed`(): Unit =
        runBlocking {
            val fake = FakeTunnel()
            val tunnel = ScionHttp3Tunnel(fake)

            val reading = async { runCatching { tunnel.read(16) } }
            awaitPending(fake)
            tunnel.close()

            assertInstanceOf(
                ScionHttp3Exception.TunnelClosed::class.java,
                reading.await().exceptionOrNull(),
            )
        }

    private suspend fun awaitPending(fake: FakeTunnel) {
        while (!fake.isReadPending) delay(1)
    }
}
