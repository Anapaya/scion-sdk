// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Exception
import com.anapaya.scion.http3.ScionTunnelSocket
import com.anapaya.scion.http3.ScionTunnelSocketFactory
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.io.InputStream
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * E2e tests for [ScionTunnelSocket] against the test server's echo tunnel.
 */
@RunWith(AndroidJUnit4::class)
class TunnelSocketTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun bytesRoundTripAndAHalfCloseEndsTheEcho() {
        val started = Fixture.tunnelsStarted()
        val reset = Fixture.tunnelsReset()
        Fixture.client().use { client ->
            ScionTunnelSocket(client).use { socket ->
                socket.connect(Fixture.tunnelEndpoint())
                assertTrue(socket.isConnected)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                // A few small frames, then one payload well over what a single frame carries, so
                // that the read loop is exercised.
                val payloads =
                    listOf(
                        byteArrayOf(0x00, 0x7f, -0x01, -0x80, 0x61),
                        Random(7).nextBytes(200_000),
                    )
                for (payload in payloads) {
                    output.write(payload)
                    assertArrayEquals(payload, input.readExactly(payload.size))
                }

                socket.shutdownOutput()
                assertEquals(-1, input.read())
                assertEquals(-1, input.read(ByteArray(8)))
            }
        }
        assertEquals(started + 1, Fixture.tunnelsStarted())
        assertEquals("a clean end of stream is not a reset", reset, Fixture.tunnelsReset())
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aReadDeadlineIsASocketTimeoutAndTheSocketStaysUsable() {
        Fixture.client().use { client ->
            ScionTunnelSocket(client).use { socket ->
                socket.connect(Fixture.tunnelEndpoint())
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                socket.soTimeout = 500

                val before = System.nanoTime()
                assertThrows(SocketTimeoutException::class.java) { input.read(ByteArray(8)) }
                val elapsedMillis = (System.nanoTime() - before) / 1_000_000
                assertTrue("timed out after ${elapsedMillis}ms", elapsedMillis >= 400)

                assertFalse(socket.isClosed)
                output.write(byteArrayOf(1, 2, 3))
                assertArrayEquals(byteArrayOf(1, 2, 3), input.readExactly(3))
            }
        }
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun closingFromAnotherThreadEndsABlockedRead() {
        Fixture.client().use { client ->
            val socket = ScionTunnelSocket(client)
            socket.connect(Fixture.tunnelEndpoint())
            val reset = Fixture.tunnelsReset()

            val failure = AtomicReference<IOException?>(null)
            val reader =
                thread {
                    try {
                        socket.getInputStream().read(ByteArray(8))
                    } catch (e: IOException) {
                        failure.set(e)
                    }
                }

            Thread.sleep(1_000)
            assertTrue(reader.isAlive)

            socket.close()
            reader.join(30_000)

            assertFalse("the blocked read did not return", reader.isAlive)
            val e = failure.get()
            assertTrue("$e", e is SocketException)
            assertEquals("Socket closed", e?.message)
            runBlocking { Fixture.awaitTunnelsReset(reset + 1) }
        }
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aRefusedTunnelFailsConnectWithTheGatewaysStatus() {
        Fixture.insecureClientFor(REFUSING_HOST).use { client ->
            val socket = ScionTunnelSocket(client)

            val e =
                assertThrows(ScionHttp3Exception.TunnelRefused::class.java) {
                    socket.connect(Fixture.tunnelEndpoint(REFUSING_HOST))
                }

            assertEquals(502, e.status)
            assertTrue(e.isRetryable)
            assertFalse(socket.isConnected)
        }
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aPeerResetIsReportedFromRead() {
        Fixture.insecureClientFor(RESETTING_HOST).use { client ->
            ScionTunnelSocket(client).use { socket ->
                socket.connect(Fixture.tunnelEndpoint(RESETTING_HOST))
                socket.soTimeout = 30_000
                val input = socket.getInputStream()
                socket.getOutputStream().write(byteArrayOf(1, 2, 3))

                // The server echoes one chunk and then resets, but a reset lets the transport drop
                // what it had not delivered yet, so the echo may or may not arrive first.
                val e =
                    assertThrows(ScionHttp3Exception.TunnelReset::class.java) {
                        val buffer = ByteArray(8)
                        while (true) {
                            val n = input.read(buffer)
                            if (n < 0) throw AssertionError("the stream ended instead of resetting")
                        }
                    }
                assertTrue(e.isRetryable)
                assertFalse("a reset by the peer is not a close on this side", socket.isClosed)
            }
        }
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun theFactoryHandsOutConnectedSockets() {
        Fixture.client().use { client ->
            val factory = ScionTunnelSocketFactory(client)

            factory.createSocket(Fixture.host, Fixture.port).use { socket ->
                assertTrue(socket.isConnected)
                socket.getOutputStream().write(byteArrayOf(4, 5))
                assertArrayEquals(byteArrayOf(4, 5), socket.getInputStream().readExactly(2))
            }

            factory.createSocket().use { socket ->
                socket.connect(Fixture.tunnelEndpoint(), 30_000)
                assertTrue(socket.isConnected)
            }
        }
    }

    private fun InputStream.readExactly(count: Int): ByteArray {
        val bytes = ByteArray(count)
        var filled = 0
        while (filled < count) {
            val n = read(bytes, filled, count - filled)
            if (n < 0) throw AssertionError("the stream ended after $filled of $count bytes")
            filled += n
        }
        return bytes
    }

    private companion object {
        const val REFUSING_HOST = "status-502.invalid"
        const val RESETTING_HOST = "reset.invalid"
    }
}
