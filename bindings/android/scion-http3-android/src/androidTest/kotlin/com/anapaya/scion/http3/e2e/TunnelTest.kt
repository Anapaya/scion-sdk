// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Exception
import com.anapaya.scion.http3.ScionHttp3Tunnel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * E2e tests for [ScionHttp3Tunnel].
 */
@RunWith(AndroidJUnit4::class)
class TunnelTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun bytesRoundTripAndTheWriteDirectionClosesOnItsOwn() =
        runBlocking {
            val bytesBefore = Fixture.tunnelBytes()
            Fixture.client().use { client ->
                client.openTunnel(Fixture.tunnelAuthority()).use { tunnel ->
                    val payload = ByteArray(100_000) { it.toByte() }
                    tunnel.write(payload)
                    assertArrayEquals(payload, tunnel.readExactly(payload.size))

                    tunnel.shutdownWrite()
                    assertEquals(0, tunnel.read(16).size)
                    assertFalse(tunnel.isClosed)
                }
            }
            assertEquals(bytesBefore + 100_000, Fixture.tunnelBytes())
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aRefusedTunnelCarriesTheStatusAndItsRetryability() =
        runBlocking {
            Fixture.insecureClientFor("status-502.invalid", "status-404.invalid").use { client ->
                val retryable =
                    expect<ScionHttp3Exception.TunnelRefused> {
                        client.openTunnel(Fixture.tunnelAuthority("status-502.invalid"))
                    }
                assertEquals(502, retryable.status)
                assertTrue(retryable.isRetryable)

                val final =
                    expect<ScionHttp3Exception.TunnelRefused> {
                        client.openTunnel(Fixture.tunnelAuthority("status-404.invalid"))
                    }
                assertEquals(404, final.status)
                assertFalse(final.isRetryable)
            }
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aPeerResetIsReportedAsOne() =
        runBlocking {
            Fixture.insecureClientFor("reset.invalid").use { client ->
                client.openTunnel(Fixture.tunnelAuthority("reset.invalid")).use { tunnel ->
                    tunnel.write(byteArrayOf(1, 2, 3))

                    // The echo of the chunk may or may not arrive before the reset.
                    val e =
                        expect<ScionHttp3Exception.TunnelReset> {
                            while (tunnel.read(16).isNotEmpty()) Unit
                            throw AssertionError("the stream ended instead of resetting")
                        }
                    assertTrue(e.isRetryable)
                    assertFalse("a reset by the peer is not a close on this side", tunnel.isClosed)
                }
            }
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun shuttingTheClientDownClosesAnOpenTunnel() =
        runBlocking {
            val client = Fixture.client()
            val tunnel = client.openTunnel(Fixture.tunnelAuthority())
            tunnel.write(byteArrayOf(9))
            assertArrayEquals(byteArrayOf(9), tunnel.readExactly(1))

            client.shutdown()

            expect<ScionHttp3Exception.Closed> { tunnel.read(16) }
            tunnel.close()
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun cancellingAReadClosesTheTunnel() =
        runBlocking {
            Fixture.client().use { client ->
                val tunnel = client.openTunnel(Fixture.tunnelAuthority())
                val reset = Fixture.tunnelsReset()

                val reading = launch { tunnel.read(16) }
                delay(1_000)
                assertTrue(reading.isActive)
                reading.cancelAndJoin()

                assertTrue("the dropped read may have lost bytes", tunnel.isClosed)
                expect<ScionHttp3Exception.TunnelClosed> { tunnel.write(byteArrayOf(1)) }
                Fixture.awaitTunnelsReset(reset + 1)
            }
        }

    private suspend fun ScionHttp3Tunnel.readExactly(count: Int): ByteArray {
        val bytes = ByteArray(count)
        var filled = 0
        while (filled < count) {
            val chunk = read(count - filled)
            if (chunk.isEmpty()) {
                throw AssertionError(
                    "the stream ended after $filled of $count bytes",
                )
            }
            chunk.copyInto(bytes, filled)
            filled += chunk.size
        }
        return bytes
    }

    private suspend inline fun <reified E : ScionHttp3Exception> expect(
        block: suspend () -> Any?,
    ): E {
        try {
            block()
        } catch (e: ScionHttp3Exception) {
            if (e is E) return e
            throw AssertionError("expected ${E::class.simpleName}, got $e", e)
        }
        throw AssertionError("expected ${E::class.simpleName}, but nothing was thrown")
    }
}
