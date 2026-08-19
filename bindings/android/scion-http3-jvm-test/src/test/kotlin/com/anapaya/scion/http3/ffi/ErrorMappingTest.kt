// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ScionHttp3Client
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import com.anapaya.scion.http3.uniffi.TimeoutPhase
import com.anapaya.scion.http3.uniffi.defaultClientConfig
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit

/**
 * Each failure a caller can actually provoke, and the exception it arrives as.
 *
 * Only the arms that a hermetic run produces the same way every time. `Protocol`, `StreamReset`,
 * `Tls`, `Resolution` and `Internal` need either a synthetic error or a working resolver, and they
 * are covered by the table test in the Rust crate's `error` module instead of by widening the
 * shipped library or depending on the network. Together the two cover the taxonomy.
 */
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class ErrorMappingTest {
    private val server = TestServer.shared

    @Test
    fun `a malformed request is rejected before anything is sent`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                // http, not https: this is an HTTP/3 client and there is nothing to fall back to.
                val plaintext =
                    assertThrows<ScionHttp3Exception.InvalidRequest> {
                        client.execute(
                            requestTo(server, "/hello") { it.copy(url = "http://example.org/") },
                        )
                    }
                assertFalse(plaintext.retryable)

                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.execute(requestTo(server, "/hello") { it.copy(method = "not a method") })
                }
                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.execute(
                        requestTo(server, "/hello") { it.copy(targets = listOf("nonsense")) },
                    )
                }
            }
        }

    @Test
    fun `requesting after shutdown reports a closed client`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                client.shutdown()

                val closed =
                    assertThrows<ScionHttp3Exception.Closed> {
                        client.execute(requestTo(server, "/hello"))
                    }
                assertFalse(closed.retryable)
            }
        }

    @Test
    fun `a request that outlives its deadline reports which phase timed out`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                // Warm the connection up, so the deadline is spent waiting for the response rather
                // than on the handshake.
                client.execute(requestTo(server, "/hello"))

                val timeout =
                    assertThrows<ScionHttp3Exception.Timeout> {
                        client.execute(
                            requestTo(
                                server,
                                "/slow?ms=10000",
                            ) { it.copy(requestTimeoutMs = 500u) },
                        )
                    }
                assertEquals(TimeoutPhase.REQUEST, timeout.phase)
                assertEquals(500u.toULong(), timeout.timeoutMs)
                assertTrue(timeout.retryable)
            }
        }

    @Test
    fun `a response larger than the limit reports the limit it exceeded`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val tooLarge =
                    assertThrows<ScionHttp3Exception.BodyTooLarge> {
                        client.execute(
                            requestTo(server, "/big?bytes=65536") {
                                it.copy(maxResponseBodyBytes = 1024u)
                            },
                        )
                    }
                assertEquals(1024u.toULong(), tooLarge.limit)
                assertFalse(tooLarge.retryable)
            }
        }

    @Test
    fun `an address nothing answers on times out rather than failing fast`(): Unit =
        runBlocking {
            clientFor(server) { it.copy(connectTimeoutMs = 3_000u) }.use { client ->
                // A well-formed SCION address in the topology's other AS, where nothing is bound.
                // Over SCION there is nothing to refuse a connection, so this is what "unreachable"
                // looks like: the connect deadline expires with no attempt having failed.
                val unreachable = server.endpoints.target.substringBefore(",") + ",127.0.0.2"
                val timeout =
                    assertThrows<ScionHttp3Exception.Timeout> {
                        client.execute(
                            requestTo(server, "/hello") { it.copy(targets = listOf(unreachable)) },
                        )
                    }
                assertEquals(TimeoutPhase.CONNECT, timeout.phase)
                assertTrue(timeout.retryable)
            }
        }

    @Test
    fun `an endhost api that is not there reports a connectivity failure`(): Unit =
        runBlocking {
            val config =
                defaultClientConfig("http://127.0.0.1:1").copy(
                    connectTimeoutMs = 3_000u,
                    requestTimeoutMs = 10_000u,
                )
            ScionHttp3Client(config).use { client ->
                assertThrows<ScionHttp3Exception.StackBuild> {
                    client.execute(requestTo(server, "/hello"))
                }
            }
        }

    // `Resolution` is deliberately not provoked here. Reaching it means asking the machine's
    // resolver for a name that does not exist, and on a host without working DNS the lookup runs
    // until the request deadline instead, so the arm that arrives depends on the network the tests
    // happen to run on. `scion-http3` covers it deterministically with a resolver that always fails.

    /**
     * A server that will not speak HTTP/3 reports `Connect`, not `Tls`, and this pins that down
     * rather than papering over it.
     *
     * `Tls` is raised only when every candidate returns `EstablishError::AlpnMismatch`, which
     * scion-quic produces after a *completed* handshake that negotiated something other than `h3`.
     * A server with no protocol in common fails the handshake instead, and scion-quic's handshake
     * loop discards the cause, so the result is indistinguishable from an unreachable peer. The
     * same limitation is why a rejected certificate arrives as `Connect` too, which
     * `scion-http3`'s error module records as a known gap.
     *
     * The consequence to be aware of: `Tls` is currently unreachable through this API, and this
     * failure is reported as retryable when it will never succeed. When scion-quic grows a distinct
     * handshake-failure cause, this test should start failing, and that is the point of it.
     */
    @Test
    fun `a server that will not speak HTTP3 reports a connect failure`(): Unit =
        runBlocking {
            TestServer.start("--alpn", "not-h3").use { alien ->
                clientFor(alien) { it.copy(connectTimeoutMs = 10_000u) }.use { client ->
                    val connect =
                        assertThrows<ScionHttp3Exception.Connect> {
                            client.execute(requestTo(alien, "/hello"))
                        }
                    assertEquals("localhost", connect.host)
                    assertTrue(connect.detail.contains("handshake"), connect.detail)
                }
            }
        }

    @Test
    fun `a server allowing no request streams reports the stream limit`(): Unit =
        runBlocking {
            TestServer.start("--max-streams", "0").use { crowded ->
                clientFor(crowded).use { client ->
                    val limit =
                        assertThrows<ScionHttp3Exception.ConnectionLimit> {
                            client.execute(requestTo(crowded, "/hello"))
                        }
                    assertTrue(limit.retryable)
                }
            }
        }
}
