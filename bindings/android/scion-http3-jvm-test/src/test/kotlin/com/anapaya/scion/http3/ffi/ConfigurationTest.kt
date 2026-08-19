// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.DiscoveryConfig
import com.anapaya.scion.http3.uniffi.Header
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import com.anapaya.scion.http3.uniffi.SnapConfig
import com.anapaya.scion.http3.uniffi.TrustAnchors
import com.anapaya.scion.http3.uniffi.UdpConfig
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/**
 * The configuration record, exercised through a real request rather than through its conversion.
 *
 * The settings that reach the SCION stack do so through a customizer closure that runs on every
 * rebuild of connectivity, and a unit test of the conversion cannot show that the closure runs or
 * that what it sets takes effect. These tests can.
 */
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class ConfigurationTest {
    private val server = TestServer.shared

    @Test
    fun `every stack setting at once still reaches the server`(): Unit =
        runBlocking {
            val configured =
                clientFor(server) {
                    it.copy(
                        discovery =
                            DiscoveryConfig(
                                maxGroups = 2u,
                                apisPerGroup = 2u,
                                perGroupDelayMs = 50u,
                            ),
                        snap = SnapConfig(dpIndex = 0u, staticIdentity = ByteArray(32) { 7 }),
                        udp =
                            UdpConfig(
                                outboundIps = listOf("127.0.0.1"),
                                nextHopResolverFetchIntervalMs = 600_000u,
                            ),
                    )
                }

            configured.use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
            }
        }

    /**
     * The counterpart to the test above: setting something the stack cannot work with has to break
     * the request. Otherwise a setter that silently went nowhere would look identical to one that
     * worked.
     */
    @Test
    fun `an unusable outbound address breaks connectivity`(): Unit =
        runBlocking {
            val misconfigured =
                clientFor(server) {
                    it.copy(
                        connectTimeoutMs = 5_000u,
                        requestTimeoutMs = 15_000u,
                        // Reserved by RFC 1112 as class E and unassignable, so no interface
                        // anywhere holds it and the bind cannot succeed. A private-range address
                        // would be bindable on a host whose VPN or container network owns it.
                        udp = UdpConfig(outboundIps = listOf("240.0.0.1")),
                    )
                }

            misconfigured.use { client ->
                assertThrows<ScionHttp3Exception> { client.execute(requestTo(server, "/hello")) }
            }
        }

    @Test
    fun `trust anchors work from a file as well as from memory`(): Unit =
        runBlocking {
            val pem = Files.createTempFile("scion-test-anchor", ".pem")
            Files.writeString(pem, server.endpoints.caPem)
            try {
                clientFor(server) {
                    it.copy(trust = TrustAnchors.CaCertsFile(pem.toAbsolutePath().toString()))
                }.use { client ->
                    assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
                }
            } finally {
                Files.deleteIfExists(pem)
            }
        }

    // `CaCertsDir` is deliberately not tested here. It maps to squiche's directory loader, which is
    // OpenSSL's CApath: the directory has to hold files named by subject hash, not arbitrary .pem
    // files, and a plain directory of certificates fails the handshake with no hint as to why. The
    // variant's own documentation states the requirement.

    /**
     * Verification off accepts a certificate no anchor covers. Worth a test because it is the one
     * setting whose failure mode is silence: it works, and it works for the wrong reasons.
     */
    @Test
    fun `verification can be turned off`(): Unit =
        runBlocking {
            clientFor(server) { it.copy(trust = TrustAnchors.InsecureNoVerify) }.use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
            }
        }

    @Test
    fun `the client-wide body limit applies when a request carries none`(): Unit =
        runBlocking {
            clientFor(server) { it.copy(maxResponseBodyBytes = 512u) }.use { client ->
                val tooLarge =
                    assertThrows<ScionHttp3Exception.BodyTooLarge> {
                        client.execute(requestTo(server, "/big?bytes=4096"))
                    }
                assertEquals(512u.toULong(), tooLarge.limit)

                // And a request that names its own limit overrides it, in both directions.
                val response =
                    client.execute(
                        requestTo(server, "/big?bytes=4096") {
                            it.copy(maxResponseBodyBytes = 8_192u)
                        },
                    )
                assertEquals(4096, response.body.size)
            }
        }

    @Test
    fun `a malformed header is rejected before anything is sent`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.execute(
                        requestTo(server, "/hello") {
                            it.copy(headers = listOf(Header("not a header name", "value")))
                        },
                    )
                }
            }
        }

    /**
     * `reset()` is what a platform network-change callback calls, so it is the most-used entry point
     * on a phone and the one with no other test. It marks connectivity stale rather than doing work,
     * so the next request has to rebuild and still succeed.
     */
    @Test
    fun `a request after reset rebuilds connectivity`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                client.reset()

                val seenBefore = server.requestsSeen("/hello")
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
                assertTrue(
                    server.requestsSeen("/hello") > seenBefore,
                    "the request after reset never reached the server",
                )
            }
        }
}
