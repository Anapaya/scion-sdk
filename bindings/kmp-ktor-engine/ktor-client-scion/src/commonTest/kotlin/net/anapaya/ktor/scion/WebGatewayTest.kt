// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.contentType
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import uniffi.ktor_scion_core.CoreException
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The WebGateway mode, against the `CONNECT` tunnels of the test server.
 *
 * The test server plays the gateway. For `CONNECT https.invalid:<port>`, it
 * runs a TLS server with HTTP/1.1 inside the tunnel. For
 * `CONNECT http.invalid:<port>`, it runs HTTP/1.1 without TLS.
 */
class WebGatewayTest {

    @Test
    fun getGoesThroughTheTunnel(): Unit = runEngineTest {
        gatewayClient().use { client ->
            val response = client.get("https://$HTTPS_HOST/hello")
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals("HTTP/1.1", response.version.toString())
            assertEquals("world", response.bodyAsText())
        }
    }

    @Test
    fun postSendsTheBodyBack(): Unit = runEngineTest {
        gatewayClient().use { client ->
            val response = client.post("https://$HTTPS_HOST/echo") {
                contentType(ContentType.Text.Plain)
                setBody("payload through the gateway")
            }
            assertEquals("payload through the gateway", response.bodyAsText())
        }
    }

    @Test
    fun plainHttpGoesThroughTheTunnel(): Unit = runEngineTest {
        gatewayClient().use { client ->
            assertEquals("world", client.get("http://$HTTP_HOST/hello").bodyAsText())
        }
    }

    @Test
    fun manyRequestsRunAtOnce(): Unit = runEngineTest {
        gatewayClient().use { client ->
            val bodies = coroutineScope {
                (1..20).map { async { client.get("https://$HTTPS_HOST/hello").bodyAsText() } }.awaitAll()
            }
            assertTrue(bodies.all { it == "world" })
        }
    }

    @Test
    fun aRefusedTunnelBecomesAnEngineError(): Unit = runEngineTest {
        gatewayClient().use { client ->
            val failure = assertFailsWith<ScionEngineException> { client.get("https://$REFUSED_HOST/hello") }
            assertIs<CoreException.Connect>(failure.cause)
        }
    }

    @Test
    fun anUntrustedOriginBecomesAnEngineError(): Unit = runEngineTest {
        gatewayClient(caPem = TestNetwork.current.wrongCaPem).use { client ->
            val failure = assertFailsWith<ScionEngineException> { client.get("https://$HTTPS_HOST/hello") }
            assertIs<CoreException.Tls>(failure.cause)
        }
    }

    @Test
    fun thePlatformTrustRejectsTheTestCa(): Unit = runEngineTest {
        // No platform trusts the CA of the test server.
        gatewayClient(caPem = null).use { client ->
            val failure = assertFailsWith<ScionEngineException> { client.get("https://$HTTPS_HOST/hello") }
            assertIs<CoreException.Tls>(failure.cause)
            assertContains(failure.cause?.message.orEmpty(), "does not trust")
        }
    }

    /**
     * A client that tunnels to the test server, which sits at each test host.
     * A [caPem] of `null` verifies the origin with the platform trust.
     */
    private fun gatewayClient(caPem: String? = TestNetwork.current.caPem): HttpClient {
        val network = TestNetwork.current
        return scionClient(engine = {
            webGateway = ScionWebGateway(port = Url(network.baseUrl).port)
            caCertificatesPem = caPem
            for (host in listOf(HTTPS_HOST, HTTP_HOST, REFUSED_HOST)) {
                dnsOverride(host, network.target)
            }
        })
    }

    private companion object {
        const val HTTPS_HOST = "https.invalid"
        const val HTTP_HOST = "http.invalid"

        /** The test server refuses a tunnel to this host with a 404. */
        const val REFUSED_HOST = "status-404.invalid"
    }
}
