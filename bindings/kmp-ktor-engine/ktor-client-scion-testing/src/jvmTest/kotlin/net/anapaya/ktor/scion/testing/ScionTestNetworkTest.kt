// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.testing

import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.ScionHttp
import net.anapaya.ktor.scion.ScionUnderlay
import net.anapaya.ktor.scion.ScionWebGateway
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals

class ScionTestNetworkTest {

    @Test
    fun theEngineReachesTheTestApiOverUdp(): Unit = theEngineReachesTheTestApi(ScionUnderlay.Udp)

    @Test
    fun theEngineReachesTheTestApiOverSnap(): Unit = theEngineReachesTheTestApi(ScionUnderlay.Snap)

    private fun theEngineReachesTheTestApi(underlay: ScionUnderlay): Unit = runBlocking {
        ScionTestNetwork.start { this.underlay = underlay }.use { network ->
            val client = HttpClient(ScionHttp) {
                engine {
                    useTestNetwork(network)
                    caCertificatesPem = network.testApiCaPem
                }
            }
            client.use { assertEquals("world", it.get("${network.testApiUrl}/hello").bodyAsText()) }
        }
    }

    @Test
    fun theGatewayConnectsATunnelToABackend(): Unit = runBlocking {
        // Start a TCP backend.
        val backend = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/hello") { exchange ->
                val body = "from the backend".toByteArray()
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            start()
        }
        try {
            ScionTestNetwork.start {
                gatewayBackend("backend.test", "127.0.0.1:${backend.address.port}")
            }.use { network ->
                val client = HttpClient(ScionHttp) {
                    engine {
                        useTestNetwork(network)
                        webGateway = ScionWebGateway(port = network.gatewayPort)
                    }
                }
                client.use {
                    assertEquals("from the backend", it.get("http://backend.test/hello").bodyAsText())
                }
            }
        } finally {
            backend.stop(0)
        }
    }

    @Test
    fun theGatewayGetsTheRequestPort(): Unit = runBlocking {
        // Start a TCP backend.
        val backend = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/hello") { exchange ->
                val body = "from port 8080".toByteArray()
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            start()
        }
        try {
            ScionTestNetwork.start {
                gatewayBackend("backend.test:8080", "127.0.0.1:${backend.address.port}")
            }.use { network ->
                val client = HttpClient(ScionHttp) {
                    engine {
                        useTestNetwork(network)
                        webGateway = ScionWebGateway(port = network.gatewayPort)
                    }
                }
                client.use {
                    assertEquals("from port 8080", it.get("http://backend.test:8080/hello").bodyAsText())
                }
            }
        } finally {
            backend.stop(0)
        }
    }
}
