// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample.testing

import io.ktor.client.HttpClient
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.ScionHttp
import net.anapaya.ktor.scion.ScionWebGateway
import net.anapaya.ktor.scion.testing.ScionTestNetwork
import net.anapaya.ktor.scion.testing.useTestNetwork
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Runs [GreetingApi] over SCION, against the API on TCP.
 *
 * ```text
 * client (ScionHttp)
 *     ||
 *     || HTTP connection, in an HTTP/3 CONNECT tunnel to the gateway
 *     ||
 * +---||-- ScionTestNetwork: a PocketSCION topology ----+
 * |   ||                                                |
 * |   || underlay: a router over UDP, or a SNAP         |
 * |   vv                                                |
 * | AS 1-ff00:0:132                                     |
 * |   ||                                                |
 * |   || SCION                                          |
 * |   vv                                                |
 * | AS 2-ff00:0:212                                     |
 * |   ||                                                |
 * |   || underlay: the same as in AS 1-ff00:0:132       |
 * |   vv                                                |
 * | gateway: an L4 CONNECT proxy                        |
 * +---|-------------------------------------------------+
 *     | HTTP connection, in TCP to the API
 *     v
 * API (embeddedServer)
 * 127.0.0.1, a free port
 * ```
 *
 * [ScionTestNetwork] runs the SCION network and the gateway in the test
 * process.
 */
class GreetingApiTest {
    private lateinit var api: EmbeddedServer<*, *>
    private lateinit var network: ScionTestNetwork
    private lateinit var client: HttpClient

    @BeforeTest
    fun start() {
        // The API of the app, on plain TCP. In production, it runs behind the
        // gateway.
        api = embeddedServer(CIO, host = "127.0.0.1", port = 0) {
            routing {
                get("/greeting") { call.respondText("Hello, ${call.parameters["name"]}!") }
            }
        }.start()

        // Retrieve the port of the API, so the gateway can connect to it.
        val apiPort = runBlocking { api.engine.resolvedConnectors().first().port }

        // The built-in server of the network plays the gateway. It connects
        // each tunnel for API_HOST to the API.
        network = ScionTestNetwork.start {
            gatewayBackend(API_HOST, "127.0.0.1:$apiPort")
        }

        // Build a client using the ScionHttp engine.
        client = HttpClient(ScionHttp) {
            engine {
                // Use the test network, so the engine can reach the gateway.
                useTestNetwork(network)
                // Send each request through the gateway. In the test network,
                // the gateway listens on gatewayPort, not on 443.
                webGateway = ScionWebGateway(port = network.gatewayPort)
                requestTimeoutMillis = 20_000
            }
        }
    }

    @AfterTest
    fun stop() {
        client.close()
        network.close()
        api.stop()
    }

    @Test
    fun greetsOverScion(): Unit = runBlocking {
        // The scheme is http, because the API has no TLS.
        val greeting = GreetingApi(client, "http://$API_HOST").greet("SCION")
        assertEquals("Hello, SCION!", greeting)
    }

    private companion object {
        const val API_HOST = "api.example.com"
    }
}
