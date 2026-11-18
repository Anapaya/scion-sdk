// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.consumer

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.ScionHttp
import net.anapaya.ktor.scion.testing.ScionTestNetwork
import net.anapaya.ktor.scion.testing.useTestNetwork
import kotlin.test.Test
import kotlin.test.assertEquals

class ConsumerTest {

    // ANCHOR: first-request
    @Test
    fun thePublishedEngineReachesTheTestApi() {
        // Start a SCION network in the test process.
        ScionTestNetwork.start().use { network ->
            runBlocking {
                // Attach the engine to the network, and trust the CA of its test API.
                val client = HttpClient(ScionHttp) {
                    engine {
                        useTestNetwork(network)
                        caCertificatesPem = network.testApiCaPem
                    }
                }

                // Send a request over SCION.
                client.use {
                    val response = it.get("${network.testApiUrl}/hello")
                    assertEquals("world", response.bodyAsText())
                }
            }
        }
    }
    // ANCHOR_END: first-request
}
