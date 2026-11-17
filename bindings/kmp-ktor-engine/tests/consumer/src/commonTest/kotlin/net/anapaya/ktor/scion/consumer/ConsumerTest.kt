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

    @Test
    fun thePublishedEngineReachesTheTestApi() {
        ScionTestNetwork.start().use { network ->
            runBlocking {
                val client = HttpClient(ScionHttp) {
                    engine {
                        useTestNetwork(network)
                        caCertificatesPem = network.testApiCaPem
                    }
                }
                client.use { assertEquals("world", it.get("${network.testApiUrl}/hello").bodyAsText()) }
            }
        }
    }
}
