// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.testing.ScionTestNetwork
import net.anapaya.ktor.scion.testing.useTestNetwork
import kotlin.test.Test
import kotlin.test.assertTrue

/** Keeps the sample running: [runSample] against a test network. */
class SampleTest {

    @Test
    fun theSampleReachesTheTestApi(): Unit = runBlocking {
        // Run the sample against a test network.
        val lines = mutableListOf<String>()
        ScionTestNetwork.start().use { network ->
            runSample("${network.testApiUrl}/hello", { lines += it }) {
                useTestNetwork(network)
                caCertificatesPem = network.testApiCaPem
            }
        }

        // Check its output.
        val output = lines.joinToString("\n")
        assertTrue("status   200" in output, output)
        assertTrue("[200, 200, 200, 200, 200, 200, 200, 200]" in output, output)
    }
}
