// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsBytes
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import net.anapaya.ktor.scion.ScionEngineConfig
import net.anapaya.ktor.scion.ScionHttp
import kotlin.time.TimeSource

/**
 * Sends a GET to [url] over SCION, then eight in parallel, and logs what came
 * back. [engine] configures the engine, for example with the API key.
 */
public suspend fun runSample(
    url: String,
    log: (String) -> Unit = ::println,
    engine: ScionEngineConfig.() -> Unit,
) {
    val client = HttpClient(ScionHttp) {
        engine(engine)
        install(HttpTimeout) { requestTimeoutMillis = 20_000 }
    }

    client.use {
        // Send one request.
        val started = TimeSource.Monotonic.markNow()
        val response = client.get(url)
        log("GET $url")
        log("  status   ${response.status}")
        log("  protocol ${response.version}")
        log("  bytes    ${response.bodyAsBytes().size}")
        log("  took     ${started.elapsedNow()} (includes SCION discovery)")

        // Send eight in parallel.
        val parallel = TimeSource.Monotonic.markNow()
        val statuses = coroutineScope {
            List(8) { async { client.get(url).status.value } }.awaitAll()
        }
        log("8 parallel requests -> $statuses in ${parallel.elapsedNow()}")
    }
}
