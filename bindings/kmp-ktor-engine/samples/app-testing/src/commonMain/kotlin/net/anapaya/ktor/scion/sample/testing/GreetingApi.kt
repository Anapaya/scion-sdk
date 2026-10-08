// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample.testing

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import io.ktor.client.statement.bodyAsText
import net.anapaya.ktor.scion.ScionTokenSource
import net.anapaya.ktor.scion.ScionHttp
import net.anapaya.ktor.scion.ScionWebGateway

/** The API of the app. It knows nothing about SCION. */
class GreetingApi(private val client: HttpClient, private val baseUrl: String) {
    suspend fun greet(name: String): String =
        client.get("$baseUrl/greeting") { parameter("name", name) }.bodyAsText()
}

/** The client that the app ships with: the AA, and the WebGateway of the API. */
fun productionClient(apiKey: String): HttpClient = HttpClient(ScionHttp) {
    engine {
        tokenSource = ScionTokenSource.AnapayaAa(apiKey = apiKey)
        webGateway = ScionWebGateway()
    }
}
