// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import com.anapaya.scion.http3.ScionAddress
import com.anapaya.scion.http3.ScionHttp3Client
import com.anapaya.scion.http3.ScionHttp3Request
import com.anapaya.scion.http3.ScionHttp3Response
import com.anapaya.scion.http3.TrustAnchors
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

internal const val TEST_TIMEOUT_MILLIS = 180_000L

/**
 * The `scion-h3-test-server` used in the e2e tests.
 */
object Fixture {
    /** What `GET /info` says. The fields are the test server's, named as it names them. */
    data class Info(
        val endhostApiUrl: String,
        val authToken: String,
        val baseUrl: String,
        /** The server's SCION address, without a port: the port comes from [baseUrl]. */
        val target: String,
        val caPem: String,
        /** An authority that signed nothing here, for a client that has to fail to verify. */
        val wrongCaPem: String,
        val underlay: String,
    )

    /** The context these tests build clients with: the test application's own. */
    val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * Where the control API is, as this side was told to reach it.
     */
    private val controlUrl: String by lazy {
        val arguments = InstrumentationRegistry.getArguments()
        val host = arguments.getString("fixtureHost") ?: "10.0.2.2"
        val port = arguments.getString("fixtureControlPort") ?: "7443"
        "http://$host:$port"
    }

    /** Read once per process: it does not change while the server runs. */
    val info: Info by lazy { fetchInfo() }

    /** The server's SCION address, for addressing it without a resolver. */
    val target: ScionAddress by lazy { ScionAddress.parse(info.target) }

    /** A URL on the server. */
    fun url(path: String): String = info.baseUrl + path

    /**
     * A client that can reach the server, with everything but the trust anchors already set.
     */
    fun clientBuilder(): ScionHttp3Client.Builder =
        ScionHttp3Client
            .Builder(context)
            .endhostApi(info.endhostApiUrl)
            .authToken(info.authToken)
            .trust(TrustAnchors.pinned(info.caPem.toByteArray()))
            .connectTimeoutMillis(30_000)
            .requestTimeoutMillis(60_000)

    /** A client trusting the certificate the server presents. */
    fun client(): ScionHttp3Client = clientBuilder().build()

    /**
     * A request to [path] on the server, addressed by SCION address rather than by name.
     *
     * The topology has no TSAR records, so every request that is meant to succeed goes through the
     * target escape hatch. What resolution does with real records is not this tier's question.
     */
    fun request(path: String): ScionHttp3Request.Builder =
        ScionHttp3Request
            .Builder()
            .url(url(path))
            .target(target)

    /** Requests for [path] that reached a handler, whether or not they finished. */
    fun requestsStarted(path: String): Long = counter("started", path)

    /** Requests for [path] that ran to completion. */
    fun requestsCompleted(path: String): Long = counter("requests", path)

    /** How many times the HTTP/3 server has been stood up again. */
    fun restarts(): Long = stats().get("restarts").asLong

    private fun stats(): JsonObject = JsonParser.parseString(control("/stats")).asJsonObject

    private fun counter(
        group: String,
        key: String,
    ): Long = stats().getAsJsonObject(group)?.get(key)?.asLong ?: 0

    /**
     * Throws every connection away and serves again at the same address.
     */
    fun restartServer() {
        control("/restart-server", "POST")
    }

    private fun fetchInfo(): Info {
        val json = JsonParser.parseString(control("/info")).asJsonObject
        return Info(
            endhostApiUrl = json.get("endhost_api_url").asString,
            authToken = json.get("auth_token").asString,
            baseUrl = json.get("base_url").asString,
            target = json.get("target").asString,
            caPem = json.get("ca_pem").asString,
            wrongCaPem = json.get("wrong_ca_pem").asString,
            underlay = json.get("underlay").asString,
        ).also {
            check(it.underlay == "snap") {
                "the test server is on the ${it.underlay} underlay, and this tier needs snap. " +
                    "Start it with --underlay snap; see ../../tools/e2e.sh."
            }
        }
    }

    /**
     * A call on the control API.
     *
     * A GET is retried while the device cannot reach the host at all. A POST is sent once.
     */
    private fun control(
        path: String,
        method: String = "GET",
    ): String {
        val expiry = System.nanoTime() + CONTROL_RETRY_WINDOW_MILLIS * 1_000_000L
        while (true) {
            try {
                return send(path, method)
            } catch (e: IOException) {
                if (method != "GET" || System.nanoTime() >= expiry) {
                    throw AssertionError(unreachable(path), e)
                }
                Thread.sleep(CONTROL_RETRY_DELAY_MILLIS)
            }
        }
    }

    private fun unreachable(path: String): String =
        "$controlUrl$path could not be reached, and stayed unreachable for " +
            "${CONTROL_RETRY_WINDOW_MILLIS / 1000} seconds."

    /**
     * @throws IOException if the server could not be reached at all.
     * @throws AssertionError if it answered, with something other than success.
     */
    private fun send(
        path: String,
        method: String,
    ): String {
        val connection = URL(controlUrl + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = CONTROL_TIMEOUT_MILLIS
            // Generous, because a restart takes as long as standing a QUIC endpoint up again takes,
            // which on an emulator is not instant.
            connection.readTimeout = CONTROL_TIMEOUT_MILLIS
            if (method == "POST") connection.doOutput = true

            // Reading the status is what performs the request, so anything that stops the two sides
            // from talking is thrown from here as the IOException the caller turns into its own
            // message. Past this line the server has answered, whatever it said.
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (code !in 200..299) {
                throw AssertionError("$method $controlUrl$path answered $code: $body")
            }
            return body
        } finally {
            connection.disconnect()
        }
    }

    private const val CONTROL_TIMEOUT_MILLIS = 60_000

    // Long enough for the emulator's networking to come back by itself, which takes well under a
    // second, and short enough that a server nobody started still says so promptly.
    private const val CONTROL_RETRY_WINDOW_MILLIS = 10_000
    private const val CONTROL_RETRY_DELAY_MILLIS = 500L
}

/**
 * `GET [path]` on the test server.
 *
 * Not [ScionHttp3Client.get], which resolves the URL's host: the topology has no TSAR records, so
 * every request goes through [Fixture.request] and its address override.
 */
internal suspend fun ScionHttp3Client.getFromFixture(path: String): ScionHttp3Response =
    newCall(Fixture.request(path).build()).execute()
