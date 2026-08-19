// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.net.URI
import java.net.http.HttpClient
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import java.net.http.HttpRequest as JavaHttpRequest
import java.net.http.HttpResponse as JavaHttpResponse

/**
 * A handle on a running `scion-h3-test-server`: a PocketSCION topology with an HTTP/3 server in it,
 * written in Rust.
 *
 * Nothing here serves anything. It starts that process, reads the endpoints it prints, asks its
 * control API what it has seen, and stops it again. A separate process because a SCION topology
 * cannot be started from a JVM.
 */
class TestServer private constructor(
    private val process: Process,
    val endpoints: Endpoints,
) : AutoCloseable {
    /** Everything a client needs to reach this server. */
    data class Endpoints(
        val endhostApiUrl: String,
        val authToken: String,
        val baseUrl: String,
        /** The server's SCION address, without a port: the port comes from the URL. */
        val target: String,
        val caPem: String,
        val controlUrl: String,
    )

    /** A URL on this server. */
    fun url(path: String): String = endpoints.baseUrl + path

    /**
     * Chunks the endless body has sent for [tag].
     *
     * Stops going up once the client's `STOP_SENDING` has arrived, which is how a test can see
     * that a cancelled call reached the server.
     */
    fun endlessChunks(tag: String): Long = counter("endless_chunks", tag)

    /** Requests the server has completed for [path]. */
    fun requestsSeen(path: String): Long = counter("requests", path)

    private fun counter(
        group: String,
        key: String,
    ): Long {
        val stats = JsonParser.parseString(get("/stats")).asJsonObject
        val entries = stats.getAsJsonObject(group) ?: JsonObject()
        return entries.get(key)?.asLong ?: 0
    }

    private fun get(path: String): String {
        val request = JavaHttpRequest.newBuilder(URI.create(endpoints.controlUrl + path)).build()
        return control.send(request, JavaHttpResponse.BodyHandlers.ofString()).body()
    }

    override fun close() {
        // Closing standard input is how the server is asked to stop; destroying it is the fallback
        // for a server that is wedged rather than merely busy.
        runCatching { process.outputStream.close() }
        if (!process.waitFor(SHUTDOWN_TIMEOUT.inWholeSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
        }
    }

    companion object {
        /** How long to wait for the topology to come up before giving up on it. */
        private val START_TIMEOUT: Duration = 120.seconds
        private val SHUTDOWN_TIMEOUT: Duration = 10.seconds

        private val control: HttpClient = HttpClient.newHttpClient()

        /**
         * The server every test uses unless it needs one configured differently.
         *
         * Shared because starting a topology is the slowest thing in this suite by a wide margin,
         * and torn down by a shutdown hook rather than by a test, so that no ordering between
         * classes has to be arranged. The Gradle test task runs one fork, so there is one of these.
         */
        val shared: TestServer by lazy {
            start().also { server ->
                Runtime.getRuntime().addShutdownHook(Thread { server.close() })
            }
        }

        /**
         * Starts a server with the given extra arguments, for the cases that need one built
         * differently: a server that speaks the wrong ALPN, or that allows no request streams.
         */
        fun start(vararg args: String): TestServer {
            val binary =
                requireNotNull(System.getProperty("scion.test.server")) {
                    "scion.test.server is not set; run this through Gradle, which builds the " +
                        "server and passes its path"
                }
            val process =
                ProcessBuilder(listOf(binary) + args)
                    // Straight to the test output, so a topology that fails to start says why
                    // rather than showing up as a timeout here.
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .start()

            val description =
                CompletableFuture
                    .supplyAsync { process.inputStream.bufferedReader().readLine() }
                    .orTimeout(START_TIMEOUT.inWholeSeconds, TimeUnit.SECONDS)
                    .exceptionally { cause ->
                        process.destroyForcibly()
                        throw IllegalStateException("$binary did not report its endpoints", cause)
                    }.join()
            checkNotNull(description) { "$binary exited before reporting its endpoints" }

            val json = JsonParser.parseString(description).asJsonObject
            return TestServer(
                process,
                Endpoints(
                    endhostApiUrl = json.get("endhost_api_url").asString,
                    authToken = json.get("auth_token").asString,
                    baseUrl = json.get("base_url").asString,
                    target = json.get("target").asString,
                    caPem = json.get("ca_pem").asString,
                    controlUrl = json.get("control_url").asString,
                ),
            )
        }
    }
}
