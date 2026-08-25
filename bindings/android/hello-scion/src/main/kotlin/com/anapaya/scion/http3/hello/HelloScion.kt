// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.hello

// ANCHOR: full-sample
import android.content.Context
import com.anapaya.scion.http3.ScionAddress
import com.anapaya.scion.http3.ScionHttp3Client
import com.anapaya.scion.http3.ScionHttp3Request
import com.anapaya.scion.http3.TrustAnchors
import java.io.Closeable
import kotlin.time.Duration.Companion.seconds

/**
 * One HTTP/3 request over SCION.
 */
class HelloScion(
    context: Context,
    private val network: LocalNetwork,
) : Closeable {
    /** What the server answered. A non-2xx status arrives here, not as an exception. */
    data class Reply(
        val code: Int,
        val body: String,
    )

    // ANCHOR: build-client
    private val client =
        ScionHttp3Client
            .Builder(context)
            // Where the client discovers its SCION connectivity.
            .endhostApi(network.endhostApiUrl)
            .authToken(network.authToken)
            .trust(TrustAnchors.pinned(network.caPem.toByteArray()))
            .connectTimeout(30.seconds)
            .requestTimeout(60.seconds)
            .build()
    // ANCHOR_END: build-client

    // ANCHOR: request

    /** `GET /hello`, which the test server answers with `world`. */
    suspend fun hello(): Reply {
        val request =
            ScionHttp3Request
                .Builder()
                .url("${network.baseUrl}/hello")
                // The test network publishes no records for its server, so address it directly.
                .target(ScionAddress.parse(network.target))
                .get()
                .build()

        return client.newCall(request).execute().use { response ->
            Reply(response.code, response.body.string())
        }
    }
    // ANCHOR_END: request

    // ANCHOR: lifetime

    /**
     * Releases the client's connections.
     *
     * This returns at once and leaves the shutdown to finish on its own. Await it with
     * [ScionHttp3Client.shutdown] instead where that matters.
     */
    override fun close() {
        client.close()
    }
    // ANCHOR_END: lifetime
}
// ANCHOR_END: full-sample
