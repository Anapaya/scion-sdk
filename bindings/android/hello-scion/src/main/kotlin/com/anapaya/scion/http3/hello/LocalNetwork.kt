// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.hello

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL

/**
 * Where the local test network is, and how to be trusted by it.
 *
 * A real app knows all of this before it is built: a fixed endhost API URL, a token from where it
 * keeps credentials, a server it addresses by name, and an authority it ships or inherits from the
 * device. `scion-h3-test-server` decides all four when it starts, because it takes ephemeral ports,
 * mints an auth token per run and generates a throwaway certificate authority, so this sample asks
 * it.
 */
data class LocalNetwork(
    val endhostApiUrl: String,
    val authToken: String,
    val baseUrl: String,
    /** The server's SCION address, without a port: the port comes from [baseUrl]. */
    val target: String,
    val caPem: String,
) {
    companion object {
        /**
         * The control API of a test server started with `--control-port 7443`. 10.0.2.2 is the
         * emulator's translation of the host's loopback, which is where the server binds.
         */
        private const val CONTROL_URL = "http://10.0.2.2:7443/info"

        /** Reads the description the test server serves. Throws if it is not running. */
        suspend fun discover(): LocalNetwork =
            withContext(Dispatchers.IO) {
                val info = JSONObject(URL(CONTROL_URL).readText())
                LocalNetwork(
                    endhostApiUrl = info.getString("endhost_api_url"),
                    authToken = info.getString("auth_token"),
                    baseUrl = info.getString("base_url"),
                    target = info.getString("target"),
                    caPem = info.getString("ca_pem"),
                )
            }
    }
}
