// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.anapaya.scion.http3.internal

import com.anapaya.scion.http3.uniffi.HttpRequest
import com.anapaya.scion.http3.uniffi.HttpResponse
import com.anapaya.scion.http3.uniffi.defaultClientConfig
import com.anapaya.scion.http3.uniffi.ScionHttp3Client as FfiClient

/**
 * [Http3Backend] over the generated bindings.
 *
 * Nothing but delegation and construction lives here. Everything that decides anything is above this
 * class, which is what lets the tests above it run without the native library this one loads.
 */
internal class UniffiHttp3Backend(
    private val client: FfiClient,
) : Http3Backend {
    override suspend fun execute(request: HttpRequest): HttpResponse = client.execute(request)

    override suspend fun warmUp(url: String) {
        client.warmUp(url)
    }

    override fun reset() {
        client.reset()
    }

    override fun setAuthToken(token: String) {
        client.setAuthToken(token)
    }

    override suspend fun shutdown() {
        client.shutdown()
    }

    override fun close() {
        client.close()
    }
}

/**
 * Builds a real backend.
 *
 * Blocking, and the caller is expected to be on a dispatcher that tolerates that: the constructor
 * installs a cryptography provider and starts the runtime that carries every request, and reading
 * the platform's trust anchors touches the disk.
 */
internal class UniffiHttp3BackendFactory(
    private val trustStore: SystemTrustStore,
) : Http3BackendFactory {
    override fun create(settings: ClientSettings): Http3Backend {
        val config =
            settings.applyTo(
                // The stack's own defaults, asked for by URL because that is the one setting it has
                // no default for.
                base = defaultClientConfig(settings.endhostApiUrl),
                trust = settings.trust.toFfi(trustStore),
            )
        return UniffiHttp3Backend(FfiClient(config))
    }
}
