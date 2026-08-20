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

/**
 * What the library needs from the generated bindings.
 *
 * Deliberately in terms of the generated request and response records rather than a set of types of
 * its own. Those records are plain data classes whose converters are separate objects, so building
 * one loads no native library, which means a fake of this interface can stand in for the whole FFI
 * while the mapping is still exercised all the way to the record the stack would receive. A seam one
 * step higher would leave that last conversion untested.
 *
 * The generated client's own interface is not used for this: it does not carry `close()`, and
 * anything that touches its companion pulls in the native library.
 */
internal interface Http3Backend : AutoCloseable {
    /** Issues a request. Cancellable: cancelling resets the HTTP/3 stream. */
    suspend fun execute(request: HttpRequest): HttpResponse

    /** Establishes connectivity to an origin before it is needed. */
    suspend fun warmUp(url: String)

    /**
     * Marks connectivity stale.
     *
     * Returns immediately: the rebuild happens on the next request, and concurrent requests that
     * find it stale are coalesced into one rebuild below this seam.
     */
    fun reset()

    /** Replaces the bearer token. Fails if the client was built without one. */
    fun setAuthToken(token: String)

    /** Closes the connection pool gracefully, faulting anything in flight. */
    suspend fun shutdown()

    /** Releases the handle. Anything issued afterwards fails. */
    override fun close()
}

/**
 * Builds a backend from validated settings.
 *
 * A separate factory because a client is built without one: constructing the backend starts a Tokio
 * runtime and may read the trust store, neither of which belongs on the thread that called
 * `build()`. The client asks for one when it first needs it.
 */
internal fun interface Http3BackendFactory {
    fun create(settings: ClientSettings): Http3Backend
}
