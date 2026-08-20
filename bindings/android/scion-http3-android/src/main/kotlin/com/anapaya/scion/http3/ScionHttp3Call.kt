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

package com.anapaya.scion.http3

import java.util.concurrent.atomic.AtomicBoolean

/**
 * A request that has not been sent yet.
 *
 * One call sends one request. Take another from [ScionHttp3Client.newCall] to send the same request
 * again; the [request] itself is immutable and reusable.
 *
 * There is no `cancel()`. Cancelling the coroutine that awaits [execute] cancels the request, all
 * the way down to the HTTP/3 stream, which is how cancellation already works in every other
 * `suspend` function an application calls.
 */
public class ScionHttp3Call internal constructor(
    /** The request this call sends. */
    public val request: ScionHttp3Request,
    private val send: suspend (ScionHttp3Request) -> ScionHttp3Response,
) {
    private val executed = AtomicBoolean(false)

    /** Whether [execute] has been called. */
    public val isExecuted: Boolean get() = executed.get()

    /**
     * Sends the request and waits for the response, body included.
     *
     * Suspends until the response is complete. Cancelling resets the HTTP/3 stream and returns
     * promptly; the connection stays usable for the next request.
     *
     * @throws IllegalStateException if this call has already been executed.
     * @throws ScionHttp3Exception if the request does not produce a response.
     */
    public suspend fun execute(): ScionHttp3Response {
        check(executed.compareAndSet(false, true)) {
            "this call has already been executed. Take a new one from " +
                "ScionHttp3Client.newCall(request) to send the same request again."
        }
        return send(request)
    }

    override fun toString(): String = "call($request)"
}
