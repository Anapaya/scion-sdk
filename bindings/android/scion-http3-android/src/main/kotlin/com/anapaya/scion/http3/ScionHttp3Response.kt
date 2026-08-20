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

import java.io.Closeable

/**
 * A response, with its body already received.
 *
 * A non-2xx status is a response, not a failure: it arrives here rather than as an exception, and
 * [isSuccessful] is the check. Exceptions are for requests that did not produce a response at all.
 *
 * `Closeable` for the same forward-compatibility reason as [ScionHttp3ResponseBody]; closing a
 * response closes its body.
 */
public class ScionHttp3Response internal constructor(
    /** The status code. */
    public val code: Int,
    /** The response's header section. */
    public val headers: ScionHttp3Headers,
    /** The body. Always present, and empty when the response carried none. */
    public val body: ScionHttp3ResponseBody,
    /**
     * The trailing header section, or null when the response had none.
     *
     * Null and empty are different: null means no trailer section was sent, an empty section means
     * one was sent and carried nothing.
     */
    public val trailers: ScionHttp3Headers?,
    /** The request this answers. */
    public val request: ScionHttp3Request,
) : Closeable {
    /** Whether [code] is in 200..299. */
    public val isSuccessful: Boolean get() = code in 200..299

    override fun close() {
        body.close()
    }

    override fun toString(): String = "$code ${request.method} ${request.url}"
}
