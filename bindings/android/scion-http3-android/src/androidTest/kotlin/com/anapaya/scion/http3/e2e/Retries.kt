// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import com.anapaya.scion.http3.ScionHttp3Client
import com.anapaya.scion.http3.ScionHttp3Exception
import kotlinx.coroutines.delay
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `GET [path]` until it answers or [deadline] passes, reporting the status of the one that did.
 *
 * @throws AssertionError if nothing succeeded in time, carrying the last failure as its cause.
 */
internal suspend fun ScionHttp3Client.getUntilItWorks(
    path: String,
    deadline: Duration,
): Int {
    val expiry = System.nanoTime() + deadline.inWholeNanoseconds
    var last: ScionHttp3Exception? = null
    while (System.nanoTime() < expiry) {
        try {
            return getFromFixture(path).use { it.code }
        } catch (e: ScionHttp3Exception) {
            // Only what the stack says may succeed on a second attempt. Retrying a deterministic
            // failure cannot do anything but spend the deadline and report the same error later,
            // by which time it looks like a timeout rather than the refusal it is.
            if (!e.isRetryable) throw e
            last = e
            delay(RETRY_DELAY)
        }
    }
    throw AssertionError("no request to $path succeeded within $deadline", last)
}

private val RETRY_DELAY: Duration = 1.seconds
