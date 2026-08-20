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

/**
 * Decides when connectivity has to be rebuilt.
 *
 * The whole decision lives here, and it is deliberately pure: observations and a clock go in, and
 * "the next request should rebuild" comes out. No timers, no handler, no coroutines, nothing from
 * the framework. That is what makes the behaviour this class exists for testable without a device.
 *
 * The rules, and why each is what it is:
 *
 * The first observation is adopted as the baseline and marks nothing. Registering a callback
 * delivers the current network immediately, and a client that has not connected yet has nothing
 * stale about it.
 *
 * An observation of a network that is not usable yet is ignored. A network is reported available
 * before it is validated and before it has addresses, and rebuilding onto it then would discard
 * working connectivity in favour of a handshake that cannot succeed.
 *
 * A different network marks connectivity stale, at most once per [debounceWindowMillis]. Marking
 * happens on the leading edge, because the rebuild is lazy: nothing is spent until the next request,
 * so there is no reason to wait, and waiting would only widen the window in which requests are still
 * sent over a network that is gone. A change arriving inside the suppression window is remembered and
 * committed at the next observation or the next request, so nothing is dropped. The suppression
 * matters below this class: a rebuild that is already running and is marked stale again has to be
 * thrown away and redone.
 *
 * A change back to the network already in use cancels a remembered change. A brief loss of cellular
 * that recovers onto the same network with the same addresses is exactly the case where the right
 * answer is to do nothing.
 *
 * Finally, a request after a long idle gap re-checks the network itself. Callbacks are delayed or
 * dropped while the device is dozing, so a returning application cannot trust that it was told.
 * Rather than rebuilding blindly, it asks what the current network is and compares.
 */
internal class StalenessTracker(
    private val clock: MonotonicClock,
    private val idleThresholdMillis: Long,
    private val log: LibraryLog,
    private val debounceWindowMillis: Long = DEBOUNCE_WINDOW_MILLIS,
) {
    private val lock = Any()

    private var baseline: NetworkIdentity? = null
    private var remembered: NetworkIdentity? = null
    private var stale = false
    private var lastMarkedMillis = Long.MIN_VALUE
    private var lastUseMillis = NEVER

    /**
     * Records what the platform reported. Called on a framework callback thread.
     *
     * Cheap and non-throwing by construction: it takes a lock, compares, and returns.
     */
    fun observe(identity: NetworkIdentity) {
        synchronized(lock) {
            if (!identity.isUsable) return
            val baseline = baseline
            if (baseline == null) {
                this.baseline = identity
                lastMarkedMillis = clock.elapsedRealtimeMillis()
                return
            }
            if (identity.isSameNetworkAs(baseline)) {
                remembered = null
                return
            }
            val now = clock.elapsedRealtimeMillis()
            if (now - lastMarkedMillis >= debounceWindowMillis) {
                mark(identity, now)
            } else {
                remembered = identity
            }
        }
    }

    /**
     * Called before a request is issued: returns whether connectivity has to be rebuilt first.
     *
     * @param probe asks the platform what the current network is, for the idle check. Only called
     *   when the gap is long enough to have hidden a change, so a request on a warm client pays
     *   nothing for it.
     */
    fun onUseAttempt(probe: () -> NetworkIdentity?): Boolean =
        synchronized(lock) {
            val now = clock.elapsedRealtimeMillis()
            commitRememberedIfDue(now)
            checkIdleGap(now, probe)
            lastUseMillis = now
            consumeStale()
        }

    /**
     * Called when a request finishes, successfully or not.
     *
     * Without this a request that takes a minute would make the request after it look like it
     * followed a minute of idleness.
     */
    fun onUseComplete() {
        synchronized(lock) { lastUseMillis = clock.elapsedRealtimeMillis() }
    }

    /** Called when the application asks for a rebuild itself, so the next request does not repeat it. */
    fun onManualReset() {
        synchronized(lock) {
            stale = false
            remembered = null
            val now = clock.elapsedRealtimeMillis()
            lastMarkedMillis = now
            lastUseMillis = now
        }
    }

    /** The network the last rebuild was, or will be, made for. Test and diagnostic use. */
    fun baseline(): NetworkIdentity? = synchronized(lock) { baseline }

    private fun mark(
        identity: NetworkIdentity,
        now: Long,
    ) {
        baseline = identity
        remembered = null
        stale = true
        lastMarkedMillis = now
        log.debug("the default network changed; connectivity will be rebuilt on the next request")
    }

    private fun commitRememberedIfDue(now: Long) {
        val remembered = remembered ?: return
        if (now - lastMarkedMillis >= debounceWindowMillis) mark(remembered, now)
    }

    private fun checkIdleGap(
        now: Long,
        probe: () -> NetworkIdentity?,
    ) {
        if (lastUseMillis == NEVER || now - lastUseMillis < idleThresholdMillis) return

        // Not `runCatching`: that would also swallow a CancellationException, and this runs on the
        // caller's coroutine. Only the framework's own failures are absorbed, because being unable
        // to ask is itself a reason to rebuild.
        val current =
            try {
                probe()
            } catch (e: RuntimeException) {
                log.warn("could not read the current network: $e")
                null
            }

        val baseline = baseline
        if (current == null || baseline == null || !current.isSameNetworkAs(baseline)) {
            mark(current ?: baseline ?: return, now)
        }
    }

    private fun consumeStale(): Boolean {
        if (!stale) return false
        stale = false
        return true
    }

    internal companion object {
        /**
         * How long one marking suppresses the next.
         *
         * Long enough to cover the burst of callbacks a single handover produces, short enough that
         * the change it defers is committed by the time anyone notices.
         */
        const val DEBOUNCE_WINDOW_MILLIS: Long = 500

        /** The floor for the idle gap, whatever the configured connection timeouts are. */
        const val MIN_IDLE_THRESHOLD_MILLIS: Long = 30_000

        private const val NEVER = Long.MIN_VALUE

        /**
         * The idle gap for a client whose idle connections are swept after
         * [idleConnectionTimeoutMillis].
         *
         * Twice that timeout, floored. Under the timeout there are still warm connections, and a
         * rebuild would throw them away for nothing. Over it the pool has been swept anyway, so a
         * needless rebuild costs one handshake on a request that was going to establish from scratch,
         * where a missed change costs a failed request. The two are not symmetric, so this leans
         * towards checking.
         */
        fun idleThresholdFor(idleConnectionTimeoutMillis: Long): Long =
            maxOf(2 * idleConnectionTimeoutMillis, MIN_IDLE_THRESHOLD_MILLIS)
    }
}
