package net.anapaya.ktor.scion

import kotlinx.coroutines.CoroutineScope

/**
 * Runs a test body and blocks until it ends.
 *
 * `runBlocking` exists on the JVM and on Kotlin/Native, but not in common code.
 * The tests need real time, so a virtual-time test scheduler does not fit.
 */
internal expect fun runEngineTest(block: suspend CoroutineScope.() -> Unit)
