package net.anapaya.ktor.scion

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking

internal actual fun runEngineTest(block: suspend CoroutineScope.() -> Unit) {
    runBlocking(block = block)
}
