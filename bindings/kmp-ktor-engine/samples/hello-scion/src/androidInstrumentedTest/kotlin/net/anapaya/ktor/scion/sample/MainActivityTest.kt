// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** A tap on "Run sample" without an API key reaches the test network in the app. */
class MainActivityTest {

    @Test
    fun aRunWithoutApiKeyReachesTheTestNetwork() {
        // Start without a saved API key.
        InstrumentationRegistry.getInstrumentation().targetContext
            .getSharedPreferences("sample", Context.MODE_PRIVATE).edit().clear().commit()

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity -> activity.views<Button>().single().performClick() }

            // Wait for the output.
            val deadline = TimeSource.Monotonic.markNow() + 30.seconds
            var output = ""
            while (deadline.hasNotPassedNow() && "parallel requests" !in output && "failed" !in output) {
                Thread.sleep(200)
                scenario.onActivity { activity ->
                    output = activity.views<TextView>().single { it !is Button && it !is EditText }.text.toString()
                }
            }

            // Check the single and the parallel requests.
            assertTrue("status   200" in output, output)
            assertTrue("[200, 200, 200, 200, 200, 200, 200, 200]" in output, output)
        }
    }
}

/** The views of type [T] in the layout of the activity, without the action bar. */
private inline fun <reified T : View> MainActivity.views(): List<T> =
    walk(findViewById(android.R.id.content)).filterIsInstance<T>()

private fun walk(view: View): List<View> {
    val children = (view as? ViewGroup)?.let { group -> List(group.childCount) { group.getChildAt(it) } }
    return listOf(view) + children.orEmpty().flatMap(::walk)
}
