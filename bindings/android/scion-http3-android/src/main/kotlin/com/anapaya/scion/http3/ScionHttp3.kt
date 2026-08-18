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

/**
 * Placeholder entry point for the SCION HTTP/3 Android client.
 *
 * The real API (`ScionHttpClient`, `ScionRequest`, `ScionResponse`) arrives with the Kotlin
 * library, on top of generated bindings. This object exists so the module compiles, packages and
 * can be consumed while the build pipeline is brought up.
 */
public object ScionHttp3 {
    /**
     * Base name of the bundled native library, as passed to [System.loadLibrary].
     *
     * The AAR carries one `jni/<abi>/lib$NATIVE_LIBRARY_NAME.so` per supported ABI.
     */
    public const val NATIVE_LIBRARY_NAME: String = "scion_http3_ffi"

    /**
     * Loads the bundled native library.
     *
     * Deliberately not done in an initialiser: loading at class-initialisation time would make this
     * class unusable from a plain JVM unit test, which is the tier the design relies on most.
     *
     * @throws UnsatisfiedLinkError if the AAR carries no library for the device's ABI.
     */
    @JvmStatic
    public fun loadNativeLibrary() {
        System.loadLibrary(NATIVE_LIBRARY_NAME)
    }
}
