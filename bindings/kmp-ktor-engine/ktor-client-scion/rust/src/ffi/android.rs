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

//! Initializes `rustls-platform-verifier` on Android.
//!
//! The verifier calls into the JVM, so it needs the JVM and the application
//! context before the first TLS handshake. UniFFI reaches the Rust library
//! over JNA, which passes no JNI environment. This JNI export is the one
//! entry point that gets one.

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JClass, JObject},
};

/// `AndroidTrust.init` in the Kotlin library. A second call has no effect.
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_anapaya_ktor_scion_AndroidTrust_init<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>();
}
