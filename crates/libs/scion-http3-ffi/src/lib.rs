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

//! # C ABI shared library for the SCION HTTP/3 client
//!
//! Placeholder surface, to be replaced by a generated API once the language bindings land. Until
//! then this crate exists to prove the mobile build pipeline end to end: that [`scion_http3`], and
//! with it squiche, BoringSSL, `ring`, `quinn-udp` and the SCION stack, cross-compiles to *and
//! links into* a `cdylib` for Android.
//!
//! Merely depending on [`scion_http3`] would prove only the first half. Cargo compiles the whole
//! dependency graph whatever this crate's code references, but the linker selects archive members
//! by reachability, so a stub that exports an unrelated symbol produces a shared library with no
//! BoringSSL in it at all. [`scion_http3_ffi_smoke`] therefore reaches the parts the build must get
//! right; see its documentation.
//!
//! Build it with `bindings/android/tools/android.py build`, which uses the workspace's `mobile`
//! cargo profile.

// The FFI boundary catches panics and turns them into error codes. Under panic=abort a panic in
// Rust would instead take the host application's process down, which is both a worse failure and
// one that no test would attribute to us. The `mobile` profile sets panic=unwind explicitly;
// this makes any configuration that does not a compile error rather than a runtime surprise.
#[cfg(panic = "abort")]
compile_error!(
    "scion-http3-ffi requires panic=unwind: the FFI boundary relies on catch_unwind to keep a \
     Rust panic from aborting the host process. Build with `--profile mobile`."
);

use std::{future::Future, pin::Pin};

use scion_http3::{Client, Config, Error, Response, scion_quic::quic::config::QuicConfig};

/// Endhost API address for the smoke test. Never contacted: `.invalid` is reserved by RFC 2606 and
/// nothing here polls the future that would use it.
const SMOKE_ENDHOST_API: &str = "https://endhost-api.invalid";

/// Request URL for the smoke test. Never contacted, as above.
const SMOKE_URL: &str = "https://example.invalid/";

/// [`QuicConfig::to_quiche_config`] failed, so BoringSSL is linked but not working.
const ERR_QUIC_CONFIG: i32 = -1;

/// The endhost API URL did not parse, which cannot happen for a constant.
const ERR_URL: i32 = -2;

/// A panic crossed the boundary. Reported rather than propagated, which is the behaviour the real
/// FFI layer needs and this crate asserts is available.
const ERR_PANIC: i32 = -3;

/// Exercises the linked-in SCION HTTP/3 stack. Returns `0` on success, or a negative error code.
///
/// Performs no I/O and contacts no network: it builds objects and then drops them.
///
/// This deliberately touches, rather than merely depends on, the two things the mobile build is
/// most likely to get wrong:
///
/// * [`QuicConfig::to_quiche_config`] constructs a `squiche::Config`, and with it a BoringSSL
///   `SSL_CTX`. That is what pulls `libssl.a`, `libcrypto.a` and the NDK C++ runtime into this
///   shared library, so the resulting `.so` can be checked for them.
/// * Boxing a request future as `dyn Future` puts its poll body behind a vtable reachable from an
///   exported symbol, which keeps the rest of the client, DNS resolution, the endhost API client
///   and the SNAP underlay, in the library instead of letting the linker discard all of it.
///
/// The future is created and dropped without ever being polled, which is why this needs no async
/// runtime and touches no socket.
#[unsafe(no_mangle)]
pub extern "C" fn scion_http3_ffi_smoke() -> i32 {
    catch_panics(smoke)
}

/// Runs `body`, turning a panic into [`ERR_PANIC`] instead of letting it unwind across the C ABI
/// boundary, where it would be undefined behaviour.
///
/// Separate from the exported function so that the panic path itself can be tested, which is the
/// property the whole arrangement exists to provide.
fn catch_panics(body: impl FnOnce() -> i32 + std::panic::UnwindSafe) -> i32 {
    std::panic::catch_unwind(body).unwrap_or(ERR_PANIC)
}

fn smoke() -> i32 {
    // Constructing this calls into BoringSSL, so it cannot be optimised away, and dropping it runs
    // SSL_CTX_free.
    let quic = match QuicConfig::default().to_quiche_config() {
        Ok(quic) => quic,
        Err(_) => return ERR_QUIC_CONFIG,
    };
    drop(std::hint::black_box(quic));

    let Ok(endhost_api) = SMOKE_ENDHOST_API.parse() else {
        return ERR_URL;
    };
    let client = Client::new(Config::new(endhost_api));

    // `async move` takes the client, so the future is 'static and the coercion to `dyn Future`
    // needs no lifetime gymnastics. Never polled: see the note above.
    let request: Pin<Box<dyn Future<Output = Result<Response, Error>>>> =
        Box::pin(async move { client.get(SMOKE_URL).await });
    drop(std::hint::black_box(request));

    0
}

#[cfg(test)]
mod tests {
    use super::{ERR_PANIC, catch_panics, scion_http3_ffi_smoke, smoke};

    /// Guards the stub on the host, so a mistake here surfaces in `cargo test` in seconds rather
    /// than minutes into an Android cross-build.
    #[test]
    fn smoke_succeeds() {
        assert_eq!(smoke(), 0);
    }

    /// The exported entry point is what the pipeline checks the shared library for, so exercise it
    /// under its real signature too.
    #[test]
    fn exported_entry_point_succeeds() {
        assert_eq!(scion_http3_ffi_smoke(), 0);
    }

    /// Panic containment is what lets the FFI boundary exist at all, so assert it rather than
    /// trusting that `catch_unwind` is wired up.
    #[test]
    fn a_panic_becomes_an_error_code() {
        // Otherwise the deliberate panic prints a backtrace that reads like a failing test.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let code = catch_panics(|| panic!("deliberate panic from a test"));
        std::panic::set_hook(previous);

        assert_eq!(code, ERR_PANIC);
    }
}
