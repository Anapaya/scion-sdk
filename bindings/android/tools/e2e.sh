#!/usr/bin/env bash
# Copyright 2026 Anapaya Systems
#
# Runs the instrumented tests: the Kotlin library, the UniFFI bindings, the cross-compiled Rust
# core and a real SCION network, on an emulator.
#
# It builds what the run needs, starts the test server on this machine, runs the tests on a Gradle
# managed device, and stops the server again however it ends.
#
# Usage:
#
#   ./e2e.sh                       everything
#   ./e2e.sh RequestsTest          only tests whose name matches
#
# Needs a JDK, the Android SDK, an NDK in ANDROID_NDK_HOME, the x86_64 Rust target, and KVM. See
# ../README.md.
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(dirname "$TOOLS_DIR")"
WORKSPACE_DIR="$(cd "$ANDROID_DIR/../.." && pwd)"

# Fixed, so that the test application needs nothing told to it per run. Overridable for a second run
# beside a first one.
CONTROL_PORT="${FIXTURE_CONTROL_PORT:-7443}"

# Where the emulator reaches this machine's loopback, and the whole of what the test application is
# told: every other address it uses comes from what the control API reports.
FIXTURE_HOST="${FIXTURE_HOST:-10.0.2.2}"

# Ten seconds, in tenths, matching what the JVM harness allows the same server before destroying it.
SHUTDOWN_TIMEOUT_TENTHS=100

LOG_DIR="${E2E_LOG_DIR:-$ANDROID_DIR/build/e2e}"
FIXTURE_LOG="$LOG_DIR/fixture-snap.log"

echo "==> Building the test server"
cargo build --locked --release -p scion-h3-test-server --manifest-path "$WORKSPACE_DIR/Cargo.toml"

# Always, never conditionally: the generated bindings are regenerated from a host build below, and a
# library older than they are fails at load with an undefined symbol that names nothing about why.
echo "==> Building the native library for x86_64"
"$TOOLS_DIR/android.py" build --abi x86_64 --skip-verify

FIXTURE_BINARY="$(
    cargo metadata --format-version 1 --no-deps --manifest-path "$WORKSPACE_DIR/Cargo.toml" |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)/release/scion-h3-test-server"

mkdir -p "$LOG_DIR"

# The server stops when its standard input closes, which is how a harness that dies leaves no
# topology behind. It reads from a pipe this script holds the writing end of, so the trap only has
# to close a file descriptor.
FIXTURE_STDIN="$(mktemp -u)"
mkfifo -m 600 "$FIXTURE_STDIN"

stop_fixture() {
    exec 9>&-
    rm -f "$FIXTURE_STDIN"
    [[ -n "${FIXTURE_PID:-}" ]] || return 0

    local waited=0
    while kill -0 "$FIXTURE_PID" 2> /dev/null && ((waited < SHUTDOWN_TIMEOUT_TENTHS)); do
        sleep 0.1
        waited=$((waited + 1))
    done
    if kill -0 "$FIXTURE_PID" 2> /dev/null; then
        echo "The test server did not stop when its input closed; killing it." >&2
        kill "$FIXTURE_PID" 2> /dev/null || true
        sleep 1
        kill -9 "$FIXTURE_PID" 2> /dev/null || true
    fi
    wait "$FIXTURE_PID" 2> /dev/null || true
}
trap stop_fixture EXIT

echo "==> Starting the test server (snap underlay, control port $CONTROL_PORT)"
"$FIXTURE_BINARY" \
    --underlay snap \
    --advertise-ip "$FIXTURE_HOST" \
    --control-port "$CONTROL_PORT" \
    < "$FIXTURE_STDIN" > "$LOG_DIR/fixture-info.json" 2> "$FIXTURE_LOG" &
FIXTURE_PID=$!
exec 9> "$FIXTURE_STDIN"

echo "==> Waiting for the topology"
for _ in $(seq 1 120); do
    if ! kill -0 "$FIXTURE_PID" 2> /dev/null; then
        echo "The test server exited. Its output is in $FIXTURE_LOG" >&2
        exit 1
    fi
    if curl -sf "http://127.0.0.1:$CONTROL_PORT/info" > /dev/null; then
        break
    fi
    sleep 1
done
if ! curl -sf "http://127.0.0.1:$CONTROL_PORT/info" > /dev/null; then
    echo "The test server did not come up. Its output is in $FIXTURE_LOG" >&2
    exit 1
fi
echo "    advertised to the emulator at $FIXTURE_HOST, control API on port $CONTROL_PORT"

echo "==> Running the instrumented tests"
GRADLE_ARGS=(
    ":scion-http3-android:emulatorX64DebugAndroidTest"
    "-PskipNativeCheck"
    "-PfixtureHost=$FIXTURE_HOST"
    "-PfixtureControlPort=$CONTROL_PORT"
)
if [[ $# -gt 0 ]]; then
    GRADLE_ARGS+=("-Pandroid.testInstrumentationRunnerArguments.class=$(
        printf 'com.anapaya.scion.http3.e2e.%s,' "$@" | sed 's/,$//'
    )")
fi
(cd "$ANDROID_DIR" && ./gradlew "${GRADLE_ARGS[@]}")
