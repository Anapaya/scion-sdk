#!/usr/bin/env bash
# Copyright 2026 Anapaya Systems
#
# Runs the Swift tests on an iOS simulator.
#
# It starts the test server on this machine, boots a simulator, runs the tests in it, and stops the
# server again however the run ends. A test in the simulator cannot start a process, so the server
# is started here and the tests find it through its control API.
#
# Usage:
#
#   ./e2e.sh                           everything
#   ./e2e.sh FacadeCancellationTests   only the test classes named
#
# Needs Xcode with an iOS simulator runtime, the XCFramework and the generated bindings in the
# package (apple.py xcframework writes both), and cargo unless SCION_H3_TEST_SERVER names a built
# server. See ../README.md.
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(dirname "$TOOLS_DIR")"
PACKAGE_DIR="$APPLE_DIR/scion-http3-swift"
PACKAGE_NAME="$(basename "$PACKAGE_DIR")"
WORKSPACE_DIR="$(cd "$APPLE_DIR/../.." && pwd)"

CONTROL_PORT="${FIXTURE_CONTROL_PORT:-7443}"
CONTROL_URL="http://127.0.0.1:$CONTROL_PORT"

# The test target that runs in the simulator.
TEST_TARGET="ScionHTTP3HostTests"

# A test that hangs fails on its own, well before a CI job's timeout.
TEST_TIME_ALLOWANCE_SECONDS=300

SHUTDOWN_TIMEOUT_TENTHS=100

LOG_DIR="${E2E_LOG_DIR:-$APPLE_DIR/build/e2e}"
FIXTURE_LOG="$LOG_DIR/fixture.log"
XCODEBUILD_LOG="$LOG_DIR/xcodebuild.log"
RESULT_BUNDLE="$LOG_DIR/Tests.xcresult"
DERIVED_DATA="${DERIVED_DATA:-$LOG_DIR/DerivedData}"

if [[ "$(uname -s)" != Darwin ]]; then
    echo "this runs on macOS with Xcode only" >&2
    exit 1
fi

if [[ ! -d "$PACKAGE_DIR/ScionHTTP3UniffiFFI.xcframework" ]] ||
    ! compgen -G "$PACKAGE_DIR/Sources/ScionHTTP3Uniffi/*.swift" > /dev/null; then
    echo "The XCFramework or the generated bindings are missing from the package." >&2
    echo "Run ./bindings/apple/tools/apple.py xcframework from $WORKSPACE_DIR first." >&2
    exit 1
fi

if [[ -n "${SCION_H3_TEST_SERVER:-}" ]]; then
    FIXTURE_BINARY="$SCION_H3_TEST_SERVER"
else
    echo "==> Building the test server"
    cargo build --locked --release -p scion-h3-test-server --manifest-path "$WORKSPACE_DIR/Cargo.toml"
    FIXTURE_BINARY="$(
        cargo metadata --format-version 1 --no-deps --manifest-path "$WORKSPACE_DIR/Cargo.toml" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
    )/release/scion-h3-test-server"
fi

mkdir -p "$LOG_DIR"
# xcodebuild refuses to write a result bundle over one that exists.
rm -rf "$RESULT_BUNDLE"

echo "==> Choosing the scheme"
SCHEME="$(
    (cd "$PACKAGE_DIR" && xcodebuild -list -json 2> /dev/null) |
        python3 -c '
import json, sys

name = sys.argv[1]
schemes = json.load(sys.stdin).get("workspace", {}).get("schemes", [])
for candidate in (name + "-Package", name):
    if candidate in schemes:
        print(candidate)
        break
else:
    sys.exit(
        "neither %s-Package nor %s is a scheme; xcodebuild lists: %s"
        % (name, name, ", ".join(schemes)))
' "$PACKAGE_NAME"
)"
echo "    $SCHEME"

# The simulator: the one named in SIMULATOR_UDID else an iPhone on the newest iOS runtime.
choose_simulator() {
    xcrun simctl list devices -j | python3 -c '
import json, sys

wanted = sys.argv[1] if len(sys.argv) > 1 else None
best = None
for runtime, devices in json.load(sys.stdin)["devices"].items():
    # com.apple.CoreSimulator.SimRuntime.iOS-26-0
    if ".iOS-" not in runtime:
        continue
    version = tuple(int(part) for part in runtime.rsplit(".iOS-", 1)[1].split("-"))
    for device in devices:
        if wanted is not None:
            if device["udid"] == wanted:
                best = (version, device)
            continue
        if not device.get("isAvailable") or "iPhone" not in device["name"]:
            continue
        if best is None or version > best[0]:
            best = (version, device)
if best is None:
    if wanted is not None:
        sys.exit(f"no iOS simulator has the UDID {wanted}")
    sys.exit("no available iPhone simulator; install an iOS runtime in Xcode")
device = best[1]
print(device["udid"])
print(device["name"])
print(device["state"])
' ${SIMULATOR_UDID:+"$SIMULATOR_UDID"}
}

{
    read -r UDID
    read -r SIMULATOR_NAME
    read -r SIMULATOR_STATE
} < <(choose_simulator)

BOOTED_HERE=0
if [[ "$SIMULATOR_STATE" != Booted ]]; then
    BOOTED_HERE=1
fi

# The server stops when its standard input closes.
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

cleanup() {
    stop_fixture
    if [[ "$BOOTED_HERE" == 1 ]]; then
        xcrun simctl shutdown "$UDID" > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Booting $SIMULATOR_NAME ($UDID)"
SECONDS=0
xcrun simctl bootstatus "$UDID" -b > /dev/null
echo "    booted in ${SECONDS}s"

echo "==> Starting the test server (control port $CONTROL_PORT)"
"$FIXTURE_BINARY" \
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
    if curl -sf "$CONTROL_URL/info" > /dev/null; then
        break
    fi
    sleep 1
done
if ! curl -sf "$CONTROL_URL/info" > /dev/null; then
    echo "The test server did not come up. Its output is in $FIXTURE_LOG" >&2
    exit 1
fi

echo "==> Running the tests on $SIMULATOR_NAME"
XCODEBUILD_ARGS=(
    test
    -scheme "$SCHEME"
    -destination "platform=iOS Simulator,id=$UDID"
    -derivedDataPath "$DERIVED_DATA"
    -resultBundlePath "$RESULT_BUNDLE"
    # One server serves every test, and some tests restart it.
    -parallel-testing-enabled NO
    -test-timeouts-enabled YES
    -default-test-execution-time-allowance "$TEST_TIME_ALLOWANCE_SECONDS"
    CODE_SIGNING_ALLOWED=NO
)
# The host tests only.
if [[ $# -eq 0 ]]; then
    XCODEBUILD_ARGS+=("-only-testing:$TEST_TARGET")
fi
for class in "$@"; do
    XCODEBUILD_ARGS+=("-only-testing:$TEST_TARGET/$class")
done

# xcodebuild strips the TEST_RUNNER_ prefix and hands the rest to the test process.
set +e
(
    cd "$PACKAGE_DIR" &&
        TEST_RUNNER_SCION_H3_TEST_SERVER_CONTROL_URL="$CONTROL_URL" \
            xcodebuild "${XCODEBUILD_ARGS[@]}"
) 2>&1 | tee "$XCODEBUILD_LOG"
status=${PIPESTATUS[0]}
set -e

if [[ $status -ne 0 ]]; then
    echo "==> Collecting the facade's log from the simulator"
    xcrun simctl spawn "$UDID" log show --last 30m \
        --predicate 'subsystem == "net.anapaya.scion.http3"' \
        > "$LOG_DIR/simulator-facade.log" 2>&1 || true
    echo "The tests failed. The result bundle and the logs are in $LOG_DIR" >&2
    exit "$status"
fi
echo "==> Passed. The result bundle is at $RESULT_BUNDLE"
