#!/usr/bin/env bash
# Copyright 2026 Anapaya Systems
#
# Runs the instrumented tests of every module on an Android emulator. The script creates the AVD,
# starts the emulator, runs connectedAndroidTest, and stops the emulator.
#
# Usage, in the dev shell or with emulator, avdmanager, and adb on the PATH:
#
#   ./tools/emulator-test.sh
#
# On Linux, the emulator needs KVM. The logcat goes to build/emulator/logcat.txt.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/build/emulator"
AVD_NAME="ktor-scion"
API_LEVEL="${API_LEVEL:-36}"
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-600}"

case "$(uname -m)" in
x86_64) ABI="x86_64" ;;
arm64 | aarch64) ABI="arm64-v8a" ;;
*)
    echo "No emulator image for $(uname -m)." >&2
    exit 1
    ;;
esac

mkdir -p "$LOG_DIR"

if ! emulator -list-avds | grep -qx "$AVD_NAME"; then
    echo "==> Creating the AVD $AVD_NAME"
    echo no | avdmanager create avd -n "$AVD_NAME" -k "system-images;android-$API_LEVEL;google_apis;$ABI"
fi

stop_emulator() {
    adb logcat -d > "$LOG_DIR/logcat.txt" 2> /dev/null || true
    adb emu kill > /dev/null 2>&1 || true
    if [[ -n "${EMULATOR_PID:-}" ]]; then
        for _ in $(seq 1 30); do
            kill -0 "$EMULATOR_PID" 2> /dev/null || break
            sleep 1
        done
        kill -9 "$EMULATOR_PID" 2> /dev/null || true
    fi
}
trap stop_emulator EXIT

echo "==> Starting the emulator"
emulator -avd "$AVD_NAME" -no-window -no-audio -no-snapshot -no-boot-anim \
    -gpu swiftshader_indirect > "$LOG_DIR/emulator.txt" 2>&1 &
EMULATOR_PID=$!

echo "==> Waiting for the boot"
deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
until [[ "$(adb shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" == "1" ]]; do
    if ! kill -0 "$EMULATOR_PID" 2> /dev/null; then
        echo "The emulator exited. Its output is in $LOG_DIR/emulator.txt" >&2
        exit 1
    fi
    if ((SECONDS > deadline)); then
        echo "The emulator did not boot in $BOOT_TIMEOUT_SECONDS s." >&2
        exit 1
    fi
    sleep 5
done
adb logcat -c

echo "==> Running the instrumented tests"
(cd "$ROOT_DIR" && ./gradlew --no-daemon --continue connectedAndroidTest -Pscion.androidAbis="$ABI")
