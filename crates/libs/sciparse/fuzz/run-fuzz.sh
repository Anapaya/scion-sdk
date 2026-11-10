#!/bin/bash

# Usage: ./run-fuzz.sh [target] [-- <libFuzzer flags>]
#
# Without a target, the script runs every target of `cargo fuzz list` in parallel, one process per
# target. Ctrl-C stops all of them.
#
# Example: ./run-fuzz.sh packet_encoding -- -max_total_time=60

set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -gt 0 && $1 != "--" ]]; then
    target=$1
    shift
    exec cargo +nightly fuzz run "$target" -c -O "$@"
fi

trap 'kill 0' INT TERM
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run "$target" -c -O "$@" &
done
wait
