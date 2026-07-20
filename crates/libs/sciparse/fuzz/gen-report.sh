#!/bin/bash
set -e

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <fuzz_target>"
    exit 1
fi

# Assign the first argument to the fuzz_target variable
FUZZ_TARGET=$1

# Ensure necessary tools are installed
if ! command -v cargo &> /dev/null; then
    echo "cargo could not be found, please install Rust and Cargo."
    exit 1
fi

if ! command -v llvm-cov &> /dev/null; then
    echo "llvm-cov could not be found, please install LLVM."
    exit 1
fi

if ! command -v rustfilt &> /dev/null; then
    echo "rustfilt could not be found, please install rustfilt."
    exit 1
fi

# Run the cargo fuzz coverage command with the provided fuzz target
cargo +nightly fuzz coverage "$FUZZ_TARGET"

# Define the paths
TARGET_DIR="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release"
PROF_DATA="coverage/$FUZZ_TARGET/coverage.profdata"
OUTPUT_FILE="cov.lcov"

# Check if the coverage data file exists
if [ ! -f "$PROF_DATA" ]; then
    echo "Coverage data file $PROF_DATA not found."
    exit 1
fi

# Generate the coverage report in LCOV format
llvm-cov export "$TARGET_DIR/$FUZZ_TARGET" -Xdemangler=rustfilt \
                                         --ignore-filename-regex="\.cargo" \
                                         -instr-profile="$PROF_DATA" \
                                         --format=lcov \
                                         > "$OUTPUT_FILE"

# Generate an HTML report from the LCOV file
genhtml "$OUTPUT_FILE" -o report
