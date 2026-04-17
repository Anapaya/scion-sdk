#!/usr/bin/env bash

set -eo pipefail

# License header check exceptions (paths to exclude)
EXCEPTIONS=(
    "src/proto/"          # Generated protobuf files
    "/protobuf/generated/" # Generated protobuf files
    # Add more exceptions here as needed
)

# Get current year
CURRENT_YEAR=$(date +%Y)

# Expected license header template
LICENSE_HEADER="// Copyright $CURRENT_YEAR Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License."

function check_license_header {
    local target_dir=$1

    echo "==> Checking license headers"

    # Use git ls-files to respect .gitignore, filter for .rs files, and exclude exceptions
    local rust_files
    rust_files=$(git ls-files "$target_dir" | grep '\.rs$' || true)

    # Apply exceptions
    for exception in "${EXCEPTIONS[@]}"; do
        rust_files=$(echo "$rust_files" | grep -v "$exception" || true)
    done

    if [ -z "$rust_files" ]; then
        echo "No Rust files found"
        return 0
    fi

    # Check each file for the license header
    local missing_files=()

    while IFS= read -r file; do
        if [ -n "$file" ]; then
            # Check if file contains Apache License header with any year (quietly)
            if ! head -n 14 "$file" 2>/dev/null | grep -q "Copyright [0-9]\{4\} Anapaya Systems" || \
               ! head -n 14 "$file" 2>/dev/null | grep -q "Licensed under the Apache License"; then
                missing_files+=("$file")
            fi
        fi
    done <<< "$rust_files"

    if [ ${#missing_files[@]} -eq 0 ]; then
        echo "✓ All files have the license header"
        return 0
    else
        cat <<EOF
✗ The following files are missing the license header:

Expected license header:
========================
$LICENSE_HEADER
========================

Files missing the header:
$(for file in "${missing_files[@]}"; do echo "  - $file"; done)

Run the following command to automatically add the license headers:

/endhost/public/license_header.sh fix

EOF
        return 1
    fi
}

function fix_license_header {
    local target_dir=$1

    echo "==> Fixing license headers"

    # Use git ls-files to respect .gitignore, filter for .rs files, and exclude exceptions
    local rust_files
    rust_files=$(git ls-files "$target_dir" | grep '\.rs$' || true)

    # Apply exceptions
    for exception in "${EXCEPTIONS[@]}"; do
        rust_files=$(echo "$rust_files" | grep -v "$exception" || true)
    done

    if [ -z "$rust_files" ]; then
        echo "No Rust files found"
        return 0
    fi

    # Find files missing the license header
    local missing_files=()

    while IFS= read -r file; do
        if [ -n "$file" ]; then
            # Check if file contains Apache License header with any year (quietly)
            if ! head -n 14 "$file" 2>/dev/null | grep -q "Copyright [0-9]\{4\} Anapaya Systems" || \
               ! head -n 14 "$file" 2>/dev/null | grep -q "Licensed under the Apache License"; then
                missing_files+=("$file")
            fi
        fi
    done <<< "$rust_files"

    if [ ${#missing_files[@]} -eq 0 ]; then
        echo "✓ All files already have the license header"
        return 0
    fi

    # Add license header to each missing file
    local fixed_count=0

    for file in "${missing_files[@]}"; do
        echo "Adding license header to: $file"

        # Create a temporary file with the license header + original content
        local temp_file=$(mktemp)
        echo "$LICENSE_HEADER" > "$temp_file"
        echo "" >> "$temp_file"
        cat "$file" >> "$temp_file"

        # Replace the original file
        mv "$temp_file" "$file"
        ((fixed_count++))
    done

    echo "✓ Added license header to $fixed_count files"
}

if [ "$1" == "check" ]; then
    check_license_header "."
elif [ "$1" == "fix" ]; then
    fix_license_header "."
else
    cat <<EOF
Usage: $0 <command>

Commands:
  check    Check for missing license headers
  fix      Add license headers to files that don't have them

EOF
    exit 1
fi
