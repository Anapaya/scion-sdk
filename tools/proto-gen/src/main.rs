// Copyright 2025 Anapaya Systems
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
// limitations under the License.'
//! A tool to compile all protobuf definitions to Rust code in this repository.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::Parser;

// Define the command-line interface using clap
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Compiles and updates the protobuf files in the source tree.
    Update,
    /// Checks if the generated protobuf files are up-to-date.
    Check,
}

// Define constants for source paths to avoid repetition
const SCION_PROTO_SRC_DIR: &str = "scion-proto/scion-protobuf/src/proto";
const ENDHOST_API_SRC_DIR: &str = "endhost-api/endhost-api-protobuf/src/proto";
const HSD_API_SRC_DIR: &str = "hsd-api/hsd-api-protobuf/src/proto";

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Update => run_update(),
        Commands::Check => run_check(),
    }
}

/// ## `update` subcommand logic
///
/// This function executes the original behavior: compiling protobufs
/// and writing the output directly into the source directories.
fn run_update() -> anyhow::Result<()> {
    println!("Updating generated protobuf files...");

    // Ensure output directories exist
    fs::create_dir_all(SCION_PROTO_SRC_DIR)?;
    fs::create_dir_all(ENDHOST_API_SRC_DIR)?;
    fs::create_dir_all(HSD_API_SRC_DIR)?;
    compile_scion_protobuf(SCION_PROTO_SRC_DIR)?;
    compile_endhost_api_protobuf(ENDHOST_API_SRC_DIR)?;
    compile_hsd_api_protobuf(HSD_API_SRC_DIR)?;

    println!("Protobuf files updated successfully.");
    Ok(())
}

/// ## `check` subcommand logic
///
/// This function compiles protobufs to a temporary directory and then
/// compares the generated files with the ones in the source tree.
fn run_check() -> anyhow::Result<()> {
    println!("Checking if generated protobuf files are up-to-date...");

    // Create a temporary directory for the generated files
    let temp_dir = tempfile::Builder::new()
        .prefix("proto-gen-check-")
        .tempdir()?;
    let temp_dir_path = temp_dir.path();

    let temp_scion_dir = temp_dir_path.join("scion");
    let temp_endhost_dir = temp_dir_path.join("endhost");
    let temp_hsd_dir = temp_dir_path.join("hsd");

    fs::create_dir_all(&temp_scion_dir)?;
    fs::create_dir_all(&temp_endhost_dir)?;
    fs::create_dir_all(&temp_hsd_dir)?;

    // Compile protos into the temporary directories
    compile_scion_protobuf(temp_scion_dir.to_str().unwrap())?;
    compile_endhost_api_protobuf(temp_endhost_dir.to_str().unwrap())?;
    compile_hsd_api_protobuf(temp_hsd_dir.to_str().unwrap())?;

    // Compare the generated files with the source files
    let scion_diffs = compare_dirs(&temp_scion_dir, Path::new(SCION_PROTO_SRC_DIR))?;
    let endhost_diffs = compare_dirs(&temp_endhost_dir, Path::new(ENDHOST_API_SRC_DIR))?;
    let hsd_diffs = compare_dirs(&temp_hsd_dir, Path::new(HSD_API_SRC_DIR))?;

    let all_diffs: Vec<_> = scion_diffs
        .into_iter()
        .chain(endhost_diffs)
        .chain(hsd_diffs)
        .collect();

    if all_diffs.is_empty() {
        println!("Protobuf files are up-to-date.");
        Ok(())
    } else {
        println!("Found differences in the following generated files:");
        for file in &all_diffs {
            println!("  - {}", file.display());
        }
        bail!(
            "Generated protobuf files are out of date. Please run the update command:\n. cargo run -p proto-gen -- update"
        )
    }
}

/// Compares two directories and returns a list of paths that are different.
/// A file is considered different if it exists in one directory but not the other,
/// or if the contents do not match.
fn compare_dirs(gen_dir: &Path, src_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut differences = HashSet::new();

    // Check for new/modified files by iterating through the generated directory
    for entry in walkdir::WalkDir::new(gen_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let gen_path = entry.path();
        let relative_path = gen_path.strip_prefix(gen_dir)?;
        let src_path = src_dir.join(relative_path);

        let gen_content = fs::read(gen_path)?;
        let src_content = fs::read(&src_path).unwrap_or_default(); // Read or get empty vec if not found

        if gen_content != src_content {
            differences.insert(src_path.to_path_buf());
        }
    }

    // Check for deleted files by iterating through the source directory
    if src_dir.exists() {
        for entry in walkdir::WalkDir::new(src_dir)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let src_path = entry.path();
            let relative_path = src_path.strip_prefix(src_dir)?;
            let gen_path = gen_dir.join(relative_path);

            if !gen_path.exists() {
                differences.insert(src_path.to_path_buf());
            }
        }
    }

    let mut sorted_diffs: Vec<_> = differences.into_iter().collect();
    sorted_diffs.sort();
    Ok(sorted_diffs)
}

fn compile_scion_protobuf(out_dir: &str) -> anyhow::Result<()> {
    let proto_root = "scion-proto/scion-protobuf/";
    let proto_files = get_proto_files(proto_root)?;
    tonic_prost_build::configure()
        .out_dir(out_dir)
        .compile_protos(&proto_files, &[proto_root.to_string()])
        .context("failed to compile scion-protobuf")?;
    Ok(())
}

fn compile_endhost_api_protobuf(out_dir: &str) -> anyhow::Result<()> {
    let proto_roots = [
        "endhost-api/endhost-api-protobuf/protobuf",
        "scion-proto/scion-protobuf",
    ];
    let proto_files = get_proto_files("endhost-api/endhost-api-protobuf/protobuf")?;
    let mut config = prost_build::Config::new();
    config
        .out_dir(out_dir)
        .protoc_arg("--experimental_allow_proto3_optional")
        .extern_path(
            ".proto.control_plane.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(
            ".proto.control_plane.experimental.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(".proto.crypto.v1", "scion_protobuf::crypto::v1")
        .compile_protos(&proto_files, &proto_roots)?;

    Ok(())
}

fn compile_hsd_api_protobuf(out_dir: &str) -> anyhow::Result<()> {
    let proto_roots = [
        "hsd-api/hsd-api-protobuf/protobuf",
        "scion-proto/scion-protobuf",
    ];
    let proto_files = get_proto_files("hsd-api/hsd-api-protobuf/protobuf")?;
    let mut config = prost_build::Config::new();
    config
        .out_dir(out_dir)
        .protoc_arg("--experimental_allow_proto3_optional")
        .extern_path(
            ".proto.control_plane.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(
            ".proto.control_plane.experimental.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(".proto.crypto.v1", "scion_protobuf::crypto::v1")
        .compile_protos(&proto_files, &proto_roots)?;

    Ok(())
}

fn get_proto_files(proto_root: &str) -> anyhow::Result<Vec<String>> {
    let mut proto_files: Vec<String> = walkdir::WalkDir::new(proto_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .map(|ext| ext == "proto")
                    .unwrap_or(false)
        })
        .map(|e| e.path().display().to_string())
        .collect();
    proto_files.sort();
    Ok(proto_files)
}
