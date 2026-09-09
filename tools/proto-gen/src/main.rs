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
// limitations under the License.
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Common extern paths for SCION protobufs
    let scion_proto_buffa_externs = ExternIncludes {
        proto_dirs: vec!["crates/libs/scion-protobuf"],
        extern_paths: vec![(".proto", "::scion_protobuf::proto")],
    };

    let targets = vec![
        BuffaCompileConfig {
            name: "scion-protobuf-buffa",
            // The SCION control plane services are reached over gRPC, which the connectrpc
            // clients speak; `segment-lister` uses the segment lookup client.
            generate_connectrpc: true,
            out_dir: "crates/libs/scion-protobuf/src/proto",
            proto_dirs: vec!["crates/libs/scion-protobuf/"],
            extern_includes: vec![],
        }
        .into(),
        BuffaCompileConfig {
            name: "endhost-api",
            generate_connectrpc: false,
            out_dir: "crates/apis/endhost-api/endhost-api-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/endhost-api/endhost-api-protobuf/protobuf"],
            extern_includes: vec![scion_proto_buffa_externs.clone()],
        }
        .into(),
        BuffaCompileConfig {
            name: "endhost-api-discovery",
            generate_connectrpc: false,
            out_dir: "crates/apis/anapaya-ead/anapaya-ead-models/src/proto",
            proto_dirs: vec!["crates/apis/anapaya-ead/anapaya-ead-models/protobuf"],
            extern_includes: vec![],
        }
        .into(),
        BuffaCompileConfig {
            name: "hsd-api",
            generate_connectrpc: false,
            out_dir: "crates/apis/anapaya-hsd-api/anapaya-hsd-api-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/anapaya-hsd-api/anapaya-hsd-api-protobuf/protobuf"],
            extern_includes: vec![scion_proto_buffa_externs.clone()],
        }
        .into(),
        BuffaCompileConfig {
            name: "anapaya-aa",
            generate_connectrpc: false,
            out_dir: "crates/apis/anapaya-aa/anapaya-aa-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/anapaya-aa/anapaya-aa-protobuf/protobuf"],
            extern_includes: vec![],
        }
        .into(),
        BuffaCompileConfig {
            name: "snap-control",
            generate_connectrpc: false,
            out_dir: "crates/snap/snap-control/src/proto",
            proto_dirs: vec!["crates/snap/snap-control/protobuf"],
            extern_includes: vec![scion_proto_buffa_externs.clone()],
        }
        .into(),
        BuffaCompileConfig {
            name: "edge-tun",
            generate_connectrpc: false,
            out_dir: "crates/libs/anapaya-edge-tun/src/proto",
            proto_dirs: vec!["crates/libs/anapaya-edge-tun/protobuf"],
            extern_includes: vec![],
        }
        .into(),
    ];

    match cli.command {
        Commands::Update => run_update(targets),
        Commands::Check => run_check(targets),
    }
}

/// ## `update` subcommand logic
///
/// This function executes the original behavior: compiling protobufs
/// and writing the output directly into the source directories.
fn run_update(targets: Vec<CompileConfig>) -> anyhow::Result<()> {
    println!("Updating generated protobuf files...");

    // Ensure output directories exist
    for target in &targets {
        fs::create_dir_all(target.out_dir())?;
    }

    // clean output directories before generating new files
    for target in &targets {
        let out_dir = Path::new(target.out_dir());

        if out_dir.exists() {
            fs::remove_dir_all(out_dir)?;
        }
    }

    for target in &targets {
        target.generate()?;
    }

    println!("Protobuf files updated successfully.");
    Ok(())
}

/// ## `check` subcommand logic
///
/// This function compiles protobufs to a temporary directory and then
/// compares the generated files with the ones in the source tree.
fn run_check(targets: Vec<CompileConfig>) -> anyhow::Result<()> {
    println!("Checking if generated protobuf files are up-to-date...");

    let mut all_diffs = Vec::new();

    for target in &targets {
        let diffs = target.check()?;
        all_diffs.extend(diffs);
    }

    if all_diffs.is_empty() {
        println!("Protobuf files are up-to-date.");
    } else {
        println!("Found differences in the following generated files:");
        for file in &all_diffs {
            println!("  - {}", file.display());
        }

        bail!(
            "Generated protobuf files are out of date. Please run the update command:\n. cargo run -p proto-gen -- update"
        )
    }

    Ok(())
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

enum CompileConfig {
    Buffa(BuffaCompileConfig),
}
impl From<BuffaCompileConfig> for CompileConfig {
    fn from(config: BuffaCompileConfig) -> Self {
        CompileConfig::Buffa(config)
    }
}

impl CompileConfig {
    fn out_dir(&self) -> &str {
        match self {
            CompileConfig::Buffa(config) => config.out_dir,
        }
    }

    fn generate(&self) -> anyhow::Result<()> {
        match self {
            CompileConfig::Buffa(config) => config.compile(config.out_dir),
        }
    }

    fn check(&self) -> anyhow::Result<Vec<PathBuf>> {
        let tmp_dir = tempfile::Builder::new()
            .prefix("proto-gen-check-")
            .tempdir()?;

        let tmp_dir_path = tmp_dir.path();
        let tmp_dir_str = tmp_dir_path
            .to_str()
            .context("failed to convert temp dir path to str")?;

        // Compare generated files with existing ones
        match self {
            CompileConfig::Buffa(config) => config.compile(tmp_dir_str)?,
        }

        // Compare generated files with existing ones
        let diffs = compare_dirs(tmp_dir_path, Path::new(self.out_dir()))?;

        Ok(diffs)
    }
}

struct BuffaCompileConfig {
    /// Name of the target being compiled (for logging purposes)
    name: &'static str,
    /// Output directory for generated files
    out_dir: &'static str,
    /// Whether to generate connectrpc service files in addition to the protobuf messages.
    generate_connectrpc: bool,
    /// Root directories containing .proto files
    ///
    /// The directories will be searched recursively to find all .proto files.
    proto_dirs: Vec<&'static str>,
    /// External includes and their Rust module mappings
    ///
    /// Allows reusing existing generated code instead of generating new code.
    extern_includes: Vec<ExternIncludes>,
}

impl BuffaCompileConfig {
    pub fn compile(&self, out_dir: &str) -> anyhow::Result<()> {
        fs::create_dir_all(out_dir)
            .with_context(|| format!("failed to create output directory {}", out_dir))?;

        match self.generate_connectrpc {
            true => {
                self.connectrpc_config(out_dir)?
                    .compile()
                    .map_err(|err| anyhow::anyhow!("failed to compile {}: {err}", self.name))?;
            }
            false => {
                self.buffa_config(out_dir)?
                    .compile()
                    .map_err(|err| anyhow::anyhow!("failed to compile {}: {err}", self.name))?;
            }
        }

        Ok(())
    }

    fn connectrpc_config(&self, out_dir: &str) -> anyhow::Result<connectrpc_build::Config> {
        let mut proto_files = Vec::new();
        let mut include_dirs = Vec::new();

        // Gather all .proto files from the specified root directories
        for proto_root in &self.proto_dirs {
            let files = get_files_with_extension(proto_root, "proto")?;
            proto_files.extend(files);
            include_dirs.push(proto_root.to_string());
        }

        let mut buffa_config = connectrpc_build::CodeGenConfig::default();
        buffa_config
            .map_fields
            .push((".".to_string(), buffa_build::MapRepr::BTreeMap));
        buffa_config.preserve_unknown_fields = false;

        // Set up extern includes
        for ext in &self.extern_includes {
            for proto_root in &ext.proto_dirs {
                include_dirs.push(proto_root.to_string());
            }

            // Set extern path mappings
            for (proto_pkg, rust_mod) in &ext.extern_paths {
                buffa_config
                    .extern_paths
                    .push((proto_pkg.to_string(), rust_mod.to_string()));
            }
        }

        // Configure and run the buffa_build compiler
        let config = connectrpc_build::Config::new()
            .buffa_config(buffa_config)
            .files(&proto_files)
            .out_dir(out_dir)
            .generate_json(true)
            .includes(&include_dirs)
            .emit_rerun_directives(false)
            .include_file("mod.rs");

        Ok(config)
    }

    fn buffa_config(&self, out_dir: &str) -> anyhow::Result<buffa_build::Config> {
        let mut proto_files = Vec::new();
        let mut include_dirs = Vec::new();

        // Gather all .proto files from the specified root directories
        for proto_root in &self.proto_dirs {
            let files = get_files_with_extension(proto_root, "proto")?;
            proto_files.extend(files);
            include_dirs.push(proto_root.to_string());
        }

        // Configure and run the buffa_build compiler
        let mut config = buffa_build::Config::new()
            .files(&proto_files)
            .out_dir(out_dir)
            .map_type(buffa_build::MapRepr::BTreeMap)
            .generate_json(true)
            .preserve_unknown_fields(false)
            .include_file("mod.rs");

        // Set up extern includes
        for ext in &self.extern_includes {
            for proto_root in &ext.proto_dirs {
                include_dirs.push(proto_root.to_string());
            }

            // Set extern path mappings
            for (proto_pkg, rust_mod) in &ext.extern_paths {
                config = config.extern_path(proto_pkg.to_string(), rust_mod.to_string());
            }
        }

        config = config.includes(&include_dirs);

        Ok(config)
    }
}

#[derive(Clone)]
struct ExternIncludes {
    /// Root directories containing external .proto files
    proto_dirs: Vec<&'static str>,
    /// Generate external type mappings.
    /// (proto package, Rust module path)
    ///
    /// E.g., (".proto.control_plane.v1", "scion_protobuf::proto::control_plane::v1")
    ///
    /// Allows reusing existing generated code instead of regenerating.
    extern_paths: Vec<(&'static str, &'static str)>,
}

/// Recursively collects all files from the specified root directory with the given extension.
fn get_files_with_extension(
    proto_root: &str,
    filter_extension: &str,
) -> anyhow::Result<Vec<String>> {
    let mut proto_files: Vec<String> = walkdir::WalkDir::new(proto_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .map(|ext| ext == filter_extension)
                    .unwrap_or(false)
        })
        .map(|e| e.path().display().to_string())
        .collect();

    proto_files.sort();

    Ok(proto_files)
}
