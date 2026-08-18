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
    //
    // When depending on scion-protobuf, add as extern_includes.
    let scion_proto_externs = ExternIncludes {
        proto_dirs: vec!["crates/libs/scion-protobuf"],
        extern_paths: vec![(".proto", "scion_protobuf")],
    };

    let targets = vec![
        CompileConfig {
            name: "scion-protobuf",
            out_dir: "crates/libs/scion-protobuf/src/proto",
            proto_dirs: vec!["crates/libs/scion-protobuf/"],
            extern_includes: vec![],
            protoc_args: vec![],
            use_tonic: true,
            serde_packages: vec![],
        },
        CompileConfig {
            name: "endhost-api",
            out_dir: "crates/apis/endhost-api/endhost-api-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/endhost-api/endhost-api-protobuf/protobuf"],
            extern_includes: vec![scion_proto_externs.clone()],
            protoc_args: vec!["--experimental_allow_proto3_optional"],
            use_tonic: false,
            serde_packages: vec![],
        },
        CompileConfig {
            name: "endhost-api-discovery",
            out_dir: "crates/apis/anapaya-ead/anapaya-ead-models/src/proto/gen",
            proto_dirs: vec!["crates/apis/anapaya-ead/anapaya-ead-models/protobuf"],
            extern_includes: vec![],
            protoc_args: vec![],
            use_tonic: false,
            serde_packages: vec![".endhost.discovery.v1"],
        },
        CompileConfig {
            name: "hsd-api",
            out_dir: "crates/apis/anapaya-hsd-api/anapaya-hsd-api-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/anapaya-hsd-api/anapaya-hsd-api-protobuf/protobuf"],
            extern_includes: vec![scion_proto_externs.clone()],
            protoc_args: vec!["--experimental_allow_proto3_optional"],
            use_tonic: false,
            serde_packages: vec![],
        },
        CompileConfig {
            name: "anapaya-aa",
            out_dir: "crates/apis/anapaya-aa/anapaya-aa-protobuf/src/proto",
            proto_dirs: vec!["crates/apis/anapaya-aa/anapaya-aa-protobuf/protobuf"],
            extern_includes: vec![],
            protoc_args: vec![],
            use_tonic: false,
            serde_packages: vec![".anapaya.aa.v1"],
        },
        CompileConfig {
            name: "snap-control",
            out_dir: "crates/snap/snap-control/src/proto",
            proto_dirs: vec!["crates/snap/snap-control/protobuf"],
            extern_includes: vec![],
            protoc_args: vec![],
            use_tonic: false,
            serde_packages: vec![],
        },
        CompileConfig {
            name: "edge-tun",
            out_dir: "crates/libs/anapaya-edge-tun/src/proto",
            proto_dirs: vec!["crates/libs/anapaya-edge-tun/protobuf"],
            extern_includes: vec![],
            protoc_args: vec![],
            use_tonic: false,
            serde_packages: vec![],
        },
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
        fs::create_dir_all(target.out_dir)?;
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

struct CompileConfig {
    /// Name of the target being compiled (for logging purposes)
    name: &'static str,
    /// Output directory for generated files
    out_dir: &'static str,
    /// Root directories containing .proto files
    ///
    /// The directories will be searched recursively to find all .proto files.
    proto_dirs: Vec<&'static str>,
    /// External includes and their Rust module mappings
    ///
    /// Allows reusing existing generated code instead of generating new code.
    extern_includes: Vec<ExternIncludes>,
    /// Additional arguments to pass to protoc
    protoc_args: Vec<&'static str>,
    /// If true, use tonic to generate gRPC service code.
    /// If false, use prost to generate only message code.
    use_tonic: bool,
    /// Which messages additionally get canonical protobuf-JSON serde impls, so
    /// that the service can also be called with the Connect JSON codec. Empty
    /// disables it.
    ///
    /// Each entry is matched as a prefix of a message's fully-qualified proto
    /// name, so `".anapaya.aa.v1"` selects every message in that package, and
    /// `""` would select all of them. Entries name proto packages, not Rust
    /// modules or crates.
    ///
    /// Output goes to one `<proto.package>.serde.rs` per package, alongside the
    /// prost `<proto.package>.rs`; the crate must `include!` both.
    ///
    /// Enable this for services reachable from a web browser, which cannot
    /// encode protobuf without a codec of its own. The impls follow the proto3
    /// JSON mapping, so `bytes` become base64 strings and 64-bit integers become
    /// strings, rather than the byte arrays and lossy numbers a plain serde
    /// derive would emit.
    ///
    /// A crate enabling this needs a `serde` dependency, and additionally
    /// `pbjson` once any of its messages has a numeric, `bytes`, or enum field —
    /// those are the ones whose generated code calls pbjson's helpers.
    serde_packages: Vec<&'static str>,
}

#[derive(Clone)]
struct ExternIncludes {
    /// Root directories containing external .proto files
    proto_dirs: Vec<&'static str>,
    /// Generate external type mappings.
    /// (proto package, Rust module path)
    ///
    /// E.g., (".proto.control_plane.v1", "scion_protobuf::control_plane::v1")
    ///
    /// Allows reusing existing generated code instead of regenerating.
    extern_paths: Vec<(&'static str, &'static str)>,
}

impl CompileConfig {
    /// Generates the protobuf files into the specified output directory.
    ///
    /// Will overwrite existing files.
    pub fn generate(&self) -> anyhow::Result<()> {
        self.compile(self.out_dir)
    }

    /// Checks if the generated files are up-to-date without writing them.
    ///
    /// If they are not up-to-date, returns a list of differing files.
    pub fn check(&self) -> anyhow::Result<Vec<PathBuf>> {
        let tmp_dir = tempfile::Builder::new()
            .prefix("proto-gen-check-")
            .tempdir()?;

        let tmp_dir_path = tmp_dir.path();
        let tmp_dir_str = tmp_dir_path
            .to_str()
            .context("failed to convert temp dir path to str")?;

        self.compile(tmp_dir_str)?;

        // Compare generated files with existing ones
        let diffs = compare_dirs(tmp_dir_path, Path::new(self.out_dir))?;

        Ok(diffs)
    }

    /// Compiles the protobuf files into the specified output directory.
    ///
    /// Uses prost_build, generating only messages.
    fn compile(&self, out_dir: &str) -> anyhow::Result<()> {
        let (mut config, include_dirs, proto_files) = self.prost_config(out_dir)?;

        fs::create_dir_all(out_dir)
            .with_context(|| format!("failed to create output directory {}", out_dir))?;

        if self.serde_packages.is_empty() {
            config
                .compile_protos(&proto_files, &include_dirs)
                .with_context(|| format!("failed to compile {}", self.name))?;
            return Ok(());
        }

        // pbjson-build works from a descriptor set, which prost_build can emit
        // as a side effect. Keep it in a temp dir: `out_dir` is a checked-in
        // source directory, and `check` diffs it against generated output.
        let descriptor_dir = tempfile::Builder::new()
            .prefix("proto-gen-descriptor-")
            .tempdir()?;
        let descriptor_path = descriptor_dir.path().join("descriptor.bin");

        config
            .file_descriptor_set_path(&descriptor_path)
            .compile_protos(&proto_files, &include_dirs)
            .with_context(|| format!("failed to compile {}", self.name))?;

        let descriptor = fs::read(&descriptor_path)
            .with_context(|| format!("failed to read descriptor set for {}", self.name))?;

        pbjson_build::Builder::new()
            .register_descriptors(&descriptor)
            .with_context(|| format!("failed to register descriptors for {}", self.name))?
            .out_dir(out_dir)
            // Skip unknown fields instead of failing, matching both the
            // protobuf codec and connect-go's JSON codec. Without this a client
            // that sends a field the server does not know yet gets a 400.
            // `ignore_unknown_enum_variants` is the same knob for enum values,
            // needed once any message here gains an enum field.
            .ignore_unknown_fields()
            .build(&self.serde_packages)
            .with_context(|| format!("failed to generate serde impls for {}", self.name))?;

        Ok(())
    }

    /// Compiles the protobuf files into the specified output directory.
    ///
    /// Uses prost_build, generating only message code without gRPC services.
    ///
    /// Returns
    /// (Config, include, proto_files)
    fn prost_config(
        &self,
        out_dir: &str,
    ) -> anyhow::Result<(prost_build::Config, Vec<String>, Vec<String>)> {
        let mut proto_files = Vec::new();
        let mut include_dirs = Vec::new();

        // Gather all .proto files from the specified root directories
        for proto_root in &self.proto_dirs {
            let files = get_proto_files(proto_root)?;
            proto_files.extend(files);
            include_dirs.push(proto_root.to_string());
        }

        // Configure and run the prost_build compiler
        let mut config = prost_build::Config::new();
        config.out_dir(out_dir);

        for arg in &self.protoc_args {
            config.protoc_arg(arg);
        }

        // Set up extern includes
        for ext in &self.extern_includes {
            // Gather extern .proto files
            for proto_root in &ext.proto_dirs {
                include_dirs.push(proto_root.to_string());
            }
            // Set extern path mappings
            for (proto_pkg, rust_mod) in &ext.extern_paths {
                config.extern_path(proto_pkg.to_string(), rust_mod.to_string());
            }
        }

        // If using tonic, set up the service generator
        // Tonic uses prost under the hood, and inserts itself as service generator.
        // So we can just get the tonic service generator and set it here.
        if self.use_tonic {
            let svc_gen = tonic_prost_build::configure().service_generator();
            config.service_generator(svc_gen);
        }

        Ok((config, include_dirs, proto_files))
    }
}

/// Recursively collects all .proto files from the specified root directory.
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
