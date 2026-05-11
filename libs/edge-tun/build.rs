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

//! Build script to compile the protobuf definitions for the ng API.

use std::io::Result;

fn main() -> Result<()> {
    let out_dir = "src/ng/protobuf/generated";
    let proto_files = ["./protobuf/anapaya.edgetun.v1.proto"];
    let proto_include_paths = ["./protobuf"];

    let mut config = prost_build::Config::new();
    config
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir(out_dir)
        .include_file("mod.rs")
        .compile_protos(&proto_files, &proto_include_paths)
        .expect("failed to compile proto files");

    Ok(())
}
