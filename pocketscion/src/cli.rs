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
//! PocketSCION CLI options.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use scion_sdk_observability::{LogFormat, LogOutput};

use crate::runtime::DEFAULT_MGMT_PORT;

/// PocketSCION
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Top-level subcommand
    #[command(subcommand)]
    pub command: Commands,

    /// Logging options
    #[command(flatten)]
    pub logging: LoggingOptions,

    /// Management API options
    #[command(flatten)]
    pub management: ManagementOptions,
}

/// Management API options.
#[derive(Debug, Args)]
pub struct ManagementOptions {
    /// The port for the management API to listen on (e.g. 9000).
    #[arg(long, global = true, default_value_t = DEFAULT_MGMT_PORT)]
    pub mgmt_port: u16,
}

/// Logging options.
#[derive(Debug, Args)]
pub struct LoggingOptions {
    /// Log output level.
    #[arg(long, global = true, default_value_t = DEFAULT_LOG_OUTPUT)]
    pub output: LogOutput,
    /// Log output format.
    #[arg(long, global = true, default_value_t = DEFAULT_LOG_FORMAT)]
    pub format: LogFormat,
}

/// Default log putput.
pub const DEFAULT_LOG_OUTPUT: LogOutput = LogOutput::Stderr;

/// Default log output format.
pub const DEFAULT_LOG_FORMAT: LogFormat = LogFormat::Json;

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start PocketSCION.
    Run {
        /// The file to optionally load the system state from.
        #[arg(long)]
        state_file: Option<PathBuf>,

        /// The file to optionally load the I/O state from.
        #[arg(long)]
        io_config_file: Option<PathBuf>,

        /// Sets the start time to the UNIX EPOCH plus the number of seconds
        /// specified.
        #[arg(long)]
        start_time_sec: Option<u64>,

        /// Specifies the nanoseconds of the start time.
        ///
        /// Ignored if `start_time_sec` is not specified. This is primarily to
        /// ensure consistency between in-memory and subprocess runtime.
        #[arg(long, hide = true)]
        start_time_subsec: Option<u32>,
    },
}
