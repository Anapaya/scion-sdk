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

//! Conversion implementations between protobuf and native types.

use crate::{
    EndhostApiGroup, EndhostApiInfo,
    proto::endhost::discovery::v1::{RpcEndhostApiGroup, RpcEndhostApiInfo},
};

// EndhostApiInfo

/// Errors that can occur when trying to convert RpcEndhostApiInfo to EndhostApiInfo.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum EndhostApiFromRpcError {
    /// The address field was empty.
    #[error("address field was empty")]
    MissingAddress,
    /// The address field contained an invalid URL.
    #[error("invalid address: {0}")]
    InvalidAddress(#[from] url::ParseError),
}

impl TryFrom<RpcEndhostApiInfo> for EndhostApiInfo {
    type Error = EndhostApiFromRpcError;

    fn try_from(value: RpcEndhostApiInfo) -> Result<Self, Self::Error> {
        if value.address.is_empty() {
            return Err(EndhostApiFromRpcError::MissingAddress);
        }

        let address = value.address.parse()?;

        Ok(EndhostApiInfo { address })
    }
}

impl From<EndhostApiInfo> for RpcEndhostApiInfo {
    fn from(value: EndhostApiInfo) -> Self {
        RpcEndhostApiInfo {
            address: value.address.to_string(),
        }
    }
}

// EndhostApiGroup

impl TryFrom<RpcEndhostApiGroup> for EndhostApiGroup {
    type Error = EndhostApiFromRpcError;

    fn try_from(value: RpcEndhostApiGroup) -> Result<Self, Self::Error> {
        let mut apis = Vec::with_capacity(value.apis.len());
        for rpc_api in value.apis {
            apis.push(rpc_api.try_into()?);
        }

        Ok(EndhostApiGroup { apis })
    }
}

impl From<EndhostApiGroup> for RpcEndhostApiGroup {
    fn from(value: EndhostApiGroup) -> Self {
        RpcEndhostApiGroup {
            apis: value
                .apis
                .into_iter()
                .map(RpcEndhostApiInfo::from)
                .collect(),
        }
    }
}
