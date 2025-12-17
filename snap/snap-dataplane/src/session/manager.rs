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
//! SNAP data plane session management.

use snap_tokens::Pssid;
use thiserror::Error;

use crate::{session::state::SessionGrant, state::Hostname};

/// TokenIssuer is the interface to issue session tokens.
pub trait TokenIssuer {
    /// Issues a session token for the given PSSID, data plane ID, and session grant.
    fn issue(
        &self,
        pssid: Pssid,
        hostname: Hostname,
        session_grant: SessionGrant,
    ) -> Result<String, SessionTokenError>;
}

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum SessionTokenError {
    /// JWT encoding error.
    #[error("decoding session token: {0:?}")]
    EncodingError(#[from] jsonwebtoken::errors::Error),
}
