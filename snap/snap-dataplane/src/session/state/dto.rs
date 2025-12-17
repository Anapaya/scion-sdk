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
//! Data transfer objects (DTOs) for SNAP data plane session state.

use std::{
    collections::BTreeMap,
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

use scion_sdk_common_types::ed25519::Ed25519SigningKeyPem;
use serde::{Deserialize, Serialize};
use snap_tokens::Pssid;
use utoipa::ToSchema;

use crate::{
    session::state::{Session, SessionId, SessionManagerState, SessionTokenIssuerState},
    state::Hostname,
};

/// The session manager state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SessionManagerStateDto {
    /// The maximum duration of a session.
    pub session_duration: Duration,
    /// List of existing sessions.
    pub sessions: Vec<SessionDto>,
}

impl From<&SessionManagerState> for SessionManagerStateDto {
    fn from(value: &SessionManagerState) -> Self {
        Self {
            session_duration: value.session_duration,
            sessions: value
                .sessions
                .iter()
                .map(|(session_id, session)| {
                    SessionDto {
                        session_id: SessionIdDto {
                            pssid: session_id.pssid.0.to_string(),
                            hostname: session_id.hostname.clone(),
                        },
                        expiry: session.expiry.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    }
                })
                .collect(),
        }
    }
}

impl TryFrom<SessionManagerStateDto> for SessionManagerState {
    type Error = std::io::Error;

    fn try_from(value: SessionManagerStateDto) -> Result<Self, Self::Error> {
        let sessions: BTreeMap<SessionId, Session> = value
            .sessions
            .into_iter()
            .map(|session| {
                Pssid::from_str(&session.session_id.pssid).map(|pssid| {
                    let session_id = SessionId::new(pssid, session.session_id.hostname);
                    let expiry = UNIX_EPOCH + Duration::from_secs(session.expiry);
                    (session_id, Session::new(expiry))
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(SessionManagerState {
            session_duration: value.session_duration,
            sessions,
        })
    }
}

/// Data plane session.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SessionDto {
    /// The ID of the session.
    pub session_id: SessionIdDto,
    /// The expiry time of the session represented as a Unix timestamp.
    pub expiry: u64,
}

/// Session ID.
#[derive(Debug, Ord, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Clone, ToSchema)]
pub struct SessionIdDto {
    /// The pseudo SCION subscriber identity (PSSID).
    pub pssid: String,
    /// The hostname of the data plane.
    pub hostname: Hostname,
}

/// Session token issuer state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SessionTokenIssuerStateDto {
    /// The encoding key (PEM format) used to issue session tokens.
    pub key: String,
}
impl From<&SessionTokenIssuerState> for SessionTokenIssuerStateDto {
    fn from(value: &SessionTokenIssuerState) -> Self {
        Self {
            key: value.key.warning_to_private_key_pem(),
        }
    }
}

impl TryFrom<SessionTokenIssuerStateDto> for SessionTokenIssuerState {
    type Error = std::io::Error;

    fn try_from(value: SessionTokenIssuerStateDto) -> Result<Self, Self::Error> {
        let key = Ed25519SigningKeyPem::from_str(&value.key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(SessionTokenIssuerState { key })
    }
}
