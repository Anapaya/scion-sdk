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

//! PocketSCION Authorization Server.

use std::{net::SocketAddr, time::Duration};

use pem::Pem;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    comp::authorization_server::{
        api::{TokenRequest, TokenResponse},
        token_exchanger::{
            PsTokenExchangeConfig, PsTokenExchanger, TokenExchange, TokenExchangeError,
        },
    },
    state::PocketScionState,
};

pub mod api;
pub mod client;
pub mod fake_idp;
pub mod token_exchanger;

/// State of the authorization server.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema, PartialEq)]
pub struct AuthServerState {
    token_exchanger: PsTokenExchanger,
}

/// Handle to interact with the authorization server.
#[derive(Clone)]
pub struct AuthorizationServerHandle {
    system_state: PocketScionState,
}

impl TokenExchange for AuthorizationServerHandle {
    fn exchange(&mut self, req: TokenRequest) -> Result<TokenResponse, TokenExchangeError> {
        let mut sstate = self.system_state.write();
        sstate
            .auth_server
            .as_mut()
            .expect("Auth server not found")
            .token_exchanger
            .exchange(req)
    }
}

// Auth
impl PocketScionState {
    /// Adds an authorization server to the pocket SCION.
    pub fn set_auth_server(&mut self, snap_token_private_pem: Pem) {
        let mut system_state = self.write();
        system_state.auth_server = Some(AuthServerState {
            token_exchanger: PsTokenExchanger::new(PsTokenExchangeConfig::new(
                snap_token_private_pem,
                Duration::from_secs(3600),
            )),
        });
    }

    pub(crate) fn auth_server(&self) -> AuthorizationServerHandle {
        AuthorizationServerHandle {
            system_state: self.clone(),
        }
    }

    pub(crate) fn has_auth_server(&self) -> bool {
        self.read().auth_server.is_some()
    }
}

/// I/O configuration for the authorization server.
#[derive(Debug, Default, Serialize, Deserialize, ToSchema, PartialEq, Clone)]
pub struct IoAuthServerConfig {
    /// The address the authorization server listens on.
    #[schema(value_type = String, example = "127.0.0.1:8080")]
    pub addr: Option<SocketAddr>,
}
