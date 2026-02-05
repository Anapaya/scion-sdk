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

//! Integration test for PocketSCION with authorization server.
//!
//! Note: The auth server is deprecated.

use std::time::SystemTime;

use pocketscion::{
    authorization_server::{self, api::TokenRequest, fake_idp},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use scion_stack::scionstack::ScionStackBuilder;
use test_log::test;
use url::Url;

// Test creating the SCION stack with the SNAP token obtained from the auth server.
#[test(tokio::test)]
async fn with_auth_server() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (snap_token_private_pem, snap_token_public_pem) = insecure_const_ed25519_key_pair_pem();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());
    pstate.set_snap_token_public_pem(snap_token_public_pem);
    pstate.set_auth_server(snap_token_private_pem);

    let isd_as = "1-ff00:0:110".parse().unwrap();
    let snap_id = pstate.add_snap(isd_as).unwrap();

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().expect("no fail"))
        .start()
        .await
        .expect("could not start runtime");

    let mgmt_client = pocketscion.api_client();
    let res = mgmt_client.get_snaps().await.expect("get snaps");
    assert_eq!(res.snaps.len(), 1);

    // get the access token from the fake identity provider
    let access_token = fake_idp::oidc_id_token("fake user".to_string());

    let auth_server = mgmt_client
        .get_auth_server()
        .await
        .expect("get auth server");

    let auth_server_api: Url = format!("http://{}/", auth_server.addr).parse().unwrap();
    tracing::debug!("auth server api: {}", auth_server_api);
    let auth_client =
        authorization_server::client::ApiClient::new(&auth_server_api).expect("no fail");
    let token_exchange_req = TokenRequest::new(access_token);
    let snap_token_resp = auth_client
        .post_token(token_exchange_req)
        .await
        .expect("no fail");

    let snap_cp_addr = res
        .snaps
        .get(&snap_id)
        .expect("get snap")
        .control_plane_api
        .clone();
    let _client_stack = ScionStackBuilder::new(snap_cp_addr)
        .with_auth_token(snap_token_resp.access_token)
        .build()
        .await
        .unwrap();
}
