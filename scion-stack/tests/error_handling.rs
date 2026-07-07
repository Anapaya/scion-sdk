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
//! Integration tests for error SCION stack error handling.

use pocketscion::util::topologies::{IA132, UnderlayType, minimal::two_path_topology};
use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use scion_stack::scionstack::{
    ScionSocketBindError, ScionStackBuilder, SnapConnectionError,
    builder::{AllEndhostApisFailed, ApiAttemptError, BuildScionStackError},
};
use snap_tokens::v0::dummy_snap_token;
use test_log::test;

// Test implementations and their corresponding test functions

// This test doesn't depend on underlay type, so we only need one version
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn endhost_api_unreachable_should_error() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let unreachable_url = "http://127.0.0.1:1".parse().unwrap();

    let result = ScionStackBuilder::new()
        .with_endhost_api(unreachable_url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await;

    match result {
        Err(BuildScionStackError::AllEndhostApisFailed(AllEndhostApisFailed(errs)))
            if matches!(
                errs.as_slice(),
                [(
                    _,
                    ApiAttemptError::UnderlayDiscovery(CrpcClientError::ConnectionError { .. })
                )]
            ) => {}
        _ => {
            panic!(
                "expected BuildScionStackError::AllEndhostApisFailed for unreachable server, got {result:?}"
            )
        }
    };
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_invalid_snap_token() {
    let ps_handle = two_path_topology(UnderlayType::Snap).await;

    let result = ScionStackBuilder::new()
        .with_endhost_api(ps_handle.endhost_api(IA132).unwrap())
        .with_auth_token("invalid token".to_string())
        .build()
        .await
        .unwrap()
        .bind(None)
        .await;

    // TODO(uniquefine): this should match a more specific error to indicate that the auth token
    // is invalid.
    assert!(
        matches!(
            result,
            Err(ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::DataPlaneDiscoveryError(_)
            ))
        ),
        "expected Snap::DataPlaneDiscoveryError::CrpcError with Unauthenticated code for invalid token, got {result:?}"
    );
}
