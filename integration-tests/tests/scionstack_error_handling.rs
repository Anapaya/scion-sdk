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

use integration_tests::{UnderlayType, minimal_pocketscion_setup};
use scion_proto::address::{ScionAddrSvc, ServiceAddr, SocketAddr};
use scion_sdk_reqwest_connect_rpc::{
    client::CrpcClientError,
    error::{CrpcError, CrpcErrorCode},
};
use scion_stack::scionstack::{
    ScionSocketBindError, ScionStackBuilder,
    builder::{BuildScionStackError, BuildSnapScionStackError},
};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;

// Test implementations and their corresponding test functions

// This test doesn't depend on underlay type, so we only need one version
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn endhost_api_unreachable_should_error() {
    let unreachable_addr = "127.0.0.1:1";

    let result = ScionStackBuilder::new(format!("http://{unreachable_addr}").parse().unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await;

    assert!(
        matches!(
            result,
            Err(BuildScionStackError::UnderlayDiscoveryError(
                CrpcClientError::ConnectionError { .. }
            ))
        ),
        "expected UnderlayDiscoveryError::ConnectionError for unreachable server, got {result:?}"
    );
}

mod v2 {
    use integration_tests::{UnderlayType, minimal_pocketscion_setup};
    use scion_proto::address::{ScionAddrSvc, ServiceAddr, SocketAddr};
    use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
    use scion_stack::scionstack::{
        ScionSocketBindError, ScionStackBuilder, builder::BuildScionStackError,
    };
    use snap_tokens::snap_token::dummy_snap_token;
    use test_log::test;

    // This test doesn't depend on underlay type, so we only need one version
    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn endhost_api_unreachable_should_error() {
        let unreachable_addr = "127.0.0.1:1";

        let result = ScionStackBuilder::new(format!("http://{unreachable_addr}").parse().unwrap())
            .with_auth_token(dummy_snap_token())
            .with_use_v2()
            .build()
            .await;

        assert!(
            matches!(
                result,
                Err(BuildScionStackError::UnderlayDiscoveryError(
                    CrpcClientError::ConnectionError { .. }
                ))
            ),
            "expected UnderlayDiscoveryError::ConnectionError for unreachable server, got {result:?}"
        );
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn test_invalid_snap_token() {
        let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;

        let result = ScionStackBuilder::new(test_env.eh_api132.url)
            .with_auth_token("invalid token".to_string())
            .with_use_v2()
            .build()
            .await
            .unwrap()
            .bind(None)
            .await;

        // TODO(uniquefine): this should match a more specific error to indicate that the auth token
        // is invalid.
        assert!(
            matches!(result, Err(ScionSocketBindError::DataplaneError(_))),
            "expected Snap::DataPlaneDiscoveryError::CrpcError with Unauthenticated code for invalid token, got {result:?}"
        );
    }

    async fn test_bind_service_address_fails_impl(underlay: UnderlayType) {
        let test_env = minimal_pocketscion_setup(underlay).await;

        let stack = ScionStackBuilder::new(test_env.eh_api132.url)
            .with_auth_token(dummy_snap_token())
            .with_use_v2()
            .build()
            .await
            .unwrap();

        let service_addr =
            SocketAddr::new(ScionAddrSvc::new(0.into(), ServiceAddr::CONTROL).into(), 0);

        let result = stack.bind(Some(service_addr)).await;
        let error = result.unwrap_err();
        assert!(
            matches!(error, ScionSocketBindError::InvalidBindAddress(addr, _) if addr == service_addr),
            "expected InvalidBindAddress({service_addr:?}) when binding to service address, got {error:?}"
        );
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn test_bind_service_address_fails_snap() {
        test_bind_service_address_fails_impl(UnderlayType::Snap).await;
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn test_bind_service_address_fails_udp() {
        test_bind_service_address_fails_impl(UnderlayType::Udp).await;
    }
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_invalid_token_snap() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;

    let result = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token("invalid token".to_string())
        .build()
        .await;

    assert!(
        matches!(
            result,
            Err(BuildScionStackError::Snap(
                BuildSnapScionStackError::DataPlaneDiscoveryError(CrpcClientError::CrpcError(
                    CrpcError {
                        code: CrpcErrorCode::Unauthenticated,
                        ..
                    }
                ))
            ))
        ),
        "expected Snap::DataPlaneDiscoveryError::CrpcError with Unauthenticated code for invalid token, got {result:?}"
    );
}

async fn test_bind_service_address_fails_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;

    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let service_addr = SocketAddr::new(ScionAddrSvc::new(0.into(), ServiceAddr::CONTROL).into(), 0);

    let result = stack.bind(Some(service_addr)).await;
    let error = result.unwrap_err();
    assert!(
        matches!(error, ScionSocketBindError::InvalidBindAddress(addr, _) if addr == service_addr),
        "expected InvalidBindAddress({service_addr:?}) when binding to service address, got {error:?}"
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_service_address_fails_snap() {
    test_bind_service_address_fails_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_service_address_fails_udp() {
    test_bind_service_address_fails_impl(UnderlayType::Udp).await;
}
