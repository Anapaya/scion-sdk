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
//! Integration tests for SNAP data plane session renewal in PocketSCION.

use std::net::Ipv4Addr;

use bytes::Bytes;
use integration_tests::single_snap_pocketscion_setup;
use scion_proto::address::{HostAddr, IsdAsn, ScionAddr, SocketAddr};
use scion_sdk_reqwest_connect_rpc::token_source::mock::MockTokenSource;
use scion_stack::scionstack::{ScionStackBuilder, builder::SnapUnderlayConfig};
use snap_tokens::v0::dummy_snap_token_with_validity;
use test_log::test;

#[test(tokio::test)]
#[ignore]
async fn auto_session_renewals() {
    // First token is valid for 2 seconds.
    // We then update a token that is valid for another 3 seconds.
    // Both tokens should allow sending packets.

    let mock_token_source = MockTokenSource::new(dummy_snap_token_with_validity(2));

    let (_pocketscion, snap_cp_addr) = single_snap_pocketscion_setup().await;
    let stack = ScionStackBuilder::new(snap_cp_addr)
        .with_auth_token_source(mock_token_source.clone())
        .with_snap_underlay_config(SnapUnderlayConfig::builder().build())
        .build()
        .await
        .unwrap();

    let sender = stack.bind(None).await.unwrap();

    let test_data = Bytes::from("Hello, World!");
    let dst_isd_as: IsdAsn = "2-ff00:0:212".parse().unwrap();
    let test_destination = SocketAddr::new(
        ScionAddr::new(dst_isd_as, HostAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        8080,
    );

    tracing::info!("Sending first packet...");
    sender
        .send_to(&test_data.clone(), test_destination)
        .await
        .expect("must be able to send in the first session timeframe");

    // Update token
    mock_token_source.update_token(dummy_snap_token_with_validity(3));

    // Skip to after the first token expired
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    tracing::info!("Sending second packet...");
    sender
        .send_to(&test_data.clone(), test_destination)
        .await
        .expect("must be able to send in the second session timeframe");

    // Wait for session to fully expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    tracing::info!("Sending third packet...");
    // Session should now be expired and the SNAP token is no longer valid.
    let res = sender.send_to(&test_data.clone(), test_destination).await;
    let err = res.expect_err("must fail to send after session fully expired");
    tracing::info!("Got expected error: {err:?}");
}
