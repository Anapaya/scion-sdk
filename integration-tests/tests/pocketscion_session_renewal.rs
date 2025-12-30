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

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use integration_tests::single_snap_pocketscion_setup;
use scion_proto::address::{HostAddr, IsdAsn, ScionAddr, SocketAddr};
use scion_stack::scionstack::{ScionStackBuilder, builder::SnapUnderlayConfig};
use snap_control::client::re_export::refresh::{RefreshTokenSource, TokenWithExpiry};
use snap_tokens::snap_token::dummy_snap_token_with_validity;
use test_log::test;
use tokio::time::timeout;

/// TODO(uniquefine): Adapt to use v2. Session tokens are no longer used, but the snap token still
/// needs to be renewed and send to the data plane.
#[test(tokio::test)]
#[ignore = "The new SCION stack no longer uses session tokens, but the SNAP token still needs to be renewed."]
async fn auto_session_renewals() {
    // For sessions we have a hardcoded automatic renew to happen at (expiration_time as f32 * 0.75)
    // as u64
    // So 4s Session Validity means Renew after 3s

    // So with
    // Token Expiry = 5s
    // Session Expiry = 4s
    // Session Renew Interval = 3s

    // Time (s):  |0    1    2    3    4    5    6    7    8|
    // -----------|-----|----|----|----|----|----|----|------
    // Token:     T-----|----|----|----|----TE   |    |
    // Session:   |A----|----|----|B---|----|----|C---|SE
    // Sends:     |-S---|----|----|----|----|-S--|----|-----|-F

    // T    = Token is issued (0s)
    // TE   = Token fully expired (4s)

    // A    = First Session Renewed (at 0.X sec)
    // B    = Second Session Renewed (at 3.X2 sec)
    // C    = Tries to Renew session with expired token (6.X2)
    // SE   = Session fully expired (7.X2 sec)

    // X = Network/App Latency

    // Slight offset between T and A because network and app latency
    const TOKEN_EXPIRY: u64 = 5;
    // const SESSION_EXPIRY: Duration = Duration::from_secs(4);

    let (_pocketscion, snap_cp_addr) = single_snap_pocketscion_setup().await;
    let stack = ScionStackBuilder::new(snap_cp_addr)
        .with_auth_token(dummy_snap_token_with_validity(TOKEN_EXPIRY))
        .with_snap_underlay_config(
            SnapUnderlayConfig::builder()
                .with_auto_token_renewal(Duration::from_secs(0))
                .build(),
        )
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

    sender
        .send_to(&test_data.clone(), test_destination)
        .await
        .expect("must be able to send in the first session timeframe");

    // (6.X) Skip to the second session timeframe, after snap token is expired
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    sender
        .send_to(&test_data.clone(), test_destination)
        .await
        .expect("must be able to send in the second session timeframe");

    // (8.X) Wait for session to fully expire
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // Session should now be expired and the SNAP token is no longer valid.
    let res = sender.send_to(&test_data.clone(), test_destination).await;
    let err = res.expect_err("must fail to send after session fully expired");
    tracing::info!("Got expected error: {err:?}");
}

/// TODO(uniquefine): Adapt to use v2. Session tokens are no longer used, but the snap token still
/// needs to be renewed and send to the data plane.
// Test the auto snaptun session renewal with a renewable connect RPC client. This tests not only
// the SNAP data plane session token renewal but also the SNAP token renewal.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
#[ignore = "The new SCION stack no longer uses session tokens, but the SNAP token still needs to be renewed."]
async fn auto_session_renewal_with_client() {
    // Setup pocketscion:
    // * SNAP data plane session token are valid for 3 seconds.
    // * SNAP token expires in 3 seconds.
    let (_pocketscion, snap_cp_addr) = single_snap_pocketscion_setup().await;
    tracing::debug!("snap cp addr: {snap_cp_addr}");
    let source = RefreshTokenSource::builder("test-renewer", || {
        async move {
            Ok(TokenWithExpiry {
                token: dummy_snap_token_with_validity(3),
                expires_at: Instant::now() + Duration::from_secs(3),
            })
        }
    })
    .min_token_lifetime(Duration::from_secs(1))
    .refresh_threshold(Duration::from_secs(1));

    let stack = ScionStackBuilder::new(snap_cp_addr)
        .with_auth_token_source(source.build())
        // with renewable SNAP token
        .with_snap_underlay_config(
            SnapUnderlayConfig::builder()
                .with_auto_token_renewal(Duration::from_secs(0))
                .build(),
        )
        .build()
        .await
        .unwrap();

    let sender = stack.bind(None).await.unwrap();

    let test_data = Bytes::from("Hello, World!");
    let test_destination = "[2-ff00:0:212,127.0.0.1]:8080".parse().unwrap();

    // sender loop sending packets to a random location (dropped by the SNAP).
    let res = timeout(std::time::Duration::from_secs(4), async {
        loop {
            let res = sender.send_to(&test_data.clone(), test_destination).await;
            if let Err(err) = res {
                return err;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
    .await;

    if let Ok(err) = res {
        // Sending should always succeed as the short lived SNAP token is also renewed.
        panic!("Expected timeout error, got: {err:?}");
    }
}
