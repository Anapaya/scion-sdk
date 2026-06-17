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

//! Trait for the SCION Daemon service.

use scion_protobuf::daemon::v1 as proto;
use scion_sdk_axum_connect_rpc::error::CrpcError;

/// The prefix for all methods of the SCION Daemon service.
pub const SERVICE_PREFIX: &str = "proto.daemon.v1.DaemonService";

/// Endpoint Path
pub const PATH_PATHS: &str = "/PocketScionStatePaths";
/// Endpoint Path
pub const PATH_AS: &str = "/PocketScionStateAS";
/// Endpoint Path
pub const PATH_INTERFACES: &str = "/PocketScionStateInterfaces";
/// Endpoint Path
pub const PATH_SERVICES: &str = "/PocketScionStateServices";
/// Endpoint Path
pub const PATH_NOTIFY_INTERFACE_DOWN: &str = "/PocketScionStateNotifyInterfaceDown";
/// Endpoint Path
pub const PATH_DR_KEY_AS_HOST: &str = "/PocketScionStateDRKeyASHost";
/// Endpoint Path
pub const PATH_DR_KEY_HOST_AS: &str = "/PocketScionStateDRKeyHostAS";
/// Endpoint Path
pub const PATH_DR_KEY_HOST_HOST: &str = "/PocketScionStateDRKeyHostHost";

/// Trait for the SCION Daemon service.
#[async_trait::async_trait]
pub trait DaemonService: Send + Sync + 'static {
    /// Return a set of paths to the requested destination.
    async fn paths(&self, request: proto::PathsRequest) -> Result<proto::PathsResponse, CrpcError>;

    /// Return information about an AS.
    async fn as_info(&self, request: proto::AsRequest) -> Result<proto::AsResponse, CrpcError>;

    /// Return the underlay addresses associated with the specified interfaces.
    async fn interfaces(
        &self,
        request: proto::InterfacesRequest,
    ) -> Result<proto::InterfacesResponse, CrpcError>;

    /// Return the underlay addresses associated with the specified services.
    async fn services(
        &self,
        request: proto::ServicesRequest,
    ) -> Result<proto::ServicesResponse, CrpcError>;

    /// Inform the SCION Daemon of a revocation.
    async fn notify_interface_down(
        &self,
        request: proto::NotifyInterfaceDownRequest,
    ) -> Result<proto::NotifyInterfaceDownResponse, CrpcError>;

    /// DRKeyASHost returns a key that matches the request.
    async fn dr_key_as_host(
        &self,
        request: proto::DrKeyAsHostRequest,
    ) -> Result<proto::DrKeyAsHostResponse, CrpcError>;

    /// DRKeyHostAS returns a key that matches the request.
    async fn dr_key_host_as(
        &self,
        request: proto::DrKeyHostAsRequest,
    ) -> Result<proto::DrKeyHostAsResponse, CrpcError>;

    /// DRKeyHostHost returns a key that matches the request.
    async fn dr_key_host_host(
        &self,
        request: proto::DrKeyHostHostRequest,
    ) -> Result<proto::DrKeyHostHostResponse, CrpcError>;
}
