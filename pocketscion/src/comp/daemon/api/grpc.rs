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

//! Grpc API for the SCION Daemon service.

use scion_protobuf::daemon::{
    v1 as grpc, v1::daemon_service_server::DaemonService as GrpcDaemonService,
};
use scion_sdk_axum_connect_rpc::error::CrpcError;

use crate::comp::daemon::model::DaemonService;

/// Grpc API for the SCION Daemon service.
pub struct DaemonGrpcApi {
    daemon_service: std::sync::Arc<dyn DaemonService + Send + Sync>,
}
impl DaemonGrpcApi {
    /// Create a new DaemonGrpcApi with the given DaemonService.
    pub fn new(daemon_service: std::sync::Arc<dyn DaemonService + Send + Sync>) -> Self {
        Self { daemon_service }
    }
}
#[async_trait::async_trait]
impl GrpcDaemonService for DaemonGrpcApi {
    /// Return a set of paths to the requested destination.
    async fn paths(
        &self,
        request: tonic::Request<grpc::PathsRequest>,
    ) -> std::result::Result<tonic::Response<grpc::PathsResponse>, tonic::Status> {
        self.daemon_service
            .paths(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// Return information about an AS.
    async fn r#as(
        &self,
        request: tonic::Request<grpc::AsRequest>,
    ) -> std::result::Result<tonic::Response<grpc::AsResponse>, tonic::Status> {
        self.daemon_service
            .as_info(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// Return the underlay addresses associated with
    /// the specified interfaces.
    async fn interfaces(
        &self,
        request: tonic::Request<grpc::InterfacesRequest>,
    ) -> std::result::Result<tonic::Response<grpc::InterfacesResponse>, tonic::Status> {
        self.daemon_service
            .interfaces(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// Return the underlay addresses associated with the
    /// specified services.
    async fn services(
        &self,
        request: tonic::Request<grpc::ServicesRequest>,
    ) -> std::result::Result<tonic::Response<grpc::ServicesResponse>, tonic::Status> {
        self.daemon_service
            .services(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// Inform the SCION Daemon of a revocation.
    async fn notify_interface_down(
        &self,
        request: tonic::Request<grpc::NotifyInterfaceDownRequest>,
    ) -> std::result::Result<tonic::Response<grpc::NotifyInterfaceDownResponse>, tonic::Status>
    {
        self.daemon_service
            .notify_interface_down(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// DRKeyASHost returns a key that matches the request.
    async fn dr_key_as_host(
        &self,
        request: tonic::Request<grpc::DrKeyAsHostRequest>,
    ) -> std::result::Result<tonic::Response<grpc::DrKeyAsHostResponse>, tonic::Status> {
        self.daemon_service
            .dr_key_as_host(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// DRKeyHostAS returns a key that matches the request.
    async fn dr_key_host_as(
        &self,
        request: tonic::Request<grpc::DrKeyHostAsRequest>,
    ) -> std::result::Result<tonic::Response<grpc::DrKeyHostAsResponse>, tonic::Status> {
        self.daemon_service
            .dr_key_host_as(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }

    /// DRKeyHostHost returns a key that matches the request.
    async fn dr_key_host_host(
        &self,
        request: tonic::Request<grpc::DrKeyHostHostRequest>,
    ) -> std::result::Result<tonic::Response<grpc::DrKeyHostHostResponse>, tonic::Status> {
        self.daemon_service
            .dr_key_host_host(request.into_inner())
            .await
            .map(tonic::Response::new)
            .map_err(to_tonic_status)
    }
}

fn to_tonic_status(e: CrpcError) -> tonic::Status {
    match e.code {
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Canceled => {
            tonic::Status::cancelled(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unknown => {
            tonic::Status::unknown(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::InvalidArgument => {
            tonic::Status::invalid_argument(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::DeadlineExceeded => {
            tonic::Status::deadline_exceeded(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::NotFound => {
            tonic::Status::not_found(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::AlreadyExists => {
            tonic::Status::already_exists(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::PermissionDenied => {
            tonic::Status::permission_denied(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::ResourceExhausted => {
            tonic::Status::resource_exhausted(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::FailedPrecondition => {
            tonic::Status::failed_precondition(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Aborted => {
            tonic::Status::aborted(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::OutOfRange => {
            tonic::Status::out_of_range(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unimplemented => {
            tonic::Status::unimplemented(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Internal => {
            tonic::Status::internal(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unavailable => {
            tonic::Status::unavailable(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::DataLoss => {
            tonic::Status::data_loss(e.message)
        }
        scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unauthenticated => {
            tonic::Status::unauthenticated(e.message)
        }
    }
}
