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

//! Connect-RPC and gRPC API for the SCION Daemon service.
//!
//! The generated [`DaemonService`](scion_protobuf::proto::daemon::v1::DaemonService) dispatcher
//! serves both protocols on one port, so a gRPC client and a Connect client reach the same
//! handlers. An adapter maps it onto the [`model::DaemonService`] the daemon implements.

use std::sync::Arc;

use axum::Router;
use axum_connect_rpc::error::CrpcError;
use connectrpc::{
    ConnectError, Encodable, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use scion_protobuf::proto::daemon::v1::{
    ASRequest, ASResponse, DRKeyASHostRequest, DRKeyASHostResponse, DRKeyHostASRequest,
    DRKeyHostASResponse, DRKeyHostHostRequest, DRKeyHostHostResponse, InterfacesRequest,
    InterfacesResponse, NotifyInterfaceDownRequest, NotifyInterfaceDownResponse, PathsRequest,
    PathsResponse, PortRangeResponse, ServicesRequest, ServicesResponse,
};

use super::super::model;

/// Serves the DaemonService on `base_router`, for Connect-RPC and gRPC clients.
///
/// The dispatcher answers every path under the service, so it takes the router's fallback. Add
/// explicit routes to `base_router` before this call to keep them.
pub fn nest_api<DaemonType: model::DaemonService>(
    base_router: Router,
    service: Arc<DaemonType>,
) -> Router {
    let dispatcher = connectrpc::Router::new().add_service(Arc::new(DaemonRpc(service)));
    base_router.fallback_service(dispatcher.into_axum_service())
}

/// Adapts a [`model::DaemonService`] to the generated Connect-RPC service.
struct DaemonRpc<DaemonType>(Arc<DaemonType>);

/// Reports a handler error and turns it into the dispatcher's error type.
fn rpc_error(rpc: &str, error: CrpcError) -> ConnectError {
    tracing::error!(rpc, ?error, "Error handling daemon request");
    ConnectError::new(error_code(&error), error.message)
}

/// Maps a Connect-RPC error code onto the dispatcher's own.
fn error_code(error: &CrpcError) -> ErrorCode {
    use axum_connect_rpc::error::CrpcErrorCode as From;
    match error.code {
        From::Canceled => ErrorCode::Canceled,
        From::Unknown => ErrorCode::Unknown,
        From::InvalidArgument => ErrorCode::InvalidArgument,
        From::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        From::NotFound => ErrorCode::NotFound,
        From::AlreadyExists => ErrorCode::AlreadyExists,
        From::PermissionDenied => ErrorCode::PermissionDenied,
        From::ResourceExhausted => ErrorCode::ResourceExhausted,
        From::FailedPrecondition => ErrorCode::FailedPrecondition,
        From::Aborted => ErrorCode::Aborted,
        From::OutOfRange => ErrorCode::OutOfRange,
        From::Unimplemented => ErrorCode::Unimplemented,
        From::Internal => ErrorCode::Internal,
        From::Unavailable => ErrorCode::Unavailable,
        From::DataLoss => ErrorCode::DataLoss,
        From::Unauthenticated => ErrorCode::Unauthenticated,
    }
}
#[allow(refining_impl_trait)]
impl<DaemonType: model::DaemonService> scion_protobuf::proto::daemon::v1::DaemonService
    for DaemonRpc<DaemonType>
{
    async fn paths<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PathsRequest>,
    ) -> ServiceResult<impl Encodable<PathsResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .paths(request)
                .await
                .map_err(|error| rpc_error("Paths", error))?,
        )
    }

    async fn r#as<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ASRequest>,
    ) -> ServiceResult<impl Encodable<ASResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .as_info(request)
                .await
                .map_err(|error| rpc_error("AS", error))?,
        )
    }

    async fn interfaces<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, InterfacesRequest>,
    ) -> ServiceResult<impl Encodable<InterfacesResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .interfaces(request)
                .await
                .map_err(|error| rpc_error("Interfaces", error))?,
        )
    }

    async fn services<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ServicesRequest>,
    ) -> ServiceResult<impl Encodable<ServicesResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .services(request)
                .await
                .map_err(|error| rpc_error("Services", error))?,
        )
    }

    async fn notify_interface_down<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, NotifyInterfaceDownRequest>,
    ) -> ServiceResult<impl Encodable<NotifyInterfaceDownResponse> + Send + use<'a, DaemonType>>
    {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .notify_interface_down(request)
                .await
                .map_err(|error| rpc_error("NotifyInterfaceDown", error))?,
        )
    }

    async fn port_range<'a>(
        &'a self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, buffa_types::google::protobuf::Empty>,
    ) -> ServiceResult<impl Encodable<PortRangeResponse> + Send + use<'a, DaemonType>> {
        Response::ok(
            self.0
                .port_range()
                .await
                .map_err(|error| rpc_error("PortRange", error))?,
        )
    }

    async fn dr_key_as_host<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DRKeyASHostRequest>,
    ) -> ServiceResult<impl Encodable<DRKeyASHostResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .dr_key_as_host(request)
                .await
                .map_err(|error| rpc_error("DRKeyASHost", error))?,
        )
    }

    async fn dr_key_host_as<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DRKeyHostASRequest>,
    ) -> ServiceResult<impl Encodable<DRKeyHostASResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .dr_key_host_as(request)
                .await
                .map_err(|error| rpc_error("DRKeyHostAS", error))?,
        )
    }

    async fn dr_key_host_host<'a>(
        &'a self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DRKeyHostHostRequest>,
    ) -> ServiceResult<impl Encodable<DRKeyHostHostResponse> + Send + use<'a, DaemonType>> {
        let request = request.to_owned_message();
        Response::ok(
            self.0
                .dr_key_host_host(request)
                .await
                .map_err(|error| rpc_error("DRKeyHostHost", error))?,
        )
    }
}
