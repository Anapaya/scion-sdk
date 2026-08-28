///Shorthand for `OwnedView<PathsRequestView<'static>>`.
pub type OwnedPathsRequestView = ::buffa::view::OwnedView<
    __buffa::view::PathsRequestView<'static>,
>;
///Shorthand for `OwnedView<PathsResponseView<'static>>`.
pub type OwnedPathsResponseView = ::buffa::view::OwnedView<
    __buffa::view::PathsResponseView<'static>,
>;
///Shorthand for `OwnedView<AsRequestView<'static>>`.
pub type OwnedAsRequestView = ::buffa::view::OwnedView<
    __buffa::view::ASRequestView<'static>,
>;
///Shorthand for `OwnedView<AsResponseView<'static>>`.
pub type OwnedAsResponseView = ::buffa::view::OwnedView<
    __buffa::view::ASResponseView<'static>,
>;
///Shorthand for `OwnedView<InterfacesRequestView<'static>>`.
pub type OwnedInterfacesRequestView = ::buffa::view::OwnedView<
    __buffa::view::InterfacesRequestView<'static>,
>;
///Shorthand for `OwnedView<InterfacesResponseView<'static>>`.
pub type OwnedInterfacesResponseView = ::buffa::view::OwnedView<
    __buffa::view::InterfacesResponseView<'static>,
>;
///Shorthand for `OwnedView<ServicesRequestView<'static>>`.
pub type OwnedServicesRequestView = ::buffa::view::OwnedView<
    __buffa::view::ServicesRequestView<'static>,
>;
///Shorthand for `OwnedView<ServicesResponseView<'static>>`.
pub type OwnedServicesResponseView = ::buffa::view::OwnedView<
    __buffa::view::ServicesResponseView<'static>,
>;
///Shorthand for `OwnedView<NotifyInterfaceDownRequestView<'static>>`.
pub type OwnedNotifyInterfaceDownRequestView = ::buffa::view::OwnedView<
    __buffa::view::NotifyInterfaceDownRequestView<'static>,
>;
///Shorthand for `OwnedView<NotifyInterfaceDownResponseView<'static>>`.
pub type OwnedNotifyInterfaceDownResponseView = ::buffa::view::OwnedView<
    __buffa::view::NotifyInterfaceDownResponseView<'static>,
>;
///Shorthand for `OwnedView<EmptyView<'static>>`.
pub type OwnedEmptyView = ::buffa::view::OwnedView<
    ::buffa_types::google::protobuf::__buffa::view::EmptyView<'static>,
>;
///Shorthand for `OwnedView<PortRangeResponseView<'static>>`.
pub type OwnedPortRangeResponseView = ::buffa::view::OwnedView<
    __buffa::view::PortRangeResponseView<'static>,
>;
///Shorthand for `OwnedView<DrKeyAsHostRequestView<'static>>`.
pub type OwnedDrKeyAsHostRequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyASHostRequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeyAsHostResponseView<'static>>`.
pub type OwnedDrKeyAsHostResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyASHostResponseView<'static>,
>;
///Shorthand for `OwnedView<DrKeyHostAsRequestView<'static>>`.
pub type OwnedDrKeyHostAsRequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyHostASRequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeyHostAsResponseView<'static>>`.
pub type OwnedDrKeyHostAsResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyHostASResponseView<'static>,
>;
///Shorthand for `OwnedView<DrKeyHostHostRequestView<'static>>`.
pub type OwnedDrKeyHostHostRequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyHostHostRequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeyHostHostResponseView<'static>>`.
pub type OwnedDrKeyHostHostResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyHostHostResponseView<'static>,
>;
impl ::connectrpc::Encodable<PathsResponse> for __buffa::view::PathsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<PathsResponse>
for ::buffa::view::OwnedView<__buffa::view::PathsResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ASResponse> for __buffa::view::ASResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ASResponse>
for ::buffa::view::OwnedView<__buffa::view::ASResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<InterfacesResponse>
for __buffa::view::InterfacesResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<InterfacesResponse>
for ::buffa::view::OwnedView<__buffa::view::InterfacesResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ServicesResponse>
for __buffa::view::ServicesResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ServicesResponse>
for ::buffa::view::OwnedView<__buffa::view::ServicesResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<NotifyInterfaceDownResponse>
for __buffa::view::NotifyInterfaceDownResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<NotifyInterfaceDownResponse>
for ::buffa::view::OwnedView<__buffa::view::NotifyInterfaceDownResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<PortRangeResponse>
for __buffa::view::PortRangeResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<PortRangeResponse>
for ::buffa::view::OwnedView<__buffa::view::PortRangeResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<DRKeyASHostResponse>
for __buffa::view::DRKeyASHostResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeyASHostResponse>
for ::buffa::view::OwnedView<__buffa::view::DRKeyASHostResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<DRKeyHostASResponse>
for __buffa::view::DRKeyHostASResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeyHostASResponse>
for ::buffa::view::OwnedView<__buffa::view::DRKeyHostASResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<DRKeyHostHostResponse>
for __buffa::view::DRKeyHostHostResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeyHostHostResponse>
for ::buffa::view::OwnedView<__buffa::view::DRKeyHostHostResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
/// Full service name for this service.
pub const DAEMON_SERVICE_SERVICE_NAME: &str = "proto.daemon.v1.DaemonService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `Paths` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_PATHS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/Paths",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `AS` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_AS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/AS",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `Interfaces` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_INTERFACES_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/Interfaces",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `Services` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_SERVICES_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/Services",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `NotifyInterfaceDown` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_NOTIFY_INTERFACE_DOWN_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/NotifyInterfaceDown",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `PortRange` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_PORT_RANGE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/PortRange",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyASHost` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_DR_KEY_AS_HOST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/DRKeyASHost",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyHostAS` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_DR_KEY_HOST_AS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/DRKeyHostAS",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyHostHost` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DAEMON_SERVICE_DR_KEY_HOST_HOST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.daemon.v1.DaemonService/DRKeyHostHost",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Server trait for DaemonService.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.8.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait DaemonService: Send + Sync + 'static {
    /// Handle the Paths RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn paths<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, PathsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<PathsResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the AS RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn r#as<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ASRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ASResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the Interfaces RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn interfaces<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, InterfacesRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<InterfacesResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the Services RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn services<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ServicesRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ServicesResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the NotifyInterfaceDown RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn notify_interface_down<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, NotifyInterfaceDownRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                NotifyInterfaceDownResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the PortRange RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn port_range<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ::buffa_types::google::protobuf::Empty>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<PortRangeResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the DRKeyASHost RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_as_host<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeyASHostRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeyASHostResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the DRKeyHostAS RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_host_as<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeyHostASRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeyHostASResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the DRKeyHostHost RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_host_host<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeyHostHostRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeyHostHostResponse> + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait DaemonServiceExt: DaemonService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: DaemonService> DaemonServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "Paths",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::PathsRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                PathsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.paths(ctx, sreq).await?.encode::<PathsResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_PATHS_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "AS",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ASRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ASRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.r#as(ctx, sreq).await?.encode::<ASResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_AS_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "Interfaces",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::InterfacesRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                InterfacesRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.interfaces(ctx, sreq)
                                .await?
                                .encode::<InterfacesResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_INTERFACES_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "Services",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ServicesRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ServicesRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.services(ctx, sreq)
                                .await?
                                .encode::<ServicesResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_SERVICES_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "NotifyInterfaceDown",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::NotifyInterfaceDownRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                NotifyInterfaceDownRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.notify_interface_down(ctx, sreq)
                                .await?
                                .encode::<NotifyInterfaceDownResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_NOTIFY_INTERFACE_DOWN_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "PortRange",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            ::buffa_types::google::protobuf::__buffa::view::EmptyView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ::buffa_types::google::protobuf::Empty,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.port_range(ctx, sreq)
                                .await?
                                .encode::<PortRangeResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_PORT_RANGE_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyASHost",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeyASHostRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeyASHostRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_as_host(ctx, sreq)
                                .await?
                                .encode::<DRKeyASHostResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_DR_KEY_AS_HOST_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyHostAS",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeyHostASRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeyHostASRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_host_as(ctx, sreq)
                                .await?
                                .encode::<DRKeyHostASResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_DR_KEY_HOST_AS_SPEC)
            .route_view(
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyHostHost",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeyHostHostRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeyHostHostRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_host_host(ctx, sreq)
                                .await?
                                .encode::<DRKeyHostHostResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DAEMON_SERVICE_DR_KEY_HOST_HOST_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct DaemonServiceRegisterMarker;
impl<S: DaemonService> ::connectrpc::ServiceRegister<DaemonServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as DaemonServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `DaemonService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = DaemonServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct DaemonServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: DaemonService> DaemonServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for DaemonServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: DaemonService> ::connectrpc::Dispatcher for DaemonServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("proto.daemon.v1.DaemonService/")?;
        match method {
            "Paths" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_PATHS_SPEC),
                )
            }
            "AS" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_AS_SPEC),
                )
            }
            "Interfaces" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_INTERFACES_SPEC),
                )
            }
            "Services" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_SERVICES_SPEC),
                )
            }
            "NotifyInterfaceDown" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_NOTIFY_INTERFACE_DOWN_SPEC),
                )
            }
            "PortRange" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_PORT_RANGE_SPEC),
                )
            }
            "DRKeyASHost" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_DR_KEY_AS_HOST_SPEC),
                )
            }
            "DRKeyHostAS" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_DR_KEY_HOST_AS_SPEC),
                )
            }
            "DRKeyHostHost" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DAEMON_SERVICE_DR_KEY_HOST_HOST_SPEC),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("proto.daemon.v1.DaemonService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "Paths" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        PathsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::PathsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        PathsRequest,
                    >::from_parts(&req, &body);
                    svc.paths(ctx, req).await?.encode::<PathsResponse>(format)
                })
            }
            "AS" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ASRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ASRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ASRequest,
                    >::from_parts(&req, &body);
                    svc.r#as(ctx, req).await?.encode::<ASResponse>(format)
                })
            }
            "Interfaces" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        InterfacesRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::InterfacesRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        InterfacesRequest,
                    >::from_parts(&req, &body);
                    svc.interfaces(ctx, req).await?.encode::<InterfacesResponse>(format)
                })
            }
            "Services" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ServicesRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ServicesRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ServicesRequest,
                    >::from_parts(&req, &body);
                    svc.services(ctx, req).await?.encode::<ServicesResponse>(format)
                })
            }
            "NotifyInterfaceDown" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        NotifyInterfaceDownRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::NotifyInterfaceDownRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        NotifyInterfaceDownRequest,
                    >::from_parts(&req, &body);
                    svc.notify_interface_down(ctx, req)
                        .await?
                        .encode::<NotifyInterfaceDownResponse>(format)
                })
            }
            "PortRange" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ::buffa_types::google::protobuf::Empty,
                    >(request.encoded()?, format)?;
                    let req: ::buffa_types::google::protobuf::__buffa::view::EmptyView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ::buffa_types::google::protobuf::Empty,
                    >::from_parts(&req, &body);
                    svc.port_range(ctx, req).await?.encode::<PortRangeResponse>(format)
                })
            }
            "DRKeyASHost" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeyASHostRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeyASHostRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeyASHostRequest,
                    >::from_parts(&req, &body);
                    svc.dr_key_as_host(ctx, req)
                        .await?
                        .encode::<DRKeyASHostResponse>(format)
                })
            }
            "DRKeyHostAS" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeyHostASRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeyHostASRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeyHostASRequest,
                    >::from_parts(&req, &body);
                    svc.dr_key_host_as(ctx, req)
                        .await?
                        .encode::<DRKeyHostASResponse>(format)
                })
            }
            "DRKeyHostHost" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeyHostHostRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeyHostHostRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeyHostHostRequest,
                    >::from_parts(&req, &body);
                    svc.dr_key_host_host(ctx, req)
                        .await?
                        .encode::<DRKeyHostHostResponse>(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("proto.daemon.v1.DaemonService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("proto.daemon.v1.DaemonService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("proto.daemon.v1.DaemonService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = DaemonServiceClient::new(conn, config);
/// let response = client.paths(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = DaemonServiceClient::new(http, config);
/// let response = client.paths(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.paths(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.paths(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct DaemonServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> DaemonServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the Paths RPC. Sends a request to /proto.daemon.v1.DaemonService/Paths.
    pub async fn paths(
        &self,
        request: PathsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PathsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.paths_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the Paths RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn paths_with_options(
        &self,
        request: PathsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PathsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "Paths",
                request,
                options,
            )
            .await
    }
    /// Call the AS RPC. Sends a request to /proto.daemon.v1.DaemonService/AS.
    pub async fn r#as(
        &self,
        request: ASRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ASResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.as_with_options(request, ::connectrpc::client::CallOptions::default()).await
    }
    /// Call the AS RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn as_with_options(
        &self,
        request: ASRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ASResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "AS",
                request,
                options,
            )
            .await
    }
    /// Call the Interfaces RPC. Sends a request to /proto.daemon.v1.DaemonService/Interfaces.
    pub async fn interfaces(
        &self,
        request: InterfacesRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::InterfacesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.interfaces_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the Interfaces RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn interfaces_with_options(
        &self,
        request: InterfacesRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::InterfacesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "Interfaces",
                request,
                options,
            )
            .await
    }
    /// Call the Services RPC. Sends a request to /proto.daemon.v1.DaemonService/Services.
    pub async fn services(
        &self,
        request: ServicesRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ServicesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.services_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the Services RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn services_with_options(
        &self,
        request: ServicesRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ServicesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "Services",
                request,
                options,
            )
            .await
    }
    /// Call the NotifyInterfaceDown RPC. Sends a request to /proto.daemon.v1.DaemonService/NotifyInterfaceDown.
    pub async fn notify_interface_down(
        &self,
        request: NotifyInterfaceDownRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::NotifyInterfaceDownResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.notify_interface_down_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the NotifyInterfaceDown RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn notify_interface_down_with_options(
        &self,
        request: NotifyInterfaceDownRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::NotifyInterfaceDownResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "NotifyInterfaceDown",
                request,
                options,
            )
            .await
    }
    /// Call the PortRange RPC. Sends a request to /proto.daemon.v1.DaemonService/PortRange.
    pub async fn port_range(
        &self,
        request: ::buffa_types::google::protobuf::Empty,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PortRangeResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.port_range_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the PortRange RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn port_range_with_options(
        &self,
        request: ::buffa_types::google::protobuf::Empty,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PortRangeResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "PortRange",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyASHost RPC. Sends a request to /proto.daemon.v1.DaemonService/DRKeyASHost.
    pub async fn dr_key_as_host(
        &self,
        request: DRKeyASHostRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyASHostResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_as_host_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeyASHost RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_as_host_with_options(
        &self,
        request: DRKeyASHostRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyASHostResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyASHost",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyHostAS RPC. Sends a request to /proto.daemon.v1.DaemonService/DRKeyHostAS.
    pub async fn dr_key_host_as(
        &self,
        request: DRKeyHostASRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyHostASResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_host_as_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeyHostAS RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_host_as_with_options(
        &self,
        request: DRKeyHostASRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyHostASResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyHostAS",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyHostHost RPC. Sends a request to /proto.daemon.v1.DaemonService/DRKeyHostHost.
    pub async fn dr_key_host_host(
        &self,
        request: DRKeyHostHostRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyHostHostResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_host_host_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeyHostHost RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_host_host_with_options(
        &self,
        request: DRKeyHostHostRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyHostHostResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DAEMON_SERVICE_SERVICE_NAME,
                "DRKeyHostHost",
                request,
                options,
            )
            .await
    }
}
