///Shorthand for `OwnedView<DrKeyLevel1RequestView<'static>>`.
pub type OwnedDrKeyLevel1RequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyLevel1RequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeyLevel1ResponseView<'static>>`.
pub type OwnedDrKeyLevel1ResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyLevel1ResponseView<'static>,
>;
///Shorthand for `OwnedView<DrKeyIntraLevel1RequestView<'static>>`.
pub type OwnedDrKeyIntraLevel1RequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyIntraLevel1RequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeyIntraLevel1ResponseView<'static>>`.
pub type OwnedDrKeyIntraLevel1ResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeyIntraLevel1ResponseView<'static>,
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
///Shorthand for `OwnedView<DrKeySecretValueRequestView<'static>>`.
pub type OwnedDrKeySecretValueRequestView = ::buffa::view::OwnedView<
    __buffa::view::DRKeySecretValueRequestView<'static>,
>;
///Shorthand for `OwnedView<DrKeySecretValueResponseView<'static>>`.
pub type OwnedDrKeySecretValueResponseView = ::buffa::view::OwnedView<
    __buffa::view::DRKeySecretValueResponseView<'static>,
>;
impl ::connectrpc::Encodable<DRKeyLevel1Response>
for __buffa::view::DRKeyLevel1ResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeyLevel1Response>
for ::buffa::view::OwnedView<__buffa::view::DRKeyLevel1ResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<DRKeyIntraLevel1Response>
for __buffa::view::DRKeyIntraLevel1ResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeyIntraLevel1Response>
for ::buffa::view::OwnedView<__buffa::view::DRKeyIntraLevel1ResponseView<'static>> {
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
impl ::connectrpc::Encodable<DRKeySecretValueResponse>
for __buffa::view::DRKeySecretValueResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DRKeySecretValueResponse>
for ::buffa::view::OwnedView<__buffa::view::DRKeySecretValueResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
/// Full service name for this service.
pub const DR_KEY_INTER_SERVICE_SERVICE_NAME: &str = "proto.control_plane.v1.DRKeyInterService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyLevel1` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTER_SERVICE_DR_KEY_LEVEL1_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyInterService/DRKeyLevel1",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Server trait for DRKeyInterService.
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
pub trait DrKeyInterService: Send + Sync + 'static {
    /// Handle the DRKeyLevel1 RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_level1<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeyLevel1Request>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeyLevel1Response> + Send + use<'a, Self>,
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
pub trait DrKeyInterServiceExt: DrKeyInterService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: DrKeyInterService> DrKeyInterServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                DR_KEY_INTER_SERVICE_SERVICE_NAME,
                "DRKeyLevel1",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeyLevel1RequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeyLevel1Request,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_level1(ctx, sreq)
                                .await?
                                .encode::<DRKeyLevel1Response>(format)
                        }
                    })
                },
            )
            .with_spec(DR_KEY_INTER_SERVICE_DR_KEY_LEVEL1_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct DrKeyInterServiceRegisterMarker;
impl<S: DrKeyInterService> ::connectrpc::ServiceRegister<DrKeyInterServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as DrKeyInterServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `DrKeyInterService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = DrKeyInterServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct DrKeyInterServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: DrKeyInterService> DrKeyInterServiceServer<T> {
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
impl<T> Clone for DrKeyInterServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: DrKeyInterService> ::connectrpc::Dispatcher for DrKeyInterServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("proto.control_plane.v1.DRKeyInterService/")?;
        match method {
            "DRKeyLevel1" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTER_SERVICE_DR_KEY_LEVEL1_SPEC),
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyInterService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "DRKeyLevel1" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeyLevel1Request,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeyLevel1RequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeyLevel1Request,
                    >::from_parts(&req, &body);
                    svc.dr_key_level1(ctx, req)
                        .await?
                        .encode::<DRKeyLevel1Response>(format)
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyInterService/")
        else {
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyInterService/")
        else {
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyInterService/")
        else {
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
/// let client = DrKeyInterServiceClient::new(conn, config);
/// let response = client.dr_key_level1(request).await?;
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
/// let client = DrKeyInterServiceClient::new(http, config);
/// let response = client.dr_key_level1(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.dr_key_level1(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.dr_key_level1(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct DrKeyInterServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> DrKeyInterServiceClient<T>
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
    /// Call the DRKeyLevel1 RPC. Sends a request to /proto.control_plane.v1.DRKeyInterService/DRKeyLevel1.
    pub async fn dr_key_level1(
        &self,
        request: DRKeyLevel1Request,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyLevel1ResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_level1_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeyLevel1 RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_level1_with_options(
        &self,
        request: DRKeyLevel1Request,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::DRKeyLevel1ResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DR_KEY_INTER_SERVICE_SERVICE_NAME,
                "DRKeyLevel1",
                request,
                options,
            )
            .await
    }
}
/// Full service name for this service.
pub const DR_KEY_INTRA_SERVICE_SERVICE_NAME: &str = "proto.control_plane.v1.DRKeyIntraService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyIntraLevel1` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTRA_SERVICE_DR_KEY_INTRA_LEVEL1_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyIntraService/DRKeyIntraLevel1",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyASHost` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTRA_SERVICE_DR_KEY_AS_HOST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyIntraService/DRKeyASHost",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyHostAS` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTRA_SERVICE_DR_KEY_HOST_AS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyIntraService/DRKeyHostAS",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeyHostHost` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTRA_SERVICE_DR_KEY_HOST_HOST_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyIntraService/DRKeyHostHost",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `DRKeySecretValue` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const DR_KEY_INTRA_SERVICE_DR_KEY_SECRET_VALUE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/proto.control_plane.v1.DRKeyIntraService/DRKeySecretValue",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Server trait for DRKeyIntraService.
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
pub trait DrKeyIntraService: Send + Sync + 'static {
    /// Handle the DRKeyIntraLevel1 RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_intra_level1<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeyIntraLevel1Request>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeyIntraLevel1Response> + Send + use<'a, Self>,
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
    /// Handle the DRKeySecretValue RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn dr_key_secret_value<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DRKeySecretValueRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<DRKeySecretValueResponse> + Send + use<'a, Self>,
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
pub trait DrKeyIntraServiceExt: DrKeyIntraService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: DrKeyIntraService> DrKeyIntraServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeyIntraLevel1",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeyIntraLevel1RequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeyIntraLevel1Request,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_intra_level1(ctx, sreq)
                                .await?
                                .encode::<DRKeyIntraLevel1Response>(format)
                        }
                    })
                },
            )
            .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_INTRA_LEVEL1_SPEC)
            .route_view(
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
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
            .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_AS_HOST_SPEC)
            .route_view(
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
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
            .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_HOST_AS_SPEC)
            .route_view(
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
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
            .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_HOST_HOST_SPEC)
            .route_view(
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeySecretValue",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DRKeySecretValueRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DRKeySecretValueRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.dr_key_secret_value(ctx, sreq)
                                .await?
                                .encode::<DRKeySecretValueResponse>(format)
                        }
                    })
                },
            )
            .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_SECRET_VALUE_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct DrKeyIntraServiceRegisterMarker;
impl<S: DrKeyIntraService> ::connectrpc::ServiceRegister<DrKeyIntraServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as DrKeyIntraServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `DrKeyIntraService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = DrKeyIntraServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct DrKeyIntraServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: DrKeyIntraService> DrKeyIntraServiceServer<T> {
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
impl<T> Clone for DrKeyIntraServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: DrKeyIntraService> ::connectrpc::Dispatcher for DrKeyIntraServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("proto.control_plane.v1.DRKeyIntraService/")?;
        match method {
            "DRKeyIntraLevel1" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_INTRA_LEVEL1_SPEC),
                )
            }
            "DRKeyASHost" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_AS_HOST_SPEC),
                )
            }
            "DRKeyHostAS" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_HOST_AS_SPEC),
                )
            }
            "DRKeyHostHost" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_HOST_HOST_SPEC),
                )
            }
            "DRKeySecretValue" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(DR_KEY_INTRA_SERVICE_DR_KEY_SECRET_VALUE_SPEC),
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyIntraService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "DRKeyIntraLevel1" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeyIntraLevel1Request,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeyIntraLevel1RequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeyIntraLevel1Request,
                    >::from_parts(&req, &body);
                    svc.dr_key_intra_level1(ctx, req)
                        .await?
                        .encode::<DRKeyIntraLevel1Response>(format)
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
            "DRKeySecretValue" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DRKeySecretValueRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::DRKeySecretValueRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DRKeySecretValueRequest,
                    >::from_parts(&req, &body);
                    svc.dr_key_secret_value(ctx, req)
                        .await?
                        .encode::<DRKeySecretValueResponse>(format)
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyIntraService/")
        else {
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyIntraService/")
        else {
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
        let Some(method) = path.strip_prefix("proto.control_plane.v1.DRKeyIntraService/")
        else {
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
/// let client = DrKeyIntraServiceClient::new(conn, config);
/// let response = client.dr_key_intra_level1(request).await?;
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
/// let client = DrKeyIntraServiceClient::new(http, config);
/// let response = client.dr_key_intra_level1(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.dr_key_intra_level1(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.dr_key_intra_level1(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct DrKeyIntraServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> DrKeyIntraServiceClient<T>
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
    /// Call the DRKeyIntraLevel1 RPC. Sends a request to /proto.control_plane.v1.DRKeyIntraService/DRKeyIntraLevel1.
    pub async fn dr_key_intra_level1(
        &self,
        request: DRKeyIntraLevel1Request,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::DRKeyIntraLevel1ResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_intra_level1_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeyIntraLevel1 RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_intra_level1_with_options(
        &self,
        request: DRKeyIntraLevel1Request,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::DRKeyIntraLevel1ResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeyIntraLevel1",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyASHost RPC. Sends a request to /proto.control_plane.v1.DRKeyIntraService/DRKeyASHost.
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
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeyASHost",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyHostAS RPC. Sends a request to /proto.control_plane.v1.DRKeyIntraService/DRKeyHostAS.
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
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeyHostAS",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeyHostHost RPC. Sends a request to /proto.control_plane.v1.DRKeyIntraService/DRKeyHostHost.
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
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeyHostHost",
                request,
                options,
            )
            .await
    }
    /// Call the DRKeySecretValue RPC. Sends a request to /proto.control_plane.v1.DRKeyIntraService/DRKeySecretValue.
    pub async fn dr_key_secret_value(
        &self,
        request: DRKeySecretValueRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::DRKeySecretValueResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.dr_key_secret_value_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DRKeySecretValue RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn dr_key_secret_value_with_options(
        &self,
        request: DRKeySecretValueRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                __buffa::view::DRKeySecretValueResponseView<'static>,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                DR_KEY_INTRA_SERVICE_SERVICE_NAME,
                "DRKeySecretValue",
                request,
                options,
            )
            .await
    }
}
