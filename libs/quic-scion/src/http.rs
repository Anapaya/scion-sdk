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

//! Trait for HTTP services.

use http::{Request, Response};
use http_body::Body as HttpBody;

/// Trait for HTTP services.
pub trait HttpService {
    /// The request body type.
    type Body: HttpBody;
    /// The response body type.
    type ResponseBody: HttpBody;

    /// Calls the HTTP service with the given request and returns a future that
    /// resolves to a response.
    fn call(
        &self,
        req: Request<Self::Body>,
    ) -> impl std::future::Future<Output = Response<Self::ResponseBody>> + Send;
}
