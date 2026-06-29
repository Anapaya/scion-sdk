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

//! Header-list conversions shared by the HTTP/3 server and client.

use squiche::h3::{Header, NameValue};

/// Converts an HTTP/3 header list into an `http::HeaderMap`, skipping
/// pseudo-headers (used for trailing header sections).
pub(crate) fn headers_to_map(list: &[Header]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for header in list {
        let name = header.name();
        if name.starts_with(b":") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name),
            http::HeaderValue::from_bytes(header.value()),
        ) {
            map.append(name, value);
        }
    }
    map
}

/// Converts an `http::HeaderMap` into an HTTP/3 header list, skipping any
/// pseudo-headers (a trailing header section must not contain them).
pub(crate) fn header_map_to_h3(map: &http::HeaderMap) -> Vec<Header> {
    map.iter()
        .filter(|(name, _)| !name.as_str().starts_with(':'))
        .map(|(name, value)| Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
}
