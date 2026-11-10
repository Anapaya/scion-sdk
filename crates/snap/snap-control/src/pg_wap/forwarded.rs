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

//! Writes and reads the addresses of a client connection in the `Forwarded` header ([RFC 7239])
//! of a request.
//!
//! [RFC 7239]: https://www.rfc-editor.org/rfc/rfc7239

use std::{borrow::Cow, net::SocketAddr};

use http::{HeaderMap, HeaderValue, header::FORWARDED};

/// The `Forwarded` header of a `CONNECT` request: the connection of the client to the proxy that
/// sent the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedHeader {
    /// The `for` parameter: the address of the client.
    pub for_addr: SocketAddr,
    /// The `by` parameter: the address on the proxy that the client connected to.
    pub by_addr: SocketAddr,
}

/// The error returned by [`ForwardedHeader::from_headers`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardedError {
    /// The header has more than one line or element, so it describes a proxy chain.
    #[error("the Forwarded header holds more than one connection")]
    ProxyChain,
    /// The header does not follow the syntax of RFC 7239, or it has no `for` or `by` address.
    #[error("the Forwarded header is malformed: {0}")]
    Malformed(Cow<'static, str>),
}

impl ForwardedHeader {
    /// Returns the header value with one element that holds the `for` and the `by` parameter.
    ///
    /// [`ForwardedHeader::from_headers`] reads this value back into an equal `ForwardedHeader`.
    pub fn encode(&self) -> HeaderValue {
        let value = format!("for=\"{}\";by=\"{}\"", self.for_addr, self.by_addr);
        HeaderValue::from_str(&value).expect("a socket address is visible ASCII")
    }

    /// Reads the `Forwarded` header in `headers`.
    ///
    /// Returns `None` if the request has no `Forwarded` header.
    ///
    /// Returns [`ForwardedError::ProxyChain`] if the header has more than one line or element,
    /// because the header holds one connection and not a proxy chain.
    ///
    /// Returns [`ForwardedError::Malformed`] if the header does not follow the syntax of RFC 7239.
    ///
    /// The element must have both a `for` and a `by` parameter with an IP address and a port.
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, ForwardedError> {
        // Take the one header line. Several lines form one list, so a second line is a second
        // element.
        let mut lines = headers.get_all(FORWARDED).iter();
        let Some(value) = lines.next() else {
            return Ok(None);
        };
        if lines.next().is_some() {
            return Err(ForwardedError::ProxyChain);
        }
        let value = value
            .to_str()
            .map_err(|_| malformed("the value is not ASCII"))?;

        // Take the one element. The list syntax allows spaces and empty elements around a comma.
        let mut elements = split_unquoted(value, ',')
            .map(str::trim)
            .filter(|element| !element.is_empty());
        let element = elements
            .next()
            .ok_or_else(|| malformed("the value is empty"))?;
        if elements.next().is_some() {
            return Err(ForwardedError::ProxyChain);
        }

        // Read the `for` and the `by` parameter. Parameter names are case-insensitive.
        let mut for_addr = None;
        let mut by_addr = None;
        for pair in split_unquoted(element, ';').filter(|pair| !pair.is_empty()) {
            // Split the pair, and check the syntax of its name and value.
            let Some((name, value)) = pair.split_once('=') else {
                return Err(malformed(format!("the parameter {pair:?} has no value")));
            };
            if !is_token(name) {
                return Err(malformed(format!(
                    "the parameter name {name:?} is not a token"
                )));
            }
            let Some(value) = unquote(value) else {
                return Err(malformed(format!(
                    "the {name} value {value:?} is not a token or a quoted string"
                )));
            };

            // Pick the slot of `for` or `by`. Skip any other parameter.
            let slot = if name.eq_ignore_ascii_case("for") {
                &mut for_addr
            } else if name.eq_ignore_ascii_case("by") {
                &mut by_addr
            } else {
                continue;
            };

            // Store the address. A second `for` or `by` makes the header malformed.
            if slot.is_some() {
                return Err(malformed(format!("the parameter {name:?} occurs twice")));
            }
            let addr = value.parse::<SocketAddr>().map_err(|_| {
                malformed(format!(
                    "the {name} value {value:?} is not an IP address with a port"
                ))
            })?;
            *slot = Some(addr);
        }

        let header = ForwardedHeader {
            for_addr: for_addr.ok_or_else(|| malformed("there is no for parameter"))?,
            by_addr: by_addr.ok_or_else(|| malformed("there is no by parameter"))?,
        };
        return Ok(Some(header));

        fn malformed(reason: impl Into<Cow<'static, str>>) -> ForwardedError {
            ForwardedError::Malformed(reason.into())
        }

        // Splits `value` at each `separator` outside a quoted string.
        fn split_unquoted(value: &str, separator: char) -> impl Iterator<Item = &str> {
            // The closure sees one character per call, so the state carries over between calls.
            let mut quoting = Quoting::default();
            value.split(move |c| quoting.step(c) && c == separator)
        }

        // Returns the content of a quoted string, or a token as it is. Returns `None` for any
        // other value. The content keeps its escapes, because an address holds no escaped
        // characters.
        fn unquote(value: &str) -> Option<&str> {
            // Strip the quotes. A value without quotes must be a token.
            let Some(content) = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            else {
                return is_token(value).then_some(value);
            };

            // Check that only the last quote closes the string. An unescaped quote in the content
            // closes it too early, and a backslash at the end escapes the last quote.
            let mut quoting = Quoting::default();
            let open_to_the_end = value[..value.len() - 1].chars().all(|c| {
                quoting.step(c);
                quoting.quoted
            });
            let is_quoted_string = open_to_the_end && !quoting.escaped;
            is_quoted_string.then_some(content)
        }

        // Tracks whether the characters of a value sit inside a quoted string.
        #[derive(Default)]
        struct Quoting {
            quoted: bool,
            escaped: bool,
        }

        impl Quoting {
            // Steps past `c`. Returns whether `c` sits outside a quoted string and is no quote.
            fn step(&mut self, c: char) -> bool {
                // If the previous character was a backslash in a quoted string, this character
                // is literal. An escaped quote does not end the string.
                if self.escaped {
                    self.escaped = false;
                } else if self.quoted && c == '\\' {
                    self.escaped = true;
                } else if c == '"' {
                    // The same quote character opens and closes a quoted string.
                    self.quoted = !self.quoted;
                } else {
                    return !self.quoted;
                }
                false
            }
        }

        // Checks that `value` is a token of RFC 7230: one or more visible characters without
        // separators.
        fn is_token(value: &str) -> bool {
            let is_token_char =
                |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
            !value.is_empty() && value.bytes().all(is_token_char)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(values: &[&str]) -> Result<Option<ForwardedHeader>, ForwardedError> {
        // Put each value on a header line of its own.
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(FORWARDED, HeaderValue::from_str(value).unwrap());
        }

        ForwardedHeader::from_headers(&headers)
    }

    fn header(for_addr: &str, by_addr: &str) -> ForwardedHeader {
        ForwardedHeader {
            for_addr: for_addr.parse().unwrap(),
            by_addr: by_addr.parse().unwrap(),
        }
    }

    fn assert_malformed(values: &[&str]) {
        let result = read(values);
        assert!(
            matches!(result, Err(ForwardedError::Malformed(_))),
            "{values:?} gave {result:?}"
        );
    }

    mod from_headers {
        use super::*;

        #[test]
        fn should_return_none_without_a_forwarded_header() {
            assert_eq!(read(&[]), Ok(None));
        }

        #[test]
        fn should_read_quoted_ipv4_and_ipv6_addresses_with_case_insensitive_names() {
            assert_eq!(
                read(&[r#"for="192.0.2.10:50000";by="198.51.100.1:443""#]),
                Ok(Some(header("192.0.2.10:50000", "198.51.100.1:443")))
            );
            assert_eq!(
                read(&[r#"By="[2001:db8::1]:443";For="[2001:db8::10]:50000";proto=https"#]),
                Ok(Some(header("[2001:db8::10]:50000", "[2001:db8::1]:443")))
            );
        }

        #[test]
        fn should_return_proxy_chain_for_a_second_element_or_line() {
            // A second element on one line.
            assert_eq!(
                read(&[
                    r#"for="192.0.2.10:50000";by="198.51.100.1:443";host="a,b", for="192.0.2.20:50000""#
                ]),
                Err(ForwardedError::ProxyChain)
            );

            // A second line.
            assert_eq!(
                read(&[
                    r#"for="192.0.2.10:50000";by="198.51.100.1:443""#,
                    r#"for="192.0.2.30:50000";by="198.51.100.1:443""#,
                ]),
                Err(ForwardedError::ProxyChain)
            );
        }

        #[test]
        fn should_reject_a_missing_for_or_by() {
            assert_malformed(&["proto=https"]);
            assert_malformed(&[r#"for="192.0.2.10:50000""#]);
            assert_malformed(&[r#"by="198.51.100.1:443""#]);
        }

        #[test]
        fn should_reject_a_value_without_a_port() {
            assert_malformed(&[r#"for=192.0.2.10;by="198.51.100.1:443""#]);
            assert_malformed(&[r#"for="192.0.2.10:50000";by="[2001:db8::1]""#]);
        }

        #[test]
        fn should_reject_unknown_and_obfuscated_values() {
            assert_malformed(&[r#"for=unknown;by="198.51.100.1:443""#]);
            assert_malformed(&[r#"for="192.0.2.10:50000";by=_hidden"#]);
        }

        #[test]
        fn should_reject_a_parameter_that_occurs_twice() {
            assert_malformed(&[
                r#"for="192.0.2.10:50000";for="192.0.2.20:50000";by="198.51.100.1:443""#,
            ]);
        }

        #[test]
        fn should_reject_a_parameter_without_a_value() {
            assert_malformed(&["for"]);
        }

        #[test]
        fn should_keep_a_separator_after_an_escaped_quote_in_a_quoted_value() {
            // Without the escape, the `;` after `\"` splits `ext`, and `for` gets lost.
            assert_eq!(
                read(&[r#"ext="a\";b";for="192.0.2.10:50000";by="198.51.100.1:443""#]),
                Ok(Some(header("192.0.2.10:50000", "198.51.100.1:443")))
            );
        }

        #[test]
        fn should_reject_an_unbalanced_quote() {
            assert_malformed(&[r#"for="192.0.2.10:50000;by="198.51.100.1:443""#]);
        }

        #[test]
        fn should_reject_an_unescaped_quote_inside_a_quoted_value() {
            assert_malformed(&[r#"for="192.0.2.10:50000";by="198.51.100.1:443";ext="a"b""#]);
        }

        #[test]
        fn should_reject_a_quoted_value_whose_last_quote_is_escaped() {
            assert_malformed(&[r#"for="192.0.2.10:50000";by="198.51.100.1:443";ext="a\""#]);
        }

        #[test]
        fn should_return_malformed_for_only_empty_elements() {
            assert_malformed(&[","]);
            assert_malformed(&[" , , "]);
        }

        #[test]
        fn should_reject_a_non_ascii_value() {
            // Build the header from bytes, because `read` takes only ASCII strings.
            let mut headers = HeaderMap::new();
            headers.insert(FORWARDED, HeaderValue::from_bytes(b"for=\"\xff\"").unwrap());

            let result = ForwardedHeader::from_headers(&headers);
            assert!(
                matches!(result, Err(ForwardedError::Malformed(_))),
                "{result:?}"
            );
        }

        #[test]
        fn should_reject_an_unquoted_address_with_a_port() {
            assert_malformed(&[r#"for=192.0.2.10:50000;by="198.51.100.1:443""#]);
        }

        #[test]
        fn should_reject_spaces_around_the_equals_sign_and_the_semicolon() {
            assert_malformed(&[r#"for ="192.0.2.10:50000";by="198.51.100.1:443""#]);
            assert_malformed(&[r#"for= "192.0.2.10:50000";by="198.51.100.1:443""#]);
            assert_malformed(&[r#"for="192.0.2.10:50000" ;by="198.51.100.1:443""#]);
            assert_malformed(&[r#"for="192.0.2.10:50000"; by="198.51.100.1:443""#]);
        }

        #[test]
        fn should_reject_a_parameter_name_with_a_space_also_for_an_unknown_parameter() {
            assert_malformed(&[r#"for="192.0.2.10:50000";by="198.51.100.1:443";ext =a"#]);
        }

        #[test]
        fn should_accept_empty_pairs() {
            assert_eq!(
                read(&[r#"for="192.0.2.10:50000";;by="198.51.100.1:443";"#]),
                Ok(Some(header("192.0.2.10:50000", "198.51.100.1:443")))
            );
        }

        #[test]
        fn should_accept_spaces_and_empty_elements_around_a_comma() {
            assert_eq!(
                read(&[r#", for="192.0.2.10:50000";by="198.51.100.1:443" ,"#]),
                Ok(Some(header("192.0.2.10:50000", "198.51.100.1:443")))
            );
        }
    }

    mod round_trip {
        use super::*;

        fn assert_round_trip(for_addr: &str, by_addr: &str) {
            // Write the header as the WAP does.
            let sent = header(for_addr, by_addr);
            let mut headers = HeaderMap::new();
            headers.insert(FORWARDED, sent.encode());

            assert_eq!(ForwardedHeader::from_headers(&headers), Ok(Some(sent)));
        }

        #[test]
        fn should_read_back_an_equal_header_for_ipv4_addresses() {
            assert_round_trip("192.0.2.10:50000", "198.51.100.1:443");
        }

        #[test]
        fn should_read_back_an_equal_header_for_ipv6_addresses() {
            assert_round_trip("[2001:db8::10]:50000", "[2001:db8::1]:443");
        }

        #[test]
        fn should_read_back_an_equal_header_for_an_ipv4_mapped_client_address() {
            assert_round_trip("[::ffff:192.0.2.10]:50000", "[2001:db8::1]:443");
        }
    }
}
