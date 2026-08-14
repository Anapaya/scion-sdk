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

//! Wrapper type around the extracted SNI from the TLS handshake.
//!
//! Implements logic around the different `domains` we exctract from the SNI.
//!
//! In the wap we differentiate between:
//! 1. `WapSNI`: The entire SNI extracted from the TLS handshake.
//! 2. `gateway_domain`: The domain used to resolve the WebGateway the WAP should connect to.
//! 3. `customer_domain`: The domain of the server that the WAP is forwarding to.

/// The extracted, validated SNI from the TLS handshake.
///
/// The expected format is:
/// `<wap-id>.<wap-namespace>.<customer-domain>`
///
/// Where:
/// wap-id: The ID identifying this WAP instance.
/// wap-namespace: A freely choosen namespace for the WAP.
/// customer-domain: The domain of the server that the WAP is forwarding to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WapSNI(String);

impl WapSNI {
    /// The `<wap-id>.<wap-namespace>.<customer-domain>` format needs at least three labels.
    const MIN_LABELS: usize = 3;

    /// Creates a new SNI from the given string.
    ///
    /// The name is lowercased and then validated, see [`validate_hostname`]. DNS is case
    /// insensitive (RFC 4343), so a peer may send any spelling of the same name. Storing the
    /// canonical one keeps the [`PartialEq`] and [`Hash`] implementations of `WapSNI` case
    /// insensitive as well.
    pub fn new(mut sni: String) -> Result<Self, SniFormatError> {
        sni.make_ascii_lowercase();
        validate_hostname(&sni, Self::MIN_LABELS)?;

        Ok(Self(sni))
    }

    /// Returns the Wap ID from the SNI.
    pub fn wap_id(&self) -> &str {
        self.0
            .split('.')
            .next()
            .expect("SNI has at least 3 segments")
    }

    /// Returns the Wap namespace from the SNI.
    pub fn wap_namespace(&self) -> &str {
        self.0
            .split('.')
            .nth(1)
            .expect("SNI has at least 3 segments")
    }

    /// Returns the customer domain from the SNI.
    ///
    /// e.g. for `id.wap.domain.com` it returns `domain.com`
    pub fn customer_domain(&self) -> CustomerDomainRef<'_> {
        // find the second dot and return the rest of the string after it
        CustomerDomainRef(
            self.0
                .splitn(3, '.')
                .last()
                .expect("SNI has at least 3 segments"),
        )
    }

    /// The suffix appended to the Gateway Domain
    pub const GATEWAY_DOMAIN_SUFFIX: &str = "wg";
    /// The gateway domain is used for the WAP to resolve the WebGateway it should connect to.
    ///
    /// The gateway domain is a combination of:
    /// GATEWAY_DOMAIN_SUFFIX + "-" + wap_id + "." + wap_namespace
    ///
    /// e.g. `id.wap.domain.com` -> `wg-wap.domain.com`
    ///
    /// The derived name is not validated again. It inherits the syntax of the SNI it is built
    /// from, but a one character WAP ID or a namespace close to [`MAX_LABEL_LEN`] can push it
    /// past the length caps that [`validate_hostname`] enforces.
    pub fn gateway_domain(&self) -> GatewayDomain {
        GatewayDomain(format!(
            "{}-{}.{}",
            Self::GATEWAY_DOMAIN_SUFFIX,
            self.wap_namespace(),
            self.customer_domain()
        ))
    }

    /// Returns the full SNI string.
    ///
    /// e.g. for `id.wap.domain.com` it returns `id.wap.domain.com`
    pub fn full_domain(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WapSNI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The domain of the server that the WAP forwards to.
///
/// This is the part of a [`WapSNI`] that follows the WAP ID and the namespace, e.g.
/// `domain.com` for `id.wap.domain.com`. Authorization grants are held per customer domain, so
/// this is the key a client is authorized against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustomerDomain(String);

impl CustomerDomain {
    /// The customer domain of `id.wap.domain.com` is `domain.com`, but a single label is a
    /// valid destination as well.
    const MIN_LABELS: usize = 1;

    /// Creates a customer domain from the given string.
    ///
    /// The name is lowercased and then validated, see [`validate_hostname`].
    pub fn new(mut domain: String) -> Result<Self, SniFormatError> {
        domain.make_ascii_lowercase();
        validate_hostname(&domain, Self::MIN_LABELS)?;

        Ok(Self(domain))
    }

    /// Borrows this domain.
    pub fn as_domain(&self) -> CustomerDomainRef<'_> {
        CustomerDomainRef(&self.0)
    }

    /// Returns the domain as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lets a `HashMap<CustomerDomain, _>` be looked up with a [`CustomerDomainRef`], which does not
/// own the string it points into.
impl std::borrow::Borrow<str> for CustomerDomain {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<CustomerDomainRef<'_>> for CustomerDomain {
    fn from(domain: CustomerDomainRef<'_>) -> Self {
        Self(domain.0.to_owned())
    }
}

impl std::fmt::Display for CustomerDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A borrowed [`CustomerDomain`], as returned by [`WapSNI::customer_domain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomerDomainRef<'a>(&'a str);

impl<'a> CustomerDomainRef<'a> {
    /// Returns the domain as a string slice.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for CustomerDomainRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The domain the WAP resolves to find the WebGateway it connects to.
///
/// This is derived from a [`WapSNI`], see [`WapSNI::gateway_domain`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayDomain(String);

impl GatewayDomain {
    /// A gateway domain is `wg-<wap-namespace>.<customer-domain>`.
    const MIN_LABELS: usize = 2;

    /// Creates a gateway domain from the given string.
    ///
    /// The name is lowercased and then validated, see [`validate_hostname`].
    pub fn new(mut domain: String) -> Result<Self, SniFormatError> {
        domain.make_ascii_lowercase();
        validate_hostname(&domain, Self::MIN_LABELS)?;

        Ok(Self(domain))
    }

    /// Borrows this domain.
    pub fn as_domain(&self) -> GatewayDomainRef<'_> {
        GatewayDomainRef(&self.0)
    }

    /// Returns the domain as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GatewayDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A borrowed [`GatewayDomain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayDomainRef<'a>(&'a str);

impl<'a> GatewayDomainRef<'a> {
    /// Returns the domain as a string slice.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl From<GatewayDomainRef<'_>> for GatewayDomain {
    fn from(domain: GatewayDomainRef<'_>) -> Self {
        Self(domain.0.to_owned())
    }
}

impl std::fmt::Display for GatewayDomainRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maximum length of a DNS name in presentation format.
///
/// RFC 1035 §2.3.4 caps the wire format at 255 octets, which leaves 253 characters for the
/// dotted string.
const MAX_NAME_LEN: usize = 253;
/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Validates that `name` is a lowercase DNS hostname of at least `min_labels` labels.
///
/// The name follows the hostname syntax of RFC 952 and RFC 1123: every label is non-empty, at
/// most [`MAX_LABEL_LEN`] bytes long and contains only `[a-z0-9-]`.
///
/// This is narrower than DNS itself, which puts no restriction on the content of a label
/// (RFC 2181 §11). It matches what RFC 6066 permits in the SNI extension, where the name is
/// carried in its ASCII form: internationalized names arrive as punycode A-labels and there is
/// no trailing dot.
///
/// The names are also interpolated into [`WapSNI::gateway_domain`] and resolved from there, so
/// the restriction keeps characters that terminate an authority component, such as `/`, `?`,
/// `#`, `@` and `:`, out of the derived name.
fn validate_hostname(name: &str, min_labels: usize) -> Result<(), SniFormatError> {
    if name.len() > MAX_NAME_LEN {
        return Err(SniFormatError::NameTooLong);
    }

    if name.split('.').count() < min_labels {
        return Err(SniFormatError::TooFewSegments);
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(SniFormatError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(SniFormatError::LabelTooLong(label.to_owned()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(SniFormatError::InvalidCharacters(label.to_owned()));
        }
    }

    Ok(())
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SniFormatError {
    /// The SNI does not have at least three segments.
    #[error("the SNI is not in the expected format: <wap-id>.<wap-namespace>.<customer-domain>")]
    TooFewSegments,
    /// The SNI is longer than a DNS name may be.
    #[error("the SNI is longer than {max} characters", max = MAX_NAME_LEN)]
    NameTooLong,
    /// The SNI contains an empty segment, e.g. a trailing dot or two consecutive dots.
    #[error("the SNI contains an empty segment")]
    EmptyLabel,
    /// A segment of the SNI is longer than a DNS label may be.
    #[error("the segment {0:?} is longer than {max} characters", max = MAX_LABEL_LEN)]
    LabelTooLong(String),
    /// A segment of the SNI contains characters that are not valid in a hostname.
    #[error("the segment {0:?} contains characters outside of [a-z0-9-]")]
    InvalidCharacters(String),
    /// The SNI is an address literal, which RFC 6066 does not permit.
    #[error("the SNI is an address literal")]
    AddressLiteral,
}

#[cfg(test)]
mod tests {
    use super::{CustomerDomain, GatewayDomain, MAX_LABEL_LEN, SniFormatError, WapSNI};

    fn sni(s: &str) -> Result<WapSNI, SniFormatError> {
        WapSNI::new(s.to_owned())
    }

    #[test]
    fn accepts_valid_names() {
        for name in [
            "id.wap.example.com",
            "id.wap.example.co.uk",
            "id-1.wap-2.example.com",
            "0.0.example.com",
            "id.wap.xn--bcher-kva.example",
            &format!("{}.wap.example.com", "a".repeat(MAX_LABEL_LEN)),
        ] {
            assert!(sni(name).is_ok(), "{name} should be accepted");
        }
    }

    #[test]
    fn splits_into_segments() {
        let sni = sni("id.wap.example.com").expect("valid SNI");

        assert_eq!(sni.wap_id(), "id");
        assert_eq!(sni.wap_namespace(), "wap");
        assert_eq!(sni.customer_domain().as_str(), "example.com");
        assert_eq!(sni.gateway_domain().as_str(), "wg-wap.example.com");
        assert_eq!(sni.full_domain(), "id.wap.example.com");
    }

    #[test]
    fn the_customer_domain_of_an_sni_equals_the_owned_one() {
        let sni = sni("id.wap.example.com").expect("valid SNI");
        let owned = CustomerDomain::new("example.com".to_owned()).expect("valid domain");

        assert_eq!(CustomerDomain::from(sni.customer_domain()), owned);
        assert_eq!(owned.as_domain(), sni.customer_domain());
        assert_eq!(owned.to_string(), "example.com");
    }

    #[test]
    fn domains_are_validated_like_the_sni_but_may_be_shorter() {
        assert!(CustomerDomain::new("backend".to_owned()).is_ok());
        assert_eq!(
            CustomerDomain::new("back end".to_owned()).unwrap_err(),
            SniFormatError::InvalidCharacters("back end".to_owned()),
        );

        assert!(GatewayDomain::new("wg-wap.example.com".to_owned()).is_ok());
        assert_eq!(
            GatewayDomain::new("wg".to_owned()).unwrap_err(),
            SniFormatError::TooFewSegments,
        );
    }

    #[test]
    fn lowercases_the_name() {
        let sni = sni("ID.Wap.Example.COM").expect("valid SNI");

        assert_eq!(sni.full_domain(), "id.wap.example.com");
        assert_eq!(sni, WapSNI::new("id.wap.example.com".to_owned()).unwrap());
    }

    #[test]
    fn rejects_invalid_names() {
        for (name, want) in [
            ("id.wap", SniFormatError::TooFewSegments),
            ("example.com", SniFormatError::TooFewSegments),
            ("", SniFormatError::TooFewSegments),
            ("id.wap.example.com.", SniFormatError::EmptyLabel),
            ("id.wap..com", SniFormatError::EmptyLabel),
            (".wap.example.com", SniFormatError::EmptyLabel),
            (
                "id.wap.example.com/evil",
                SniFormatError::InvalidCharacters("com/evil".to_owned()),
            ),
            (
                "id.wap.example.com:443",
                SniFormatError::InvalidCharacters("com:443".to_owned()),
            ),
            (
                "id.wap.example.com?a=b",
                SniFormatError::InvalidCharacters("com?a=b".to_owned()),
            ),
            (
                "id.wap.example.com#f",
                SniFormatError::InvalidCharacters("com#f".to_owned()),
            ),
            (
                "id.wap@evil.example.com",
                SniFormatError::InvalidCharacters("wap@evil".to_owned()),
            ),
            (
                "id.wap.exämple.com",
                SniFormatError::InvalidCharacters("exämple".to_owned()),
            ),
            (
                "id.wap.example .com",
                SniFormatError::InvalidCharacters("example ".to_owned()),
            ),
        ] {
            assert_eq!(sni(name).unwrap_err(), want, "for {name:?}");
        }
    }

    #[test]
    fn rejects_oversized_names() {
        let long_label = "a".repeat(MAX_LABEL_LEN + 1);
        assert_eq!(
            sni(&format!("{long_label}.wap.example.com")).unwrap_err(),
            SniFormatError::LabelTooLong(long_label),
        );

        // Four labels of 63 characters plus the dots are 255 characters.
        let label = "a".repeat(MAX_LABEL_LEN);
        let long_name = [label.as_str(); 4].join(".");
        assert_eq!(long_name.len(), 255);
        assert_eq!(sni(&long_name).unwrap_err(), SniFormatError::NameTooLong);
    }
}
