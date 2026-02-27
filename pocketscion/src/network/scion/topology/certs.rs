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

//! Helper to create certificates for the SCION topology.

use anyhow::Context;
use rcgen::{DistinguishedName, ExtendedKeyUsagePurpose, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use scion_proto::address::IsdAsn;

const RELATIVE_DISTINGUISHED_NAME_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 55324, 1, 2, 1];
const SCION_ROOT_CA_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 55324, 1, 3, 3];

/// Creates a root CA certificate for the given ISD-AS.
/// The certificate is self-signed with the given key.
pub fn create_ca_root_cert(
    key: &PrivateKeyDer,
    isd_asn: IsdAsn,
) -> anyhow::Result<CertificateDer<'static>> {
    let key: KeyPair = key
        .try_into()
        .context("failed to convert private key to rcgen key pair")?;

    let mut param =
        rcgen::CertificateParams::new(vec![]).context("failed to create certificate params")?;

    param.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);

    let mut dn = DistinguishedName::new();
    dn.push(
        rcgen::DnType::CommonName,
        format!("{} Root Cerificate - GEN I", isd_asn),
    );
    dn.push(
        rcgen::DnType::CustomDnType(RELATIVE_DISTINGUISHED_NAME_OID.to_vec()),
        isd_asn.to_string(),
    );
    param.distinguished_name = dn;

    param.insert_extended_key_usage(ExtendedKeyUsagePurpose::TimeStamping);
    param.insert_extended_key_usage(ExtendedKeyUsagePurpose::Other(SCION_ROOT_CA_OID.to_vec()));

    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(1));

    let issuer = Issuer::new(param.clone(), &key);
    let cert = param
        .signed_by(&key, &issuer)
        .context("failed to sign root CA certificate")?;

    Ok(cert.into())
}

/// Creates a CA certificate for the given ISD-AS, signed by the given issuer.
/// The certificate is signed with the given key.
pub fn create_core_ca_cert<S: rcgen::SigningKey>(
    key: &PrivateKeyDer,
    issuer: &Issuer<S>,
    isd_asn: IsdAsn,
) -> anyhow::Result<CertificateDer<'static>> {
    let key: KeyPair = key
        .try_into()
        .context("failed to convert private key to rcgen key pair")?;

    let mut param =
        rcgen::CertificateParams::new(vec![]).context("failed to create certificate params")?;

    param.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);

    let mut dn = DistinguishedName::new();
    dn.push(
        rcgen::DnType::CommonName,
        format!("{} AS Certificate - GEN I", isd_asn),
    );
    dn.push(
        rcgen::DnType::CustomDnType(RELATIVE_DISTINGUISHED_NAME_OID.to_vec()),
        isd_asn.to_string(),
    );
    param.distinguished_name = dn;

    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(1));
    param.use_authority_key_identifier_extension = true;

    let cert = param
        .signed_by(&key, issuer)
        .context("failed to sign core CA certificate")?;

    Ok(cert.into())
}

/// Creates an AS certificate for the given ISD-AS. The certificate is signed by the given issuer.
pub fn create_as_cert<S: rcgen::SigningKey>(
    key: &PrivateKeyDer,
    issuer: &Issuer<S>,
    isd_asn: IsdAsn,
) -> anyhow::Result<CertificateDer<'static>> {
    let key: KeyPair = key
        .try_into()
        .context("error converting private key to rcgen key pair")?;

    let mut param = rcgen::CertificateParams::new(vec!["test".to_string()])
        .context("failed to create certificate params")?;

    param
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, isd_asn.to_string());
    dn.push(
        rcgen::DnType::CustomDnType(RELATIVE_DISTINGUISHED_NAME_OID.to_vec()),
        isd_asn.to_string(),
    );
    param.distinguished_name = dn;

    param.insert_extended_key_usage(ExtendedKeyUsagePurpose::ServerAuth);
    param.insert_extended_key_usage(ExtendedKeyUsagePurpose::ClientAuth);
    param.insert_extended_key_usage(ExtendedKeyUsagePurpose::TimeStamping);

    param.use_authority_key_identifier_extension = true;
    param.is_ca = rcgen::IsCa::ExplicitNoCa;

    let cert = param
        .signed_by(&key, issuer)
        .context("error signing certificate with rcgen")?;

    Ok(cert.into())
}
