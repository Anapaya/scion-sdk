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

//! SCION Trust Store

use std::{collections::BTreeMap, fmt::Debug, hash::Hash, ops::Deref, path::Path};

use anyhow::{Context, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use ecdsa::{SigningKey, signature::rand_core::OsRng};
use p256::{
    NistP256,
    pkcs8::{AssociatedOid, EncodePrivateKey},
};
use pem::Pem;
use rcgen::Issuer;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use scion_proto::address::{Isd, IsdAsn};
use scion_sdk_trc::trc::{ParseTrcError, Trc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utoipa::{PartialSchema, ToSchema};
use x509_cert::{der::Decode, ext::pkix::SubjectKeyIdentifier};

use crate::network::scion::trust_store::dir_parser::trust_store_from_directory;
mod dir_parser;
pub mod issuing;

/// Pocket SCION trust store
// XXX(ake): The Trust store should be merged with the topology at some point
// Currently this is only seperate as we can't generate TRCs
#[derive(Debug, Default, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
pub struct TrustStore {
    /// The ISD trust stores, keyed by ISD
    pub isds: BTreeMap<Isd, IsdTrustStore>,
}
impl TrustStore {
    /// Creates a new, empty trust store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads the trust store from a directory containing the TRCs and CA certificates
    #[doc(hidden)]
    pub fn from_scion_pki_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        trust_store_from_directory(path)
    }
    /// Adds a new ISD trust store to the trust store, containing the TRC and CA certificates for
    /// the ISD.
    ///
    /// Returns an error if the IsdTrustStore for the given ISD already exists or if there was an
    /// error parsing the TRC from the raw bytes.
    pub fn add_isd_trust_store(&mut self, raw_trc: Vec<u8>) -> anyhow::Result<&mut IsdTrustStore> {
        let trc =
            StoreTrc::from_raw(raw_trc.clone()).context("failed to parse TRC from raw bytes")?;

        let isd: Isd = trc.trc.id().isd.into();

        match self.isds.entry(isd) {
            std::collections::btree_map::Entry::Occupied(_) => {
                anyhow::bail!("ISD {} already exists in trust store", isd)
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let trust_store = IsdTrustStore {
                    isd,
                    trc,
                    ca_certs: Default::default(),
                    as_certs: Default::default(),
                };
                Ok(entry.insert(trust_store))
            }
        }
    }

    /// Since we can't create TRCs, this function adds a mock TRC for the given ISD for testing.
    pub(crate) fn add_mock_isd_trust_store(
        &mut self,
        isd: Isd,
    ) -> anyhow::Result<&mut IsdTrustStore> {
        const MOCK_TRC: &str = include_str!("./trust_store/mock_trc.pem");

        let trc = StoreTrc {
            trc: Trc::parse_from_pem(MOCK_TRC.as_bytes()).expect("should succeed on static data"),
            raw: MOCK_TRC.as_bytes().to_vec(),
        };

        match self.isds.entry(isd) {
            std::collections::btree_map::Entry::Occupied(_) => {
                anyhow::bail!("ISD {} already exists in trust store", isd)
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let trust_store = IsdTrustStore {
                    isd,
                    trc,
                    ca_certs: Default::default(),
                    as_certs: Default::default(),
                };
                Ok(entry.insert(trust_store))
            }
        }
    }

    /// Adds an AS key pair for the given ISD-AS to the trust store.
    ///
    /// If the ISD for the given ISD-AS does not exist in the trust store, an error is returned.
    pub fn add_as_key_pair(
        &mut self,
        isd_as: IsdAsn,
        key_pair: CertifiedKeyPair,
    ) -> anyhow::Result<()> {
        let isd = isd_as.isd();
        self.isds
            .get_mut(&isd)
            .context(format!("ISD {} not found in trust store", isd))?
            .add_as_key_pair(isd_as, key_pair)
    }

    /// Adds an CA identity for the given ISD-AS to the trust store.
    ///
    /// If the ISD for the given ISD-AS does not exist in the trust store, an error is returned.
    pub fn add_as_ca(
        &mut self,
        isd_as: IsdAsn,
        root: CertifiedKeyPair,
        intermediary: CertifiedKeyPair,
    ) -> anyhow::Result<()> {
        let isd = isd_as.isd();
        self.isds
            .get_mut(&isd)
            .context(format!("ISD {} not found in trust store", isd))?
            .add_as_ca(isd_as, root, intermediary)
    }

    /// Returns the TRC for the given ISD, if it exists in the trust store.
    pub fn trc(&self, isd: &Isd) -> Option<&Trc> {
        self.isds.get(isd).map(|store| &store.trc.trc)
    }

    /// Returns the CA certificates for the given ISD, if they exist in the trust store.
    pub fn ca_certs(&self, isd: &Isd) -> Option<&BTreeMap<IsdAsn, IsdCa>> {
        self.isds.get(isd).map(|store| &store.ca_certs)
    }

    /// Returns the CA certificate for the given ISD-AS, if it exists in the trust store.
    pub fn ca_cert(&self, isd_asn: &IsdAsn) -> Option<&IsdCa> {
        self.isds
            .get(&isd_asn.isd())
            .map(|store| &store.ca_certs)
            .and_then(|cas| cas.get(isd_asn))
    }

    /// Returns the identity for the given ISD-AS, if it exists in the trust store.
    pub fn as_key_pair(&self, isd_asn: &IsdAsn) -> Option<&CertifiedKeyPair> {
        self.isds
            .get(&isd_asn.isd())
            .map(|store| &store.as_certs)
            .and_then(|certs| certs.get(isd_asn))
    }

    fn ensure_or_mock_trc(&mut self, isd: Isd) {
        if self.trc(&isd).is_none() {
            self.add_mock_isd_trust_store(isd)
                .expect("no isd exists, so this should succeed");
        }
    }

    fn add_ca_root(&mut self, isd: Isd, ca: IsdCa) -> anyhow::Result<()> {
        let Some(isd) = self.isds.get_mut(&isd) else {
            bail!("ISD {} not found in trust store", isd)
        };

        match isd.ca_certs.entry(ca.isd_as) {
            std::collections::btree_map::Entry::Occupied(_) => {
                anyhow::bail!("CA for ISD-AS {} already exists in trust store", ca.isd_as)
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(ca);
                Ok(())
            }
        }

        // Note: This would also have to be added to the TRC, but we can't generate TRCs ourselves
        // yet
    }

    /// Get the CA for the given ISD-AS, or issues a new one if it does not exist in the trust
    /// store.
    pub fn get_or_issue_ca(&mut self, isd_asn: IsdAsn) -> &IsdCa {
        if self.ca_cert(&isd_asn).is_some() {
            // Compiler can't determine that self is not borrowed after the if block
            return self.ca_cert(&isd_asn).expect("Ca should exist");
        }

        let root_key = SigningKey::<NistP256>::random(&mut OsRng);
        let root_key = PrivatePkcs8KeyDer::from(
            root_key
                .to_pkcs8_der()
                .expect("Should not fail with static input")
                .as_bytes()
                .to_vec(),
        );
        let root_rcgen_key =
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&root_key, &rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("Should not fail with static input");
        let root_key: PrivateKeyDer<'static> = root_key.into();

        let root_cert = issuing::create_ca_root_cert(&root_key, isd_asn)
            .expect("should succeed on valid key and ISD-ASN");

        let intermediary_key = SigningKey::<NistP256>::random(&mut OsRng);
        let intermediary_key = PrivatePkcs8KeyDer::from(
            intermediary_key
                .to_pkcs8_der()
                .expect("Should not fail with static input")
                .as_bytes()
                .to_vec(),
        );
        let intermediary_key: PrivateKeyDer<'static> = intermediary_key.into();

        let root_issuer = Issuer::from_ca_cert_der(&root_cert, &root_rcgen_key)
            .expect("Should not fail with static input");
        let intermediary_cert = issuing::create_ca_cert(&intermediary_key, &root_issuer, isd_asn)
            .expect("should succeed on valid key and ISD-ASN");

        let ca = IsdCa {
            isd_as: isd_asn,
            root: CertifiedKeyPair {
                key: StoreKeyDer::new(root_key),
                cert: StoreCertificateDer::new(root_cert),
            },
            intermediary: CertifiedKeyPair {
                key: StoreKeyDer::new(intermediary_key),
                cert: StoreCertificateDer::new(intermediary_cert),
            },
        };

        self.ensure_or_mock_trc(isd_asn.isd());
        self.add_ca_root(isd_asn.isd(), ca)
            .expect("CA should not already exist, so this should succeed");

        self.ca_cert(&isd_asn)
            .expect("CA should exist after adding it to the trust store")
    }

    /// Get the AS identity for the given ISD-AS, or issues a new one if it does not exist in the
    /// trust store.
    pub fn get_or_issue_as_key_pair(&mut self, isd_asn: IsdAsn) -> &CertifiedKeyPair {
        if self.as_key_pair(&isd_asn).is_some() {
            // Compiler can't determine that self is not borrowed after the if block
            return self
                .as_key_pair(&isd_asn)
                .expect("AS key pair should exist");
        }

        let key = SigningKey::<NistP256>::random(&mut OsRng);
        let key = PrivatePkcs8KeyDer::from(
            key.to_pkcs8_der()
                .expect("Should not fail with static input")
                .as_bytes()
                .to_vec(),
        );

        let key: PrivateKeyDer<'static> = key.into();

        let ca = self.get_or_issue_ca(isd_asn);
        let rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
            &ca.intermediary.key.0,
            &rcgen::PKCS_ECDSA_P256_SHA256, // TODO: this should be determined by the key type
        )
        .expect("should succeed with valid key");

        let issuer = Issuer::from_ca_cert_der(&ca.intermediary.cert.0, &rcgen_key)
            .expect("Should not fail with static input");

        let cert = issuing::create_as_cert(&key, &issuer, isd_asn)
            .expect("should succeed with valid key and ISD-ASN");

        self.add_as_key_pair(
            isd_asn,
            CertifiedKeyPair {
                key: StoreKeyDer::new(key),
                cert: StoreCertificateDer::new(cert),
            },
        )
        .expect("All previous steps ensure that the ISD exists and the AS key pair does not exist, so this should succeed");
        self.as_key_pair(&isd_asn)
            .expect("AS key pair should exist after adding it to the trust store")
    }
}

/// Isd specific trust store, containing the TRC and CA certificates for the ISD
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
pub struct IsdTrustStore {
    /// The ISD for this trust store
    pub isd: Isd,
    /// The TRC of this ISD
    pub trc: StoreTrc,
    /// The CA certificates for this ISD, keyed by ISD-AS
    pub ca_certs: BTreeMap<IsdAsn, IsdCa>,
    /// The AS certificates for this ISD, keyed by ISD-AS
    pub as_certs: BTreeMap<IsdAsn, CertifiedKeyPair>,
}
impl IsdTrustStore {
    /// Adds a CA for the given ISD-AS into the trust store.
    ///
    /// Returns an error if a CA for the given ISD-AS already exists in the trust store.
    pub fn add_as_ca(
        &mut self,
        isd_as: IsdAsn,
        root: CertifiedKeyPair,
        intermediary: CertifiedKeyPair,
    ) -> anyhow::Result<()> {
        match self.ca_certs.entry(isd_as) {
            std::collections::btree_map::Entry::Occupied(_) => {
                anyhow::bail!("CA for ISD-AS {} already exists in trust store", isd_as)
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let ca = IsdCa {
                    isd_as,
                    root,
                    intermediary,
                };
                entry.insert(ca);
                Ok(())
            }
        }
    }

    /// Adds an AS certificate for the given ISD-AS to the trust store, containing the certificate
    /// and private key for the AS.
    ///
    /// Returns an error if an AS certificate for the given ISD-AS already exists in the trust
    /// store.
    pub fn add_as_key_pair(
        &mut self,
        isd_as: IsdAsn,
        key_pair: CertifiedKeyPair,
    ) -> anyhow::Result<()> {
        if self.as_certs.contains_key(&isd_as) {
            anyhow::bail!(
                "AS certificate for ISD-AS {} already exists in trust store",
                isd_as
            );
        }

        self.as_certs.insert(isd_as, key_pair);

        Ok(())
    }
}

/// CA certificate for an ISD-AS, containing the certificate and private key for the CA, as well as
/// the root certificate for the ISD
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
pub struct IsdCa {
    /// The ISD-AS for this CA
    pub isd_as: IsdAsn,
    /// The root identity for this CA
    pub root: CertifiedKeyPair,
    /// The intermediary identity for this CA
    pub intermediary: CertifiedKeyPair,
}
/// Struct containing a certificate and private key for an AS, used for both AS certificates and
/// CA certificates
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Hash, PartialEq, Eq)]
pub struct CertifiedKeyPair {
    /// Private Key
    pub key: StoreKeyDer,
    /// Certificate
    pub cert: StoreCertificateDer,
}

/// TRC for an ISD, containing the parsed TRC and the raw bytes of the TRC for
/// serialization/deserialization
///
/// Serialized as Base64 string until we can serialize and deserialize the TRC directly
#[derive(Clone)]
pub struct StoreTrc {
    /// The parsed TRC for this ISD
    pub trc: Trc,
    /// The raw bytes of the TRC, used for serialization and deserialization
    pub raw: Vec<u8>,
}
impl StoreTrc {
    /// Parses the bytes to create a StoreTrc
    pub fn from_raw(raw_data: Vec<u8>) -> Result<StoreTrc, ParseTrcError> {
        let trc = Trc::parse_from_pem(&raw_data)?;
        Ok(StoreTrc { trc, raw: raw_data })
    }
}
impl Debug for StoreTrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreTrc").field("trc", &self.trc).finish()
    }
}
impl PartialSchema for StoreTrc {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        String::schema()
    }
}
impl ToSchema for StoreTrc {
    fn schemas(
        _schemas: &mut Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) {
        // No additional schemas needed since StoreTrc is represented as a base64 string
    }
}
impl PartialEq for StoreTrc {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl Eq for StoreTrc {}
impl Hash for StoreTrc {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Serialize for StoreTrc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let base64_str = BASE64_STANDARD.encode(&self.raw);
        serializer.serialize_str(&base64_str)
    }
}
impl<'de> Deserialize<'de> for StoreTrc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(&base64_str)
            .map_err(serde::de::Error::custom)?;
        let trc = Trc::parse_from_pem(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("error parsing TRC from bytes: {}", e))
        })?;
        Ok(StoreTrc { trc, raw: bytes })
    }
}

#[derive(Debug, ToSchema, Clone, PartialEq, Eq)]
#[schema(value_type = String)]
/// Wrapper around CertificateDer
pub struct StoreCertificateDer(CertificateDer<'static>);
impl StoreCertificateDer {
    /// Creates a new StoreCertificateDer from the given CertificateDer
    pub fn new(cert_der: CertificateDer<'static>) -> Self {
        StoreCertificateDer(cert_der)
    }

    /// Creates a new StoreCertificateDer from the given DER-encoded certificate bytes
    pub fn new_from_slice(cert_der: &[u8]) -> anyhow::Result<Self> {
        let cert_der = CertificateDer::from(cert_der); // TODO: this should check that this is valid
        Ok(StoreCertificateDer(cert_der.into_owned()))
    }

    /// Converts the StoreCertificateDer to PEM format
    pub fn to_pem(&self) -> String {
        let pem = Pem::new("CERTIFICATE", self.0.as_ref().to_vec());
        pem::encode(&pem)
    }

    /// Extracts the Subject Key Identifier from the certificate, if it exists.
    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        let cert = x509_cert::Certificate::from_der(self.0.as_ref())
            .expect("should be valid since we created it from valid DER bytes");
        let extensions = cert.tbs_certificate.extensions?;
        let r = extensions
            .iter()
            .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)?;

        Some(
            SubjectKeyIdentifier::from_der(r.extn_value.as_bytes())
                .ok()?
                .0
                .into_bytes(),
        )
    }
}
impl Deref for StoreCertificateDer {
    type Target = CertificateDer<'static>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Serialize for StoreCertificateDer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = &self.0;
        let base64_str = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&base64_str)
    }
}
impl<'de> Deserialize<'de> for StoreCertificateDer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(&base64_str)
            .map_err(serde::de::Error::custom)?;
        let der = StoreCertificateDer::new_from_slice(&bytes).map_err(serde::de::Error::custom)?; // TODO: this should check that this is valid
        Ok(der)
    }
}
impl Hash for StoreCertificateDer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

#[serde_as]
#[derive(Debug, ToSchema, PartialEq, Eq)]
#[schema(value_type = String)]
/// Wrapper around PrivateKeyDer
pub struct StoreKeyDer(PrivateKeyDer<'static>);
impl StoreKeyDer {
    /// Creates a new StoreKeyDer from the given PrivateKeyDer
    pub fn new(key_der: PrivateKeyDer<'static>) -> Self {
        StoreKeyDer(key_der)
    }

    /// Creates a new StoreKeyDer from the given DER-encoded private key bytes
    pub fn new_from_slice(key_der: &[u8]) -> anyhow::Result<Self> {
        let key_der = PrivateKeyDer::try_from(key_der)
            .map_err(|e| anyhow::anyhow!("error converting key from bytes: {}", e))?;
        Ok(StoreKeyDer(key_der.clone_key()))
    }
}
impl Clone for StoreKeyDer {
    fn clone(&self) -> Self {
        StoreKeyDer(self.0.clone_key())
    }
}
impl Deref for StoreKeyDer {
    type Target = PrivateKeyDer<'static>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Hash for StoreKeyDer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.secret_der().hash(state);
    }
}
impl Serialize for StoreKeyDer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.secret_der();
        let base64_str = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&base64_str)
    }
}
impl<'de> Deserialize<'de> for StoreKeyDer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(&base64_str)
            .map_err(serde::de::Error::custom)?;
        let key_der = PrivateKeyDer::try_from(bytes).map_err(|e| {
            serde::de::Error::custom(format!("error converting key from bytes: {}", e))
        })?;
        Ok(StoreKeyDer(key_der))
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::pem::PemObject;
    use scion_proto::address::Asn;

    use super::*;

    #[test]
    pub fn should_create_valid_pem() {
        let cert = rcgen::generate_simple_self_signed(vec![]).unwrap();
        let der = cert.cert.der();
        let store_der = StoreCertificateDer::new_from_slice(der).unwrap();
        let pem = store_der.to_pem();

        let parsed_der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();

        let a: &[u8] = parsed_der.as_ref();
        let b: &[u8] = der;
        assert_eq!(a, b);
    }

    #[test]
    pub fn should_rountrip_serialization() {
        let mut store = TrustStore::new();
        store.get_or_issue_as_key_pair(IsdAsn::new(Isd(1), Asn(1)));
        store.get_or_issue_as_key_pair(IsdAsn::new(Isd(2), Asn(2)));

        let serial = serde_json::to_string(&store).expect("should serialize");
        let deserialized: TrustStore = serde_json::from_str(&serial).expect("should deserialize");
        assert_eq!(store, deserialized);
    }

    #[test]
    pub fn should_extract_subject_key_id() {
        let pair = TrustStore::new()
            .get_or_issue_as_key_pair(IsdAsn::new(Isd(1), Asn(1)))
            .clone();

        pair.cert.subject_key_id().unwrap();
    }
}
