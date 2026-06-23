// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//! # TRC
//!
//! The [Trc] struct represents a Trust Root Certificate (TRC) as defined in
//! <https://docs.scion.org/en/latest/cryptography/trc.html>.
//!
//! Provides functionality to parse a TRC from PEM encoded data, access its fields, and check if a
//! given AS is a core AS.

use std::{
    str::FromStr,
    time::{SystemTime, SystemTimeError},
};

use cms::{
    content_info::{CmsVersion, ContentInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos},
};
use der::{
    Any, Decode, DecodeValue, Encode, EncodeValue, PemReader, Sequence, SliceReader,
    asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString, PrintableString},
    pem::LineEnding,
};
use sciparse::{
    address::AddressParseError,
    identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
};
use thiserror::Error;

/// OID for the CMS SignedData content type (RFC 5652, `id-signedData`).
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// Dummy OID for the SCION TRC payload content type
/// (https://docs.scion.org/en/latest/cryptography/trc.html).
const ID_TRC_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.12345.1.2.3");

/// Trust root certificate (TRC).
#[derive(Debug, Clone)]
pub struct Trc {
    id: TrcId,
    trc_payload: TrcPayload,
    core_ases: Vec<IsdAsn>,
}

impl Trc {
    /// Parse a TRC from PEM encoded data.
    pub fn parse_from_pem(data: &[u8]) -> Result<Self, ParseTrcError> {
        let mut pem_reader = PemReader::new(data)?;

        let content_info = ContentInfo::decode(&mut pem_reader)?;

        let mut inner_bytes = SliceReader::new(content_info.content.value())?;
        let signed_data =
            SignedData::decode_value(&mut inner_bytes, content_info.content.header()?)?;

        let payload_bytes = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .unwrap()
            .value();

        let mut payload_bytes = SliceReader::new(payload_bytes)?;
        let trc_payload = TrcPayload::decode(&mut payload_bytes)?;

        let id = TrcId::from_trc_payload(&trc_payload.id)?;

        let core_ases: Vec<IsdAsn> = trc_payload
            .core_ases
            .iter()
            .map(|s| -> Result<IsdAsn, ParseTrcError> {
                let isd = der_int_to_isd(&trc_payload.id.isd)?;
                let asn = Asn::from_str(s.as_str())?;
                Ok(IsdAsn::new(isd, asn))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            id,
            trc_payload,
            core_ases,
        })
    }

    /// Returns true if the given AS is a core AS.
    pub fn is_core(&self, asn: IsdAsn) -> bool {
        self.core_ases.contains(&asn)
    }

    /// Returns an iterator over the core ASes.
    pub fn core_ases(&self) -> impl Iterator<Item = IsdAsn> {
        self.core_ases.iter().cloned()
    }

    /// Returns the TRC payload.
    pub fn raw_trc_payload(&self) -> &TrcPayload {
        &self.trc_payload
    }

    /// Returns the TRC ID.
    pub fn id(&self) -> &TrcId {
        &self.id
    }

    /// Builds a minimal, unsigned TRC from the given ID and core ASes.
    ///
    /// The resulting TRC contains only the information required for a consumer to determine the
    /// core ASes of an ISD (the TRC ID and the list of core ASes). It is **not** signed and does
    /// not contain any certificates, so it must only be used in contexts where signature
    /// verification is not performed (for example, local test harnesses).
    pub fn new_unsigned(
        id: TrcId,
        core_ases: &[IsdAsn],
        not_before: SystemTime,
        not_after: SystemTime,
        description: &str,
    ) -> Result<Self, BuildTrcError> {
        let core_ases: Vec<IsdAsn> = core_ases.to_vec();

        let core_ases_str = core_ases
            .iter()
            .map(|ia| PrintableString::new(&ia.asn().to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        let trc_payload = TrcPayload {
            version: u64_to_int(1)?,
            id: TrcIdPayload {
                isd: u64_to_int(u64::from(id.isd.to_u16()))?,
                serial_number: u64_to_int(id.serial)?,
                base_number: u64_to_int(id.base)?,
            },
            validity: Validity {
                not_before: system_time_to_generalized(not_before)?,
                not_after: system_time_to_generalized(not_after)?,
            },
            grace_period: u64_to_int(0)?,
            no_trust_reset: false,
            votes: Vec::new(),
            voting_quorum: u64_to_int(1)?,
            core_ases: core_ases_str,
            authoritative_ases: Vec::new(),
            description: description.to_string(),
            certificates: Vec::new(),
        };

        Ok(Self {
            id,
            trc_payload,
            core_ases,
        })
    }

    /// Encodes the TRC as PEM.
    ///
    /// The TRC is wrapped in an unsigned CMS `SignedData` envelope (empty digest algorithms,
    /// certificates and signer infos) and PEM-encoded with the `TRC` label.
    pub fn to_pem(&self) -> Result<String, EncodingError> {
        let payload_der = self.trc_payload.to_der()?;
        let econtent = Any::encode_from(&OctetString::new(payload_der)?)?;

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: Default::default(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_TRC_CONTENT,
                econtent: Some(econtent),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(Default::default()),
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data)?,
        };

        let der = content_info.to_der()?;
        der::pem::encode_string("TRC", LineEnding::LF, &der).map_err(EncodingError::Pem)
    }
}

/// Errors produced when DER- or PEM-encoding a TRC.
#[derive(Debug, Error)]
pub enum EncodingError {
    /// DER encoding error.
    #[error("error producing DER encoding: {0}")]
    Der(#[from] der::Error),
    /// PEM encoding error.
    #[error("error encoding PEM: {0}")]
    Pem(der::pem::Error),
}

/// TRC parsing errors.
#[derive(Debug, Error)]
pub enum ParseTrcError {
    /// DER decoding error.
    #[error("error parsing DER encoding: {0}")]
    DerError(der::Error),
    /// Invalid ISD-AS format.
    #[error("could not parse ISD-AS: {0:?}")]
    AddressParseError(#[from] AddressParseError),
    /// Invalid ISD.
    #[error("invalid ISD")]
    InvalidIsd(),
    /// Invalid integer value.
    #[error("invalid integer value")]
    InvalidIntegerValue(),
}

/// TRC writing errors.
#[derive(Debug, Error)]
pub enum BuildTrcError {
    /// DER encoding error.
    #[error("error producing DER encoding: {0}")]
    DerError(#[from] der::Error),
    /// The provided time is before the Unix epoch.
    #[error("time is before the unix epoch: {0}")]
    InvalidTime(#[from] SystemTimeError),
}

// XXX(dsd): Couldn't use thiserror's #[from] in this case due to compiler errors.
impl From<der::Error> for ParseTrcError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

/// TRC identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrcId {
    // Note: the order of fields is relevant here!
    /// ISD number.
    pub isd: Isd,
    /// Base number.
    pub base: u64,
    /// Serial number.
    pub serial: u64,
}

impl TrcId {
    pub(crate) fn from_trc_payload(value: &TrcIdPayload) -> Result<Self, ParseTrcError> {
        let isd = der_int_to_isd(&value.isd)?;
        let base = der_int_to_u64(&value.base_number)?;
        let serial = der_int_to_u64(&value.serial_number)?;

        Ok(Self { isd, base, serial })
    }
}

/// TRCPayload as specified by the spec [1].
///
/// ## Notes
///
/// While the specification declares ASN as INTEGER, the actual implementation of cppki [2] (and
/// therefore TRCs used in practice) use PrintableString as the type for ASN.
///
/// [1]: <https://docs.scion.org/en/v0.11.0/cryptography/trc.html>
/// [2]: <https://github.com/scionproto/scion/blob/v0.12.0/pkg/scrypto/cppki/trc_asn1.go#L215>
#[derive(Debug, PartialEq, Sequence, Clone)]
pub struct TrcPayload {
    /// Version number.
    pub version: Int,
    /// TRC ID payload.
    pub id: TrcIdPayload,
    /// Validity period.
    pub validity: Validity,
    /// Grace period in seconds.
    pub grace_period: Int,
    /// Whether trust reset is disabled.
    pub no_trust_reset: bool,
    /// Votes required to issue a new TRC.
    pub votes: Vec<Int>,
    /// Voting quorum.
    pub voting_quorum: Int,
    /// Core ASes.
    pub core_ases: Vec<PrintableString>,
    /// Authoritative ASes.
    pub authoritative_ases: Vec<PrintableString>,
    /// Description.
    pub description: String, // Utf8StringRef<'a>,
    /// Certificates.
    pub certificates: Vec<x509_cert::Certificate>,
}

/// TRC ID payload.
#[derive(Debug, PartialEq, Sequence, Clone)]
pub struct TrcIdPayload {
    /// ISD number.
    pub isd: Int,
    /// Serial number.
    pub serial_number: Int,
    /// Base number.
    pub base_number: Int,
}

/// Validity period.
#[derive(Debug, PartialEq, Sequence, Clone)]
pub struct Validity {
    /// Not before time.
    pub not_before: GeneralizedTime,
    /// Not after time.
    pub not_after: GeneralizedTime,
}

/// Convert from DER encoded integer to a u64.
///
/// DER-encoded INTEGERs have arbitrary width. If the value of the given DER-encoded integer is
/// negative or larger than the maximum value of a u64, an error is returned.
///
/// [1]: <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
pub fn der_int_to_u64(asn_int: &Int) -> Result<u64, ParseTrcError> {
    const U64_SIZE: usize = std::mem::size_of::<u64>();
    let bytes = asn_int.as_bytes();
    if bytes.is_empty() || bytes.len() > U64_SIZE + 1 {
        return Err(ParseTrcError::InvalidIntegerValue());
    }
    // offset is the pos after leading zeros.
    let offset = (bytes[0] == 0) as usize;
    if offset == 0 && ((bytes[0] & 0x80 != 0) || bytes.len() > U64_SIZE) {
        // negative number or number too large
        return Err(ParseTrcError::InvalidIntegerValue());
    }
    let mut be_bytes = [0u8; U64_SIZE];

    let start_idx = U64_SIZE - bytes.len() + offset;
    for idx in start_idx..U64_SIZE {
        be_bytes[idx] = bytes[idx - start_idx + offset];
    }

    Ok(u64::from_be_bytes(be_bytes))
}

/// Convert a u64 to a DER-encoded INTEGER.
///
/// The value is encoded as a minimal big-endian byte sequence. A leading zero byte is prepended
/// when the most significant bit is set, so that the value is always interpreted as a non-negative
/// integer (the inverse of [`der_int_to_u64`]).
fn u64_to_int(value: u64) -> Result<Int, der::Error> {
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let mut bytes = be[start..].to_vec();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    Int::new(&bytes)
}

fn der_int_to_isd(asn_int: &Int) -> Result<Isd, ParseTrcError> {
    der_int_to_u64(asn_int)
        .and_then(|value| u16::try_from(value).map_err(|_| ParseTrcError::InvalidIsd()))
        .map_err(|_| ParseTrcError::InvalidIsd())
        .map(Isd::new)
}

/// Convert a [`SystemTime`] to a DER `GeneralizedTime`.
fn system_time_to_generalized(time: SystemTime) -> Result<GeneralizedTime, BuildTrcError> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH)?;
    Ok(GeneralizedTime::from_unix_duration(duration)?)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sciparse::identifier::{isd::Isd, isd_asn::IsdAsn};

    use super::{Trc, TrcId};

    const TRC_ISD64_B1_S11: &[u8] = include_bytes!("testdata/ISD64-B1-S11.trc");
    const ISD64_CORE_ASES: &[&str] = &[
        "64-559",
        "64-3303",
        "64-6730",
        "64-12350",
        "64-13030",
        "64-15623",
        "64-2:0:13",
        "64-2:0:23",
    ];

    const TRC_ISD65_B1_S10: &[u8] = include_bytes!("testdata/ISD65-B1-S10.trc");
    const ISD65_CORE_ASES: &[&str] = &[
        "65-30870",
        "65-2:0:f",
        "65-2:0:20",
        "65-2:0:24",
        "65-2:0:51",
        "65-2:0:6c",
        "65-2:0:71",
    ];

    const TRCS: &[&[u8]] = &[TRC_ISD64_B1_S11, TRC_ISD65_B1_S10];
    const CORE_ASES: &[&[&str]] = &[ISD64_CORE_ASES, ISD65_CORE_ASES];
    const TRC_IDS: &[TrcId] = &[
        TrcId {
            isd: Isd(64),
            base: 1,
            serial: 11,
        },
        TrcId {
            isd: Isd(65),
            base: 1,
            serial: 10,
        },
    ];

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn can_parse_core_ases_and_id() -> TestResult {
        for ((trc_bytes, expected_core_ases), trc_id) in
            TRCS.iter().zip(CORE_ASES.iter()).zip(TRC_IDS)
        {
            let trc = Trc::parse_from_pem(trc_bytes)?;

            assert_eq!(trc.id(), trc_id, "TRC ID should match expected value");

            let core_ases: Vec<_> = trc.core_ases().collect();
            let expected: Vec<IsdAsn> = expected_core_ases
                .iter()
                .map(|&s| IsdAsn::from_str(s).expect("isd-asn"))
                .collect();
            assert_eq!(core_ases.as_slice(), expected.as_slice());
        }
        Ok(())
    }

    #[test]
    fn unsigned_trc_roundtrips() -> TestResult {
        use std::time::{Duration, SystemTime};

        let id = TrcId {
            isd: Isd(64),
            base: 1,
            serial: 1,
        };
        let core_ases: Vec<IsdAsn> = ["64-559", "64-2:0:13", "64-13030"]
            .iter()
            .map(|&s| IsdAsn::from_str(s).expect("isd-asn"))
            .collect();

        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(60 * 60 * 24 * 365);

        let trc = Trc::new_unsigned(id, &core_ases, not_before, not_after, "test trc")?;
        let pem = trc.to_pem()?;

        let parsed = Trc::parse_from_pem(pem.as_bytes())?;
        assert_eq!(parsed.id(), &id);

        let parsed_cores: Vec<IsdAsn> = parsed.core_ases().collect();
        assert_eq!(parsed_cores.as_slice(), core_ases.as_slice());
        Ok(())
    }
}
