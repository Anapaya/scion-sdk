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

//! Dir Parser for the SCION trust store.

use std::path::{Path, PathBuf};

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};

use super::{CertifiedKeyPair, StoreCertificateDer, StoreKeyDer};
use crate::network::scion::trust_store::TrustStore;

/// Build a trust store by scanning a filesystem directory.
pub fn trust_store_from_directory(path: impl AsRef<Path>) -> anyhow::Result<TrustStore> {
    let path = path.as_ref();
    let trcs = collect_raw_trcs(path)?;
    let as_dir_readers = collect_as_dir_readers(path)?;

    let mut trust_store = TrustStore::new();
    for (raw, trc_path) in trcs {
        trust_store.add_isd_trust_store(raw).context(format!(
            "failed to add TRC from file {}",
            trc_path.display()
        ))?;
    }

    for as_reader in as_dir_readers {
        let identity = as_reader.load_as_identity()?;
        trust_store.add_as_key_pair(as_reader.isd_asn, identity)?;

        let ca_identities = as_reader.load_ca_identities()?;
        if let Some((ca_identity, root_identity)) = ca_identities {
            trust_store.add_as_ca(as_reader.isd_asn, root_identity, ca_identity)?;
        }
    }

    Ok(trust_store)
}
fn collect_raw_trcs(base_path: &Path) -> anyhow::Result<Vec<(Vec<u8>, PathBuf)>> {
    let trc_path = base_path.join("trcs");

    let mut trc_paths = Vec::new();
    collect_files_with_extension(&trc_path, "trc", &mut trc_paths)?;

    let mut trcs = Vec::new();
    for trc_path in trc_paths {
        let raw = std::fs::read(&trc_path)
            .with_context(|| format!("failed to read TRC file {}", trc_path.display()))?;
        trcs.push((raw, trc_path));
    }

    Ok(trcs)
}

/// For every folder starting with AS, create an AsDirReader to parse the AS identity and CA
/// certificates from the folder.
fn collect_as_dir_readers(base_path: &Path) -> anyhow::Result<Vec<AsDirReader>> {
    // Non recusively find every folder starting with AS
    let mut parsers = Vec::new();
    for entry in std::fs::read_dir(base_path)
        .with_context(|| format!("failed to read directory {}", base_path.display()))?
    {
        let entry = entry.with_context(|| {
            format!("failed to read entry in directory {}", base_path.display())
        })?;

        let entry_path = entry.path();
        if entry_path.is_dir()
            && let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
            && name.starts_with("AS")
        {
            let reader = AsDirReader::new(entry_path.clone()).with_context(|| {
                format!(
                    "failed to create AS directory parser for {}",
                    entry_path.display()
                )
            })?;

            parsers.push(reader);
        }
    }

    Ok(parsers)
}

#[derive(Debug, Serialize, Deserialize)]
struct CpAsTemplate {
    isd_as: IsdAsn,
}
struct AsDirReader {
    pub isd_asn: IsdAsn,
    pub path: PathBuf,
}

impl AsDirReader {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        // ./crypto/as/cp-as.tmpl contains the ISD-AS
        let isd_asn = {
            let tmpl_path = path.join("./crypto/as/cp-as.tmpl");
            let tmpl = std::fs::read_to_string(&tmpl_path).with_context(|| {
                format!("failed to read AS template file {}", tmpl_path.display())
            })?;
            let template: CpAsTemplate = serde_json::from_str(&tmpl).with_context(|| {
                format!("failed to parse AS template file {}", tmpl_path.display())
            })?;
            template.isd_as
        };

        Ok(AsDirReader { isd_asn, path })
    }

    // Located in `/<AS_NAME>/crypto/as`
    //
    // Should contain
    // ```
    // cp-as.key
    // ISDX-ASY.pem
    // ```
    fn load_as_identity(&self) -> anyhow::Result<CertifiedKeyPair> {
        let as_crypto_dir = self.path.join("crypto").join("as");
        // cp-as.key
        // ISDX-ASY.pem

        let key_path = as_crypto_dir.join("cp-as.key");
        let mut certs = Vec::new();
        collect_files_with_extension(&as_crypto_dir, "pem", &mut certs)?;

        if certs.len() != 1 {
            anyhow::bail!(
                "expected exactly one PEM file in {}, found {}",
                as_crypto_dir.display(),
                certs.len()
            );
        }

        // Load the private key
        let key_der = PrivateKeyDer::from_pem_file(&key_path).with_context(|| {
            format!("failed to parse AS private key PEM {}", key_path.display())
        })?;

        let cert_der = CertificateDer::from_pem_file(&certs[0]).with_context(|| {
            format!("failed to parse AS certificate PEM {}", certs[0].display())
        })?;

        Ok(CertifiedKeyPair {
            key: StoreKeyDer(key_der),
            cert: StoreCertificateDer(cert_der),
        })
    }

    /// May exist in `/<AS_NAME>/crypto/ca`
    ///
    /// Should contain
    // ```
    // cp-ca.key
    // cp-root.key
    // ISDX-ASY.ca.crt
    // ISDX-ASY.root.crt
    // ```
    //
    // Returns (CA identity, root identity) if the CA crypto directory exists, otherwise returns
    // None.
    fn load_ca_identities(&self) -> anyhow::Result<Option<(CertifiedKeyPair, CertifiedKeyPair)>> {
        let ca_crypto_dir = self.path.join("crypto").join("ca");
        if !ca_crypto_dir.exists() {
            return Ok(None);
        }

        let certs = {
            let mut certs = Vec::new();
            collect_files_with_extension(&ca_crypto_dir, "crt", &mut certs)?;
            certs
        };

        if certs.len() != 2 {
            anyhow::bail!(
                "expected exactly two CRT files in {}, found {}",
                ca_crypto_dir.display(),
                certs.len()
            );
        }

        let key_path = ca_crypto_dir.join("cp-ca.key");
        let root_key_path = ca_crypto_dir.join("cp-root.key");

        let key_der = PrivateKeyDer::from_pem_file(&key_path).with_context(|| {
            format!("failed to parse CA private key PEM {}", key_path.display())
        })?;
        let root_key_der = PrivateKeyDer::from_pem_file(&root_key_path).with_context(|| {
            format!(
                "failed to parse CA root private key PEM {}",
                root_key_path.display()
            )
        })?;

        // get index of the .root.crt file, which is the root certificate, the other one is the
        // intermediary certificate
        let (idx, _path) = certs
            .iter()
            .enumerate()
            .find(|(_, p)| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".root.crt"))
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "failed to find root certificate in CA crypto directory {}",
                    ca_crypto_dir.display()
                )
            })?;

        let (root_crt_path, ca_cert_path) = match idx {
            0 => (&certs[0], &certs[1]),
            1 => (&certs[1], &certs[0]),
            _ => unreachable!(),
        };

        let cert_der = CertificateDer::from_pem_file(ca_cert_path).with_context(|| {
            format!(
                "failed to parse CA certificate PEM {}",
                ca_cert_path.display()
            )
        })?;
        let root_cert_der = CertificateDer::from_pem_file(root_crt_path).with_context(|| {
            format!(
                "failed to parse CA root certificate PEM {}",
                root_crt_path.display()
            )
        })?;

        Ok(Some((
            CertifiedKeyPair {
                key: StoreKeyDer(key_der),
                cert: StoreCertificateDer(cert_der),
            },
            CertifiedKeyPair {
                key: StoreKeyDer(root_key_der),
                cert: StoreCertificateDer(root_cert_der),
            },
        )))
    }
}

/// Recursively collect files with a given extension.
fn collect_files_with_extension(
    path: &Path,
    extension: &str,
    acc: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed to read entry in directory {}", path.display()))?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_files_with_extension(&entry_path, extension, acc)?;
        } else if entry_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == extension)
        {
            acc.push(entry_path);
        }
    }

    Ok(())
}
