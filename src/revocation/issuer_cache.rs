use super::{der, ocsp::Query};
use crate::{Result, storage::database::Database};
use openssl::{
    hash::{MessageDigest, hash},
    x509::X509,
};
use std::collections::HashMap;

type Identity = (usize, Vec<u8>, Vec<u8>);
#[derive(Default)]
pub(crate) struct IssuerCache {
    pub generation: Option<i64>,
    issuers: HashMap<Identity, String>,
}

pub(super) fn select(database: &Database, queries: &[Query]) -> Result<Option<String>> {
    let generation: i64 = database.conn.query_row(
        "SELECT COALESCE(MAX(idx),0) FROM certificates WHERE kind='intermediate'",
        [],
        |r| r.get(0),
    )?;
    let mut cache = database.ocsp_issuers.borrow_mut();
    if cache.generation != Some(generation) {
        let mut issuers = HashMap::new();
        for ca in database.intermediate_public()? {
            let cert = X509::from_pem(ca.pem.as_bytes())?;
            let name = cert.subject_name().to_der()?;
            let spki = cert.public_key()?.public_key_to_der()?;
            let mut encoded = der::content(&spki, 0x30)?;
            der::read(&mut encoded)?;
            let (_, bits, _) = der::read(&mut encoded)?;
            let bits = bits.get(1..).ok_or("invalid public key")?;
            for digest in [MessageDigest::sha1(), MessageDigest::sha256()] {
                issuers.insert(
                    (
                        digest.size(),
                        hash(digest, &name)?.to_vec(),
                        hash(digest, bits)?.to_vec(),
                    ),
                    ca.fingerprint.clone(),
                );
            }
        }
        *cache = IssuerCache {
            generation: Some(generation),
            issuers,
        };
    }
    let mut selected = None;
    for q in queries {
        let Some(id) =
            cache
                .issuers
                .get(&(q.algorithm.size(), q.name_hash.clone(), q.key_hash.clone()))
        else {
            return Ok(None);
        };
        if selected.as_ref().is_some_and(|previous| previous != id) {
            return Ok(None);
        }
        selected = Some(id.clone());
    }
    Ok(selected)
}
