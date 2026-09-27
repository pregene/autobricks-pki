use crate::Result;
use openssl::ocsp::{OcspRequest, OcspResponse, OcspResponseStatus};
pub const REQUEST_TYPE: &str = "application/ocsp-request";
pub const RESPONSE_TYPE: &str = "application/ocsp-response";
use super::der::{self, read, seq, tlv};
use crate::storage::database::Certificate;
use openssl::{
    hash::{MessageDigest, hash},
    pkey::PKey,
    sign::Signer,
    x509::X509,
};
pub(super) struct Query {
    encoded: Vec<u8>,
    pub(super) algorithm: MessageDigest,
    pub(super) name_hash: Vec<u8>,
    pub(super) key_hash: Vec<u8>,
    serial: Vec<u8>,
}
fn queries(body: &[u8]) -> Result<(Vec<Query>, Option<Vec<u8>>)> {
    let request = OcspRequest::from_der(body)?;
    if request.to_der()? != body {
        return Err("non-canonical OCSP request".into());
    }
    let mut outer = der::content(body, 0x30)?;
    let (tag, tbs, _) = read(&mut outer)?;
    if tag != 0x30 {
        return Err("invalid OCSP request".into());
    }
    let mut tbs = tbs;
    if tbs.first() == Some(&0xa0) {
        read(&mut tbs)?;
    }
    if tbs.first() == Some(&0xa1) {
        read(&mut tbs)?;
    }
    let (tag, mut list, _) = read(&mut tbs)?;
    if tag != 0x30 {
        return Err("missing OCSP request list".into());
    }
    let mut out = Vec::new();
    while !list.is_empty() {
        if out.len() >= 32 {
            return Err("too many OCSP requests".into());
        }
        let (tag, mut one, _) = read(&mut list)?;
        if tag != 0x30 {
            return Err("invalid OCSP request item".into());
        }
        let (tag, mut id, raw) = read(&mut one)?;
        if !one.is_empty() {
            let (tag, extensions, _) = read(&mut one)?;
            if tag != 0xa0 {
                return Err("invalid single-request extensions".into());
            }
            let mut extensions = der::content(extensions, 0x30)?;
            while !extensions.is_empty() {
                let (_, mut extension, _) = read(&mut extensions)?;
                read(&mut extension)?;
                if extension.first() == Some(&1) && read(&mut extension)?.1 != [0] {
                    return Err("unsupported critical single-request extension".into());
                }
            }
        }

        if tag != 0x30 {
            return Err("invalid CertID".into());
        }
        let (_, mut alg, _) = read(&mut id)?;
        let (_, oid, _) = read(&mut alg)?;
        let algorithm = match oid {
            [0x2b, 0x0e, 0x03, 0x02, 0x1a] => MessageDigest::sha1(),
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => MessageDigest::sha256(),
            _ => return Err("unsupported CertID digest".into()),
        };
        let (_, name_hash, _) = read(&mut id)?;
        let (_, key_hash, _) = read(&mut id)?;
        let (_, serial, _) = read(&mut id)?;
        out.push(Query {
            encoded: raw.to_vec(),
            algorithm,
            name_hash: name_hash.to_vec(),
            key_hash: key_hash.to_vec(),
            serial: serial.to_vec(),
        });
    }
    if out.is_empty() {
        return Err("empty OCSP request list".into());
    }
    let mut nonce = None;
    if !tbs.is_empty() {
        let (tag, extensions, _) = read(&mut tbs)?;
        if tag != 0xa2 {
            return Err("invalid request extensions".into());
        }
        let mut extensions = der::content(extensions, 0x30)?;
        while !extensions.is_empty() {
            let (_, mut e, raw) = read(&mut extensions)?;
            let (_, oid, _) = read(&mut e)?;
            let critical = if e.first() == Some(&1) {
                read(&mut e)?.1 != [0]
            } else {
                false
            };
            if oid == [0x2b, 6, 1, 5, 5, 7, 0x30, 1, 2] {
                if nonce.is_some() {
                    return Err("duplicate nonce".into());
                }
                nonce = Some(raw.to_vec());
            } else if critical {
                return Err("unsupported critical OCSP extension".into());
            }
        }
    }
    Ok((out, nonce))
}
fn error(status: OcspResponseStatus) -> Result<Vec<u8>> {
    Ok(OcspResponse::create(status, None)?.to_der()?)
}
/// Cache public issuer identities; always query live certificate status by issuer/serial.
pub fn respond_database(
    body: &[u8],
    database: &crate::storage::database::Database,
    now: i64,
) -> Result<Vec<u8>> {
    let (items, nonce) = match queries(body) {
        Ok(items) => items,
        Err(_) => return error(OcspResponseStatus::MALFORMED_REQUEST),
    };
    let Some(fingerprint) = super::issuer_cache::select(database, &items)? else {
        return error(OcspResponseStatus::UNAUTHORIZED);
    };
    let lineage = database.ca_lineage(&fingerprint)?;
    let mut records = Vec::new();
    let serials = items
        .iter()
        .map(|item| {
            Ok(openssl::bn::BigNum::from_slice(&item.serial)?
                .to_hex_str()?
                .to_string())
        })
        .collect::<Result<Vec<String>>>()?;
    for generation in &lineage {
        if generation != &fingerprint {
            records.push(database.metadata(generation)?);
        }
        for serial in &serials {
            if let Some(record) = database.by_issuer_serial(generation, serial)? {
                records.push(record);
            }
        }
    }
    records.push(database.get(&fingerprint)?);
    respond_parsed(items, nonce, &records, now)
}

fn matches_issuer(queries: &[Query], cert: &X509) -> Result<bool> {
    let name = cert.subject_name().to_der()?;
    let spki = cert.public_key()?.public_key_to_der()?;
    let mut spki = der::content(&spki, 0x30)?;
    read(&mut spki)?;
    let (_, bits, _) = read(&mut spki)?;
    let bits = bits.get(1..).ok_or("invalid public key")?;
    Ok(queries.iter().all(|q| {
        hash(q.algorithm, &name).is_ok_and(|d| d.as_ref() == q.name_hash)
            && hash(q.algorithm, bits).is_ok_and(|d| d.as_ref() == q.key_hash)
    }))
}

pub fn respond(body: &[u8], certificates: &[Certificate], now: i64) -> Result<Vec<u8>> {
    let (queries, nonce) = match queries(body) {
        Ok(q) => q,
        Err(_) => return error(OcspResponseStatus::MALFORMED_REQUEST),
    };
    respond_parsed(queries, nonce, certificates, now)
}

fn respond_parsed(
    queries: Vec<Query>,
    nonce: Option<Vec<u8>>,
    certificates: &[Certificate],
    now: i64,
) -> Result<Vec<u8>> {
    let mut selected = None;
    for ca in certificates
        .iter()
        .rev()
        .filter(|c| c.kind == "intermediate")
    {
        let cert = X509::from_pem(ca.pem.as_bytes())?;
        if matches_issuer(&queries, &cert)? {
            selected = Some((ca, cert));
            break;
        }
    }
    let Some((ca, cert)) = selected else {
        return error(OcspResponseStatus::UNAUTHORIZED);
    };
    let generations: Vec<_> = certificates
        .iter()
        .filter(|c| c.kind == "intermediate" && c.cn == ca.cn)
        .map(|c| c.fingerprint.as_str())
        .collect();
    let mut responses = Vec::new();
    for q in queries {
        let serial = openssl::bn::BigNum::from_slice(&q.serial)?
            .to_hex_str()?
            .to_string();
        let entry = certificates.iter().find(|c| {
            c.issuer
                .as_deref()
                .is_some_and(|id| generations.contains(&id))
                && c.serial == serial
        });
        let status = match entry {
            Some(c) if c.revoked_at.is_some() => {
                tlv(0xa1, &der::time(c.revoked_at.unwrap_or(now))?)
            }
            Some(_) => tlv(0x80, &[]),
            None => tlv(0x82, &[]),
        };
        responses.push(seq(&[q.encoded, status, der::time(now)?]));
    }
    let mut fields = vec![
        tlv(0xa1, &cert.subject_name().to_der()?),
        der::time(now)?,
        seq(&responses),
    ];
    if let Some(nonce) = nonce {
        fields.push(tlv(0xa1, &seq(&[nonce])));
    }
    let data = seq(&fields);
    let key = PKey::private_key_from_pem(ca.key_pem.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(&data)?;
    let mut signature = vec![0];
    signature.extend(signer.sign_to_vec()?);
    let algorithm = seq(&[tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])]);
    let basic = seq(&[
        data,
        algorithm,
        tlv(3, &signature),
        tlv(0xa0, &seq(&[cert.to_der()?])),
    ]);
    let response = seq(&[
        tlv(0x0a, &[0]),
        tlv(
            0xa0,
            &seq(&[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]), tlv(4, &basic)]),
        ),
    ]);
    OcspResponse::from_der(&response)?;
    Ok(response)
}
