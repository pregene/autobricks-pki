use crate::{Result, certificate::validity::DAY};
pub const LIFETIME_SECONDS: i64 = 7 * DAY;
pub fn next_update(this_update: i64) -> Result<i64> {
    this_update
        .checked_add(LIFETIME_SECONDS)
        .ok_or_else(|| "CRL timestamp overflow".into())
}
/// Revocation must publish immediately; scheduled refresh is independent.
pub fn refresh_required(now: i64, next_update: i64, revocation: bool) -> bool {
    revocation || now >= next_update
}
pub fn generate(
    issuer: &crate::storage::database::Certificate,
    certificates: &[crate::storage::database::Certificate],
    now: i64,
    number: i64,
) -> Result<Vec<u8>> {
    use openssl::{
        asn1::{Asn1Object, Asn1OctetString, Asn1Time},
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509, X509CrlBuilder, X509Extension, X509RevokedBuilder},
    };
    let cert = X509::from_pem(issuer.pem.as_bytes())?;
    let key = PKey::private_key_from_pem(issuer.key_pem.as_bytes())?;
    let mut b = X509CrlBuilder::new()?;
    b.set_issuer_name(cert.subject_name())?;
    let last = Asn1Time::from_unix(now)?;
    let next = Asn1Time::from_unix(next_update(now)?)?;
    b.set_last_update(&last)?;
    b.set_next_update(&next)?;
    let generations: Vec<_> = certificates
        .iter()
        .filter(|c| c.kind == "intermediate" && c.cn == issuer.cn)
        .map(|c| c.fingerprint.as_str())
        .collect();
    for entry in certificates.iter().filter(|c| {
        c.issuer
            .as_deref()
            .is_some_and(|id| generations.contains(&id))
    }) {
        if let Some(revoked) = entry.revoked_at {
            let serial = openssl::bn::BigNum::from_hex_str(&entry.serial)?.to_asn1_integer()?;
            let mut r = X509RevokedBuilder::new()?;
            r.set_serial_number(&serial)?;
            let date = Asn1Time::from_unix(revoked)?;
            r.set_revocation_date(&date)?;
            b.add_revoked(r.build())?;
        }
    }
    let raw = openssl::bn::BigNum::from_dec_str(&number.to_string())?
        .to_asn1_integer()?
        .to_bn()?
        .to_vec();
    let mut positive = Vec::new();
    if raw.first().is_some_and(|b| b & 0x80 != 0) {
        positive.push(0);
    }
    positive.extend(raw);
    let oid = Asn1Object::from_str("2.5.29.20")?;
    let value = Asn1OctetString::new_from_bytes(&super::der::tlv(2, &positive))?;
    b.append_extension(X509Extension::new_from_der(&oid, false, &value)?)?;
    if let Some(ski) = cert.subject_key_id() {
        let oid = Asn1Object::from_str("2.5.29.35")?;
        let value = Asn1OctetString::new_from_bytes(&super::der::seq(&[super::der::tlv(
            0x80,
            ski.as_slice(),
        )]))?;
        b.append_extension(X509Extension::new_from_der(&oid, false, &value)?)?;
    }
    b.sort()?;
    b.sign(&key, MessageDigest::sha256())?;
    Ok(b.build()?.to_pem()?)
}
