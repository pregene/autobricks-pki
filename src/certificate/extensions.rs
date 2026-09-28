//! Encoding only: applications consuming the certificate interpret extension semantics.
use super::{names, profile::LeafProfile, values::*};
use crate::{
    Result,
    revocation::der::{self, tlv},
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub const EXTENSIONS: &[(&str, &str)] = &[
    ("key_usage", "2.5.29.15"),
    ("extended_key_usage", "2.5.29.37"),
    ("name_constraints", "2.5.29.30"),
    ("certificate_policies", "2.5.29.32"),
    ("policy_mappings", "2.5.29.33"),
    ("policy_constraints", "2.5.29.36"),
    ("inhibit_any_policy", "2.5.29.54"),
    ("freshest_crl", "2.5.29.46"),
    ("subject_info_access", "1.3.6.1.5.5.7.1.11"),
    ("issuer_alt_name", "2.5.29.18"),
    ("subject_directory_attributes", "2.5.29.9"),
    ("tls_feature", "1.3.6.1.5.5.7.1.24"),
    ("ocsp_no_check", "1.3.6.1.5.5.7.48.1.5"),
    ("qc_statements", "1.3.6.1.5.5.7.1.3"),
];
pub fn eku(s: &str) -> Result<String> {
    let id = match s {
        "serverAuth" => "1.3.6.1.5.5.7.3.1",
        "clientAuth" => "1.3.6.1.5.5.7.3.2",
        "codeSigning" => "1.3.6.1.5.5.7.3.3",
        "emailProtection" => "1.3.6.1.5.5.7.3.4",
        "timeStamping" => "1.3.6.1.5.5.7.3.8",
        "OCSPSigning" => "1.3.6.1.5.5.7.3.9",
        "ipsecIKE" => "1.3.6.1.5.5.7.3.17",
        "anyExtendedKeyUsage" => "2.5.29.37.0",
        _ => s,
    };
    oid(id)?;
    Ok(id.to_owned())
}
pub fn critical(p: &LeafProfile, field: &str, default: bool) -> Result<bool> {
    if let Some(v) = p.extra.get("critical") {
        let m = v.as_object().ok_or("critical must be an object")?;
        if let Some(v) = m.get(field) {
            return v
                .as_bool()
                .ok_or_else(|| "critical flag must be Boolean".into());
        }
    }
    Ok(default)
}
fn usage(v: &Value) -> Result<Vec<u8>> {
    let mut bits = 0u16;
    for value in array(v, 9)? {
        let n = match text(value, 32, true)? {
            "digitalSignature" => 0,
            "contentCommitment" | "nonRepudiation" => 1,
            "keyEncipherment" => 2,
            "dataEncipherment" => 3,
            "keyAgreement" => 4,
            "keyCertSign" => 5,
            "cRLSign" => 6,
            "encipherOnly" => 7,
            "decipherOnly" => 8,
            _ => return Err("unknown Key Usage bit name".into()),
        };
        bits |= 1 << n;
    }
    let high = 15 - bits.leading_zeros() as usize;
    let mut encoded = vec![(7 - high % 8) as u8];
    for byte in 0..=high / 8 {
        let mut b = 0u8;
        for bit in 0..8 {
            if bits & (1 << (byte * 8 + bit)) != 0 {
                b |= 1 << (7 - bit);
            }
        }
        encoded.push(b);
    }
    Ok(tlv(3, &encoded))
}
fn counter(v: &Value) -> Result<Vec<u8>> {
    let n = v
        .as_i64()
        .filter(|n| (0..=i64::from(i32::MAX)).contains(n))
        .ok_or("counter exceeds integer range")?;
    Ok(integer(n))
}
fn policies(v: &Value) -> Result<Vec<u8>> {
    let mut out = vec![];
    for value in array(v, 16)? {
        let m = object(value, &["policy_oid", "cps_uri", "user_notice"])?;
        let mut p = vec![oid(text(required(m, "policy_oid")?, 100, true)?)?];
        let mut q = vec![];
        if let Some(uri_value) = m.get("cps_uri") {
            q.push(sequence(&[
                oid("1.3.6.1.5.5.7.2.1")?,
                tlv(22, uri(uri_value, false)?.as_bytes()),
            ]));
        }
        if let Some(v) = m.get("user_notice") {
            q.push(sequence(&[
                oid("1.3.6.1.5.5.7.2.2")?,
                sequence(&[tlv(12, text(v, 200, false)?.as_bytes())]),
            ]));
        }
        if !q.is_empty() {
            p.push(sequence(&q));
        }
        out.push(sequence(&p));
    }
    Ok(sequence(&out))
}
fn encoded(field: &str, v: &Value) -> Result<Vec<u8>> {
    Ok(match field {
        "key_usage" => usage(v)?,
        "extended_key_usage" => sequence(
            &array(v, 16)?
                .iter()
                .map(|v| oid(&eku(text(v, 100, true)?)?))
                .collect::<Result<Vec<_>>>()?,
        ),
        "certificate_policies" => policies(v)?,
        "policy_mappings" => sequence(
            &array(v, 16)?
                .iter()
                .map(|v| {
                    let m = object(v, &["issuer_domain_policy", "subject_domain_policy"])?;
                    Ok(sequence(&[
                        oid(text(required(m, "issuer_domain_policy")?, 100, true)?)?,
                        oid(text(required(m, "subject_domain_policy")?, 100, true)?)?,
                    ]))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        "policy_constraints" => {
            let m = object(v, &["require_explicit_policy", "inhibit_policy_mapping"])?;
            let mut parts = vec![];
            for (k, tag) in [
                ("require_explicit_policy", 0x80),
                ("inhibit_policy_mapping", 0x81),
            ] {
                if let Some(v) = m.get(k) {
                    let mut b = counter(v)?;
                    b[0] = tag;
                    parts.push(b);
                }
            }
            sequence(&parts)
        }
        "inhibit_any_policy" => counter(v)?,
        "name_constraints" => {
            let m = object(v, &["permitted_subtrees", "excluded_subtrees"])?;
            let mut parts = vec![];
            for (k, tag) in [("permitted_subtrees", 0xa0), ("excluded_subtrees", 0xa1)] {
                if let Some(v) = m.get(k) {
                    let mut subtrees = vec![];
                    for v in array(v, 16)? {
                        let names = names::general_names(
                            v.as_object().ok_or("subtree must be an object")?,
                            true,
                        )?;
                        if names.len() != 1 {
                            return Err("each subtree requires one GeneralName".into());
                        }
                        subtrees.push(sequence(&names));
                    }
                    parts.push(tlv(tag, &subtrees.concat()));
                }
            }
            sequence(&parts)
        }
        "freshest_crl" => sequence(
            &array(v, 16)?
                .iter()
                .map(|v| {
                    Ok(sequence(&[tlv(
                        0xa0,
                        &tlv(0xa0, &tlv(0x86, uri(v, false)?.as_bytes())),
                    )]))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        "subject_info_access" => sequence(
            &array(v, 16)?
                .iter()
                .map(|v| {
                    let m = object(v, &["access_method", "uri"])?;
                    Ok(sequence(&[
                        oid(text(required(m, "access_method")?, 100, true)?)?,
                        tlv(0x86, uri(required(m, "uri")?, false)?.as_bytes()),
                    ]))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        "issuer_alt_name" => sequence(&names::general_names(
            v.as_object().ok_or("issuer_alt_name must be an object")?,
            false,
        )?),
        "subject_directory_attributes" => {
            let mut entries = vec![];
            for v in array(v, 16)? {
                let m = object(v, &["oid", "values"])?;
                let mut values = array(required(m, "values")?, 16)?
                    .iter()
                    .map(typed_object)
                    .collect::<Result<Vec<_>>>()?;
                entries.push(sequence(&[
                    oid(text(required(m, "oid")?, 100, true)?)?,
                    set(&mut values),
                ]));
            }
            sequence(&entries)
        }
        "tls_feature" => sequence(
            &array(v, 16)?
                .iter()
                .map(|v| {
                    let n = match v.as_str() {
                        Some("status_request") => 5,
                        Some("status_request_v2") => 17,
                        Some(_) => return Err("unknown TLS feature name; use an integer".into()),
                        None => v
                            .as_i64()
                            .filter(|v| (0..=65535).contains(v))
                            .ok_or("TLS feature integer out of range")?,
                    };
                    Ok(integer(n))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        "ocsp_no_check" => {
            v.as_bool().ok_or("ocsp_no_check must be Boolean")?;
            tlv(5, &[])
        }
        "qc_statements" => {
            let mut entries = vec![];
            for v in array(v, 16)? {
                let m = object(v, &["statement_id", "statement_info"])?;
                let mut parts = vec![oid(text(required(m, "statement_id")?, 100, true)?)?];
                if let Some(v) = m.get("statement_info") {
                    parts.push(typed_object(v)?);
                }
                entries.push(sequence(&parts));
            }
            sequence(&entries)
        }
        _ => return Err("unknown extension field".into()),
    })
}
pub struct Prepared {
    pub subject: openssl::x509::X509Name,
    pub extensions: Vec<openssl::x509::X509Extension>,
}
pub fn prepare(p: &LeafProfile) -> Result<Prepared> {
    let mut dn = Map::new();
    dn.insert("common_name".into(), Value::String(p.common_name.clone()));
    for &(field, _, _, _) in names::DN {
        if let Some(v) = p.extra.get(field) {
            dn.insert(field.into(), v.clone());
        }
    }
    let subject = openssl::x509::X509Name::from_der(&names::dn(&dn)?)?;
    let mut san = Map::new();
    if !p.dns_names.is_empty() {
        san.insert("dns_names".into(), serde_json::to_value(&p.dns_names)?);
    }
    if !p.ip_addresses.is_empty() {
        san.insert(
            "ip_addresses".into(),
            serde_json::to_value(&p.ip_addresses)?,
        );
    }
    if !p.uri_sans.is_empty() {
        san.insert("uri_sans".into(), serde_json::to_value(&p.uri_sans)?);
    }
    for &field in names::SAN {
        if let Some(v) = p.extra.get(field) {
            san.insert(field.into(), v.clone());
        }
    }
    let mut extensions = vec![];
    if !san.is_empty() {
        extensions.push(extension(
            "2.5.29.17",
            critical(p, "subject_alt_name", false)?,
            &sequence(&names::general_names(&san, false)?),
        )?);
    }
    let mut emitted = BTreeSet::from([
        "basic_constraints",
        "subject_key_identifier",
        "authority_key_identifier",
        "authority_info_access",
        "crl_distribution_points",
    ]);
    if !san.is_empty() {
        emitted.insert("subject_alt_name");
    }
    for &(field, id) in EXTENSIONS {
        let default;
        let value = if let Some(v) = p.extra.get(field) {
            v
        } else if field == "key_usage" {
            default = serde_json::json!(["digitalSignature"]);
            &default
        } else if field == "extended_key_usage" {
            default = serde_json::to_value(p.ekus())?;
            &default
        } else {
            continue;
        };
        if field == "ocsp_no_check" && value == &Value::Bool(false) {
            continue;
        }
        let flag = critical(
            p,
            field,
            matches!(
                field,
                "key_usage"
                    | "name_constraints"
                    | "policy_constraints"
                    | "inhibit_any_policy"
                    | "policy_mappings"
            ),
        )?;
        extensions.push(extension(id, flag, &encoded(field, value)?)?);
        emitted.insert(field);
    }
    if let Some(v) = p.extra.get("critical") {
        let m = v.as_object().ok_or("critical must be an object")?;
        if m.is_empty()
            || m.len() > 32
            || m.iter()
                .any(|(k, v)| !emitted.contains(k.as_str()) || !v.is_boolean())
        {
            return Err("unknown critical extension or non-Boolean flag".into());
        }
    }
    if let Some(v) = p.extra.get("private_oid") {
        let mut oids = BTreeSet::new();
        for v in array(v, 16)? {
            let m = object(v, &["oid", "asn1_type", "value", "critical"])?;
            let id = text(required(m, "oid")?, 100, true)?;
            // An X.509 certificate may not contain duplicate extension OIDs.
            if EXTENSIONS.iter().any(|(_, known)| *known == id)
                || [
                    "2.5.29.17",
                    "2.5.29.19",
                    "2.5.29.14",
                    "2.5.29.35",
                    "2.5.29.31",
                    "1.3.6.1.5.5.7.1.1",
                ]
                .contains(&id)
                || !oids.insert(id)
            {
                return Err("duplicate extension OID".into());
            }
            extensions.push(extension(
                id,
                required(m, "critical")?
                    .as_bool()
                    .ok_or("critical must be Boolean")?,
                &typed(m)?,
            )?);
        }
    }
    Ok(Prepared {
        subject,
        extensions,
    })
}
// Useful for reading extension values without depending on display formatting.
pub fn extension_parts(bytes: &[u8]) -> Result<(Vec<u8>, bool, Vec<u8>)> {
    let mut input = der::content(bytes, 0x30)?;
    let (tag, _, id) = der::read(&mut input)?;
    if tag != 6 {
        return Err("extension lacks OID".into());
    }
    let mut critical = false;
    if input.first() == Some(&1) {
        let (_, c, _) = der::read(&mut input)?;
        critical = c == [255];
    }
    let (tag, value, _) = der::read(&mut input)?;
    if tag != 4 || !input.is_empty() {
        return Err("invalid extension encoding".into());
    }
    Ok((id.to_vec(), critical, value.to_vec()))
}
