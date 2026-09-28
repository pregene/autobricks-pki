//! Read issued DER independently of the production profile encoder.
use super::*;
use autobricks_pki::certificate::input;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const FULL: &str = include_str!("../fixtures/full-profile.json");
#[derive(Debug)]
struct Node<'a> {
    tag: u8,
    value: &'a [u8],
}
fn nodes(mut bytes: &[u8]) -> Vec<Node<'_>> {
    let mut out = vec![];
    while !bytes.is_empty() {
        let tag = bytes[0];
        let mut offset = 2;
        let size = if bytes[1] < 128 {
            usize::from(bytes[1])
        } else {
            let n = usize::from(bytes[1] & 127);
            offset += n;
            bytes[2..offset]
                .iter()
                .fold(0usize, |v, b| v * 256 + usize::from(*b))
        };
        out.push(Node {
            tag,
            value: &bytes[offset..offset + size],
        });
        bytes = &bytes[offset + size..];
    }
    out
}
fn oid(bytes: &[u8]) -> String {
    let mut arcs = vec![];
    let mut acc = 0u64;
    for b in bytes {
        acc = acc * 128 + u64::from(b & 127);
        if b & 128 == 0 {
            arcs.push(acc);
            acc = 0;
        }
    }
    let first = arcs.remove(0);
    let root = if first < 40 {
        0
    } else if first < 80 {
        1
    } else {
        2
    };
    let mut parts = vec![root.to_string(), (first - root * 40).to_string()];
    parts.extend(arcs.iter().map(u64::to_string));
    parts.join(".")
}
fn extensions(c: &X509) -> BTreeMap<String, (bool, Vec<u8>)> {
    let der = c.to_der().unwrap();
    let cert = nodes(&der);
    let cert = nodes(cert[0].value);
    let tbs = nodes(cert[0].value);
    let container = tbs.iter().find(|n| n.tag == 0xa3).unwrap();
    let sequence = nodes(container.value);
    nodes(sequence[0].value)
        .iter()
        .map(|ext| {
            let fields = nodes(ext.value);
            assert_eq!(fields[0].tag, 6);
            let critical = fields.len() == 3;
            if critical {
                assert_eq!(fields[1].tag, 1);
                assert_eq!(fields[1].value, [255]);
            }
            let last = fields.last().unwrap();
            assert_eq!(last.tag, 4);
            (oid(fields[0].value), (critical, last.value.to_vec()))
        })
        .collect()
}
fn sequence(bytes: &[u8]) -> Vec<Node<'_>> {
    let outer = nodes(bytes);
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].tag, 0x30);
    nodes(outer[0].value)
}
fn request(v: &Value) -> Create {
    input::create(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn full() -> Value {
    serde_json::from_str(FULL).unwrap()
}
fn string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}
fn subject(cert: &X509) -> BTreeMap<String, Vec<(u8, String)>> {
    let der = cert.subject_name().to_der().unwrap();
    let mut out: BTreeMap<String, Vec<(u8, String)>> = BTreeMap::new();
    for rdn in sequence(&der) {
        assert_eq!(rdn.tag, 0x31);
        for ava in nodes(rdn.value) {
            let pair = nodes(ava.value);
            out.entry(oid(pair[0].value))
                .or_default()
                .push((pair[1].tag, string(pair[1].value)));
        }
    }
    out
}
#[test]
fn all_fields_are_encoded_with_values_types_and_critical_flags() {
    let f = Fixture::new();
    let v = full();
    let profile = &v["profile"];
    let issued = f.service.create(request(&v)).unwrap();
    let cert = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let issuer = f.service.db.issuer("www.autobricks.internal").unwrap();
    let ca = X509::from_pem(issuer.pem.as_bytes()).unwrap();
    assert!(cert.verify(&ca.public_key().unwrap()).unwrap());
    assert_eq!(
        cert.issuer_name().to_der().unwrap(),
        ca.subject_name().to_der().unwrap()
    );
    let dn = subject(&cert);
    let mapping = [
        ("common_name", "2.5.4.3", 12),
        ("organization_name", "2.5.4.10", 12),
        ("unit_name", "2.5.4.11", 12),
        ("country_name", "2.5.4.6", 19),
        ("state_or_province_name", "2.5.4.8", 12),
        ("locality_name", "2.5.4.7", 12),
        ("street_address", "2.5.4.9", 12),
        ("postal_code", "2.5.4.17", 12),
        ("subject_serial_number", "2.5.4.5", 19),
        ("given_name", "2.5.4.42", 12),
        ("surname", "2.5.4.4", 12),
        ("pseudonym", "2.5.4.65", 12),
        ("user_id", "0.9.2342.19200300.100.1.1", 12),
        ("initials", "2.5.4.43", 12),
        ("title", "2.5.4.12", 12),
        ("description", "2.5.4.13", 12),
        ("business_category", "2.5.4.15", 12),
        ("organization_identifier", "2.5.4.97", 12),
        ("dn_qualifier", "2.5.4.46", 19),
        ("generation_qualifier", "2.5.4.44", 12),
        ("subject_email", "1.2.840.113549.1.9.1", 22),
    ];
    assert_eq!(dn.len(), 22);
    for (field, id, tag) in mapping {
        assert_eq!(
            dn[id],
            vec![(tag, profile[field].as_str().unwrap().to_owned())],
            "{field}"
        );
    }
    assert_eq!(
        dn["0.9.2342.19200300.100.1.25"],
        vec![(22, "autobricks".into()), (22, "internal".into())]
    );
    let ext = extensions(&cert);
    let known = [
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
    assert_eq!(ext.len(), 21);
    for (field, id) in known {
        assert_eq!(
            ext[id].0,
            profile["critical"][field].as_bool().unwrap_or(false),
            "{field} critical"
        );
    }
    assert_eq!(ext["2.5.29.15"].1, [3, 2, 7, 128]);
    let ekus = sequence(&ext["2.5.29.37"].1);
    assert_eq!(
        ekus.iter().map(|n| oid(n.value)).collect::<Vec<_>>(),
        ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]
    );
    let san = sequence(&ext["2.5.29.17"].1);
    assert_eq!(
        san.iter()
            .filter(|n| n.tag == 0x82)
            .map(|n| string(n.value))
            .collect::<Vec<_>>(),
        ["www-web01.autobricks.internal"]
    );
    assert_eq!(
        san.iter()
            .filter(|n| n.tag == 0x87)
            .map(|n| n.value.to_vec())
            .collect::<Vec<_>>(),
        vec![
            vec![192, 0, 2, 20],
            "2001:db8::20"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        ]
    );
    assert_eq!(
        san.iter()
            .filter(|n| n.tag == 0x86)
            .map(|n| string(n.value))
            .collect::<Vec<_>>(),
        profile["uri_sans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        san.iter().find(|n| n.tag == 0x81).map(|n| string(n.value)),
        Some("operator@example.test".into())
    );
    let directory = san.iter().find(|n| n.tag == 0xa4).unwrap();
    let name = openssl::x509::X509Name::from_der(directory.value).unwrap();
    for (nid, value) in [
        (openssl::nid::Nid::COMMONNAME, "web01"),
        (openssl::nid::Nid::ORGANIZATIONNAME, "Example Operations"),
        (openssl::nid::Nid::ORGANIZATIONALUNITNAME, "Infrastructure"),
        (openssl::nid::Nid::COUNTRYNAME, "KR"),
    ] {
        assert_eq!(
            name.entries_by_nid(nid)
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap(),
            value
        );
    }
    assert_eq!(
        oid(san.iter().find(|n| n.tag == 0x88).unwrap().value),
        "1.3.6.1.4.1.32473.1.1"
    );
    let other = nodes(san.iter().find(|n| n.tag == 0xa0).unwrap().value);
    assert_eq!(oid(other[0].value), "1.3.6.1.4.1.32473.1.2");
    assert_eq!(other[1].tag, 0xa0);
    let value = nodes(other[1].value);
    assert_eq!(value[0].tag, 12);
    assert_eq!(string(value[0].value), "DEVICE-WEB01");
    let policies = sequence(&ext["2.5.29.32"].1);
    let policy = nodes(policies[0].value);
    assert_eq!(oid(policy[0].value), "1.3.6.1.4.1.32473.2.1");
    let qualifiers = nodes(policy[1].value);
    let cps = nodes(qualifiers[0].value);
    assert_eq!(oid(cps[0].value), "1.3.6.1.5.5.7.2.1");
    assert_eq!(cps[1].tag, 22);
    assert_eq!(string(cps[1].value), "https://policy.example.test/cps");
    let notice = nodes(qualifiers[1].value);
    assert_eq!(oid(notice[0].value), "1.3.6.1.5.5.7.2.2");
    let notice = nodes(notice[1].value);
    assert_eq!(notice[0].tag, 12);
    assert_eq!(string(notice[0].value), "Example service identity policy");
    let mapping = sequence(&ext["2.5.29.33"].1);
    let mapping = nodes(mapping[0].value);
    assert_eq!(oid(mapping[0].value), "1.3.6.1.4.1.32473.2.1");
    assert_eq!(oid(mapping[1].value), "1.3.6.1.4.1.32473.2.2");
    assert_eq!(ext["2.5.29.36"].1, [0x30, 6, 0x80, 1, 0, 0x81, 1, 1]);
    assert_eq!(ext["2.5.29.54"].1, [2, 1, 0]);
    let constraints = sequence(&ext["2.5.29.30"].1);
    assert_eq!(constraints[0].tag, 0xa0);
    assert_eq!(constraints[1].tag, 0xa1);
    let permitted = nodes(constraints[0].value);
    assert_eq!(
        string(nodes(permitted[0].value)[0].value),
        "autobricks.internal"
    );
    assert_eq!(
        nodes(permitted[1].value)[0].value,
        [192, 0, 2, 0, 255, 255, 255, 0]
    );
    assert_eq!(nodes(permitted[2].value)[0].value.len(), 32);
    let excluded = nodes(constraints[1].value);
    assert_eq!(
        string(nodes(excluded[0].value)[0].value),
        "restricted.autobricks.internal"
    );
    let delta = sequence(&ext["2.5.29.46"].1);
    let dp = nodes(delta[0].value);
    let full_name = nodes(dp[0].value);
    let url = nodes(full_name[0].value);
    assert_eq!(url[0].tag, 0x86);
    assert_eq!(
        string(url[0].value),
        "https://pki.example.test/crl/delta.crl"
    );
    let sia = sequence(&ext["1.3.6.1.5.5.7.1.11"].1);
    let sia = nodes(sia[0].value);
    assert_eq!(oid(sia[0].value), "1.3.6.1.4.1.32473.3.1");
    assert_eq!(
        string(sia[1].value),
        "https://service.example.test/information"
    );
    assert_eq!(
        string(sequence(&ext["2.5.29.18"].1)[0].value),
        "www.autobricks.internal"
    );
    let attributes = sequence(&ext["2.5.29.9"].1);
    let attribute = nodes(attributes[0].value);
    assert_eq!(oid(attribute[0].value), "1.3.6.1.4.1.32473.4.1");
    assert_eq!(attribute[1].tag, 0x31);
    assert_eq!(
        string(nodes(attribute[1].value)[0].value),
        "infrastructure-device"
    );
    assert_eq!(ext["1.3.6.1.5.5.7.1.24"].1, [0x30, 3, 2, 1, 5]);
    assert_eq!(ext["1.3.6.1.5.5.7.48.1.5"].1, [5, 0]);
    let statements = sequence(&ext["1.3.6.1.5.5.7.1.3"].1);
    let statement = nodes(statements[0].value);
    assert_eq!(oid(statement[0].value), "1.3.6.1.4.1.32473.5.1");
    assert_eq!(statement[1].tag, 12);
    assert_eq!(string(statement[1].value), "Documentation-only statement");
    let private = nodes(&ext["1.3.6.1.4.1.32473.6.1"].1);
    assert_eq!(private[0].tag, 12);
    assert_eq!(string(private[0].value), "web01-service-metadata");
    assert!(!ext["1.3.6.1.4.1.32473.6.1"].0);
    assert!(ext["2.5.29.19"].0);
    assert_eq!(ext["2.5.29.19"].1, [0x30, 0]);
    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.public_key()
            .unwrap()
            .ec_key()
            .unwrap()
            .group()
            .curve_name(),
        Some(openssl::nid::Nid::X9_62_PRIME256V1)
    );
    assert_eq!(
        issued.certificate.validity.not_after - issued.certificate.validity.not_before,
        47 * 86400
    );
    assert_eq!(
        autobricks_pki::certificate::crypto::fingerprint(&cert).unwrap(),
        issued.certificate.fingerprint
    );
    let stored = f.service.db.get(&issued.certificate.fingerprint).unwrap();
    assert_eq!(stored.pem, issued.certificate.pem);
    assert!(
        cert.public_key().unwrap().public_eq(
            &openssl::pkey::PKey::private_key_from_pem(stored.key_pem.as_bytes()).unwrap()
        )
    );
}

#[test]
fn supplied_values_are_not_relying_application_policy() {
    let f = Fixture::new();
    let mut v = full();
    let p = v["profile"].as_object_mut().unwrap();
    p.insert("common_name".into(), json!("opaque"));
    p.insert(
        "dns_names".into(),
        json!(["www-opaque.autobricks.internal"]),
    );
    p.insert(
        "uri_sans".into(),
        json!(["not a URI", "urn:autobricks:purpose:consumer-defined"]),
    );
    p.insert("country_name".into(), json!("ZZ"));
    p.insert("email_sans".into(), json!(["consumer-defined mailbox"]));
    p.insert(
        "extended_key_usage".into(),
        json!(["serverAuth", "OCSPSigning", "timeStamping"]),
    );
    p.insert(
        "key_usage".into(),
        json!(["keyAgreement", "encipherOnly", "decipherOnly"]),
    );
    p.insert(
        "issuer_alt_name".into(),
        json!({"dns_names":["unverified-issuer-label"]}),
    );
    p["critical"]["extended_key_usage"] = json!(false);
    let issued = f.service.create(request(&v)).unwrap();
    let cert = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let ext = extensions(&cert);
    let values = sequence(&ext["2.5.29.17"].1);
    assert!(
        values
            .iter()
            .any(|n| n.tag == 0x86 && n.value == b"not a URI")
    );
    assert!(
        values
            .iter()
            .any(|n| n.tag == 0x81 && n.value == b"consumer-defined mailbox")
    );
    assert_eq!(ext["2.5.29.15"].1, [3, 3, 7, 9, 128]);
    assert_eq!(sequence(&ext["2.5.29.37"].1).len(), 3);
    assert!(!ext["2.5.29.37"].0);
    assert_eq!(
        string(sequence(&ext["2.5.29.18"].1)[0].value),
        "unverified-issuer-label"
    );
}

#[test]
fn field_length_boundaries_use_characters_and_preserve_input() {
    use autobricks_pki::certificate::extensions::prepare;
    let base = full();
    for (field, max) in [
        ("organization_name", 64),
        ("unit_name", 64),
        ("state_or_province_name", 128),
        ("locality_name", 128),
        ("street_address", 128),
        ("postal_code", 40),
        ("given_name", 64),
        ("surname", 64),
        ("pseudonym", 128),
        ("user_id", 64),
        ("initials", 16),
        ("title", 64),
        ("description", 1024),
        ("business_category", 128),
        ("organization_identifier", 64),
        ("generation_qualifier", 16),
    ] {
        let mut v = base.clone();
        v["profile"][field] = json!("한".repeat(max));
        assert!(prepare(&request(&v).profile).is_ok(), "{field} at limit");
        v["profile"][field] = json!("한".repeat(max + 1));
        assert!(
            prepare(&request(&v).profile).is_err(),
            "{field} above limit"
        );
    }
    for (field, max) in [
        ("subject_serial_number", 64),
        ("dn_qualifier", 64),
        ("subject_email", 128),
    ] {
        let mut v = base.clone();
        v["profile"][field] = json!("a".repeat(max));
        assert!(prepare(&request(&v).profile).is_ok());
        v["profile"][field] = json!("a".repeat(max + 1));
        assert!(prepare(&request(&v).profile).is_err());
    }
    let mut v = base;
    v["profile"]["country_name"] = json!("AAA");
    assert!(prepare(&request(&v).profile).is_err());
    v["profile"]["country_name"] = json!("ZZ");
    v["profile"]["uri_sans"] = json!(["x".repeat(2048)]);
    assert!(prepare(&request(&v).profile).is_ok());
    v["profile"]["uri_sans"] = json!(["x".repeat(2049)]);
    assert!(prepare(&request(&v).profile).is_err());
}

#[test]
fn strict_profile_input_rejects_size_and_structural_errors() {
    assert!(input::create(br#"{"issuer":"a","profile":{"kind":"client","common_name":"a","unit_name":"x","unit_name":"y"}}"#).is_err());
    let mut v = full();
    v["profile"]["unit_name"] = Value::Null;
    assert!(input::create(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = full();
    v["profile"]["kind"] = json!("server");
    assert!(input::create(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = full();
    v["profile"]["unit_name"] = json!("x".repeat(65536));
    assert!(input::create(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = full();
    v["profile"]["other_name_sans"][0]["unknown"] = json!(1);
    assert!(autobricks_pki::certificate::extensions::prepare(&request(&v).profile).is_err());
}

#[test]
fn renewal_preserves_extended_profile_and_non_tls_leaf_lifecycle() {
    let f = Fixture::new();
    let mut v = full();
    v["profile"]["extended_key_usage"] = json!(["codeSigning"]);
    v["profile"]["common_name"] = json!("signer");
    let issued = f.service.create(request(&v)).unwrap();
    assert_eq!(issued.certificate.kind, "leaf");
    assert!(
        f.service
            .db
            .list_certificates(false)
            .unwrap()
            .iter()
            .any(|c| c.fingerprint == issued.certificate.fingerprint)
    );
    let original = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    f.service
        .request_admin_renewal(&issued.certificate.fingerprint, ADMIN)
        .unwrap();
    let renewed = f
        .service
        .renew(&issued.certificate.fingerprint, &issued.download_token)
        .unwrap();
    let new = X509::from_pem(renewed.certificate.pem.as_bytes()).unwrap();
    assert_eq!(
        new.subject_name().to_der().unwrap(),
        original.subject_name().to_der().unwrap()
    );
    let old = extensions(&original);
    let new_ext = extensions(&new);
    for (id, value) in old {
        if id != "2.5.29.14" {
            assert_eq!(new_ext[&id], value, "renewal changed {id}");
        }
    }
    assert_eq!(
        renewed.certificate.validity.not_after - renewed.certificate.validity.not_before,
        issued.certificate.validity.not_after - issued.certificate.validity.not_before
    );
    assert!(
        !original
            .public_key()
            .unwrap()
            .public_eq(&new.public_key().unwrap())
    );
    let conn = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let started: i64 = conn
        .query_row(
            "SELECT superseded_at FROM certificates WHERE fingerprint=?",
            [&issued.certificate.fingerprint],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        f.service.retire_superseded(started + 7 * 86_400).unwrap(),
        1
    );
    assert!(
        f.service
            .db
            .revocation_status(&issued.certificate.fingerprint)
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        f.service
            .db
            .revocation_status(&renewed.certificate.fingerprint)
            .unwrap(),
        Some(None)
    );
}

#[test]
fn typed_values_and_usage_bits_survive_certificate_round_trip() {
    let f = Fixture::new();
    let cases = [
        (
            "UTF8String",
            json!("가나다"),
            vec![12, 9, 0xea, 0xb0, 0x80, 0xeb, 0x82, 0x98, 0xeb, 0x8b, 0xa4],
        ),
        (
            "PrintableString",
            json!("a + / ?"),
            vec![19, 7, b'a', b' ', b'+', b' ', b'/', b' ', b'?'],
        ),
        (
            "IA5String",
            json!("not-an-email"),
            vec![
                22, 12, b'n', b'o', b't', b'-', b'a', b'n', b'-', b'e', b'm', b'a', b'i', b'l',
            ],
        ),
        ("INTEGER", json!("-129"), vec![2, 2, 255, 127]),
        ("BOOLEAN", json!(true), vec![1, 1, 255]),
        (
            "OBJECT IDENTIFIER",
            json!("2.999.3"),
            vec![6, 3, 0x88, 0x37, 3],
        ),
        ("OCTET STRING", json!("AAH/"), vec![4, 3, 0, 1, 255]),
        ("DER", json!("MAMCAQU="), vec![0x30, 3, 2, 1, 5]),
    ];
    for (i, (kind, value, expected)) in cases.into_iter().enumerate() {
        let v = json!({"issuer":"www.autobricks.internal","profile":{
            "common_name":format!("typed{i}"),"extended_key_usage":["clientAuth"],
            "key_usage":["digitalSignature","contentCommitment","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"],
            "other_name_sans":[{"oid":"1.3.6.1.4.1.32473.9.1","asn1_type":kind,"value":value}],
            "private_oid":[{"oid":"1.3.6.1.4.1.32473.9.2","asn1_type":kind,"value":value,"critical":true}],
            "critical":{"key_usage":false,"extended_key_usage":true,"subject_alt_name":true,"subject_key_identifier":true,"authority_key_identifier":true,"authority_info_access":true,"crl_distribution_points":true,"basic_constraints":false}
        }});
        let issued = f.service.create(request(&v)).unwrap();
        let cert = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
        let e = extensions(&cert);
        assert_eq!(
            e["1.3.6.1.4.1.32473.9.2"],
            (true, expected.clone()),
            "{kind}"
        );
        let san = sequence(&e["2.5.29.17"].1);
        let other = nodes(san[0].value);
        assert_eq!(other[1].value, expected, "{kind} otherName wrapper");
        assert_eq!(e["2.5.29.15"], (false, vec![3, 3, 7, 255, 128]));
        for id in [
            "2.5.29.37",
            "2.5.29.17",
            "2.5.29.14",
            "2.5.29.35",
            "1.3.6.1.5.5.7.1.1",
            "2.5.29.31",
        ] {
            assert!(e[id].0, "{id}");
        }
        assert!(!e["2.5.29.19"].0);
    }
}

#[test]
fn legacy_profiles_downloads_and_service_generated_fields_are_preserved() {
    let f = Fixture::new();
    let v = json!({"issuer":"www.autobricks.internal","profile":{"kind":"server","common_name":"legacy","ip_addresses":["192.0.2.20"],"uri_sans":["urn:autobricks:purpose:www"]}});
    let issued = f.service.create(request(&v)).unwrap();
    let certificate = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let e = extensions(&certificate);
    let issuer = f.service.db.issuer("www.autobricks.internal").unwrap();
    let issuer_cert = X509::from_pem(issuer.pem.as_bytes()).unwrap();
    let issuer_ext = extensions(&issuer_cert);
    assert_eq!(nodes(&e["2.5.29.14"].1)[0].value.len(), 20);
    let aki = sequence(&e["2.5.29.35"].1);
    assert_eq!(aki[0].tag, 0x80);
    assert_eq!(aki[0].value, nodes(&issuer_ext["2.5.29.14"].1)[0].value);
    let aia = sequence(&e["1.3.6.1.5.5.7.1.1"].1);
    let access = nodes(aia[0].value);
    assert_eq!(oid(access[0].value), "1.3.6.1.5.5.7.48.1");
    assert_eq!(string(access[1].value), "https://localhost/ocsp/");
    let dp = sequence(&e["2.5.29.31"].1);
    let dp = nodes(dp[0].value);
    let full = nodes(dp[0].value);
    let names = nodes(full[0].value);
    assert_eq!(
        string(names[0].value),
        format!("https://localhost/crl/{}", issuer.fingerprint)
    );
    assert_eq!(
        certificate.signature_algorithm().object().nid(),
        openssl::nid::Nid::ECDSA_WITH_SHA256
    );
    assert_eq!(certificate.serial_number().to_bn().unwrap().num_bits(), 159);
    let archive = f
        .service
        .download(&issued.certificate.fingerprint, &issued.download_token)
        .unwrap();
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice()));
    let mut files = BTreeMap::new();
    for file in tar.entries().unwrap() {
        let mut file = file.unwrap();
        let name = file.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        files.insert(name, bytes);
    }
    assert_eq!(
        files.keys().cloned().collect::<Vec<_>>(),
        ["certificate.pem", "private-key.pem", "trust-chain"]
    );
    assert_eq!(files["certificate.pem"], issued.certificate.pem.as_bytes());
    assert!(
        certificate.public_key().unwrap().public_eq(
            &openssl::pkey::PKey::private_key_from_pem(&files["private-key.pem"]).unwrap()
        )
    );
    assert!(
        f.service
            .download(&issued.certificate.fingerprint, "wrong-token")
            .is_err()
    );
}

#[test]
fn extended_profiles_use_indexes_and_leave_invalid_input_unstored() {
    let f = Fixture::new();
    let connection = rusqlite::Connection::open(f._temp.path().join("pki.sqlite")).unwrap();
    let query = "EXPLAIN QUERY PLAN SELECT idx FROM certificates WHERE kind IN ('server','client','server-and-client','leaf') AND valid='SUPERSEDED' AND idx>0 AND idx<10000 ORDER BY idx LIMIT 257";
    let plan = connection
        .prepare(query)
        .unwrap()
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|p| p.contains("certificates_extended_leaf_state_idx"))
    );
    let before = f.service.db.all().unwrap().len();
    let mut v = full();
    v["profile"]["unit_name"] = json!("x".repeat(65));
    assert!(f.service.create(request(&v)).is_err());
    assert_eq!(f.service.db.all().unwrap().len(), before);
}

#[test]
fn san_duplicates_and_constraint_values_are_not_reinterpreted() {
    let f = Fixture::new();
    let v = json!({"issuer":"www.autobricks.internal","profile":{
        "kind":"client","common_name":"repeated",
        "uri_sans":["same value","same value"],
        "name_constraints":{"permitted_subtrees":[{"email_sans":["..consumer-value"]},{"ip_addresses":["192.0.2.123/24"]}]}
    }});
    let issued = f.service.create(request(&v)).unwrap();
    let cert = X509::from_pem(issued.certificate.pem.as_bytes()).unwrap();
    let e = extensions(&cert);
    let san = sequence(&e["2.5.29.17"].1);
    assert_eq!(san.len(), 2);
    assert_eq!(san[0].value, b"same value");
    assert_eq!(san[1].value, b"same value");
    let nc = sequence(&e["2.5.29.30"].1);
    let subtrees = nodes(nc[0].value);
    assert_eq!(nodes(subtrees[0].value)[0].value, b"..consumer-value");
    assert_eq!(
        nodes(subtrees[1].value)[0].value,
        [192, 0, 2, 123, 255, 255, 255, 0]
    );
}
