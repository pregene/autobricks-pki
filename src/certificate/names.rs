use super::values::*;
use crate::{Result, revocation::der::tlv};
use serde_json::{Map, Value};

pub const DN: &[(&str, &str, usize, u8)] = &[
    ("common_name", "2.5.4.3", 64, 12),
    ("organization_name", "2.5.4.10", 64, 12),
    ("unit_name", "2.5.4.11", 64, 12),
    ("country_name", "2.5.4.6", 2, 19),
    ("state_or_province_name", "2.5.4.8", 128, 12),
    ("locality_name", "2.5.4.7", 128, 12),
    ("street_address", "2.5.4.9", 128, 12),
    ("postal_code", "2.5.4.17", 40, 12),
    ("subject_serial_number", "2.5.4.5", 64, 19),
    ("given_name", "2.5.4.42", 64, 12),
    ("surname", "2.5.4.4", 64, 12),
    ("pseudonym", "2.5.4.65", 128, 12),
    ("user_id", "0.9.2342.19200300.100.1.1", 64, 12),
    ("domain_components", "0.9.2342.19200300.100.1.25", 63, 22),
    ("initials", "2.5.4.43", 16, 12),
    ("title", "2.5.4.12", 64, 12),
    ("description", "2.5.4.13", 1024, 12),
    ("business_category", "2.5.4.15", 128, 12),
    ("organization_identifier", "2.5.4.97", 64, 12),
    ("dn_qualifier", "2.5.4.46", 64, 19),
    ("generation_qualifier", "2.5.4.44", 16, 12),
    ("subject_email", "1.2.840.113549.1.9.1", 128, 22),
];
pub const SAN: &[&str] = &[
    "dns_names",
    "ip_addresses",
    "uri_sans",
    "email_sans",
    "directory_name_sans",
    "registered_id_sans",
    "other_name_sans",
];
pub fn dns(s: &str) -> Result<String> {
    if s.is_empty() || s.len() > 253 || !s.is_ascii() {
        return Err("DNS value exceeds IA5String length/type limits".into());
    }
    Ok(s.to_owned())
}
pub fn email(s: &str) -> Result<String> {
    if s.is_empty() || s.len() > 254 || !s.is_ascii() {
        return Err("mailbox value exceeds IA5String length/type limits".into());
    }
    Ok(s.to_owned())
}
pub fn dn(m: &Map<String, Value>) -> Result<Vec<u8>> {
    if m.is_empty() || m.keys().any(|k| !DN.iter().any(|(f, _, _, _)| k == f)) {
        return Err("invalid DN object".into());
    }
    let mut parts = vec![];
    for &(field, id, max, tag) in DN {
        if let Some(v) = m.get(field) {
            let values: Vec<&Value> = if field == "domain_components" {
                array(v, 8)?.iter().collect()
            } else {
                vec![v]
            };
            for value in values {
                let s = text(value, max, tag != 12)?;
                if (tag == 19 && !printable(s)) || (field == "country_name" && s.len() != 2) {
                    return Err("invalid DN string encoding".into());
                }
                let normalized = match field {
                    "domain_components" => dns(s)?,
                    "subject_email" => email(s)?,
                    _ => s.to_owned(),
                };
                parts.push(tlv(
                    0x31,
                    &sequence(&[oid(id)?, tlv(tag, normalized.as_bytes())]),
                ));
            }
        }
    }
    Ok(sequence(&parts))
}
pub fn general_names(m: &Map<String, Value>, constraint: bool) -> Result<Vec<Vec<u8>>> {
    if m.keys().any(|k| !SAN.contains(&k.as_str())) {
        return Err("unknown GeneralName field".into());
    }
    let mut out = vec![];
    for field in SAN {
        if let Some(v) = m.get(*field) {
            for item in array(v, 16)? {
                let value = match *field {
                    "dns_names" => {
                        let s = text(item, 254, true)?;
                        let dot = constraint && s.starts_with('.');
                        let n = dns(if dot { &s[1..] } else { s })?;
                        tlv(
                            0x82,
                            format!("{}{n}", if dot { "." } else { "" }).as_bytes(),
                        )
                    }
                    "email_sans" => {
                        let s = text(item, 254, true)?;
                        let n = email(s)?;
                        tlv(0x81, n.as_bytes())
                    }
                    "uri_sans" => {
                        let s = if constraint {
                            text(item, 254, true)?
                        } else {
                            uri(item, false)?
                        };
                        if constraint {
                            dns(s.strip_prefix('.').unwrap_or(s))?;
                        }
                        tlv(0x86, s.as_bytes())
                    }
                    "ip_addresses" => {
                        let s = text(item, 64, true)?;
                        let mut bytes = vec![];
                        if constraint {
                            let (address, prefix) = s
                                .split_once('/')
                                .ok_or("IP constraint requires address/prefix")?;
                            let address: std::net::IpAddr = address.parse()?;
                            let prefix: u32 = prefix.parse()?;
                            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                                return Err("IP mask prefix exceeds address width".into());
                            }
                            match address {
                                std::net::IpAddr::V4(ip) => {
                                    bytes.extend(ip.octets());
                                    bytes.extend(
                                        u32::MAX
                                            .checked_shl(32 - prefix)
                                            .unwrap_or(0)
                                            .to_be_bytes(),
                                    );
                                }
                                std::net::IpAddr::V6(ip) => {
                                    bytes.extend(ip.octets());
                                    bytes.extend(
                                        u128::MAX
                                            .checked_shl(128 - prefix)
                                            .unwrap_or(0)
                                            .to_be_bytes(),
                                    );
                                }
                            }
                        } else {
                            match s.parse::<std::net::IpAddr>()? {
                                std::net::IpAddr::V4(ip) => bytes.extend(ip.octets()),
                                std::net::IpAddr::V6(ip) => bytes.extend(ip.octets()),
                            }
                        }
                        tlv(0x87, &bytes)
                    }
                    "directory_name_sans" => {
                        tlv(0xa4, &dn(item.as_object().ok_or("expected DN object")?)?)
                    }
                    "registered_id_sans" if !constraint => {
                        let mut b = oid(text(item, 100, true)?)?;
                        b[0] = 0x88;
                        b
                    }
                    "other_name_sans" if !constraint => {
                        let m = object(item, &["oid", "asn1_type", "value"])?;
                        tlv(
                            0xa0,
                            &[
                                oid(text(required(m, "oid")?, 100, true)?)?,
                                tlv(0xa0, &typed(m)?),
                            ]
                            .concat(),
                        )
                    }
                    _ => return Err("unsupported constraint name form".into()),
                };
                out.push(value);
            }
        }
    }
    if out.is_empty() || out.len() > 64 {
        return Err("GeneralNames count is out of range".into());
    }
    Ok(out)
}
