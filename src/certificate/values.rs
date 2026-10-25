//! Bounded JSON values and direct DER encoding for certificate profile fields.
use crate::{
    Result,
    revocation::der::{self, seq, tlv},
};
use serde_json::{Map, Value};

pub fn object<'a>(v: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let m = v.as_object().ok_or("expected an object")?;
    if m.is_empty() || m.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("empty object or unknown profile member".into());
    }
    Ok(m)
}
pub fn array(v: &Value, max: usize) -> Result<&[Value]> {
    let a = v.as_array().ok_or("expected an array")?;
    if a.is_empty() || a.len() > max {
        return Err("profile array length is out of range".into());
    }
    Ok(a)
}
pub fn text(v: &Value, max: usize, ascii: bool) -> Result<&str> {
    let s = v.as_str().ok_or("expected a string")?;
    if s.is_empty() || s.chars().count() > max || (ascii && !s.is_ascii()) {
        return Err("profile string length or encoding is invalid".into());
    }
    Ok(s)
}
pub fn required<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a Value> {
    m.get(k)
        .ok_or_else(|| format!("missing profile member: {k}").into())
}
pub fn printable(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&c))
}
fn base128(mut n: u64) -> Vec<u8> {
    let mut bytes = vec![(n & 127) as u8];
    n >>= 7;
    while n > 0 {
        bytes.push((n & 127) as u8 | 128);
        n >>= 7;
    }
    bytes.reverse();
    bytes
}
pub fn oid(s: &str) -> Result<Vec<u8>> {
    if s.len() > 100 {
        return Err("OID exceeds 100 bytes".into());
    }
    let parts = s
        .split('.')
        .map(|p| -> Result<u32> {
            if p.is_empty()
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_digit())
            {
                return Err("noncanonical OID".into());
            }
            Ok(p.parse()?)
        })
        .collect::<Result<Vec<_>>>()?;
    if parts.len() < 2 || parts.len() > 20 || parts[0] > 2 || (parts[0] < 2 && parts[1] > 39) {
        return Err("invalid OID components".into());
    }
    let mut bytes = base128(u64::from(parts[0]) * 40 + u64::from(parts[1]));
    for p in &parts[2..] {
        bytes.extend(base128(u64::from(*p)));
    }
    Ok(tlv(6, &bytes))
}
pub fn integer(n: i64) -> Vec<u8> {
    let raw = n.to_be_bytes();
    let mut first = 0;
    while first < 7
        && ((raw[first] == 0 && raw[first + 1] & 128 == 0)
            || (raw[first] == 255 && raw[first + 1] & 128 != 0))
    {
        first += 1;
    }
    tlv(2, &raw[first..])
}
pub fn uri(v: &Value, _https: bool) -> Result<&str> {
    text(v, 2048, true)
}
pub fn base64(v: &Value) -> Result<Vec<u8>> {
    let s = text(v, 5500, true)?;
    let bytes = openssl::base64::decode_block(s)?;
    if openssl::base64::encode_block(&bytes) != s {
        return Err("noncanonical Base64".into());
    }
    Ok(bytes)
}
fn canonical_der(data: &[u8], depth: usize) -> Result<()> {
    if depth > 8 {
        return Err("DER nesting exceeds limit".into());
    }
    let mut input = data;
    let (tag, content, encoded) = der::read(&mut input)?;
    if !input.is_empty() || tag & 31 == 31 || encoded != tlv(tag, content) {
        return Err("noncanonical DER".into());
    }
    if tag & 32 != 0 {
        let mut remaining = content;
        let mut previous: Option<&[u8]> = None;
        while !remaining.is_empty() {
            let (_, _, child) = der::read(&mut remaining)?;
            canonical_der(child, depth + 1)?;
            if tag == 0x31 && previous.is_some_and(|p| p > child) {
                return Err("noncanonical DER SET order".into());
            }
            previous = Some(child);
        }
    } else {
        match tag {
            0x01 if content != [0] && content != [255] => return Err("invalid DER BOOLEAN".into()),
            0x02 if content.is_empty()
                || (content.len() > 1
                    && ((content[0] == 0 && content[1] & 128 == 0)
                        || (content[0] == 255 && content[1] & 128 != 0))) =>
            {
                return Err("invalid DER INTEGER".into());
            }
            0x05 if !content.is_empty() => return Err("invalid DER NULL".into()),
            0x0c => {
                std::str::from_utf8(content)?;
            }
            0x13 if !printable(std::str::from_utf8(content)?) => {
                return Err("invalid DER PrintableString".into());
            }
            0x16 if !content.is_ascii() => return Err("invalid DER IA5String".into()),
            0x00 => return Err("DER end-of-contents is forbidden".into()),
            _ => {}
        }
    }
    Ok(())
}
pub fn typed(m: &Map<String, Value>) -> Result<Vec<u8>> {
    let kind = text(required(m, "asn1_type")?, 32, true)?;
    let value = required(m, "value")?;
    let encoded = match kind {
        "UTF8String" => tlv(12, text(value, 1024, false)?.as_bytes()),
        "IA5String" => tlv(22, text(value, 1024, true)?.as_bytes()),
        "PrintableString" => {
            let s = text(value, 1024, true)?;
            if !printable(s) {
                return Err("invalid PrintableString".into());
            }
            tlv(19, s.as_bytes())
        }
        "INTEGER" => {
            let s = text(value, 20, true)?;
            let n: i64 = s.parse()?;
            if n.to_string() != s {
                return Err("noncanonical integer".into());
            }
            integer(n)
        }
        "BOOLEAN" => tlv(
            1,
            &[if value.as_bool().ok_or("expected Boolean")? {
                255
            } else {
                0
            }],
        ),
        "OBJECT IDENTIFIER" => oid(text(value, 100, true)?)?,
        "OCTET STRING" => {
            let b = base64(value)?;
            if b.is_empty() || b.len() > 4000 {
                return Err("OCTET STRING size exceeds limit".into());
            }
            tlv(4, &b)
        }
        "DER" => {
            let b = base64(value)?;
            canonical_der(&b, 0)?;
            b
        }
        _ => return Err("unsupported ASN.1 input type".into()),
    };
    if encoded.len() > 4096 {
        return Err("typed value exceeds DER limit".into());
    }
    Ok(encoded)
}
pub fn typed_object(v: &Value) -> Result<Vec<u8>> {
    typed(object(v, &["asn1_type", "value"])?)
}
pub fn extension(
    oid_text: &str,
    critical: bool,
    value: &[u8],
) -> Result<openssl::x509::X509Extension> {
    use openssl::asn1::{Asn1Object, Asn1OctetString};
    oid(oid_text)?;
    Ok(openssl::x509::X509Extension::new_from_der(
        Asn1Object::from_str(oid_text)?.as_ref(),
        critical,
        Asn1OctetString::new_from_bytes(value)?.as_ref(),
    )?)
}
pub fn set(parts: &mut [Vec<u8>]) -> Vec<u8> {
    parts.sort();
    tlv(0x31, &parts.concat())
}
pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    seq(parts)
}
