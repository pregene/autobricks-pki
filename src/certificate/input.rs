use crate::Result;
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

pub const MAX_CREATE: usize = 65_536;
pub struct StrictValue(pub Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictValue(n.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = vec![];
                while let Some(v) = a.next_element::<StrictValue>()? {
                    out.push(v.0);
                }
                Ok(StrictValue(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom(format!("duplicate JSON member: {k}")));
                    }
                    out.insert(k, a.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn shape(v: &Value, depth: usize) -> Result<()> {
    if depth > 12 {
        return Err("profile nesting exceeds limit".into());
    }
    match v {
        Value::Null => return Err("omit optional fields instead of null".into()),
        Value::Object(m) => {
            for child in m.values() {
                shape(child, depth + 1)?;
            }
        }
        Value::Array(a) => {
            for child in a {
                shape(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn create(bytes: &[u8]) -> Result<crate::server::service::Create> {
    if bytes.len() > MAX_CREATE {
        return Err("create request exceeds 65536 bytes".into());
    }
    let v: StrictValue = serde_json::from_slice(bytes)?;
    shape(&v.0, 0)?;
    Ok(serde_json::from_value(v.0)?)
}
