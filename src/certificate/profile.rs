use crate::{Result, certificate::validity::Validity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeafKind {
    Server,
    Client,
    ServerAndClient,
    Leaf,
}
impl LeafKind {
    pub fn is_server(self) -> bool {
        matches!(self, Self::Server | Self::ServerAndClient)
    }
}
#[derive(Debug, Clone)]
pub struct LeafProfile {
    pub kind: LeafKind,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub uri_sans: Vec<String>,
    pub validity: Validity,
    pub extra: Map<String, Value>,
}
impl LeafProfile {
    pub fn ekus(&self) -> Vec<String> {
        if let Some(Value::Array(a)) = self.extra.get("extended_key_usage") {
            return a
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        match self.kind {
            LeafKind::Server => vec!["serverAuth".into()],
            LeafKind::Client => vec!["clientAuth".into()],
            LeafKind::ServerAndClient => vec!["serverAuth".into(), "clientAuth".into()],
            LeafKind::Leaf => vec![],
        }
    }
    pub fn validate(&self, issuer: Validity) -> Result<()> {
        super::common_name::leaf(&self.common_name)?;
        self.validity.validate(Some(issuer))?;
        super::extensions::prepare(self)?;
        Ok(())
    }
    fn from_value(value: Value) -> Result<Self> {
        super::input::shape(&value, 1)?;
        let mut m = value
            .as_object()
            .ok_or("profile must be an object")?
            .clone();
        let kind = m.remove("kind");
        let ekus = m.get("extended_key_usage");
        if kind.is_some() && ekus.is_some() {
            return Err("use either kind or extended_key_usage".into());
        }
        let kind = if let Some(v) = kind {
            serde_json::from_value::<LeafKind>(v)?
        } else if let Some(v) = ekus {
            let ids = super::values::array(v, 16)?
                .iter()
                .map(|v| super::extensions::eku(super::values::text(v, 100, true)?))
                .collect::<Result<Vec<_>>>()?;
            match (
                ids.iter().any(|s| s == "1.3.6.1.5.5.7.3.1"),
                ids.iter().any(|s| s == "1.3.6.1.5.5.7.3.2"),
            ) {
                (true, true) => LeafKind::ServerAndClient,
                (true, false) => LeafKind::Server,
                (false, true) => LeafKind::Client,
                _ => LeafKind::Leaf,
            }
        } else {
            return Err("missing kind or extended_key_usage".into());
        };
        let common_name =
            serde_json::from_value(m.remove("common_name").ok_or("missing common_name")?)?;
        let dns_names = serde_json::from_value(
            m.remove("dns_names")
                .unwrap_or_else(|| serde_json::json!([])),
        )?;
        let ip_addresses = serde_json::from_value(
            m.remove("ip_addresses")
                .unwrap_or_else(|| serde_json::json!([])),
        )?;
        let uri_sans = serde_json::from_value(
            m.remove("uri_sans")
                .unwrap_or_else(|| serde_json::json!([])),
        )?;
        let validity = if let Some(v) = m.remove("validity") {
            super::values::object(&v, &["not_before", "not_after"])?;
            serde_json::from_value(v)?
        } else {
            Validity::default()
        };
        for k in m.keys() {
            if !super::names::DN.iter().any(|(f, _, _, _)| k == f)
                && !super::names::SAN.contains(&k.as_str())
                && !super::extensions::EXTENSIONS.iter().any(|(f, _)| k == f)
                && !["critical", "private_oid"].contains(&k.as_str())
            {
                return Err(format!("unknown profile field: {k}").into());
            }
        }
        Ok(Self {
            kind,
            common_name,
            dns_names,
            ip_addresses,
            uri_sans,
            validity,
            extra: m,
        })
    }
}
impl<'de> Deserialize<'de> for LeafProfile {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = super::input::StrictValue::deserialize(d)?;
        Self::from_value(v.0).map_err(serde::de::Error::custom)
    }
}
impl Serialize for LeafProfile {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = self.extra.clone();
        if !m.contains_key("extended_key_usage") {
            m.insert(
                "kind".into(),
                serde_json::to_value(self.kind).map_err(serde::ser::Error::custom)?,
            );
        }
        m.insert(
            "common_name".into(),
            Value::String(self.common_name.clone()),
        );
        m.insert(
            "dns_names".into(),
            serde_json::to_value(&self.dns_names).map_err(serde::ser::Error::custom)?,
        );
        m.insert(
            "ip_addresses".into(),
            serde_json::to_value(&self.ip_addresses).map_err(serde::ser::Error::custom)?,
        );
        m.insert(
            "uri_sans".into(),
            serde_json::to_value(&self.uri_sans).map_err(serde::ser::Error::custom)?,
        );
        m.insert(
            "validity".into(),
            serde_json::to_value(self.validity).map_err(serde::ser::Error::custom)?,
        );
        m.serialize(s)
    }
}
pub use crate::client::origin::Distribution;
pub const AIA_OID: &str = "1.3.6.1.5.5.7.1.1";
pub const OCSP_ACCESS_OID: &str = "1.3.6.1.5.5.7.48.1";
pub const CRL_DISTRIBUTION_OID: &str = "2.5.29.31";
