use crate::{
    Result,
    certificate::{purpose, validity::Validity},
};
use serde::{Deserialize, Serialize};
use url::Url;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeafKind {
    Server,
    Client,
    ServerAndClient,
}
impl LeafKind {
    pub fn is_server(self) -> bool {
        self != Self::Client
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafProfile {
    pub kind: LeafKind,
    pub common_name: String,
    #[serde(default)]
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<std::net::IpAddr>,
    #[serde(default)]
    pub uri_sans: Vec<String>,
    #[serde(default)]
    pub validity: Validity,
}
impl LeafProfile {
    pub fn validate(&self, issuer: Validity) -> Result<()> {
        super::common_name::leaf(&self.common_name)?;
        purpose::validate(&self.uri_sans, self.kind.is_server())?;
        let mut source_count = 0;
        for uri in &self.uri_sans {
            if uri.chars().any(char::is_control) {
                return Err("invalid URI SAN".into());
            }
            if uri.starts_with("urn:autobricks:")
                && !uri.starts_with(purpose::PREFIX)
                && matches!(
                    super::access::Access::parse(uri)?,
                    super::access::Access::Source(_)
                )
            {
                source_count += 1;
            }
        }
        if source_count > 1 {
            return Err("only one source CIDR policy is supported".into());
        }

        self.validity.validate(Some(issuer))
    }
}
#[derive(Debug, Clone)]
pub struct Distribution {
    base: Url,
}
impl Distribution {
    pub fn new(base: &str) -> Result<Self> {
        let base = Url::parse(base)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(
                "service address must be an HTTPS origin without credentials, query, or path"
                    .into(),
            );
        }
        Ok(Self { base })
    }
    pub fn ocsp(&self) -> String {
        format!("{}ocsp/", self.base)
    }
    pub fn crl(&self, issuer: &str) -> Result<String> {
        if issuer.is_empty()
            || issuer == "."
            || issuer == ".."
            || issuer.chars().any(char::is_control)
        {
            return Err("invalid CRL issuer identifier".into());
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| "invalid origin")?
            .pop_if_empty()
            .push("crl")
            .push(issuer);
        Ok(url.into())
    }
}
pub const AIA_OID: &str = "1.3.6.1.5.5.7.1.1";
pub const OCSP_ACCESS_OID: &str = "1.3.6.1.5.5.7.48.1";
pub const CRL_DISTRIBUTION_OID: &str = "2.5.29.31";
