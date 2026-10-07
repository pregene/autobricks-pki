use crate::Result;
use url::Url;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_origins_require_verified_https_without_extra_url_components() {
        for origin in [
            "http://pki.example/",
            "https://user@pki.example/",
            "https://pki.example/path",
            "https://pki.example/?query=1",
            "https://pki.example/#fragment",
        ] {
            assert!(Distribution::new(origin).is_err(), "{origin}");
        }
        assert!(Distribution::new("https://pki.example:5546/").is_ok());
        assert!(Distribution::new("https://[::1]:5546/").is_ok());
    }

    #[test]
    fn shared_distribution_preserves_issuer_path_encoding() {
        let origin = Distribution::new("https://pki.example:5546/").unwrap();
        assert_eq!(origin.ocsp(), "https://pki.example:5546/ocsp/");
        assert_eq!(
            origin.crl("ca/name").unwrap(),
            "https://pki.example:5546/crl/ca%2Fname"
        );
        assert!(origin.crl("..").is_err());
    }
}
