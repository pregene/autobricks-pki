use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaSubject {
    pub country_name: String,
    pub state_or_province_name: String,
    pub locality_name: String,
    pub organization_name: String,
    pub organizational_unit_name: String,
    pub street_address: String,
    pub postal_code: String,
}

impl CaSubject {
    pub fn validate(self) -> Result<Self> {
        if self.country_name.len() != 2
            || !self
                .country_name
                .bytes()
                .all(|value| value.is_ascii_alphabetic())
        {
            return Err("country_name must contain exactly two ASCII letters".into());
        }
        for (value, name, maximum) in [
            (&self.state_or_province_name, "state_or_province_name", 128),
            (&self.locality_name, "locality_name", 128),
            (&self.organization_name, "organization_name", 128),
            (
                &self.organizational_unit_name,
                "organizational_unit_name",
                128,
            ),
            (&self.street_address, "street_address", 128),
            (&self.postal_code, "postal_code", 40),
        ] {
            if value.is_empty()
                || value.len() > maximum
                || !value.is_ascii()
                || value.chars().any(char::is_control)
            {
                return Err(
                    format!("{name} must contain 1-{maximum} printable ASCII characters").into(),
                );
            }
        }
        Ok(self)
    }
}
