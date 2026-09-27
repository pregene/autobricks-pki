use crate::Result;
use openssl::{
    nid::Nid,
    x509::{X509Name, X509NameBuilder},
};

pub fn name(common_name: &str) -> Result<X509Name> {
    let mut name = X509NameBuilder::new()?;
    for (attribute, value) in [
        (Nid::COUNTRYNAME, "KR"),
        (Nid::STATEORPROVINCENAME, "Seoul"),
        (Nid::LOCALITYNAME, "Seoul"),
        (Nid::ORGANIZATIONNAME, "Autobricks, Co."),
        (Nid::ORGANIZATIONALUNITNAME, "Autobricks PKI Service"),
        (Nid::COMMONNAME, common_name),
    ] {
        name.append_entry_by_nid(attribute, value)?;
    }
    Ok(name.build())
}
