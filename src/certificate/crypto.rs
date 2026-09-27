use crate::{
    Result,
    certificate::{
        profile::{Distribution, LeafKind, LeafProfile},
        validity::Validity,
    },
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509Builder, X509Extension, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
pub fn key() -> Result<PKey<Private>> {
    Ok(PKey::from_ec_key(EcKey::generate(
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
    )?)?)
}
pub fn fingerprint(cert: &X509) -> Result<String> {
    Ok(cert
        .digest(MessageDigest::sha256())?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub fn serial(cert: &X509) -> Result<String> {
    Ok(cert.serial_number().to_bn()?.to_hex_str()?.to_string())
}
fn random_serial() -> Result<Asn1Integer> {
    let mut n = BigNum::new()?;
    n.rand(159, MsbOption::ONE, false)?;
    Ok(n.to_asn1_integer()?)
}
fn base(
    cn: &str,
    key: &PKey<Private>,
    issuer: Option<&X509>,
    validity: Validity,
) -> Result<X509Builder> {
    validity.validate(None)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name.build();
    let mut b = X509::builder()?;
    b.set_version(2)?;
    b.set_serial_number(random_serial()?.as_ref())?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(issuer.map(|c| c.subject_name()).unwrap_or(&name))?;
    b.set_pubkey(key)?;
    b.set_not_before(Asn1Time::from_unix(validity.not_before)?.as_ref())?;
    b.set_not_after(Asn1Time::from_unix(validity.not_after)?.as_ref())?;
    Ok(b)
}
pub fn ca(
    cn: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    validity: Validity,
) -> Result<(X509, PKey<Private>)> {
    ca_with_key(cn, issuer, validity, key()?)
}
pub fn ca_with_key(
    cn: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    validity: Validity,
    key: PKey<Private>,
) -> Result<(X509, PKey<Private>)> {
    ca_with_subject(cn, issuer, validity, key, None)
}
pub fn ca_with_subject(
    cn: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    validity: Validity,
    key: PKey<Private>,
    subject: Option<&openssl::x509::X509NameRef>,
) -> Result<(X509, PKey<Private>)> {
    let parent = issuer.map(|p| p.0);
    let mut b = base(cn, &key, parent, validity)?;
    let default_subject = crate::authority::subject::name(cn)?;
    let subject = subject.unwrap_or(default_subject.as_ref());
    b.set_subject_name(subject)?;
    if parent.is_none() {
        b.set_issuer_name(subject)?;
    }
    if issuer.is_none() {
        b.set_not_after(Asn1Time::from_str_x509(crate::authority::ROOT_NOT_AFTER)?.as_ref())?;
    }
    b.append_extension(
        BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(if issuer.is_none() { 1 } else { 0 })
            .build()?,
    )?;
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    let ski =
        SubjectKeyIdentifier::new().build(&b.x509v3_context(parent.map(|x| x.as_ref()), None))?;
    b.append_extension(ski)?;
    if parent.is_some() {
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&b.x509v3_context(parent.map(|x| x.as_ref()), None))?;
        b.append_extension(aki)?;
    }
    b.sign(issuer.map(|p| p.1).unwrap_or(&key), MessageDigest::sha256())?;
    Ok((b.build(), key))
}
pub fn leaf(
    profile: &LeafProfile,
    issuer: &X509,
    issuer_key: &PKey<Private>,
    distribution: &Distribution,
    issuer_id: &str,
) -> Result<(X509, PKey<Private>)> {
    let key = key()?;
    let mut b = base(&profile.common_name, &key, Some(issuer), profile.validity)?;
    b.append_extension(BasicConstraints::new().critical().build()?)?;
    b.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    let mut eku = ExtendedKeyUsage::new();
    if profile.kind.is_server() {
        eku.server_auth();
    }
    if profile.kind != LeafKind::Server {
        eku.client_auth();
    }
    b.append_extension(eku.build()?)?;
    let mut san = SubjectAlternativeName::new();
    for name in &profile.dns_names {
        san.dns(name);
    }
    for ip in &profile.ip_addresses {
        san.ip(&ip.to_string());
    }
    for uri in &profile.uri_sans {
        san.uri(uri);
    }
    if !profile.dns_names.is_empty()
        || !profile.ip_addresses.is_empty()
        || !profile.uri_sans.is_empty()
    {
        let e = san.build(&b.x509v3_context(Some(issuer), None))?;
        b.append_extension(e)?;
    }
    let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(Some(issuer), None))?;
    b.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&b.x509v3_context(Some(issuer), None))?;
    b.append_extension(aki)?;
    #[allow(deprecated)]
    let aia = X509Extension::new_nid(
        None,
        Some(&b.x509v3_context(Some(issuer), None)),
        Nid::INFO_ACCESS,
        &format!("OCSP;URI:{}", distribution.ocsp()),
    )?;
    b.append_extension(aia)?;
    #[allow(deprecated)]
    let crl = X509Extension::new_nid(
        None,
        Some(&b.x509v3_context(Some(issuer), None)),
        Nid::CRL_DISTRIBUTION_POINTS,
        &format!("URI:{}", distribution.crl(issuer_id)?),
    )?;
    b.append_extension(crl)?;
    b.sign(issuer_key, MessageDigest::sha256())?;
    Ok((b.build(), key))
}
