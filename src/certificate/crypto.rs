#![allow(unsafe_code)]
use crate::{
    Result,
    certificate::{
        profile::{Distribution, LeafProfile},
        validity::Validity,
    },
};
use libloading::{Library, Symbol};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rand::rand_bytes,
    symm::Cipher,
    x509::X509,
};
use std::{
    mem::{MaybeUninit, size_of},
    path::{Path, PathBuf},
    slice,
};
const ABI: u32 = 1;
#[repr(C)]
#[derive(Clone, Copy)]
struct Bytes {
    data: *const u8,
    length: usize,
}
#[repr(C)]
struct Buffer {
    data: *mut u8,
    length: usize,
    capacity: usize,
}
#[repr(C)]
struct CaRequest {
    struct_size: usize,
    abi_version: u32,
    common_name: Bytes,
    not_before: i64,
    not_after: i64,
    issuer_certificate_pem: Bytes,
    issuer_private_key_pem: Bytes,
    issuer_private_key_password: Bytes,
    existing_private_key_pem: Bytes,
    existing_private_key_password: Bytes,
    previous_certificate_pem: Bytes,
}
#[repr(C)]
struct LeafRequest {
    struct_size: usize,
    abi_version: u32,
    profile_frame: Bytes,
    issuer_certificate_pem: Bytes,
    issuer_private_key_pem: Bytes,
    issuer_private_key_password: Bytes,
    distribution_origin: Bytes,
    issuer_id: Bytes,
}
#[repr(C)]
struct Generated {
    struct_size: usize,
    certificate_pem: Buffer,
    private_key_pem: Buffer,
    private_key_password: Buffer,
    fingerprint: Buffer,
    serial: Buffer,
    error: Buffer,
}
type GenCa = unsafe extern "C" fn(*const CaRequest, *mut Generated) -> i32;
type GenLeaf = unsafe extern "C" fn(*const LeafRequest, *mut Generated) -> i32;
type Free = unsafe extern "C" fn(Generated);
type ProtectedIssuer = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
fn filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libautobricks_certificate.dylib"
    } else {
        "libautobricks_certificate.so"
    }
}
fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AUTOBRICKS_CERTIFICATE_LIBRARY").map(PathBuf::from) {
        return p
            .is_file()
            .then_some(p)
            .ok_or_else(|| "AUTOBRICKS_CERTIFICATE_LIBRARY is not a file".into());
    }
    if let Some(d) = std::env::current_exe()?.parent() {
        let p = d.join(filename());
        if p.is_file() {
            return Ok(p);
        }
    }
    for d in ["/usr/lib/autobricks", "/usr/local/lib/autobricks"] {
        let p = Path::new(d).join(filename());
        if p.is_file() {
            return Ok(p);
        }
    }
    Err("Autobricks Certificate dynamic library was not found".into())
}
fn b(v: &[u8]) -> Bytes {
    Bytes {
        data: v.as_ptr(),
        length: v.len(),
    }
}
fn opt(v: Option<&[u8]>) -> Bytes {
    v.map(b).unwrap_or(Bytes {
        data: std::ptr::null(),
        length: 0,
    })
}
unsafe fn copy(v: &Buffer) -> Vec<u8> {
    if v.data.is_null() {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(v.data, v.length) }.to_vec()
    }
}
fn finish(status: i32, v: Generated, free: &Symbol<Free>) -> Result<(X509, PKey<Private>)> {
    let c = unsafe { copy(&v.certificate_pem) };
    let k = unsafe { copy(&v.private_key_pem) };
    let p = unsafe { copy(&v.private_key_password) };
    let e = unsafe { copy(&v.error) };
    unsafe { free(v) };
    if status != 0 {
        return Err(String::from_utf8(e)
            .unwrap_or_else(|_| "certificate generation failed".into())
            .into());
    }
    Ok((
        X509::from_pem(&c)?,
        PKey::private_key_from_pem_passphrase(&k, &p)?,
    ))
}
fn protected(k: &PKey<Private>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut r = [0u8; 32];
    rand_bytes(&mut r)?;
    let p: String = r.iter().map(|v| format!("{v:02x}")).collect();
    Ok((
        k.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), p.as_bytes())?,
        p.into_bytes(),
    ))
}
fn issuer(v: Option<(&X509, &PKey<Private>)>) -> Result<ProtectedIssuer> {
    match v {
        Some((c, k)) => {
            let (k, p) = protected(k)?;
            Ok((Some(c.to_pem()?), Some(k), Some(p)))
        }
        None => Ok((None, None, None)),
    }
}
fn call_ca(r: &CaRequest) -> Result<(X509, PKey<Private>)> {
    let l = unsafe { Library::new(path()?)? };
    let g: Symbol<GenCa> = unsafe { l.get(b"ab_certificate_generate_ca_v1\0")? };
    let f: Symbol<Free> = unsafe { l.get(b"ab_certificate_free_result_v1\0")? };
    let mut o = MaybeUninit::uninit();
    let s = unsafe { g(r, o.as_mut_ptr()) };
    finish(s, unsafe { o.assume_init() }, &f)
}
fn call_leaf(r: &LeafRequest) -> Result<(X509, PKey<Private>)> {
    let l = unsafe { Library::new(path()?)? };
    let g: Symbol<GenLeaf> = unsafe { l.get(b"ab_certificate_generate_leaf_v1\0")? };
    let f: Symbol<Free> = unsafe { l.get(b"ab_certificate_free_result_v1\0")? };
    let mut o = MaybeUninit::uninit();
    let s = unsafe { g(r, o.as_mut_ptr()) };
    finish(s, unsafe { o.assume_init() }, &f)
}
pub fn fingerprint(c: &X509) -> Result<String> {
    Ok(c.digest(MessageDigest::sha256())?
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect())
}
pub fn serial(c: &X509) -> Result<String> {
    Ok(c.serial_number().to_bn()?.to_hex_str()?.to_string())
}
pub fn ca(
    cn: &str,
    i: Option<(&X509, &PKey<Private>)>,
    v: Validity,
) -> Result<(X509, PKey<Private>)> {
    let (c, k, p) = issuer(i)?;
    call_ca(&CaRequest {
        struct_size: size_of::<CaRequest>(),
        abi_version: ABI,
        common_name: b(cn.as_bytes()),
        not_before: v.not_before,
        not_after: v.not_after,
        issuer_certificate_pem: opt(c.as_deref()),
        issuer_private_key_pem: opt(k.as_deref()),
        issuer_private_key_password: opt(p.as_deref()),
        existing_private_key_pem: opt(None),
        existing_private_key_password: opt(None),
        previous_certificate_pem: opt(None),
    })
}
pub fn renew_ca(
    cn: &str,
    i: Option<(&X509, &PKey<Private>)>,
    v: Validity,
    existing: &PKey<Private>,
    previous: &X509,
) -> Result<(X509, PKey<Private>)> {
    let (c, k, p) = issuer(i)?;
    let (ek, ep) = protected(existing)?;
    let prev = previous.to_pem()?;
    call_ca(&CaRequest {
        struct_size: size_of::<CaRequest>(),
        abi_version: ABI,
        common_name: b(cn.as_bytes()),
        not_before: v.not_before,
        not_after: v.not_after,
        issuer_certificate_pem: opt(c.as_deref()),
        issuer_private_key_pem: opt(k.as_deref()),
        issuer_private_key_password: opt(p.as_deref()),
        existing_private_key_pem: b(&ek),
        existing_private_key_password: b(&ep),
        previous_certificate_pem: b(&prev),
    })
}
pub fn leaf(
    p: &LeafProfile,
    i: &X509,
    k: &PKey<Private>,
    d: &Distribution,
    id: &str,
) -> Result<(X509, PKey<Private>)> {
    let frame = rmp_serde::to_vec_named(p)?;
    let cert = i.to_pem()?;
    let (key, pass) = protected(k)?;
    let origin = d.ocsp().trim_end_matches("ocsp/").to_owned();
    call_leaf(&LeafRequest {
        struct_size: size_of::<LeafRequest>(),
        abi_version: ABI,
        profile_frame: b(&frame),
        issuer_certificate_pem: b(&cert),
        issuer_private_key_pem: b(&key),
        issuer_private_key_password: b(&pass),
        distribution_origin: b(origin.as_bytes()),
        issuer_id: b(id.as_bytes()),
    })
}
