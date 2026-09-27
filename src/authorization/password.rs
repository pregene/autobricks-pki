use crate::{Result, storage::database::Database};
use openssl::{hash::MessageDigest, memcmp, pkcs5::pbkdf2_hmac, rand::rand_bytes};
const ITERATIONS: usize = 600_000;
pub fn set(db: &Database, password: &[u8]) -> Result<()> {
    if password.len() < 12 {
        return Err("administrator password must contain at least 12 bytes".into());
    }
    let mut salt = [0u8; 32];
    rand_bytes(&mut salt)?;
    let mut hash = [0u8; 32];
    pbkdf2_hmac(
        password,
        &salt,
        ITERATIONS,
        MessageDigest::sha256(),
        &mut hash,
    )?;
    let mut value = salt.to_vec();
    value.extend_from_slice(&hash);
    db.set_setting("administrator_password", &value)
}
pub fn verify(db: &Database, password: &[u8]) -> Result<()> {
    let value = db
        .setting("administrator_password")?
        .ok_or("administrator password is not configured")?;
    if value.len() != 64 {
        return Err("invalid administrator password record".into());
    }
    let mut hash = [0u8; 32];
    pbkdf2_hmac(
        password,
        &value[..32],
        ITERATIONS,
        MessageDigest::sha256(),
        &mut hash,
    )?;
    if !memcmp::eq(&hash, &value[32..]) {
        return Err("administrator authorization failed".into());
    }
    Ok(())
}
