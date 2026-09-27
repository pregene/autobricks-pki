use crate::{Result, storage::database::Database};
use openssl::{pkey::PKey, rand::rand_bytes, symm::Cipher};

const PASSWORD_SETTING: &str = "private_key_password";

impl Database {
    pub(crate) fn initialize_key_encryption(&self) -> Result<()> {
        self.transaction(|| {
            if self.setting(PASSWORD_SETTING)?.is_none() {
                let count: i64 = self.conn.query_row(
                    "SELECT count(*) FROM certificates WHERE key_pem LIKE '%BEGIN ENCRYPTED PRIVATE KEY%'",
                    [], |row| row.get(0),
                )?;
                if count != 0 {
                    return Err("encrypted keys exist without their password".into());
                }
                let mut random = [0; 32];
                rand_bytes(&mut random)?;
                let password: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
                self.set_setting(PASSWORD_SETTING, password.as_bytes())?;
            }
            let records = {
                let mut query = self.conn.prepare("SELECT fingerprint,key_pem FROM certificates")?;
                query.query_map([], |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?)))?
                    .collect::<std::result::Result<Vec<_>,_>>()?
            };
            for (fingerprint, pem) in records {
                if pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
                    self.decrypt_key(&pem)?;
                } else {
                    self.conn.execute("UPDATE certificates SET key_pem=? WHERE fingerprint=?",
                        rusqlite::params![self.encrypt_key(&pem)?, fingerprint])?;
                }
            }
            self.conn.pragma_update(None, "user_version", 2)?;
            Ok(())
        })
    }

    pub(crate) fn encrypt_key(&self, pem: &str) -> Result<String> {
        let password = self
            .setting(PASSWORD_SETTING)?
            .ok_or("missing key encryption password")?;
        let key = PKey::private_key_from_pem(pem.as_bytes())?;
        Ok(String::from_utf8(
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), &password)?,
        )?)
    }

    pub(crate) fn decrypt_key(&self, pem: &str) -> Result<String> {
        if !pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return Err("unencrypted stored private key".into());
        }
        let password = self
            .setting(PASSWORD_SETTING)?
            .ok_or("missing key encryption password")?;
        let key = PKey::private_key_from_pem_passphrase(pem.as_bytes(), &password)?;
        Ok(String::from_utf8(key.private_key_to_pem_pkcs8()?)?)
    }

    pub fn encrypted_key(&self, fingerprint: &str) -> Result<String> {
        Ok(self.conn.query_row(
            "SELECT key_pem FROM certificates WHERE fingerprint=?",
            [fingerprint],
            |row| row.get(0),
        )?)
    }
}
