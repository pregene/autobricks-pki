use crate::{Result, server::service::Service};
use openssl::x509::X509;
use rusqlite::OptionalExtension;

impl Service {
    /// Render the public certificate without loading any private key.
    pub fn certificate_info(&self, fingerprint: &str) -> Result<Option<Vec<u8>>> {
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("fingerprint must contain 64 lowercase hexadecimal characters".into());
        }
        let path: Option<String> = self
            .db
            .conn
            .query_row(
                "SELECT certificate_path FROM certificates WHERE fingerprint=?",
                [fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        let Some(path) = path else {
            return Ok(None);
        };
        let pem = self.worm.read_text(&path)?;
        let certificate = X509::from_pem(pem.as_bytes())?;
        if super::crypto::fingerprint(&certificate)? != fingerprint {
            return Err("stored certificate fingerprint mismatch".into());
        }
        let mut output = format!("SHA256 Fingerprint: {fingerprint}\n").into_bytes();
        output.extend(certificate.to_text()?);
        Ok(Some(output))
    }
}
