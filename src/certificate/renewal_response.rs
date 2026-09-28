use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RenewalResponse {
    pub result: u16,
    pub renewed: bool,
    pub status: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_token: Option<String>,
}

impl RenewalResponse {
    pub fn state(result: u16, status: &str, fingerprint: &str) -> Self {
        Self {
            result,
            renewed: false,
            status: status.into(),
            fingerprint: fingerprint.into(),
            previous_fingerprint: None,
            superseded_at: None,
            revoke_at: None,
            download_token: None,
        }
    }
}
