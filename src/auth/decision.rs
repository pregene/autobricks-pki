use crate::{Result, revocation::ocsp, storage::database::Certificate};

pub const REQUEST_TYPE: &str = "application/ocsp-request";
pub const RESPONSE_TYPE: &str = "application/ocsp-response";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Good,
    Revoked,
    Unknown,
}

/// Resolves CLIENT then SERVER CertIDs and produces the fail-closed AUTH token.
pub fn respond(
    body: &[u8],
    database: &crate::storage::database::Database,
    now: i64,
    check: impl FnOnce(&str, &str) -> Result<bool>,
) -> Vec<u8> {
    let Ok(queries) = ocsp::auth_queries(body) else {
        return b"UNKNOWN:DENY".to_vec();
    };
    let records = queries
        .iter()
        .map(|query| ocsp::resolve_auth_query(database, query))
        .collect::<Result<Vec<_>>>();
    let Ok(records) = records else {
        return b"UNKNOWN:DENY".to_vec();
    };
    let client = records.first().and_then(Option::as_ref);
    let server = records.get(1).and_then(Option::as_ref);
    let client_status = status(client, true, now);
    let server_status = status(server, false, now);
    if [client_status, server_status].contains(&Status::Revoked) {
        return b"REVOKED:DENY".to_vec();
    }
    if client_status != Status::Good || server_status != Status::Good {
        return b"UNKNOWN:DENY".to_vec();
    }
    let Some((client, server)) = client.zip(server) else {
        return b"UNKNOWN:DENY".to_vec();
    };
    match check(&server.fingerprint, &client.fingerprint) {
        Ok(true) => b"GOOD:ALLOW".to_vec(),
        Ok(false) => b"GOOD:DENY".to_vec(),
        Err(_) => b"UNKNOWN:DENY".to_vec(),
    }
}

fn status(record: Option<&Certificate>, client: bool, now: i64) -> Status {
    let Some(record) = record else {
        return Status::Unknown;
    };
    if record.revoked_at.is_some() {
        return Status::Revoked;
    }
    let capable = if client {
        matches!(record.kind.as_str(), "client" | "server-and-client")
    } else {
        matches!(record.kind.as_str(), "server" | "server-and-client")
    };
    if capable && record.validity.not_before <= now && record.validity.not_after > now {
        Status::Good
    } else {
        Status::Unknown
    }
}
