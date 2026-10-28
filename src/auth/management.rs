#![allow(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use libloading::{Library, Symbol};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer, x509::X509};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const IPC_ABI_VERSION: u32 = 5;
const IPC_FRAME_VERSION: u32 = 1;
type Version = unsafe extern "C" fn() -> u32;
type Initialize = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type Uninitialize = unsafe extern "C" fn(*mut c_void);
type Exchange = unsafe extern "C" fn(*const c_void, *const c_char) -> *mut c_char;
type StringFree = unsafe extern "C" fn(*mut c_char);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authentication {
    #[allow(dead_code)]
    required: bool,
    certificate: PathBuf,
    private_key: Option<PathBuf>,
    #[allow(dead_code)]
    peer_certificate: PathBuf,
    #[allow(dead_code)]
    peer_fingerprint: Option<String>,
}

#[derive(Serialize)]
struct Token {
    timestamp: u64,
    fingerprint: String,
    signature: String,
}

#[derive(Deserialize)]
struct Response {
    request_id: u64,
    ok: bool,
    output: Option<String>,
    error: Option<String>,
}

pub(super) struct Client {
    _library: Library,
    handle: *mut c_void,
    exchange: Exchange,
    uninitialize: Uninitialize,
    string_free: StringFree,
    fingerprint: String,
    key: PKey<openssl::pkey::Private>,
    next_request_id: AtomicU64,
    last_timestamp: AtomicU64,
}

unsafe impl Send for Client {}
unsafe impl Sync for Client {}

impl Client {
    pub(super) fn initialize(directory: &Path) -> Result<Self, String> {
        let config_path = std::env::var_os("AUTOBRICKS_AUTH_CONFIG")
            .map(PathBuf::from)
            .ok_or_else(|| "AUTOBRICKS_AUTH_CONFIG is required for Auth management".to_owned())?;
        let root: Value = serde_json::from_slice(
            &std::fs::read(&config_path)
                .map_err(|error| format!("Auth management configuration read failed: {error}"))?,
        )
        .map_err(|error| format!("Auth management configuration is invalid: {error}"))?;
        let ipc = root
            .get("ipc")
            .ok_or_else(|| "Auth management IPC configuration is missing".to_owned())?;
        let authentication: Authentication = serde_json::from_value(
            root.get("ipc_authentication")
                .cloned()
                .ok_or_else(|| "Auth management authentication is missing".to_owned())?,
        )
        .map_err(|error| format!("Auth management authentication is invalid: {error}"))?;
        let key_path = authentication
            .private_key
            .ok_or_else(|| "Auth management private key is required".to_owned())?;
        let certificate = X509::from_pem(
            &std::fs::read(&authentication.certificate)
                .map_err(|error| format!("Auth management certificate read failed: {error}"))?,
        )
        .map_err(|error| format!("Auth management certificate is invalid: {error}"))?;
        let key = PKey::private_key_from_pem(
            &std::fs::read(key_path)
                .map_err(|error| format!("Auth management private key read failed: {error}"))?,
        )
        .map_err(|error| format!("Auth management private key is invalid: {error}"))?;
        if !certificate
            .public_key()
            .map_err(|error| error.to_string())?
            .public_eq(&key)
        {
            return Err("Auth management certificate and private key do not match".to_owned());
        }
        let fingerprint = certificate
            .digest(MessageDigest::sha256())
            .map_err(|error| error.to_string())?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let library_path = directory.join(if cfg!(target_os = "macos") {
            "libautobricks_ipc.dylib"
        } else {
            "libautobricks_ipc.so"
        });
        let library = unsafe { Library::new(&library_path) }.map_err(|error| {
            format!(
                "Auth management IPC library load failed at {}: {error}",
                library_path.display()
            )
        })?;
        let abi = symbol::<Version>(&library, b"ab_ipc_abi_version\0")?;
        let frame = symbol::<Version>(&library, b"ab_ipc_frame_version\0")?;
        if unsafe { abi() } != IPC_ABI_VERSION || unsafe { frame() } != IPC_FRAME_VERSION {
            return Err("Auth management IPC ABI or frame version mismatch".to_owned());
        }
        let initialize = symbol::<Initialize>(&library, b"ab_ipc_client_initialize\0")?;
        let uninitialize = symbol::<Uninitialize>(&library, b"ab_ipc_client_uninitialize\0")?;
        let exchange = symbol::<Exchange>(&library, b"ab_ipc_client_request\0")?;
        let string_free = symbol::<StringFree>(&library, b"ab_ipc_client_response_free\0")?;
        let ipc = CString::new(ipc.to_string())
            .map_err(|_| "Auth management IPC configuration contains NUL".to_owned())?;
        let handle = unsafe { initialize(ipc.as_ptr()) };
        if handle.is_null() {
            return Err("Auth management IPC initialization failed".to_owned());
        }
        Ok(Self {
            _library: library,
            handle,
            exchange,
            uninitialize,
            string_free,
            fingerprint,
            key,
            next_request_id: AtomicU64::new(1),
            last_timestamp: AtomicU64::new(0),
        })
    }

    pub(super) fn execute(
        &self,
        operation: &str,
        server: &str,
        clients: &[String],
    ) -> Result<String, String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut request = match operation {
            "add" if !clients.is_empty() => json!({
                "operation": "add", "request_id": request_id,
                "server_fingerprint": server, "client_fingerprints": clients,
            }),
            "del" if clients.len() <= 1 => json!({
                "operation": "del", "request_id": request_id,
                "server_fingerprint": server,
                "client_fingerprint": clients.first(),
            }),
            _ => return Err("invalid Auth management operation".to_owned()),
        };
        request["token"] = serde_json::to_value(self.token()?)
            .map_err(|error| format!("Auth management token serialization failed: {error}"))?;
        let payload = CString::new(request.to_string())
            .map_err(|_| "Auth management request contains NUL".to_owned())?;
        let pointer = unsafe { (self.exchange)(self.handle, payload.as_ptr()) };
        if pointer.is_null() {
            return Err("Auth management IPC exchange failed".to_owned());
        }
        let text = unsafe { CStr::from_ptr(pointer) }
            .to_str()
            .map(str::to_owned)
            .map_err(|error| format!("Auth management response is not UTF-8: {error}"));
        unsafe { (self.string_free)(pointer) };
        let response: Response = serde_json::from_str(&text?)
            .map_err(|error| format!("Auth management response is invalid: {error}"))?;
        if response.request_id != request_id {
            return Err("Auth management response request_id mismatch".to_owned());
        }
        if response.ok {
            Ok(response.output.unwrap_or_default())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Auth management operation failed".to_owned()))
        }
    }

    fn token(&self) -> Result<Token, String> {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| u64::try_from(value.as_nanos()).unwrap_or(u64::MAX))
            .map_err(|error| error.to_string())?;
        let mut previous = self.last_timestamp.load(Ordering::Relaxed);
        let timestamp = loop {
            let next = current.max(previous.saturating_add(1));
            match self.last_timestamp.compare_exchange_weak(
                previous,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break next,
                Err(observed) => previous = observed,
            }
        };
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)
            .map_err(|error| format!("Auth management token signer failed: {error}"))?;
        signer
            .update(format!("{timestamp}\n{}", self.fingerprint).as_bytes())
            .map_err(|error| format!("Auth management token signer failed: {error}"))?;
        Ok(Token {
            timestamp,
            fingerprint: self.fingerprint.clone(),
            signature: STANDARD.encode(
                signer
                    .sign_to_vec()
                    .map_err(|error| format!("Auth management token signer failed: {error}"))?,
            ),
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.uninitialize)(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    let value: Symbol<'_, T> = unsafe { library.get(name) }
        .map_err(|error| format!("Auth management IPC symbol load failed: {error}"))?;
    Ok(*value)
}
