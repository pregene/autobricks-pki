//! Dynamic Autobricks Auth consumer boundary.

#![allow(unsafe_code)]

pub mod decision;

use libloading::{Library, Symbol};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    path::{Path, PathBuf},
    ptr,
};

const ABI_VERSION: u32 = 3;

#[cfg(target_os = "macos")]
const LIBRARY_NAME: &str = "libautobricks_auth.dylib";
#[cfg(not(target_os = "macos"))]
const LIBRARY_NAME: &str = "libautobricks_auth.so";

type AbiVersion = unsafe extern "C" fn() -> u32;
type Initialize = unsafe extern "C" fn() -> *mut c_void;
type Check = unsafe extern "C" fn(*const c_void, *const c_char, *const c_char) -> i32;
type LastError = unsafe extern "C" fn() -> *const c_char;
type Uninitialize = unsafe extern "C" fn(*mut c_void) -> i32;

/// One process-local client of the running Autobricks Auth service.
pub struct Runtime {
    handle: *mut c_void,
    check: Check,
    last_error: LastError,
    uninitialize: Uninitialize,
    _library: Library,
}

unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    /// Loads the Auth module and connects it to the configured local Auth service.
    pub fn initialize() -> Result<Self, String> {
        let path = library_path()?;
        let library = unsafe { Library::new(&path) }
            .map_err(|error| format!("Auth library load failed at {}: {error}", path.display()))?;
        let abi = symbol::<AbiVersion>(&library, b"ab_auth_abi_version\0")?;
        if unsafe { abi() } != ABI_VERSION {
            return Err(format!(
                "unsupported Autobricks Auth ABI: expected {ABI_VERSION}"
            ));
        }
        let initialize = symbol::<Initialize>(&library, b"ab_auth_initialize\0")?;
        let check = symbol::<Check>(&library, b"ab_auth_check\0")?;
        let last_error = symbol::<LastError>(&library, b"ab_auth_last_error\0")?;
        let uninitialize = symbol::<Uninitialize>(&library, b"ab_auth_uninitialize\0")?;
        let handle = unsafe { initialize() };
        if handle.is_null() {
            return Err(format!("Auth initialization failed: {}", unsafe {
                diagnostic(last_error)
            }));
        }
        Ok(Self {
            handle,
            check,
            last_error,
            uninitialize,
            _library: library,
        })
    }

    /// Returns true only for an explicit ALLOW decision. Errors remain distinct.
    pub fn check(
        &self,
        server_fingerprint: &str,
        client_fingerprint: &str,
    ) -> Result<bool, String> {
        let server = CString::new(server_fingerprint)
            .map_err(|_| "server fingerprint contains NUL".to_owned())?;
        let client = CString::new(client_fingerprint)
            .map_err(|_| "client fingerprint contains NUL".to_owned())?;
        match unsafe { (self.check)(self.handle, server.as_ptr(), client.as_ptr()) } {
            1 => Ok(true),
            0 => Ok(false),
            -1 => Err(format!("Auth check failed: {}", unsafe {
                diagnostic(self.last_error)
            })),
            status => Err(format!("Auth check returned invalid status {status}")),
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.uninitialize)(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    let value: Symbol<'_, T> = unsafe { library.get(name) }
        .map_err(|error| format!("Auth dynamic symbol load failed: {error}"))?;
    Ok(*value)
}

unsafe fn diagnostic(last_error: LastError) -> String {
    let value = unsafe { last_error() };
    if value.is_null() {
        return "no diagnostic available".to_owned();
    }
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

fn library_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("AUTOBRICKS_AUTH_LIBRARY") {
        let path = PathBuf::from(path);
        return path
            .is_file()
            .then_some(path)
            .ok_or_else(|| "AUTOBRICKS_AUTH_LIBRARY does not identify a library file".to_owned());
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("current executable path is unavailable: {error}"))?;
    if let Some(directory) = executable.parent() {
        for candidate in [
            directory.join(LIBRARY_NAME),
            directory.join("lib").join(LIBRARY_NAME),
        ] {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for directory in ["/usr/lib/autobricks", "/usr/local/lib/autobricks"] {
        let candidate = Path::new(directory).join(LIBRARY_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("Autobricks Auth dynamic library was not found".to_owned())
}
