#![allow(unsafe_code)]

use libloading::Library;
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr,
    sync::Arc,
};

const COMM_ABI: u32 = 1;
const IPC_API: u32 = 2;
const SERVICE_API: u32 = 1;
const TRANSPORT_API: u32 = 2;

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub client_ip: String,
    pub certificate: Vec<u8>,
}

pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Deserialize)]
struct NativeHttpRequest {
    method: String,
    object: String,
    headers: std::collections::BTreeMap<String, String>,
    client_ip: String,
    body: Vec<u8>,
    #[serde(default)]
    cert: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct NativeHttpResponse {
    status: u16,
    content_type: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

pub struct StructuredRequest {
    pub metadata: Vec<u8>,
    pub payload: Vec<u8>,
    pub client_ip: Option<String>,
    pub certificate: Vec<u8>,
}

pub struct StructuredResponse {
    pub metadata: Vec<u8>,
    pub payload: Vec<u8>,
}

type IpcHandler = dyn Fn(&str) -> Result<String, String> + Send + Sync;
type HttpHandler = dyn Fn(HttpRequest) -> Result<HttpResponse, String> + Send + Sync;
type StructuredHandler =
    dyn Fn(StructuredRequest) -> Result<StructuredResponse, String> + Send + Sync;

struct Context {
    ipc: Arc<IpcHandler>,
    http: Arc<HttpHandler>,
    structured: Arc<StructuredHandler>,
}

#[repr(C)]
struct IpcRequest {
    struct_size: usize,
    connection_id: u64,
    payload: *const c_char,
    has_peer_credentials: bool,
    peer_uid: u32,
    peer_gid: u32,
}

#[repr(C)]
struct IpcApi {
    struct_size: usize,
    api_version: u32,
    request: Option<unsafe extern "C" fn(*const c_char, *mut c_void, *mut bool) -> *mut c_char>,
    response_free: Option<unsafe extern "C" fn(*mut c_char)>,
    request_v2:
        Option<unsafe extern "C" fn(*const IpcRequest, *mut c_void, *mut bool) -> *mut c_char>,
}

#[repr(C)]
struct ServiceApi {
    struct_size: usize,
    api_version: u32,
    request: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_char>,
    response_free: Option<unsafe extern "C" fn(*mut c_char)>,
    peer_verifier: Option<unsafe extern "C" fn(*const u8, usize, *mut c_void) -> bool>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Bytes {
    data: *const u8,
    length: usize,
}

#[repr(C)]
struct TransportRequest {
    struct_size: usize,
    sid: *const c_char,
    client_ip: *const c_char,
    transport: *const c_char,
    cert: Bytes,
    metadata: Bytes,
    payload: Bytes,
}

#[repr(C)]
struct TransportResponse {
    struct_size: usize,
    metadata: Bytes,
    payload: Bytes,
    close: bool,
    idle_timeout_ms: u64,
    absolute_deadline_unix_ms: u64,
}

#[repr(C)]
struct TransportApi {
    struct_size: usize,
    api_version: u32,
    request: Option<
        unsafe extern "C" fn(*const TransportRequest, *mut TransportResponse, *mut c_void) -> i32,
    >,
    response_free: Option<unsafe extern "C" fn(*mut TransportResponse, *mut c_void)>,
    session_closed: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
}

#[repr(C)]
struct ApplicationApi {
    struct_size: usize,
    api_version: u32,
    ipc: *const IpcApi,
    http: *const c_void,
    structured: *const TransportApi,
}

type AbiVersion = unsafe extern "C" fn() -> u32;
type LastError = unsafe extern "C" fn() -> *const c_char;
type Initialize = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type Bind = unsafe extern "C" fn(*const ApplicationApi, *mut c_void) -> *mut c_void;
type Start = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type Stop = unsafe extern "C" fn(*mut c_void) -> i32;
type Unbind = unsafe extern "C" fn(*mut c_void);
type Uninitialize = unsafe extern "C" fn(*mut c_void);

pub struct Runtime {
    runtime: *mut c_void,
    application: *mut c_void,
    definition: *mut c_void,
    context: *mut Context,
    stop: Stop,
    unbind: Unbind,
    uninitialize: Uninitialize,
    _library: Library,
    _ipc_api: Box<IpcApi>,
    _service_api: Box<ServiceApi>,
    _transport_api: Box<TransportApi>,
}

unsafe impl Send for Runtime {}

impl Runtime {
    pub fn start(
        library: &Path,
        config: &str,
        ipc: impl Fn(&str) -> Result<String, String> + Send + Sync + 'static,
        http: impl Fn(HttpRequest) -> Result<HttpResponse, String> + Send + Sync + 'static,
        structured: impl Fn(StructuredRequest) -> Result<StructuredResponse, String>
        + Send
        + Sync
        + 'static,
    ) -> Result<Self, String> {
        let library = unsafe { Library::new(library) }.map_err(|e| e.to_string())?;
        let abi: AbiVersion = *unsafe { library.get::<AbiVersion>(b"ab_comm_abi_version\0") }
            .map_err(|e| e.to_string())?;
        if unsafe { abi() } != COMM_ABI {
            return Err("unsupported Autobricks COMM ABI".into());
        }
        let last_error: LastError = *unsafe { library.get::<LastError>(b"ab_comm_last_error\0") }
            .map_err(|e| e.to_string())?;
        let initialize: Initialize = *unsafe { library.get::<Initialize>(b"ab_comm_initialize\0") }
            .map_err(|e| e.to_string())?;
        let bind: Bind = *unsafe { library.get::<Bind>(b"ab_comm_bind_application\0") }
            .map_err(|e| e.to_string())?;
        let start: Start =
            *unsafe { library.get::<Start>(b"ab_comm_start\0") }.map_err(|e| e.to_string())?;
        let stop: Stop =
            *unsafe { library.get::<Stop>(b"ab_comm_stop\0") }.map_err(|e| e.to_string())?;
        let unbind: Unbind = *unsafe { library.get::<Unbind>(b"ab_comm_unbind_application\0") }
            .map_err(|e| e.to_string())?;
        let uninitialize: Uninitialize =
            *unsafe { library.get::<Uninitialize>(b"ab_comm_uninitialize\0") }
                .map_err(|e| e.to_string())?;
        let config = CString::new(config).map_err(|_| "COMM config contains NUL")?;
        let definition = unsafe { initialize(config.as_ptr()) };
        if definition.is_null() {
            return Err(format!("COMM initialization failed: {}", unsafe {
                diagnostic(last_error)
            }));
        }
        let context = Box::into_raw(Box::new(Context {
            ipc: Arc::new(ipc),
            http: Arc::new(http),
            structured: Arc::new(structured),
        }));
        let ipc_api = Box::new(IpcApi {
            struct_size: size_of::<IpcApi>(),
            api_version: IPC_API,
            request: None,
            response_free: Some(ipc_response_free),
            request_v2: Some(ipc_request),
        });
        let service_api = Box::new(ServiceApi {
            struct_size: size_of::<ServiceApi>(),
            api_version: SERVICE_API,
            request: Some(http_request),
            response_free: Some(ipc_response_free),
            peer_verifier: None,
        });
        let transport_api = Box::new(TransportApi {
            struct_size: size_of::<TransportApi>(),
            api_version: TRANSPORT_API,
            request: Some(transport_request),
            response_free: Some(transport_response_free),
            session_closed: Some(transport_session_closed),
        });
        let api = ApplicationApi {
            struct_size: size_of::<ApplicationApi>(),
            api_version: 1,
            ipc: &*ipc_api,
            http: (&*service_api as *const ServiceApi).cast(),
            structured: &*transport_api,
        };
        let application = unsafe { bind(&api, context.cast()) };
        if application.is_null() {
            unsafe {
                drop(Box::from_raw(context));
                uninitialize(definition);
            }
            return Err("COMM application binding failed".into());
        }
        let runtime = unsafe { start(definition, application) };
        if runtime.is_null() {
            unsafe {
                unbind(application);
                drop(Box::from_raw(context));
                uninitialize(definition);
            }
            return Err(format!("COMM runtime start failed: {}", unsafe {
                diagnostic(last_error)
            }));
        }
        Ok(Self {
            runtime,
            application,
            definition,
            context,
            stop,
            unbind,
            uninitialize,
            _library: library,
            _ipc_api: ipc_api,
            _service_api: service_api,
            _transport_api: transport_api,
        })
    }
}

unsafe fn diagnostic(function: LastError) -> String {
    let value = unsafe { function() };
    if value.is_null() {
        "no diagnostic provided".into()
    } else {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {
            (self.stop)(self.runtime);
            (self.unbind)(self.application);
            (self.uninitialize)(self.definition);
            drop(Box::from_raw(self.context));
        }
    }
}

unsafe extern "C" fn ipc_request(
    request: *const IpcRequest,
    context: *mut c_void,
    _stop: *mut bool,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if request.is_null() || context.is_null() || (*request).payload.is_null() {
            return None;
        }
        let input = CStr::from_ptr((*request).payload).to_str().ok()?;
        let context = &*context.cast::<Context>();
        CString::new((context.ipc)(input).ok()?)
            .ok()
            .map(CString::into_raw)
    }));
    result.ok().flatten().unwrap_or(ptr::null_mut())
}

unsafe extern "C" fn ipc_response_free(response: *mut c_char) {
    if !response.is_null() {
        unsafe { drop(CString::from_raw(response)) };
    }
}

unsafe extern "C" fn http_request(request: *const c_char, context: *mut c_void) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if request.is_null() || context.is_null() {
            return None;
        }
        let request: NativeHttpRequest =
            serde_json::from_slice(CStr::from_ptr(request).to_bytes()).ok()?;
        let response = ((&*context.cast::<Context>()).http)(HttpRequest {
            method: request.method,
            path: request.object,
            headers: request.headers,
            body: request.body,
            client_ip: request.client_ip,
            certificate: request.cert.unwrap_or_default(),
        })
        .ok()?;
        let response = NativeHttpResponse {
            status: response.status,
            content_type: response.content_type,
            headers: response.headers,
            body: response.body,
        };
        CString::new(serde_json::to_vec(&response).ok()?)
            .ok()
            .map(CString::into_raw)
    }));
    result.ok().flatten().unwrap_or(ptr::null_mut())
}

unsafe fn copy_bytes(value: Bytes) -> Option<Vec<u8>> {
    if value.length == 0 {
        return Some(Vec::new());
    }
    if value.data.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(value.data, value.length) }.to_vec())
}

unsafe extern "C" fn transport_request(
    request: *const TransportRequest,
    response: *mut TransportResponse,
    context: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if request.is_null() || response.is_null() || context.is_null() {
            return None;
        }
        let client_ip = if (*request).client_ip.is_null() {
            None
        } else {
            CStr::from_ptr((*request).client_ip)
                .to_str()
                .ok()
                .map(str::to_owned)
        };
        let output = ((&*context.cast::<Context>()).structured)(StructuredRequest {
            metadata: copy_bytes((*request).metadata)?,
            payload: copy_bytes((*request).payload)?,
            client_ip,
            certificate: copy_bytes((*request).cert)?,
        })
        .ok()?;
        let metadata = Box::leak(output.metadata.into_boxed_slice());
        let payload = Box::leak(output.payload.into_boxed_slice());
        (*response).metadata = Bytes {
            data: metadata.as_ptr(),
            length: metadata.len(),
        };
        (*response).payload = Bytes {
            data: payload.as_ptr(),
            length: payload.len(),
        };
        (*response).close = true;
        (*response).idle_timeout_ms = 0;
        (*response).absolute_deadline_unix_ms = 0;
        Some(())
    }));
    if result.ok().flatten().is_some() {
        0
    } else {
        -1
    }
}

unsafe extern "C" fn transport_response_free(
    response: *mut TransportResponse,
    _context: *mut c_void,
) {
    unsafe {
        if response.is_null() {
            return;
        }
        for bytes in [(*response).metadata, (*response).payload] {
            if !bytes.data.is_null() {
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    bytes.data.cast_mut(),
                    bytes.length,
                )));
            }
        }
        (*response).metadata = Bytes {
            data: ptr::null(),
            length: 0,
        };
        (*response).payload = Bytes {
            data: ptr::null(),
            length: 0,
        };
    }
}

unsafe extern "C" fn transport_session_closed(_sid: *const c_char, _context: *mut c_void) {}
