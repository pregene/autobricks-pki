#![forbid(unsafe_code)]
#[cfg(not(target_os = "linux"))]
compile_error!("Autobricks PKI Server supports Linux only");
pub mod authority;
pub mod authorization;
pub mod certificate;
pub mod client;
pub mod help;
pub mod integration;
pub mod revocation;
pub mod server;
pub mod storage;
pub mod transport;
pub const PRODUCT: &str = "Autobricks PKI Server 1.0";
pub const VERSION: &str = env!("AUTOBRICKS_PKI_VERSION");
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
