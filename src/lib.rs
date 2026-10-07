#![forbid(unsafe_code)]
#[cfg(all(feature = "server", not(target_os = "linux")))]
compile_error!("Autobricks PKI Server supports Linux only");
#[cfg(feature = "server")]
pub mod authority;
#[cfg(feature = "server")]
pub mod authorization;
#[cfg(feature = "server")]
pub mod certificate;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("The PKI client supports Linux and macOS only");
pub mod client;
pub mod help;
#[cfg(feature = "server")]
pub mod integration;
#[cfg(feature = "server")]
pub mod revocation;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod storage;
pub mod transport;
pub const PRODUCT: &str = "Autobricks PKI Server 1.0";
pub const VERSION: &str = env!("AUTOBRICKS_PKI_VERSION");
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
