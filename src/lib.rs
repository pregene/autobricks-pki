#![deny(unsafe_code)]
#[cfg(feature = "server")]
pub mod authority;
#[cfg(feature = "server")]
pub mod authorization;
#[cfg(feature = "server")]
pub mod certificate;
#[cfg(feature = "server")]
pub mod comm;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("Autobricks PKI development builds support Linux and macOS only");
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
pub const VERSION: &str = "1.1.135";
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
