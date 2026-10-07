use std::{env, fs};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=VERSION");
    println!("cargo:rerun-if-env-changed=AUTOBRICKS_PKI_VERSION");
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os != "linux"
        && (target_os != "macos" || env::var_os("CARGO_FEATURE_SERVER").is_some())
    {
        return Err("The server requires Linux; client-only builds support Linux and macOS".into());
    }
    let version = fs::read_to_string("VERSION")?;
    let version = version.trim();
    let allocated = env::var("AUTOBRICKS_PKI_VERSION").map_err(
        |_| "Build through scripts/build/run.sh cargo build (or cargo test/check/clippy)",
    )?;
    if allocated != version {
        return Err("Build version must match VERSION".into());
    }
    println!("cargo:rustc-env=AUTOBRICKS_PKI_VERSION={version}");
    Ok(())
}
