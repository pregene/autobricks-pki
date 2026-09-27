use std::{env, fs};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=VERSION");
    println!("cargo:rerun-if-env-changed=AUTOBRICKS_PKI_VERSION");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Err("Linux only".into());
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
