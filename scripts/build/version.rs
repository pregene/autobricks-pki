use std::{env, fs};
fn main() {
    println!("cargo:rerun-if-changed=VERSION");
    println!("cargo:rerun-if-env-changed=AUTOBRICKS_PKI_VERSION");
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "Linux only"
    );
    let version = fs::read_to_string("VERSION").expect("read VERSION");
    let version = version.trim();
    let allocated = env::var("AUTOBRICKS_PKI_VERSION")
        .expect("Build through scripts/build/run.sh cargo build (or cargo test/check/clippy)");
    assert_eq!(allocated, version, "Build version must match VERSION");
    println!("cargo:rustc-env=AUTOBRICKS_PKI_VERSION={version}");
}
