//! Compile the narrow macOS bridge to Apple's private Store frameworks.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/infrastructure/appstore/native_auth.m");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/infrastructure/appstore/native_auth.m")
            .flag("-fblocks")
            .flag("-fobjc-arc")
            .compile("ipakeep_native_auth");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
