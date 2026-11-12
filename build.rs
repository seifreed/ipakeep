//! Compile the narrow macOS bridge to Apple's private Store frameworks.

use std::{env, path::Path, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/infrastructure/appstore/native_auth.m");
    println!("cargo:rerun-if-changed=tools/modern-anisette");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/infrastructure/appstore/native_auth.m")
            .flag("-fblocks")
            .flag("-fobjc-arc")
            .compile("ipakeep_native_auth");
        println!("cargo:rustc-link-lib=framework=Foundation");

        build_modern_anisette_helper();
        println!("cargo:rustc-cfg=ipakeep_modern_adi");
    }
    println!("cargo:rustc-check-cfg=cfg(ipakeep_modern_adi)");
}

fn build_modern_anisette_helper() {
    let go_arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "amd64",
        _ => panic!("modern Apple Anisette requires an arm64 or x86_64 macOS target"),
    };
    let output_path = Path::new(&env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"))
        .join("ipakeep-modern-anisette");
    let output = Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&output_path)
        .arg(".")
        .current_dir("tools/modern-anisette")
        .env("GOOS", "darwin")
        .env("GOARCH", go_arch)
        .output()
        .expect("macOS builds require Go 1.26.5 or newer for modern Apple Anisette");
    assert!(
        output.status.success(),
        "failed to build modern Apple Anisette helper: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "cargo:rustc-env=IPAKEEP_MODERN_ANISETTE_HELPER={}",
        output_path.display()
    );
}
