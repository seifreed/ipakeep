//! RSA key + Certificate Signing Request generation via `openssl`.
//!
//! Apple's Developer Services issues a development certificate in exchange for a
//! CSR. We shell out to `openssl` (always present on macOS) rather than pull in
//! a heavy RSA/ASN.1 crate.

use crate::infrastructure::exec::{require_program, run_quiet, temp_dir};
use std::process::Command;

/// A freshly generated private key (PEM) and its CSR (PEM).
#[derive(Debug, Clone)]
pub struct KeyAndCsr {
    /// PKCS#8 private key, PEM-encoded.
    pub key_pem: Vec<u8>,
    /// Certificate signing request, PEM-encoded.
    pub csr_pem: Vec<u8>,
}

/// Generate a 2048-bit RSA key and a CSR with `common_name`.
///
/// # Errors
///
/// Returns an error if `openssl` is missing or generation fails.
pub fn generate_key_and_csr(common_name: &str) -> Result<KeyAndCsr, String> {
    require_program("openssl")?;
    let dir = temp_dir("csr")?;
    let key = dir.join("key.pem");
    let csr = dir.join("csr.pem");

    let mut command = Command::new("openssl");
    command
        .args(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&csr)
        .args(["-subj", &format!("/CN={common_name}/O=ipakeep/C=US")]);
    let result = run_quiet(command);

    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let out = result.and_then(|()| {
        Ok(KeyAndCsr {
            key_pem: read(&key)?,
            csr_pem: read(&csr)?,
        })
    });
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_key_and_csr() {
        let KeyAndCsr { key_pem, csr_pem } = generate_key_and_csr("ipakeep-test").unwrap();
        let key = String::from_utf8_lossy(&key_pem);
        let csr = String::from_utf8_lossy(&csr_pem);
        assert!(key.contains("PRIVATE KEY"), "{key}");
        assert!(csr.contains("CERTIFICATE REQUEST"), "{csr}");
    }
}
