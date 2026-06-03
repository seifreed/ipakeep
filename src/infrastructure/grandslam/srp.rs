//! SRP-6a helpers for Apple `GrandSlam` authentication.
//!
//! Apple uses a variant of SRP-6a with SHA-256 and PBKDF2-HMAC-SHA256
//! password derivation. This module handles the cryptographic steps
//! needed to authenticate with Apple's `GrandSlam` servers.

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

const SRP_DERIVED_PASSWORD_LEN: usize = 32;
const AES_256_KEY_LEN: usize = 32;
const AES_BLOCK_LEN: usize = 16;

/// Credentials derived from the SRP exchange.
#[derive(Debug, Clone)]
pub struct SrpCredentials {
    /// Directory Services ID (Apple account numeric ID).
    pub dsid: String,

    /// IDMS token used for subsequent authenticated requests.
    pub idms_token: String,
}

/// Derive the SRP password from the user's cleartext password using
/// Apple's PBKDF2-HMAC-SHA256 scheme.
///
/// # Arguments
/// * `password` — the user's cleartext Apple ID password.
/// * `salt` — the server-provided salt bytes.
/// * `iterations` — the server-provided iteration count.
/// * `sp` — the server-provided protocol string (`"s2k"` or `"s2k_fo"`).
///
/// # Returns
/// The derived 32-byte password to use as the SRP secret.
pub fn derive_srp_password(password: &str, salt: &[u8], iterations: u32, sp: &str) -> Vec<u8> {
    let password_digest = Sha256::digest(password.as_bytes());
    let password_material = if sp == "s2k_fo" {
        hex::encode(password_digest).into_bytes()
    } else {
        password_digest.to_vec()
    };

    let mut derived = [0u8; SRP_DERIVED_PASSWORD_LEN];
    pbkdf2_hmac::<Sha256>(&password_material, salt, iterations, &mut derived);

    derived.to_vec()
}

/// Decrypt Apple's `spd` (server private data) field.
///
/// Apple encrypts `spd` with AES-CBC using a key derived from the
/// SRP shared secret via HMAC-SHA256.
///
/// # Arguments
/// * `session_key` — the SRP session key `K = SHA256(S)`.
/// * `spd` — the Base64-encoded encrypted payload from the server.
///
/// # Returns
/// The decrypted XML plist bytes.
///
/// # Errors
/// Returns an error if decryption or padding removal fails.
pub fn decrypt_spd(session_key: &[u8], spd: &[u8]) -> Result<Vec<u8>, String> {
    // Derive AES key: HMAC-SHA256(session_key, "extra data key:")
    let key = hmac_sha256(session_key, b"extra data key:");

    // Derive IV: first 16 bytes of HMAC-SHA256(session_key, "extra data iv:")
    let iv_full = hmac_sha256(session_key, b"extra data iv:");
    let iv = &iv_full[..AES_BLOCK_LEN];

    aes_cbc_decrypt(&key, iv, spd)
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key size is valid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Decrypt AES-256-CBC with the full 32-byte HMAC-derived key.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes::Aes256;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    if key.len() < AES_256_KEY_LEN {
        return Err("AES key too short (expected 32 bytes)".into());
    }

    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| format!("invalid AES key/IV: {e}"))?;

    let mut buffer = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| format!("AES decryption failed: {e}"))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_srp_password_s2k() {
        let password = "test_password";
        let salt = b"testsalt";
        let iterations = 10_000;
        let sp = "s2k";

        let derived = derive_srp_password(password, salt, iterations, sp);
        assert_eq!(
            hex::encode(derived),
            "38ea4b3529a352be95e9a6fd416a8912b4c7001fb8eb4be9a4acfd0e3d72be42"
        );
    }

    #[test]
    fn derive_srp_password_s2k_fo() {
        let password = "test_password";
        let salt = b"testsalt";
        let iterations = 10_000;
        let sp = "s2k_fo";

        let derived = derive_srp_password(password, salt, iterations, sp);
        assert_eq!(
            hex::encode(derived),
            "7d7d1026dec045a1a09c199547f143fe9edb4ea1293a5c015d5198f1206eb0bc"
        );
    }

    #[test]
    fn decrypt_spd_roundtrip() {
        let session_key = b"0123456789abcdef0123456789abcdef";
        let plaintext = br#"<?xml version="1.0"?><plist><dict><key>dsid</key><string>123</string></dict></plist>"#;
        let encrypted = encrypt_spd_fixture(session_key, plaintext);

        let decrypted = decrypt_spd(session_key, &encrypted).expect("decrypt_spd failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_spd_rejects_bad_input() {
        let result = decrypt_spd(b"short_key", b"short_spd");
        assert!(result.is_err());
    }

    fn encrypt_spd_fixture(session_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use aes::Aes256;
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use cbc::Encryptor;

        let key = hmac_sha256(session_key, b"extra data key:");
        let iv_full = hmac_sha256(session_key, b"extra data iv:");
        let encryptor =
            Encryptor::<Aes256>::new_from_slices(&key, &iv_full[..AES_BLOCK_LEN]).unwrap();

        let mut buffer = plaintext.to_vec();
        let plaintext_len = buffer.len();
        buffer.resize(plaintext_len + AES_BLOCK_LEN, 0);

        encryptor
            .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer, plaintext_len)
            .unwrap()
            .to_vec()
    }
}
