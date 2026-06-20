//! SRP-6a handshake math for Apple `GrandSlam`.
//!
//! Apple preprocesses the password with PBKDF2, then uses RFC 5054 SRP with
//! the username omitted from `x`: `x = H(salt || H(":" || derived_password))`.
//! This module wires the `srp` crate's low-level primitives with those
//! GrandSlam-specific steps.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::utils::{compute_k, compute_m2};

const SRP_PRIVATE_EPHEMERAL_LEN: usize = 256;
const SRP_GENERATOR: u8 = 2;

/// Generate a random 256-byte private ephemeral `a`.
///
/// # Panics
///
/// Panics if the OS random source fails.
pub fn generate_a() -> Vec<u8> {
    let mut a = vec![0u8; SRP_PRIVATE_EPHEMERAL_LEN];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut a);
    a[0] |= 0x80;
    a
}

/// Compute the client public ephemeral `A = g^a mod N`.
///
/// Uses the 2048-bit SRP group (RFC 5054 Group 14) that Apple expects.
pub fn compute_a_pub(a: &[u8]) -> Vec<u8> {
    let client = SrpClient::<Sha256>::new(&G_2048);
    let a_big = BigUint::from_bytes_be(a);
    client.compute_a_pub(&a_big).to_bytes_be()
}

/// Compute the client proof `M1` and the session key `K`.
///
/// Apple uses the RFC 5054 proof formula with SHA-256:
///
/// ```text
/// M1 = H( H(N) XOR H(g_padded) || H(identity) || salt || A || B || K )
/// ```
///
/// where `K = H(S)` and `x = H(salt || H(":" || derived_password))`.
///
/// # Arguments
///
/// * `a` - the private ephemeral bytes.
/// * `a_pub` - the client public ephemeral `A`.
/// * `b_pub` - the server public ephemeral `B`.
/// * `identity` - the user's Apple ID email.
/// * `salt` - the server-provided salt bytes.
/// * `derived_password` - the PBKDF2-derived password.
///
/// # Returns
///
/// A tuple `(M1, K)` where `M1` is the 32-byte client proof and `K = H(S)` is
/// used for M2 verification and `decrypt_spd`.
///
/// # Errors
///
/// Returns an error if `b_pub` is invalid or an SRP value is wider than the
/// configured group modulus.
// justification: the single-letter bindings (a, u, k, s) are the canonical SRP-6a /
// RFC 5054 variable names. Renaming them would obscure the mapping to the published
// protocol that this function implements verbatim.
#[allow(clippy::many_single_char_names)]
pub fn compute_client_proof(
    a: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    identity: &str,
    salt: &[u8],
    derived_password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let client = SrpClient::<Sha256>::new(&G_2048);

    let a_big = BigUint::from_bytes_be(a);
    let b_big = BigUint::from_bytes_be(b_pub);
    let x_big = compute_apple_x(salt, derived_password);

    if &b_big % &G_2048.n == BigUint::default() {
        return Err("invalid server public ephemeral (B % N == 0)".into());
    }

    let u = compute_u_padded(a_pub, b_pub)?;
    let k = compute_k::<Sha256>(&G_2048);

    let s = client.compute_premaster_secret(&b_big, &k, &x_big, &a_big, &u);
    let session_key = Sha256::digest(s.to_bytes_be()).to_vec();
    let m1 = compute_apple_m1(identity, salt, a_pub, b_pub, &session_key);

    Ok((m1, session_key))
}

/// Verify the server's proof `M2`.
///
/// Apple expects:
///
/// ```text
/// M2 = H(A || M1 || K)
/// ```
///
/// where `K = H(S)` is the 32-byte session key.
///
/// # Arguments
///
/// * `a_pub` - the client public ephemeral `A`.
/// * `m1` - the client proof `M1`.
/// * `session_key` - the session key `K = H(S)`.
/// * `m2` - the server proof `M2` received from Apple.
///
/// # Errors
///
/// Returns an error if the server proof does not match.
pub fn verify_server_proof(
    a_pub: &[u8],
    m1: &[u8],
    session_key: &[u8],
    m2: &[u8],
) -> Result<(), String> {
    let expected = compute_m2::<Sha256>(a_pub, m1.into(), session_key);
    if expected.as_slice() == m2 {
        Ok(())
    } else {
        Err("server proof verification failed".into())
    }
}

fn compute_apple_x(salt: &[u8], derived_password: &[u8]) -> BigUint {
    let mut inner = Sha256::new();
    inner.update(b":");
    inner.update(derived_password);
    let identity_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(salt);
    outer.update(identity_hash);
    BigUint::from_bytes_be(&outer.finalize())
}

fn compute_u_padded(a_pub: &[u8], b_pub: &[u8]) -> Result<BigUint, String> {
    let width = G_2048.n.to_bytes_be().len();
    let a = left_pad(a_pub, width)?;
    let b = left_pad(b_pub, width)?;

    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    Ok(BigUint::from_bytes_be(&hasher.finalize()))
}

fn compute_apple_m1(
    identity: &str,
    salt: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    session_key: &[u8],
) -> Vec<u8> {
    let n_bytes = G_2048.n.to_bytes_be();
    let mut g_padded = vec![0u8; n_bytes.len()];
    g_padded[n_bytes.len() - 1] = SRP_GENERATOR;

    let h_n = Sha256::digest(&n_bytes);
    let h_g = Sha256::digest(&g_padded);
    let xor_h: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(nb, gb)| nb ^ gb).collect();
    let h_identity = Sha256::digest(identity.as_bytes());

    let mut m1_hasher = Sha256::new();
    m1_hasher.update(&xor_h);
    m1_hasher.update(h_identity);
    m1_hasher.update(salt);
    m1_hasher.update(a_pub);
    m1_hasher.update(b_pub);
    m1_hasher.update(session_key);
    m1_hasher.finalize().to_vec()
}

fn left_pad(value: &[u8], width: usize) -> Result<Vec<u8>, String> {
    if value.len() > width {
        return Err("SRP value is wider than the group modulus".into());
    }

    let mut padded = vec![0u8; width];
    padded[width - value.len()..].copy_from_slice(value);
    Ok(padded)
}

#[cfg(test)]
mod tests;
