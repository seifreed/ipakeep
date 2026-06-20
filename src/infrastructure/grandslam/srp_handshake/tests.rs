use super::*;

#[test]
fn generate_a_returns_256_bytes() {
    let a = generate_a();
    assert_eq!(a.len(), SRP_PRIVATE_EPHEMERAL_LEN);
    assert_ne!(a[0] & 0x80, 0);
}

#[test]
fn compute_a_pub_is_deterministic() {
    let a = vec![1u8; 32];
    let a_pub1 = compute_a_pub(&a);
    let a_pub2 = compute_a_pub(&a);
    assert_eq!(a_pub1, a_pub2);
    assert!(!a_pub1.is_empty());
}

#[test]
fn compute_client_proof_with_valid_params() {
    let a = generate_a();
    let a_pub = compute_a_pub(&a);
    let b_pub = compute_a_pub(&[2u8; 32]);
    let salt = b"testsalt";
    let derived_password = vec![3u8; 32];

    let result = compute_client_proof(
        &a,
        &a_pub,
        &b_pub,
        "test@example.com",
        salt,
        &derived_password,
    );
    assert!(result.is_ok());

    let (m1, session_key) = result.unwrap();
    assert_eq!(m1.len(), 32);
    assert_eq!(session_key.len(), 32);
}

#[test]
fn compute_apple_x_matches_no_username_in_x_vector() {
    let derived =
        hex::decode("38ea4b3529a352be95e9a6fd416a8912b4c7001fb8eb4be9a4acfd0e3d72be42").unwrap();
    let x = compute_apple_x(b"testsalt", &derived);

    assert_eq!(
        hex::encode(x.to_bytes_be()),
        "4946fc5064dc4e8253c76fde44cdb8e3a22c0c32bd8eb5b9f41dafb335c3d386"
    );
}

#[test]
fn compute_u_pads_values_to_group_width() {
    let a_pub = compute_a_pub(&[1u8; 32]);
    let b_pub = compute_a_pub(&[2u8; 32]);
    let width = G_2048.n.to_bytes_be().len();

    let u = compute_u_padded(&a_pub, &b_pub).unwrap();
    let mut expected_hasher = Sha256::new();
    expected_hasher.update(left_pad(&a_pub, width).unwrap());
    expected_hasher.update(left_pad(&b_pub, width).unwrap());
    let expected = expected_hasher.finalize();

    assert_eq!(u.to_bytes_be(), expected.as_slice());
}

#[test]
fn compute_client_proof_rejects_zero_b() {
    let a = generate_a();
    let a_pub = compute_a_pub(&a);
    let b_pub = vec![0u8];
    let salt = b"testsalt";
    let derived_password = vec![3u8; 32];

    let result = compute_client_proof(
        &a,
        &a_pub,
        &b_pub,
        "test@example.com",
        salt,
        &derived_password,
    );
    assert!(result.is_err());
}

#[test]
fn verify_server_proof_success() {
    let a_pub = vec![1u8; 32];
    let m1 = vec![2u8; 32];
    let session_key = vec![3u8; 32];

    let expected_m2 = compute_m2::<Sha256>(&a_pub, m1.as_slice().into(), &session_key);
    assert!(verify_server_proof(&a_pub, &m1, &session_key, expected_m2.as_slice()).is_ok());
}

#[test]
fn verify_server_proof_failure() {
    let a_pub = vec![1u8; 32];
    let m1 = vec![2u8; 32];
    let session_key = vec![3u8; 32];
    let bad_m2 = vec![0u8; 32];

    assert!(verify_server_proof(&a_pub, &m1, &session_key, &bad_m2).is_err());
}
