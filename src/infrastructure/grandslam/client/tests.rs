use super::response::extract_base64;
use super::response::parse_trusted_phone_numbers;
use super::response::two_factor_status_error;
use super::srp_response::two_factor_required_result;
use super::*;
use crate::infrastructure::http::plist_codec::encode_plist;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn extract_base64_success() {
    let encoded = BASE64.encode(b"hello");
    let value = serde_json::json!({ "data": encoded });
    assert_eq!(extract_base64(&value, "data").unwrap(), b"hello");
}

#[test]
fn extract_base64_missing_key() {
    let value = serde_json::json!({});
    assert!(extract_base64(&value, "data").is_err());
}

#[test]
fn parse_trusted_phone_numbers_reads_documented_hsa2_format() {
    // Fixture mirrors Apple's GET https://gsa.apple.com/auth HSA2 response.
    let value = serde_json::json!({
        "trustedPhoneNumbers": [
            {
                "id": 1,
                "numberWithDialCode": "+1 (•••) •••-••12",
                "pushMode": "sms",
                "obfuscatedNumber": "•••-•••-••12",
                "lastTwoDigits": "12"
            },
            {
                "id": 2,
                "numberWithDialCode": "+44 •••• ••••89",
                "pushMode": "sms",
                "obfuscatedNumber": "•••••89",
                "lastTwoDigits": "89"
            }
        ],
        "trustedDeviceCount": 0,
        "authenticationType": "hsa2"
    });

    let phones = parse_trusted_phone_numbers(&value);
    assert_eq!(phones.len(), 2);
    assert_eq!(phones[0].id, 1);
    assert_eq!(phones[0].number, "+1 (•••) •••-••12");
    assert_eq!(phones[1].id, 2);
    assert_eq!(phones[1].number, "+44 •••• ••••89");
}

#[test]
fn parse_trusted_phone_numbers_falls_back_when_dial_code_absent() {
    let value = serde_json::json!({
        "trustedPhoneNumbers": [
            { "id": 7, "obfuscatedNumber": "•••••42" }
        ]
    });

    let phones = parse_trusted_phone_numbers(&value);
    assert_eq!(phones.len(), 1);
    assert_eq!(phones[0].id, 7);
    assert_eq!(phones[0].number, "•••••42");
}

#[test]
fn parse_trusted_phone_numbers_skips_entries_without_id_and_handles_missing_array() {
    let with_bad_entry = serde_json::json!({
        "trustedPhoneNumbers": [ { "numberWithDialCode": "+1 555" } ]
    });
    assert!(parse_trusted_phone_numbers(&with_bad_entry).is_empty());

    let missing_array = serde_json::json!({ "trustedDeviceCount": 1 });
    assert!(parse_trusted_phone_numbers(&missing_array).is_empty());
}

fn encrypt_spd_fixture(session_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use aes::Aes256;
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let derive = |label: &[u8]| {
        let mut mac = Hmac::<Sha256>::new_from_slice(session_key).unwrap();
        mac.update(label);
        mac.finalize().into_bytes().to_vec()
    };
    let key = derive(b"extra data key:");
    let iv = derive(b"extra data iv:");

    let encryptor = Encryptor::<Aes256>::new_from_slices(&key, &iv[..16]).unwrap();
    let mut buffer = plaintext.to_vec();
    let len = buffer.len();
    buffer.resize(len + 16, 0);
    encryptor
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer, len)
        .unwrap()
        .to_vec()
}

#[test]
fn two_factor_required_result_extracts_identity_from_encrypted_spd() {
    let session_key = b"0123456789abcdef0123456789abcdef";
    let spd = encode_plist(&serde_json::json!({
        "adsid": "adsid-xyz",
        "GsIdmsToken": "idms-xyz",
    }))
    .expect("encode spd plist");
    let inner = serde_json::json!({
        "spd": BASE64.encode(encrypt_spd_fixture(session_key, &spd)),
    });

    let result = two_factor_required_result(&inner, session_key)
        .expect("2FA result should decode identity fields from spd");

    match result {
        SrpCompleteResult::TwoFactorRequired { dsid, idms_token } => {
            assert_eq!((dsid, idms_token), ("adsid-xyz".into(), "idms-xyz".into()));
        }
        SrpCompleteResult::Success(_) => panic!("expected TwoFactorRequired, got Success"),
    }
}

#[test]
fn two_factor_required_result_errors_when_identity_fields_absent() {
    let session_key = b"0123456789abcdef0123456789abcdef";
    let spd = encode_plist(&serde_json::json!({ "foo": "bar" })).expect("encode spd plist");
    let inner = serde_json::json!({
        "spd": BASE64.encode(encrypt_spd_fixture(session_key, &spd)),
    });

    assert!(matches!(
        two_factor_required_result(&inner, session_key),
        Err(AppStoreError::AuthenticationFailed(_))
    ));
}

#[test]
fn two_factor_status_error_includes_http_status_and_body() {
    let error = two_factor_status_error(
        "trusted device request",
        reqwest::StatusCode::UNAUTHORIZED,
        b"not authorized",
    );

    let AppStoreError::AuthenticationFailed(message) = error else {
        panic!("expected authentication failure");
    };
    assert!(message.contains("HTTP 401"));
    assert!(message.contains("not authorized"));
}

#[tokio::test]
async fn post_plist_returns_status_error_before_decoding_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/grandslam"))
        .respond_with(ResponseTemplate::new(500).set_body_raw(
            encode_plist(&serde_json::json!({ "Response": { "ok": true } })).expect("plist"),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let result = http::post_plist(
        &client,
        &format!("{}/grandslam", server.uri()),
        &serde_json::json!({}),
        None,
    )
    .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 500"));
    assert!(message.contains("Response"));
}
