//! Plist XML codec for Apple's private API communication.
//!
//! Apple's App Store APIs use binary plist (bplist) and XML plist
//! formats for request/response bodies. This module provides
//! encoding and decoding utilities.

use base64::Engine;
use plist::Value;
use serde_json::Value as JsonValue;
use std::io::Cursor;

/// Encode a JSON value into plist XML bytes.
///
/// # Errors
///
/// Returns `plist::Error` if the plist XML serialization fails.
pub fn encode_plist(value: &JsonValue) -> Result<Vec<u8>, plist::Error> {
    let plist_value = json_to_plist(value);
    let mut buf = Vec::new();
    plist_value.to_writer_xml(&mut buf)?;
    Ok(buf)
}

/// Decode plist bytes (XML or binary) into a JSON value.
///
/// # Errors
///
/// Returns a string describing the parse error if the plist is malformed.
pub fn decode_plist(bytes: &[u8]) -> Result<JsonValue, String> {
    let cursor = Cursor::new(bytes);
    let plist_value =
        Value::from_reader(cursor).map_err(|e| format!("failed to parse plist: {e}"))?;

    Ok(plist_to_json(&plist_value))
}

/// Convert a plist Value to a JSON Value.
fn plist_to_json(value: &plist::Value) -> JsonValue {
    match value {
        plist::Value::String(s) => JsonValue::String(s.clone()),
        plist::Value::Boolean(b) => JsonValue::Bool(*b),
        plist::Value::Integer(i) => {
            if let Some(signed) = i.as_signed() {
                JsonValue::Number(serde_json::Number::from(signed))
            } else if let Some(unsigned) = i.as_unsigned() {
                // JSON can't represent u64 > i64::MAX, fall back to string
                if unsigned > i64::MAX as u64 {
                    JsonValue::String(unsigned.to_string())
                } else {
                    JsonValue::Number(serde_json::Number::from(unsigned.cast_signed()))
                }
            } else {
                JsonValue::Number(serde_json::Number::from(0))
            }
        }
        plist::Value::Real(f) => {
            serde_json::Number::from_f64(*f).map_or(JsonValue::Null, JsonValue::Number)
        }
        plist::Value::Data(data) => JsonValue::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        )),
        plist::Value::Date(d) => JsonValue::String(format!("{d:?}")),
        plist::Value::Array(arr) => JsonValue::Array(arr.iter().map(plist_to_json).collect()),
        plist::Value::Dictionary(dict) => {
            let map = dict
                .iter()
                .map(|(k, v)| (k.clone(), plist_to_json(v)))
                .collect();
            JsonValue::Object(map)
        }
        _ => JsonValue::Null,
    }
}

/// Convert a JSON Value to a plist Value.
fn json_to_plist(value: &JsonValue) -> plist::Value {
    match value {
        JsonValue::Null => plist::Value::String(String::new()),
        JsonValue::Bool(b) => plist::Value::Boolean(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                plist::Value::Integer(plist::Integer::from(i))
            } else if let Some(f) = n.as_f64() {
                plist::Value::Real(f)
            } else {
                plist::Value::String(n.to_string())
            }
        }
        JsonValue::String(s) => plist::Value::String(s.clone()),
        JsonValue::Array(arr) => plist::Value::Array(arr.iter().map(json_to_plist).collect()),
        JsonValue::Object(map) if map.len() == 1 && map.contains_key("__binary") => {
            if let Some(JsonValue::String(s)) = map.get("__binary")
                && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s)
            {
                return plist::Value::Data(bytes);
            }
            plist::Value::String(String::new())
        }
        JsonValue::Object(map) => {
            let dict = map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_plist(v)))
                .collect();
            plist::Value::Dictionary(dict)
        }
    }
}

/// Build a plist dictionary from key-value pairs for Apple API requests.
pub fn build_plist_dict(pairs: &[(&str, &str)]) -> JsonValue {
    let map: serde_json::Map<String, JsonValue> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), JsonValue::String((*v).to_string())))
        .collect();
    JsonValue::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_decode_roundtrip_simple_string() {
        let value = json!({"key": "value"});
        let encoded = encode_plist(&value).expect("encoding failed");
        let decoded = decode_plist(&encoded).expect("decoding failed");
        assert_eq!(decoded["key"], "value");
    }

    #[test]
    fn encode_decode_roundtrip_nested() {
        let value = json!({
            "level1": {
                "level2": "deep_value",
                "number": 42,
            }
        });
        let encoded = encode_plist(&value).expect("encoding failed");
        let decoded = decode_plist(&encoded).expect("decoding failed");
        assert_eq!(decoded["level1"]["level2"], "deep_value");
    }

    #[test]
    fn encode_decode_roundtrip_boolean() {
        let value = json!({"flag": true});
        let encoded = encode_plist(&value).expect("encoding failed");
        let decoded = decode_plist(&encoded).expect("decoding failed");
        assert_eq!(decoded["flag"], true);
    }

    #[test]
    fn encode_decode_roundtrip_array() {
        let value = json!({"items": ["a", "b", "c"]});
        let encoded = encode_plist(&value).expect("encoding failed");
        let decoded = decode_plist(&encoded).expect("decoding failed");
        assert_eq!(decoded["items"][0], "a");
        assert_eq!(decoded["items"][2], "c");
    }

    #[test]
    fn build_plist_dict_creates_string_dict() {
        let dict = build_plist_dict(&[("key1", "val1"), ("key2", "val2")]);
        assert_eq!(dict["key1"], "val1");
        assert_eq!(dict["key2"], "val2");
    }

    #[test]
    fn encode_decode_binary_marker() {
        let value = json!({"data": {"__binary": "aGVsbG8="}});
        let encoded = encode_plist(&value).expect("encoding failed");
        let decoded = decode_plist(&encoded).expect("decoding failed");
        assert_eq!(decoded["data"], "aGVsbG8=");
    }
}
