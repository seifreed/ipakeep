//! HTTP infrastructure — Apple API client and plist codec.

pub mod client;
pub mod plist_codec;

pub use client::AppleHttpClient;
pub use plist_codec::{build_plist_dict, decode_plist, encode_plist};

/// Maximum number of characters from a response body included in error previews.
const RESPONSE_SNIPPET_LEN: usize = 240;

/// Render a short, control-char-sanitized preview of a response body, for use in
/// error messages without leaking raw binary or oversized payloads.
pub(crate) fn response_snippet(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(RESPONSE_SNIPPET_LEN)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_snippet_sanitizes_and_truncates() {
        let body = format!("a\nb{}", "x".repeat(RESPONSE_SNIPPET_LEN + 10));

        let snippet = response_snippet(body.as_bytes());

        assert!(!snippet.contains('\n'));
        assert_eq!(snippet.chars().count(), RESPONSE_SNIPPET_LEN);
        assert!(snippet.starts_with("a b"));
    }
}
