//! Stub for platforms that do not support AOSKit.

use std::collections::HashMap;

/// Always returns `None` so the caller falls back to simulated Anisette data.
pub fn retrieve_otp_headers(_dsid: &str) -> Option<HashMap<String, String>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieve_otp_headers_returns_none() {
        assert!(retrieve_otp_headers("-2").is_none());
    }
}
