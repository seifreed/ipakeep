//! TLS backend setup: reqwest runs on rustls with the `ring` crypto provider.

use std::sync::Once;

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

/// Start building a `reqwest` client on the process-wide rustls `ring` provider.
///
/// reqwest is built with `rustls-no-provider`, so every client must be created
/// through this function: it installs the provider once before the TLS
/// configuration is built. Server certificates are checked by the platform
/// verifier (the operating system's trust store plus any added roots).
pub fn client_builder() -> reqwest::ClientBuilder {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        // An `Err` means a provider is already installed; reqwest uses that one.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    reqwest::Client::builder()
}

#[cfg(test)]
mod tests {
    use super::client_builder;
    use crate::infrastructure::apple_sap::storeauth::apple_auth_client;

    const APPLE_ENDPOINTS: [&str; 7] = [
        "https://init.itunes.apple.com/bag.xml?ix=6",
        "https://gsa.apple.com/",
        "https://apps.apple.com/",
        "https://itunes.apple.com/",
        "https://developerservices2.apple.com/",
        "https://updates.cdn-apple.com/",
        "https://wkms-public.apple.com/",
    ];

    #[test]
    fn builds_client_with_ring_provider() {
        client_builder().build().expect("rustls client");
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[tokio::test]
    #[ignore = "network: TLS handshakes with Apple endpoints"]
    async fn handshakes_with_apple_endpoints() {
        let general = client_builder().build().expect("general client");
        let pinned = apple_auth_client().expect("Apple-root client");
        for client in [&general, &pinned] {
            for url in APPLE_ENDPOINTS {
                let response = client.get(url).send().await;
                assert!(response.is_ok(), "{url}: {response:?}");
            }
        }
    }
}
