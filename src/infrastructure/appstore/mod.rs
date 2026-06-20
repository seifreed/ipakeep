//! App Store infrastructure — Apple private API implementations.

pub mod authentication;
pub mod bag;
pub mod config;
pub mod store_api;
pub mod storefront;

pub use config::AppleApiConfig;
pub use store_api::AppleAppStoreRepository;
pub use storefront::{locale_country, storefront_for_country};
