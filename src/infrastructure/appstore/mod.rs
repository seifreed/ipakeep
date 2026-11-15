//! App Store infrastructure — Apple private API implementations.

pub mod config;
pub mod store_api;
pub mod storefront;

pub use config::AppleApiConfig;
pub use store_api::store_machine::StoreMachine;
pub use store_api::{AppleAppStoreRepository, device_guid};
pub use storefront::{locale_country, storefront_for_country};
