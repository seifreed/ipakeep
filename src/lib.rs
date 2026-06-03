#![allow(unexpected_cfgs)]

//! ipakeep — Download IPA files from the Apple App Store.
//!
//! This library provides the core functionality for authenticating with
//! Apple, searching the App Store, purchasing apps, and downloading IPAs.
//!
//! # Architecture
//!
//! The crate follows Clean Architecture with four layers:
//!
//! - **Domain** (`domain`): Pure business entities, repository traits, and
//!   use cases. No external dependencies.
//! - **Infrastructure** (`infrastructure`): Concrete implementations of
//!   repository traits (HTTP client, App Store API, file keychain).
//! - **Presentation** (`presentation`): CLI interface adapters.
//!
//! # Example
//!
//! ```no_run
//! use ipakeep::domain::usecase::Search;
//! use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
//! use ipakeep::infrastructure::http::AppleHttpClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = AppleHttpClient::new()?;
//! let repo = AppleAppStoreRepository::new(client);
//! let search = Search::new(repo);
//! let results = search.execute("twitter", "us", 5).await?;
//! for app in &results {
//!     println!("{} ({}) - {}", app.name, app.bundle_id, app.version);
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;

pub mod domain;
pub mod infrastructure;
pub mod presentation;
