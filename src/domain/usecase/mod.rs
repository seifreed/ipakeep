//! Use cases — application business rules orchestrating domain entities.
//!
//! Each use case depends only on repository traits (ports),
//! making them fully testable with mock implementations.

pub mod auth_info;
pub mod auth_login;
pub mod auth_revoke;
pub mod download;
pub mod list_versions;
pub mod purchase;
pub mod purchases;
/// Resolves a user-facing app reference to its App Store id.
pub mod resolve_app;
pub mod search;

pub use auth_info::AuthInfo;
pub use auth_login::{AuthLogin, GrandslamCredentials};
pub use auth_revoke::AuthRevoke;
pub use download::Download;
pub use list_versions::ListVersions;
pub use purchase::Purchase;
pub use purchases::Purchases;
pub use resolve_app::ResolveApp;
pub use search::Search;
