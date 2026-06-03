//! Domain entities — pure business objects with no external dependencies.

pub mod account;
pub mod app;
pub mod download_item;
pub mod sinf;

pub use account::Account;
pub use app::{App, AppVersion};
pub use download_item::{DownloadItem, DownloadMetadata};
pub use sinf::Sinf;
