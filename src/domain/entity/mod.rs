//! Domain entities — pure business objects with no external dependencies.

pub mod account;
pub mod app;
pub mod download_item;
pub mod sinf;
pub mod trusted_phone_number;

pub use account::Account;
pub use app::{App, AppVersion};
pub use download_item::{DownloadItem, DownloadMetadata, metadata_string};
pub use sinf::Sinf;
pub use trusted_phone_number::TrustedPhoneNumber;
