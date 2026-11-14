//! Keychain infrastructure — credential persistence implementations.

mod common;
#[cfg(test)]
mod test_support;

pub mod file_keychain;

#[cfg(target_os = "macos")]
pub mod macos_keychain;

pub use file_keychain::FileKeychain;

#[cfg(target_os = "macos")]
pub use macos_keychain::MacOSKeychain;
