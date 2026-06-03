//! `GrandSlam` authentication module — Apple SRP-based auth protocol.
//!
//! This module implements the Apple `GrandSlam` authentication flow used by
//! Xcode and other Apple tools, supporting trusted-device 2FA notifications.

pub mod anisette;
pub mod client;
pub mod srp;
pub mod srp_handshake;

#[cfg(target_os = "macos")]
pub mod aoskit;

#[cfg(not(target_os = "macos"))]
pub mod aoskit_fallback;

pub use anisette::{AnisetteData, generate_anisette};
pub use client::GrandSlamClient;
pub use srp::{SrpCredentials, decrypt_spd, derive_srp_password};
