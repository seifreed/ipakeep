//! `GrandSlam` authentication module — Apple SRP-based auth protocol.
//!
//! This module implements the Apple `GrandSlam` authentication flow used by
//! Xcode and other Apple tools, supporting trusted-device 2FA notifications.

mod anisette;
mod client;
mod srp;
mod srp_handshake;

#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
mod aoskit;

#[cfg(not(target_os = "macos"))]
mod anisette_docker;

#[cfg(ipakeep_modern_adi)]
mod modern_adi;

pub use anisette::{AnisetteData, resolve_anisette};
pub use client::{GrandSlamClient, SrpCompleteResult, SrpInitResponse};
#[cfg(ipakeep_modern_adi)]
pub use modern_adi::{store_login, store_request};
