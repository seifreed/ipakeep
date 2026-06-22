//! `GrandSlam` authentication module — Apple SRP-based auth protocol.
//!
//! This module implements the Apple `GrandSlam` authentication flow used by
//! Xcode and other Apple tools, supporting trusted-device 2FA notifications.

mod anisette;
mod client;
mod srp;
mod srp_handshake;

#[cfg(target_os = "macos")]
mod aoskit;

#[cfg(not(target_os = "macos"))]
mod aoskit_fallback;

mod anisette_docker;

pub use anisette::{AnisetteData, resolve_anisette};
pub use client::{GrandSlamClient, SrpCompleteResult, SrpInitResponse};
