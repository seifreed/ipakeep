//! Sinf entity representing DRM encryption metadata.

/// DRM encryption metadata for an application binary.
///
/// Sinf data must be injected into the IPA's `SC_Info/` directory
/// for the app to be properly authorized on the device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Sinf {
    /// Identifier matching a specific binary within the app.
    pub id: i64,
    /// Raw DRM encryption metadata bytes.
    pub data: Vec<u8>,
}
