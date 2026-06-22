//! Apple Developer Services: generate a development provisioning profile so a
//! decrypted app can be re-signed with its restricted entitlements granted.
//!
//! The protocol is reverse-engineered (`AltSign`/`SideStore`) and needs a paid
//! account + a registered device to run; it cannot be validated offline. The
//! pure request/response/CSR helpers are unit-tested; [`provision`] is the live
//! integration.

mod client;
mod csr;
mod parsing;
mod request;

pub use client::DeveloperClient;
pub use csr::{KeyAndCsr, generate_key_and_csr};
pub use parsing::{Certificate, Device, Team};

use crate::domain::entity::Account;

const MACHINE_NAME: &str = "ipakeep";

/// Inputs to the provisioning flow.
pub struct ProvisionRequest<'a> {
    /// The logged-in account.
    pub account: &'a Account,
    /// Team id to use, or `None` to pick the first development team.
    pub team_id: Option<&'a str>,
    /// Device UDID to register the profile for.
    pub device_udid: &'a str,
    /// Friendly device name.
    pub device_name: &'a str,
    /// App ID identifier for the team profile (a wildcard `*` is common).
    pub app_id_id: &'a str,
}

/// Artifacts produced by provisioning.
pub struct ProvisionResult {
    /// The team the profile belongs to.
    pub team_id: String,
    /// The `.mobileprovision` bytes.
    pub mobileprovision: Vec<u8>,
    /// The generated private key (PEM) for the signing certificate.
    pub key_pem: Vec<u8>,
    /// The issued certificate (DER).
    pub certificate_der: Vec<u8>,
    /// The certificate serial number.
    pub certificate_serial: String,
}

/// Run the full provisioning flow: pick a team, register the device, submit a
/// CSR, and download the team provisioning profile.
///
/// # Errors
///
/// Returns an error if auth, any Developer Services call, or CSR generation
/// fails.
pub async fn provision(req: &ProvisionRequest<'_>) -> Result<ProvisionResult, String> {
    let client = DeveloperClient::for_account(req.account).await?;

    let team_id = match req.team_id {
        Some(id) => id.to_string(),
        None => client
            .list_teams()
            .await?
            .into_iter()
            .next()
            .map(|team| team.id)
            .ok_or("account has no development teams")?,
    };

    client
        .register_device(&team_id, req.device_udid, req.device_name)
        .await?;

    let KeyAndCsr { key_pem, csr_pem } = generate_key_and_csr(req.device_name)?;
    let csr = String::from_utf8_lossy(&csr_pem).into_owned();
    let cert = client.submit_csr(&team_id, &csr, MACHINE_NAME).await?;
    let mobileprovision = client.download_profile(&team_id, req.app_id_id).await?;

    Ok(ProvisionResult {
        team_id,
        mobileprovision,
        key_pem,
        certificate_der: cert.der,
        certificate_serial: cert.serial,
    })
}
