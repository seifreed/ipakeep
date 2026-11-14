use crate::domain::entity::Account;
use crate::domain::error::CredentialError;
use std::time::Instant;

pub(super) fn serialize_account(account: &Account) -> Result<String, CredentialError> {
    serde_json::to_string_pretty(account)
        .map_err(|e| CredentialError::SaveFailed(format!("serialization failed: {e}")))
}

pub(super) fn deserialize_account(bytes: &[u8]) -> Result<Account, CredentialError> {
    serde_json::from_slice(bytes).map_err(|e| {
        CredentialError::InvalidCredentials(format!("failed to parse credentials: {e}"))
    })
}

pub(super) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
