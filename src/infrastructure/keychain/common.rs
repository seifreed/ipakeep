use crate::domain::entity::Account;
use crate::domain::error::CredentialError;

pub(super) fn serialize_account(account: &Account) -> Result<String, CredentialError> {
    serialize_record(account)
}

/// Serialize a stored credential record as pretty JSON, mapping failures to
/// [`CredentialError::SaveFailed`].
fn serialize_record<T: serde::Serialize>(record: &T) -> Result<String, CredentialError> {
    serde_json::to_string_pretty(record)
        .map_err(|e| CredentialError::SaveFailed(format!("serialization failed: {e}")))
}

pub(super) fn deserialize_account(bytes: &[u8]) -> Result<Account, CredentialError> {
    serde_json::from_slice(bytes).map_err(|e| {
        CredentialError::InvalidCredentials(format!("failed to parse credentials: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{deserialize_account, serialize_record};
    use crate::domain::error::CredentialError;
    use std::collections::BTreeMap;

    #[test]
    fn reports_serialization_failure_as_save_failed() {
        // JSON object keys must be strings, so a map keyed by byte vectors
        // cannot be serialized.
        let record = BTreeMap::from([(vec![1_u8], 1_u8)]);
        assert!(matches!(
            serialize_record(&record),
            Err(CredentialError::SaveFailed(message)) if message.starts_with("serialization failed:")
        ));
    }

    #[test]
    fn rejects_malformed_account_data() {
        assert!(matches!(
            deserialize_account(b"{"),
            Err(CredentialError::InvalidCredentials(message)) if message.starts_with("failed to parse credentials:")
        ));
    }
}
