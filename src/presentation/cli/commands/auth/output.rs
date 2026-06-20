//! Auth command output formatting.

use crate::domain::entity::Account;
use crate::presentation::cli::output::{OutputFormat, format_account, format_output};
use serde::Serialize;

pub(super) fn format_login_account(account: &Account, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json => format_output(&AuthAccountOutput::from(account), format),
        OutputFormat::Text => format_account(account),
    }
}

#[derive(Debug, Serialize)]
struct AuthAccountOutput<'a> {
    email: &'a str,
    name: &'a str,
    store_front: &'a str,
    pod: &'a str,
    has_password_token: bool,
    has_cookies: bool,
    has_idms_token: bool,
    has_grandslam_state: bool,
}

impl<'a> From<&'a Account> for AuthAccountOutput<'a> {
    fn from(account: &'a Account) -> Self {
        Self {
            email: &account.email,
            name: &account.name,
            store_front: &account.store_front,
            pod: &account.pod,
            has_password_token: !account.password_token.is_empty(),
            has_cookies: !account.cookies.is_empty(),
            has_idms_token: account.idms_token.as_deref().is_some_and(|v| !v.is_empty()),
            has_grandslam_state: account
                .grandslam_session_key
                .as_deref()
                .is_some_and(|v| !v.is_empty())
                && account
                    .grandslam_continuation
                    .as_deref()
                    .is_some_and(|v| !v.is_empty()),
        }
    }
}
