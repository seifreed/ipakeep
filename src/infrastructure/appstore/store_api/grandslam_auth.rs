use crate::domain::entity::{Account, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::{GrandSlamClient, SrpCompleteResult};
use crate::infrastructure::http::AppleHttpClient;

pub(super) async fn authenticate(
    client: &AppleHttpClient,
    email: &str,
    password: &str,
) -> Result<Account, AppStoreError> {
    let grand_slam = grand_slam_client(client);
    let init = grand_slam.srp_init(email).await?;
    match grand_slam.srp_complete(email, password, &init).await? {
        SrpCompleteResult::Success(account) => Ok(*account),
        SrpCompleteResult::TwoFactorRequired { dsid, idms_token } => {
            Err(AppStoreError::AuthCodeRequired { dsid, idms_token })
        }
    }
}

pub(super) async fn request_trusted_device_notification(
    client: &AppleHttpClient,
    dsid: &str,
    idms_token: &str,
) -> Result<(), AppStoreError> {
    grand_slam_client(client)
        .request_trusted_device_notification(dsid, idms_token)
        .await
}

pub(super) async fn validate_trusted_device_code(
    client: &AppleHttpClient,
    dsid: &str,
    idms_token: &str,
    code: &str,
) -> Result<(), AppStoreError> {
    grand_slam_client(client)
        .validate_trusted_device_code(dsid, idms_token, code)
        .await
}

pub(super) async fn list_trusted_phone_numbers(
    client: &AppleHttpClient,
    dsid: &str,
    idms_token: &str,
) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
    grand_slam_client(client)
        .list_trusted_phone_numbers(dsid, idms_token)
        .await
}

pub(super) async fn request_sms(
    client: &AppleHttpClient,
    dsid: &str,
    idms_token: &str,
    phone_id: i64,
) -> Result<(), AppStoreError> {
    grand_slam_client(client)
        .request_sms(dsid, idms_token, phone_id)
        .await
}

pub(super) async fn validate_sms_code(
    client: &AppleHttpClient,
    dsid: &str,
    idms_token: &str,
    phone_id: i64,
    code: &str,
) -> Result<(), AppStoreError> {
    grand_slam_client(client)
        .validate_sms_code(dsid, idms_token, phone_id, code)
        .await
}

fn grand_slam_client(client: &AppleHttpClient) -> GrandSlamClient {
    GrandSlamClient::new(client.client().clone())
}
