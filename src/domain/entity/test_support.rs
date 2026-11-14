use super::{Account, App};

pub(crate) fn test_account() -> Account {
    Account {
        email: "test@example.com".into(),
        name: "Test User".into(),
        password_token: "token123".into(),
        directory_services_id: "dsid123".into(),
        store_front: "143441-2,26".into(),
        pod: "3".into(),
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: Vec::new(),
    }
}

pub(crate) fn app(id: i64) -> App {
    App {
        id,
        bundle_id: "com.example.app".into(),
        name: "Example".into(),
        version: "1.0".into(),
        price: 0.0,
    }
}
