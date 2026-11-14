use super::*;

fn profile(identifier: &str) -> Profile {
    Profile {
        path: PathBuf::from("test.mobileprovision"),
        entitlements: Dictionary::from_iter([
            (
                "application-identifier".to_string(),
                Value::String(identifier.to_string()),
            ),
            (
                "com.apple.developer.team-identifier".to_string(),
                Value::String("NEWTEAM".to_string()),
            ),
            ("get-task-allow".to_string(), Value::Boolean(true)),
            (
                "keychain-access-groups".to_string(),
                Value::Array(vec![Value::String("PREFIX.*".to_string())]),
            ),
        ]),
    }
}

#[test]
fn wildcard_profile_produces_concrete_identity_and_rebinds_only_default_keychain() {
    let requested = Dictionary::from_iter([
        (
            "application-identifier".to_string(),
            Value::String("OLD.com.example.app".to_string()),
        ),
        (
            "keychain-access-groups".to_string(),
            Value::Array(vec![Value::String("OLD.com.example.app".to_string())]),
        ),
        ("beta-reports-active".to_string(), Value::Boolean(true)),
    ]);
    let result = signing_entitlements(&requested, &profile("PREFIX.*"), "com.example.app").unwrap();
    assert_eq!(
        result["application-identifier"].as_string(),
        Some("PREFIX.com.example.app")
    );
    assert_eq!(
        result["com.apple.developer.team-identifier"].as_string(),
        Some("NEWTEAM")
    );
    assert_eq!(
        result["keychain-access-groups"].as_array().unwrap()[0].as_string(),
        Some("PREFIX.com.example.app")
    );
    assert!(!result.contains_key("beta-reports-active"));
}

#[test]
fn retains_custom_capabilities_without_adding_unrequested_ones() {
    let mut profile = profile("PREFIX.com.example.app");
    profile.entitlements.insert(
        "aps-environment".to_string(),
        Value::String("development".to_string()),
    );
    profile.entitlements.insert(
        "com.apple.developer.healthkit".to_string(),
        Value::Boolean(true),
    );
    let requested = Dictionary::from_iter([(
        "aps-environment".to_string(),
        Value::String("development".to_string()),
    )]);
    let result = signing_entitlements(&requested, &profile, "com.example.app").unwrap();
    assert_eq!(result["aps-environment"], requested["aps-environment"]);
    assert!(!result.contains_key("com.apple.developer.healthkit"));
}

#[test]
fn rejects_missing_or_incompatible_capabilities_instead_of_dropping_them() {
    for key in [
        "com.apple.private.test",
        "com.apple.security.application-groups",
        "aps-environment",
    ] {
        let requested =
            Dictionary::from_iter([(key.to_string(), Value::String("custom".to_string()))]);
        let error =
            signing_entitlements(&requested, &profile("PREFIX.*"), "com.example.app").unwrap_err();
        assert!(error.contains(key));
    }
}

#[test]
fn does_not_remap_shared_keychain_groups_to_another_team() {
    let requested = Dictionary::from_iter([(
        "keychain-access-groups".to_string(),
        Value::Array(vec![Value::String("OLD.shared".to_string())]),
    )]);
    assert!(signing_entitlements(&requested, &profile("PREFIX.*"), "com.example.app").is_err());
}

#[test]
fn chooses_separate_profiles_for_app_and_extension() {
    let profiles = [
        profile("PREFIX.com.example.app"),
        profile("PREFIX.com.example.app.widget"),
    ];
    assert!(std::ptr::eq(
        select_profile(&profiles, "com.example.app").unwrap(),
        &raw const profiles[0]
    ));
    assert!(std::ptr::eq(
        select_profile(&profiles, "com.example.app.widget").unwrap(),
        &raw const profiles[1]
    ));
    assert!(select_profile(&profiles[..1], "com.example.app.widget").is_err());
}

#[test]
fn prefers_explicit_profile_and_rejects_ambiguous_matches() {
    let profiles = [profile("PREFIX.*"), profile("PREFIX.com.example.app")];
    assert!(std::ptr::eq(
        select_profile(&profiles, "com.example.app").unwrap(),
        &raw const profiles[1]
    ));
    assert!(
        select_profile(
            &[profile("PREFIX.*"), profile("OTHER.*")],
            "com.example.app"
        )
        .is_err()
    );
}

#[test]
fn entitlement_arrays_require_every_requested_value_to_be_authorized() {
    let allowed = Value::Array(vec![Value::String("PREFIX.*".to_string())]);
    assert!(permits(
        &allowed,
        &Value::Array(vec![Value::String("PREFIX.shared".to_string())])
    ));
    assert!(!permits(
        &allowed,
        &Value::Array(vec![Value::String("OTHER.shared".to_string())])
    ));
    assert!(!permits(
        &Value::Boolean(true),
        &Value::String("true".to_string())
    ));
}

#[test]
fn profile_application_id_requires_a_valid_string_pattern() {
    assert_eq!(
        profile("PREFIX.*").app_id("com.example.app").as_deref(),
        Some("PREFIX.com.example.app")
    );
    assert_eq!(
        profile("PREFIX.com.example.app")
            .app_id("com.example.app")
            .as_deref(),
        Some("PREFIX.com.example.app")
    );
    assert!(profile("malformed").app_id("com.example.app").is_none());

    let mut missing = profile("PREFIX.*");
    missing.entitlements.remove("application-identifier");
    assert!(missing.app_id("com.example.app").is_none());
    let mut wrong_type = profile("PREFIX.*");
    wrong_type
        .entitlements
        .insert("application-identifier".into(), Value::Boolean(true));
    assert!(wrong_type.app_id("com.example.app").is_none());
}

#[test]
fn entitlement_dictionary_matching_is_recursive_and_key_complete() {
    let allowed = Value::Dictionary(Dictionary::from_iter([
        ("group".to_string(), Value::String("TEAM.*".into())),
        ("enabled".to_string(), Value::Boolean(true)),
    ]));
    let accepted = Value::Dictionary(Dictionary::from_iter([(
        "group".to_string(),
        Value::String("TEAM.app".into()),
    )]));
    let rejected = Value::Dictionary(Dictionary::from_iter([(
        "group".to_string(),
        Value::String("OTHER.app".into()),
    )]));
    assert!(permits(&allowed, &accepted));
    assert!(!permits(&allowed, &rejected));
    assert!(!permits(&allowed, &Value::Array(Vec::new())));
}

#[test]
fn entitlement_override_must_be_a_dictionary_and_profile_must_match() {
    let dir = tempfile::tempdir().unwrap();
    let override_path = dir.path().join("entitlements.plist");
    Value::Dictionary(Dictionary::new())
        .to_file_xml(&override_path)
        .unwrap();
    assert!(
        read_entitlements(Path::new("unused.app"), Some(&override_path))
            .unwrap()
            .is_empty()
    );

    Value::Array(Vec::new())
        .to_file_xml(&override_path)
        .unwrap();
    assert!(
        read_entitlements(Path::new("unused.app"), Some(&override_path))
            .unwrap_err()
            .contains("must be a dictionary")
    );
    assert!(
        signing_entitlements(
            &Dictionary::new(),
            &profile("OTHER.com.other"),
            "com.example.app"
        )
        .unwrap_err()
        .contains("profile does not match bundle ID")
    );
}

#[test]
fn entitlement_patterns_only_treat_trailing_star_as_wildcard() {
    assert!(matches_pattern("TEAM.app", "TEAM.app"));
    assert!(!matches_pattern("TEAM.app", "TEAM.app.extra"));
    assert!(matches_pattern("TEAM*", "TEAM.app"));
    assert!(!matches_pattern("TEAM.*.app", "TEAM.one.app"));
}

#[cfg(target_os = "macos")]
#[test]
fn prepare_target_reads_real_codesign_entitlements_and_embeds_matching_profile() {
    let dir = tempfile::tempdir().unwrap();
    let (app, capabilities) = signed_test_app(dir.path());
    let mut profile = profile("PREFIX.com.example.test");
    profile.entitlements.extend(capabilities);
    profile.path = dir.path().join("profile.mobileprovision");
    fs::write(&profile.path, b"profile selected for test bundle").unwrap();
    let path = prepare_target(&app, &[profile], None, dir.path(), 0)
        .unwrap()
        .unwrap();
    let result = Value::from_file(path).unwrap();
    assert_eq!(
        result.as_dictionary().unwrap()["com.apple.developer.healthkit"],
        Value::Boolean(true)
    );
    assert_eq!(
        fs::read(app.join("embedded.mobileprovision")).unwrap(),
        b"profile selected for test bundle"
    );
}

#[cfg(target_os = "macos")]
fn signed_test_app(root: &Path) -> (PathBuf, Dictionary) {
    let app = root.join("Test.app");
    fs::create_dir(&app).unwrap();
    fs::copy("/bin/echo", app.join("Test")).unwrap();
    Value::Dictionary(Dictionary::from_iter([
        (
            "CFBundleIdentifier".to_string(),
            Value::String("com.example.test".to_string()),
        ),
        (
            "CFBundleExecutable".to_string(),
            Value::String("Test".to_string()),
        ),
    ]))
    .to_file_xml(app.join("Info.plist"))
    .unwrap();
    let original = root.join("original.plist");
    let capabilities = Dictionary::from_iter([(
        "com.apple.developer.healthkit".to_string(),
        Value::Boolean(true),
    )]);
    Value::Dictionary(capabilities.clone())
        .to_file_xml(&original)
        .unwrap();
    let status = Command::new("/usr/bin/codesign")
        .args(["-f", "-s", "-", "--entitlements"])
        .arg(&original)
        .arg(&app)
        .status()
        .unwrap();
    assert!(status.success());
    (app, capabilities)
}
