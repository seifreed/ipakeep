use super::*;
use crate::infrastructure::observability::log_capture::LogCapture;

#[test]
fn reads_der_and_indefinite_length_ber_provisioning_profiles() {
    let mut entitlements = Dictionary::new();
    entitlements.insert(
        "application-identifier".into(),
        Value::String("PREFIX.*".into()),
    );
    let mut profile = Dictionary::new();
    profile.insert("Entitlements".into(), Value::Dictionary(entitlements));
    let mut plist = Vec::new();
    Value::Dictionary(profile)
        .to_writer_xml(&mut plist)
        .expect("encode profile plist");
    let dir = tempfile::tempdir().unwrap();
    let capture = LogCapture::default();
    let _guard = capture.install();

    for (name, envelope) in [
        ("der", cms::fixtures::der_signed_data(&plist)),
        ("ber", cms::fixtures::ber_signed_data(&plist, 64)),
    ] {
        let path = dir.path().join(format!("{name}.mobileprovision"));
        fs::write(&path, envelope).unwrap();
        let parsed = Profile::read(&path).expect("provisioning profile");
        assert_eq!(parsed.path, path);
        assert_eq!(
            parsed.app_id("com.example.app").as_deref(),
            Some("PREFIX.com.example.app")
        );
    }
    let logs = capture.contents();
    assert_eq!(logs.matches("provisioning_profile.decoded").count(), 2);
    assert!(logs.contains("outcome=\"success\""));
    assert!(logs.contains("duration_ms="));
    assert!(!logs.contains("PREFIX"));
    assert!(!logs.contains(".mobileprovision"));
}

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
    assert_eq!(select_profile(&profiles, "com.example.app"), Ok(0));
    assert_eq!(select_profile(&profiles, "com.example.app.widget"), Ok(1));
    assert!(select_profile(&profiles[..1], "com.example.app.widget").is_err());
}

#[test]
fn prefers_explicit_profile_and_rejects_ambiguous_matches() {
    let profiles = [profile("PREFIX.*"), profile("PREFIX.com.example.app")];
    assert_eq!(select_profile(&profiles, "com.example.app"), Ok(1));
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
fn parses_entitlements_from_cms_profile_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.mobileprovision");
    let encoded = dir.path().join("profile.plist");
    Value::Dictionary(Dictionary::from_iter([(
        "Entitlements".to_string(),
        Value::Dictionary(Dictionary::new()),
    )]))
    .to_file_xml(&encoded)
    .unwrap();
    let output = fs::read(&encoded).unwrap();

    let profile = Profile::from_cms_output(&path, &output).unwrap();
    assert_eq!(profile.path, path);
    assert!(profile.entitlements.is_empty());
    assert!(
        Profile::from_cms_output(&path, b"invalid plist")
            .err()
            .unwrap()
            .contains("invalid profile")
    );

    Value::Dictionary(Dictionary::new())
        .to_file_xml(&encoded)
        .unwrap();
    let output = fs::read(&encoded).unwrap();
    assert_eq!(
        Profile::from_cms_output(&path, &output).err().unwrap(),
        "provisioning profile has no Entitlements dictionary"
    );
}

#[test]
fn profile_reader_rejects_invalid_cms_data_and_missing_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.mobileprovision");
    fs::write(&path, b"not a provisioning profile").unwrap();
    let capture = LogCapture::default();
    let _guard = capture.install();
    let error = Profile::read(&path).err().unwrap();
    assert!(error.starts_with("decoding "), "{error}");

    let missing = directory.path().join("missing.mobileprovision");
    let error = Profile::read(&missing).err().unwrap();
    assert!(error.starts_with("reading "), "{error}");

    let logs = capture.contents();
    assert!(logs.contains("WARN"));
    assert!(logs.contains("outcome=\"failure\""));
    assert!(logs.contains("error_type=\"invalid_cms\""));
    assert!(logs.contains("error_type=\"read_failed\""));
    assert!(!logs.contains("not a provisioning profile"));
    assert!(!logs.contains(".mobileprovision"));
}

#[test]
fn non_bundle_signing_targets_do_not_get_bundle_entitlements() {
    assert_eq!(
        prepare_target(
            Path::new("Frameworks/Support.dylib"),
            &[],
            None,
            Path::new("unused"),
            0,
        )
        .unwrap(),
        None
    );
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

fn unsigned_test_app(root: &Path) -> PathBuf {
    let app = root.join("Test.app");
    fs::create_dir_all(app.join("Frameworks")).unwrap();
    fs::write(app.join("Frameworks").join("Support.dylib"), b"dylib").unwrap();
    Value::Dictionary(Dictionary::from_iter([(
        "CFBundleIdentifier".to_string(),
        Value::String("com.example.test".to_string()),
    )]))
    .to_file_xml(app.join("Info.plist"))
    .unwrap();
    app
}

fn test_request<'a>(
    profiles: &'a [PathBuf],
    entitlements: Option<&'a Path>,
) -> crate::infrastructure::device::InstallRequest<'a> {
    crate::infrastructure::device::InstallRequest {
        ipa: Path::new("unused.ipa"),
        device: "device",
        identity: "Apple Development",
        provisioning_profiles: profiles,
        entitlements,
        launch: false,
        legacy_device: false,
        native_device: false,
        bundle_id: None,
    }
}

fn command_line(command: &Command) -> Vec<String> {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn signs_nested_code_before_the_app_with_validated_entitlements() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let override_path = dir.path().join("override.plist");
    Value::Dictionary(Dictionary::new())
        .to_file_xml(&override_path)
        .unwrap();
    let mut signing_profile = profile("PREFIX.com.example.test");
    signing_profile.path = dir.path().join("profile.mobileprovision");
    fs::write(&signing_profile.path, b"profile for test bundle").unwrap();
    let request = test_request(&[], Some(&override_path));
    let mut commands = Vec::new();

    sign_bundle_with_profiles(
        &app,
        &request,
        &[signing_profile],
        dir.path(),
        &mut |command| {
            commands.push(command_line(&command));
            Ok(())
        },
    )
    .unwrap();

    let dylib = app.join("Frameworks").join("Support.dylib");
    let entitlements = dir.path().join("entitlements-1.plist");
    assert_eq!(
        commands,
        [
            vec![
                "/usr/bin/codesign".to_string(),
                "--force".into(),
                "--sign".into(),
                "Apple Development".into(),
                "--preserve-metadata=identifier,requirements,flags,entitlements".into(),
                dylib.display().to_string(),
            ],
            vec![
                "/usr/bin/codesign".to_string(),
                "--force".into(),
                "--sign".into(),
                "Apple Development".into(),
                "--entitlements".into(),
                entitlements.display().to_string(),
                app.display().to_string(),
            ],
        ]
    );
    let written = Value::from_file(&entitlements).unwrap();
    assert_eq!(
        written.as_dictionary().unwrap()["application-identifier"],
        Value::String("PREFIX.com.example.test".into())
    );
    assert_eq!(
        fs::read(app.join("embedded.mobileprovision")).unwrap(),
        b"profile for test bundle"
    );
}

#[test]
fn codesign_failure_stops_signing_remaining_targets() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let override_path = dir.path().join("override.plist");
    Value::Dictionary(Dictionary::new())
        .to_file_xml(&override_path)
        .unwrap();
    let mut signing_profile = profile("PREFIX.com.example.test");
    signing_profile.path = dir.path().join("profile.mobileprovision");
    fs::write(&signing_profile.path, b"profile").unwrap();
    let request = test_request(&[], Some(&override_path));
    let mut attempts = 0;

    let error =
        sign_bundle_with_profiles(&app, &request, &[signing_profile], dir.path(), &mut |_| {
            attempts += 1;
            Err("codesign rejected".to_string())
        })
        .unwrap_err();

    assert_eq!(error, "codesign rejected");
    assert_eq!(attempts, 1);
}

#[test]
fn sign_bundle_reads_request_profiles_and_rejects_unmatched_bundles_before_signing() {
    let mut entitlements = Dictionary::new();
    entitlements.insert(
        "application-identifier".into(),
        Value::String("OTHER.com.other".into()),
    );
    let mut plist = Vec::new();
    Value::Dictionary(Dictionary::from_iter([(
        "Entitlements".to_string(),
        Value::Dictionary(entitlements),
    )]))
    .to_writer_xml(&mut plist)
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let profile_path = dir.path().join("other.mobileprovision");
    fs::write(&profile_path, cms::fixtures::der_signed_data(&plist)).unwrap();

    let profiles = [profile_path];
    let error = sign_bundle(&app, &test_request(&profiles, None), dir.path()).unwrap_err();
    assert_eq!(
        error,
        "no provisioning profile matches com.example.test; supply --provisioning-profile for this bundle"
    );
    assert!(!app.join("embedded.mobileprovision").exists());

    let missing = [dir.path().join("missing.mobileprovision")];
    let error = sign_bundle(&app, &test_request(&missing, None), dir.path()).unwrap_err();
    assert!(error.starts_with("reading "), "{error}");
}

#[test]
fn ambiguous_profiles_are_reported_by_bundle_identifier() {
    assert_eq!(
        select_profile(
            &[profile("PREFIX.*"), profile("OTHER.*")],
            "com.example.app"
        ),
        Err(
            "multiple provisioning profiles match com.example.app; supply one matching profile"
                .to_string()
        )
    );
}

#[test]
fn codesign_entitlement_output_is_parsed_as_a_dictionary() {
    assert!(parse_entitlements_xml(" \n").unwrap().is_empty());
    let mut xml = Vec::new();
    Value::Dictionary(Dictionary::from_iter([(
        "get-task-allow".to_string(),
        Value::Boolean(true),
    )]))
    .to_writer_xml(&mut xml)
    .unwrap();
    let parsed = parse_entitlements_xml(&String::from_utf8(xml).unwrap()).unwrap();
    assert_eq!(parsed["get-task-allow"], Value::Boolean(true));

    let mut array = Vec::new();
    Value::Array(Vec::new()).to_writer_xml(&mut array).unwrap();
    assert_eq!(
        parse_entitlements_xml(&String::from_utf8(array).unwrap()).unwrap_err(),
        "entitlements must be a dictionary"
    );
    assert!(parse_entitlements_xml("<plist><dict>").is_err());
}

#[test]
fn embedded_entitlements_of_unreadable_code_are_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_entitlements(&dir.path().join("Missing.app"), None).is_err());
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
#[test]
fn signs_nested_code_and_app_using_matching_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let (app, capabilities) = signed_test_app(dir.path());
    let framework = app.join("Frameworks");
    fs::create_dir(&framework).unwrap();
    fs::copy("/bin/echo", framework.join("Support.dylib")).unwrap();
    let mut signing_profile = profile("PREFIX.com.example.test");
    signing_profile.entitlements.extend(capabilities);
    signing_profile.path = dir.path().join("profile.mobileprovision");
    fs::write(&signing_profile.path, b"profile selected for test bundle").unwrap();
    let profiles = [signing_profile];
    let request = crate::infrastructure::device::InstallRequest {
        ipa: Path::new("unused.ipa"),
        device: "device",
        identity: "-",
        provisioning_profiles: &[],
        entitlements: None,
        launch: false,
        legacy_device: false,
        native_device: false,
        bundle_id: None,
    };

    sign_bundle_with_profiles(&app, &request, &profiles, dir.path(), &mut run_inherit).unwrap();

    assert_eq!(
        fs::read(app.join("embedded.mobileprovision")).unwrap(),
        b"profile selected for test bundle"
    );
    assert!(
        extract_entitlements(&app)
            .unwrap()
            .contains("com.apple.developer.healthkit")
    );

    let empty_app = signed_app_without_entitlements(dir.path());
    let mut empty_profile = profile("PREFIX.com.example.empty");
    empty_profile.path = dir.path().join("empty.mobileprovision");
    fs::write(&empty_profile.path, b"empty app profile").unwrap();
    let path = prepare_target(&empty_app, &[empty_profile], None, dir.path(), 1)
        .unwrap()
        .unwrap();
    let entitlements = Value::from_file(path).unwrap();
    assert_eq!(
        entitlements.as_dictionary().unwrap()["application-identifier"],
        Value::String("PREFIX.com.example.empty".into())
    );
    assert!(
        !entitlements
            .as_dictionary()
            .unwrap()
            .contains_key("com.apple.developer.healthkit")
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

#[cfg(target_os = "macos")]
fn signed_app_without_entitlements(root: &Path) -> PathBuf {
    let app = root.join("Empty.app");
    fs::create_dir(&app).unwrap();
    fs::copy("/bin/echo", app.join("Test")).unwrap();
    Value::Dictionary(Dictionary::from_iter([
        (
            "CFBundleIdentifier".to_string(),
            Value::String("com.example.empty".into()),
        ),
        (
            "CFBundleExecutable".to_string(),
            Value::String("Test".into()),
        ),
    ]))
    .to_file_xml(app.join("Info.plist"))
    .unwrap();
    let status = Command::new("/usr/bin/codesign")
        .args(["-f", "-s", "-"])
        .arg(&app)
        .status()
        .unwrap();
    assert!(status.success());
    app
}

/// Write `entitlements` as an override plist under `dir`.
fn entitlement_override(dir: &Path, entitlements: Dictionary) -> PathBuf {
    let path = dir.join("override.plist");
    Value::Dictionary(entitlements).to_file_xml(&path).unwrap();
    path
}

#[test]
fn prepare_target_prefixes_unauthorized_entitlements_with_the_bundle_id() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let requested = Dictionary::from_iter([(
        "com.apple.developer.healthkit".to_string(),
        Value::Boolean(true),
    )]);
    let override_path = entitlement_override(dir.path(), requested);
    let profiles = [profile("PREFIX.com.example.test")];

    let error = prepare_target(&app, &profiles, Some(&override_path), dir.path(), 0).unwrap_err();

    assert!(
        error.starts_with("com.example.test: entitlement \"com.apple.developer.healthkit\""),
        "{error}"
    );
}

#[test]
fn prepare_target_reports_unwritable_entitlement_files() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let override_path = entitlement_override(dir.path(), Dictionary::new());
    let workdir = dir.path().join("missing-workdir");
    let profiles = [profile("PREFIX.com.example.test")];

    let error = prepare_target(&app, &profiles, Some(&override_path), &workdir, 0).unwrap_err();

    let expected = workdir.join("entitlements-0.plist");
    assert!(
        error.starts_with(&format!("{}: ", expected.display())),
        "{error}"
    );
}

#[test]
fn prepare_target_reports_profiles_that_cannot_be_embedded() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let override_path = entitlement_override(dir.path(), Dictionary::new());
    let mut missing_profile = profile("PREFIX.com.example.test");
    missing_profile.path = dir.path().join("missing.mobileprovision");

    let error = prepare_target(
        &app,
        &[missing_profile],
        Some(&override_path),
        dir.path(),
        0,
    )
    .unwrap_err();

    assert!(
        error.starts_with(&format!("embedding profile in {}: ", app.display())),
        "{error}"
    );
}

#[test]
fn unsigned_bundles_have_no_entitlements_but_other_codesign_errors_remain() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let unsigned = Err(format!("/tmp/Test.app: {UNSIGNED_CODE}"));
    assert_eq!(unsigned_as_empty(unsigned), Ok(String::new()));
    let logs = capture.contents();
    assert!(logs.contains("entitlements.unsigned_bundle"), "{logs}");
    assert!(!logs.contains("/tmp/Test.app"), "{logs}");
    assert_eq!(
        unsigned_as_empty(Err("invalid signature".into())),
        Err("invalid signature".to_string())
    );
    assert_eq!(
        unsigned_as_empty(Ok("<plist/>".into())),
        Ok("<plist/>".into())
    );
}

// Runs the real /usr/bin/codesign to read the unsigned bundle (macOS only);
// the unsigned-to-empty decision itself is covered on every OS above.
#[cfg(target_os = "macos")]
#[test]
fn signs_a_never_signed_bundle_with_profile_entitlements_only() {
    let dir = tempfile::tempdir().unwrap();
    let app = unsigned_test_app(dir.path());
    let mut signing_profile = profile("PREFIX.com.example.test");
    signing_profile.path = dir.path().join("profile.mobileprovision");
    fs::write(&signing_profile.path, b"profile").unwrap();
    let request = test_request(&[], None);
    let mut commands = 0;

    sign_bundle_with_profiles(&app, &request, &[signing_profile], dir.path(), &mut |_| {
        commands += 1;
        Ok(())
    })
    .unwrap();

    assert_eq!(commands, 2);
    let written = Value::from_file(dir.path().join("entitlements-1.plist")).unwrap();
    assert_eq!(
        written.as_dictionary().unwrap()["application-identifier"],
        Value::String("PREFIX.com.example.test".into())
    );
}
