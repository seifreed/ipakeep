use super::*;

fn test_ipa_bytes() -> Vec<u8> {
    test_ipa_bytes_with_manifest(None)
}

fn test_ipa_bytes_with_manifest(manifest: Option<plist::Dictionary>) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();

    writer
        .start_file("Payload/Test.app/Info.plist", options)
        .expect("start Info.plist");
    let mut info = plist::Dictionary::new();
    info.insert(
        "CFBundleExecutable".into(),
        plist::Value::String("TestExec".into()),
    );
    let mut info_bytes = Vec::new();
    plist::Value::Dictionary(info)
        .to_writer_xml(&mut info_bytes)
        .expect("write info");
    writer.write_all(&info_bytes).expect("write Info.plist");

    writer
        .start_file("Payload/Test.app/TestExec", options.unix_permissions(0o755))
        .expect("start executable");
    writer.write_all(b"binary").expect("write executable");

    writer
        .add_symlink("Payload/Test.app/Frameworks/Current", "Versions/A", options)
        .expect("add symlink");

    if let Some(manifest) = manifest {
        writer
            .start_file("Payload/Test.app/SC_Info/Manifest.plist", options)
            .expect("start manifest");
        let mut manifest_bytes = Vec::new();
        plist::Value::Dictionary(manifest)
            .to_writer_xml(&mut manifest_bytes)
            .expect("write manifest");
        writer
            .write_all(&manifest_bytes)
            .expect("write manifest bytes");
    }

    writer.finish().expect("finish zip").into_inner()
}

fn zip_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip");
    let mut file = archive.by_name(name).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("read entry");
    Some(data)
}

#[test]
fn patch_ipa_writes_sinf_inside_app_sc_info() {
    let patched = patch_ipa(
        &test_ipa_bytes(),
        &[Sinf {
            id: 0,
            data: b"decoded-sinf".to_vec(),
        }],
        &DownloadMetadata::new(),
    )
    .expect("patch ipa");

    assert!(zip_entry(&patched, "SC_Info/0.sinf").is_none());
    assert_eq!(
        zip_entry(&patched, "Payload/Test.app/SC_Info/TestExec.sinf").expect("app sinf"),
        b"decoded-sinf"
    );
}

#[test]
fn patch_ipa_preserves_zip_permissions() {
    let patched = patch_ipa(&test_ipa_bytes(), &[], &DownloadMetadata::new()).expect("patch");
    let mut archive = zip::ZipArchive::new(Cursor::new(patched)).expect("zip");

    {
        let executable = archive
            .by_name("Payload/Test.app/TestExec")
            .expect("executable");
        assert_eq!(executable.unix_mode(), Some(0o100_000 | 0o755));
    }

    {
        let symlink = archive
            .by_name("Payload/Test.app/Frameworks/Current")
            .expect("symlink");
        assert!(symlink.is_symlink());
        assert_eq!(symlink.unix_mode(), Some(0o120_000 | 0o777));
    }
}

#[test]
fn patch_ipa_replicates_manifest_sinf_paths() {
    let mut manifest = plist::Dictionary::new();
    manifest.insert(
        "SinfPaths".into(),
        plist::Value::Array(vec![plist::Value::String("SC_Info/TestExec.sinf".into())]),
    );
    manifest.insert(
        "SinfReplicationPaths".into(),
        plist::Value::Array(vec![plist::Value::String(
            "Frameworks/TestSDK.framework/SC_Info/TestSDK.sinf".into(),
        )]),
    );

    let patched = patch_ipa(
        &test_ipa_bytes_with_manifest(Some(manifest)),
        &[Sinf {
            id: 0,
            data: b"decoded-sinf".to_vec(),
        }],
        &DownloadMetadata::new(),
    )
    .expect("patch ipa");

    assert_eq!(
        zip_entry(&patched, "Payload/Test.app/SC_Info/TestExec.sinf").expect("app sinf"),
        b"decoded-sinf"
    );
    assert_eq!(
        zip_entry(
            &patched,
            "Payload/Test.app/Frameworks/TestSDK.framework/SC_Info/TestSDK.sinf"
        )
        .expect("replicated sinf"),
        b"decoded-sinf"
    );
}

#[test]
fn patch_ipa_rejects_traversal_sinf_manifest_path() {
    let mut manifest = plist::Dictionary::new();
    manifest.insert(
        "SinfPaths".into(),
        plist::Value::Array(vec![plist::Value::String("../evil.sinf".into())]),
    );

    let error = patch_ipa(
        &test_ipa_bytes_with_manifest(Some(manifest)),
        &[Sinf {
            id: 0,
            data: b"decoded-sinf".to_vec(),
        }],
        &DownloadMetadata::new(),
    )
    .unwrap_err();

    assert!(error.contains("unsafe sinf manifest path"));
}

#[test]
fn patch_ipa_rejects_sinf_manifest_path_outside_app_bundle() {
    let mut manifest = plist::Dictionary::new();
    manifest.insert(
        "SinfPaths".into(),
        plist::Value::Array(vec![plist::Value::String(
            "Payload/Other.app/SC_Info/TestExec.sinf".into(),
        )]),
    );

    let error = patch_ipa(
        &test_ipa_bytes_with_manifest(Some(manifest)),
        &[Sinf {
            id: 0,
            data: b"decoded-sinf".to_vec(),
        }],
        &DownloadMetadata::new(),
    )
    .unwrap_err();

    assert!(error.contains("outside app bundle"));
}

#[test]
fn metadata_plist_preserves_non_string_values() {
    let metadata = serde_json::json!({
        "bundleShortVersionString": "1.0",
        "softwareVersionExternalIdentifiers": [100, "200"],
        "hasOrEverHasHadIAP": true
    });
    let metadata = metadata.as_object().expect("object");

    let plist_bytes = build_itunes_metadata_plist(metadata).expect("metadata plist");
    let plist = plist::Value::from_reader(Cursor::new(plist_bytes)).expect("plist");
    let dict = plist.as_dictionary().expect("dict");

    assert!(matches!(
        dict.get("softwareVersionExternalIdentifiers"),
        Some(plist::Value::Array(_))
    ));
    assert_eq!(
        dict.get("hasOrEverHasHadIAP"),
        Some(&plist::Value::Boolean(true))
    );
}

#[test]
fn verify_md5_accepts_matching_checksum() {
    let bytes = b"hello world";
    let expected = format!("{:x}", md5::compute(bytes));
    assert!(verify_md5(bytes, &expected).is_ok());
}

#[test]
fn verify_md5_skips_empty_checksum() {
    assert!(verify_md5(b"anything", "").is_ok());
}

#[test]
fn verify_md5_rejects_mismatch() {
    assert!(verify_md5(b"hello", "00000000000000000000000000000000").is_err());
}
