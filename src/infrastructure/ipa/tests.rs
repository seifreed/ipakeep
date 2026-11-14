use super::*;

fn test_ipa_bytes() -> Vec<u8> {
    test_ipa_bytes_with_manifest(None)
}

fn test_ipa_bytes_with_manifest(manifest: Option<plist::Dictionary>) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    write_info_plist(&mut writer, options);

    writer
        .start_file("Payload/Test.app/TestExec", options.unix_permissions(0o755))
        .expect("start executable");
    writer.write_all(b"binary").expect("write executable");

    writer
        .add_symlink("Payload/Test.app/Frameworks/Current", "Versions/A", options)
        .expect("add symlink");

    if let Some(manifest) = manifest {
        write_manifest(&mut writer, options, manifest);
    }

    writer.finish().expect("finish zip").into_inner()
}

fn write_info_plist(
    writer: &mut zip::ZipWriter<Cursor<Vec<u8>>>,
    options: zip::write::SimpleFileOptions,
) {
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
}

fn write_manifest(
    writer: &mut zip::ZipWriter<Cursor<Vec<u8>>>,
    options: zip::write::SimpleFileOptions,
    manifest: plist::Dictionary,
) {
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

#[test]
fn extract_ipa_finds_the_payload_app_bundle() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let ipa = temp_dir.path().join("test.ipa");
    let destination = temp_dir.path().join("extracted");
    std::fs::write(&ipa, test_ipa_bytes()).expect("write IPA");
    std::fs::create_dir(&destination).expect("create destination");

    extract_ipa(&ipa, &destination).expect("extract IPA");

    assert_eq!(
        find_app_bundle(&destination).expect("find app bundle"),
        destination.join("Payload/Test.app")
    );
}

#[cfg(unix)]
#[test]
fn find_app_bundle_ignores_symlinked_app_directories() {
    use std::os::unix::fs::symlink;

    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let payload = temp_dir.path().join("Payload");
    let external_app = temp_dir.path().join("External.app");
    std::fs::create_dir(&payload).expect("create payload");
    std::fs::create_dir(&external_app).expect("create external app");
    symlink(&external_app, payload.join("Linked.app")).expect("create app symlink");

    assert!(find_app_bundle(temp_dir.path()).is_err());
}

#[test]
fn bundle_identifier_reads_nonempty_info_plist_value() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let app = temp_dir.path().join("Example.app");
    std::fs::create_dir(&app).expect("create app bundle");
    write_bundle_identifier(&app, "com.example.app");

    assert_eq!(bundle_identifier(&app).unwrap(), "com.example.app");
}

#[test]
fn bundle_identifier_rejects_empty_info_plist_value() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let app = temp_dir.path().join("Example.app");
    std::fs::create_dir(&app).expect("create app bundle");
    write_bundle_identifier(&app, "");

    assert!(bundle_identifier(&app).is_err());
}

fn write_bundle_identifier(app: &std::path::Path, identifier: &str) {
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert(
        "CFBundleIdentifier".into(),
        plist::Value::String(identifier.into()),
    );
    let mut bytes = Vec::new();
    plist::Value::Dictionary(dictionary)
        .to_writer_xml(&mut bytes)
        .expect("encode Info.plist");
    std::fs::write(app.join("Info.plist"), bytes).expect("write Info.plist");
}

fn zip_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip");
    let mut file = archive.by_name(name).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("read entry");
    Some(data)
}

#[test]
fn prepare_download_checks_checksum_and_patches_a_valid_archive() {
    let bytes = test_ipa_bytes();
    let item = crate::domain::entity::DownloadItem {
        url: "https://example.test/app.ipa".into(),
        md5: format!("{:x}", md5::compute(&bytes)),
        sinfs: Vec::new(),
        metadata: DownloadMetadata::new(),
    };

    let prepared = prepare_download(&item, &bytes).expect("valid download");
    assert!(zip_entry(&prepared, "Payload/Test.app/TestExec").is_some());

    let item = crate::domain::entity::DownloadItem {
        md5: "invalid-checksum".into(),
        ..item
    };
    assert!(prepare_download(&item, &bytes).is_err());
}

#[test]
fn prepare_download_rejects_non_zip_data() {
    let item = crate::domain::entity::DownloadItem {
        url: "https://example.test/app.ipa".into(),
        md5: String::new(),
        sinfs: Vec::new(),
        metadata: DownloadMetadata::new(),
    };

    assert!(prepare_download(&item, b"not a zip archive").is_err());
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
fn patch_ipa_replaces_existing_metadata_and_sinf_and_preserves_directories() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    write_info_plist(&mut writer, options);
    writer
        .add_directory("Payload/Test.app/Frameworks/", options)
        .expect("add Frameworks directory");
    writer
        .start_file("Payload/Test.app/SC_Info/TestExec.sinf", options)
        .expect("start old sinf");
    writer.write_all(b"old sinf").expect("write old sinf");
    writer
        .start_file("iTunesMetadata.plist", options)
        .expect("start old metadata");
    writer
        .write_all(b"old metadata")
        .expect("write old metadata");
    let ipa = writer.finish().expect("finish zip").into_inner();
    let metadata = serde_json::json!({"bundleId": "com.example.app"});
    let sinfs = [Sinf {
        id: 0,
        data: b"new sinf".to_vec(),
    }];

    let patched =
        patch_ipa(&ipa, &sinfs, metadata.as_object().expect("metadata")).expect("patch ipa");

    assert_eq!(
        zip_entry(&patched, "Payload/Test.app/SC_Info/TestExec.sinf").expect("sinf"),
        b"new sinf"
    );
    assert_eq!(
        zip_entry(&patched, "Payload/Test.app/Frameworks/"),
        Some(Vec::new())
    );
    let metadata_bytes = zip_entry(&patched, "iTunesMetadata.plist").expect("metadata plist");
    assert!(String::from_utf8_lossy(&metadata_bytes).contains("com.example.app"));
}

#[test]
fn patch_ipa_deduplicates_input_entries_with_the_same_name() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, contents) in [("first.txt", &b"first"[..]), ("other.txt", &b"second"[..])] {
        writer.start_file(name, options).expect("start entry");
        writer.write_all(contents).expect("write entry");
    }
    let mut ipa = writer.finish().expect("finish zip").into_inner();
    for offset in 0..=ipa.len() - b"other.txt".len() {
        if ipa[offset..offset + b"other.txt".len()] == *b"other.txt" {
            ipa[offset..offset + b"first.txt".len()].copy_from_slice(b"first.txt");
        }
    }
    let expected = {
        let mut input = zip::ZipArchive::new(Cursor::new(&ipa)).expect("input ZIP");
        assert!(input.has_duplicate_names());
        let mut first = input.by_index(0).expect("first duplicate");
        let mut contents = Vec::new();
        first
            .read_to_end(&mut contents)
            .expect("read first duplicate");
        contents
    };

    let patched = patch_ipa(&ipa, &[], &DownloadMetadata::new()).expect("patch IPA");
    let mut archive = zip::ZipArchive::new(Cursor::new(patched)).expect("patched ZIP");

    assert_eq!(archive.len(), 1);
    let mut entry = archive.by_name("first.txt").expect("single entry");
    let mut contents = Vec::new();
    entry.read_to_end(&mut contents).expect("read entry");
    assert_eq!(contents, expected);
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
