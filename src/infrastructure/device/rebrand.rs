//! Rewrite `CFBundleIdentifier` across an app and its extensions (`--bundle-id`).
//!
//! Installing a decrypted app under its real id replaces the App Store copy on
//! the device. Rewriting the main id (and remapping every extension that lived
//! under it) installs a distinct copy alongside it. Entitlements need no special
//! handling here: the signing step reads the rewritten `Info.plist`, selects the
//! matching provisioning profile, sets `application-identifier` from it, and
//! rebinds the default keychain group — so correctness follows from the rewrite.

use crate::infrastructure::ipa::bundle_identifier;
use crate::infrastructure::signing::collect_sign_targets;
use plist::Value;
use std::path::Path;

/// Rewrite the app's main `CFBundleIdentifier` to `new_main_id` and remap every
/// nested `.app`/`.appex` that lived under the old id's namespace onto the new
/// one. A no-op when the id already matches.
pub(super) fn rewrite_bundle_ids(app: &Path, new_main_id: &str) -> Result<(), String> {
    let old_main = bundle_identifier(app)?;
    if old_main == new_main_id {
        return Ok(());
    }
    let mut targets = Vec::new();
    collect_sign_targets(app, &mut targets, &|_| Ok(false))?;
    for target in targets {
        if !target
            .extension()
            .is_some_and(|ext| ext == "app" || ext == "appex")
        {
            continue;
        }
        let current = bundle_identifier(&target)?;
        if let Some(updated) = remap_id(&old_main, new_main_id, &current) {
            write_bundle_identifier(&target, &updated)?;
        }
    }
    Ok(())
}

/// Map `current` onto the new namespace: the old main id becomes `new_main`; a
/// child (`old_main.suffix`) becomes `new_main.suffix`; a foreign id (an
/// embedded SDK with its own namespace) is left unchanged (`None`).
fn remap_id(old_main: &str, new_main: &str, current: &str) -> Option<String> {
    if current == old_main {
        return Some(new_main.to_string());
    }
    current
        .strip_prefix(old_main)
        .filter(|rest| rest.starts_with('.'))
        .map(|rest| format!("{new_main}{rest}"))
}

fn write_bundle_identifier(bundle: &Path, new_id: &str) -> Result<(), String> {
    let info = bundle.join("Info.plist");
    let mut value =
        Value::from_file(&info).map_err(|error| format!("{}: {error}", info.display()))?;
    value
        .as_dictionary_mut()
        .ok_or_else(|| format!("{}: Info.plist is not a dictionary", info.display()))?
        .insert("CFBundleIdentifier".into(), Value::String(new_id.into()));
    value
        .to_file_xml(&info)
        .map_err(|error| format!("{}: {error}", info.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Value;
    use std::path::PathBuf;

    #[test]
    fn remap_covers_main_child_and_foreign() {
        assert_eq!(
            remap_id("com.king.candy", "com.me.candy", "com.king.candy").as_deref(),
            Some("com.me.candy")
        );
        assert_eq!(
            remap_id("com.king.candy", "com.me.candy", "com.king.candy.notify").as_deref(),
            Some("com.me.candy.notify")
        );
        // A bundle whose id only shares a prefix segment is not a child.
        assert_eq!(
            remap_id("com.king.candy", "com.me.candy", "com.king.candyland"),
            None
        );
        // Foreign namespace: leave it alone.
        assert_eq!(
            remap_id("com.king.candy", "com.me.candy", "io.sdk.lib"),
            None
        );
    }

    fn write_info(dir: &Path, bundle_id: &str) {
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), Value::String(bundle_id.into()));
        Value::Dictionary(dict)
            .to_file_xml(dir.join("Info.plist"))
            .unwrap();
    }

    #[test]
    fn rewrites_app_and_extension_leaves_foreign_untouched() {
        let tmp = tempfile::TempDir::new().unwrap();
        let app = tmp.path().join("Payload").join("Candy.app");
        let ext = app.join("PlugIns").join("Notify.appex");
        let sdk = app.join("Frameworks").join("Vendor.framework");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::create_dir_all(&sdk).unwrap();
        write_info(&app, "com.king.candy");
        write_info(&ext, "com.king.candy.notify");
        write_info(&sdk, "io.vendor.sdk");

        rewrite_bundle_ids(&app, "com.me.candy").unwrap();

        let read = |p: &PathBuf| bundle_identifier(p).unwrap();
        assert_eq!(read(&app), "com.me.candy");
        assert_eq!(read(&ext), "com.me.candy.notify");
        // Frameworks keep their own identity.
        assert_eq!(read(&sdk), "io.vendor.sdk");
    }

    #[test]
    fn same_id_is_a_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let app = tmp.path().join("Candy.app");
        std::fs::create_dir_all(&app).unwrap();
        write_info(&app, "com.king.candy");
        rewrite_bundle_ids(&app, "com.king.candy").unwrap();
        assert_eq!(bundle_identifier(&app).unwrap(), "com.king.candy");
    }
}
