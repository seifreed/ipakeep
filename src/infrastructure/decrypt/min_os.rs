use super::{macho, open_archive, read_if_macho, repack};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek};

/// Patch every `LC_BUILD_VERSION.minos` and the app's `MinimumOSVersion` down to
/// `version` (e.g. `"16.0"`), so the IPA *installs* on an older iOS.
///
/// Note: installing is not running — apps that call newer APIs crash. The CLI
/// warns about this; this function only performs the patch.
///
/// # Errors
///
/// Returns an error if `version` is malformed or no patch target exists.
pub fn set_min_os(ipa_bytes: &[u8], version: &str) -> Result<Vec<u8>, String> {
    let packed = parse_version(version)?;
    let mut archive = open_archive(ipa_bytes)?;
    let mut patched = BTreeMap::new();

    for index in 0..archive.len() {
        let Some((name, mut bytes)) = read_if_macho(&mut archive, index)? else {
            continue;
        };
        let slices = macho::parse(&bytes).map_err(|error| format!("{name}: {error}"))?;
        let mut touched = false;
        for slice in &slices {
            let Some(build) = slice.build_version else {
                continue;
            };
            let offset =
                usize::try_from(build.minos_offset).map_err(|_| "minos offset overflow")?;
            bytes
                .get_mut(offset..offset + 4)
                .ok_or("minos field out of bounds")?
                .copy_from_slice(&packed.to_le_bytes());
            touched = true;
        }
        if touched {
            patched.insert(name, bytes);
        }
    }

    if let Some((info_name, info_bytes)) = patched_info_plist(&mut archive, version)? {
        patched.insert(info_name, info_bytes);
    }
    if patched.is_empty() {
        return Err("no LC_BUILD_VERSION or Info.plist found to patch".into());
    }
    repack(ipa_bytes, &patched, &BTreeSet::new())
}

pub(super) fn parse_version(version: &str) -> Result<u32, String> {
    let mut parts = version.split('.');
    let mut next = |what: &str| -> Result<u32, String> {
        match parts.next() {
            None => Ok(0),
            Some(part) => part
                .parse::<u32>()
                .map_err(|_| format!("invalid {what} in version {version:?}")),
        }
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if major > 0xffff || minor > 0xff || patch > 0xff {
        return Err(format!("version out of range: {version:?}"));
    }
    Ok((major << 16) | (minor << 8) | patch)
}

fn patched_info_plist<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    version: &str,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let Some(info_name) = find_info_plist_name(archive)? else {
        return Ok(None);
    };
    let mut data = Vec::new();
    archive
        .by_name(&info_name)
        .map_err(|error| error.to_string())?
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    let mut value =
        plist::Value::from_reader(Cursor::new(data)).map_err(|error| error.to_string())?;
    let dictionary = value
        .as_dictionary_mut()
        .ok_or("Info.plist is not a dictionary")?;
    dictionary.insert(
        "MinimumOSVersion".to_string(),
        plist::Value::String(version.to_string()),
    );
    let mut output = Vec::new();
    value
        .to_writer_xml(&mut output)
        .map_err(|error| format!("re-encoding Info.plist: {error}"))?;
    Ok(Some((info_name, output)))
}

fn find_info_plist_name<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<Option<String>, String> {
    for index in 0..archive.len() {
        let name = archive
            .by_index(index)
            .map_err(|error| error.to_string())?
            .name()
            .map_err(|error| error.to_string())?
            .to_string();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            return Ok(Some(name));
        }
    }
    Ok(None)
}
