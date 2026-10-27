//! Per-bundle provisioning and entitlement validation for physical devices.

use super::{InstallRequest, bundle_identifier, collect_sign_targets};
use crate::infrastructure::decrypt::extract_entitlements;
use crate::infrastructure::exec::run_inherit;
use plist::{Dictionary, Value};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct Profile {
    path: PathBuf,
    entitlements: Dictionary,
}

impl Profile {
    pub(super) fn read(path: &Path) -> Result<Self, String> {
        let output = Command::new("/usr/bin/security")
            .args(["cms", "-D", "-i"])
            .arg(path)
            .output()
            .map_err(|error| format!("decoding {}: {error}", path.display()))?;
        if !output.status.success() {
            return Err(format!(
                "{}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let value = Value::from_reader(Cursor::new(output.stdout))
            .map_err(|error| format!("invalid profile {}: {error}", path.display()))?;
        let entitlements = value
            .as_dictionary()
            .and_then(|dict| dict.get("Entitlements"))
            .and_then(Value::as_dictionary)
            .ok_or("provisioning profile has no Entitlements dictionary")?
            .clone();
        Ok(Self {
            path: path.to_path_buf(),
            entitlements,
        })
    }

    fn app_id(&self, bundle_id: &str) -> Option<String> {
        let pattern = self
            .entitlements
            .get("application-identifier")?
            .as_string()?;
        let (prefix, _) = pattern.split_once('.')?;
        let identifier = format!("{prefix}.{bundle_id}");
        matches_pattern(pattern, &identifier).then_some(identifier)
    }
}

pub(super) fn sign_bundle(
    app: &Path,
    request: &InstallRequest<'_>,
    workdir: &Path,
) -> Result<(), String> {
    let profiles = request
        .provisioning_profiles
        .iter()
        .map(|path| Profile::read(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut targets = Vec::new();
    collect_sign_targets(app, &mut targets)?;
    targets.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    // Validate every bundle before changing any signatures.
    let mut prepared = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let override_path = (target == app).then_some(request.entitlements).flatten();
        let entitlements = prepare_target(target, &profiles, override_path, workdir, index)?;
        prepared.push((target, entitlements));
    }
    for (target, entitlements) in prepared {
        let mut command = Command::new("/usr/bin/codesign");
        command.args(["--force", "--sign", request.identity]);
        if let Some(path) = entitlements {
            command.arg("--entitlements").arg(path);
        } else {
            command.arg("--preserve-metadata=identifier,requirements,flags,entitlements");
        }
        command.arg(target);
        run_inherit(command)?;
    }
    Ok(())
}

fn prepare_target(
    target: &Path,
    profiles: &[Profile],
    override_path: Option<&Path>,
    workdir: &Path,
    index: usize,
) -> Result<Option<PathBuf>, String> {
    if !target
        .extension()
        .is_some_and(|ext| ext == "app" || ext == "appex")
    {
        return Ok(None);
    }
    let bundle_id = bundle_identifier(target)?;
    let profile = select_profile(profiles, &bundle_id)?;
    let requested = read_entitlements(target, override_path)?;
    let entitlements = signing_entitlements(&requested, profile, &bundle_id)
        .map_err(|error| format!("{bundle_id}: {error}"))?;
    let path = workdir.join(format!("entitlements-{index}.plist"));
    Value::Dictionary(entitlements)
        .to_file_xml(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    fs::copy(&profile.path, target.join("embedded.mobileprovision"))
        .map_err(|error| format!("embedding profile in {}: {error}", target.display()))?;
    Ok(Some(path))
}

fn select_profile<'a>(profiles: &'a [Profile], bundle_id: &str) -> Result<&'a Profile, String> {
    let matching: Vec<_> = profiles
        .iter()
        .filter(|p| p.app_id(bundle_id).is_some())
        .collect();
    let exact: Vec<_> = matching
        .iter()
        .copied()
        .filter(|p| {
            p.entitlements
                .get("application-identifier")
                .and_then(Value::as_string)
                .is_some_and(|id| !id.contains('*'))
        })
        .collect();
    let candidates = if exact.is_empty() { &matching } else { &exact };
    match candidates.as_slice() {
        [profile] => Ok(profile),
        [] => Err(format!(
            "no provisioning profile matches {bundle_id}; supply --provisioning-profile for this bundle"
        )),
        _ => Err(format!(
            "multiple provisioning profiles match {bundle_id}; supply one matching profile"
        )),
    }
}

fn read_entitlements(target: &Path, override_path: Option<&Path>) -> Result<Dictionary, String> {
    let value = if let Some(path) = override_path {
        Value::from_file(path).map_err(|error| format!("{}: {error}", path.display()))?
    } else {
        let xml = extract_entitlements(target)?;
        if xml.trim().is_empty() {
            return Ok(Dictionary::new());
        }
        Value::from_reader(Cursor::new(xml)).map_err(|error| error.to_string())?
    };
    value
        .into_dictionary()
        .ok_or_else(|| "entitlements must be a dictionary".into())
}

fn signing_entitlements(
    requested: &Dictionary,
    profile: &Profile,
    bundle_id: &str,
) -> Result<Dictionary, String> {
    let app_id = profile
        .app_id(bundle_id)
        .ok_or("profile does not match bundle ID")?;
    let mut result = requested.clone();
    rebind_default_keychain(&mut result, &app_id);
    result.insert("application-identifier".into(), Value::String(app_id));
    // Distribution metadata is not an app capability; the new profile owns it.
    for key in [
        "com.apple.developer.team-identifier",
        "get-task-allow",
        "beta-reports-active",
    ] {
        result.remove(key);
        if let Some(value) = profile.entitlements.get(key) {
            result.insert(key.into(), value.clone());
        }
    }
    for (key, value) in &result {
        if !profile
            .entitlements
            .get(key)
            .is_some_and(|allowed| permits(allowed, value))
        {
            return Err(format!(
                "entitlement {key:?} is not authorized by {}; use a matching profile or an explicit --entitlements override",
                profile.path.display()
            ));
        }
    }
    Ok(result)
}

fn rebind_default_keychain(entitlements: &mut Dictionary, app_id: &str) {
    let original_id = entitlements
        .get("application-identifier")
        .and_then(Value::as_string)
        .map(str::to_owned);
    if let Some(Value::Array(groups)) = entitlements.get_mut("keychain-access-groups") {
        for group in groups {
            if group
                .as_string()
                .is_some_and(|id| Some(id) == original_id.as_deref())
            {
                *group = Value::String(app_id.to_owned());
            }
        }
    }
}

fn permits(allowed: &Value, requested: &Value) -> bool {
    match (allowed, requested) {
        (Value::String(pattern), Value::String(value)) => matches_pattern(pattern, value),
        (Value::Array(options), Value::Array(values)) => values
            .iter()
            .all(|value| options.iter().any(|option| permits(option, value))),
        (Value::Dictionary(options), Value::Dictionary(values)) => {
            values.iter().all(|(key, value)| {
                options
                    .get(key)
                    .is_some_and(|option| permits(option, value))
            })
        }
        _ => allowed == requested,
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or_else(|| pattern == value, |prefix| value.starts_with(prefix))
}

#[cfg(test)]
mod tests;
