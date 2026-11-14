use std::fs;
use std::path::{Path, PathBuf};

/// Collect nested bundle and dylib paths while skipping symlinks.
pub(crate) fn collect_sign_targets(
    path: &Path,
    targets: &mut Vec<PathBuf>,
    is_signable_dylib: &dyn Fn(&Path) -> Result<bool, String>,
) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if path
            .extension()
            .is_some_and(|extension| extension == "dylib")
            && is_signable_dylib(path)?
        {
            targets.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    if path.extension().is_some_and(|extension| {
        matches!(
            extension.to_string_lossy().as_ref(),
            "framework" | "appex" | "app"
        )
    }) {
        targets.push(path.to_path_buf());
    }
    for entry in fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        collect_sign_targets(
            &entry.map_err(|error| error.to_string())?.path(),
            targets,
            is_signable_dylib,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::collect_sign_targets;

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_bundles() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = dir.path().join("Outside.framework");
        let link = dir
            .path()
            .join("App.app")
            .join("Frameworks")
            .join("Linked.framework");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let mut targets = Vec::new();
        collect_sign_targets(dir.path(), &mut targets, &|_| Ok(true)).unwrap();

        assert!(!targets.iter().any(|target| target == &link));
    }
}
