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

    #[test]
    fn collects_bundles_and_signable_dylibs_and_propagates_detection_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let bundle = dir.path().join("Demo.app");
        let dylib = dir.path().join("libDemo.dylib");
        let text = dir.path().join("readme.txt");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(&dylib, b"library").unwrap();
        std::fs::write(&text, b"text").unwrap();

        let mut targets = Vec::new();
        collect_sign_targets(dir.path(), &mut targets, &|path| {
            Ok(path
                .extension()
                .is_some_and(|extension| extension == "dylib"))
        })
        .unwrap();

        assert!(targets.contains(&bundle));
        assert!(targets.contains(&dylib));
        assert!(!targets.contains(&text));

        let error = collect_sign_targets(&dylib, &mut Vec::new(), &|_| {
            Err("dylib inspection failed".into())
        })
        .unwrap_err();
        assert_eq!(error, "dylib inspection failed");
    }

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

    #[cfg(unix)]
    #[test]
    fn skips_socket_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("not-a-bundle");
        let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let mut targets = Vec::new();
        collect_sign_targets(&socket_path, &mut targets, &|_| Ok(true)).unwrap();

        assert_eq!(targets, [] as [std::path::PathBuf; 0]);
    }
}
