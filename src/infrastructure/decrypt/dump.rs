//! Dump orchestration: drive a builtin or external dumper to produce a fully
//! decrypted IPA.
//!
//! The builtin backend runs `scripts/frida/ipakeep_dump.py` (per-slice bins) and
//! patches them into the encrypted IPA. The external backends shell out to
//! third-party tools that already emit a decrypted IPA, which we normalize.
//!
//! The argv builders are pure and unit-tested; the actual execution needs a
//! device (USB) or an Apple Silicon Mac (`Local`).

use super::{ensure_decrypted, patch_ipa_decrypted_with};
use crate::infrastructure::exec::{
    newest_ipa, observed_output, observed_status, require_program, run_inherit, temp_dir,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Which dumper backend to drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dumper {
    /// ipakeep's own Frida agent (per-slice bins → patched here).
    Builtin,
    /// `AloneMonkey`'s frida-ios-dump.
    FridaIosDump,
    /// bagbak.
    Bagbak,
    /// r2flutch.
    R2flutch,
    /// `NyaMisty`'s `FoulDecrypt`: static, no-launch decryption on a jailbroken
    /// device over SSH.
    FoulDecrypt,
}

impl Dumper {
    /// Parse a `--dumper` value.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "builtin" => Ok(Self::Builtin),
            "frida-ios-dump" => Ok(Self::FridaIosDump),
            "bagbak" => Ok(Self::Bagbak),
            "r2flutch" => Ok(Self::R2flutch),
            "fouldecrypt" => Ok(Self::FoulDecrypt),
            other => Err(format!(
                "unknown dumper {other:?} (expected builtin|frida-ios-dump|bagbak|r2flutch|fouldecrypt)"
            )),
        }
    }
}

/// Frida device the builtin runner targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpDevice {
    /// USB-attached iOS device.
    Usb,
    /// Local machine (iOS app on an Apple Silicon Mac).
    Local,
}

impl DumpDevice {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Local => "local",
        }
    }
}

/// SSH connection parameters for on-device backends (`FoulDecrypt`).
///
/// The password is never carried here or on argv; it is read from the
/// `IPAKEEP_SSH_PASSWORD` environment variable and fed to `sshpass` via its own
/// `SSHPASS` env. When unset, key auth / interactive prompting is used.
#[derive(Clone, Copy, Debug)]
pub struct SshParams<'a> {
    /// Host to reach the device on (default `127.0.0.1` for USB via iproxy).
    pub host: &'a str,
    /// SSH port (default `2222`, the usual iproxy forward of device port 22).
    pub port: u16,
    /// SSH user (default `mobile`).
    pub user: &'a str,
}

/// Everything needed to produce a decrypted IPA.
pub struct DumpRequest<'a> {
    /// Backend to drive.
    pub dumper: Dumper,
    /// App bundle id (target on the device/Mac).
    pub bundle_id: &'a str,
    /// SSH connection used by the `FoulDecrypt` backend (ignored otherwise).
    pub ssh: SshParams<'a>,
    /// Encrypted IPA to patch — required by the builtin backend.
    pub ipa: Option<&'a Path>,
    /// Frida device for the builtin backend.
    pub device: DumpDevice,
    /// Custom runner for the builtin backend; `None` uses bundled scripts.
    pub agent: Option<&'a Path>,
    /// Seconds to wait for lazily-loaded frameworks and extension processes (builtin).
    pub settle: f64,
    /// Spawn the app rather than attach (builtin).
    pub spawn: bool,
    /// Remove app extensions without a dump instead of failing (builtin).
    pub drop_undumped_extensions: bool,
}

/// Run the dump and return the decrypted IPA bytes.
///
/// # Errors
///
/// Returns an error if the tool is missing, the dump fails, or (builtin) the
/// IPA cannot be patched.
pub fn run_dump(req: &DumpRequest) -> Result<Vec<u8>, String> {
    let work = temp_dir("dump")?;
    let result = match req.dumper {
        Dumper::Builtin => run_builtin(req, &work),
        Dumper::FoulDecrypt => run_fouldecrypt(req, &work),
        external => run_external(external, req.bundle_id, &work),
    };
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn run_builtin(req: &DumpRequest, work: &Path) -> Result<Vec<u8>, String> {
    let python = python_with_frida()?;
    let pulled;
    let ipa = match (req.ipa, req.device) {
        (Some(ipa), _) => ipa,
        (None, DumpDevice::Usb) => {
            pulled = pull_installed_bundle(&python, req.bundle_id, work)?;
            &pulled
        }
        (None, DumpDevice::Local) => {
            return Err("dumping on this Mac needs --ipa <encrypted.ipa> to patch".into());
        }
    };
    let agent = prepare_agent(req.agent, work)?;
    let (program, args) = builtin_argv(BuiltinArgv {
        python: &python,
        agent: &agent,
        bundle_id: req.bundle_id,
        ipa,
        device: req.device,
        out_dir: work,
        settle: req.settle,
        spawn: req.spawn,
    });
    let mut command = Command::new(program);
    command.args(&args);
    run_inherit(command)?;

    let ipa_bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    ensure_decrypted(patch_ipa_decrypted_with(
        &ipa_bytes,
        work,
        req.drop_undumped_extensions,
    )?)
}

/// Copy the installed, still-encrypted bundle off the device so the patch base
/// is always the exact build that gets dumped, not an App Store download that
/// may be a different version.
fn pull_installed_bundle(python: &str, bundle_id: &str, work: &Path) -> Result<PathBuf, String> {
    let directory = work.join("pull");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    for (name, contents) in [
        (
            "ipakeep_pull.py",
            include_str!("../../../scripts/frida/ipakeep_pull.py"),
        ),
        (
            "ipakeep_pull.js",
            include_str!("../../../scripts/frida/ipakeep_pull.js"),
        ),
    ] {
        std::fs::write(directory.join(name), contents).map_err(|error| error.to_string())?;
    }
    let ipa = work.join("installed-encrypted.ipa");
    let mut command = Command::new(python);
    command
        .arg(directory.join("ipakeep_pull.py"))
        .arg("--out")
        .arg(&ipa)
        .arg(bundle_id);
    run_inherit(command)?;
    Ok(ipa)
}

const PYTHON_OVERRIDE_ENV: &str = "IPAKEEP_PYTHON";
const FRIDA_LAUNCHERS: [&str; 2] = ["frida-ps", "frida"];

fn python_with_frida() -> Result<String, String> {
    let override_python = std::env::var(PYTHON_OVERRIDE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let launchers = launcher_interpreters(std::env::var_os("PATH").as_deref());
    let candidates = python_candidates(override_python, &launchers);
    for candidate in &candidates {
        let mut command = Command::new(candidate);
        command.args(["-c", "import frida"]);
        if observed_output(&mut command).is_ok_and(|output| output.status.success()) {
            tracing::info!(
                service = "ipakeep",
                component = "decrypt",
                event_name = "frida.interpreter.selected",
                interpreter = candidate.as_str(),
                "selected Python interpreter for the Frida runner"
            );
            return Ok(candidate.clone());
        }
    }
    Err(format!(
        "cannot import Frida from any of {candidates:?}; set {PYTHON_OVERRIDE_ENV} or install `frida` and `frida-tools` in the same Python environment"
    ))
}

fn python_candidates(override_python: Option<String>, launchers: &[String]) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    for candidate in override_python
        .into_iter()
        .chain(std::iter::once("python3".to_string()))
        .chain(launchers.iter().cloned())
    {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn launcher_interpreters(path: Option<&std::ffi::OsStr>) -> Vec<String> {
    let Some(path) = path else {
        return Vec::new();
    };
    std::env::split_paths(path)
        .flat_map(|dir| FRIDA_LAUNCHERS.map(|launcher| dir.join(launcher)))
        .filter_map(|launcher| std::fs::read(launcher).ok())
        .filter_map(|contents| {
            let first_line = contents.split(|byte| *byte == b'\n').next()?;
            interpreter_from_shebang(std::str::from_utf8(first_line).ok()?)
        })
        .collect()
}

fn interpreter_from_shebang(line: &str) -> Option<String> {
    let mut words = line.strip_prefix("#!")?.split_whitespace();
    let executable = words.next()?;
    if executable == "/usr/bin/env" {
        words.next().map(str::to_string)
    } else {
        Some(executable.to_string())
    }
}

fn prepare_agent(override_path: Option<&Path>, work: &Path) -> Result<PathBuf, String> {
    if let Some(path) = override_path {
        return Ok(path.to_path_buf());
    }
    let directory = work.join("agent");
    std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
    for (name, contents) in [
        (
            "ipakeep_dump.py",
            include_str!("../../../scripts/frida/ipakeep_dump.py"),
        ),
        (
            "ipakeep_dump.js",
            include_str!("../../../scripts/frida/ipakeep_dump.js"),
        ),
        (
            "ipakeep_extensions.js",
            include_str!("../../../scripts/frida/ipakeep_extensions.js"),
        ),
    ] {
        std::fs::write(directory.join(name), contents).map_err(|error| error.to_string())?;
    }
    Ok(directory.join("ipakeep_dump.py"))
}

fn run_external(dumper: Dumper, bundle_id: &str, work: &Path) -> Result<Vec<u8>, String> {
    let (program, args) = external_argv(dumper, bundle_id, work)?;
    require_program(&program)?;
    let mut command = Command::new(&program);
    command.args(&args);
    run_inherit(command)?;

    let produced = newest_ipa(work)
        .ok_or_else(|| format!("{program} produced no .ipa in {}", work.display()))?;
    let bytes = std::fs::read(&produced).map_err(|e| format!("{}: {e}", produced.display()))?;
    ensure_decrypted(bytes)
}

const SSH_PASSWORD_ENV: &str = "IPAKEEP_SSH_PASSWORD";
const REMOTE_SCRIPT: &str = "/tmp/ipakeep_fouldecrypt.sh";
const REMOTE_OUT_IPA: &str = "/tmp/ipakeep-fouldecrypt.ipa";
/// sshd rate-limits rapid auth attempts; pause between connections.
const SSH_PAUSE: Duration = Duration::from_millis(1500);

/// Decrypt an installed app's Mach-O slices ON DISK with `FoulDecrypt` (no app
/// launch), repackage into an IPA on the device, pull it, and verify.
fn run_fouldecrypt(req: &DumpRequest, work: &Path) -> Result<Vec<u8>, String> {
    let password = std::env::var(SSH_PASSWORD_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let use_password = password.is_some();
    require_program("ssh")?;
    require_program("scp")?;
    if use_password {
        require_program("sshpass").map_err(|error| {
            format!("{error}; or unset {SSH_PASSWORD_ENV} to use key auth / prompting")
        })?;
    }

    let local_script = write_fouldecrypt_script(work)?;
    deploy_and_run_fouldecrypt(req, &local_script, password.as_deref(), use_password)?;

    let local_ipa = work.join("fouldecrypt.ipa");
    run_remote(
        scp_argv(
            req.ssh,
            use_password,
            &remote_spec(req.ssh, REMOTE_OUT_IPA),
            &local_ipa.to_string_lossy(),
        ),
        password.as_deref(),
    )?;
    let bytes = std::fs::read(&local_ipa).map_err(|error| {
        format!(
            "{}: {error} (FoulDecrypt produced no IPA; see the device-side output above)",
            local_ipa.display()
        )
    })?;
    ensure_decrypted(bytes)
}

fn write_fouldecrypt_script(work: &Path) -> Result<String, String> {
    let path = work.join("run.sh");
    std::fs::write(&path, include_str!("../../../scripts/fouldecrypt/run.sh"))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

fn deploy_and_run_fouldecrypt(
    req: &DumpRequest,
    local_script: &str,
    password: Option<&str>,
    use_password: bool,
) -> Result<(), String> {
    run_remote(
        scp_argv(
            req.ssh,
            use_password,
            local_script,
            &remote_spec(req.ssh, REMOTE_SCRIPT),
        ),
        password,
    )?;
    std::thread::sleep(SSH_PAUSE);
    run_remote(
        ssh_argv(
            req.ssh,
            use_password,
            &remote_command(REMOTE_SCRIPT, req.bundle_id, REMOTE_OUT_IPA),
        ),
        password,
    )?;
    std::thread::sleep(SSH_PAUSE);
    Ok(())
}

/// Run a prepared ssh/scp command, feeding the password through `SSHPASS` (never
/// on argv) when one is configured.
fn run_remote(
    (program, args): (String, Vec<String>),
    password: Option<&str>,
) -> Result<(), String> {
    let mut command = Command::new(&program);
    command.args(&args);
    if let Some(password) = password {
        command.env("SSHPASS", password);
    }
    // Do not use `run_inherit`: it Debug-formats the whole `Command`, which would
    // print the `SSHPASS` value. Report only the program name on failure.
    let status = observed_status(&mut command)
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

/// `user@host:path` spec for scp.
fn remote_spec(ssh: SshParams<'_>, path: &str) -> String {
    format!("{}@{}:{}", ssh.user, ssh.host, path)
}

/// The remote shell command that runs the device-side runner on `bundle_id`.
fn remote_command(script: &str, bundle_id: &str, out_ipa: &str) -> String {
    format!(
        "sh {} {} {}",
        shell_quote(script),
        shell_quote(bundle_id),
        shell_quote(out_ipa)
    )
}

/// POSIX single-quote a token so the remote shell treats it literally.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Shared ssh/scp hardening options. Pure for testing.
fn ssh_options(use_password: bool) -> Vec<String> {
    let mut options = vec![
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
    ];
    if use_password {
        options.extend([
            "-o".into(),
            "NumberOfPasswordPrompts=1".into(),
            "-o".into(),
            "PreferredAuthentications=password,keyboard-interactive".into(),
            "-o".into(),
            "PubkeyAuthentication=no".into(),
        ]);
    }
    options
}

/// Argv to run `remote_command` on the device over ssh. Pure for testing.
fn ssh_argv(ssh: SshParams<'_>, use_password: bool, remote_command: &str) -> (String, Vec<String>) {
    let (program, mut args) = sshpass_prefix(use_password, "ssh");
    args.extend(ssh_options(use_password));
    args.push("-p".into());
    args.push(ssh.port.to_string());
    args.push(format!("{}@{}", ssh.user, ssh.host));
    args.push(remote_command.to_string());
    (program, args)
}

/// Argv to copy `source` to `dest` with scp. Pure for testing.
fn scp_argv(
    ssh: SshParams<'_>,
    use_password: bool,
    source: &str,
    dest: &str,
) -> (String, Vec<String>) {
    let (program, mut args) = sshpass_prefix(use_password, "scp");
    args.extend(ssh_options(use_password));
    args.push("-P".into());
    args.push(ssh.port.to_string());
    args.push(source.to_string());
    args.push(dest.to_string());
    (program, args)
}

/// Pick the launcher: `sshpass -e <tool>` when a password is used (keeping it
/// off argv), otherwise the tool directly.
fn sshpass_prefix(use_password: bool, tool: &str) -> (String, Vec<String>) {
    if use_password {
        ("sshpass".into(), vec!["-e".into(), tool.into()])
    } else {
        (tool.into(), Vec::new())
    }
}

/// Argv for the builtin Python runner. Pure for testing.
#[derive(Clone, Copy)]
struct BuiltinArgv<'a> {
    python: &'a str,
    agent: &'a Path,
    bundle_id: &'a str,
    ipa: &'a Path,
    device: DumpDevice,
    out_dir: &'a Path,
    settle: f64,
    spawn: bool,
}

fn builtin_argv(request: BuiltinArgv<'_>) -> (String, Vec<String>) {
    let mut args = vec![
        request.agent.to_string_lossy().into_owned(),
        "--out".into(),
        request.out_dir.to_string_lossy().into_owned(),
        "--device".into(),
        request.device.as_arg().into(),
        "--ipa".into(),
        request.ipa.to_string_lossy().into_owned(),
        "--settle".into(),
        format!("{}", request.settle),
    ];
    if request.spawn {
        args.push("--spawn".into());
    }
    args.push(request.bundle_id.to_string());
    (request.python.into(), args)
}

/// Argv for an external dumper writing its decrypted IPA into `out_dir`.
///
/// These mirror each tool's common CLI; adjust if a tool version differs.
///
/// # Errors
///
/// Returns an error for the builtin variant (handled elsewhere).
pub(super) fn external_argv(
    dumper: Dumper,
    bundle_id: &str,
    out_dir: &Path,
) -> Result<(String, Vec<String>), String> {
    let dir = out_dir.to_string_lossy().into_owned();
    Ok(match dumper {
        Dumper::FridaIosDump => (
            "frida-ios-dump".into(),
            vec![
                "-o".into(),
                out_dir
                    .join("frida-ios-dump.ipa")
                    .to_string_lossy()
                    .into_owned(),
                bundle_id.to_string(),
            ],
        ),
        Dumper::Bagbak => (
            "bagbak".into(),
            vec!["--output".into(), dir, bundle_id.to_string()],
        ),
        Dumper::R2flutch => (
            "r2flutch".into(),
            vec!["-o".into(), dir, bundle_id.to_string()],
        ),
        Dumper::Builtin | Dumper::FoulDecrypt => {
            return Err("this dumper has no host-tool external argv".into());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_dumpers_and_rejects_unknown() {
        assert_eq!(Dumper::parse("builtin").unwrap(), Dumper::Builtin);
        assert_eq!(Dumper::parse("bagbak").unwrap(), Dumper::Bagbak);
        assert_eq!(Dumper::parse("fouldecrypt").unwrap(), Dumper::FoulDecrypt);
        assert!(Dumper::parse("nope").is_err());
    }

    const SSH: SshParams<'static> = SshParams {
        host: "127.0.0.1",
        port: 2222,
        user: "mobile",
    };

    #[test]
    fn ssh_argv_uses_ssh_directly_without_a_password() {
        let (program, args) = ssh_argv(SSH, false, "sh /tmp/run.sh 'com.x.App'");
        assert_eq!(program, "ssh");
        assert!(args.windows(2).any(|w| w == ["-p", "2222"]));
        assert_eq!(args[args.len() - 2], "mobile@127.0.0.1");
        assert_eq!(args.last().unwrap(), "sh /tmp/run.sh 'com.x.App'");
        assert!(!args.iter().any(|a| a == "PubkeyAuthentication=no"));
    }

    #[test]
    fn ssh_argv_wraps_sshpass_and_forces_password_auth() {
        let (program, args) = ssh_argv(SSH, true, "true");
        assert_eq!(program, "sshpass");
        assert_eq!(&args[0..2], ["-e", "ssh"]);
        assert!(args.iter().any(|a| a == "PubkeyAuthentication=no"));
        assert!(args.iter().any(|a| a == "NumberOfPasswordPrompts=1"));
        // The password itself never appears on argv.
        assert!(!args.iter().any(|a| a.contains("IPAKEEP") || a == "0000"));
    }

    #[test]
    fn scp_argv_threads_port_and_remote_spec() {
        let (program, args) = scp_argv(
            SSH,
            false,
            &remote_spec(SSH, "/tmp/out.ipa"),
            "/host/out.ipa",
        );
        assert_eq!(program, "scp");
        assert!(args.windows(2).any(|w| w == ["-P", "2222"]));
        assert_eq!(args[args.len() - 2], "mobile@127.0.0.1:/tmp/out.ipa");
        assert_eq!(args.last().unwrap(), "/host/out.ipa");
    }

    #[test]
    fn scp_argv_wraps_sshpass_when_a_password_is_used() {
        let (program, args) = scp_argv(SSH, true, "/host/run.sh", "mobile@127.0.0.1:/tmp/run.sh");
        assert_eq!(program, "sshpass");
        assert_eq!(&args[0..2], ["-e", "scp"]);
    }

    #[test]
    fn remote_command_single_quotes_each_token() {
        assert_eq!(
            remote_command("/tmp/run.sh", "com.x.App", "/tmp/out.ipa"),
            "sh '/tmp/run.sh' 'com.x.App' '/tmp/out.ipa'"
        );
        // Embedded quotes are escaped, not left to break out of the string.
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn builtin_argv_threads_device_settle_and_spawn() {
        let (program, args) = builtin_argv(BuiltinArgv {
            python: "python3.14",
            agent: Path::new("/x/ipakeep_dump.py"),
            bundle_id: "com.example.App",
            ipa: Path::new("/tmp/App.ipa"),
            device: DumpDevice::Local,
            out_dir: Path::new("/tmp/out"),
            settle: 7.5,
            spawn: true,
        });
        assert_eq!(program, "python3.14");
        assert_eq!(args[0], "/x/ipakeep_dump.py");
        assert!(args.windows(2).any(|w| w == ["--device", "local"]));
        assert!(args.windows(2).any(|w| w == ["--ipa", "/tmp/App.ipa"]));
        assert!(args.windows(2).any(|w| w == ["--settle", "7.5"]));
        assert!(args.contains(&"--spawn".to_string()));
        assert_eq!(args.last().unwrap(), "com.example.App");
    }

    #[test]
    fn reads_python_from_frida_tools_shebang() {
        assert_eq!(
            interpreter_from_shebang("#!/opt/homebrew/bin/python3.14"),
            Some("/opt/homebrew/bin/python3.14".into())
        );
        assert_eq!(
            interpreter_from_shebang("#!/usr/bin/env python3.14"),
            Some("python3.14".into())
        );
    }

    #[test]
    fn override_python_is_tried_first_and_duplicates_are_dropped() {
        let launchers = vec!["/opt/a/python3.13".to_string(), "python3".to_string()];
        assert_eq!(
            python_candidates(Some("/venv/bin/python".into()), &launchers),
            ["/venv/bin/python", "python3", "/opt/a/python3.13"]
        );
        assert_eq!(python_candidates(None, &[]), ["python3"]);
    }

    #[test]
    fn every_frida_launcher_on_path_contributes_its_interpreter() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(
            first.path().join("frida-ps"),
            "#!/opt/first/bin/python3\nimport frida\n",
        )
        .unwrap();
        std::fs::write(
            second.path().join("frida-ps"),
            "#!/usr/bin/env python3.14\n",
        )
        .unwrap();
        std::fs::write(second.path().join("frida"), "#!/opt/second/python\n").unwrap();
        let path = std::env::join_paths([first.path(), second.path()]).unwrap();

        assert_eq!(
            launcher_interpreters(Some(&path)),
            ["/opt/first/bin/python3", "python3.14", "/opt/second/python"]
        );
        assert!(launcher_interpreters(None).is_empty());
    }

    #[test]
    fn external_argv_per_backend() {
        let dir = Path::new("/tmp/d");
        let (p, a) = external_argv(Dumper::Bagbak, "com.x.App", dir).unwrap();
        assert_eq!(p, "bagbak");
        assert!(a.windows(2).any(|w| w == ["--output", "/tmp/d"]));
        assert_eq!(a.last().unwrap(), "com.x.App");

        let (p, a) = external_argv(Dumper::FridaIosDump, "com.x.App", dir).unwrap();
        assert_eq!(p, "frida-ios-dump");
        assert!(a.iter().any(|s| s.ends_with("frida-ios-dump.ipa")));

        assert!(external_argv(Dumper::Builtin, "com.x.App", dir).is_err());
    }
}
