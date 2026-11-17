//! Frozen Unicorn oracle for the native differential tests.
//!
//! Every differential case (code words + initial state, see [`super::diff`])
//! was run once on the deprecated Unicorn backend and its final architectural
//! state recorded under `tests/fixtures/native_oracle/`, one `.oracle` file per
//! test source file below `native/` (`coverage_tests/diff_int.rs` becomes
//! `coverage_tests__diff_int.oracle`). The tests compare the native
//! interpreter against that frozen data, so they need no Unicorn at test time
//! and run in the default build.
//!
//! A fixture line is `<case key> => <expected state>`; `#` lines are comments
//! (a `# <test name>` line opens the cases first recorded by that test). The
//! line format is owned by [`super::diff`]; this module only stores and looks
//! up `key -> value` strings, so other harnesses (e.g. block-cache tests) can
//! freeze their own cases with the same tool.
//!
//! # Regenerating
//!
//! First produced on 2026-11-17 from unicorn-engine 2.1.5 (the version is also
//! stamped in each fixture header, read from `Cargo.lock`). With the `unicorn`
//! feature, run the regenerator by its exact name:
//!
//! ```text
//! cargo test --lib --all-features --locked -- --ignored --exact \
//!     infrastructure::apple_sap::emu::native::frozen::freeze_native_oracle
//! ```
//!
//! It re-runs this test binary filtered to the native tests with
//! [`RECORD_ENV`] set: every `diff::check` then runs on Unicorn too, asserts
//! native == Unicorn and logs Unicorn's state. The regenerator collates the log
//! and rewrites every `.oracle` file. A case added to any test under `native/`
//! is frozen by the same command.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Directory holding the frozen fixture files.
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/native_oracle");

/// Separates a case key from its expected value in a fixture line.
const SEPARATOR: &str = " => ";

/// Fixture file (relative to [`FIXTURE_DIR`]) for a test source file path as
/// reported by [`std::panic::Location::file`].
pub(super) fn fixture_name(source: &str) -> String {
    let source = source.replace('\\', "/");
    let relative = source
        .rsplit_once("/native/")
        .map_or(source.as_str(), |(_, r)| r);
    let stem = relative.strip_suffix(".rs").unwrap_or(relative);
    format!("{}.oracle", stem.replace('/', "__"))
}

/// Parses a fixture file's text into its `key -> value` map.
fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line
                .split_once(SEPARATOR)
                .unwrap_or_else(|| panic!("malformed oracle line: {line}"));
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

/// The frozen value of `key` in fixture `fixture`, if it was recorded.
pub(super) fn lookup(fixture: &str, key: &str) -> Option<String> {
    type Cache = Mutex<HashMap<String, Arc<HashMap<String, String>>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let table = {
        let mut cache = CACHE.get_or_init(Cache::default).lock().unwrap();
        Arc::clone(cache.entry(fixture.to_owned()).or_insert_with(|| {
            let path = format!("{FIXTURE_DIR}/{fixture}");
            Arc::new(std::fs::read_to_string(path).map_or_else(|_| HashMap::new(), |t| parse(&t)))
        }))
    };
    table.get(key).cloned()
}

/// Panics with the regeneration hint for a case missing from its fixture.
#[track_caller]
pub(super) fn missing(fixture: &str, key: &str) -> ! {
    panic!(
        "case not frozen in tests/fixtures/native_oracle/{fixture}: `{key}`; \
         regenerate with the `unicorn` feature (see native/frozen.rs)"
    )
}

/// Environment variable naming the log file the recording run appends to.
#[cfg(feature = "unicorn")]
const RECORD_ENV: &str = "IPAKEEP_NATIVE_ORACLE_LOG";

/// Whether this process is the regenerator's recording run.
#[cfg(feature = "unicorn")]
pub(super) fn recording() -> bool {
    std::env::var_os(RECORD_ENV).is_some()
}

/// Appends one Unicorn result to the recording log (no-op unless recording).
#[cfg(feature = "unicorn")]
pub(super) fn record(fixture: &str, key: &str, value: &str) {
    use std::io::Write;

    static LOCK: Mutex<()> = Mutex::new(());
    let Some(path) = std::env::var_os(RECORD_ENV) else {
        return;
    };
    let test = std::thread::current().name().unwrap_or("?").to_owned();
    let line = format!("{fixture}\t{test}\t{key}\t{value}\n");
    let _guard = LOCK.lock().unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .expect("append to the oracle log");
}

/// Collates a recording log into fixture file contents: per fixture, cases are
/// grouped under their test (tests sorted by name, cases in call order) and a
/// key already emitted is skipped, so the output is deterministic whatever the
/// thread schedule. A key recorded with two different values panics.
#[cfg(feature = "unicorn")]
fn collate(log: &str, header: &str) -> std::collections::BTreeMap<String, String> {
    use std::collections::BTreeMap;
    use std::fmt::Write;

    /// fixture -> test -> `(key, value)` in call order.
    type Grouped<'a> = BTreeMap<&'a str, BTreeMap<&'a str, Vec<(&'a str, &'a str)>>>;
    let mut grouped = Grouped::new();
    for line in log.lines() {
        let mut fields = line.splitn(4, '\t');
        let (Some(fixture), Some(test), Some(key), Some(value)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed oracle log line: {line}");
        };
        grouped
            .entry(fixture)
            .or_default()
            .entry(test)
            .or_default()
            .push((key, value));
    }
    grouped
        .into_iter()
        .map(|(fixture, tests)| {
            let source = fixture.trim_end_matches(".oracle").replace("__", "/");
            let mut text = header.replace("{fixture}", &format!("{source}.rs"));
            let mut emitted: HashMap<&str, &str> = HashMap::new();
            for (test, cases) in tests {
                let mut section = String::new();
                for (key, value) in cases {
                    if let Some(previous) = emitted.insert(key, value) {
                        assert_eq!(previous, value, "nondeterministic oracle for `{key}`");
                        continue;
                    }
                    writeln!(section, "{key}{SEPARATOR}{value}").unwrap();
                }
                if !section.is_empty() {
                    write!(text, "\n# {test}\n{section}").unwrap();
                }
            }
            (fixture.to_owned(), text)
        })
        .collect()
}

/// The `unicorn-engine` version pinned in `Cargo.lock`.
#[cfg(feature = "unicorn")]
fn unicorn_version() -> String {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("read Cargo.lock");
    lock.split("[[package]]")
        .find(|package| package.contains("name = \"unicorn-engine\"\n"))
        .and_then(|package| {
            package
                .lines()
                .find_map(|line| line.strip_prefix("version = \""))
                .map(|v| v.trim_end_matches('"').to_owned())
        })
        .expect("unicorn-engine in Cargo.lock")
}

/// Regenerator: records every native differential case on Unicorn and
/// rewrites `tests/fixtures/native_oracle/`. Run it by exact name (see the
/// module docs); it never runs other ignored tests.
#[cfg(feature = "unicorn")]
#[test]
#[ignore = "regenerates the frozen Unicorn oracle; run by exact name"]
fn freeze_native_oracle() {
    let log =
        std::env::temp_dir().join(format!("ipakeep-native-oracle-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("apple_sap::emu::native::")
        .env(RECORD_ENV, &log)
        .output()
        .expect("spawn the recording run");
    assert!(
        output.status.success(),
        "recording run failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&log).expect("read the oracle log");
    let _ = std::fs::remove_file(&log);
    let header = format!(
        "# Frozen Unicorn oracle for native/{{fixture}}; format: native/frozen.rs.\n\
         # Recorded from unicorn-engine {} by\n\
         # cargo test --lib --all-features --locked -- --ignored --exact \
         infrastructure::apple_sap::emu::native::frozen::freeze_native_oracle\n",
        unicorn_version()
    );
    let fixtures = collate(&text, &header);
    std::fs::create_dir_all(FIXTURE_DIR).expect("create the fixture directory");
    for entry in std::fs::read_dir(FIXTURE_DIR).expect("list fixtures") {
        let path = entry.expect("fixture entry").path();
        if path.extension().is_some_and(|ext| ext == "oracle") {
            std::fs::remove_file(path).expect("remove a stale fixture");
        }
    }
    for (fixture, contents) in &fixtures {
        std::fs::write(format!("{FIXTURE_DIR}/{fixture}"), contents).expect("write a fixture");
    }
    let cases: usize = fixtures.values().map(|c| parse(c).len()).sum();
    println!("froze {cases} cases into {} fixtures", fixtures.len());
}

#[test]
fn fixture_names_follow_the_source_path() {
    assert_eq!(
        fixture_name("src/infrastructure/apple_sap/emu/native/simd.rs"),
        "simd.oracle"
    );
    assert_eq!(
        fixture_name("src\\infrastructure\\apple_sap\\emu\\native\\coverage_tests\\diff_int.rs"),
        "coverage_tests__diff_int.oracle"
    );
}
