//! Frozen Unicorn oracle for the native differential tests.
//!
//! Every differential case (code words + initial state, see [`super::diff`],
//! and the block-cache whole programs in `block_tests.rs`) was run once on the
//! Unicorn engine and its final architectural state recorded under
//! `tests/fixtures/native_oracle/`, one `.oracle` file per test source file
//! below `native/` (`coverage_tests/diff_int.rs` becomes
//! `coverage_tests__diff_int.oracle`). The tests compare the native
//! interpreter against that frozen data; ipakeep no longer depends on Unicorn.
//!
//! A fixture line is `<case key> => <expected state>`; `#` lines are comments
//! (a `# <test name>` line opens the cases first recorded by that test). The
//! value format is owned by the harness that wrote it; this module only looks
//! up `key -> value` strings.
//!
//! # Provenance
//!
//! Recorded on 2026-11-17 from unicorn-engine 2.1.5 by the regenerator
//! `native::frozen::freeze_native_oracle` of commit `d7688c5` ("test(emu):
//! freeze the Unicorn differential oracle as fixtures"), the last revision with
//! the `unicorn` feature:
//!
//! ```text
//! cargo test --lib --all-features --locked -- --ignored --exact \
//!     infrastructure::apple_sap::emu::native::frozen::freeze_native_oracle
//! ```
//!
//! A case whose key is not in its fixture fails as "not frozen". New
//! differential cases need that revision (or another trusted A64 reference) to
//! be frozen; otherwise assert hand-derived expected values instead.

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
        "case not frozen in tests/fixtures/native_oracle/{fixture}: `{key}` \
         (see native/frozen.rs)"
    )
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
