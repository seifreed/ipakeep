# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
cargo build                              # Build the project
cargo test                                # Run all unit tests (24 currently)
cargo test <module_path>                  # Run a specific test module, e.g. cargo test domain::usecase::auth_login
cargo test <test_name>                    # Run a single test by name
cargo clippy --all-targets -- -D warnings # Lint (must pass clean)
cargo fmt                                 # Auto-format code
cargo fmt --check                         # Check formatting without modifying
cargo run -- auth info                     # Run CLI commands
```

## Mandatory CI Gates

These gates are part of the regression contract — every change must pass them locally before review:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo deny check`
- `cargo audit`

Bypassing a lint with an inline `#[allow(...)]` attribute is **forbidden** — including `#[allow(dead_code)]` and `#[allow(unused)]`. Fix the underlying issue (delete the dead code, wire up the unused item, or use `?`/`unwrap_or` instead of suppressing). An inline suppression is only acceptable if explicitly justified in an adjacent comment and reviewed. The same rule applies to `#[cfg(test)]`-only relaxations leaking into production modules.

**Crate-level allows** (the `[lints.clippy]` block in `Cargo.toml`) are a separate, deliberately small policy list — not a place to silence inconvenient lints. The only sanctioned entries are `module_name_repetitions`, `must_use_candidate`, and `struct_excessive_bools`. Adding any new crate-level `allow` requires a one-line `# justification:` comment next to it in `Cargo.toml` and review; never add one to make a failing `cargo clippy` pass instead of fixing the code. `dead_code` and `unused*` must never appear in this block.

## Architecture: Clean Architecture

Dependency rule: inner layers never depend on outer layers.

```
domain/          → Zero external deps. Entities, repository traits (ports), use cases, error types.
infrastructure/  → Depends on domain only. HTTP client, plist codec, App Store API impl, file keychain.
presentation/    → Depends on domain + infrastructure. Clap CLI commands, output formatting.
main.rs          → Wires concrete infrastructure types into presentation handlers.
```

**Forbidden imports:**
- `domain/` must not import from `infrastructure/` or `presentation/`
- `domain/entity/` must not import from `domain/repository/` or `domain/usecase/`
- `infrastructure/` must not import from `presentation/`

## Key Conventions

- Rust edition 2024, async runtime: tokio
- Lint config: `unsafe_code = forbid`, `missing_docs = warn`, clippy `all = deny`, `pedantic = warn`
- Clippy allows: `module_name_repetitions`, `must_use_candidate`, `struct_excessive_bools`
- Error handling: `thiserror` for domain errors, never `unwrap()`/`panic!()` in prod code
- Mock naming: `AppStoreRepo`/`CredentialRepo` in `mock!` blocks (mockall adds `Mock` prefix → `MockAppStoreRepo`)
- All domain entities need `Serialize`/`Deserialize` derives
- Repository traits use `#[async_trait]`
- Use cases receive repository traits via generic parameters, not concrete types
- `# Errors` doc section required on all `Result`-returning public functions (clippy enforces this)
- Public `get_guid()` lives in `presentation/cli/commands/mod.rs`; `auth.rs` has a private copy

## Apple App Store Protocol

- Auth: `GET bag.xml?guid=<MAC>` → discover endpoint → `POST authenticate` with form data (handles 2FA, -5000 retry)
- Search: `GET itunes.apple.com/search` (public, no auth)
- Purchase: `POST buyProduct` with plist body + auth headers (X-Dsid, X-Token, X-Apple-Store-Front)
- Download: `POST volumeStoreDownloadProduct` with plist body → returns URL + sinfs + metadata
- IPA patching: inject iTunesMetadata.plist + replicate sinf into `SC_Info/`
- Credential storage: `~/.ipakeep/auth.json` (FileKeychain)

## Clean Code Requirements

All new code must follow these principles. Violations are caught in review.

- **Zero `unwrap()`/`expect()`/`panic!()` in production code.** Use `?`, `unwrap_or`, `unwrap_or_default`, `ok_or_else`, or `let...else`. Test code may use `unwrap()`.
- **No dead code, unused imports, or commented-out blocks.** If code is no longer needed, delete it — git preserves history. Do not add `#[allow(dead_code)]`/`#[allow(unused)]` to silence it (see *Mandatory CI Gates*). Do not leave `// TODO: remove` placeholders without an owner and a date.
- **No magic numbers.** Configuration limits, retry counts, error codes (e.g. the App Store `-5000` retry, `2FA` flow constants) use named constants in the relevant module.
- **Function size: target <80 lines.** Beyond that requires justification; split via extracted helpers or a dispatcher `match`. Exhaustive dispatch tables over a closed enum may exceed the limit when the body carries no domain logic.
- **Nesting depth: max 4 levels.** Flatten deeper `match`/`if`/`for` with early returns, `let...else`, or extracted helpers.
- **Named imports only** in production modules. Glob imports (`use ...::*`) are allowed only in `mod.rs` re-export blocks and `#[cfg(test)]` modules.
- **Immutability by default.** Prefer `&T` over `&mut T`. Avoid `.clone()` outside ownership-transfer boundaries; if you reach for `clone()` on a hot path (download streaming, plist/IPA processing), justify it in review.
- **DRY with a brake.** Three similar lines are better than a premature abstraction. Extract a helper or trait only when the third or fourth occurrence proves the shape.
- **Touch only what you must.** A focused change must not bundle drive-by refactors of unrelated code. Cleaning up mess *introduced by the current change* is expected; leave a note or follow-up for incidental mess nearby.

## Regression Policy

Every fix that changes auth, App Store protocol, plist codec, download, or IPA-patching behavior must leave a durable regression artifact (a focused unit/integration test or a fixture-backed golden expectation).

Required workflow:

1. Reproduce the issue with a minimal case.
2. Add or tighten the regression test **first** (it should fail).
3. Implement the change.
4. Run the relevant module tests while iterating.
5. Run the full gate suite (see *Mandatory CI Gates*) before calling the work complete.
6. If behavior intentionally changes, update the matching expectation in the same change.

## Performance

Measure before refactoring for performance. Drive-by `.clone()` removals, hash/codec swaps, or "this looks expensive" rewrites without a profile are forbidden. Establish a baseline (a timed `cargo run` against a representative IPA, or `cargo bench` if a bench exists) and record the before/after delta before claiming an improvement.

## SBOM & Supply Chain

- `cargo deny check` and `cargo audit` are mandatory gates (advisories, license policy, banned/duplicate deps).
- Generate a CycloneDX SBOM from the workspace lockfile for supply-chain review (`syft .` or `cargo cyclonedx`), writing transient output under `target/` — do not commit generated SBOM churn alongside unrelated code changes.
- New dependencies must be justified; prefer the existing crate set over adding new transitive surface.

## Testing Strategy & Discipline

- Unit tests: inline `#[cfg(test)]` modules with `mockall` mock repositories.
- Infrastructure tests: real filesystem with `tempfile` (e.g., FileKeychain).
- HTTP tests: `wiremock` against real client code — do not mock crate-internal collaboration; reserve test doubles for the OS/FFI/network boundary.
- CLI integration tests: `assert_cmd` + `predicates` (dev-deps present, tests not yet written).
- The `tests/` directory has placeholder structure but is empty — integration tests are a known gap.
- **Naming:** `test_<subject>_<scenario>_<expected_outcome>`. Avoid `test_works`, `test_basic`, `test_1`.
- **Single logical assertion per test** — a test should fail for one reason. Split multi-invariant scenarios across tests.
- Default suites must not depend on real Apple credentials or live network; any live-network regression must be explicitly opt-in (env-gated) and excluded from the default run.
- Every PR must include regression tests for the changed behavior.

## Observability

- Use `tracing`, not `println!`/`eprintln!`/`dbg!`, on production code paths. (`indicatif` progress bars and intentional CLI stdout output are the exception.)
- Levels: `error` for contract violations, `warn` for recoverable anomalies, `info` for lifecycle events, `debug` for per-event detail, `trace` for hot loops.
- Never log raw credentials, tokens, `X-Token`/`X-Dsid` headers, or full payloads above `debug` — prefer hashes, sizes, and short previews.

## Evolution Policy

- **No legacy compatibility for project-owned features.** When a new feature, CLI flag, or internal API replaces an older one, remove the obsolete implementation, docs, tests, fixtures, and fallback paths in the same change. Compatibility work is only valid when modeling external contracts the tool must support (Apple App Store protocol, plist/IPA formats, OS APIs).

## Incomplete Features (TODOs in code)

- Download handler: actual file download, IPA patching (sinf injection, iTunesMetadata.plist), saving to output path
- Auth handler: interactive 2FA flow, interactive email/password prompts
- `Sinf` and `DownloadItem` entities are missing `Serialize`/`Deserialize` derives (violates convention)