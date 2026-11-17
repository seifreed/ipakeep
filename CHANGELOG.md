# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump
may contain breaking changes).

## [0.2.0] - 2026-11-17

ipakeep 0.2.0 runs the whole Apple Store authentication and commerce stack
in-process on its own code. Apple's own SAP, ADI and kbsync binaries execute on
a built-in Rust ARM64 interpreter. There is no Go helper, no Unicorn, no C
toolchain and no remote anisette server, and binaries are MIT-licensed.

### Breaking changes

- **Rust 1.100 is now required.** The pinned toolchain is 1.100.0
  (`rust-toolchain.toml`) and the MSRV is `rust-version = "1.100"`.
- **The Unicorn engine is gone.** The `unicorn` and `native-cpu` Cargo features
  no longer exist and the crate has no features at all. The native interpreter
  is the only ARM64 engine.
- **Store sign-in and commerce run on the native SAP stack.** The Go helper and
  the legacy Store paths are removed.
- **HTTP uses `rustls` with `ring`** instead of `native-tls`.
- **Library API:** the emulator error variants that only the Unicorn backend
  could raise (`InvalidTimeout`, `GuardAlreadyInstalled`, `MemoryRejected`, and
  the unused `EngineErrorCode` values) are removed.

### Added

- **Native ARM64 emulation engine** (`apple_sap::emu::native`). An A64
  interpreter in safe Rust with no `unsafe` code. It covers integer, load/store,
  branch and the NEON/FP subset Apple's white-box code uses. Execution goes
  through pre-decoded basic blocks with chaining, a direct-mapped software TLB,
  per-block hook checks, and invalidation of self-modifying code.
- **Native port of the Apple SAP stack:**
  - The pinned macOS 27.0.1 restore image is read over HTTP byte ranges.
  - Assets are extracted through AEA1 decryption, APFS with decmpfs (LZVN,
    LZFSE, LZBITMAP), dyld shared-cache export and kernel-collection export.
  - Mach-O arm64e preparation and roughly 200 platform shims.
  - SAP, ADI (anisette and Store AMD), StoreAgent and kbsync machines.
- **Native Store client:** sign-in with trusted-device 2FA, the URL bag, free-app
  purchase (`buyProduct`), download tickets, version listing, purchase history
  (`purchases`), storefront mapping and a kbsync cache.
- **Decryption:**
  - `decrypt offline` decrypts FairPlay IPAs natively in Rust.
  - Frida-based `decrypt dump`, which starts app extensions, follows extension
    processes, can optionally drop extensions that cannot be dumped, and pulls
    the installed bundle when `--ipa` is omitted.
  - A static FoulDecrypt backend.
- **Device install:**
  - `device install-ipa` installs on iOS devices through `devicectl`, or through
    libimobiledevice for iOS 16.
  - **Experimental:** `--native` installs in-process over usbmuxd, lockdownd
    with TLS, AFC and `installation_proxy`, without libimobiledevice. It is
    tested against a simulated device only.
- **MCP server:** `mcp` serves stdio MCP tools, including purchases.
- **Observability:**
  - Configurable CLI tracing.
  - Secret-free structured events for HTTP traffic, subprocesses, the Frida
    runner, credential storage, retries and panics.

### Changed

- **Performance of the native engine:** the block cache and software TLB cut
  the CPU time of kbsync generation by about 2.5×. See the README for measured
  numbers.
- **CI:**
  - Every job builds without a C toolchain.
  - Coverage uses tarpaulin's LLVM engine on every OS, with 100% line coverage
    enforced.
  - CodeQL analysis is added, and a signed CycloneDX SBOM is published.

### Removed

- The Go helper and its dependencies.
- The Unicorn backend, the CMake/libclang build requirements and the GPL-2.0
  exception in `deny.toml`.
- `scripts/deplatform/`, a retired C research tool for AMFI de-platforming.

### Fixed

- **kbsync on the native engine:**
  - `CASAL` was decoded as `LDAXP`.
  - The SIMD permutes (`UZP`, `ZIP`, `TRN`) were run as `TBL`.
- **Native decoder:** it now rejects reserved and unmodelled encodings instead
  of executing a neighbouring instruction. That covers `EXT`, `INS (element)`,
  `FRECPE`/`FRSQRTE`, reserved element sizes and `ADDV` with `U=1`. An
  `llvm-mc`-derived decode oracle guards these cases.
- **Native engine:** a hook fault no longer leaks into the next run.
- **Flaky tests:** log-capture tests no longer fail when a timestamp or port
  happens to contain the test's fake secret.
- **Windows:** the unreadable-file tests are now portable.

### Verification

- 13 golden tests run Apple's real binaries and reproduce, byte for byte, the
  outputs recorded from upstream ipatool.
- 1,489 frozen differential cases come from Unicorn 2.1.5 (see
  `tests/fixtures/native_oracle/`).

## [0.1.1] - 2026-06-30

- Fix `cargo install`.

[0.2.0]: https://github.com/seifreed/ipakeep/compare/16a357e...v0.2.0
[0.1.1]: https://github.com/seifreed/ipakeep/commit/16a357e
