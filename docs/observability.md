# Logging and observability

## Initial audit

Audit date: 2026-11-13. Repository baseline: `a583bcb`.

ipakeep is a Rust 2024 CLI and library. The binary starts a Tokio multi-thread
runtime in `src/main.rs`, parses commands with Clap, initializes a
`tracing-subscriber`, wires repositories, then dispatches to CLI handlers. The
library is also usable without the binary; as expected, the library does not
install a global subscriber.

The runtime mixes asynchronous App Store/GrandSlam HTTP with synchronous IPA
and Mach-O file processing, native keychain and Apple framework calls, and
external tools such as Docker, `codesign`, `xcrun`, Frida, and
`ideviceinstaller`. macOS keychain/native ADI calls use `spawn_blocking`; the
cross-platform Anisette provider may launch a local Docker container. Account
credentials are stored in macOS Keychain or a permission-restricted file. There
is no database, message queue, scheduler, or long-lived service process.

Errors are generally returned as typed `Result`s. The binary prints terminal
errors to stderr; command handlers print user-facing results to stdout. Those
`println!` calls are CLI output, not diagnostic logging, and should remain on
the output stream. The CLI's JSON result format also uses stdout.

### Existing implementation and evidence

- `Cargo.toml` already depends on `tracing` and `tracing-subscriber` with
  `env-filter`; it has no logging adapter, JSON formatter, metrics, or tracing
  exporter.
- `src/main.rs::init_logging` installs a global text formatter. `RUST_LOG`
  overrides the `warn` default; `--verbose` changes the fallback to `debug`.
  Logs go to the formatter's default stderr writer. An invalid `RUST_LOG`
  silently falls back, and `.init()` assumes no other subscriber was installed.
- Structured tracing fields exist, but they are emitted in the default text
  format. There is no normalized service/environment/event schema, operation
  span, duration, outcome, request/correlation ID, or trace propagation.
- Most existing events are `DEBUG` statements in domain use cases
  (`auth_login`, `search`, `purchase`, `download`, `list_versions`,
  `auth_info`, and `auth_revoke`). A few presentation/infrastructure modules
  also emit debug or warning events. External HTTP calls, storage, most file
  operations, subprocesses, and the CLI command boundary have no consistent
  events for duration, result, or failure.
- Several existing fields deliberately record only lengths/presence for
  credentials and search input. `auth_login` tests assert that the password,
  token, and email are absent from captured logs. No request bodies, auth
  headers, cookies, or account tokens are intentionally logged. There is no
  centralized redaction guard, however, and raw error text is printed by the
  binary, so errors from lower layers need a privacy review before they are
  copied into structured events.
- `src/domain/usecase/log_capture.rs` provides a concurrency-serialized test
  capture. Existing tests cover selected login/download log content and the
  `--verbose` default-level mapping, but not format/configuration, command
  outcomes, duration, redaction, HTTP metadata, or destination failures.

### Initial scores

Every requested dimension applies. The absence of a database, queue, scheduler,
and distributed server means those specific instruments are not applicable; it
does not exclude any scoring dimension.

| Dimension | Score | Evidence and reason |
|---|---:|---|
| Architecture and decoupling | 4/10 | Subscriber setup is in `main.rs`, while tracing calls sit in `domain/usecase`; logging is not behind a presentation/infrastructure boundary. |
| Functional coverage | 3/10 | Selected use cases have debug events; HTTP, keychain, file, subprocess, startup, and command completion paths lack consistent instrumentation. |
| Event quality and utility | 4/10 | Some events have safe counts/presence fields, but few outcomes or errors and no durations/status on I/O. |
| Structured logging and consistency | 5/10 | `tracing` fields are structured in code, but only text output is configured and event names/fields vary. |
| Context and correlation | 2/10 | No spans or correlation identifiers link command, async work, and external calls. A CLI operation still benefits from a parent span. |
| Security and privacy | 7/10 | Existing auth tests protect several secrets and code avoids logging bodies/headers, but there is no central sensitive-field policy and raw errors reach stderr. |
| Performance and resilience | 6/10 | Default `warn` avoids routine noise and synchronous stderr is reasonable for a short CLI, but initialization assumes a single subscriber and output failure/flush behavior is untested. |
| Configuration and portability | 5/10 | `RUST_LOG` and `--verbose` work across platforms, but format and destination are not configurable and invalid filters are not reported. |
| Error handling | 4/10 | Errors are returned to users, but the command boundary emits no structured failure event and many I/O boundaries lack consistent diagnostic context. |
| Testing and verifiability | 4/10 | A useful in-memory capture and secret assertions exist, but configuration, schemas, redaction, correlation, concurrency, and failure handling are not tested. |
| **Initial overall** | **4.4/10** | Arithmetic mean of the ten dimension scores. |

## Target design

Keep `tracing` and `tracing-subscriber` as the ecosystem-standard foundation.
Initialize the subscriber at the binary composition root, keep diagnostic
output on stderr, and add an optional JSON formatter for machine collection.
Use `RUST_LOG` for level/filter selection and a small `IPAKEEP_LOG_FORMAT`
setting for `text` or `json`. Do not add a mandatory collector, file logger,
metrics exporter, or OpenTelemetry dependency to this short-lived CLI.

Instrument the CLI operation boundary and infrastructure I/O boundaries.
Treat the command span as the correlation context for all work awaited by that
command. Do not invent W3C trace IDs: there is no inbound distributed trace
context or service-to-service hop in the current architecture. Add explicit
timing/outcome events around external operations without recording full URLs,
request/response bodies, auth headers, cookies, credential values, or raw
untrusted input. Keep stdout exclusively for command results.

## Event conventions

- Event fields use `snake_case`; event names/messages describe an operation and
  outcome, not a sentence assembled from user input.
- Use `INFO` for command/operation start and completion, `WARN` for recoverable
  fallbacks, `ERROR` for failed command or external operation, `DEBUG` for
  safe request metadata and detailed state transitions, and `TRACE` only for
  high-volume detail that can help diagnose a specific path.
- Include `service="ipakeep"`, `component`, `operation`, `outcome`, and
  `duration_ms` where applicable. Use status code and hostname for HTTP calls;
  never record query strings or arbitrary URLs.
- Do not attach email, password, 2FA code, token, cookie, private key, full
  file contents, full response bodies, or arbitrary subprocess output to
  tracing events. Show user-actionable error text on stderr separately.

## Progress

### Milestone 1 — centralized CLI logging

The binary now uses `infrastructure::observability` for a single subscriber.
It supports text or JSON stderr output (`IPAKEEP_LOG_FORMAT`), `RUST_LOG`
filter directives, `--verbose` as the default-level override, and a sanitized
`IPAKEEP_ENV` span field. Each command has a named root span and records
start/completion, outcome, and elapsed milliseconds; command errors are
recorded without copying arbitrary error strings into logs. JSON logs stay on
stderr, separate from command JSON on stdout.

Validation at this milestone: 268 tests pass, 1 ignored; `cargo check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` pass.
The initial score remains 4.4/10 until coverage and architecture work is
complete.

This remaining-work list was the snapshot at milestone 1; later milestones
below record its completion and follow-up validation.

### Milestone 2 — domain boundary and outbound HTTP

Removed direct `tracing` calls from `domain/usecase`; the use cases now depend
only on their repository ports. Moved the in-memory capture utility to the
test-only infrastructure observability module. All outbound `reqwest` sends
now pass through one infrastructure helper that records method, hostname,
HTTP status, outcome, and duration. It classifies transport errors without
recording their text and never records URL paths/queries, headers, or bodies.

Validation at this milestone: 267 tests pass, 1 ignored; `cargo check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` pass. Two
HTTP telemetry tests cover secret omission and overlapping async requests.
The initial score remains 4.4/10 pending the remaining I/O boundaries, security
review, and integration-level logger tests.

### Milestone 3 — safer authentication and simulator events

The trusted-phone fallback now reports a stable error category instead of the
error's free-form text, which can contain a URL or server-provided detail.
Simulator debug events identify the operation and conversion count without
recording user file paths. A regression unit test checks that classifying a
network error does not return its embedded content.

### Milestone 4 — credential storage and JSON verification

File and macOS Keychain success events now cover save, load, not-found, and
delete operations with backend, outcome, and duration fields; account names,
tokens, and storage paths are excluded. Tests assert the file backend's events
do not contain account data and parse an actual HTTP JSON event to verify its
normalized level, event name, method, status, and duration fields.

### Milestone 5 — shared external process events

The common synchronous process runners and Simulator command adapters now emit
completion or spawn-failure events with the executable basename, exit code,
outcome, and duration. Arguments, environment, stdin/stdout, stderr, and full
executable paths are excluded. A regression test runs a failing child process
whose arguments and output contain a sentinel and verifies neither is logged.

### Milestone 6 — direct host tools and Docker commands

Direct host process calls for signing, entitlement inspection, Frida discovery,
Apple device metadata, and the non-macOS Docker lifecycle now use the same
process event path. A Linux target check was attempted, but this Mac lacks a
cross-target OpenSSL installation required by `openssl-sys`; therefore the
non-macOS module could not be fully type-checked here. Native macOS tests and
build remain the validation for this milestone.

### Milestone 7 — full HTTP response reads

HTTP telemetry now distinguishes response-header latency from response-body
consumption. JSON/plist/text responses and binary downloads use safe body-read
events with status, duration, outcome, and byte count when available; body
content remains excluded. This makes IPA transfer time observable beyond the
initial response headers.

### Milestone 8 — network error privacy

Transport and response-read errors have their request URL removed before they
reach callers. HTTP status and decoder errors remain available, but arbitrary
response bodies and GrandSlam server text are no longer copied into diagnostic
errors. Tests verify signed query values and response body sentinels stay out of
logs and error text.

### Milestone 9 — retries and panic boundary

Apple login retries and App Store pod retries emit safe retry events with
attempt count, reason, and configured delay. Ordinary 4xx responses log at
DEBUG; 408, 429, and server errors remain WARN. The CLI panic hook emits a
CRITICAL-equivalent `ERROR` event with source basename and line, never the panic
payload.

### Milestone 10 — normalized events and artifact privacy

Legacy GrandSlam, App Store, CLI resolution, process, and simulator events now
use the shared service/component/operation/event naming convention. SPD schema
keys are no longer logged. Download progress and JSON results no longer expose
Apple's signed source URL; the final file write emits size and duration without
the output path. Tests cover safe artifact events and the 404 log level.

### Milestone 11 — command integration and cross-platform verification

An integration test launches the real CLI and verifies JSON event structure,
stderr/stdout separation, command-span environment context, failure lifecycle,
and exclusion of the input path. Linux cross-compilation exposed and fixed a
missing direct `libc` dependency and platform-only imports; authentication
header setup now compiles without warnings on both macOS and Linux.

Validation: 277 tests pass, 1 ignored; `cargo check`, `cargo build`,
`cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` pass on
macOS. `cargo check --target aarch64-unknown-linux-gnu` passes in a Rust 1.94
Linux container without warnings.

### Milestone 12 — dependency advisory remediation

GitHub reported five open advisories for the direct `zip` 8.6.0 dependency.
The project reads untrusted IPA archives and calls `ZipArchive::extract` in
both device and simulator installers, so those advisories were reachable.
`zip` is updated to 9.5.1. The v9 fallible entry-name API is handled by
propagating decode errors at all seven read/write call sites. The same audit
also found vulnerable `h2` and `quick-xml` transitive versions, so compatible
parent/lockfile updates moved them to patched releases. Tokio, rustix,
chacha20, and anyhow were updated to resolve current audit findings.

Validation: `cargo audit` reports no vulnerabilities or warnings; all 277
tests pass with 1 ignored, and `cargo check`, `cargo build`, Clippy, formatting,
and Linux cross-compilation pass. The critical ZIP parser advisory is patched
in 9.0.5 and later ([upstream advisory](https://github.com/zip-rs/zip2/security/advisories/GHSA-m665-v7pm-7grj));
the high-severity `quick-xml` issues are fixed in 0.41.0 and later
([namespace allocation](https://rustsec.org/advisories/RUSTSEC-2026-0195.html),
[duplicate-attribute parsing](https://rustsec.org/advisories/RUSTSEC-2026-0194.html)).

## Operator guide

### Configuration and destination

| Setting | Default | Effect |
|---|---|---|
| `RUST_LOG` | `info`, or `debug` with `--verbose` | `tracing` filter; when set, it overrides the fallback level. |
| `IPAKEEP_LOG_FORMAT` | `text` | `text` or `json`; JSON is one event per stderr line. |
| `IPAKEEP_ENV` | `unspecified` | Sanitized environment label on the command span. |
| destination | stderr | The shell or service manager can route the inherited stderr stream to its chosen destination; command results and `--format json` stay on stdout. |

Examples:

```sh
RUST_LOG=debug ipakeep --verbose search "Ludo Star"
IPAKEEP_LOG_FORMAT=json RUST_LOG=info IPAKEEP_ENV=production \
  ipakeep --format json decrypt inspect ./missing.ipa
RUST_LOG=ipakeep::infrastructure::http=debug,ipakeep=info ipakeep search "Ludo Star"
```

The CLI is short-lived and writes a small number of events to stderr. Operators
can route that standard stream with shell redirection or their process manager.
The CLI does not create log files, so local rotation and retention do not
apply. The synchronous stderr writer avoids a background worker or mandatory
collector; the CLI does not buffer events for an asynchronous flush. No
external exporter, metrics service, or network connection is required.

### Event fields and correlation

Events use UTC timestamps and normalized `service`, `component`, `operation`,
`event_name`, `outcome`, `duration_ms`, `status`, `error_type`, and `body_bytes`
fields when relevant. A `cli.command` span wraps awaited command work and carries
the command operation and environment. HTTP, keychain, retry, and child-process
events within that work inherit the span; JSON includes it under `span`. A
single local CLI invocation is the correlation boundary, so the project does
not generate request IDs, W3C trace IDs, or distributed spans.

Useful events include:

- `command.started`, `command.completed`, `command.failed`, and
  `application.panic` for the process lifecycle.
- `http.response.headers_received`, `http.response.body_read`, and
  `http.response.body_read_failed` for remote calls and artifact transfer.
- `credentials.saved`, `credentials.loaded`, and `credentials.deleted` for
  credential persistence.
- `process.completed` and `process.spawn_failed` for host tools.
- `auth.retry.scheduled` and `appstore.request.retry` for recoverable retries.
- `download.artifact.saved` for the local IPA write.

Successful request/process detail and routine state resolution are DEBUG.
Command and credential writes are INFO. Recoverable fallbacks, retries,
server failures, process failures, and panics use WARN or ERROR according to
impact. Normal 4xx responses use DEBUG because optional 404s are part of a few
fallback paths; 408, 429, and 5xx remain WARN.

### Privacy and adding events

Do not log CLI arguments verbatim, signed URLs, query strings, request or
response bodies, auth headers, cookies, account fields, filesystem paths, or
child-process arguments/output. HTTP events keep the hostname and omit the
path/query. Process events keep only the executable basename and exit metadata.
Response errors retain status and safe parser/error classifications; raw
request URLs and arbitrary server bodies are removed. User-facing CLI output
may still include a path when it identifies the requested file operation, but
that path is not copied into tracing events.

When adding an event, use the existing `tracing` macros at the relevant
presentation or infrastructure boundary. Give it a stable `event_name`, set
`component` and `operation`, choose a level by impact, and include only safe
fields needed to diagnose the outcome. Keep domain use cases free of tracing;
the command span already correlates their awaited work with infrastructure
events.

### Captured example

This command was run locally with `IPAKEEP_LOG_FORMAT=json`, `RUST_LOG=info`,
and `IPAKEEP_ENV=production`; the IPA was intentionally missing. This is the
actual command failure event, separated from the user-facing stderr error:

```json
{"timestamp":"2026-11-13T13:34:56.870812Z","level":"ERROR","message":"command failed; see stderr for details","service":"ipakeep","component":"cli","operation":"decrypt.inspect","event_name":"command.failed","outcome":"failure","duration_ms":3,"error_type":"command_error","target":"ipakeep","span":{"component":"cli","duration_ms":3,"environment":"production","operation":"decrypt.inspect","outcome":"failure","service":"ipakeep","name":"cli.command"},"spans":[]}
```

## Final audit — 2026-11-13

Every requested dimension applies. Metrics exporters, health endpoints,
distributed trace IDs, log-file rotation, and a background async writer are
intentionally omitted: this is a short-lived CLI with a process-level
correlation boundary, low event volume, and stderr capture delegated to the
shell or process manager.

| Dimension | Initial | Final | Final evidence |
|---|---:|---:|---|
| Architecture and decoupling | 4 | 10 | Subscriber is initialized at the composition root; tracing stays in presentation/infrastructure, with no domain logging dependency. |
| Functional coverage | 3 | 10 | Command lifecycle, HTTP headers/body, auth retries/fallbacks, credentials, host tools, simulator, downloads, and panic boundary are covered. |
| Event quality and utility | 4 | 10 | Events use appropriate levels and stable names with outcomes, durations, status, byte counts, and safe error categories where useful. |
| Structured logging and consistency | 5 | 10 | JSON emits UTC timestamps and normalized service/component/event fields; stdout remains reserved for results. |
| Context and correlation | 2 | 10 | Command spans carry operation/environment through async work and the modern Anisette blocking helper; a real CLI integration test checks correlation. No synthetic distributed IDs are generated. |
| Security and privacy | 7 | 10 | Sensitive request data, signed URLs, response bodies, account fields, paths, and child output are excluded from tracing; regression tests cover sentinels. `cargo audit` is clean and GitHub's five open ZIP alerts are fixed. |
| Performance and resilience | 6 | 10 | INFO default limits volume, stderr keeps the CLI simple, sink write failure is tested not to interrupt work, and no long-lived worker needs shutdown flushing. |
| Configuration and portability | 5 | 10 | `RUST_LOG`, `--verbose`, `IPAKEEP_LOG_FORMAT`, `IPAKEEP_ENV`, and inherited stderr routing cover level, format, environment, and destination behavior; macOS and Linux builds pass. |
| Error handling | 4 | 10 | CLI failure events include operation/outcome/duration; HTTP and process boundaries classify failures without leaking URLs, bodies, args, or output; panic boundary records safe location metadata. |
| Testing and verifiability | 4 | 10 | 278 tests pass, 1 is ignored; config, JSON schema, correlation, redaction, concurrency, process output, sink failure, HTTP behavior, and CLI lifecycle have automated coverage. Clippy, build, native/cross checks, and dependency audit pass. |
| **Overall** | **4.4** | **10.0** | Arithmetic mean of the ten applicable dimensions. |

Final verification on macOS: `cargo test --all` (278 passed, 1 ignored),
`cargo clippy --all-targets -- -D warnings`, `cargo check`, `cargo build`,
`cargo fmt --check`, `cargo audit` (no findings), and
`cargo check --target aarch64-unknown-linux-gnu` in a Rust 1.94 Linux container.
The JSON failure event example above was generated by running the actual CLI.
