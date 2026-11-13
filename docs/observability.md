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

This section is updated with each implementation milestone and the final score.
