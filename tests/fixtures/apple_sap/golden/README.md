# Golden vectors: Apple SAP, ADI, Store AMD and kbsync

These are byte-exact oracles for the native Rust port in `src/infrastructure/apple_sap/`.
They were produced by upstream ipatool v2.8.1 (`github.com/majd/ipatool/v2@v2.8.1`). The
upstream code ran on the SHA-256-pinned asset bundle
`apple-assets-macos-27-26A434-arm64-v5`, with every host randomness and time source made
deterministic.

All values are lowercase hex unless the key says `b64`. Nothing here is secret. The device
identity is synthetic, no Apple ID was used, and the only network peers were Apple's
public bag/SAP endpoints and GSA MidService machine provisioning, which needs no account.

## Injected constants

| Name | Value | Used by |
|---|---|---|
| fixed time | `2026-11-15T12:00:00Z` (unix `1794744000`) | every guest time shim (`gettimeofday`, `time`, `clock_get_calendar_microtime`) and the AMS emulator (`time`, `dispatch_time`, `NSDate`, its `gettimeofday` adapter) |
| primary seed | ASCII `ipakeep-h0-golden-seed-v1` | RNG stream |
| alternate seed | ASCII `ipakeep-h0-golden-seed-v2` | sensitivity checks only |
| hardware ID (MAC / Store guid) | `020000000001` | SAP, kbsync, Store AMD |
| ADI host UUID / identifier | `00112233445566778899aabbccddeeff` | ADI, AMD |
| kbsync DSID | `1234567890` | kbsync |
| GSA machine DSID | `0xfffffffffffffffe` (-2) | ADI provisioning + `RequestOTP` |
| Store AMD DSID | `0xffffffffffffffff` (-1) | what AMS asks adid for |

**RNG stream.** Block *i* = `SHA-256(seed || be64(i))`, for i = 0, 1, 2, and so on. The
blocks are concatenated into one global byte stream. Every random shim reads the next bytes
in call order: `arc4random` (4 bytes, little-endian u32), `random` (4 bytes LE `& 0x7fffffff`),
`arc4random_uniform` (4-byte LE draws with rejection sampling), and `read_random` /
`kernel_read_random` (n bytes). The AMS emulator's `CFUUIDCreate` and UUID strings read the
same stream. To reproduce a vector, a Rust port must use the same shims, in the same order,
and draw the same number of bytes from each. `observed_sources` in each file lists the bytes
or calls consumed per phase.

`sysctlbyname`, `gethostuuid` (= identifier), `sysconf` and the virtual filesystem were already
constant upstream. `/Users/Shared/SC Info` and `adi.pb` exist only in emulator memory.

## Determinism summary

| Oracle | Same seed and time, fresh runtime | Depends on RNG | Depends on time |
|---|---|---|---|
| SAP exchange 1 (setup request) | identical, also across processes | yes | yes |
| SAP exchange 2 / `Sign` (given recorded Apple reply) | identical, also offline in a fresh process | via exchange 1 | via exchange 1 |
| SAP context pointer | identical (`0xc00000000260`) | no | no |
| kbsync | identical, also across processes | yes | yes |
| ADI cpim / session (given recorded spim) | identical | yes | not tested separately |
| ADI OTP / MID, `adi.pb` state (given recorded spim/ptm/tk) | identical, also offline in a fresh process | — | OTP yes, MID no |
| Store AMD headers | identical, also across processes | **no** | AMD yes, AMD-M no |

RNG is consumed only in SAP `Initialize` (12 bytes from `arc4random`, plus one
`gettimeofday` call). The `Exchange` and `Sign` phases consume none. So
`Initialize` → `Exchange(cert)` is fully reproducible offline, and so is everything after it
once the recorded Apple setup reply is fed back.

The only parts that are not deterministic come from the network and cannot be replayed live:
- Apple's `sign-sap-setup` reply.
- The GSA `spim`, `ptm`, `tk` and `X-Apple-I-MD-RINFO` values.

Each run returns different values for these. They are recorded verbatim, so a Rust test
replays them offline. GSA also refuses to re-provision an identifier it has already seen:
the second run with the same identifier got `-29002` (server error), and the dsid -1 attempt
got `-29003` (environment mismatch). To regenerate `adi.json` live, use a new identifier.

## Files

### `sap.json`: FairPlay SAP v200 (`internal/sap/machine/machine.go`, `signer_local.go`, `protocol.go`)
- `hardware_id_hex`, `hardware_block_hex`: the 24-byte block passed to the guest,
  `le32(len) || id || zero padding`.
- `certificate_url`, `certificate_http`: the bag's `sign-sap-setup-cert` value and the
  `GET` exchange. `response_body_hex` is the raw plist; `certificate_hex` is its
  `sign-sap-setup-cert` data.
- `context_pointer`: the guest context returned by `Initialize`.
- `exchange1_input_hex` (= the certificate), `exchange1_output_hex`, `exchange1_state`
  (1): the setup request.
- `setup_url`, `setup_http`: the `POST` to `sign-sap-setup`. The request body is the XML
  plist `{sign-sap-setup-buffer: exchange1_output}`; the response is Apple's reply plist.
- `exchange2_input_hex`: the `sign-sap-setup-buffer` extracted from the reply.
  `exchange2_output_hex` is empty and `exchange2_state` is 0.
- `signatures[]`: `Sign(context, input)` called in array order on the same context
  after setup.
- `exchange1_output_alt_seed_hex`: the same session with the alternate seed.
- `deterministic_replay`, `time_independent`: see the summary above.
- `observed_sources`: RNG bytes and time calls per phase.

### `adi.json`: modern ADI (`modern_adi.go`, `storeauth/anisette.go`)
- `gsa_start_http`, `gsa_finish_http`: the full GSA MidService exchanges (headers and
  request/response bodies), for offline replay.
- `start_provisioning`: `StartProvisioning(dsid=-2, spim)` → `cpim`, `session`.
- `end_provisioning`: `EndProvisioning(session, ptm, tk)`.
- `request_otp`: `RequestOTP(-2)` → `mid` (60 bytes), `otp` (28 bytes).
- `adi_state_hex`: the resulting `/var/db/fpsd/adi/adi.pb`.
- `anisette_state_json`: the persisted ipatool anisette state, in the same shape as
  `anisette-v4.json`.
- `anisette_headers`: the headers `storeauth.AnisetteHeaders` builds:
  - `X-Apple-I-MD` = b64(otp), `X-Apple-I-MD-M` = b64(mid).
  - `X-Apple-I-MD-LU` = hex(SHA-256(identifier)).
  - `X-Mme-Device-Id` = the identifier formatted as a UUID.
  - `X-Apple-I-TimeZone` = `UTC`, because the frozen time is in UTC.
- `xpc`: the client ↔ `com.apple.adid` payloads per call. The format is big-endian, as far as
  observed:
  - Request: `be32 1 || be32 opcode || be32 1 || be64 dsid || …`. Opcodes: start
    `0x716bd86c`, end `0x0b2b3196`, OTP `0xcfe0b46a`.
  - Reply: `be32 status || be32 len || bytes …`.
    - Start replies with `status, len, cpim, be32 session`.
    - OTP replies with `status, len, mid, len, otp`.
- `alt_seed`: `cpim` and `session` under the alternate seed.

### `amd.json`: Store AMD (`store/emulator/anisette.go`, `delegate.go`, `storeauth/store_amd.go`)
The input is the `adi.json` state (identifier `…eeff`). AMS runs `AMSAnisette
_headersForRequest:account:nil type:2` inside the AppleMediaServices emulator, and
`ModernADI.ExchangeXPC` answers `com.apple.adid`.
- `genuine_dsid_minus1`: what AMS really sends: exactly one XPC request,
  `00000001 cfe0b46a 00000001 ffffffffffffffff`. adid answers `ffff4ffb` (-45061, not
  provisioned) because only the account-bound Store "SP" action provisions dsid -1. AMS then
  returns no headers.
- `rewritten_dsid_minus2`: the same flow, but the handler rewrites the request's DSID
  (bytes 12–20) to -2. The resulting `headers` match `adi.json`'s `X-Apple-I-MD` /
  `X-Apple-I-MD-M` byte for byte. Further checks:
  - Identical for a different URL.
  - Identical for a different seed.
  - AMD changes after +90 s; AMD-M does not.
- `direct_reply`: `ExchangeXPC` of the forwarded request without AMS, parsed into
  `status`, `mid` and `otp`.
- `request_otp_minus2`, `request_otp_minus1`: `ModernADI.RequestOTP` for comparison. The
  commerce client's XPC request for -1 matches AMS's request byte for byte.
- `verdict`: all fields are `true`.

**AMD verdict:**
- `X-Apple-AMD` = base64(`RequestOTP(0xffffffffffffffff)`.otp).
- `X-Apple-AMD-M` = base64(`RequestOTP(0xffffffffffffffff)`.mid).

In other words, the "Configurator AMD proof" is the same ADI OTP the commerce client
produces, requested for DSID -1. It ignores the URL, and it needs dsid -1 to be provisioned
through the Store "SP" provisioning (`storeauth.ProvisionStoreAnisette`). A Rust port can drop
the AppleMediaServices emulator and call the adid OTP path directly.

### `kbsync.json`: StoreAgent (`machine/kbsync.go`)
`GenerateKBSync(hardwareID, dsid=1234567890)` with an empty virtual SC Info. It consumes 24
bytes from `arc4random` and makes 2 `gettimeofday` calls. `kbsync_alt_seed_hex` holds the
alternate-seed output. The result depends on both seed and time.

### `ipatool-golden-hooks.patch`, `harness.patch`
These two patches regenerate everything above.
- `ipatool-golden-hooks.patch` applies to a writable copy of ipatool v2.8.1. It adds
  `internal/golden`, which provides:
  - Freezable `Now` and `Read`, with per-source counters.
  - An `XPCTrace` hook.
  - The `IPAKEEP_WIRE_LOG` JSONL wire logger.

  The patch also routes every shim and emulator `time.Now` / `crypto/rand` call through
  `internal/golden`, and hooks the wire logger into `store/backend.go` (`requestTransport`),
  `emulator/network.go` (`performHTTP`) and `storeauth/http_client.go`.
- `harness.patch` contains:
  - The Go harness, module `github.com/majd/ipatool/v2/h0golden`, with
    `replace github.com/majd/ipatool/v2 => ../ipatool`.
  - `wire/redact.py`.

Regenerate:
```
cp -R ~/go/pkg/mod/github.com/majd/ipatool/v2@v2.8.1 ipatool && chmod -R u+w ipatool
(cd ipatool && git init -q && git apply ../ipatool-golden-hooks.patch)
git apply harness.patch && cp ipatool/go.sum harness/ && cd harness && go build -o h0golden .
./h0golden kbsync OUT; ./h0golden sap OUT; ./h0golden adi OUT   # adi: set H0_ADI_ID=<fresh 16-byte hex>
./h0golden amd OUT                                             # needs OUT/adi.json
./h0golden sap-verify DIR; ./h0golden adi-verify DIR           # offline replay of committed fixtures
```
