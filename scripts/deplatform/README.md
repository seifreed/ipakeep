# Static on-device decrypt: de-platform helper

The `--dumper fouldecrypt` backend does a static, no-launch FairPlay decrypt on a
jailbroken device. On A11/t8015 under Dopamine (iPhone de Pau, iOS 16.7.16 /
20H392) it is blocked by AMFI **library validation**:

- Our decrypter runs as a **platform binary with LV** (trust-cached; `csops`
  reports `0x2680380d`). AMFI's `file_check_mmap` → library-validation hook
  forbids a platform/LV process from creating an executable
  (`PROT_READ|PROT_EXEC`) mapping of a **foreign-team** Apple-signed Mach-O.
- `mremap_encrypted` needs exactly that `r-x` mapping, so it returns **EPERM**
  (proven at every offset; a read-only mapping has no mremap fallback).

The only known fix is to **de-platform our own process** with kernel R/W.
Clearing `p_csflags` was proven insufficient. On this kernel (verified live
against Dopamine's own offset database, `jbinfo_get_serialized`) the platform
status that gates library validation is the **`TFRO_PLATFORM` (0x400)** bit in
the read-only proc structure `proc_ro.t_flags_ro`:

```
proc -> proc_ro (@+24) -> t_flags_ro (@+120)  &= ~0x400
```

`proc_ro` is read-only-mapped kernel memory, so the write must go through a
physical-write-backed primitive (libjailbreak's `kwrite32` / `physwritebuf`),
not an ordinary virtual write. (The generic XNU `cs_blob.csb_platform_binary`
chain — `proc -> p_textvp -> ubc_info -> cs_blobs` — does not apply here:
`proc_find_main_binary_code_dir` is arm64e-gated and returns -1 on A11.)

## Hard constraints (verified by research wf_7d2faab6-116)

- Kernel R/W must come from **Dopamine's own libjailbreak** — all three kfd PUAF
  exploits (physpuppet/smith/landa) are patched on 20H392.
- The offsets for 20H392/t8015 are **not published** anywhere; they must be
  derived on-device. Dopamine's ready `proc_find_main_binary_code_dir` helper is
  arm64e-gated and bails on A11, so we walk the chain ourselves.

## Running a helper on the device (the non-obvious parts)

1. **Build + sign** on macOS: `LIBJAILBREAK=<dylib> ./build.sh src out`
   (repoints to `/var/jb/basebin/libjailbreak.dylib`, signs with `ldid`).
2. **Trust-cache** the cdhash: `sudo jbctl trustcache add <CDHash>` (hex from
   `codesign -dvvv`, NOT a path).
3. **Run from a jbroot path**: `sudo cp` it to `/var/jb/usr/bin/` and run it
   there. A trust-cached binary under `/var/mobile` is still SIGKILLed at exec
   by the sandbox (`failed to apply exec policy`); under `/var/jb` the platform
   sandbox profile applies and it runs.
4. **Run as root**: `jbclient_initialize_primitives` only grants kernel R/W to
   a root process. (`kalloc/kmap/kcall` also need an IOSurface entitlement, but
   de-platforming needs only `kread`/`kwrite`, which work without it.)
5. SSH to the device throttles hard on repeated password auth; use an
   `ssh -M`/`ControlMaster` multiplexed connection to avoid re-auth.

## Staged plan (each stage commits + pushes)

1. ✅ **Probe (read-only)** — `deplatform_probe.c`: dumps `jbinfo` offsets,
   tests `proc_find_main_binary_code_dir`, walks the chain, `csops`. No writes.
2. ✅ **Offsets pinned** from Dopamine's live offset DB (see above).
3. ✅ **Clear helper** — `deplatform.c`: validates `proc -> proc_ro ->
   t_flags_ro`, then clears `TFRO_PLATFORM` via `kwrite32`. Dry-run by default;
   writes only with `--commit` after validation.
4. Self-de-platform, then `mmap(PROT_EXEC)` + `mremap_encrypted` the installed
   binary in-process (no `exec`, which would re-platformize us); write plaintext.
5. Wire into `run.sh` / the `fouldecrypt` backend and add EPERM detection.

## Files

- `deplatform_probe.c` — stage 1, read-only offset/chain discovery.
- `deplatform.c` — stage 3, the TFRO_PLATFORM clear (dry-run unless `--commit`).
- `libjailbreak.h` — minimal decls for the libjailbreak exports we call.
- `build.sh` — cross-compile on macOS (iPhoneOS SDK) + link libjailbreak + sign.
- `ent.plist` — ad-hoc signing entitlements (optional; trust cache suffices).

Safety rule (user's personal device): no blind kernel writes — read-validate
every offset against the live values before any write; dry-run is the default.
