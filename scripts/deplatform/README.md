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

The only known fix is to **de-platform our own process**: clear
`csb_platform_binary` in our main-binary `cs_blob` (and `TF_PLATFORM` in our
task). Clearing `p_csflags` was proven insufficient — platform status is read
from the `cs_blob`/task, not `p_csflags` (matches XNU `csproc_clear_platform_binary`).
This requires kernel R/W and the struct-offset chain:

```
proc -> p_textvp (vnode) -> v_ubcinfo (ubc_info) -> cs_blobs -> csb_platform_binary
```

## Hard constraints (verified by research wf_7d2faab6-116)

- Kernel R/W must come from **Dopamine's own libjailbreak** — all three kfd PUAF
  exploits (physpuppet/smith/landa) are patched on 20H392.
- The offsets for 20H392/t8015 are **not published** anywhere; they must be
  derived on-device. Dopamine's ready `proc_find_main_binary_code_dir` helper is
  arm64e-gated and bails on A11, so we walk the chain ourselves.

## Staged plan (each stage commits + pushes)

1. **Probe (read-only)** — `deplatform_probe.c`: walk the chain with
   env-supplied offsets, validate every pointer is a kernel VA, hexdump the
   `cs_blob`, print `csops`. Writes nothing. ← start here.
2. Locate the `csb_platform_binary` bit by diffing a platform vs non-platform
   `cs_blob` dump; pin the offsets.
3. **Clear helper** — read-validate the full chain, then `kwrite` the platform
   bit + `TF_PLATFORM`; re-read `csops` to confirm. Writes gated behind a
   validated check and an explicit `--commit` flag (dry-run by default).
4. Self-de-platform, then `mmap(PROT_EXEC)` + `mremap_encrypted` the installed
   binary (in-process, so no `exec` re-platformizes us); write plaintext out.
5. Wire into `run.sh` / the `fouldecrypt` backend and add EPERM detection.

## Files

- `deplatform_probe.c` — stage 1, read-only.
- `libjailbreak.h` — minimal decls for the libjailbreak exports we call.
- `build.sh` — cross-compile on macOS (iPhoneOS SDK) + link libjailbreak + sign.
- `ent.plist` — ad-hoc signing entitlements.

Safety rule (user's personal device): no blind kernel writes — read-validate
every offset against known-good values before any write.
