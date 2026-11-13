# Static on-device decrypt — kernel RE notes (exploration, not the shipping path)

> **Bottom line:** the shipping decrypt is `ipakeep decrypt dump` (Frida, live
> process; verified E2E) and `decrypt offline` (ipadecrypt). This directory is a
> **documented dead end**: an attempt at a *static, no-launch* FairPlay decrypt
> on a jailbroken device. It produced one genuinely useful kernel result (an
> AMFI library-validation bypass) but cannot decrypt modern apps. Kept for the
> research; not wired into any backend.

Test device: "iPhone de Pau", iPhone10,1 (A11 / t8015, arm64), iOS 16.7.16
(20H392), **Dopamine** (KFD/physrw) jailbreak. All addresses below are from IDA
on the clean 16.7.16/t8015 kernelcache (unslid, imagebase `0xfffffff007004000`).

## The blocker, correctly diagnosed

A separate process mapping an App Store binary executable (`PROT_READ|PROT_EXEC`,
which `mremap_encrypted` needs) is denied **EPERM** by AMFI's `mmap` hook:

```c
// AMFI mpo_file_check_mmap hook (sub_FFFFFFF0056F6A8C)
v12 = cs_require_lv(current_proc);
if ((maxprot & VM_PROT_EXECUTE) && v12)
    if (library_validation_check(...) == 0) return DENY;  // EPERM
```

Two facts settle the old "de-platform our process" theory as **wrong**:

1. `_cs_require_lv` (`0xfffffff00759e710`) is literally `MOV W0,#1 ; RET` —
   library validation is **unconditional**. No per-process flag (csflags,
   `CS_REQUIRE_LV`, `csb_platform_binary`, `TFRO_PLATFORM`) can switch it off.
2. The LV check (`sub_FFFFFFF0056F6B10`) compares the **mapped file** vs the
   **mapping process**. De-platforming ourselves only moves us between reject
   branches (`"mapping process is a platform binary…"` →
   `"…has no Team ID / different Team IDs"`): a foreign-team app never passes
   that way.

The one branch that *allows* a foreign file: when the **file** is a platform
binary (`csfg_get_platform_binary(file) == 1`).

## The useful result — a KTRR-safe library-validation bypass (PROVEN live)

`csfg_get_platform_binary` (`0xfffffff00759ef54`) reads a single heap bit:

```
file vnode -> +0x78 (v_ubcinfo) -> +0x50 (cs_blobs) -> cs_blob
cs_blob + 0xAC, bit 0   ==   csb_platform_binary
```

The `cs_blob` lives in kalloc heap (writable via libjailbreak physrw — **no
KTRR**, unlike kernel `__TEXT_EXEC`, which on this Dopamine/KFD/A11 device is
AMCC-locked and would **panic** if written). Setting that one bit on the target
app's own blob makes AMFI treat the file as platform, so any process may map it
executable. Reach the file's vnode with libjailbreak `proc_get_vnode_for_fd`.

`lvmap.c` does this and it was **verified on the live kernel** (Ludo Star):
pre-patch `mmap(RX)` = EPERM → set `cs_blob+0xAC` bit 0 → post-patch `mmap(RX)` =
OK. (This is why the earlier `jbclient_trust_file_by_path` failed: a *dynamic*
trust cache sets `csb_validated`, not `csb_platform_binary`; the direct kwrite
does.)

## Why the static decrypt still fails (the real dead end)

Modern FairPlay encrypts a **single 4K page at a 4K-granular (non-16K) offset**
— confirmed on both Ludo Star (`cryptoff=0x1049000`) and Candy Crush
(`cryptoff=0xcdd000`), each `cryptsize=0x1000`. `mremap_encrypted` operates at
the **calling process's page granularity**, which is 16K for every iOS-16 arm64
process. A 16K process cannot express "decrypt this 4K page":

- raw call at the 4K offset → `EINVAL`;
- rounding the window to 16K → wrong `crypto_backing_offset`/range → corrupt
  output **and a wedged apple-protect pager** on that vnode (recovered by reboot).

A 4K-paged helper is not creatable on iOS 16. So the static mmap+`mremap_encrypted`
approach (old flexdecrypt/bfdecrypt style) is obsolete for modern apps. The live
process already has its `__TEXT` decrypted by the kernel's apple-protect pager,
which is exactly why the **Frida live-process dump is the right tool** and why
`ipakeep decrypt dump` works.

## Files

- `lvmap.c` — the proven LV bypass (set file `csb_platform_binary`) + a decrypt
  attempt that demonstrates the 4K/16K `mremap_encrypted` wall.
- `lvpatch.c` — read-only probe that resolves the kernel slide from `jbinfo`
  and validates `cs_require_lv`; a `--patch` to flip it to `return 0` exists but
  is **unsafe on this device** (KTRR → kernel-text write panics) and must not be
  run on Dopamine/KFD/A11.
- `libjailbreak.h` — minimal decls for the libjailbreak exports we call.
- `build.sh` — cross-compile (iPhoneOS SDK) + repoint to
  `/var/jb/basebin/libjailbreak.dylib` + `ldid` sign.
- `ent.plist` — ad-hoc entitlements.

## Running a helper on the device (the non-obvious parts)

1. Build: `LIBJAILBREAK=<dylib> ./build.sh lvmap.c out`.
2. Trust-cache the **sha256 cdhash** (hex from `codesign -dvvv`, not a path):
   `sudo jbctl trustcache add <CDHash>`.
3. Run from a **jbroot** path (`sudo cp` to `/var/jb/usr/bin/`): a trust-cached
   binary under `/var/mobile` is SIGKILLed at exec by the sandbox; under
   `/var/jb` the platform profile applies.
4. Run as **root** — `jbclient_initialize_primitives` grants kernel R/W only to
   root (raw `kread`/`kwrite` work even though `kalloc/kmap/kcall` need an
   IOSurface entitlement this helper lacks).
5. SSH throttles on repeated password auth; use one `ssh -M`/`ControlMaster`
   multiplexed connection.

Kernel slide: parse `jbinfo_get_serialized` → `kernelConstant.slide` (the value
is the **decimal** after the xpc pointer, not the `0x…` pointer itself).

Safety rule (user's personal device): read-validate every offset against live
values before any write; never write kernel text on a KTRR-locked kernel.
