/*
 * ipakeep lvpatch — toggle the kernel AMFI library-validation gate.
 *
 * IDA on the 16.7.16 / t8015 kernelcache showed AMFI's mmap hook does:
 *     if ((maxprot & VM_PROT_EXECUTE) && cs_require_lv(current_proc))
 *         if (library_validation_check(...) == 0) return DENY;   // EPERM
 * and that `_cs_require_lv` is hardcoded `MOV W0,#1 ; RET` — library
 * validation is unconditional, so NO per-process flag clear can bypass it
 * (the whole de-platform approach was a dead end). The only on-device route
 * is to flip that one instruction so cs_require_lv returns 0: the mmap hook
 * then skips LV entirely and mmap(PROT_EXEC) of foreign code is allowed,
 * which is what FairPlay decrypt (mremap_encrypted) needs.
 *
 * This is a GLOBAL, system-wide LV disable while active — reversible with
 * --restore. Kernel-text writes only stick on a checkm8/KTRR-disabled
 * jailbreak (palera1n); on a KTRR-locked kernel the write won't persist and
 * we abort cleanly (verify-after-write). Run as root from a jbroot path.
 *
 * Usage (staged — safe by default):
 *   lvpatch                 init + dump jbinfo + read & validate target (NO write)
 *   lvpatch --patch         validate then flip MOV W0,#1 -> MOV W0,#0, verify
 *   lvpatch --restore       flip back to MOV W0,#1, verify
 * Env: IPAKEEP_KSLIDE=0x... forces the kernel slide (authoritative; use the
 * value printed by the jbinfo dump if auto-detection is wrong).
 *
 * ponytail: single-instruction toggle, no dump wiring here — prove the gate
 * opens first, then wire the dumper. Add the mremap dumper when --patch is
 * confirmed to stick on the device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "libjailbreak.h"

/* Unslid addresses from IDA on the clean 16.7.16/t8015 kernelcache. */
#define CS_REQUIRE_LV_UNSLID 0xfffffff00759e710ULL
#define KERNEL_STATIC_BASE   0xfffffff007004000ULL
#define INSN_MOV_W0_1        0x52800020u   /* unpatched: cs_require_lv -> 1 */
#define INSN_MOV_W0_0        0x52800000u   /* patched:   cs_require_lv -> 0 */

static int looks_like_kptr(uint64_t p) {
    return p >= 0xfffffff000000000ULL && p != 0xffffffffffffffffULL;
}

/*
 * Best-effort kernel slide. IPAKEEP_KSLIDE wins if set. Otherwise parse the
 * jbinfo serialized description: prefer an explicit "slide", else derive it
 * from a kernel "base" (slide = base - static base). Returns 0 if unknown.
 */
static uint64_t find_slide(const char *desc) {
    const char *e = getenv("IPAKEEP_KSLIDE");
    if (e && *e) return strtoull(e, NULL, 0);
    if (!desc) return 0;
    const char *p = strstr(desc, "slide");
    if (p) {
        const char *h = strstr(p, "0x");
        if (h) {
            uint64_t v = strtoull(h, NULL, 16);
            if (v && v < 0x40000000ULL) return v;   /* a plausible slide */
        }
    }
    /* Fall back to a kernel base value (0xfffffff0........). */
    for (p = desc; (p = strstr(p, "0xfffffff0")) != NULL; p += 2) {
        uint64_t v = strtoull(p, NULL, 16);
        if (v >= KERNEL_STATIC_BASE && v < KERNEL_STATIC_BASE + 0x40000000ULL)
            return v - KERNEL_STATIC_BASE;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)!write(2, "ALIVE\n", 6);
    setvbuf(stdout, NULL, _IONBF, 0);

    int do_patch = 0, do_restore = 0;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--patch"))   do_patch = 1;
        else if (!strcmp(argv[i], "--restore")) do_restore = 1;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }

    if (jbclient_initialize_primitives() != 0) {
        fprintf(stderr, "jbclient init failed (run as root from a jbroot path)\n");
        return 2;
    }

    char *desc = NULL;
    void *info = jbinfo_get_serialized();
    if (info) desc = xpc_copy_description(info);
    if (desc) { printf("=== jbinfo ===\n%s\n=== end jbinfo ===\n", desc); }

    uint64_t slide = find_slide(desc);
    if (!slide) {
        fprintf(stderr, "could not determine kernel slide; set IPAKEEP_KSLIDE=0x...\n");
        return 2;
    }
    uint64_t target = CS_REQUIRE_LV_UNSLID + slide;
    printf("kernel slide = 0x%llx\n", (unsigned long long)slide);
    printf("cs_require_lv @ 0x%llx (unslid 0x%llx)\n",
           (unsigned long long)target, (unsigned long long)CS_REQUIRE_LV_UNSLID);
    if (!looks_like_kptr(target)) { fprintf(stderr, "target not a kernel VA; abort\n"); return 2; }

    uint32_t cur = kread32(target);
    printf("current insn = 0x%08x (%s)\n", cur,
           cur == INSN_MOV_W0_1 ? "MOV W0,#1 — LV ON (unpatched)"
         : cur == INSN_MOV_W0_0 ? "MOV W0,#0 — LV OFF (patched)"
         : "UNEXPECTED");

    if (!do_patch && !do_restore) {
        printf("(read-only; pass --patch or --restore to write)\n");
        return (cur == INSN_MOV_W0_1 || cur == INSN_MOV_W0_0) ? 0 : 1;
    }

    uint32_t want = do_patch ? INSN_MOV_W0_0 : INSN_MOV_W0_1;
    uint32_t need_cur = do_patch ? INSN_MOV_W0_1 : INSN_MOV_W0_0;
    if (cur == want) { printf("already in desired state; nothing to do.\n"); return 0; }
    if (cur != need_cur) {
        fprintf(stderr, "refusing to write: insn 0x%08x is not the expected 0x%08x "
                        "(wrong slide or different kernel). ABORT.\n", cur, need_cur);
        return 2;
    }

    kwrite32(target, want);
    uint32_t after = kread32(target);
    if (after != want) {
        fprintf(stderr, "write did NOT stick (0x%08x) — KTRR-locked kernel text? "
                        "No change made. Need a checkm8/KTRR-off jailbreak.\n", after);
        return 1;
    }
    printf(">>> %s: cs_require_lv now 0x%08x (%s). %s\n",
           do_patch ? "PATCHED" : "RESTORED", after,
           after == INSN_MOV_W0_0 ? "LV OFF" : "LV ON",
           do_patch ? "Run the dump, then --restore." : "LV re-enabled.");
    return 0;
}
