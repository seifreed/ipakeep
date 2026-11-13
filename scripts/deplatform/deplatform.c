/*
 * ipakeep de-platform helper (stage 3).
 *
 * Clears this process's platform-binary status so AMFI library validation
 * stops forbidding it from creating executable mappings of foreign-team code
 * (the mmap(PROT_EXEC) + mremap_encrypted FairPlay decrypt path).
 *
 * On the target kernel (t8015 / iOS 16.7.16 / 20H392, Dopamine) the platform
 * status that matters is the TFRO_PLATFORM bit in the read-only proc structure
 * `proc_ro.t_flags_ro` -- NOT p_csflags (clearing p_csflags was proven
 * insufficient in earlier work). The offsets below were read live from
 * Dopamine's own offset database (jbinfo_get_serialized); they are the build
 * defaults and can be overridden by env var for a different build:
 *
 *   proc.proc_ro        = 24   (IPAKEEP_OFF_PROC_PROCRO)
 *   proc_ro.t_flags_ro  = 120  (IPAKEEP_OFF_PROCRO_TFLAGS)
 *   proc_ro.csflags     = 28   (IPAKEEP_OFF_PROCRO_CSFLAGS)
 *   TFRO_PLATFORM       = 0x400 (IPAKEEP_TFRO_PLATFORM)
 *
 * Safety: by default this is a DRY RUN -- it walks and validates the chain,
 * prints the current flags, and writes NOTHING. It only writes kernel memory
 * when given `--commit`, and only after every pointer validates as a kernel VA
 * and the platform bit is actually set. Requires root (jbserver grants the
 * kernel R/W primitives to a root process; kwrite is physical-write backed so
 * it reaches the read-only proc_ro page). Run from a jbroot path
 * (/var/jb/usr/bin/...) or the sandbox kills it at exec.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "libjailbreak.h"

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_STATUS 0

static int looks_like_kernel_ptr(uint64_t p) {
    return p >= 0xffffff0000000000ULL && p != 0xffffffffffffffffULL;
}

static uint64_t env_u(const char *name, uint64_t dflt) {
    const char *v = getenv(name);
    return (v && *v) ? (uint64_t)strtoull(v, NULL, 0) : dflt;
}

static uint32_t read_csops(void) {
    uint32_t f = 0;
    if (csops(getpid(), CS_OPS_STATUS, &f, sizeof(f)) != 0) perror("csops");
    return f;
}

int main(int argc, char **argv) {
    (void)!write(2, "ALIVE\n", 6);
    setvbuf(stdout, NULL, _IONBF, 0);

    int commit = 0;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--commit") == 0) commit = 1;

    const uint64_t off_procro = env_u("IPAKEEP_OFF_PROC_PROCRO", 24);
    const uint64_t off_tflags = env_u("IPAKEEP_OFF_PROCRO_TFLAGS", 120);
    const uint64_t off_csflags = env_u("IPAKEEP_OFF_PROCRO_CSFLAGS", 28);
    const uint32_t tfro_platform = (uint32_t)env_u("IPAKEEP_TFRO_PLATFORM", 0x400);

    printf("== ipakeep de-platform (%s) ==\n", commit ? "COMMIT" : "dry-run");
    printf("csops p_csflags (before) = 0x%08x\n", read_csops());

    if (jbclient_initialize_primitives() != 0) {
        fprintf(stderr, "jbclient_initialize_primitives failed -- run as root "
                        "(sudo) from a jbroot path on a Dopamine device.\n");
        return 2;
    }

    uint64_t proc = proc_self();
    if (!looks_like_kernel_ptr(proc)) {
        fprintf(stderr, "proc_self (0x%llx) not a kernel VA.\n",
                (unsigned long long)proc);
        return 2;
    }
    uint64_t proc_ro = kread64(proc + off_procro);
    printf("proc=0x%llx  proc_ro=0x%llx\n", (unsigned long long)proc,
           (unsigned long long)proc_ro);
    if (!looks_like_kernel_ptr(proc_ro)) {
        fprintf(stderr, "proc_ro not a kernel VA; offset likely wrong. Abort.\n");
        return 2;
    }

    uint32_t tflags = kread32(proc_ro + off_tflags);
    uint32_t csflags = kread32(proc_ro + off_csflags);
    printf("proc_ro.t_flags_ro @+%llu = 0x%08x (TFRO_PLATFORM 0x%x -> %s)\n",
           (unsigned long long)off_tflags, tflags, tfro_platform,
           (tflags & tfro_platform) ? "SET" : "clear");
    printf("proc_ro.csflags    @+%llu = 0x%08x\n",
           (unsigned long long)off_csflags, csflags);

    if (!(tflags & tfro_platform)) {
        printf("Platform bit already clear; nothing to do.\n");
        return 0;
    }
    if (!commit) {
        printf("Dry run: validated the chain, wrote nothing. "
               "Re-run with --commit to clear TFRO_PLATFORM.\n");
        return 0;
    }

    uint32_t cleared = tflags & ~tfro_platform;
    printf("writing t_flags_ro 0x%08x -> 0x%08x ...\n", tflags, cleared);
    kwrite32(proc_ro + off_tflags, cleared);

    uint32_t after = kread32(proc_ro + off_tflags);
    printf("proc_ro.t_flags_ro (after) = 0x%08x (%s)\n", after,
           (after & tfro_platform) ? "STILL SET -- write failed"
                                   : "platform cleared");
    printf("csops p_csflags (after)    = 0x%08x\n", read_csops());
    return (after & tfro_platform) ? 1 : 0;
}
