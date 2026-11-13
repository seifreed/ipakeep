/*
 * ipakeep de-platform PROBE (read-only).
 *
 * Why this exists: on this A11/t8015 iOS 16.7.16 (Dopamine) device, a static
 * FoulDecrypt decrypt is blocked by AMFI library validation. The decrypter
 * process runs as a PLATFORM binary (trust-cached), and a platform/LV process
 * may not create an executable mapping of a foreign-team Apple-signed Mach-O,
 * so mmap(PROT_EXEC) / mremap_encrypted on the app binary returns EPERM.
 *
 * The only known fix is to clear `csb_platform_binary` in our own main-binary
 * cs_blob (clearing p_csflags was proven insufficient: platform status is read
 * from the cs_blob / task, not from p_csflags). Reaching the cs_blob means
 * walking proc -> p_textvp(vnode) -> ubc_info -> cs_blobs -> csb_platform_binary.
 *
 * Those struct offsets are NOT published for 20H392/t8015, so this probe gathers
 * them empirically WITHOUT writing kernel memory: it walks the chain with the
 * offsets you supply via env vars, validates every pointer is a sane kernel VA,
 * and hexdumps the cs_blob so the platform bitfield can be located by eye (and
 * by diffing a platform vs non-platform blob). NOTHING here writes the kernel.
 *
 * Offsets come from the environment so no wrong value is ever baked in:
 *   IPAKEEP_OFF_P_TEXTVP      proc -> p_textvp            (struct proc)
 *   IPAKEEP_OFF_V_UBCINFO     vnode -> v_ubcinfo          (struct vnode)
 *   IPAKEEP_OFF_UBC_CSBLOBS   ubc_info -> cs_blobs        (struct ubc_info)
 *   IPAKEEP_OFF_CSB_NEXT      cs_blob -> csb_next         (list link, default 0)
 * Each is a hex or decimal byte offset. Unset ones stop the walk at that step
 * (and the probe says so) rather than dereferencing a guess.
 *
 * Build: scripts/deplatform/build.sh  (see that file).
 * Run on device:  ./deplatform_probe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "libjailbreak.h"

/* csops(2): ops=0 (CS_OPS_STATUS) fills a uint32 with the proc's p_csflags. */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_STATUS 0

/* iOS 16 arm64 kernel VAs live in the top-of-memory half. */
static int looks_like_kernel_ptr(uint64_t p) {
    return p >= 0xffffff0000000000ULL && p != 0xffffffffffffffffULL;
}

/* Parse a hex (0x..) or decimal env var into an offset; returns -1 if unset. */
static long env_off(const char *name) {
    const char *v = getenv(name);
    if (!v || !*v) return -1;
    return (long)strtoul(v, NULL, 0);
}

static void hexdump(const char *label, const uint8_t *b, size_t n) {
    printf("%s (%zu bytes):\n", label, n);
    for (size_t i = 0; i < n; i += 16) {
        printf("  +0x%03zx:", i);
        for (size_t j = 0; j < 16 && i + j < n; j++) printf(" %02x", b[i + j]);
        printf("\n");
    }
}

int main(void) {
    /* Raw, unbuffered proof-of-exec: survives a later SIGKILL (which would
     * otherwise discard buffered stdout, hiding whether we launched at all). */
    (void)!write(2, "ALIVE\n", 6);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("== ipakeep de-platform probe (read-only) ==\n");
    printf("pid=%d\n", getpid());

    /* p_csflags before anything, straight from the kernel via csops. */
    uint32_t csflags = 0;
    if (csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags)) == 0)
        printf("csops CS_OPS_STATUS p_csflags = 0x%08x\n", csflags);
    else
        perror("csops");

    if (jbclient_initialize_primitives() != 0) {
        fprintf(stderr, "jbclient_initialize_primitives failed "
                        "(is this a Dopamine device with libjailbreak?)\n");
        return 1;
    }

    uint64_t proc = proc_self();
    printf("proc_self()        = 0x%016llx\n", (unsigned long long)proc);
    if (!looks_like_kernel_ptr(proc)) {
        fprintf(stderr, "proc pointer does not look like a kernel VA; stopping.\n");
        return 1;
    }
    printf("proc_task(proc)    = 0x%016llx\n",
           (unsigned long long)proc_task(proc));
    printf("proc_getcsflags()  = 0x%08x\n", proc_getcsflags(proc));

    /*
     * Offset discovery (read-only). The jailbreak already knows the kernel
     * struct offsets; dump them instead of patchfinding the kernelcache.
     */
    printf("\n== jbinfo serialized (offset database) ==\n");
    void *info = jbinfo_get_serialized();
    if (info) {
        char *desc = xpc_copy_description(info);
        if (desc) { puts(desc); free(desc); }
        else puts("(xpc_copy_description returned NULL)");
    } else {
        puts("(jbinfo_get_serialized returned NULL)");
    }

    printf("\n== proc_find_main_binary_code_dir(proc) ==\n");
    uint64_t cdir = proc_find_main_binary_code_dir(proc);
    printf("code_dir = 0x%016llx %s\n", (unsigned long long)cdir,
           looks_like_kernel_ptr(cdir) ? "(looks like a kernel VA!)"
                                       : "(not a kernel VA -- likely gated)");
    if (looks_like_kernel_ptr(cdir)) {
        uint8_t buf[0x80];
        if (kreadbuf(cdir, buf, sizeof(buf)) == 0)
            hexdump("code_dir head", buf, sizeof(buf));
    }

    long off_textvp = env_off("IPAKEEP_OFF_P_TEXTVP");
    if (off_textvp < 0) {
        printf("\nIPAKEEP_OFF_P_TEXTVP unset -> stopping at proc.\n"
               "Set it (and the others) once known to walk to the cs_blob.\n");
        return 0;
    }
    uint64_t vnode = kread64(proc + (uint64_t)off_textvp);
    printf("proc.p_textvp @+0x%lx = 0x%016llx\n", off_textvp,
           (unsigned long long)vnode);
    if (!looks_like_kernel_ptr(vnode)) {
        fprintf(stderr, "p_textvp not a kernel VA; offset likely wrong. Stop.\n");
        return 1;
    }

    long off_ubc = env_off("IPAKEEP_OFF_V_UBCINFO");
    if (off_ubc < 0) { printf("\nIPAKEEP_OFF_V_UBCINFO unset -> stop at vnode.\n"); return 0; }
    uint64_t ubc = kread64(vnode + (uint64_t)off_ubc);
    printf("vnode.v_ubcinfo @+0x%lx = 0x%016llx\n", off_ubc,
           (unsigned long long)ubc);
    if (!looks_like_kernel_ptr(ubc)) {
        fprintf(stderr, "v_ubcinfo not a kernel VA; offset likely wrong. Stop.\n");
        return 1;
    }

    long off_csb = env_off("IPAKEEP_OFF_UBC_CSBLOBS");
    if (off_csb < 0) { printf("\nIPAKEEP_OFF_UBC_CSBLOBS unset -> stop at ubc_info.\n"); return 0; }
    uint64_t blob = kread64(ubc + (uint64_t)off_csb);
    printf("ubc_info.cs_blobs @+0x%lx = 0x%016llx\n", off_csb,
           (unsigned long long)blob);

    long off_next = env_off("IPAKEEP_OFF_CSB_NEXT");
    if (off_next < 0) off_next = 0; /* csb_next is the first field in XNU. */

    for (int i = 0; blob && i < 8; i++) {
        if (!looks_like_kernel_ptr(blob)) {
            fprintf(stderr, "cs_blob #%d (0x%016llx) not a kernel VA; stop.\n",
                    i, (unsigned long long)blob);
            break;
        }
        printf("\n-- cs_blob #%d @ 0x%016llx --\n", i,
               (unsigned long long)blob);
        uint8_t buf[0x100];
        if (kreadbuf(blob, buf, sizeof(buf)) == 0)
            hexdump("cs_blob head", buf, sizeof(buf));
        else
            fprintf(stderr, "kreadbuf failed on cs_blob #%d\n", i);
        blob = kread64(blob + (uint64_t)off_next);
    }

    printf("\nRead-only probe done. No kernel memory was written.\n");
    printf("Next: locate the csb_platform_binary bit in the dump above "
           "(diff a platform vs non-platform blob), then the clear helper.\n");
    return 0;
}
