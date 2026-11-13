/*
 * ipakeep lvmap — KTRR-safe unblock of mmap(PROT_EXEC) for FairPlay decrypt.
 *
 * Why not patch the kernel: IDA showed AMFI's mmap hook calls cs_require_lv()
 * which is hardcoded `MOV W0,#1`, so library validation is unconditional. The
 * device is Dopamine (KFD/physrw) on A11 — kernel __TEXT_EXEC is KTRR-locked,
 * so a text patch would panic. But AMFI's LV check (sub_FFFFFFF0056F6B10)
 * ALLOWS the mapping immediately when the MAPPED FILE is a platform binary:
 *     if (csfg_get_platform_binary(file) == 1) return ALLOW;
 * and csfg_get_platform_binary reads one heap bit:
 *     cs_blob + 0xAC, bit 0   (reached via vnode+0x78 -> ubc_info+0x50 -> blob)
 * The cs_blob lives in kalloc heap (writable via physrw, no KTRR). Setting
 * that bit on the target app's own blob makes AMFI treat the file as platform,
 * so ANY process may map it executable — exactly what mremap_encrypted needs.
 * Scoped to this one file, reversible (clear the bit), no kernel text touched.
 *
 * Sequence: open file; attempt PROT_EXEC mmap once to force AMFI to load+cache
 * the cs_blob on the vnode (expected EPERM); walk vnode->ubc->blob chain and
 * set csb_platform_binary on every blob; retry the PROT_EXEC mmap. Success =
 * LV bypassed. Run as root from a jbroot path.
 *
 *   lvmap <path-to-app-macho>
 *
 * ponytail: proves the gate opens; mremap_encrypted + file writeback is the
 * next step once this reports OK (wire into the fouldecrypt backend then).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>

#include "libjailbreak.h"

/* FairPlay decrypt syscall (not in the public SDK headers). */
extern int mremap_encrypted(const void *addr, size_t len, uint32_t cryptid,
                            uint32_t cputype, uint32_t cpusubtype);

#define UBCINFO_OFF  0x78   /* vnode.v_ubcinfo */
#define CSBLOBS_OFF  0x50   /* ubc_info.cs_blobs */
#define CSB_NEXT_OFF 0x00   /* cs_blob.next */
#define CSB_PLAT_OFF 0xAC   /* byte holding csb_platform_binary (bit 0) */

/* Kernel VAs span the heap/physmap (0xffffffe...) and kernelcache (0xfffffff0...). */
static int kptr(uint64_t p) {
    return p >= 0xffffff0000000000ULL && p != 0xffffffffffffffffULL;
}

/* arm64 (non-arm64e) slice file offset, or 0 for a thin file. */
static uint64_t arm64_slice(int fd) {
    uint32_t magic;
    if (pread(fd, &magic, 4, 0) != 4) return 0;
    if (magic != FAT_MAGIC && magic != FAT_CIGAM) return 0;
    struct fat_header fh;
    if (pread(fd, &fh, sizeof(fh), 0) != sizeof(fh)) return 0;
    uint32_t n = OSSwapBigToHostInt32(fh.nfat_arch);
    for (uint32_t i = 0; i < n; i++) {
        struct fat_arch fa;
        if (pread(fd, &fa, sizeof(fa), sizeof(fh) + i * sizeof(fa)) != sizeof(fa)) break;
        if ((cpu_type_t)OSSwapBigToHostInt32(fa.cputype) == CPU_TYPE_ARM64 &&
            (OSSwapBigToHostInt32(fa.cpusubtype) & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64_ALL)
            return OSSwapBigToHostInt32(fa.offset);
    }
    return 0;
}

/*
 * Parse the slice at `base`: fill crypt{off,size,id}, cpu{type,subtype}, and the
 * file offset of the LC_ENCRYPTION_INFO_64 cryptid field (for later clearing).
 * Returns 0 if an encryption command was found.
 */
static int parse_slice(int fd, uint64_t base, uint64_t *coff, uint64_t *csize,
                       uint32_t *cid, uint32_t *cputype, uint32_t *cpusub,
                       uint64_t *cryptid_file_off) {
    struct mach_header_64 mh;
    if (pread(fd, &mh, sizeof(mh), base) != sizeof(mh) || mh.magic != MH_MAGIC_64)
        return -1;
    *cputype = mh.cputype;
    *cpusub  = mh.cpusubtype;
    uint64_t off = base + sizeof(mh);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        struct load_command lc;
        if (pread(fd, &lc, sizeof(lc), off) != sizeof(lc)) break;
        if (lc.cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 e;
            if (pread(fd, &e, sizeof(e), off) != sizeof(e)) break;
            *coff = e.cryptoff; *csize = e.cryptsize; *cid = e.cryptid;
            /* cryptid is the 3rd uint32 in the struct: cmd,cmdsize,cryptoff,cryptsize,cryptid */
            *cryptid_file_off = off + offsetof(struct encryption_info_command_64, cryptid);
            return 0;
        }
        off += lc.cmdsize;
    }
    return -1;
}

/* Try an executable mapping at the crypt region; returns errno (0 = success). */
static int try_exec_map(int fd, uint64_t base, uint64_t co) {
    long ps = sysconf(_SC_PAGESIZE);
    off_t mo = (off_t)(base + co) & ~(ps - 1);
    errno = 0;
    void *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, mo);
    if (p == MAP_FAILED) return errno ? errno : -1;
    munmap(p, (size_t)ps);
    return 0;
}

int main(int argc, char **argv) {
    (void)!write(2, "ALIVE\n", 6);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <macho-path>\n", argv[0]); return 2; }
    const char *path = argv[1];

    if (jbclient_initialize_primitives() != 0) {
        fprintf(stderr, "jbclient init failed (run as root from a jbroot path)\n");
        return 2;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 2; }

    const char *outpath = argc > 2 ? argv[2] : NULL;

    uint64_t base = arm64_slice(fd);
    uint64_t co = 0, csize = 0, cid_foff = 0;
    uint32_t cryptid = 0, cputype = 0, cpusub = 0;
    if (parse_slice(fd, base, &co, &csize, &cryptid, &cputype, &cpusub, &cid_foff) != 0) {
        fprintf(stderr, "no LC_ENCRYPTION_INFO_64 in slice; nothing to decrypt\n");
        close(fd); return 2;
    }
    printf("slice base=0x%llx cryptoff=0x%llx cryptsize=0x%llx cryptid=%u cpu=0x%x/0x%x\n",
           (unsigned long long)base, (unsigned long long)co, (unsigned long long)csize,
           cryptid, cputype, cpusub);

    int r0 = try_exec_map(fd, base, 0);        /* probe the slice's first page */
    printf("pre-patch mmap(RX)@0x%llx = %s\n", (unsigned long long)base,
           r0 == 0 ? "OK (already mappable)" : strerror(r0));

    uint64_t proc = proc_self();
    uint64_t vp = proc_get_vnode_for_fd(proc, fd);
    printf("proc=0x%llx vnode=0x%llx\n", (unsigned long long)proc, (unsigned long long)vp);
    if (!kptr(vp)) { fprintf(stderr, "no vnode for fd; abort\n"); close(fd); return 2; }

    uint64_t ubc = kread64(vp + UBCINFO_OFF);
    uint64_t blob = kptr(ubc) ? kread64(ubc + CSBLOBS_OFF) : 0;
    printf("ubc_info=0x%llx cs_blobs=0x%llx\n", (unsigned long long)ubc, (unsigned long long)blob);
    if (!kptr(blob)) { fprintf(stderr, "no cs_blob cached on vnode; abort\n"); close(fd); return 2; }

    int set = 0;
    for (uint64_t b = blob; kptr(b) && set < 8; b = kread64(b + CSB_NEXT_OFF), set++) {
        uint32_t w = kread32(b + CSB_PLAT_OFF);
        printf("  cs_blob 0x%llx: +0xAC = 0x%08x (platform=%d)",
               (unsigned long long)b, w, w & 1);
        if (!(w & 1)) {
            kwrite32(b + CSB_PLAT_OFF, w | 1u);
            uint32_t v = kread32(b + CSB_PLAT_OFF);
            printf(" -> 0x%08x (platform=%d)%s", v, v & 1, (v & 1) ? "" : " WRITE FAILED");
        }
        printf("\n");
    }

    int r1 = try_exec_map(fd, base, 0);
    printf(">>> post-patch mmap(RX) %s\n",
           r1 == 0 ? "OK — LV BYPASSED (file now platform)" : strerror(r1));
    if (r1 != 0 || !outpath || cryptid == 0) { close(fd); return r1 == 0 ? 0 : 1; }

    /* --- FairPlay decrypt: map the slice RX, mremap_encrypted, write out ---
     * mremap_encrypted needs page-aligned addr/len (process page = 16K here).
     * cryptoff may be only 4K-aligned, so align the window down/up to pages. */
    uint64_t ps = (uint64_t)sysconf(_SC_PAGESIZE);
    uint64_t pa    = co & ~(ps - 1);                      /* page-aligned crypt start */
    uint64_t delta = co - pa;                             /* crypt offset within page */
    uint64_t wlen  = ((delta + csize) + ps - 1) & ~(ps - 1);
    size_t   maplen = (size_t)(pa + wlen);
    void *m = mmap(NULL, maplen, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, (off_t)base);
    if (m == MAP_FAILED) { fprintf(stderr, "slice mmap failed: %s\n", strerror(errno)); close(fd); return 1; }
    errno = 0;
    int mr = mremap_encrypted((char *)m + pa, (size_t)wlen, cryptid, cputype, cpusub);
    printf("mremap_encrypted(addr=m+0x%llx len=0x%llx) rc=%d (%s)\n",
           (unsigned long long)pa, (unsigned long long)wlen, mr, mr ? strerror(errno) : "OK");
    if (mr != 0) { munmap(m, maplen); close(fd); return 1; }
    printf("mremap_encrypted OK; decrypted %llu bytes at cryptoff 0x%llx\n",
           (unsigned long long)csize, (unsigned long long)co);

    /* Copy the whole original file to outpath, then overwrite the crypt region
     * with the decrypted bytes and zero cryptid so the result is a plain Mach-O. */
    off_t fsize = lseek(fd, 0, SEEK_END);
    int ofd = open(outpath, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) { perror("open out"); munmap(m, maplen); close(fd); return 1; }
    size_t bufsz = 1 << 20;
    char *buf = malloc(bufsz);
    if (!buf) { perror("malloc"); close(ofd); munmap(m, maplen); close(fd); return 1; }
    off_t pos = 0;
    while (pos < fsize) {
        ssize_t n = pread(fd, buf, bufsz, pos);
        if (n <= 0) break;
        if (pwrite(ofd, buf, (size_t)n, pos) != n) { perror("copy"); break; }
        pos += n;
    }
    free(buf);
    if (pwrite(ofd, (char *)m + co, (size_t)csize, (off_t)(base + co)) != (ssize_t)csize)
        perror("writeback crypt");
    uint32_t zero = 0;
    if (pwrite(ofd, &zero, 4, (off_t)cid_foff) != 4) perror("clear cryptid");
    close(ofd);
    munmap(m, maplen);
    close(fd);
    printf(">>> wrote decrypted Mach-O to %s (cryptid cleared)\n", outpath);
    return 0;
}
