#include <assert.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <libkern/OSByteOrder.h>

static unsigned char mapped_bytes[32768];
static void *test_mmap(void *, size_t, int, int, int, off_t);
static int test_munmap(void *, size_t);
static ssize_t test_pwrite(int, const void *, size_t, off_t);

#define mmap test_mmap
#define munmap test_munmap
#define pwrite test_pwrite
#define main lvmap_program_main
#include "lvmap.c"
#undef main
#undef pwrite
#undef mmap
#undef munmap

#define KERNEL_BASE 0xffffffe000000000ULL
#define VNODE (KERNEL_BASE + 0x1000)
#define UBC (KERNEL_BASE + 0x2000)
#define BLOB (KERNEL_BASE + 0x3000)

static int init_result;
static uint64_t vnode_result = VNODE;
static uint64_t blob_result = BLOB;
static uint32_t platform_word = 1;
static int kernel_writes;
static int decrypt_calls;
static int fail_mmap;
static int fail_writeback;

int jbclient_initialize_primitives(void) { return init_result; }
uint64_t proc_self(void) { return KERNEL_BASE; }
uint64_t proc_get_vnode_for_fd(uint64_t proc, int fd) {
    assert(proc == KERNEL_BASE);
    assert(fd >= 0);
    return vnode_result;
}
uint64_t kread64(uint64_t address) {
    if (address == VNODE + UBCINFO_OFF) return UBC;
    if (address == UBC + CSBLOBS_OFF) return blob_result;
    return 0;
}
uint32_t kread32(uint64_t address) {
    return address == BLOB + CSB_PLAT_OFF ? platform_word : 0;
}
void kwrite32(uint64_t address, uint32_t value) {
    assert(address == BLOB + CSB_PLAT_OFF);
    platform_word = value;
    kernel_writes++;
}
int mremap_encrypted(const void *addr, size_t len, uint32_t cryptid,
                     uint32_t cputype, uint32_t cpusubtype) {
    (void)cryptid;
    (void)cputype;
    (void)cpusubtype;
    decrypt_calls++;
    memset((void *)addr, 0x42, len);
    return 0;
}
static void *test_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    (void)addr;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)off;
    if (fail_mmap) {
        errno = EACCES;
        return MAP_FAILED;
    }
    return len <= sizeof(mapped_bytes) ? mapped_bytes : MAP_FAILED;
}
static int test_munmap(void *addr, size_t len) {
    (void)addr;
    (void)len;
    return 0;
}
static ssize_t test_pwrite(int fd, const void *buffer, size_t length, off_t offset) {
    if (fail_writeback && offset == 4096 && length == 4096) {
        errno = EIO;
        return -1;
    }
    return pwrite(fd, buffer, length, offset);
}

static int make_macho(uint32_t cryptid, int has_encryption) {
    char path[] = "/tmp/ipakeep-macho-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(unlink(path) == 0);
    assert(ftruncate(fd, 8192) == 0);
    struct mach_header_64 header = {
        .magic = MH_MAGIC_64,
        .cputype = CPU_TYPE_ARM64,
        .cpusubtype = CPU_SUBTYPE_ARM64_ALL,
        .filetype = MH_EXECUTE,
        .ncmds = has_encryption ? 1 : 0,
        .sizeofcmds = has_encryption ? sizeof(struct encryption_info_command_64) : 0,
    };
    assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
    if (has_encryption) {
        struct encryption_info_command_64 command = {
            .cmd = LC_ENCRYPTION_INFO_64,
            .cmdsize = sizeof(command),
            .cryptoff = 4096,
            .cryptsize = 4096,
            .cryptid = cryptid,
        };
        assert(pwrite(fd, &command, sizeof(command), sizeof(header)) == sizeof(command));
    }
    return fd;
}

static int make_fat_macho(cpu_type_t cputype) {
    char path[] = "/tmp/ipakeep-fat-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(unlink(path) == 0);
    assert(ftruncate(fd, 8192) == 0);
    const uint32_t slice_offset = 0x100;
    struct fat_header header = {
        .magic = FAT_MAGIC,
        .nfat_arch = OSSwapHostToBigInt32(1),
    };
    struct fat_arch arch = {
        .cputype = OSSwapHostToBigInt32(cputype),
        .cpusubtype = OSSwapHostToBigInt32(CPU_SUBTYPE_ARM64_ALL),
        .offset = OSSwapHostToBigInt32(slice_offset),
        .size = OSSwapHostToBigInt32(4096),
    };
    struct mach_header_64 macho = {
        .magic = MH_MAGIC_64,
        .cputype = CPU_TYPE_ARM64,
        .cpusubtype = CPU_SUBTYPE_ARM64_ALL,
    };
    assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
    assert(pwrite(fd, &arch, sizeof(arch), sizeof(header)) == sizeof(arch));
    assert(pwrite(fd, &macho, sizeof(macho), slice_offset) == sizeof(macho));
    return fd;
}

static void test_pointer_and_parser_helpers(void) {
    assert(kptr(KERNEL_BASE));
    assert(!kptr(0));
    assert(!kptr(0xffffffffffffffffULL));
    assert(arm64_slice(-1) == 0);

    int fd = make_macho(1, 1);
    uint64_t cryptoff = 0, cryptsize = 0, cryptid_offset = 0;
    uint32_t cryptid = 0, cputype = 0, cpusub = 0;
    assert(parse_slice(fd, 0, &cryptoff, &cryptsize, &cryptid, &cputype,
                       &cpusub, &cryptid_offset) == 0);
    assert(cryptoff == 4096 && cryptsize == 4096 && cryptid == 1);
    assert(cputype == CPU_TYPE_ARM64 && cpusub == CPU_SUBTYPE_ARM64_ALL);
    assert(cryptid_offset == sizeof(struct mach_header_64) +
                             offsetof(struct encryption_info_command_64, cryptid));
    close(fd);

    fd = make_fat_macho(CPU_TYPE_ARM64);
    assert(arm64_slice(fd) == 0x100);
    close(fd);

    fd = make_fat_macho(CPU_TYPE_X86_64);
    assert(arm64_slice(fd) == 0);
    close(fd);

    fd = make_macho(0, 0);
    assert(parse_slice(fd, 0, &cryptoff, &cryptsize, &cryptid, &cputype,
                       &cpusub, &cryptid_offset) == -1);
    close(fd);

    char invalid_path[] = "/tmp/ipakeep-invalid-macho-XXXXXX";
    fd = mkstemp(invalid_path);
    assert(fd >= 0);
    assert(unlink(invalid_path) == 0);
    struct mach_header_64 invalid_header = {.magic = MH_MAGIC};
    assert(pwrite(fd, &invalid_header, sizeof(invalid_header), 0) == sizeof(invalid_header));
    assert(parse_slice(fd, 0, &cryptoff, &cryptsize, &cryptid, &cputype,
                       &cpusub, &cryptid_offset) == -1);
    close(fd);

    char path[] = "/tmp/ipakeep-load-command-XXXXXX";
    fd = mkstemp(path);
    assert(fd >= 0);
    assert(unlink(path) == 0);
    struct mach_header_64 header = {.magic = MH_MAGIC_64, .ncmds = 1};
    struct load_command command = {.cmd = LC_SEGMENT_64, .cmdsize = sizeof(command)};
    assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
    assert(pwrite(fd, &command, sizeof(command), sizeof(header)) == sizeof(command));
    assert(parse_slice(fd, 0, &cryptoff, &cryptsize, &cryptid, &cputype,
                       &cpusub, &cryptid_offset) == -1);
    close(fd);
}

static void test_program_validation_and_kernel_failures(void) {
    char *no_args[] = {"lvmap"};
    assert(lvmap_program_main(1, no_args) == 2);
    init_result = -1;
    char *missing[] = {"lvmap", "/not/a/file"};
    assert(lvmap_program_main(2, missing) == 2);
    init_result = 0;
    assert(lvmap_program_main(2, missing) == 2);

    int fd = make_macho(1, 0);
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", fd);
    char *bad_slice[] = {"lvmap", fd_path};
    assert(lvmap_program_main(2, bad_slice) == 2);
    close(fd);

    fd = make_macho(1, 1);
    snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", fd);
    char *valid[] = {"lvmap", fd_path};
    vnode_result = 0;
    assert(lvmap_program_main(2, valid) == 2);
    vnode_result = VNODE;
    blob_result = 0;
    assert(lvmap_program_main(2, valid) == 2);
    blob_result = BLOB;
    vnode_result = VNODE;
    close(fd);
}

static void test_safe_mmap_path_skips_decryption(void) {
    init_result = 0;
    vnode_result = VNODE;
    blob_result = BLOB;
    platform_word = 1;
    kernel_writes = 0;
    decrypt_calls = 0;
    int fd = make_macho(1, 1);
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", fd);
    char *without_output[] = {"lvmap", fd_path};
    assert(lvmap_program_main(2, without_output) == 0);
    assert(kernel_writes == 0);
    assert(decrypt_calls == 0);

    platform_word = 0;
    kernel_writes = 0;
    char output_path[] = "/tmp/ipakeep-output-XXXXXX";
    int outfd = mkstemp(output_path);
    assert(outfd >= 0);
    close(outfd);
    char *with_output[] = {"lvmap", fd_path, output_path};
    assert(lvmap_program_main(3, with_output) == 0);
    assert(kernel_writes == 1 && decrypt_calls == 1);
    outfd = open(output_path, O_RDONLY);
    assert(outfd >= 0);
    uint32_t cleared_cryptid = 1;
    assert(pread(outfd, &cleared_cryptid, sizeof(cleared_cryptid),
                 sizeof(struct mach_header_64) +
                     offsetof(struct encryption_info_command_64, cryptid)) == sizeof(cleared_cryptid));
    assert(cleared_cryptid == 0);
    close(outfd);
    unlink(output_path);

    platform_word = 0;
    kernel_writes = 0;
    char writeback_path[] = "/tmp/ipakeep-writeback-XXXXXX";
    outfd = mkstemp(writeback_path);
    assert(outfd >= 0);
    close(outfd);
    char *writeback[] = {"lvmap", fd_path, writeback_path};
    fail_writeback = 1;
    assert(lvmap_program_main(3, writeback) == 0);
    fail_writeback = 0;
    unlink(writeback_path);

    fail_mmap = 1;
    assert(lvmap_program_main(2, without_output) == 1);
    fail_mmap = 0;
    close(fd);
}

int main(void) {
    test_pointer_and_parser_helpers();
    test_program_validation_and_kernel_failures();
    test_safe_mmap_path_skips_decryption();
    return 0;
}
