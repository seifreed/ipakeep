/*
 * Minimal declarations for the subset of Dopamine's libjailbreak (BaseBin)
 * that the ipakeep de-platform helper uses. The real library ships on a
 * Dopamine device at /var/jb/usr/lib/libjailbreak.dylib; it exposes kernel
 * read/write and code-signing helpers over the jbserver XPC channel.
 *
 * We declare only what we call so the helper compiles against the device's
 * dylib without needing Dopamine's full (unshipped) headers. Symbol names and
 * signatures are taken from the BaseBin iOS 16 arm64 export table.
 *
 * ponytail: hand-written stub header over vendoring BaseBin; extend only when
 * a new export is actually called.
 */
#ifndef IPAKEEP_LIBJAILBREAK_H
#define IPAKEEP_LIBJAILBREAK_H

#include <stdint.h>
#include <stddef.h>

/* Bring up the kernel R/W primitives (connects to jbserver). 0 on success. */
int jbclient_initialize_primitives(void);

/* Kernel pointer to the calling process's `struct proc`. 0 on failure. */
uint64_t proc_self(void);

/* Kernel pointer to a proc's `task`. */
uint64_t proc_task(uint64_t proc);

/* p_csflags accessor (process-level CS_* flags; NOT where platform lives). */
uint32_t proc_getcsflags(uint64_t proc);

/* Kernel memory reads. kreadbuf copies `size` bytes from kernel VA `kaddr`. */
uint32_t kread32(uint64_t kaddr);
uint64_t kread64(uint64_t kaddr);
int kreadbuf(uint64_t kaddr, void *buf, size_t size);

/*
 * Kernel memory writes. On Dopamine these are physical-write backed (physrw),
 * so they reach read-only-mapped kernel memory such as the proc_ro structure
 * (where the platform flag lives) -- an ordinary virtual write could not.
 */
void kwrite32(uint64_t kaddr, uint32_t value);
void kwrite64(uint64_t kaddr, uint64_t value);

/*
 * Offset discovery. jbinfo_get_serialized returns an xpc dictionary of the
 * jailbreak's boot constants and kernel struct offsets; xpc_copy_description
 * renders any xpc object as readable text. proc_find_main_binary_code_dir
 * resolves a proc's main-binary code directory in kernel memory (reportedly
 * arm64e-gated -- the probe tests whether it works on this A11 anyway).
 * Signatures are best-effort from the export table; the probe only reads.
 */
void *jbinfo_get_serialized(void);
char *xpc_copy_description(void *object);
uint64_t proc_find_main_binary_code_dir(uint64_t proc);

#endif /* IPAKEEP_LIBJAILBREAK_H */
