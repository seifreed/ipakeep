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

#endif /* IPAKEEP_LIBJAILBREAK_H */
