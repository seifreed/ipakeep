//! The only `unsafe` code of the JIT tier: entering generated code and
//! releasing the executable memory that holds it.

use cranelift_jit::JITModule;

use super::JitCtx;

/// Signature of every compiled block.
type BlockFn = extern "C" fn(*mut JitCtx) -> u32;

/// Runs the compiled block at `code` on `ctx` and returns its exit status.
#[allow(unsafe_code)]
pub(super) fn call_block(code: *const u8, ctx: &mut JitCtx) -> u32 {
    // SAFETY: `code` comes from `JITModule::get_finalized_function` for a
    // function declared with exactly the `BlockFn` signature (one pointer
    // parameter, one `u32` result, the host's default C calling convention),
    // and the module that owns that memory lives as long as the `Jit` that
    // holds the pointer (it is only freed in `release`, on drop). The generated
    // code reads and writes only:
    //   * `ctx` (exclusively borrowed here, `#[repr(C)]`, offsets taken with
    //     `offset_of!`), and
    //   * guest page frames through host pointers in `ctx.tlb`, each obtained
    //     from a live `Memory` frame of the CPU that is exclusively borrowed by
    //     the caller for the whole call; the TLB is flushed whenever pages are
    //     mapped or unmapped, so no stale frame pointer survives. Every access
    //     is bounds-checked in the generated code to stay inside its 4 KiB
    //     frame.
    // The generated code never unwinds, traps or calls back into Rust.
    unsafe {
        let block = std::mem::transmute::<*const u8, BlockFn>(code);
        block(ctx)
    }
}

/// Frees the executable memory of `module`.
#[allow(unsafe_code)]
pub(super) fn release(module: JITModule) {
    // SAFETY: called only from `Jit::drop`, after which no function pointer
    // obtained from this module (all stored in that `Jit`) can be called.
    unsafe { module.free_memory() }
}
