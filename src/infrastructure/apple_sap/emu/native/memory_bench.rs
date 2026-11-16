//! Micro-benchmark of guest [`Memory`] data accesses.
//!
//! It runs as an ordinary (fast) unit test with a small iteration count so it
//! stays covered and cheap; set `IPAKEEP_MEM_BENCH_ITERS` (e.g. `20000000`)
//! and run it in release with `--nocapture` to print ns/access per pattern:
//!
//! ```text
//! IPAKEEP_MEM_BENCH_ITERS=20000000 cargo test --release --lib \
//!   memory_bench -- --nocapture --test-threads=1
//! ```
//!
//! The patterns mimic the interpreter's load/store traffic: one hot page (a
//! stack frame), a few interleaved pages (stack + heap + globals, which
//! thrashes a one-entry cache), random pages within a small working set, a
//! working set larger than any small cache, and page-straddling accesses.

#![allow(clippy::cast_precision_loss)]

use std::hint::black_box;
use std::time::Instant;

use super::{Memory, PAGE_SIZE};

/// Base of the benchmark's mapped region.
const BASE: u64 = 0x1_0000_0000;
/// Pages mapped for the benchmark (covers the largest working set).
const PAGES: u64 = 2048;

/// Deterministic xorshift64 address stream.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Runs `iters` 8-byte loads (or stores) over `set` pages using `pick` to
/// choose each page, and returns (ns/access, checksum).
fn run(
    mem: &mut Memory,
    iters: u64,
    set: u64,
    store: bool,
    pick: impl Fn(u64, u64) -> u64,
) -> (f64, u64) {
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut sum = 0u64;
    let start = Instant::now();
    for i in 0..iters {
        let r = next(&mut rng);
        let page = pick(i, r) % set;
        let addr = BASE + page * PAGE_SIZE + ((r >> 20) & 0xff8);
        if store {
            mem.write(black_box(addr), &i.to_le_bytes()).unwrap();
        } else {
            let mut buf = [0u8; 8];
            mem.read(black_box(addr), &mut buf).unwrap();
            sum = sum.wrapping_add(u64::from_le_bytes(buf));
        }
    }
    let ns = start.elapsed().as_nanos() as f64 / iters as f64;
    (ns, black_box(sum))
}

#[test]
fn memory_bench() {
    let iters: u64 = std::env::var("IPAKEEP_MEM_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut mem = Memory::default();
    mem.map(BASE, PAGES * PAGE_SIZE);
    // Distinct non-zero contents so the load checksum depends on the page.
    for page in 0..PAGES {
        mem.write(BASE + page * PAGE_SIZE + 8, &(page + 1).to_le_bytes())
            .unwrap();
    }
    let cases: [(&str, u64, bool, fn(u64, u64) -> u64); 7] = [
        ("load  1 page        ", 1, false, |_, _| 0),
        ("load  3 interleaved ", 3, false, |i, _| i),
        ("load  32 random     ", 32, false, |_, r| r),
        ("load  2048 random   ", PAGES, false, |_, r| r),
        ("store 1 page        ", 1, true, |_, _| 0),
        ("store 3 interleaved ", 3, true, |i, _| i),
        ("store 32 random     ", 32, true, |_, r| r),
    ];
    for (name, set, store, pick) in cases {
        let (ns, sum) = run(&mut mem, iters, set, store, pick);
        eprintln!("memory_bench {name} {ns:7.2} ns/access (checksum {sum:#x})");
    }
    // Page-straddling 8-byte loads (slow path).
    let mut buf = [0u8; 8];
    let start = Instant::now();
    for i in 0..iters {
        let addr = BASE + (i % (PAGES - 1) + 1) * PAGE_SIZE - 4;
        mem.read(black_box(addr), &mut buf).unwrap();
    }
    let ns = start.elapsed().as_nanos() as f64 / iters as f64;
    eprintln!("memory_bench load  straddling     {ns:7.2} ns/access");
    assert!(mem.read(BASE + PAGES * PAGE_SIZE - 4, &mut buf).is_err());
}
