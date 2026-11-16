#!/usr/bin/env bash
# Optional profile-guided (PGO) release build of ipakeep.
#
# The native ARM64 interpreter is branch-heavy decode/dispatch code, which is
# what PGO helps most. The default build never depends on this script.
# Since the block cache landed, the PGO build measures slower than the plain
# release build on kbsync (see README "Performance"); re-check with --verify
# before relying on it.
#
# Steps:
#   1. build the lib test binary instrumented with -Cprofile-generate;
#   2. train it on the real-asset golden workloads (kbsync, SAP session and
#      ADI provisioning: the emulated Apple guests). These are #[ignore]d
#      tests that need the cached Apple assets; run by exact name so no test
#      downloads the restore image;
#   3. merge the raw profiles with the toolchain's llvm-profdata;
#   4. build `target/pgo/release/ipakeep` (or, with --verify, the lib test
#      binary, and time kbsync with it) using -Cprofile-use.
#
# Requirements: the pinned toolchain's `llvm-tools` component
# (`rustup component add llvm-tools`) and the cached Apple assets used by the
# golden tests.
#
# Usage: scripts/pgo.sh [--verify]
set -euo pipefail

cd "$(dirname "$0")/.."
root=$(pwd)
pgo_dir="$root/target/pgo"
raw_dir="$pgo_dir/raw"
profile="$pgo_dir/merged.profdata"

sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
profdata="$sysroot/lib/rustlib/$host/bin/llvm-profdata"
if [[ ! -x "$profdata" ]]; then
    echo "llvm-profdata not found; run: rustup component add llvm-tools" >&2
    exit 1
fi

train=(
    infrastructure::apple_sap::machine::kbsync::tests::kbsync_reproduces_golden_vectors
    infrastructure::apple_sap::machine::sap::golden_tests::sap_session_reproduces_golden_vectors
    infrastructure::apple_sap::machine::modern_adi::golden_tests::provisioning_reproduces_golden_vectors
)

rm -rf "$raw_dir" "$profile"
mkdir -p "$raw_dir"

echo "==> instrumented build + training run"
RUSTFLAGS="-Cprofile-generate=$raw_dir" CARGO_TARGET_DIR="$pgo_dir/gen" \
    cargo test --release --lib --locked -- --ignored --exact --test-threads=1 "${train[@]}"

echo "==> merging profiles"
"$profdata" merge -o "$profile" "$raw_dir"

# The training ran the cfg(test) build of the crate; functions that differ in
# the non-test binary just get no profile, so mismatch warnings are noise.
use_flags="-Cprofile-use=$profile -Cllvm-args=-no-pgo-warn-mismatch"

if [[ "${1:-}" == "--verify" ]]; then
    echo "==> PGO-optimized test binary: kbsync timing"
    RUSTFLAGS="$use_flags" CARGO_TARGET_DIR="$pgo_dir/use" \
        cargo test --release --lib --locked -- --ignored --exact --test-threads=1 "${train[0]}"
else
    echo "==> PGO-optimized release binary"
    RUSTFLAGS="$use_flags" CARGO_TARGET_DIR="$pgo_dir" cargo build --release --locked
    echo "binary: $pgo_dir/release/ipakeep"
fi
