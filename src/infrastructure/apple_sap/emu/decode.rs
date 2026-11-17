//! Pure A64 instruction *classifier* — no execution.
//!
//! Decodes a 32-bit little-endian ARM64 (AArch64) instruction word into its
//! top-level encoding class ([`A64Class`], from the Arm Architecture Reference
//! Manual "A64 instruction set encoding", bits `[28:25]` = `op0`) and, for the
//! common instructions ipakeep's guest executes, a best-effort mnemonic. This
//! lets a caller build a meaningful opcode histogram without pulling in a full
//! disassembler. Nothing here reads memory, touches a CPU, or depends on any
//! external crate, so it compiles even when the emulator is stubbed out.
//!
//! The decode is deliberately partial: it resolves every top-level class
//! exactly, and names the integer / branch / load-store / system instructions a
//! typical SAP guest uses. Scalar-FP, NEON/SIMD and crypto encodings collapse to
//! a coarse `"simd/fp"` family tag (with a few easily-decoded exceptions such as
//! `EOR3`, `BCAX` and the `AES*` round helpers). Anything unresolved returns
//! `"unknown (<Class>)"`.
// Dense bit-encoded instruction literals and field extraction make these
// pedantic lints noise in a decoder.
#![allow(
    clippy::unreadable_literal,
    clippy::match_same_arms,
    clippy::unnested_or_patterns,
    clippy::verbose_bit_mask,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]

/// Top-level A64 encoding groups, selected by `op0` (`word[28:25]`) and its
/// neighbouring bits per the Arm ARM "A64 instruction set encoding" table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A64Class {
    /// `op0 == 0b0000`: the reserved encoding space (e.g. `UDF`).
    Reserved,
    /// Unallocated / not decoded here (includes the SVE space, `op0 == 0b0010`).
    Unallocated,
    /// Data Processing -- Immediate: PC-rel `ADR`/`ADRP`, add/sub immediate,
    /// logical immediate, move wide, bitfield and extract.
    DataProcImm,
    /// Branches, Exception Generating and System instructions.
    BranchSystem,
    /// Loads and Stores: register, pair, exclusive, literal, atomic (LSE) and
    /// load/store-ordered forms.
    LoadStore,
    /// Data Processing -- Register: logical/arithmetic shifted & extended,
    /// add/sub with carry, conditional compare/select, 1/2/3-source.
    DataProcReg,
    /// Data Processing -- Scalar Floating-Point and Advanced SIMD (incl. crypto).
    DataProcSimdFp,
}

/// Classify `word` into its top-level A64 encoding group.
///
/// Dispatch mirrors the Arm ARM top-level table on `op0 = word[28:25]`:
/// `x1x0` → loads/stores, `x101` → data-proc register, `x111` → SIMD/FP,
/// `100x` → data-proc immediate, `101x` → branch/system, `0000` → reserved,
/// and the remaining `op0` values (`0001`, `0010` SVE, `0011`) → unallocated.
pub fn classify(word: u32) -> A64Class {
    let op0 = (word >> 25) & 0xf;
    let bit27 = (op0 >> 2) & 1;
    let bit26 = (op0 >> 1) & 1;
    let bit25 = op0 & 1;

    if bit27 == 1 {
        // op0 == x1xx
        if bit25 == 0 {
            A64Class::LoadStore // x1x0
        } else if bit26 == 0 {
            A64Class::DataProcReg // x101
        } else {
            A64Class::DataProcSimdFp // x111
        }
    } else {
        match op0 {
            0b1000 | 0b1001 => A64Class::DataProcImm,
            0b1010 | 0b1011 => A64Class::BranchSystem,
            0b0000 => A64Class::Reserved,
            // 0b0001, 0b0010 (SVE), 0b0011.
            _ => A64Class::Unallocated,
        }
    }
}

/// Best-effort specific mnemonic for `word`, or `"unknown (<Class>)"`.
///
/// Test-only: its sole caller is the opcode-histogram probe test; the
/// interpreter itself needs only [`classify`].
#[cfg(test)]
pub fn mnemonic(word: u32) -> &'static str {
    match classify(word) {
        A64Class::DataProcImm => dp_imm(word),
        A64Class::BranchSystem => branch_system(word),
        A64Class::LoadStore => load_store(word),
        A64Class::DataProcReg => dp_reg(word),
        A64Class::DataProcSimdFp => simd_fp(word),
        A64Class::Reserved => "UDF",
        A64Class::Unallocated => "unknown (Unallocated)",
    }
}

// ---------------------------------------------------------------------------
// Data Processing -- Immediate (op0 == 100x). Sub-group is word[25:23].
// ---------------------------------------------------------------------------

#[cfg(test)]
fn dp_imm(word: u32) -> &'static str {
    match (word >> 23) & 0x7 {
        // PC-relative addressing: bit31 selects ADR (0) vs ADRP (1).
        0b000 | 0b001 => {
            if (word >> 31) & 1 == 0 {
                "ADR"
            } else {
                "ADRP"
            }
        }
        // Add/subtract (immediate): word[30]=op, word[29]=S.
        0b010 => match (word >> 29) & 0x3 {
            0b00 => "ADD",
            0b01 => "ADDS",
            0b10 => "SUB",
            0b11 => "SUBS",
            _ => unreachable!(),
        },
        // Add/subtract (immediate, with tags).
        0b011 => "ADDG/SUBG",
        // Logical (immediate): word[30:29]=opc.
        0b100 => match (word >> 29) & 0x3 {
            0b00 => "AND",
            0b01 => "ORR",
            0b10 => "EOR",
            0b11 => "ANDS",
            _ => unreachable!(),
        },
        // Move wide (immediate): word[30:29]=opc (01 is unallocated).
        0b101 => match (word >> 29) & 0x3 {
            0b00 => "MOVN",
            0b10 => "MOVZ",
            0b11 => "MOVK",
            _ => "movewide",
        },
        // Bitfield: word[30:29]=opc (11 is unallocated).
        0b110 => match (word >> 29) & 0x3 {
            0b00 => "SBFM",
            0b01 => "BFM",
            0b10 => "UBFM",
            _ => "bitfield",
        },
        // Extract.
        0b111 => "EXTR",
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Branches, Exception Generating and System instructions (op0 == 101x).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn branch_system(word: u32) -> &'static str {
    // Unconditional branch (immediate): word[30:26] == 00101.
    match (word >> 26) & 0x3f {
        0b000101 => return "B",
        0b100101 => return "BL",
        _ => {}
    }

    // Compare-and-branch / test-and-branch: word[30:25].
    match (word >> 25) & 0x3f {
        0b011010 => {
            return if (word >> 24) & 1 == 0 { "CBZ" } else { "CBNZ" };
        }
        0b011011 => {
            return if (word >> 24) & 1 == 0 { "TBZ" } else { "TBNZ" };
        }
        _ => {}
    }

    // Conditional branch (immediate): word[31:24] == 0x54, word[4] == 0.
    if word & 0xff00_0010 == 0x5400_0000 {
        return "B.cond";
    }

    // Unconditional branch (register): word[31:25] == 1101011, opc at [24:21].
    if (word >> 25) & 0x7f == 0b1101011 {
        return match (word >> 21) & 0xf {
            0b0000 => "BR",
            0b0001 => "BLR",
            0b0010 => "RET",
            0b0100 => "ERET",
            0b0101 => "DRPS",
            _ => "br (reg)",
        };
    }

    // Exception generation: word[31:24] == 11010100.
    if (word >> 24) & 0xff == 0b1101_0100 {
        let opc = (word >> 21) & 0x7;
        let ll = word & 0x3;
        return match (opc, ll) {
            (0b000, 0b01) => "SVC",
            (0b000, 0b10) => "HVC",
            (0b000, 0b11) => "SMC",
            (0b001, 0b00) => "BRK",
            (0b010, 0b00) => "HLT",
            (0b101, 0b01) => "DCPS1",
            (0b101, 0b10) => "DCPS2",
            (0b101, 0b11) => "DCPS3",
            _ => "exception",
        };
    }

    system(word)
}

#[cfg(test)]
fn system(word: u32) -> &'static str {
    // System register move: word[31:20] == 0xD53 (MRS) / 0xD51 (MSR register).
    match (word >> 20) & 0xfff {
        0xd53 => return "MRS",
        0xd51 => return "MSR",
        _ => {}
    }

    // Hints (CRn == 0010, Rt == 11111): word[31:12] == 0xD5032.
    if word & 0xffff_f01f == 0xd503_201f {
        return match ((word >> 8) & 0xf, (word >> 5) & 0x7) {
            (0b0000, 0b000) => "NOP",
            (0b0000, 0b001) => "YIELD",
            (0b0000, 0b010) => "WFE",
            (0b0000, 0b011) => "WFI",
            (0b0000, 0b100) => "SEV",
            (0b0000, 0b101) => "SEVL",
            _ => "HINT",
        };
    }

    // Barriers (CRn == 0011, Rt == 11111): word[31:12] == 0xD5033.
    if word & 0xffff_f01f == 0xd503_301f {
        return match (word >> 5) & 0x7 {
            0b010 => "CLREX",
            0b100 => "DSB",
            0b101 => "DMB",
            0b110 => "ISB",
            0b111 => "SB",
            _ => "barrier",
        };
    }

    // MSR (immediate) to PSTATE: CRn == 0100, Rt == 11111.
    if word & 0xfff8_f01f == 0xd500_401f {
        return "MSR";
    }

    "system"
}

// ---------------------------------------------------------------------------
// Loads and Stores (op0 == x1x0).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn load_store(word: u32) -> &'static str {
    // Load/store exclusive + load/store ordered + compare-and-swap all share
    // word[29:24] == 001000.
    if (word >> 24) & 0x3f == 0b001000 {
        return ldst_exclusive(word);
    }

    let group = (word >> 27) & 0x7; // word[29:27]

    // Atomic memory operations / SWP (LSE): word[29:27]=111, V=0,
    // word[25:24]=00, word[21]=1, word[11:10]=00.
    if group == 0b111
        && (word >> 26) & 1 == 0
        && (word >> 24) & 0x3 == 0b00
        && (word >> 21) & 1 == 1
        && (word >> 10) & 0x3 == 0b00
    {
        return ldst_atomic(word);
    }

    match group {
        0b111 => ldst_register(word),
        // Load/store register pair: word[22]=L.
        0b101 => {
            if (word >> 22) & 1 == 0 {
                "STP"
            } else {
                "LDP"
            }
        }
        // Load register (literal): word[25:24] == 00.
        0b011 if (word >> 24) & 0x3 == 0b00 => ldst_literal(word),
        // Advanced SIMD load/store (multiple / single structures).
        0b001 => "ld/st (simd)",
        _ => "unknown (LoadStore)",
    }
}

#[cfg(test)]
fn ldst_exclusive(word: u32) -> &'static str {
    let o2 = (word >> 23) & 1;
    let l = (word >> 22) & 1;
    let o1 = (word >> 21) & 1;
    let o0 = (word >> 15) & 1;

    match (o2, o1) {
        // Exclusive, single register.
        (0, 0) => match (l, o0) {
            (0, 0) => "STXR",
            (0, 1) => "STLXR",
            (1, 0) => "LDXR",
            (1, 1) => "LDAXR",
            _ => unreachable!(),
        },
        // Exclusive pair.
        (0, 1) => {
            if l == 0 {
                "STXP"
            } else {
                "LDXP"
            }
        }
        // Load/store ordered (acquire/release).
        (1, 0) => match (l, o0) {
            (0, 0) => "STLLR",
            (0, 1) => "STLR",
            (1, 0) => "LDLAR",
            (1, 1) => "LDAR",
            _ => unreachable!(),
        },
        // Compare and swap: L is the acquire bit, o0 the release bit.
        (1, 1) => match (l, o0) {
            (0, 0) => "CAS",
            (1, 0) => "CASA",
            (0, 1) => "CASL",
            (1, 1) => "CASAL",
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[cfg(test)]
fn ldst_atomic(word: u32) -> &'static str {
    let o3 = (word >> 15) & 1;
    let opc = (word >> 12) & 0x7;

    if o3 == 1 && opc == 0b000 {
        // SWP: word[23]=A (acquire), word[22]=R (release).
        let (a, r) = ((word >> 23) & 1, (word >> 22) & 1);
        return [["SWP", "SWPL"], ["SWPA", "SWPAL"]][a as usize][r as usize];
    }

    if o3 == 0 {
        // LD<op>/ST<op> read-modify-write family.
        // Indexed by opc (3 bits, so every index is in range).
        return [
            "LDADD", "LDCLR", "LDEOR", "LDSET", "LDSMAX", "LDSMIN", "LDUMAX", "LDUMIN",
        ][opc as usize];
    }

    "atomic (LSE)"
}

#[cfg(test)]
fn ldst_literal(word: u32) -> &'static str {
    // word[31:30] = opc: 00 LDR(32), 01 LDR(64), 10 LDRSW, 11 PRFM.
    match (word >> 30) & 0x3 {
        0b00 | 0b01 => "LDR",
        0b10 => "LDRSW",
        0b11 => "PRFM",
        _ => unreachable!(),
    }
}

#[cfg(test)]
fn ldst_register(word: u32) -> &'static str {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    let opc = (word >> 22) & 0x3;

    // Unscaled immediate (LDUR/STUR): word[25:24]=00, word[21]=0, word[11:10]=00.
    let unscaled =
        (word >> 24) & 0x3 == 0b00 && (word >> 21) & 1 == 0 && (word >> 10) & 0x3 == 0b00;

    if v == 1 {
        ldst_fp(opc, unscaled)
    } else {
        ldst_integer(size, opc, unscaled)
    }
}

#[cfg(test)]
fn ldst_fp(opc: u32, unscaled: bool) -> &'static str {
    // For SIMD/FP load/store the low opc bit is the load flag.
    match (opc & 1, unscaled) {
        (1, true) => "LDUR",
        (1, false) => "LDR",
        (_, true) => "STUR",
        (_, false) => "STR",
    }
}

#[cfg(test)]
fn ldst_integer(size: u32, opc: u32, unscaled: bool) -> &'static str {
    // size: 11=doubleword, 10=word, 01=halfword, 00=byte.
    // opc:  00=store, 01=load, 10/11=load signed.
    match (size, opc, unscaled) {
        (0b11, 0b00, false) => "STR",
        (0b11, 0b01, false) => "LDR",
        (0b11, 0b10, false) => "PRFM",
        (0b11, 0b00, true) => "STUR",
        (0b11, 0b01, true) => "LDUR",
        (0b11, 0b10, true) => "PRFUM",

        (0b10, 0b00, false) => "STR",
        (0b10, 0b01, false) => "LDR",
        (0b10, 0b10, false) => "LDRSW",
        (0b10, 0b00, true) => "STUR",
        (0b10, 0b01, true) => "LDUR",
        (0b10, 0b10, true) => "LDURSW",

        (0b01, 0b00, false) => "STRH",
        (0b01, 0b01, false) => "LDRH",
        (0b01, 0b10, false) | (0b01, 0b11, false) => "LDRSH",
        (0b01, 0b00, true) => "STURH",
        (0b01, 0b01, true) => "LDURH",
        (0b01, 0b10, true) | (0b01, 0b11, true) => "LDURSH",

        (0b00, 0b00, false) => "STRB",
        (0b00, 0b01, false) => "LDRB",
        (0b00, 0b10, false) | (0b00, 0b11, false) => "LDRSB",
        (0b00, 0b00, true) => "STURB",
        (0b00, 0b01, true) => "LDURB",
        (0b00, 0b10, true) | (0b00, 0b11, true) => "LDURSB",

        _ => "unknown (LoadStore)",
    }
}

// ---------------------------------------------------------------------------
// Data Processing -- Register (op0 == x101).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn dp_reg(word: u32) -> &'static str {
    let op = (word >> 24) & 0x1f; // word[28:24]

    // Logical (shifted register): word[30:29]=opc, word[21]=N.
    if op == 0b01010 {
        // Indexed by [opc][N].
        return [
            ["AND", "BIC"],
            ["ORR", "ORN"],
            ["EOR", "EON"],
            ["ANDS", "BICS"],
        ][((word >> 29) & 0x3) as usize][((word >> 21) & 1) as usize];
    }

    // Add/subtract (shifted or extended register): word[30]=op, word[29]=S.
    if op == 0b01011 {
        // Indexed by op:S.
        return ["ADD", "ADDS", "SUB", "SUBS"][((word >> 29) & 0x3) as usize];
    }

    // Data-processing (3 source): word[30:29]=op54, word[23:21]=op31, word[15]=o0.
    if op == 0b11011 {
        return match ((word >> 21) & 0x7, (word >> 15) & 1) {
            (0b000, 0) => "MADD",
            (0b000, 1) => "MSUB",
            (0b001, 0) => "SMADDL",
            (0b001, 1) => "SMSUBL",
            (0b010, 0) => "SMULH",
            (0b101, 0) => "UMADDL",
            (0b101, 1) => "UMSUBL",
            (0b110, 0) => "UMULH",
            _ => "dp3src",
        };
    }

    // Remaining families share word[28:21] == 11010xxx.
    match (word >> 21) & 0xff {
        // Add/subtract (with carry).
        0b11010000 => match (word >> 29) & 0x3 {
            0b00 => "ADC",
            0b01 => "ADCS",
            0b10 => "SBC",
            0b11 => "SBCS",
            _ => unreachable!(),
        },
        // Conditional compare (register or immediate): word[30] selects.
        0b11010010 => {
            if (word >> 30) & 1 == 0 {
                "CCMN"
            } else {
                "CCMP"
            }
        }
        // Conditional select: word[30]=op, word[11:10]=op2.
        0b11010100 => match ((word >> 30) & 1, (word >> 10) & 0x3) {
            (0, 0b00) => "CSEL",
            (0, 0b01) => "CSINC",
            (1, 0b00) => "CSINV",
            (1, 0b01) => "CSNEG",
            _ => "csel",
        },
        // Data-processing (2 source) when word[30]=0, else (1 source).
        0b11010110 => {
            if (word >> 30) & 1 == 0 {
                match (word >> 10) & 0x3f {
                    0b000010 => "UDIV",
                    0b000011 => "SDIV",
                    0b001000 => "LSLV",
                    0b001001 => "LSRV",
                    0b001010 => "ASRV",
                    0b001011 => "RORV",
                    _ => "dp2src",
                }
            } else {
                match (word >> 10) & 0x3f {
                    0b000000 => "RBIT",
                    0b000001 => "REV16",
                    0b000010 => "REV",
                    0b000100 => "CLZ",
                    0b000101 => "CLS",
                    _ => "dp1src",
                }
            }
        }
        _ => "unknown (DataProcReg)",
    }
}

// ---------------------------------------------------------------------------
// Data Processing -- Scalar FP and Advanced SIMD (op0 == x111).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn simd_fp(word: u32) -> &'static str {
    // Crypto three-register (SHA3): EOR3 / BCAX share word & 0xffe08000.
    if word & 0xffe0_8000 == 0xce00_0000 {
        return "EOR3";
    }
    if word & 0xffe0_8000 == 0xce20_0000 {
        return "BCAX";
    }

    // AES round helpers (crypto AES, two-register).
    match word & 0xffff_fc00 {
        0x4e28_4800 => return "AESE",
        0x4e28_5800 => return "AESD",
        0x4e28_6800 => return "AESMC",
        0x4e28_7800 => return "AESIMC",
        _ => {}
    }

    "simd/fp"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_top_level_groups() {
        assert_eq!(classify(0x9100_0400), A64Class::DataProcImm); // ADD imm
        assert_eq!(classify(0xd2800000), A64Class::DataProcImm); // MOVZ
        assert_eq!(classify(0x1400_0000), A64Class::BranchSystem); // B
        assert_eq!(classify(0xd65f_03c0), A64Class::BranchSystem); // RET
        assert_eq!(classify(0xf940_0000), A64Class::LoadStore); // LDR imm
        assert_eq!(classify(0xc8e0_fc00), A64Class::LoadStore); // CASAL
        assert_eq!(classify(0x8a02_0000), A64Class::DataProcReg); // AND reg
        assert_eq!(classify(0xce00_0000), A64Class::DataProcSimdFp); // EOR3
        assert_eq!(classify(0x0000_0000), A64Class::Reserved); // UDF
    }

    #[test]
    fn decodes_branch_and_system() {
        assert_eq!(mnemonic(0xd65f_03c0), "RET"); // RET X30
        assert_eq!(mnemonic(0xd61f_0000), "BR"); // BR X0
        assert_eq!(mnemonic(0xd63f_0000), "BLR"); // BLR X0
        assert_eq!(mnemonic(0x1400_0000), "B"); // B .+0
        assert_eq!(mnemonic(0x9400_0000), "BL"); // BL .+0
        assert_eq!(mnemonic(0x5400_0000), "B.cond"); // B.EQ .+0
        assert_eq!(mnemonic(0xb400_0000), "CBZ"); // CBZ X0
        assert_eq!(mnemonic(0xb500_0000), "CBNZ"); // CBNZ X0
        assert_eq!(mnemonic(0x3600_0000), "TBZ"); // TBZ
        assert_eq!(mnemonic(0x3700_0000), "TBNZ"); // TBNZ
        assert_eq!(mnemonic(0xd400_0001), "SVC"); // SVC #0
        assert_eq!(mnemonic(0xd420_0000), "BRK"); // BRK #0
        assert_eq!(mnemonic(0xd503_201f), "NOP"); // NOP
        assert_eq!(mnemonic(0xd503_3fdf), "ISB"); // ISB SY
        assert_eq!(mnemonic(0xd53b_0000), "MRS"); // MRS
        assert_eq!(mnemonic(0xd51b_0000), "MSR"); // MSR (register)
    }

    #[test]
    fn decodes_data_proc_immediate() {
        assert_eq!(mnemonic(0x9100_0400), "ADD"); // ADD X0,X0,#1
        assert_eq!(mnemonic(0xb100_0400), "ADDS"); // ADDS X0,X0,#1
        assert_eq!(mnemonic(0xd100_0400), "SUB"); // SUB X0,X0,#1
        assert_eq!(mnemonic(0xf100_0400), "SUBS"); // SUBS X0,X0,#1
        assert_eq!(mnemonic(0x9240_0000), "AND"); // AND X0,X0,#1
        assert_eq!(mnemonic(0xb240_0000), "ORR"); // ORR X0,X0,#1
        assert_eq!(mnemonic(0xd240_0000), "EOR"); // EOR X0,X0,#1
        assert_eq!(mnemonic(0xf240_0000), "ANDS"); // ANDS X0,X0,#1
        assert_eq!(mnemonic(0xd280_0000), "MOVZ"); // MOVZ X0,#0
        assert_eq!(mnemonic(0x9280_0000), "MOVN"); // MOVN X0,#0
        assert_eq!(mnemonic(0xf280_0000), "MOVK"); // MOVK X0,#0
        assert_eq!(mnemonic(0x1000_0000), "ADR"); // ADR X0,.+0
        assert_eq!(mnemonic(0x9000_0000), "ADRP"); // ADRP X0,.+0
        assert_eq!(mnemonic(0x9340_0000), "SBFM"); // SBFM X0,X0,#0,#0
        assert_eq!(mnemonic(0xd340_0000), "UBFM"); // UBFM X0,X0,#0,#0
        assert_eq!(mnemonic(0xb340_0000), "BFM"); // BFM X0,X0,#0,#0
        assert_eq!(mnemonic(0x9380_0000), "EXTR"); // EXTR X0,X0,X0,#0
    }

    #[test]
    fn decodes_data_proc_register() {
        assert_eq!(mnemonic(0x8a02_0000), "AND"); // AND X0,X0,X2
        assert_eq!(mnemonic(0xaa02_0000), "ORR"); // ORR X0,X0,X2
        assert_eq!(mnemonic(0xca02_0000), "EOR"); // EOR X0,X0,X2
        assert_eq!(mnemonic(0xeb02_0000), "SUBS"); // SUBS X0,X0,X2
        assert_eq!(mnemonic(0x8b02_0000), "ADD"); // ADD X0,X0,X2 (shifted)
        assert_eq!(mnemonic(0x9ac2_0800), "UDIV"); // UDIV X0,X0,X2
        assert_eq!(mnemonic(0x9ac2_0c00), "SDIV"); // SDIV X0,X0,X2
        assert_eq!(mnemonic(0x9ac2_2000), "LSLV"); // LSLV X0,X0,X2
        assert_eq!(mnemonic(0x9ac2_2400), "LSRV"); // LSRV X0,X0,X2
        assert_eq!(mnemonic(0x9ac2_2800), "ASRV"); // ASRV X0,X0,X2
        assert_eq!(mnemonic(0x9ac2_2c00), "RORV"); // RORV X0,X0,X2
        assert_eq!(mnemonic(0x9b02_0c00), "MADD"); // MADD X0,X0,X2,X3
        assert_eq!(mnemonic(0x9b02_8c00), "MSUB"); // MSUB X0,X0,X2,X3
        assert_eq!(mnemonic(0x9a82_0000), "CSEL"); // CSEL X0,X0,X2,EQ
        assert_eq!(mnemonic(0x9a82_0400), "CSINC"); // CSINC X0,X0,X2,EQ
        assert_eq!(mnemonic(0xda82_0000), "CSINV"); // CSINV X0,X0,X2,EQ
        assert_eq!(mnemonic(0xda82_0400), "CSNEG"); // CSNEG X0,X0,X2,EQ
        assert_eq!(mnemonic(0xfa40_0800), "CCMP"); // CCMP X0,X0,#0,EQ
        assert_eq!(mnemonic(0x3a40_0800), "CCMN"); // CCMN X0,X0,#0,EQ
    }

    #[test]
    fn decodes_loads_and_stores() {
        assert_eq!(mnemonic(0xf940_0000), "LDR"); // LDR X0,[X0]
        assert_eq!(mnemonic(0xf900_0000), "STR"); // STR X0,[X0]
        assert_eq!(mnemonic(0xf800_0000), "STUR"); // STUR X0,[X0,#0]
        assert_eq!(mnemonic(0xf840_0000), "LDUR"); // LDUR X0,[X0,#0]
        assert_eq!(mnemonic(0x5800_0000), "LDR"); // LDR (literal)
        assert_eq!(mnemonic(0x9800_0000), "LDRSW"); // LDRSW (literal)
        assert_eq!(mnemonic(0xa900_0440), "STP"); // STP X0,X1,[X2]
        assert_eq!(mnemonic(0xa940_0440), "LDP"); // LDP X0,X1,[X2]
        assert_eq!(mnemonic(0xc85f_7c00), "LDXR"); // LDXR X0,[X0]
        assert_eq!(mnemonic(0xc800_7c00), "STXR"); // STXR W0,X0,[X0]
        assert_eq!(mnemonic(0xc8df_fc00), "LDAR"); // LDAR X0,[X0]
        assert_eq!(mnemonic(0xc89f_fc00), "STLR"); // STLR X0,[X0]
        assert_eq!(mnemonic(0xc8e0_fc00), "CASAL"); // CASAL X0,X0,[X0]
        assert_eq!(mnemonic(0xf8e0_8000), "SWPAL"); // SWPAL X0,X0,[X0]
    }

    #[test]
    fn decodes_simd_fp_family() {
        assert_eq!(classify(0xce00_0000), A64Class::DataProcSimdFp);
        assert_eq!(mnemonic(0xce00_0000), "EOR3"); // EOR3
        assert_eq!(mnemonic(0xce20_0000), "BCAX"); // BCAX
        assert_eq!(mnemonic(0x4e28_4800), "AESE"); // AESE
        // A generic NEON op falls back to the coarse family tag.
        assert_eq!(mnemonic(0x4ea0_1c00), "simd/fp"); // MOV Vd.16B,Vn.16B (ORR)
    }

    #[test]
    fn reserved_and_unallocated() {
        assert_eq!(classify(0x0000_0000), A64Class::Reserved);
        assert_eq!(mnemonic(0x0000_0000), "UDF");
        // op0 == 0b0010 is the SVE space, reported as unallocated here.
        assert_eq!(classify(0x0400_0000), A64Class::Unallocated);
    }
}

#[cfg(test)]
#[path = "decode_mnemonic_tests.rs"]
mod mnemonic_tests;
