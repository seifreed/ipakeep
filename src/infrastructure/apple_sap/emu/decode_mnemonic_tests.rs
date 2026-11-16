//! Table-driven mnemonic tests covering every named arm of the classifier.
//! Words come from `llvm-mc -triple=aarch64 --show-encoding`; the comments
//! name the instruction, or the field that makes an encoding fall through to
//! a family tag.

use super::{A64Class, classify, mnemonic};

#[track_caller]
fn assert_mnemonics(cases: &[(u32, &str)]) {
    for &(word, expected) in cases {
        assert_eq!(mnemonic(word), expected, "word {word:#010x}");
    }
}

#[test]
fn unallocated_and_data_proc_immediate_tags() {
    assert_eq!(classify(0x0400_0000), A64Class::Unallocated);
    assert_mnemonics(&[
        (0x0400_0000, "unknown (Unallocated)"), // op0 == 0b0010 (SVE)
        (0x9181_0420, "ADDG/SUBG"),             // addg x0, x1, #16, #1
        (0x3280_0000, "movewide"),              // move wide, opc == 01
        (0x7300_0000, "bitfield"),              // bitfield, opc == 11
    ]);
}

#[test]
fn branch_register_and_exception_generation() {
    assert_mnemonics(&[
        (0xd69f_03e0, "ERET"),      // eret
        (0xd6bf_03e0, "DRPS"),      // drps
        (0xd71f_0801, "br (reg)"),  // braa x0, x1
        (0xd400_0002, "HVC"),       // hvc #0
        (0xd400_0003, "SMC"),       // smc #0
        (0xd440_0000, "HLT"),       // hlt #0
        (0xd4a0_0001, "DCPS1"),     // dcps1
        (0xd4a0_0002, "DCPS2"),     // dcps2
        (0xd4a0_0003, "DCPS3"),     // dcps3
        (0xd420_0001, "exception"), // brk opc with LL == 01
    ]);
}

#[test]
fn hints_barriers_and_other_system() {
    assert_mnemonics(&[
        (0xd503_203f, "YIELD"),   // yield
        (0xd503_205f, "WFE"),     // wfe
        (0xd503_207f, "WFI"),     // wfi
        (0xd503_209f, "SEV"),     // sev
        (0xd503_20bf, "SEVL"),    // sevl
        (0xd503_20df, "HINT"),    // hint #6
        (0xd503_3f5f, "CLREX"),   // clrex
        (0xd503_3f9f, "DSB"),     // dsb sy
        (0xd503_3bbf, "DMB"),     // dmb ish
        (0xd503_30ff, "SB"),      // sb
        (0xd503_301f, "barrier"), // CRn == 0011, op2 == 000
        (0xd503_42df, "MSR"),     // msr daifset, #2
        (0xd508_751f, "system"),  // ic iallu
    ]);
}

#[test]
fn exclusive_ordered_and_compare_and_swap() {
    assert_mnemonics(&[
        (0xc802_fc01, "STLXR"), // stlxr w2, x1, [x0]
        (0xc85f_fc01, "LDAXR"), // ldaxr x1, [x0]
        (0xc823_0801, "STXP"),  // stxp w3, x1, x2, [x0]
        (0xc87f_0801, "LDXP"),  // ldxp x1, x2, [x0]
        (0xc89f_7c01, "STLLR"), // stllr x1, [x0]
        (0xc8df_7c01, "LDLAR"), // ldlar x1, [x0]
        (0xc8a1_7c02, "CAS"),   // cas x1, x2, [x0]
        (0xc8e1_7c02, "CASA"),  // casa x1, x2, [x0]
        (0xc8a1_fc02, "CASL"),  // casl x1, x2, [x0]
    ]);
}

#[test]
fn lse_atomics() {
    assert_mnemonics(&[
        (0xf821_8002, "SWP"),          // swp x1, x2, [x0]
        (0xf8a1_8002, "SWPA"),         // swpa x1, x2, [x0]
        (0xf861_8002, "SWPL"),         // swpl x1, x2, [x0]
        (0xf821_0002, "LDADD"),        // ldadd x1, x2, [x0]
        (0xf821_1002, "LDCLR"),        // ldclr x1, x2, [x0]
        (0xf821_2002, "LDEOR"),        // ldeor x1, x2, [x0]
        (0xf821_3002, "LDSET"),        // ldset x1, x2, [x0]
        (0xf821_4002, "LDSMAX"),       // ldsmax x1, x2, [x0]
        (0xf821_5002, "LDSMIN"),       // ldsmin x1, x2, [x0]
        (0xf821_6002, "LDUMAX"),       // ldumax x1, x2, [x0]
        (0xf821_7002, "LDUMIN"),       // ldumin x1, x2, [x0]
        (0xf8bf_c020, "atomic (LSE)"), // ldapr x0, [x1] (o3 == 1, opc != 000)
    ]);
}

#[test]
fn literal_simd_and_unclassified_load_store() {
    assert_mnemonics(&[
        (0xd800_0040, "PRFM"),                // prfm pldl1keep, #8
        (0x4c40_7000, "ld/st (simd)"),        // ld1 {v0.16b}, [x0]
        (0xd920_0820, "unknown (LoadStore)"), // stg x0, [x1]
        (0x3dc0_0000, "LDR"),                 // ldr q0, [x0]
        (0x3cc0_1000, "LDUR"),                // ldur q0, [x0, #1]
        (0x3d80_0000, "STR"),                 // str q0, [x0]
        (0x3c80_1000, "STUR"),                // stur q0, [x0, #1]
    ]);
}

#[test]
fn integer_register_loads_and_stores() {
    assert_mnemonics(&[
        (0xf980_0000, "PRFM"),                // prfm pldl1keep, [x0]
        (0xf880_1000, "PRFUM"),               // prfum pldl1keep, [x0, #1]
        (0xf9c0_0000, "unknown (LoadStore)"), // 64-bit, opc == 11
        (0xb900_0001, "STR"),                 // str w1, [x0]
        (0xb940_0001, "LDR"),                 // ldr w1, [x0]
        (0xb980_0001, "LDRSW"),               // ldrsw x1, [x0]
        (0xb800_1001, "STUR"),                // stur w1, [x0, #1]
        (0xb840_1001, "LDUR"),                // ldur w1, [x0, #1]
        (0xb880_1001, "LDURSW"),              // ldursw x1, [x0, #1]
        (0x7900_0001, "STRH"),                // strh w1, [x0]
        (0x7940_0001, "LDRH"),                // ldrh w1, [x0]
        (0x7980_0001, "LDRSH"),               // ldrsh x1, [x0]
        (0x79c0_0001, "LDRSH"),               // ldrsh w1, [x0]
        (0x7800_1001, "STURH"),               // sturh w1, [x0, #1]
        (0x7840_1001, "LDURH"),               // ldurh w1, [x0, #1]
        (0x7880_1001, "LDURSH"),              // ldursh x1, [x0, #1]
        (0x78c0_1001, "LDURSH"),              // ldursh w1, [x0, #1]
        (0x3900_0001, "STRB"),                // strb w1, [x0]
        (0x3940_0001, "LDRB"),                // ldrb w1, [x0]
        (0x3980_0001, "LDRSB"),               // ldrsb x1, [x0]
        (0x39c0_0001, "LDRSB"),               // ldrsb w1, [x0]
        (0x3800_1001, "STURB"),               // sturb w1, [x0, #1]
        (0x3840_1001, "LDURB"),               // ldurb w1, [x0, #1]
        (0x3880_1001, "LDURSB"),              // ldursb x1, [x0, #1]
        (0x38c0_1001, "LDURSB"),              // ldursb w1, [x0, #1]
    ]);
}

#[test]
fn data_proc_register_families() {
    assert_mnemonics(&[
        (0x8a22_0020, "BIC"),                   // bic x0, x1, x2
        (0xaa22_0020, "ORN"),                   // orn x0, x1, x2
        (0xca22_0020, "EON"),                   // eon x0, x1, x2
        (0xea02_0020, "ANDS"),                  // ands x0, x1, x2
        (0xea22_0020, "BICS"),                  // bics x0, x1, x2
        (0xab02_0020, "ADDS"),                  // adds x0, x1, x2
        (0xcb02_0020, "SUB"),                   // sub x0, x1, x2
        (0x9b22_0c20, "SMADDL"),                // smaddl x0, w1, w2, x3
        (0x9b22_8c20, "SMSUBL"),                // smsubl x0, w1, w2, x3
        (0x9b42_7c20, "SMULH"),                 // smulh x0, x1, x2
        (0x9ba2_0c20, "UMADDL"),                // umaddl x0, w1, w2, x3
        (0x9ba2_8c20, "UMSUBL"),                // umsubl x0, w1, w2, x3
        (0x9bc2_7c20, "UMULH"),                 // umulh x0, x1, x2
        (0x9b42_fc20, "dp3src"),                // smulh with o0 == 1
        (0x9a02_0020, "ADC"),                   // adc x0, x1, x2
        (0xba02_0020, "ADCS"),                  // adcs x0, x1, x2
        (0xda02_0020, "SBC"),                   // sbc x0, x1, x2
        (0xfa02_0020, "SBCS"),                  // sbcs x0, x1, x2
        (0x9a82_0820, "csel"),                  // conditional select, op2 == 10
        (0x1ac2_4020, "dp2src"),                // crc32b w0, w1, w2
        (0xdac0_0020, "RBIT"),                  // rbit x0, x1
        (0xdac0_0420, "REV16"),                 // rev16 x0, x1
        (0x5ac0_0820, "REV"),                   // rev w0, w1
        (0xdac0_1020, "CLZ"),                   // clz x0, x1
        (0xdac0_1420, "CLS"),                   // cls x0, x1
        (0xdac0_1820, "dp1src"),                // 1-source, opcode == 000110
        (0x9a20_0000, "unknown (DataProcReg)"), // word[28:21] == 11010001
    ]);
}

#[test]
fn aes_round_helpers() {
    assert_mnemonics(&[
        (0x4e28_5820, "AESD"),   // aesd v0.16b, v1.16b
        (0x4e28_6820, "AESMC"),  // aesmc v0.16b, v1.16b
        (0x4e28_7820, "AESIMC"), // aesimc v0.16b, v1.16b
    ]);
}
