//! Encodings the interpreter must reject with an exact
//! [`NativeError::Unsupported`]: either architecturally unallocated, or real
//! instructions deliberately outside the guest's surface (system registers,
//! PAC loads, MTE, CRC, LSE read-modify-write, half precision, ...).
//!
//! Each word is annotated with its `llvm-mc` disassembly, or with the field
//! that makes it unallocated when it was derived from a neighbouring encoding.

use super::super::dpimm::decode_bit_masks;
use super::super::{A64Class, class_name};
use super::assert_unsupported;

#[test]
fn top_level_reserved_and_unallocated_classes() {
    assert_unsupported(0x0000_0000, "reserved"); // udf #0
    assert_unsupported(0x0400_0000, "unallocated"); // op0 == 0b0010 (SVE)
}

#[test]
fn class_names_cover_every_class() {
    for (class, name) in [
        (A64Class::Reserved, "reserved"),
        (A64Class::Unallocated, "unallocated"),
        (A64Class::DataProcImm, "data-proc-imm"),
        (A64Class::BranchSystem, "branch/system"),
        (A64Class::LoadStore, "load/store"),
        (A64Class::DataProcReg, "data-proc-reg"),
        (A64Class::DataProcSimdFp, "simd/fp"),
    ] {
        assert_eq!(class_name(class), name);
    }
}

#[test]
fn branch_exception_and_system() {
    assert_unsupported(0xd69f_03e0, "branch-reg (eret/drps/pac)"); // eret
    assert_unsupported(0xd6bf_03e0, "branch-reg (eret/drps/pac)"); // drps
    assert_unsupported(0xd400_0001, "exception (svc/hvc/smc/hlt)"); // svc #0
    assert_unsupported(0xd400_0002, "exception (svc/hvc/smc/hlt)"); // hvc #0
    assert_unsupported(0xd53b_d040, "system register / msr"); // mrs x0, tpidr_el0
    assert_unsupported(0xd503_42df, "system register / msr"); // msr daifset, #2
}

#[test]
fn data_processing_immediate() {
    assert_unsupported(0x9181_0420, "dpimm/tagged"); // addg x0, x1, #16, #1
    assert_unsupported(0x1240_0020, "logical-imm/N"); // and w0, w1, #imm with N=1
    assert_unsupported(0x1200_fc20, "logical-imm/reserved"); // N:imms = 0:111111
    assert_unsupported(0x1200_f820, "logical-imm/reserved"); // N:imms = 0:111110
    assert_unsupported(0x9240_fc20, "logical-imm/reserved"); // all-ones element
    assert_unsupported(0x52c0_0000, "movw/hw"); // movz w0 with hw = 2
    assert_unsupported(0x3280_0000, "movw/opc"); // move wide opc = 01
    assert_unsupported(0x9300_0000, "bitfield/N"); // sbfm x0 with N = 0
    assert_unsupported(0x1300_fc20, "bitfield/reserved"); // sbfm w0, w1, #0, #63
}

#[test]
fn decode_bit_masks_rejects_an_element_wider_than_the_register() {
    // N == 1 selects a 64-bit element, which cannot fit a 32-bit datasize.
    assert_eq!(decode_bit_masks(1, 0, 0, true, 32), None);
    assert_eq!(decode_bit_masks(1, 0, 0, false, 32), None);
    assert!(decode_bit_masks(1, 0, 0, true, 64).is_some());
}

#[test]
fn data_processing_register() {
    assert_unsupported(0x9aa2_0020, "dpreg/op2"); // op1 = 1, op2 = 0101
    assert_unsupported(0xba00_8402, "dpreg/flagops"); // rmif x0, #1, #2
    assert_unsupported(0x3a00_080d, "dpreg/flagops"); // setf8 w0
    assert_unsupported(0x9a82_0820, "dpreg/csel"); // csel with op2 = 10
    assert_unsupported(0x1ac2_4020, "dpreg/2src"); // crc32b w0, w1, w2
    assert_unsupported(0x9b42_fc20, "dpreg/3src"); // smulh with o0 = 1
    assert_unsupported(0xdac1_0020, "dpreg/1src"); // pacia x0, x1
    assert_unsupported(0x5ac0_0c20, "dpreg/1src"); // 64-bit REV opcode with sf = 0
}

#[test]
fn integer_loads_and_stores() {
    assert_unsupported(0xb9c0_0020, "ldst/unalloc"); // ldrsw with opc = 11
    assert_unsupported(0xf9c0_0020, "ldst/unalloc"); // 64-bit load with opc = 11
    assert_unsupported(0xd920_0820, "ldst/group"); // stg x0, [x1]
    assert_unsupported(0x9940_0020, "ldst/group"); // ldapur w0, [x1]
    assert_unsupported(0xf820_0420, "ldst/reg-unalloc"); // ldraa x0, [x1]
    assert_unsupported(0xf840_0820, "ldst/unpriv"); // ldtr x0, [x1]
    assert_unsupported(0xe940_0440, "ldst/pair-unalloc"); // ldp with opc = 11
    assert_unsupported(0xf820_0041, "ldst/atomic"); // ldadd x0, x1, [x2]
}

#[test]
fn simd_dispatch_and_three_register_groups() {
    assert_unsupported(0x5ee2_8420, "simd/fp"); // add d0, d1, d2 (scalar AdvSIMD)
    assert_unsupported(0x4e28_4820, "simd/three"); // aese v0.16b, v1.16b
    assert_unsupported(0x4e42_1820, "simd/three"); // uzp1 v0.8h, v1.8h, v2.8h
    assert_unsupported(0x4e22_0c20, "simd/three"); // sqadd v0.16b, v1.16b, v2.16b
    assert_unsupported(0x0e22_c020, "simd/three-diff"); // smull v0.8h, v1.8b, v2.8b
}

#[test]
fn simd_two_register_misc_and_across_lanes() {
    assert_unsupported(0x0ee1_2820, "simd/2misc"); // xtn with size = 11
    assert_unsupported(0x2ea0_5820, "simd/2misc"); // not/rbit with size = 10
    assert_unsupported(0x4e20_3820, "simd/2misc"); // suqadd v0.16b, v1.16b
    assert_unsupported(0x2ee1_3820, "simd/2misc"); // shll with size = 11
    assert_unsupported(0x4ee0_2820, "simd/2misc"); // saddlp with size = 11
    assert_unsupported(0x0e21_6820, "simd/2misc-fp"); // fcvtn v0.4h, v1.4s
    assert_unsupported(0x6e30_f820, "simd/across"); // fmaxv s0, v1.4s
}

#[test]
fn simd_copy_and_immediate_groups() {
    assert_unsupported(0x4e10_0420, "simd/dup"); // dup with imm5 = x0000
    assert_unsupported(0x6e0c_4420, "simd/dup"); // mov v0.s[1], v1.s[2] (INS element)
    assert_unsupported(0x4fa2_8020, "simd/imm"); // mul v0.4s, v1.4s, v2.s[1]
    assert_unsupported(0x4f00_1420, "simd/movi"); // orr v0.4s, #1
    assert_unsupported(0x0f0d_9420, "simd/shift"); // sqshrn v0.8b, v1.8h, #3
}

#[test]
fn scalar_floating_point() {
    assert_unsupported(0x1e02_f420, "simd/fp-scalar"); // scvtf s0, w1, #3
    assert_unsupported(0x1e21_0400, "simd/fp-scalar"); // fccmp s0, s1, #0, eq
    assert_unsupported(0x1ee3_0020, "simd/ucvtf"); // ucvtf h0, w1
    assert_unsupported(0x1ee7_0020, "simd/fmov"); // fmov h0, w1
    assert_unsupported(0x1e38_0020, "simd/fp-convert"); // fcvtzs w0, s1
    assert_unsupported(0x1ee0_4020, "simd/fmov"); // fmov h0, h1
    assert_unsupported(0x1ee1_4020, "simd/fneg"); // fneg h0, h1
    assert_unsupported(0x1e20_c020, "simd/fp-1src"); // fabs s0, s1
    assert_unsupported(0x1e22_2820, "simd/fp-2src"); // fadd s0, s1, s2
    assert_unsupported(0x1ee2_0820, "simd/fmul"); // fmul h0, h1, h2
    assert_unsupported(0x1eee_1000, "simd/fmov-imm"); // fmov h0, #1.0
    assert_unsupported(0x1ee1_2000, "simd/fcmp"); // fcmp h0, h1
}

#[test]
fn simd_loads_and_stores() {
    assert_unsupported(0x4c40_7000, "ldst/group"); // ld1 {v0.16b}, [x0]
    assert_unsupported(0x7dc0_0000, "simd/ldst"); // ldr q with size = 01 (32 bytes)
    assert_unsupported(0x3c60_0000, "simd/ldst"); // register offset, bits[11:10] = 00
    assert_unsupported(0x3c40_0800, "simd/ldst"); // unprivileged form with V = 1
    assert_unsupported(0xed40_0400, "simd/ldp"); // ldp q with opc = 11
    assert_unsupported(0xdc00_0040, "simd/ldr-lit"); // ldr (literal) with opc = 11
}
