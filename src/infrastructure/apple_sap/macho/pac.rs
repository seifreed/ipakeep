//! Rewriting of `ARM64e` pointer-authentication instructions.

const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;
const BR: u32 = 0xd61f_0000;
const BLR: u32 = 0xd63f_0000;
const RN_FIELD: u32 = 0x3e0;
const RN_OPCODE_MASK: u32 = 0xffff_fc00;
const RD_OPCODE_MASK: u32 = 0xffff_ffe0;
const INSTRUCTION_SIZE: usize = 4;

/// `braa/brab/braaz/brabz` (register-indirect authenticated branches).
const AUTHENTICATED_BRANCHES: [u32; 4] = [0xd71f_0800, 0xd71f_0c00, 0xd61f_0800, 0xd61f_0c00];
/// `blraa/blrab/blraaz/blrabz`.
const AUTHENTICATED_CALLS: [u32; 4] = [0xd73f_0800, 0xd73f_0c00, 0xd63f_0800, 0xd63f_0c00];
/// `pacia/pacib/pacda/pacdb/autia/autib/autda/autdb` with a register modifier.
const SIGN_AUTH_REGISTER: [u32; 8] = [
    0xdac1_0000,
    0xdac1_0400,
    0xdac1_0800,
    0xdac1_0c00,
    0xdac1_1000,
    0xdac1_1400,
    0xdac1_1800,
    0xdac1_1c00,
];
/// `retaa/retab`.
const AUTHENTICATED_RETURNS: [u32; 2] = [0xd65f_0bff, 0xd65f_0fff];
/// Hint-space PAC instructions (`pacia1716`, `paciasp`, `autiasp`, `xpaclri`, ...).
const PAC_HINTS: [u32; 9] = [
    0xd503_211f,
    0xd503_215f,
    0xd503_219f,
    0xd503_21df,
    0xd503_233f,
    0xd503_237f,
    0xd503_23bf,
    0xd503_23ff,
    0xd503_20ff,
];
/// Zero-modifier sign/auth and `xpaci/xpacd` forms.
const SIGN_AUTH_ZERO: [u32; 10] = [
    0xdac1_23e0,
    0xdac1_27e0,
    0xdac1_2be0,
    0xdac1_2fe0,
    0xdac1_33e0,
    0xdac1_37e0,
    0xdac1_3be0,
    0xdac1_3fe0,
    0xdac1_43e0,
    0xdac1_47e0,
];

/// Rewrites `ARM64e` authentication operations for a VM with canonical,
/// unsigned pointers. Other instructions are returned unchanged.
pub fn without_pointer_authentication(instruction: u32) -> u32 {
    let rn_opcode = instruction & RN_OPCODE_MASK;
    if AUTHENTICATED_BRANCHES.contains(&rn_opcode) {
        return BR | (instruction & RN_FIELD);
    }
    if AUTHENTICATED_CALLS.contains(&rn_opcode) {
        return BLR | (instruction & RN_FIELD);
    }
    if SIGN_AUTH_REGISTER.contains(&rn_opcode) || PAC_HINTS.contains(&instruction) {
        return NOP;
    }
    if AUTHENTICATED_RETURNS.contains(&instruction) {
        return RET;
    }
    if SIGN_AUTH_ZERO.contains(&(instruction & RD_OPCODE_MASK)) {
        return NOP;
    }
    instruction
}

/// A rewritten instruction at a file offset of the thin image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionPatch {
    /// File offset of the instruction.
    pub offset: u64,
    /// Replacement instruction word.
    pub value: u32,
}

/// Rewrites every authentication instruction in `[start, end)` of `data`,
/// recording each change in `patches`.
pub(crate) fn strip_range(
    data: &mut [u8],
    start: usize,
    end: usize,
    patches: &mut Vec<InstructionPatch>,
) {
    let mut offset = start;
    while offset + INSTRUCTION_SIZE <= end {
        let mut word = [0u8; INSTRUCTION_SIZE];
        word.copy_from_slice(&data[offset..offset + INSTRUCTION_SIZE]);
        let instruction = u32::from_le_bytes(word);
        let replacement = without_pointer_authentication(instruction);
        if replacement != instruction {
            data[offset..offset + INSTRUCTION_SIZE].copy_from_slice(&replacement.to_le_bytes());
            patches.push(InstructionPatch {
                offset: offset as u64,
                value: replacement,
            });
        }
        offset += INSTRUCTION_SIZE;
    }
}

/// Applies previously recorded patches to `data`. Out-of-range patches are
/// clipped to the buffer.
pub(crate) fn apply_patches(data: &mut [u8], patches: &[InstructionPatch]) {
    for patch in patches {
        let start = usize::try_from(patch.offset).unwrap_or(usize::MAX);
        let bytes = patch.value.to_le_bytes();
        let available = data.len().saturating_sub(start).min(INSTRUCTION_SIZE);
        if available > 0 {
            data[start..start + available].copy_from_slice(&bytes[..available]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_branches_become_plain() {
        assert_eq!(without_pointer_authentication(0xd71f_0a30), 0xd61f_0220); // braa x17, x16 -> br x17
        assert_eq!(without_pointer_authentication(0xd63f_081f), 0xd63f_0000); // blraaz x0 -> blr x0
        assert_eq!(without_pointer_authentication(0xd73f_0c30), 0xd63f_0020); // blrab x1 -> blr x1
    }

    #[test]
    fn signing_and_hints_become_nop() {
        assert_eq!(without_pointer_authentication(0xd503_237f), NOP); // pacibsp
        assert_eq!(without_pointer_authentication(0xd503_23ff), NOP); // autibsp
        assert_eq!(without_pointer_authentication(0xdac1_0230), NOP); // pacia x16, x17
        assert_eq!(without_pointer_authentication(0xdac1_47f0), NOP); // xpacd x16
        assert_eq!(without_pointer_authentication(0xdac1_23f1), NOP); // paciza x17
    }

    #[test]
    fn authenticated_returns_become_ret() {
        assert_eq!(without_pointer_authentication(0xd65f_0fff), RET);
        assert_eq!(without_pointer_authentication(0xd65f_0bff), RET);
    }

    #[test]
    fn ordinary_instructions_are_unchanged() {
        for word in [RET, NOP, 0xd61f_0200, 0x9100_03fd, 0xdac0_0c00, 0xd503_201f] {
            assert_eq!(without_pointer_authentication(word), word);
        }
    }

    #[test]
    fn strip_range_records_patches() {
        let mut data = Vec::new();
        for word in [0xd503_237fu32, 0x9100_03fd, 0xd65f_0fff] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        let mut patches = Vec::new();
        strip_range(&mut data, 0, 12, &mut patches);
        assert_eq!(patches.len(), 2);
        assert_eq!(
            patches[1],
            InstructionPatch {
                offset: 8,
                value: RET
            }
        );
        let mut copy = vec![0u8; 12];
        apply_patches(&mut copy, &patches);
        assert_eq!(&copy[8..12], &RET.to_le_bytes());
    }

    #[test]
    fn apply_patches_clips_to_the_buffer() {
        let mut data = vec![0u8; 6];
        let patches = [
            InstructionPatch {
                offset: 4,
                value: NOP,
            },
            InstructionPatch {
                offset: 64,
                value: RET,
            },
        ];
        apply_patches(&mut data, &patches);
        assert_eq!(data, [0, 0, 0, 0, 0x1f, 0x20]);
    }
}
