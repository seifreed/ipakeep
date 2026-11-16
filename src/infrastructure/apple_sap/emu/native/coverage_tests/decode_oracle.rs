//! Decode oracle: every size/Q/U combination of the two-register-misc,
//! across-lanes, EXT and INS (element) groups, classified by llvm-mc
//! (`decode_oracle_data`). Invalid and unmodelled encodings must be rejected
//! as `Unsupported`; modelled ones must match Unicorn. This is the guard
//! against a reserved or unmodelled encoding silently running as a neighbour.

#[path = "decode_oracle_data.rs"]
mod data;

use super::{NativeCpu, NativeError};

fn step_one(word: u32) -> Result<(), NativeError> {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(0x1_0000, 0x1000);
    cpu.mem.write(0x1_0000, &word.to_le_bytes()).unwrap();
    cpu.set_pc(0x1_0000);
    cpu.step().map(|_| ())
}

#[test]
fn invalid_and_unmodelled_encodings_are_rejected() {
    let words = data::INVALID
        .iter()
        .map(|&w| (w, "invalid"))
        .chain(data::UNMODELLED.iter().copied());
    for (word, what) in words {
        assert!(
            matches!(step_one(word), Err(NativeError::Unsupported { .. })),
            "{word:#010x} ({what}) must be rejected"
        );
    }
}

#[cfg(feature = "unicorn")]
#[test]
fn modelled_encodings_match_unicorn() {
    use super::super::diff::{Init, check};

    // Integer-shaped and FP-shaped inputs (normal, non-NaN values).
    let inputs: [(u128, u128); 2] = [
        (
            0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
            0x8899_aabb_ccdd_eeff_1122_3344_5566_7788,
        ),
        (
            0x3ff8_0000_0000_0000_c002_0000_0000_0000,
            0x3fc0_0000_c010_0000_0000_0000_8000_0000,
        ),
    ];
    for &(word, what) in data::MODELLED {
        for (v1, v2) in inputs {
            let mut init = Init::default();
            init.v[0] = 0xdead_beef_dead_beef_dead_beef_dead_beef;
            init.v[1] = v1;
            init.v[2] = v2;
            let result = std::panic::catch_unwind(|| check(&[word], init));
            assert!(
                result.is_ok(),
                "{word:#010x} ({what}) diverges from Unicorn"
            );
        }
    }
}
