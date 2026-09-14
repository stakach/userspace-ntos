//! Checked redirection of the x64 `mov rax, cr8; ret` helper into a hosted getter.

const CR8_GETTER: [u8; 5] = [0x44, 0x0f, 0x20, 0xc0, 0xc3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cr8GetterPatchError {
    InvalidLength { actual: usize },
    UnexpectedInstructions,
    SourceAddressOverflow,
    TargetOutOfRange,
}

/// Plan a five-byte near jump without modifying the original helper. The caller must supply
/// the exact helper body and keep its mapping stable until applying the returned bytes.
pub fn plan_cr8_getter_redirect(
    original: &[u8],
    source_va: u64,
    target_va: u64,
) -> Result<[u8; 5], Cr8GetterPatchError> {
    if original.len() != CR8_GETTER.len() {
        return Err(Cr8GetterPatchError::InvalidLength {
            actual: original.len(),
        });
    }
    if original != CR8_GETTER {
        return Err(Cr8GetterPatchError::UnexpectedInstructions);
    }
    let next_ip = source_va
        .checked_add(5)
        .ok_or(Cr8GetterPatchError::SourceAddressOverflow)?;
    let displacement = i32::try_from(i128::from(target_va) - i128::from(next_ip))
        .map_err(|_| Cr8GetterPatchError::TargetOutOfRange)?
        .to_le_bytes();
    Ok([
        0xe9,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_backward_and_zero_jumps_are_relative_to_the_next_instruction() {
        for (source, target, expected) in [
            (0x1000, 0x2000, [0xe9, 0xfb, 0x0f, 0, 0]),
            (0x2000, 0x1000, [0xe9, 0xfb, 0xef, 0xff, 0xff]),
            (0x1000, 0x1005, [0xe9, 0, 0, 0, 0]),
            (0x1000, 0x1000, [0xe9, 0xfb, 0xff, 0xff, 0xff]),
        ] {
            assert_eq!(
                plan_cr8_getter_redirect(&CR8_GETTER, source, target),
                Ok(expected)
            );
        }
    }

    #[test]
    fn exact_signed_rel32_boundaries_are_accepted_but_one_byte_farther_is_not() {
        let source = 0x1_0000_0000u64;
        let next_ip = source + 5;
        assert_eq!(
            plan_cr8_getter_redirect(&CR8_GETTER, source, next_ip + i32::MAX as u64),
            Ok([0xe9, 0xff, 0xff, 0xff, 0x7f])
        );
        assert_eq!(
            plan_cr8_getter_redirect(&CR8_GETTER, source, next_ip - (1u64 << 31)),
            Ok([0xe9, 0, 0, 0, 0x80])
        );
        for target in [next_ip + (1u64 << 31), next_ip - (1u64 << 31) - 1] {
            assert_eq!(
                plan_cr8_getter_redirect(&CR8_GETTER, source, target),
                Err(Cr8GetterPatchError::TargetOutOfRange)
            );
        }
    }

    #[test]
    fn address_arithmetic_cannot_wrap_or_truncate_high_bits() {
        for source in (u64::MAX - 4)..=u64::MAX {
            assert_eq!(
                plan_cr8_getter_redirect(&CR8_GETTER, source, 0),
                Err(Cr8GetterPatchError::SourceAddressOverflow)
            );
        }
        assert_eq!(
            plan_cr8_getter_redirect(&CR8_GETTER, u64::MAX - 5, u64::MAX),
            Ok([0xe9, 0, 0, 0, 0])
        );
        for (source, target) in [(0, u64::MAX), (u64::MAX - 5, 0)] {
            assert_eq!(
                plan_cr8_getter_redirect(&CR8_GETTER, source, target),
                Err(Cr8GetterPatchError::TargetOutOfRange)
            );
        }
    }

    #[test]
    fn unexpected_opcode_register_ret_and_lengths_are_rejected_without_mutation() {
        for index in 0..CR8_GETTER.len() {
            let mut changed = CR8_GETTER;
            changed[index] ^= 1;
            let before = changed;
            assert_eq!(
                plan_cr8_getter_redirect(&changed, 0x1000, 0x2000),
                Err(Cr8GetterPatchError::UnexpectedInstructions)
            );
            assert_eq!(changed, before);
        }
        let bytes = [0x44, 0x0f, 0x20, 0xc0, 0xc3, 0x90];
        for len in [0, 1, 2, 3, 4, 6] {
            assert_eq!(
                plan_cr8_getter_redirect(&bytes[..len], 0x1000, 0x2000),
                Err(Cr8GetterPatchError::InvalidLength { actual: len })
            );
        }
        assert_eq!(bytes, [0x44, 0x0f, 0x20, 0xc0, 0xc3, 0x90]);
        let original = CR8_GETTER;
        for target in [0x2000, u64::MAX] {
            let _ = plan_cr8_getter_redirect(&original, 0x1000, target);
            assert_eq!(original, CR8_GETTER);
        }
    }
}
