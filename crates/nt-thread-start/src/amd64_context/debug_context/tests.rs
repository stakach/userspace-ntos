use super::*;
use crate::amd64_context::{CONTEXT_FLOATING_POINT, FLOAT_SAVE_OFFSET};
use crate::{put_u32, put_u64};

const HIGHEST: u64 = 0x7fff_ffff_ffff;

fn context(groups: u32) -> CapturedAmd64Context {
    CapturedAmd64Context::capture(
        |_, bytes| {
            bytes.fill(0xa5);
            put_u32(bytes, 0x30, CONTEXT_AMD64 | groups);
            bytes[0x38..0x3a].copy_from_slice(&0x33u16.to_le_bytes());
            put_u32(bytes, 0x44, 0x202);
            put_u64(bytes, 0xf8, 0x400123);
            put_u64(bytes, 0x98, 0x801ff8);
            bytes[0x48..0x78].fill(0);
            Ok(())
        },
        0x1000,
    )
    .unwrap()
}

fn debug(context: &mut CapturedAmd64Context, image: [u64; 6]) {
    for (index, value) in image.into_iter().enumerate() {
        put_u64(&mut context.bytes, 0x48 + index * 8, value);
    }
}

#[test]
fn debug_set_masks_control_clamps_every_address_and_clears_dr6() {
    let mut input = context(0x10);
    debug(
        &mut input,
        [
            HIGHEST,
            HIGHEST + 1,
            u64::MAX,
            0x1000,
            u64::MAX,
            (u64::MAX & !0xffff_0000) | (1 << 28),
        ],
    );
    let before = input.bytes;
    let result = input.prepare_set(HIGHEST).unwrap();
    assert_eq!(result.debug, Some([HIGHEST, 0, 0, 0x1000, 0, 0x1000_0155]));
    assert_eq!(result.register_mask, 0);
    assert_eq!(result.registers, [0; 20]);
    assert_eq!(result.floating_point, None);
    assert_eq!(input.bytes, before);
}

#[test]
fn debug_continuation_keeps_canonical_resume_controls_and_selects_debug() {
    let mut input = context(0x10);
    debug(&mut input, [0x1000, 0x2000, 0x3000, 0x4000, 0xdead, 1]);
    let result = input
        .prepare_continue(0x1234, 0x9876, 0x202, HIGHEST, false)
        .unwrap();
    assert_eq!(result.register_mask, 7);
    assert_eq!(&result.registers[..3], &[0x1234, 0x9876, 0x202]);
    assert_eq!(result.debug, Some([0x1000, 0x2000, 0x3000, 0x4000, 0, 1]));
}

#[test]
fn debug_rejects_io_even_disabled_and_invalid_active_lengths() {
    for slot in 0..4 {
        for enabled in [0, 1 << (slot * 2)] {
            let mut input = context(0x10);
            debug(&mut input, [0; 6]);
            put_u64(&mut input.bytes, 0x70, enabled | (2 << (16 + slot * 4)));
            assert_eq!(
                input.prepare_set(HIGHEST),
                Err(CodecError::UnsupportedDebugRegisters)
            );
        }
        let mut input = context(0x10);
        put_u64(
            &mut input.bytes,
            0x70,
            (1 << (slot * 2)) | (1 << (18 + slot * 4)),
        );
        assert_eq!(
            input.prepare_set(HIGHEST),
            Err(CodecError::InvalidDebugRegisters)
        );
        put_u64(&mut input.bytes, 0x70, 1 << (18 + slot * 4));
        assert!(
            input.prepare_set(HIGHEST).is_ok(),
            "disabled execution length is retained"
        );
    }
}

#[test]
fn active_data_alignment_is_checked_after_address_sanitization() {
    let mut input = context(0x10);
    debug(&mut input, [0x1001, 0, 0, 0, 0, 1 | (1 << 16) | (2 << 18)]);
    assert_eq!(
        input.prepare_set(HIGHEST),
        Err(CodecError::InvalidDebugRegisters)
    );
    put_u64(&mut input.bytes, 0x48, HIGHEST + 1);
    assert_eq!(input.prepare_set(HIGHEST).unwrap().debug.unwrap()[0], 0);
}

#[test]
fn partial_set_does_not_validate_or_select_unrequested_control_or_debug() {
    for groups in [0, 2, 4, 8] {
        let mut input = context(groups);
        put_u64(&mut input.bytes, 0xf8, 0);
        put_u64(&mut input.bytes, 0x98, u64::MAX);
        put_u32(&mut input.bytes, 0x44, u32::MAX);
        debug(&mut input, [u64::MAX; 6]);
        let result = input.prepare_set(HIGHEST).unwrap();
        assert_eq!(
            result.register_mask,
            if groups == 2 { ((1 << 15) - 1) << 3 } else { 0 }
        );
        assert_eq!(&result.registers[..3], &[0; 3]);
        assert_eq!(&result.registers[18..], &[0; 2]);
        assert_eq!(result.debug, None);
        assert_eq!(result.floating_point.is_some(), groups == 8);
    }
}

#[test]
fn partial_set_still_obeys_nt5_native_cs_selection_and_extended_state_rejection() {
    for cs in [0u16, 0x23, 0x10, 0xffff] {
        let mut input = context(0x10);
        input.bytes[0x38..0x3a].copy_from_slice(&cs.to_le_bytes());
        assert_eq!(
            input.prepare_set(HIGHEST),
            Err(CodecError::UnsupportedCompatibilityMode)
        );
    }
    for groups in [0x40, 0x80, 0x50, 0x90] {
        assert_eq!(
            context(groups).prepare_set(HIGHEST),
            Err(CodecError::UnsupportedExtendedState)
        );
    }
    assert_eq!(
        context(0x10).prepare_continue(1, 2, 0x202, HIGHEST, true),
        Err(CodecError::UnsupportedTestAlert)
    );
}

#[test]
fn requested_set_control_integer_fp_debug_are_one_plan_without_tls() {
    let mut input = context(0x1b);
    for (i, offset) in [
        0x78, 0x90, 0x80, 0x88, 0xa8, 0xb0, 0xa0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(&mut input.bytes, offset, 100 + i as u64);
    }
    let result = input.prepare_set(HIGHEST).unwrap();
    assert_eq!(result.register_mask, (1 << 18) - 1);
    assert_eq!(&result.registers[..3], &[0x400123, 0x801ff8, 0x202]);
    for i in 0..15 {
        assert_eq!(result.registers[3 + i], 100 + i as u64);
    }
    assert_eq!(&result.registers[18..], &[0, 0]);
    assert!(result.floating_point.is_some());
    assert_eq!(result.debug, Some([0; 6]));
}

#[test]
fn raw_debug_get_preserves_dr6_high_addresses_and_control_without_masks() {
    let mut input = context(0x10);
    let before = input.bytes;
    let raw = [u64::MAX, 2, 3, 4, 0xffff_4ff9, 0xffff_2faa];
    assert_eq!(input.publish_legacy_debug_registers(&raw), Ok(true));
    let mut expected = before;
    for (i, value) in raw.into_iter().enumerate() {
        put_u64(&mut expected, 0x48 + i * 8, value);
    }
    assert_eq!(input.bytes, expected);
}

#[test]
fn every_get_group_preserves_all_unrequested_bytes_and_exact_flags() {
    let mut registers = [0u64; 20];
    for (index, value) in registers.iter_mut().enumerate() {
        *value = 0x1000 + index as u64;
    }
    let offsets = [
        0x78, 0x90, 0x80, 0x88, 0xa8, 0xb0, 0xa0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0,
    ];
    for groups in 0..8 {
        let mut input = context(groups);
        let mut expected = input.bytes;
        if groups & 1 != 0 {
            put_u64(&mut expected, 0xf8, registers[0]);
            put_u64(&mut expected, 0x98, registers[1]);
            put_u32(&mut expected, 0x44, registers[2] as u32);
            expected[0x38..0x3a].copy_from_slice(&0x33u16.to_le_bytes());
            expected[0x42..0x44].copy_from_slice(&0x2bu16.to_le_bytes());
        }
        if groups & 2 != 0 {
            for (i, offset) in offsets.into_iter().enumerate() {
                put_u64(&mut expected, offset, registers[3 + i]);
            }
        }
        if groups & 4 != 0 {
            for (offset, value) in [(0x3a, 0x2bu16), (0x3c, 0x2b), (0x3e, 0x53), (0x40, 0x2b)] {
                expected[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
        assert_eq!(input.publish_legacy_registers(&registers), Ok(groups != 0));
        assert_eq!(input.bytes, expected);
    }
}

#[test]
fn get_validation_is_no_mutation_and_unrequested_debug_is_untouched() {
    let mut input = context(0);
    let before = input.bytes;
    assert_eq!(
        input.publish_legacy_debug_registers(&[u64::MAX; 6]),
        Ok(false)
    );
    assert_eq!(input.bytes, before);
    for flags in [CONTEXT_AMD64 | 0x50, CONTEXT_AMD64 | 0x90, 0x10] {
        put_u32(&mut input.bytes, 0x30, flags);
        let before = input.bytes;
        let expected = if flags & CONTEXT_AMD64 == 0 {
            CodecError::InvalidArchitecture
        } else {
            CodecError::UnsupportedExtendedState
        };
        assert_eq!(input.publish_legacy_debug_registers(&[0; 6]), Err(expected));
        assert_eq!(input.publish_legacy_registers(&[0; 20]), Err(expected));
        assert_eq!(input.bytes, before);
    }
}

#[test]
fn fp_publication_remains_independent_of_debug_and_gpr_publication() {
    let mut input = context(CONTEXT_FLOATING_POINT | 0x10);
    let mut image = [0u8; 512];
    image[..2].copy_from_slice(&0x37fu16.to_le_bytes());
    image[24..28].copy_from_slice(&0x1fc0u32.to_le_bytes());
    input.publish_legacy_floating_point(&image).unwrap();
    let before = input.bytes;
    input
        .publish_legacy_debug_registers(&[1, 2, 3, 4, 5, 6])
        .unwrap();
    assert_eq!(
        &input.bytes[FLOAT_SAVE_OFFSET..],
        &before[FLOAT_SAVE_OFFSET..]
    );
    assert_eq!(input.publish_legacy_registers(&[u64::MAX; 20]), Ok(false));
}
