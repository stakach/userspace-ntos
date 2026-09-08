use super::*;

fn bytes(flags: u32) -> [u8; AMD64_CONTEXT_SIZE] {
    let mut bytes = [0; AMD64_CONTEXT_SIZE];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    bytes[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
    bytes
}

fn captured(bytes: &[u8; AMD64_CONTEXT_SIZE]) -> CapturedAmd64Context {
    CapturedAmd64Context::capture(
        |_, output| {
            output.copy_from_slice(bytes);
            Ok(())
        },
        0x1000,
    )
    .unwrap()
}

#[test]
fn full_context_capture_preserves_every_byte_and_projects_only_startup_fields() {
    let bytes = bytes(CONTEXT_FLOATING_POINT | 3);
    let mut calls = 0;
    let context = CapturedAmd64Context::capture(
        |address, output| {
            calls += 1;
            assert_eq!(address, 0x4000);
            assert_eq!(output.len(), 0x4d0);
            output.copy_from_slice(&bytes);
            Ok(())
        },
        0x4000,
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(context.as_bytes(), &bytes);
    assert_eq!(context.flags(), CONTEXT_FLOATING_POINT | 3);
    assert_eq!(
        context.startup_projection(),
        Amd64ThreadContext {
            rip: captured_u64(&bytes, CONTEXT_RIP_OFFSET),
            rsp: captured_u64(&bytes, CONTEXT_RSP_OFFSET),
            rcx: captured_u64(&bytes, CONTEXT_RCX_OFFSET),
            rdx: captured_u64(&bytes, CONTEXT_RDX_OFFSET),
        }
    );
}

#[test]
fn full_context_capture_rejects_invalid_spans_and_alignment_before_read() {
    for (address, error) in [
        (0, CaptureError::InvalidAddress),
        (u64::MAX - 15, CaptureError::InvalidAddress),
        (0x1008, CaptureError::Misaligned),
    ] {
        assert_eq!(
            CapturedAmd64Context::capture(|_, _| panic!("invalid read"), address),
            Err(error)
        );
    }
}

#[test]
fn full_context_capture_preserves_reader_status_after_partial_or_complete_copy() {
    for (copied, status) in [
        (0, 0xc000_0005),
        (0x100, 0x8000_0001),
        (AMD64_CONTEXT_SIZE, 0xc000_0006),
    ] {
        assert_eq!(
            CapturedAmd64Context::capture(
                |_, output| {
                    output[..copied].fill(0x55);
                    Err(status)
                },
                0x1000
            ),
            Err(CaptureError::ReadFailed(status))
        );
    }
}

#[test]
fn extraction_uses_top_level_mxcsr_and_preserves_all_other_fp_bytes() {
    let mut bytes = bytes(CONTEXT_FLOATING_POINT);
    bytes[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[CONTEXT_MXCSR_OFFSET..CONTEXT_MXCSR_OFFSET + 4]
        .copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    bytes[FLOAT_SAVE_OFFSET + FX_MXCSR_OFFSET..FLOAT_SAVE_OFFSET + FX_MXCSR_OFFSET + 4].fill(0);
    let context = captured(&bytes);
    let image = context.extract_legacy_floating_point().unwrap().unwrap();
    assert_eq!(u16::from_le_bytes(image[..2].try_into().unwrap()), 0x1f37);
    assert_eq!(read_u32(&image, FX_MXCSR_OFFSET), 0xffbf);
    for offset in 0..LEGACY_FLOATING_POINT_BYTES {
        if offset < 2 || (FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4).contains(&offset) {
            continue;
        }
        assert_eq!(image[offset], bytes[FLOAT_SAVE_OFFSET + offset]);
    }
    assert_eq!(context.as_bytes(), &bytes);
}

#[test]
fn publication_updates_both_mxcsr_locations_and_only_requested_fp_group() {
    let original = bytes(CONTEXT_FLOATING_POINT | 0x8000_0017);
    let mut context = captured(&original);
    let mut image = [0; LEGACY_FLOATING_POINT_BYTES];
    for (index, byte) in image.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(11);
    }
    image[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    image[FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert_eq!(context.publish_legacy_floating_point(&image), Ok(true));
    assert_eq!(context.flags(), CONTEXT_FLOATING_POINT | 0x8000_0017);
    assert_eq!(read_u32(context.as_bytes(), CONTEXT_MXCSR_OFFSET), u32::MAX);
    let mut expected = original;
    expected[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES]
        .copy_from_slice(&image);
    expected[CONTEXT_MXCSR_OFFSET..CONTEXT_MXCSR_OFFSET + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(context.as_bytes(), &expected);
    // FXSAVE's x87 slots and all sixteen XMM registers survive without truncation.
    assert_eq!(
        &context.as_bytes()[FLOAT_SAVE_OFFSET + 32..FLOAT_SAVE_OFFSET + 416],
        &image[32..416]
    );
    assert_eq!(image[..2], u16::MAX.to_le_bytes());
}

#[test]
fn get_preserves_hardware_fcw_and_daz_while_set_applies_nt5_masks() {
    let mut context = captured(&bytes(CONTEXT_FLOATING_POINT));
    let mut image = [0; LEGACY_FLOATING_POINT_BYTES];
    image[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    image[FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4].copy_from_slice(&0x1fc0u32.to_le_bytes());
    context.publish_legacy_floating_point(&image).unwrap();
    assert_eq!(
        &context.as_bytes()[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES],
        &image
    );
    assert_eq!(read_u32(context.as_bytes(), CONTEXT_MXCSR_OFFSET), 0x1fc0);
    assert_eq!(
        read_u32(context.as_bytes(), FLOAT_SAVE_OFFSET + FX_MXCSR_OFFSET),
        0x1fc0
    );
    let set_image = context.extract_legacy_floating_point().unwrap().unwrap();
    assert_eq!(
        u16::from_le_bytes(set_image[..2].try_into().unwrap()),
        0x037f & NT5_FCW_MASK
    );
    assert_eq!(read_u32(&set_image, FX_MXCSR_OFFSET), 0x1f80);
    assert_eq!(read_u32(context.as_bytes(), CONTEXT_MXCSR_OFFSET), 0x1fc0);
}

#[test]
fn sanitized_fp_roundtrip_is_stable() {
    let original = bytes(CONTEXT_FLOATING_POINT);
    let mut context = captured(&original);
    let image = context.extract_legacy_floating_point().unwrap().unwrap();
    assert_eq!(context.publish_legacy_floating_point(&image), Ok(true));
    assert_eq!(
        context.extract_legacy_floating_point().unwrap(),
        Some(image)
    );
    assert_eq!(
        read_u32(context.as_bytes(), CONTEXT_MXCSR_OFFSET),
        read_u32(&image, FX_MXCSR_OFFSET)
    );
}

#[test]
fn unrequested_fp_group_preserves_reserved_and_unrelated_context_bytes() {
    for flags in [0, CONTEXT_AMD64 | 3, CONTEXT_AMD64 | 0x8000_0017, 0x8] {
        let original = bytes(flags);
        let mut context = captured(&original);
        assert_eq!(context.extract_legacy_floating_point(), Ok(None));
        assert_eq!(
            context.publish_legacy_floating_point(&[0xff; LEGACY_FLOATING_POINT_BYTES]),
            Ok(false)
        );
        assert_eq!(context.as_bytes(), &original);
    }
}

#[test]
fn extended_state_requests_are_explicitly_unsupported_without_mutation() {
    for flags in [
        CONTEXT_XSTATE,
        CONTEXT_XSTATE | CONTEXT_FLOATING_POINT,
        0x40,
        CONTEXT_AMD64 | 0x80,
        CONTEXT_FLOATING_POINT | 0x80,
        0x80,
    ] {
        let original = bytes(flags);
        let mut context = captured(&original);
        assert_eq!(
            context.validate_legacy_state(),
            Err(CodecError::UnsupportedExtendedState)
        );
        assert_eq!(
            context.extract_legacy_floating_point(),
            Err(CodecError::UnsupportedExtendedState)
        );
        assert_eq!(
            context.publish_legacy_floating_point(&[0; LEGACY_FLOATING_POINT_BYTES]),
            Err(CodecError::UnsupportedExtendedState)
        );
        assert_eq!(context.as_bytes(), &original);
    }
    assert_eq!(CodecError::UnsupportedExtendedState.status(), 0xc000_00bb);
}
