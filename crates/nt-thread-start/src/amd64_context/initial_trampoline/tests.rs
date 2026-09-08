use super::*;

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn check_continue_tail(bytes: &[u8], context: u64, nt_continue: u64) {
    assert_eq!(bytes.len(), 26);
    assert_eq!(&bytes[..2], &[0x48, 0xb9]);
    assert_eq!(word(bytes, 2), context);
    assert_eq!(&bytes[10..14], &[0x31, 0xd2, 0x48, 0xb8]);
    assert_eq!(word(bytes, 14), nt_continue);
    assert_eq!(&bytes[22..], &[0xff, 0xd0, 0x0f, 0x0b]);
}

#[test]
fn direct_start_calls_continue_false_and_traps_on_return() {
    let code = initial_context_trampoline(0x11900, 0x8877_6655_4433_2211, None).unwrap();
    assert_eq!(code.as_bytes().len(), 30);
    assert_eq!(&code.as_bytes()[..4], &[0x48, 0x83, 0xec, 0x20]);
    check_continue_tail(&code.as_bytes()[4..], 0x11900, 0x8877_6655_4433_2211);
}

#[test]
fn loader_receives_same_durable_context_then_continue_reloads_arguments() {
    let code = initial_context_trampoline(0x11900, 0x1111, Some((0x2222, 0x3333))).unwrap();
    let bytes = code.as_bytes();
    assert_eq!(bytes.len(), INITIAL_CONTEXT_TRAMPOLINE_CAPACITY);
    assert_eq!(
        &bytes[..8],
        &[0x48, 0x83, 0xec, 0x20, 0x31, 0xc9, 0x48, 0xba]
    );
    assert_eq!(word(bytes, 8), 0x3333);
    assert_eq!(&bytes[16..21], &[0x45, 0x31, 0xc0, 0x49, 0xb9]);
    assert_eq!(word(bytes, 21), 0x11900);
    assert_eq!(&bytes[29..31], &[0x48, 0xb8]);
    assert_eq!(word(bytes, 31), 0x2222);
    assert_eq!(&bytes[39..41], &[0xff, 0xd0]);
    check_continue_tail(&bytes[41..], 0x11900, 0x1111);
}

#[test]
fn missing_exports_and_bad_context_storage_are_rejected() {
    for address in [0, 0x11901, u64::MAX - 15] {
        assert!(matches!(
            initial_context_trampoline(address, 1, None),
            Err(CodecError::InvalidContextAddress)
        ));
    }
    for (entry, loader) in [(0, None), (1, Some((0, 1))), (1, Some((1, 0)))] {
        assert!(matches!(
            initial_context_trampoline(0x11900, entry, loader),
            Err(CodecError::InvalidInstructionPointer)
        ));
    }
}

#[test]
fn existing_teb_tail_context_is_aligned_and_below_retained_canary() {
    const CONTEXT_OFFSET: usize = 0x1900;
    const CANARY_OFFSET: usize = 0x1fc0;
    assert_eq!(CONTEXT_OFFSET % AMD64_CONTEXT_ALIGNMENT as usize, 0);
    assert_eq!(CONTEXT_OFFSET + AMD64_CONTEXT_SIZE, 0x1dd0);
    assert!(CONTEXT_OFFSET + AMD64_CONTEXT_SIZE <= CANARY_OFFSET);
}
