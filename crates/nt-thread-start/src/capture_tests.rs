use super::*;

#[test]
fn invalid_context_span_never_calls_reader() {
    for address in [0, u64::MAX, u64::MAX - AMD64_CONTEXT_SIZE as u64 + 1] {
        assert_eq!(
            Amd64ThreadContext::capture(|_, _| panic!("invalid span reached reader"), address),
            Err(CaptureError::InvalidAddress)
        );
    }
}

#[test]
fn invalid_initial_teb_span_never_calls_reader() {
    for address in [0, u64::MAX, u64::MAX - INITIAL_TEB64_SIZE as u64 + 1] {
        assert_eq!(
            InitialTeb64::capture(|_, _| panic!("invalid span reached reader"), address),
            Err(CaptureError::InvalidAddress)
        );
    }
}

#[test]
fn misaligned_context_never_calls_reader() {
    assert_eq!(AMD64_CONTEXT_ALIGNMENT, 16);
    for offset in 1..AMD64_CONTEXT_ALIGNMENT {
        assert_eq!(
            Amd64ThreadContext::capture(
                |_, _| panic!("misaligned context reached reader"),
                0x1000 + offset,
            ),
            Err(CaptureError::Misaligned)
        );
    }
}

#[test]
fn misaligned_initial_teb_never_calls_reader() {
    assert_eq!(INITIAL_TEB64_ALIGNMENT, 4);
    for offset in 1..INITIAL_TEB64_ALIGNMENT {
        assert_eq!(
            InitialTeb64::capture(
                |_, _| panic!("misaligned INITIAL_TEB reached reader"),
                0x2000 + offset,
            ),
            Err(CaptureError::Misaligned)
        );
    }
}

#[test]
fn either_old_stack_field_is_explicitly_unsupported_after_complete_capture() {
    for (old_base, old_limit) in [(1, 0), (0, 1), (u64::MAX, u64::MAX)] {
        let mut calls = 0;
        let result = InitialTeb64::capture(
            |address, bytes| {
                calls += 1;
                assert_eq!(address, 0x2000);
                assert_eq!(bytes.len(), INITIAL_TEB64_SIZE);
                bytes.fill(0);
                put_u64(bytes, 0, old_base);
                put_u64(bytes, 8, old_limit);
                put_u64(bytes, INITIAL_TEB_STACK_BASE_OFFSET as usize, 0x9000);
                put_u64(bytes, INITIAL_TEB_STACK_LIMIT_OFFSET as usize, 0x8000);
                put_u64(
                    bytes,
                    INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET as usize,
                    0x7000,
                );
                Ok(())
            },
            0x2000,
        );
        assert_eq!(result, Err(CaptureError::UnsupportedOldStack));
        assert_eq!(calls, 1);
    }
}

#[test]
fn capture_errors_have_exact_native_statuses() {
    assert_eq!(CaptureError::InvalidAddress.status(), 0xc000_0005);
    for status in [0xc000_0005, 0x8000_0001, 0xc000_012d, 0xc000_0006] {
        assert_eq!(CaptureError::ReadFailed(status).status(), status);
    }
    assert_eq!(CaptureError::Misaligned.status(), 0x8000_0002);
    assert_eq!(CaptureError::UnsupportedOldStack.status(), 0xc000_00bb);
}

#[test]
fn complete_context_is_requested_once_even_when_only_four_registers_are_projected() {
    let mut calls = 0;
    let context = Amd64ThreadContext::capture(
        |address, bytes| {
            calls += 1;
            assert_eq!(address, 0x1000);
            assert_eq!(bytes.len(), AMD64_CONTEXT_SIZE);
            bytes.fill(0xa5);
            put_u64(bytes, CONTEXT_RIP_OFFSET as usize, 1);
            put_u64(bytes, CONTEXT_RSP_OFFSET as usize, 2);
            put_u64(bytes, CONTEXT_RCX_OFFSET as usize, 3);
            put_u64(bytes, CONTEXT_RDX_OFFSET as usize, 4);
            Ok(())
        },
        0x1000,
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(
        context,
        Amd64ThreadContext {
            rip: 1,
            rsp: 2,
            rcx: 3,
            rdx: 4
        }
    );
}

#[test]
fn complete_initial_teb_including_previous_stack_fields_is_requested_once() {
    let mut calls = 0;
    let teb = InitialTeb64::capture(
        |address, bytes| {
            calls += 1;
            assert_eq!(address, 0x2004);
            assert_eq!(bytes.len(), 40);
            bytes[..16].fill(0);
            put_u64(bytes, INITIAL_TEB_STACK_BASE_OFFSET as usize, 1);
            put_u64(bytes, INITIAL_TEB_STACK_LIMIT_OFFSET as usize, 2);
            put_u64(bytes, INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET as usize, 3);
            Ok(())
        },
        0x2004,
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(
        teb,
        InitialTeb64 {
            stack_base: 1,
            stack_limit: 2,
            allocated_stack_base: 3
        }
    );
}

#[test]
fn short_context_capture_never_returns_partially_decoded_registers() {
    // A readable register prefix is insufficient: even the last byte of CONTEXT is required.
    let source = [0x5a; AMD64_CONTEXT_SIZE];
    for available in [0, 1, 0x100, AMD64_CONTEXT_SIZE - 1] {
        let mut calls = 0;
        let result = Amd64ThreadContext::capture(
            |_, output| {
                calls += 1;
                output[..available].copy_from_slice(&source[..available]);
                Err(0xc000_0005)
            },
            0x1000,
        );
        assert_eq!(result, Err(CaptureError::ReadFailed(0xc000_0005)));
        assert_eq!(calls, 1);
    }
}

#[test]
fn short_initial_teb_capture_never_returns_partially_decoded_bounds() {
    let source = [0x5a; INITIAL_TEB64_SIZE];
    for available in [0, 1, 16, INITIAL_TEB64_SIZE - 1] {
        let mut calls = 0;
        let result = InitialTeb64::capture(
            |_, output| {
                calls += 1;
                output[..available].copy_from_slice(&source[..available]);
                Err(0xc000_0005)
            },
            0x2000,
        );
        assert_eq!(result, Err(CaptureError::ReadFailed(0xc000_0005)));
        assert_eq!(calls, 1);
    }
}

#[test]
fn reader_failure_is_authoritative_even_after_filling_the_destination() {
    assert_eq!(
        Amd64ThreadContext::capture(
            |_, bytes| {
                bytes.fill(0xff);
                Err(0x8000_0001)
            },
            0x1000
        ),
        Err(CaptureError::ReadFailed(0x8000_0001))
    );
    assert_eq!(
        InitialTeb64::capture(
            |_, bytes| {
                bytes.fill(0xff);
                Err(0xc000_012d)
            },
            0x2000
        ),
        Err(CaptureError::ReadFailed(0xc000_012d))
    );
}

#[test]
fn highest_aligned_nonwrapping_span_is_read_without_adding_address_space_policy() {
    let context_address = (u64::MAX - AMD64_CONTEXT_SIZE as u64) & !(AMD64_CONTEXT_ALIGNMENT - 1);
    assert_eq!(
        Amd64ThreadContext::capture(
            |address, bytes| {
                assert_eq!(address, context_address);
                bytes.fill(0);
                Ok(())
            },
            context_address,
        ),
        Ok(Amd64ThreadContext {
            rip: 0,
            rsp: 0,
            rcx: 0,
            rdx: 0
        })
    );
    let teb_address = (u64::MAX - INITIAL_TEB64_SIZE as u64) & !(INITIAL_TEB64_ALIGNMENT - 1);
    assert_eq!(
        InitialTeb64::capture(
            |address, bytes| {
                assert_eq!(address, teb_address);
                bytes.fill(0);
                Ok(())
            },
            teb_address,
        ),
        Ok(InitialTeb64 {
            stack_base: 0,
            stack_limit: 0,
            allocated_stack_base: 0
        })
    );
}
