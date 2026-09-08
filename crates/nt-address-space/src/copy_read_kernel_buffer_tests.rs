use super::*;
use alloc::{vec, vec::Vec};

#[test]
fn empty_capture_never_reads_even_an_invalid_address() {
    assert_eq!(
        read_kernel_buffer(u64::MAX, &mut [], 0, |_, _| panic!("empty read")),
        Ok(())
    );
}

#[test]
fn invalid_whole_span_preserves_output_without_reading_a_prefix() {
    for (address, length, limit) in [
        (0x1fff, 2, 0x2000),
        (u64::MAX - 3, 8, u64::MAX),
        (u64::MAX, 1, u64::MAX),
        (0x3000, 1, 0x2000),
        (0, 1, 0),
    ] {
        let mut output = vec![0xa5; length];
        assert_eq!(
            read_kernel_buffer(address, &mut output, limit, |_, _| panic!(
                "invalid span read"
            )),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(output, vec![0xa5; length]);
    }
}

#[test]
fn zero_address_and_exact_user_limit_are_delegated_without_extra_policy() {
    let mut output = [0xa5; 8];
    let mut calls = Vec::new();
    read_kernel_buffer(0, &mut output, 8, |address, bytes| {
        calls.push((address, bytes.len()));
        bytes.fill(0x5a);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, [(0, 8)]);
    assert_eq!(output, [0x5a; 8]);
}

#[test]
fn unaligned_read_captures_exact_bytes_and_preserves_output_neighbors() {
    let value = 0x0123_4567_89ab_cdefu64.to_le_bytes();
    let mut output = [0xa5; 16];
    let start = PAGE_SIZE - 3;
    let mut calls = Vec::new();
    read_kernel_buffer(
        start,
        &mut output[4..12],
        2 * PAGE_SIZE,
        |address, bytes| {
            calls.push((address, bytes.len()));
            let offset = (address - start) as usize;
            bytes.copy_from_slice(&value[offset..offset + bytes.len()]);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls, [(PAGE_SIZE - 3, 3), (PAGE_SIZE, 5)]);
    assert_eq!(&output[..4], &[0xa5; 4]);
    assert_eq!(&output[4..12], &value);
    assert_eq!(&output[12..], &[0xa5; 4]);
}

#[test]
fn first_failure_returns_exact_status_without_retry_or_reading_next_page() {
    let mut output = [0xa5; 3];
    let mut calls = Vec::new();
    assert_eq!(
        read_kernel_buffer(
            PAGE_SIZE - 1,
            &mut output,
            3 * PAGE_SIZE,
            |address, bytes| {
                calls.push((address, bytes.len()));
                Err(crate::STATUS_COMMITMENT_LIMIT)
            }
        ),
        Err(crate::STATUS_COMMITMENT_LIMIT)
    );
    assert_eq!(calls, [(PAGE_SIZE - 1, 1)]);
    assert_eq!(output, [0xa5; 3]);
}

#[test]
fn later_failure_preserves_completed_prefix_and_never_retries_failed_alias() {
    let mut output = vec![0xa5; PAGE_SIZE as usize + 3];
    let mut calls = Vec::new();
    let result = read_kernel_buffer(
        PAGE_SIZE - 1,
        &mut output,
        4 * PAGE_SIZE,
        |address, bytes| {
            calls.push((address, bytes.len()));
            if address == 2 * PAGE_SIZE {
                return Err(STATUS_GUARD_PAGE_VIOLATION);
            }
            bytes.fill(0x5a);
            Ok(())
        },
    );
    assert_eq!(result, Err(STATUS_GUARD_PAGE_VIOLATION));
    assert_eq!(
        calls,
        [
            (PAGE_SIZE - 1, 1),
            (PAGE_SIZE, PAGE_SIZE as usize),
            (2 * PAGE_SIZE, 2)
        ]
    );
    assert!(output[..PAGE_SIZE as usize + 1]
        .iter()
        .all(|&byte| byte == 0x5a));
    assert_eq!(&output[PAGE_SIZE as usize + 1..], &[0xa5; 2]);
}

#[test]
fn a_failing_backend_may_change_only_its_supplied_chunk_without_losing_prior_capture() {
    let mut output = vec![0xa5; PAGE_SIZE as usize + 3];
    let mut calls = 0;
    assert_eq!(
        read_kernel_buffer(PAGE_SIZE - 1, &mut output, 4 * PAGE_SIZE, |_, bytes| {
            calls += 1;
            bytes[0] = 0x5a;
            if calls == 2 {
                Err(STATUS_ACCESS_VIOLATION)
            } else {
                Ok(())
            }
        }),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(calls, 2);
    assert_eq!(&output[..2], &[0x5a; 2]);
    assert!(output[2..].iter().all(|&byte| byte == 0xa5));
}

#[test]
fn every_alignment_and_tail_uses_contiguous_nonempty_page_contained_chunks() {
    for offset in [0, 1, 7, 17, 4093, 4095] {
        for length in [1, 2, 8, 513, 4096, 4099] {
            let input: Vec<_> = (0..length).map(|index| index as u8).collect();
            let mut output = vec![0xa5; length];
            let start = PAGE_SIZE + offset;
            let mut copied = 0;
            read_kernel_buffer(start, &mut output, 4 * PAGE_SIZE, |address, bytes| {
                assert_eq!(address, start + copied as u64);
                assert!(!bytes.is_empty());
                assert!(address % PAGE_SIZE + bytes.len() as u64 <= PAGE_SIZE);
                bytes.copy_from_slice(&input[copied..copied + bytes.len()]);
                copied += bytes.len();
                Ok(())
            })
            .unwrap();
            assert_eq!(copied, length);
            assert_eq!(output, input);
        }
    }
}
