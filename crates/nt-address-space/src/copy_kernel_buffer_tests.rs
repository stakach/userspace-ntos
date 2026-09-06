use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn unaligned_scalar_crosses_pages_without_padding_or_rewriting_neighbors() {
    let value = 0x0123_4567_89ab_cdefu64.to_le_bytes();
    let mut destination = [0xa5; 16];
    let start = PAGE_SIZE - 3;
    let mut calls = Vec::new();
    write_kernel_buffer(start, &value, 2 * PAGE_SIZE, |address, bytes| {
        calls.push((address, bytes.len()));
        let offset = (address - start) as usize + 4;
        destination[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, [(PAGE_SIZE - 3, 3), (PAGE_SIZE, 5)]);
    assert_eq!(&destination[..4], &[0xa5; 4]);
    assert_eq!(&destination[4..12], &value);
    assert_eq!(&destination[12..], &[0xa5; 4]);
}

#[test]
fn invalid_whole_range_is_rejected_before_any_write() {
    for (address, size, limit) in [
        (0x1fff, 2, 0x2000),
        (u64::MAX - 3, 8, u64::MAX),
        (0x3000, 1, 0x2000),
    ] {
        let mut calls = 0;
        assert_eq!(
            write_kernel_buffer(address, &vec![0; size], limit, |_, _| {
                calls += 1;
                Ok(())
            }),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(calls, 0);
    }
}

#[test]
fn empty_buffer_never_touches_a_destination() {
    assert_eq!(
        write_kernel_buffer(u64::MAX, &[], 0, |_, _| panic!("empty write")),
        Ok(())
    );
}

#[test]
fn later_failure_preserves_prefix_and_exact_status_without_retry() {
    let input = vec![0x5a; PAGE_SIZE as usize + 3];
    let mut calls = Vec::new();
    let mut copied = 0;
    let result = write_kernel_buffer(PAGE_SIZE - 1, &input, 4 * PAGE_SIZE, |address, bytes| {
        calls.push(address);
        if address == 2 * PAGE_SIZE {
            return Err(STATUS_GUARD_PAGE_VIOLATION);
        }
        copied += bytes.len();
        Ok(())
    });
    assert_eq!(result, Err(STATUS_GUARD_PAGE_VIOLATION));
    assert_eq!(calls, [PAGE_SIZE - 1, PAGE_SIZE, 2 * PAGE_SIZE]);
    assert_eq!(copied, PAGE_SIZE as usize + 1);
}

#[test]
fn first_page_admission_failure_prevents_all_bytes_and_later_pages() {
    let mut calls = 0;
    assert_eq!(
        write_kernel_buffer(PAGE_SIZE - 1, &[1, 2, 3], 3 * PAGE_SIZE, |_, _| {
            calls += 1;
            Err(crate::STATUS_COMMITMENT_LIMIT)
        }),
        Err(crate::STATUS_COMMITMENT_LIMIT)
    );
    assert_eq!(calls, 1);
}

#[test]
fn all_alignment_and_tail_cases_use_exact_page_contained_slices() {
    for offset in [0, 1, 7, 17, 4093, 4095] {
        for length in [1, 2, 8, 513, 4096, 4099] {
            let input: Vec<_> = (0..length).map(|byte| byte as u8).collect();
            let start = PAGE_SIZE + offset;
            let mut output = Vec::new();
            let mut expected_address = start;
            write_kernel_buffer(start, &input, 4 * PAGE_SIZE, |address, bytes| {
                assert_eq!(address, expected_address);
                assert!(!bytes.is_empty());
                assert!(address % PAGE_SIZE + bytes.len() as u64 <= PAGE_SIZE);
                output.extend_from_slice(bytes);
                expected_address += bytes.len() as u64;
                Ok(())
            })
            .unwrap();
            assert_eq!(expected_address, start + length as u64);
            assert_eq!(output, input);
        }
    }
}
