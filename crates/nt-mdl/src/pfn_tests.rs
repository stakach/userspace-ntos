use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// Noncontiguous owned frames for three virtual pages starting at 0x10_0000.
fn frames(page: u64) -> Option<u64> {
    match page {
        0x10_0000 => Some(0x7_3000),
        0x10_1000 => Some(0x2_9000),
        0x10_2000 => Some(0x9_1000),
        _ => None,
    }
}

fn populated(
    start: u64,
    offset: u32,
    count: u32,
    capacity: u64,
) -> (Result<u64, PfnError>, Vec<u64>) {
    let mut pfns = vec![0; capacity as usize];
    let result = populate(start, offset, count, capacity, frames, |index, pfn| {
        pfns[index as usize] = pfn;
    });
    (result, pfns)
}

#[test]
fn unaligned_one_page_buffer_records_its_frame() {
    assert_eq!(populated(0x10_0000, 0x123, 0x100, 1), (Ok(1), vec![0x73]));
}

#[test]
fn unaligned_buffer_crossing_a_page_records_both_noncontiguous_frames() {
    assert_eq!(
        populated(0x10_0000, 0xff0, 0x20, 2),
        (Ok(2), vec![0x73, 0x29])
    );
    assert_eq!(
        populated(0x10_0000, 0x800, 0x1801, 3),
        (Ok(3), vec![0x73, 0x29, 0x91])
    );
}

#[test]
fn any_untranslated_page_writes_no_pfn() {
    let (result, pfns) = populated(0x10_1000, 0x10, 0x2000, 3);
    assert_eq!(result, Err(PfnError::Untranslated { page: 0x10_3000 }));
    assert_eq!(pfns, [0, 0, 0]);
}

#[test]
fn unaligned_translation_writes_no_pfn() {
    let mut writes = 0;
    let result = populate(
        0x10_0000,
        0,
        0x2000,
        2,
        |page| Some(page + 8),
        |_, _| writes += 1,
    );
    assert_eq!(result, Err(PfnError::Unaligned { page: 0x10_0000 }));
    assert_eq!(writes, 0);
}

#[test]
fn declared_size_bounds_the_pfn_array() {
    assert_eq!(
        populated(0x10_0000, 0xff0, 0x20, 1).0,
        Err(PfnError::Capacity)
    );
    assert_eq!(pfn_capacity(48), Some(0));
    assert_eq!(pfn_capacity(48 + 16), Some(2));
    assert_eq!(pfn_capacity(47), None);
    assert_eq!(pfn_capacity(50), None);
    // A header-only MDL (as MmCreateMdl for zero bytes) has no PFN slot.
    assert_eq!(populated(0x10_0000, 0, 1, 0).0, Err(PfnError::Capacity));
}

#[test]
fn malformed_header_ranges_are_rejected() {
    for (start, offset, count) in [(0x10_0001, 0, 1), (0x10_0000, 0x1000, 1), (0x10_0000, 0, 0)] {
        assert_eq!(
            populated(start, offset, count, 4).0,
            Err(PfnError::InvalidRange)
        );
    }
    assert_eq!(span_pages(u64::MAX, 2), None);
}

#[test]
fn partial_subrange_copies_the_pages_it_spans() {
    // Source buffer 0x10_0800 + 0x2000 spans three pages; the subrange starts in the second.
    let source = [0x73, 0x29, 0x91];
    let (offset, count) = partial_window(0x10_0000, 0x800, 0x2000, 0x10_1ff0, 0x20).unwrap();
    assert_eq!((offset, count), (1, 2));
    assert_eq!(
        &source[offset as usize..(offset + count) as usize],
        &[0x29, 0x91]
    );
    assert_eq!(
        partial_window(0x10_0000, 0x800, 0x2000, 0x10_0800, 0x2000),
        Ok((0, 3))
    );
    assert_eq!(
        partial_window(0x10_0000, 0x800, 0x2000, 0x10_2000, 0x10),
        Ok((2, 1))
    );
}

#[test]
fn partial_subrange_outside_the_source_is_rejected() {
    for (address, length) in [(0x10_07ff, 1), (0x10_2700, 0x101), (0x10_0800, 0)] {
        assert_eq!(
            partial_window(0x10_0000, 0x800, 0x2000, address, length),
            Err(PfnError::InvalidRange)
        );
    }
}
