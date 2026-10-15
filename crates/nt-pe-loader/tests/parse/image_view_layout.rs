//! Canonical SEC_IMAGE raw-page policy, independent of native view placement or ownership.

use super::*;

#[test]
fn raw_page_preserves_image_addresses_and_source_across_loader_writes() {
    let pointer = BASE + 0x1234;
    let mut payload = vec![0x90; 0x1000];
    payload[0x38..0x40].copy_from_slice(&pointer.to_le_bytes());
    let bytes = build_pe(BASE, 0x1000, 0x3000, &[text_section(0x1000, payload)], &[]);
    let before = bytes.clone();
    let pe = PeFile::parse(&bytes).unwrap();
    let mut first_view = fill_image_page(&pe, 0x1000, bytes.len() as u64);
    assert_eq!(
        u64::from_le_bytes(first_view[0x38..0x40].try_into().unwrap()),
        pointer
    );
    // Real user-mode relocation/import writes mutate a private view, not the captured source.
    first_view[0x38..0x40].copy_from_slice(&(pointer + 0x400000).to_le_bytes());
    let second_view = fill_image_page(&pe, 0x1000, bytes.len() as u64);
    assert_eq!(
        u64::from_le_bytes(second_view[0x38..0x40].try_into().unwrap()),
        pointer
    );
    assert_eq!(bytes, before);
}

#[test]
fn full_image_page_protections_separate_private_copy_and_explicit_shared_data() {
    let mut bytes = build_pe(
        BASE,
        0x1000,
        0x6000,
        &[
            text_section(0x1000, vec![0xcc; 0x1800]),
            Sec {
                name: *b".shared\0",
                va: 0x3000,
                chars: 0xd0000040,
                data: vec![0x55; 0x200],
            },
            Sec {
                name: *b".bss\0\0\0\0",
                va: 0x4000,
                chars: 0xc0000080,
                data: Vec::new(),
            },
        ],
        &[],
    );
    put_u32(&mut bytes, SECTION_TABLE + 2 * 40 + 8, 0x1000);
    let pe = PeFile::parse(&bytes).unwrap();
    let protections: Vec<_> = (0..pe.size_of_image())
        .step_by(0x1000)
        .map(|rva| {
            pe.image_page_fill_plan(rva, bytes.len() as u64)
                .unwrap()
                .protection()
        })
        .collect();
    assert_eq!(
        protections,
        [
            ImageProtection::ReadOnly,
            ImageProtection::ExecuteWriteCopy,
            ImageProtection::ExecuteWriteCopy,
            ImageProtection::ReadWrite,
            ImageProtection::WriteCopy,
            ImageProtection::ReadOnly
        ]
    );
    let writecopy_bytes = protections
        .iter()
        .filter(|protection| protection.copy_on_write())
        .count()
        * 0x1000;
    assert_eq!(writecopy_bytes, 0x3000);
    assert!(fill_image_page(&pe, 0x4000, bytes.len() as u64)
        .iter()
        .all(|byte| *byte == 0));
}

#[test]
fn every_image_page_span_is_inside_authenticated_file_and_one_output_page() {
    let bytes = build_pe(
        BASE,
        0x1000,
        0x4000,
        &[text_section(0x1000, vec![0xcc; 0x1100])],
        &[],
    );
    let pe = PeFile::parse(&bytes).unwrap();
    for rva in (0..pe.size_of_image()).step_by(0x1000) {
        let plan = pe.image_page_fill_plan(rva, bytes.len() as u64).unwrap();
        for span in plan.spans() {
            assert!(
                span.file_offset
                    .checked_add(u64::from(span.length))
                    .unwrap()
                    <= bytes.len() as u64
            );
            assert!(usize::from(span.page_offset) + usize::from(span.length) <= 0x1000);
        }
    }
    let tail = fill_image_page(&pe, 0x2000, bytes.len() as u64);
    assert!(tail[..0x100].iter().all(|byte| *byte == 0xcc));
    assert!(tail[0x200..].iter().all(|byte| *byte == 0));
}

#[test]
fn header_page_plan_rejects_truncated_full_image_backing() {
    let bytes = build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xcc; 0x400])],
        &[],
    );
    let pe = PeFile::parse(&bytes).unwrap();
    assert_eq!(
        pe.image_page_fill_plan(0, bytes.len() as u64 - 1),
        Err(PeError::SectionOutOfBounds)
    );
    assert!(pe.image_page_fill_plan(0, bytes.len() as u64).is_ok());
}
