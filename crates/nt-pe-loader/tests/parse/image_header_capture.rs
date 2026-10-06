//! SEC_IMAGE metadata capture reads bounded header windows, not the File payload.

use super::*;
use nt_pe_loader::{capture_image_layout, ImageHeaderCaptureError};

fn capture_bytes(bytes: &[u8]) -> nt_pe_loader::PeLayout {
    capture_image_layout(bytes.len() as u64, |offset, output: &mut [u8]| {
        let start = offset as usize;
        output.copy_from_slice(&bytes[start..start + output.len()]);
        Ok::<_, u32>(output.len())
    })
    .unwrap()
}

#[test]
fn small_file_capture_and_owned_plans_match_full_file_parser() {
    let bytes = build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xcc; 0x200])],
        &[],
    );
    assert!(bytes.len() < 4096);
    let mut reads = Vec::new();
    let layout = capture_image_layout(bytes.len() as u64, |offset, output: &mut [u8]| {
        reads.push((offset, output.len()));
        output.copy_from_slice(&bytes[offset as usize..offset as usize + output.len()]);
        Ok::<_, u32>(output.len())
    })
    .unwrap();
    assert_eq!(reads, [(0, bytes.len())]);
    let pe = PeFile::parse(&bytes).unwrap();
    for rva in (0..pe.size_of_image()).step_by(4096) {
        assert_eq!(
            layout.image_page_fill_plan(rva, bytes.len() as u64),
            pe.image_page_fill_plan(rva, bytes.len() as u64)
        );
        assert_eq!(layout.image_protection_at(rva), pe.image_protection_at(rva));
    }
    assert_eq!(capture_bytes(&bytes).headers().image_base, BASE);
}

struct SparseHeaders {
    dos: [u8; 64],
    nt: Vec<u8>,
    offset: u32,
    extent: u64,
}

impl SparseHeaders {
    fn new(offset: u32, count: usize) -> Self {
        let sections: Vec<_> = (0..count)
            .map(|i| text_section(0x1000 + i as u32 * 0x1000, vec![0xcc; 0x200]))
            .collect();
        let bytes = build_pe(BASE, 0x1000, 0x100000, &sections, &[]);
        let mut dos = [0; 64];
        dos.copy_from_slice(&bytes[..64]);
        put_u32(&mut dos, 0x3c, offset);
        let nt = bytes[NT_OFF..SECTION_TABLE + count * 40].to_vec();
        Self {
            dos,
            nt,
            offset,
            extent: u64::from(offset) + 0x10000,
        }
    }

    fn read(&self, offset: u64, output: &mut [u8]) -> usize {
        output.fill(0);
        for (start, bytes) in [
            (0, self.dos.as_slice()),
            (u64::from(self.offset), self.nt.as_slice()),
        ] {
            let begin = offset.max(start);
            let end = (offset + output.len() as u64).min(start + bytes.len() as u64);
            if begin < end {
                output[(begin - offset) as usize..(end - offset) as usize]
                    .copy_from_slice(&bytes[(begin - start) as usize..(end - start) as usize]);
            }
        }
        output.len()
    }
}

#[test]
fn high_nt_offset_does_not_capture_dos_gap_eof_or_size_of_headers() {
    let mut source = SparseHeaders::new(0x7000_0300, 1);
    // Metadata declares a large header region, but capture needs only the typed table.
    put_u32(&mut source.nt, 24 + 60, 0x7000_1000);
    let mut reads = Vec::new();
    let layout = capture_image_layout(source.extent, |offset, output: &mut [u8]| {
        reads.push((offset, output.len()));
        Ok::<_, u32>(source.read(offset, output))
    })
    .unwrap();
    assert_eq!(layout.headers().nt_offset, source.offset as usize);
    assert_eq!(layout.headers().size_of_headers, 0x7000_1000);
    assert_eq!(reads, [(0, 4096), (0x7000_0000, 8192)]);
    assert_eq!(layout.sections().len(), 1);
}

#[test]
fn ninety_six_sections_crossing_nt_window_use_bounded_table_window() {
    let source = SparseHeaders::new(0xffc, 96);
    let mut reads = Vec::new();
    let layout = capture_image_layout(source.extent, |offset, output: &mut [u8]| {
        reads.push((offset, output.len()));
        Ok::<_, u32>(source.read(offset, output))
    })
    .unwrap();
    assert_eq!(layout.headers().nt_offset, 0xffc);
    assert_eq!(layout.sections().len(), 96);
    assert_eq!(reads, [(0, 4096), (0, 8192), (4096, 8192)]);
}

#[test]
fn capture_refuses_short_reads_and_preserves_actual_read_error() {
    let source = SparseHeaders::new(0x3000, 1);
    for failing_read in [0, 1] {
        let mut calls = 0;
        let error = capture_image_layout(source.extent, |offset, output: &mut [u8]| {
            let this = calls;
            calls += 1;
            if this == failing_read {
                return Ok::<_, u32>(output.len() - 1);
            }
            Ok(source.read(offset, output))
        })
        .unwrap_err();
        assert_eq!(
            error,
            ImageHeaderCaptureError::ShortRead {
                expected: if failing_read == 0 { 4096 } else { 8192 },
                actual: if failing_read == 0 { 4095 } else { 8191 },
            }
        );
        assert_eq!(calls, failing_read + 1);
    }
    let mut calls = 0;
    let error = capture_image_layout(source.extent, |offset, output: &mut [u8]| {
        calls += 1;
        if calls == 2 {
            return Err(0xc0000185u32);
        }
        Ok(source.read(offset, output))
    })
    .unwrap_err();
    assert_eq!(error, ImageHeaderCaptureError::Read(0xc0000185));
    assert_eq!(calls, 2);
}

#[test]
fn capture_rejects_outside_eof_truncated_table_and_excess_section_count() {
    let source = SparseHeaders::new(0xffff_fffc, 1);
    let mut calls = 0;
    assert_eq!(
        capture_image_layout(4096, |offset, output: &mut [u8]| {
            calls += 1;
            Ok::<_, u32>(source.read(offset, output))
        })
        .unwrap_err(),
        ImageHeaderCaptureError::Parse(PeError::Truncated)
    );
    assert_eq!(calls, 1, "invalid offset is refused before a second read");
    let source = SparseHeaders::new(0xffc, 96);
    let extent = u64::from(source.offset) + source.nt.len() as u64 - 1;
    assert_eq!(
        capture_image_layout(extent, |offset, output: &mut [u8]| {
            Ok::<_, u32>(source.read(offset, output))
        })
        .unwrap_err(),
        ImageHeaderCaptureError::Parse(PeError::Truncated)
    );
    let mut source = SparseHeaders::new(0x3000, 1);
    put_u16(&mut source.nt, 6, 97);
    assert_eq!(
        capture_image_layout(source.extent, |offset, output: &mut [u8]| {
            Ok::<_, u32>(source.read(offset, output))
        })
        .unwrap_err(),
        ImageHeaderCaptureError::Parse(PeError::TooManySections(97))
    );
}

#[test]
fn optional_header_padding_bounded_capture_matches_full_parser() {
    let original = build_pe(
        BASE,
        0x1000,
        0x9000,
        &[text_section(0x8000, vec![0xcc; 0x200])],
        &[],
    );
    let declared = 0x4000usize;
    let table = NT_OFF + 24 + declared;
    let header_end = align_up(table + 40, 0x200);
    let mut bytes = vec![0u8; header_end + 0x200];
    bytes[..SECTION_TABLE].copy_from_slice(&original[..SECTION_TABLE]);
    put_u16(&mut bytes, NT_OFF + 20, declared as u16);
    put_u32(&mut bytes, OPT_OFF + 60, header_end as u32);
    bytes[table..table + 40].copy_from_slice(&original[SECTION_TABLE..SECTION_TABLE + 40]);
    put_u32(&mut bytes, table + 20, header_end as u32);
    bytes[header_end..].fill(0xcc);
    let pe = PeFile::parse(&bytes).unwrap();
    assert_eq!(pe.headers().size_of_optional_header, 0x4000);
    let mut reads = Vec::new();
    let layout = capture_image_layout(bytes.len() as u64, |offset, output: &mut [u8]| {
        reads.push((offset, output.len()));
        output.copy_from_slice(&bytes[offset as usize..offset as usize + output.len()]);
        Ok::<_, u32>(output.len())
    })
    .unwrap();
    assert_eq!(layout.headers().size_of_optional_header, 0x4000);
    assert_eq!(layout.headers().section_table_offset(), table);
    assert!(reads.iter().all(|(_, size)| *size <= 8192));
    assert!(reads
        .iter()
        .any(|(offset, _)| *offset == (table & !4095) as u64));
    for rva in (0..pe.size_of_image()).step_by(4096) {
        assert_eq!(
            layout.image_page_fill_plan(rva, bytes.len() as u64),
            pe.image_page_fill_plan(rva, bytes.len() as u64)
        );
    }

    // Known fields are present, but the declared optional extent itself extends beyond EOF.
    let truncated = &bytes[..table - 1];
    assert_eq!(PeFile::parse(truncated).unwrap_err(), PeError::Truncated);
    assert_eq!(
        capture_image_layout(truncated.len() as u64, |offset, output: &mut [u8]| {
            output.copy_from_slice(&truncated[offset as usize..offset as usize + output.len()]);
            Ok::<_, u32>(output.len())
        })
        .unwrap_err(),
        ImageHeaderCaptureError::Parse(PeError::Truncated)
    );
}
