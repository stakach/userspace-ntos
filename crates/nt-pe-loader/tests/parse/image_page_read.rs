use super::*;
use nt_pe_loader::{ImagePageReadError, IMAGE_PAGE_SIZE};

fn test_image() -> Vec<u8> {
    build_pe(
        BASE,
        0x1000,
        0x3000,
        &[text_section(0x1000, vec![0xcc; 0x600])],
        &[],
    )
}

#[test]
fn page_reader_copies_checked_offsets_and_zeroes_unbacked_tail() {
    let bytes = test_image();
    let plan = PeFile::parse(&bytes)
        .unwrap()
        .image_page_fill_plan(0x1000, bytes.len() as u64)
        .unwrap();
    let mut page = [0xff; IMAGE_PAGE_SIZE];
    let mut reads = Vec::new();
    plan.read_into_page(&mut page, |offset, output: &mut [u8]| {
        reads.push((offset, output.len()));
        output.copy_from_slice(&bytes[offset as usize..offset as usize + output.len()]);
        Ok::<_, u32>(output.len())
    })
    .unwrap();
    assert_eq!(reads, [(plan.spans()[0].file_offset, 0x600)]);
    assert!(page[..0x600].iter().all(|byte| *byte == 0xcc));
    assert!(page[0x600..].iter().all(|byte| *byte == 0));
    let empty = PeFile::parse(&bytes)
        .unwrap()
        .image_page_fill_plan(0x2000, bytes.len() as u64)
        .unwrap();
    let mut calls = 0;
    empty
        .read_into_page(&mut page, |_, _: &mut [u8]| {
            calls += 1;
            Ok::<_, u32>(0)
        })
        .unwrap();
    assert_eq!(calls, 0);
    assert!(page.iter().all(|byte| *byte == 0));
}

#[test]
fn page_reader_refuses_short_failure_and_wrong_page_size() {
    let bytes = test_image();
    let plan = PeFile::parse(&bytes)
        .unwrap()
        .image_page_fill_plan(0x1000, bytes.len() as u64)
        .unwrap();
    let mut page = [0xff; IMAGE_PAGE_SIZE];
    assert_eq!(
        plan.read_into_page(&mut page, |_, output: &mut [u8]| Ok::<_, u32>(
            output.len() - 1
        )),
        Err(ImagePageReadError::ShortRead {
            expected: 0x600,
            actual: 0x5ff
        })
    );
    assert_eq!(
        plan.read_into_page(&mut page, |_, _: &mut [u8]| Err(0xc0000185u32)),
        Err(ImagePageReadError::Read(0xc0000185))
    );
    let mut calls = 0;
    assert_eq!(
        plan.read_into_page(&mut page[..4095], |_, _: &mut [u8]| {
            calls += 1;
            Ok::<_, u32>(0)
        }),
        Err(ImagePageReadError::InvalidPageSize(4095))
    );
    assert_eq!(calls, 0);
}
