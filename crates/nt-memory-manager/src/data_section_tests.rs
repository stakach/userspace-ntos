use super::*;
use alloc::vec::Vec;

struct FileIo {
    info: DataSectionFileInfo,
    calls: Vec<u64>,
    fail_query: u32,
    fail_extend: u32,
    ignore_extend: bool,
    requery: Option<Result<DataSectionFileInfo, u32>>,
}

impl FileIo {
    fn new(size: u64) -> Self {
        Self {
            info: DataSectionFileInfo {
                end_of_file: size,
                is_directory: false,
                read_only_volume: false,
            },
            calls: Vec::new(),
            fail_query: 0,
            fail_extend: 0,
            ignore_extend: false,
            requery: None,
        }
    }
}

impl DataSectionFileIo for FileIo {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32> {
        self.calls.push(0);
        if self.fail_query != 0 {
            return Err(self.fail_query);
        }
        if self.calls.len() >= 3 {
            if let Some(result) = self.requery.take() {
                return result;
            }
        }
        Ok(self.info)
    }
    fn extend_file(&mut self, size: u64) -> Result<(), u32> {
        self.calls.push(size);
        if self.fail_extend != 0 {
            return Err(self.fail_extend);
        }
        if !self.ignore_extend {
            self.info.end_of_file = size;
        }
        Ok(())
    }
}

#[test]
fn nt5_file_access_masks_include_execute_and_exclude_cow_writes() {
    for (protection, access) in [
        (2, 1),
        (4, 3),
        (8, 1),
        (0x10, 0x20),
        (0x20, 0x21),
        (0x40, 0x23),
        (0x80, 0x21),
    ] {
        assert_eq!(data_section_file_access(protection), Ok(access));
        assert_eq!(check_data_section_file_access(protection, access), Ok(()));
        for bit in [1, 2, 0x20] {
            if access & bit != 0 {
                assert_eq!(
                    check_data_section_file_access(protection, access & !bit),
                    Err(STATUS_ACCESS_DENIED)
                );
            }
        }
    }
    assert_eq!(check_data_section_file_access(8, 0x8000_0000), Ok(()));
    assert_eq!(
        check_data_section_file_access(4, 0x4000_0000),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(check_data_section_file_access(4, 0xc000_0000), Ok(()));
    assert_eq!(check_data_section_file_access(0x40, 0x1000_0000), Ok(()));
    assert_eq!(check_data_section_file_access(0x10, 0x2000_0000), Ok(()));
}

#[test]
fn invalid_protection_has_native_status_and_no_io() {
    assert_eq!(STATUS_INVALID_PAGE_PROTECTION, 0xc000_0045);
    for protection in [0, 1, 3, 6, 0x104, 0x204, 0x404, u32::MAX] {
        let mut io = FileIo::new(20);
        assert_eq!(
            prepare_data_section_file(0, protection, u32::MAX, &mut io),
            Err(0xc000_0045)
        );
        assert!(io.calls.is_empty());
    }
}

#[test]
fn handle_access_is_checked_before_query_or_extension() {
    let mut io = FileIo::new(10);
    assert_eq!(
        prepare_data_section_file(20, 4, 1, &mut io),
        Err(STATUS_ACCESS_DENIED)
    );
    assert!(io.calls.is_empty());
}

#[test]
fn zero_request_uses_eof_and_smaller_section_preserves_file_extent() {
    let mut io = FileIo::new(0x2345);
    assert_eq!(
        prepare_data_section_file(0, 2, 1, &mut io),
        Ok(DataSectionFileExtent {
            section_size: 0x2345,
            file_size: 0x2345
        })
    );
    assert_eq!(
        prepare_data_section_file(20, 2, 1, &mut io),
        Ok(DataSectionFileExtent {
            section_size: 20,
            file_size: 0x2345
        })
    );
    assert_eq!(io.calls, [0, 0]);
}

#[test]
fn empty_file_and_directory_fail_without_publishing_an_extent() {
    let mut io = FileIo::new(0);
    assert_eq!(
        prepare_data_section_file(0, 2, 1, &mut io),
        Err(STATUS_MAPPED_FILE_SIZE_ZERO)
    );
    io.info.is_directory = true;
    assert_eq!(
        prepare_data_section_file(20, 4, 3, &mut io),
        Err(STATUS_INVALID_FILE_FOR_SECTION)
    );
    assert_eq!(io.calls, [0, 0]);
}

#[test]
fn readonly_volume_allows_private_cow_but_never_shared_write_admission() {
    let mut io = FileIo::new(20);
    io.info.read_only_volume = true;
    assert!(prepare_data_section_file(0, 8, 1, &mut io).is_ok());
    assert!(prepare_data_section_file(0, 0x80, 0x21, &mut io).is_ok());
    for size in [10, 20, 30] {
        assert_eq!(
            prepare_data_section_file(size, 4, 3, &mut io),
            Err(0xc000_00a2)
        );
    }
    assert!(io.calls.iter().all(|call| *call == 0));
}

#[test]
fn only_shared_writable_protection_can_extend() {
    for protection in [2, 8, 0x10, 0x20, 0x80] {
        let mut io = FileIo::new(10);
        assert_eq!(
            prepare_data_section_file(20, protection, 0x23, &mut io),
            Err(STATUS_SECTION_TOO_BIG)
        );
        assert_eq!(io.calls, [0]);
    }
    for protection in [4, 0x40] {
        let mut io = FileIo::new(10);
        assert_eq!(
            prepare_data_section_file(20, protection, 0x23, &mut io),
            Ok(DataSectionFileExtent {
                section_size: 20,
                file_size: 20
            })
        );
        assert_eq!(
            io.calls,
            [0, 20, 0],
            "requery actual EOF before publication"
        );
    }
}

#[test]
fn query_and_extension_failures_are_propagated_and_false_success_is_rejected() {
    let mut io = FileIo::new(10);
    io.fail_query = 0xc000_0008;
    assert_eq!(
        prepare_data_section_file(20, 4, 3, &mut io),
        Err(0xc000_0008)
    );
    for error in [0xc000_00a2, 0xc000_007f, STATUS_ACCESS_DENIED] {
        let mut io = FileIo::new(10);
        io.fail_extend = error;
        assert_eq!(prepare_data_section_file(20, 4, 3, &mut io), Err(error));
        assert_eq!(io.info.end_of_file, 10);
        assert_eq!(io.calls, [0, 20]);
    }
    let mut io = FileIo::new(10);
    io.ignore_extend = true;
    assert_eq!(
        prepare_data_section_file(20, 4, 3, &mut io),
        Err(STATUS_IO_DEVICE_ERROR)
    );
}

#[test]
fn negative_file_sizes_never_reach_the_extension_mechanism() {
    let mut io = FileIo::new(10);
    assert_eq!(
        prepare_data_section_file(u64::MAX, 2, 1, &mut io),
        Err(STATUS_SECTION_TOO_BIG)
    );
    assert_eq!(
        prepare_data_section_file(u64::MAX, 4, 3, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(io.calls, [0, 0]);
}

#[test]
fn supported_extent_limit_is_checked_before_file_mutation() {
    for size in [MAX_DATA_SECTION_SIZE - 1, MAX_DATA_SECTION_SIZE] {
        let mut io = FileIo::new(size);
        assert!(prepare_data_section_file(0, 2, 1, &mut io).is_ok());
    }
    let mut io = FileIo::new(10);
    assert_eq!(
        prepare_data_section_file(MAX_DATA_SECTION_SIZE + 1, 4, 3, &mut io),
        Err(STATUS_SECTION_TOO_BIG)
    );
    assert_eq!(io.calls, [0]);
    assert_eq!(io.info.end_of_file, 10);
    let mut io = FileIo::new(MAX_DATA_SECTION_SIZE + 1);
    assert_eq!(
        prepare_data_section_file(10, 2, 1, &mut io),
        Err(STATUS_SECTION_TOO_BIG)
    );
}

#[test]
fn failed_or_inconsistent_requery_never_publishes_an_extent() {
    for result in [
        Err(0xc000_00a3),
        Ok(DataSectionFileInfo {
            end_of_file: 20,
            is_directory: true,
            read_only_volume: false,
        }),
        Ok(DataSectionFileInfo {
            end_of_file: 20,
            is_directory: false,
            read_only_volume: true,
        }),
        Ok(DataSectionFileInfo {
            end_of_file: MAX_DATA_SECTION_SIZE + 1,
            is_directory: false,
            read_only_volume: false,
        }),
    ] {
        let expected = result.err().unwrap_or(STATUS_IO_DEVICE_ERROR);
        let mut io = FileIo::new(10);
        io.requery = Some(result);
        assert_eq!(prepare_data_section_file(20, 4, 3, &mut io), Err(expected));
        assert_eq!(
            io.info.end_of_file, 20,
            "the actual extension is not rolled back or hidden"
        );
        assert_eq!(io.calls, [0, 20, 0]);
    }
}

struct ReadIo {
    status: u32,
    short: isize,
    calls: Vec<(u64, usize)>,
}
impl DataSectionReadIo for ReadIo {
    fn read(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize) {
        self.calls.push((offset, output.len()));
        output.fill(0xa5);
        (self.status, (output.len() as isize + self.short) as usize)
    }
}
fn reader() -> ReadIo {
    ReadIo {
        status: 0,
        short: 0,
        calls: Vec::new(),
    }
}

#[test]
fn pagein_reads_full_file_prefix_even_through_a_shorter_section() {
    let mut io = reader();
    let mut output = [0xcc; DATA_PAGE_SIZE];
    read_data_section_page(0, 20, 0x2100, &mut output, &mut io).unwrap();
    assert_eq!(io.calls, [(0, DATA_PAGE_SIZE)]);
    assert_eq!(output, [0xa5; DATA_PAGE_SIZE]);
}

#[test]
fn only_eof_suffix_is_zero_filled() {
    let mut io = reader();
    let mut output = [0xcc; DATA_PAGE_SIZE];
    read_data_section_page(2, 0x2100, 0x2100, &mut output, &mut io).unwrap();
    assert_eq!(io.calls, [(0x2000, 0x100)]);
    assert_eq!(&output[..0x100], &[0xa5; 0x100]);
    assert!(output[0x100..].iter().all(|byte| *byte == 0));
}

#[test]
fn read_errors_and_short_or_oversized_success_never_form_a_valid_page() {
    for (status, short, expected) in [
        (0, -1, STATUS_IO_DEVICE_ERROR),
        (0, 1, STATUS_IO_DEVICE_ERROR),
        (STATUS_END_OF_FILE, 0, STATUS_END_OF_FILE),
        (0xc000_00a3, -10, 0xc000_00a3),
    ] {
        let mut io = reader();
        io.status = status;
        io.short = short;
        assert_eq!(
            read_data_section_page(0, 0x1000, 0x1000, &mut [0; DATA_PAGE_SIZE], &mut io),
            Err(expected)
        );
    }
}

#[test]
fn truncation_and_invalid_page_ranges_do_not_read_or_synthesize_pages() {
    let mut io = reader();
    let mut output = [0xcc; DATA_PAGE_SIZE];
    assert_eq!(
        read_data_section_page(1, 0x2000, 0x1000, &mut output, &mut io),
        Err(STATUS_END_OF_FILE)
    );
    assert_eq!(
        read_data_section_page(u64::MAX, u64::MAX, u64::MAX, &mut output, &mut io),
        Err(crate::STATUS_INVALID_VIEW_SIZE)
    );
    assert_eq!(
        read_data_section_page(1, 0x1000, 0x2000, &mut output, &mut io),
        Err(crate::STATUS_INVALID_VIEW_SIZE)
    );
    assert!(io.calls.is_empty());
    assert_eq!(output, [0xcc; DATA_PAGE_SIZE]);
}

struct MemFile {
    fs: nt_fs::FileSystem,
    handle: u64,
}
impl DataSectionFileIo for MemFile {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32> {
        let info = self
            .fs
            .zw_query_standard_information(self.handle)
            .ok_or(0xc000_0008u32)?;
        Ok(DataSectionFileInfo {
            end_of_file: info.end_of_file,
            is_directory: info.is_directory,
            read_only_volume: false,
        })
    }
    fn extend_file(&mut self, size: u64) -> Result<(), u32> {
        let status = self.fs.zw_set_information_file(
            self.handle,
            nt_fs::FILE_END_OF_FILE_INFORMATION,
            &size.to_le_bytes(),
        );
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
}
impl DataSectionReadIo for MemFile {
    fn read(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize) {
        let (status, bytes) = self
            .fs
            .zw_read_file(self.handle, Some(offset), output.len());
        output[..bytes.len()].copy_from_slice(&bytes);
        (status, bytes.len())
    }
}

#[test]
fn real_file_extension_is_visible_before_pagein_and_preserves_existing_bytes() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let file = fs.zw_create_file(r"\??\C:\mapped", 3, 0, 0, nt_fs::FILE_CREATE, 0);
    assert_eq!(file.status, 0);
    assert_eq!(fs.zw_write_file(file.handle, Some(0), b"seed"), (0, 4));
    let mut io = MemFile {
        fs,
        handle: file.handle,
    };
    let extent = prepare_data_section_file(0x2100, 4, 3, &mut io).unwrap();
    assert_eq!(io.query_file().unwrap().end_of_file, 0x2100);
    let mut bytes = [0xcc; DATA_PAGE_SIZE];
    read_data_section_page(
        0,
        extent.section_size,
        extent.file_size,
        &mut bytes,
        &mut io,
    )
    .unwrap();
    assert_eq!(&bytes[..4], b"seed");
    assert!(bytes[4..].iter().all(|byte| *byte == 0));
    bytes.fill(0xcc);
    read_data_section_page(
        2,
        extent.section_size,
        extent.file_size,
        &mut bytes,
        &mut io,
    )
    .unwrap();
    assert_eq!(bytes, [0; DATA_PAGE_SIZE]);
}
