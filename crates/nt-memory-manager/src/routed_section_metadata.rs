//! Exact provider metadata required before a routed data section can be published.

use crate::data_section::{
    complete_data_section_extension, plan_data_section_file, DataSectionFileExtent,
    DataSectionFileInfo, DataSectionFilePlan, STATUS_IO_DEVICE_ERROR,
};
use crate::{SectionFileIdentity, SectionMountId};

const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_DATA_ERROR: u32 = 0xc000_003e;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;

#[derive(Clone, Copy)]
pub struct CompletedFileQuery<'a> {
    pub status: u32,
    pub information: u64,
    pub output: &'a [u8],
}

impl<'a> CompletedFileQuery<'a> {
    pub(crate) fn exact(self, length: usize) -> Result<&'a [u8], u32> {
        if self.status == STATUS_PENDING {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        if self.status != 0 {
            return Err(self.status);
        }
        if self.information != length as u64 || self.output.len() != length {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        Ok(self.output)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutedSectionMetadata {
    pub file: SectionFileIdentity,
    pub end_of_file: u64,
    pub is_directory: bool,
}

impl RoutedSectionMetadata {
    pub fn from_queries(
        mount: SectionMountId,
        standard: CompletedFileQuery<'_>,
        internal: CompletedFileQuery<'_>,
    ) -> Result<Self, u32> {
        let (end_of_file, is_directory) = decode_standard_query(standard)?;
        let internal = internal.exact(8)?;
        let file =
            SectionFileIdentity::from_file_internal(mount, internal).ok_or(STATUS_DATA_ERROR)?;
        Ok(Self {
            file,
            end_of_file,
            is_directory,
        })
    }

    /// Admit a routed data section. As in NT's MmCreateSection, the File handle's granted access
    /// is the authority for a writable section (NT5 MmMakeFileAccess): the filesystem refused
    /// write access to read-only media at CREATE. Shared pages are written back through the same
    /// FILE_OBJECT with paging IRPs. A writable section larger than the file first has the
    /// routed filesystem set the new end of file (FsRtlSetFileSize, NT5 creasect.c); the metadata
    /// queried after that update (`extended`) must cover the section.
    pub fn admit(
        self,
        maximum_size: u64,
        protection: u32,
        granted_access: u32,
        extended: bool,
    ) -> Result<RoutedSectionAdmission, u32> {
        let info = DataSectionFileInfo {
            end_of_file: self.end_of_file,
            is_directory: self.is_directory,
            read_only_volume: false,
        };
        match plan_data_section_file(maximum_size, protection, granted_access, info)? {
            DataSectionFilePlan::Ready(extent) => Ok(RoutedSectionAdmission::Ready(extent)),
            DataSectionFilePlan::Extend { section_size } if extended => {
                complete_data_section_extension(section_size, info).map(RoutedSectionAdmission::Ready)
            }
            DataSectionFilePlan::Extend { section_size } => {
                Ok(RoutedSectionAdmission::ExtendFile(section_size))
            }
        }
    }

    /// The extent of a section whose file already covers it. Growing the file is the retained
    /// creation's own step (`admit`); a caller that cannot issue it is refused.
    pub fn prepare(
        self,
        maximum_size: u64,
        protection: u32,
        granted_access: u32,
    ) -> Result<DataSectionFileExtent, u32> {
        match self.admit(maximum_size, protection, granted_access, false)? {
            RoutedSectionAdmission::Ready(extent) => Ok(extent),
            RoutedSectionAdmission::ExtendFile(_) => Err(STATUS_NOT_SUPPORTED),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutedSectionAdmission {
    Ready(DataSectionFileExtent),
    /// The routed filesystem must first set this end of file.
    ExtendFile(u64),
}

pub fn decode_standard_query(query: CompletedFileQuery<'_>) -> Result<(u64, bool), u32> {
    let standard = query.exact(24)?;
    let end_of_file = i64::from_le_bytes(standard[8..16].try_into().unwrap());
    if end_of_file < 0 {
        return Err(STATUS_DATA_ERROR);
    }
    Ok((end_of_file as u64, standard[21] != 0))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionMountIds;

    fn metadata(eof: i64, directory: bool, index: u64) -> (SectionMountId, [u8; 24], [u8; 8]) {
        let mount = SectionMountIds::new().allocate().unwrap();
        let mut standard = [0u8; 24];
        standard[8..16].copy_from_slice(&eof.to_le_bytes());
        standard[21] = u8::from(directory);
        (mount, standard, index.to_le_bytes())
    }

    fn query(bytes: &[u8]) -> CompletedFileQuery<'_> {
        CompletedFileQuery {
            status: 0,
            information: bytes.len() as u64,
            output: bytes,
        }
    }

    #[test]
    fn exact_metadata_uses_mounted_file_identity_and_handle_access_policy() {
        let (mount, standard, internal) = metadata(0x2345, false, 0x321);
        let result =
            RoutedSectionMetadata::from_queries(mount, query(&standard), query(&internal)).unwrap();
        assert_eq!(
            result.file,
            SectionFileIdentity::from_file_internal(mount, &internal).unwrap()
        );
        assert_eq!(result.end_of_file, 0x2345);
        assert_eq!(
            result.prepare(0, 0x08, 0x01).unwrap().section_size,
            0x2345
        );
        // NT5 MmMakeFileAccess: a shared writable section needs FILE_WRITE_DATA on the File.
        assert_eq!(result.prepare(0, 0x04, 0x03).unwrap().section_size, 0x2345);
        assert_eq!(result.prepare(0, 0x04, 0x01), Err(0xc000_0022));
        assert_eq!(result.prepare(0, 0x40, 0x23).unwrap().file_size, 0x2345);
        assert_eq!(
            result.prepare(0x3000, 0x08, 0x01),
            Err(crate::STATUS_SECTION_TOO_BIG)
        );
        assert_eq!(
            result.prepare(0x3000, 0x04, 0x03),
            Err(STATUS_NOT_SUPPORTED),
            "growing the routed file is the retained creation's EOF update, not issued here"
        );
    }

    #[test]
    fn a_writable_section_larger_than_its_file_sets_the_end_of_file_first() {
        // NT5 creasect.c MmCreateSection: MaximumSize > EndOfFile with PAGE_READWRITE or
        // PAGE_EXECUTE_READWRITE calls FsRtlSetFileSize(File, MaximumSize).
        let (mount, standard, internal) = metadata(0x2345, false, 0x321);
        let small = RoutedSectionMetadata::from_queries(mount, query(&standard), query(&internal))
            .unwrap();
        assert_eq!(small.admit(0x3000, 0x04, 0x03, false), Ok(RoutedSectionAdmission::ExtendFile(0x3000)));
        assert_eq!(small.admit(0x3000, 0x40, 0x23, false), Ok(RoutedSectionAdmission::ExtendFile(0x3000)));
        assert_eq!(small.admit(0x3000, 0x02, 0x01, false), Err(crate::STATUS_SECTION_TOO_BIG));
        assert_eq!(small.admit(0x3000, 0x04, 0x01, false), Err(0xc000_0022));
        // After the update the re-queried file must cover the section.
        assert_eq!(small.admit(0x3000, 0x04, 0x03, true), Err(STATUS_IO_DEVICE_ERROR));
        let (mount, grown, internal) = metadata(0x3000, false, 0x321);
        let grown = RoutedSectionMetadata::from_queries(mount, query(&grown), query(&internal))
            .unwrap();
        assert_eq!(
            grown.admit(0x3000, 0x04, 0x03, true),
            Ok(RoutedSectionAdmission::Ready(DataSectionFileExtent { section_size: 0x3000, file_size: 0x3000 }))
        );
    }

    #[test]
    fn admitted_readonly_extent_bounds_later_page_reads() {
        let (mount, standard, internal) = metadata(0x2345, false, 0x321);
        let metadata =
            RoutedSectionMetadata::from_queries(mount, query(&standard), query(&internal))
                .unwrap();
        let extent = metadata.prepare(0, 0x08, 0x01).unwrap();
        assert_eq!(extent.file_size, metadata.end_of_file);
        let tail = crate::data_section::plan_data_section_page_read(
            2,
            extent.section_size,
            extent.file_size,
        )
        .unwrap();
        assert_eq!(tail.offset(), 0x2000);
        assert_eq!(tail.length(), 0x345);
    }

    #[test]
    fn terminal_queries_must_be_successful_and_exact() {
        let (mount, standard, internal) = metadata(4096, false, 7);
        let pending = CompletedFileQuery {
            status: STATUS_PENDING,
            ..query(&standard)
        };
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, pending, query(&internal)),
            Err(STATUS_IO_DEVICE_ERROR)
        );
        let warning = CompletedFileQuery {
            status: 0x8000_0005,
            ..query(&standard)
        };
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, warning, query(&internal)),
            Err(0x8000_0005)
        );
        let short = CompletedFileQuery {
            information: 23,
            ..query(&standard)
        };
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, short, query(&internal)),
            Err(STATUS_IO_DEVICE_ERROR)
        );
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, query(&standard[..23]), query(&internal)),
            Err(STATUS_IO_DEVICE_ERROR)
        );
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, query(&standard), query(&internal[..7])),
            Err(STATUS_IO_DEVICE_ERROR)
        );
        let oversized = CompletedFileQuery {
            information: 9,
            ..query(&internal)
        };
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, query(&standard), oversized),
            Err(STATUS_IO_DEVICE_ERROR)
        );
    }

    #[test]
    fn invalid_file_metadata_never_becomes_a_section() {
        let (mount, negative, internal) = metadata(-1, false, 7);
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, query(&negative), query(&internal)),
            Err(STATUS_DATA_ERROR)
        );
        let (mount, standard, zero) = metadata(4096, false, 0);
        assert_eq!(
            RoutedSectionMetadata::from_queries(mount, query(&standard), query(&zero)),
            Err(STATUS_DATA_ERROR)
        );
        let (mount, directory, internal) = metadata(4096, true, 7);
        let result =
            RoutedSectionMetadata::from_queries(mount, query(&directory), query(&internal))
                .unwrap();
        assert_eq!(
            result.prepare(0, 0x02, 0x01),
            Err(crate::data_section::STATUS_INVALID_FILE_FOR_SECTION)
        );
    }
}
