//! Exact provider metadata required before a routed data section can be published.

use crate::data_section::{
    prepare_data_section_file, DataSectionFileExtent, DataSectionFileInfo, DataSectionFileIo,
    STATUS_IO_DEVICE_ERROR,
};
use crate::{SectionFileIdentity, SectionMountId};

const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_DATA_ERROR: u32 = 0xc000_003e;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xc000_00a2;

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

    /// Initial routed admission is read-only/COW until per-file writeback is coherent.
    pub fn prepare_readonly(
        self,
        maximum_size: u64,
        protection: u32,
        granted_access: u32,
    ) -> Result<DataSectionFileExtent, u32> {
        prepare_data_section_file(
            maximum_size,
            protection,
            granted_access,
            &mut ReadOnlyRoutedFile(self),
        )
    }
}

pub fn decode_standard_query(query: CompletedFileQuery<'_>) -> Result<(u64, bool), u32> {
    let standard = query.exact(24)?;
    let end_of_file = i64::from_le_bytes(standard[8..16].try_into().unwrap());
    if end_of_file < 0 {
        return Err(STATUS_DATA_ERROR);
    }
    Ok((end_of_file as u64, standard[21] != 0))
}

struct ReadOnlyRoutedFile(RoutedSectionMetadata);

impl DataSectionFileIo for ReadOnlyRoutedFile {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32> {
        Ok(DataSectionFileInfo {
            end_of_file: self.0.end_of_file,
            is_directory: self.0.is_directory,
            read_only_volume: true,
        })
    }

    fn extend_file(&mut self, _size: u64) -> Result<(), u32> {
        Err(STATUS_MEDIA_WRITE_PROTECTED)
    }
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
    fn exact_metadata_uses_mounted_file_identity_and_readonly_cow_policy() {
        let (mount, standard, internal) = metadata(0x2345, false, 0x321);
        let result =
            RoutedSectionMetadata::from_queries(mount, query(&standard), query(&internal)).unwrap();
        assert_eq!(
            result.file,
            SectionFileIdentity::from_file_internal(mount, &internal).unwrap()
        );
        assert_eq!(result.end_of_file, 0x2345);
        assert_eq!(
            result.prepare_readonly(0, 0x08, 0x01).unwrap().section_size,
            0x2345
        );
        assert_eq!(
            result.prepare_readonly(0, 0x04, 0x03),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        assert_eq!(
            result.prepare_readonly(0x3000, 0x08, 0x01),
            Err(crate::STATUS_SECTION_TOO_BIG)
        );
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
            result.prepare_readonly(0, 0x02, 0x01),
            Err(crate::data_section::STATUS_INVALID_FILE_FOR_SECTION)
        );
    }
}
