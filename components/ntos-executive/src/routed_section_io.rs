//! Canonical provider I/O for mounted data-section metadata and page reads.

use nt_io_manager::{
    DeviceId, ExternalDispatchResult, FileId, InformationParameters, IoParameters,
    ReadWriteParameters,
};
use nt_types::ClientId;
use nt_memory_manager::data_section::{DataSectionFileInfo, STATUS_IO_DEVICE_ERROR};
use nt_memory_manager::{CompletedFileQuery, PendingSectionMetadataQueries, RoutedSectionMetadata, SectionMountId};

use crate::driver_launch::{self, IO_MANAGER_COMPONENT_ID};

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

fn query_information(
    file_id: u64,
    device_id: u64,
    class: u32,
    output: &mut [u8],
) -> Result<(u32, u64), u32> {
    let result = unsafe {
        driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
            ClientId(IO_MANAGER_COMPONENT_ID),
            DeviceId(device_id),
            Some(FileId(file_id)),
            0,
            0,
            nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
            IoParameters::QueryInformation(InformationParameters {
                info_class: class,
                length: output.len() as u32,
            }),
            0,
            output.len() as u32,
            output,
        )
    }
    .map_err(|status| status.raw() as u32)?;
    match result {
        ExternalDispatchResult::Completed {
            status,
            information,
            ..
        } => Ok((status.raw() as u32, information)),
        ExternalDispatchResult::Pending { irp_id } => {
            unsafe { driver_launch::abandon_pending_irp(irp_id.raw()) }?;
            Err(STATUS_IO_DEVICE_ERROR)
        }
    }
}

pub(crate) fn query_metadata(
    file_id: u64,
    device_id: u64,
    mount: SectionMountId,
) -> Result<RoutedSectionMetadata, u32> {
    let mut work = PendingSectionMetadataQueries::<(), u64>::new();
    let id = work
        .reserve(mount, ())
        .map_err(|()| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut standard = [0u8; 24];
    let (status, information) = query_information(
        file_id,
        device_id,
        nt_fs::FILE_STANDARD_INFORMATION,
        &mut standard,
    )?;
    if !work.complete_inline(
        id,
        CompletedFileQuery {
            status,
            information,
            output: &standard,
        },
    ) {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    if work.next_query(id) != Some(nt_fs::FILE_INTERNAL_INFORMATION) {
        return work
            .take_terminal(id)
            .map(|(_, result)| result)
            .unwrap_or(Err(STATUS_IO_DEVICE_ERROR));
    }
    let mut internal = [0u8; 8];
    let (status, information) = query_information(
        file_id,
        device_id,
        nt_fs::FILE_INTERNAL_INFORMATION,
        &mut internal,
    )?;
    if !work.complete_inline(
        id,
        CompletedFileQuery {
            status,
            information,
            output: &internal,
        },
    ) {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    work.take_terminal(id)
        .map(|(_, result)| result)
        .unwrap_or(Err(STATUS_IO_DEVICE_ERROR))
}

pub(crate) fn query_standard(file_id: u64, device_id: u64) -> Result<DataSectionFileInfo, u32> {
    let mut standard = [0u8; 24];
    let (status, information) = query_information(
        file_id,
        device_id,
        nt_fs::FILE_STANDARD_INFORMATION,
        &mut standard,
    )?;
    let (end_of_file, is_directory) = nt_memory_manager::routed_section_metadata::decode_standard_query(
        CompletedFileQuery { status, information, output: &standard },
    )?;
    Ok(DataSectionFileInfo {
        end_of_file,
        is_directory,
        read_only_volume: true,
    })
}

pub(crate) fn read(file_id: u64, device_id: u64, offset: u64, output: &mut [u8]) -> (u32, usize) {
    let Ok(length) = u32::try_from(output.len()) else {
        return (STATUS_IO_DEVICE_ERROR, 0);
    };
    let result = unsafe {
        driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
            ClientId(IO_MANAGER_COMPONENT_ID),
            DeviceId(device_id),
            Some(FileId(file_id)),
            0,
            0,
            nt_io_abi::major::IRP_MJ_READ,
            IoParameters::Read(ReadWriteParameters {
                length,
                key: 0,
                offset,
            }),
            0,
            length,
            output,
        )
    };
    match result {
        Ok(ExternalDispatchResult::Completed {
            status,
            information,
            ..
        }) => {
            let Ok(information) = usize::try_from(information) else {
                return (STATUS_IO_DEVICE_ERROR, 0);
            };
            if information > output.len() {
                return (STATUS_IO_DEVICE_ERROR, 0);
            }
            (status.raw() as u32, information)
        }
        Ok(ExternalDispatchResult::Pending { irp_id }) => {
            let status = unsafe { driver_launch::abandon_pending_irp(irp_id.raw()) }
                .err()
                .unwrap_or(STATUS_IO_DEVICE_ERROR);
            (status, 0)
        }
        Err(status) => (status.raw() as u32, 0),
    }
}
