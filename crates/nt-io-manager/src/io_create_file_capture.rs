//! Fault-aware capture of the ordinary x64 IoCreateFile call shape.

use alloc::vec::Vec;
use nt_types::AccessMode;

use crate::io_create_file::{
    self, IoCreateFileInput, IoCreateFileScalars, OwnedIoCreateFileRequest,
};

const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xc000_0033;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

/// The hosted driver adapter supplies a checked read, not an unchecked kernel pointer cast.
pub trait DriverMemoryReader {
    fn read(&self, address: u64, destination: &mut [u8]) -> bool;
}

/// All fourteen Win64 IoCreateFile arguments, including output addresses retained by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawIoCreateFileArguments {
    pub file_handle_out: u64,
    pub desired_access: u32,
    pub object_attributes: u64,
    pub io_status_block_out: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub ea_buffer: u64,
    pub ea_length: u32,
    pub create_file_type: u32,
    pub extra_create_parameters: u64,
    pub io_options: u32,
}

/// The output addresses are deliberately not part of the transferred request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerOutputs {
    pub file_handle: u64,
    pub io_status_block: u64,
}

pub struct CapturedDriverCreate {
    pub request: OwnedIoCreateFileRequest,
    pub outputs: CallerOutputs,
}

fn read_array<const N: usize>(
    reader: &impl DriverMemoryReader,
    address: u64,
) -> Result<[u8; N], u32> {
    let mut bytes = [0; N];
    if address == 0 || !reader.read(address, &mut bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(bytes)
}

fn read_bytes(
    reader: &impl DriverMemoryReader,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, u32> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if address == 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    bytes.resize(length, 0);
    if !reader.read(address, &mut bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Capture the ordinary-file subset needed by Mup. Security descriptors, QoS, and typed
/// pipe/mailslot extra structures require separate structural capture before they may cross IPC.
pub fn capture_ordinary(
    reader: &impl DriverMemoryReader,
    args: RawIoCreateFileArguments,
    previous_mode: AccessMode,
) -> Result<CapturedDriverCreate, u32> {
    if args.file_handle_out == 0 || args.io_status_block_out == 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if args.create_file_type != 0 || args.extra_create_parameters != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let oa = read_array::<48>(reader, args.object_attributes)?;
    if u32_at(&oa, 0) != 48 || u32_at(&oa, 24) & !0x0000_07f2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if u64_at(&oa, 32) != 0 || u64_at(&oa, 40) != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let name_address = u64_at(&oa, 16);
    if name_address == 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let name_descriptor = read_array::<16>(reader, name_address)?;
    let name_length = u16::from_le_bytes(name_descriptor[0..2].try_into().unwrap()) as usize;
    let name_maximum = u16::from_le_bytes(name_descriptor[2..4].try_into().unwrap()) as usize;
    if name_length == 0
        || name_length & 1 != 0
        || name_length > name_maximum
        || u64_at(&name_descriptor, 8) == 0
    {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let name_bytes = read_bytes(reader, u64_at(&name_descriptor, 8), name_length)?;
    let mut name = Vec::new();
    name.try_reserve_exact(name_length / 2)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for unit in name_bytes.chunks_exact(2) {
        name.push(u16::from_le_bytes([unit[0], unit[1]]));
    }
    let allocation_size = if args.allocation_size == 0 {
        None
    } else {
        Some(i64::from_le_bytes(read_array::<8>(
            reader,
            args.allocation_size,
        )?))
    };
    let ea = read_bytes(reader, args.ea_buffer, args.ea_length as usize)?;
    let request = io_create_file::capture(IoCreateFileInput {
        scalars: IoCreateFileScalars {
            desired_access: args.desired_access,
            file_attributes: args.file_attributes,
            share_access: args.share_access,
            disposition: args.disposition,
            create_options: args.create_options,
            create_file_type: args.create_file_type,
            extra_create_parameters_present: false,
            io_options: args.io_options,
        },
        previous_mode,
        object_attributes: u32_at(&oa, 24),
        root_directory: u64_at(&oa, 8),
        name: &name,
        allocation_size,
        ea: &ea,
        security_descriptor: None,
        security_qos: None,
        extra_create_parameters: None,
    })?;
    Ok(CapturedDriverCreate {
        request,
        outputs: CallerOutputs {
            file_handle: args.file_handle_out,
            io_status_block: args.io_status_block_out,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Memory(Vec<(u64, Vec<u8>)>);

    impl DriverMemoryReader for Memory {
        fn read(&self, address: u64, destination: &mut [u8]) -> bool {
            self.0.iter().any(|(base, bytes)| {
                let Some(offset) = address.checked_sub(*base).map(|offset| offset as usize) else {
                    return false;
                };
                let Some(end) = offset.checked_add(destination.len()) else {
                    return false;
                };
                if end > bytes.len() {
                    return false;
                }
                destination.copy_from_slice(&bytes[offset..end]);
                true
            })
        }
    }

    fn fixture() -> (Memory, RawIoCreateFileArguments) {
        let mut oa = [0u8; 48];
        oa[0..4].copy_from_slice(&48u32.to_le_bytes());
        oa[8..16].copy_from_slice(&0x84u64.to_le_bytes());
        oa[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        oa[24..28].copy_from_slice(&0x240u32.to_le_bytes());
        let mut name = [0u8; 16];
        name[0..2].copy_from_slice(&4u16.to_le_bytes());
        name[2..4].copy_from_slice(&4u16.to_le_bytes());
        name[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        let memory = Memory(alloc::vec![
            (0x1000, oa.to_vec()),
            (0x2000, name.to_vec()),
            (0x3000, alloc::vec![b'\\', 0, b'D', 0]),
            (0x4000, 64i64.to_le_bytes().to_vec()),
        ]);
        let args = RawIoCreateFileArguments {
            file_handle_out: 0x5000,
            desired_access: 1,
            object_attributes: 0x1000,
            io_status_block_out: 0x6000,
            allocation_size: 0x4000,
            file_attributes: 0,
            share_access: 3,
            disposition: nt_fs::FILE_OPEN,
            create_options: 0,
            ea_buffer: 0,
            ea_length: 0,
            create_file_type: 0,
            extra_create_parameters: 0,
            io_options: io_create_file::IO_NO_PARAMETER_CHECKING,
        };
        (memory, args)
    }

    #[test]
    fn mup_shape_copies_name_and_keeps_output_addresses_local() {
        let (mut memory, args) = fixture();
        let captured = capture_ordinary(&memory, args, AccessMode::UserMode).unwrap();
        memory.0[2].1.fill(0);
        assert_eq!(captured.request.name, [b'\\' as u16, b'D' as u16]);
        assert_eq!(captured.request.root_directory, 0x84);
        assert_eq!(captured.request.object_attributes, 0x240);
        assert_eq!(captured.request.allocation_size, Some(64));
        assert_eq!(captured.outputs.file_handle, 0x5000);
        assert_eq!(captured.outputs.io_status_block, 0x6000);
    }

    #[test]
    fn malformed_or_unreadable_name_never_becomes_a_request() {
        let (mut memory, args) = fixture();
        memory.0[1].1[0..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_OBJECT_NAME_INVALID)
        ));
        memory.0[1].1[0..2].copy_from_slice(&4u16.to_le_bytes());
        memory.0[1].1[8..16].copy_from_slice(&0xdead_u64.to_le_bytes());
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_ACCESS_VIOLATION)
        ));
    }

    #[test]
    fn unsupported_pointer_structures_are_not_forwarded() {
        let (mut memory, mut args) = fixture();
        memory.0[0].1[32..40].copy_from_slice(&0x7000u64.to_le_bytes());
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_NOT_SUPPORTED)
        ));
        memory.0[0].1[32..40].fill(0);
        args.create_file_type = 1;
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_NOT_SUPPORTED)
        ));
        args.create_file_type = 0;
        args.extra_create_parameters = 0x7000;
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_NOT_SUPPORTED)
        ));
    }

    #[test]
    fn ea_pointer_and_length_are_read_as_one_checked_extent() {
        let (mut memory, mut args) = fixture();
        args.ea_length = 8;
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_ACCESS_VIOLATION)
        ));
        args.ea_buffer = 0x7000;
        memory.0.push((0x7000, alloc::vec![0; 7]));
        assert!(matches!(
            capture_ordinary(&memory, args, AccessMode::KernelMode),
            Err(STATUS_ACCESS_VIOLATION)
        ));
    }
}
