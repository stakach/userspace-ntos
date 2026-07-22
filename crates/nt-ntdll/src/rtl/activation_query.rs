//! Pure x64 activation-context query buffer construction.
//!
//! Pointer-shaped fields in the packed buffers contain byte offsets from the start of the buffer.
//! The on-target ABI layer must add the destination buffer address to each non-zero field before
//! returning it to user mode.

use alloc::vec::Vec;
use core::mem::{offset_of, size_of};

use crate::{NtStatus, STATUS_INVALID_PARAMETER};

use super::activation::STATUS_BUFFER_TOO_SMALL;

pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;

pub const ACTIVATION_CONTEXT_PATH_TYPE_NONE: u32 = 1;
pub const ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE: u32 = 2;
pub const ACTIVATION_CONTEXT_PATH_TYPE_URL: u32 = 3;
pub const ACTIVATION_CONTEXT_PATH_TYPE_ASSEMBLYREF: u32 = 4;

pub const DETAILED_INFORMATION_POINTER_FIELDS: [usize; 3] = [0x28, 0x30, 0x38];
pub const ASSEMBLY_DETAILED_INFORMATION_POINTER_FIELDS: [usize; 4] = [0x40, 0x48, 0x50, 0x58];

/// x64 `ACTIVATION_CONTEXT_DETAILED_INFORMATION`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextDetailedInformation64 {
    pub flags: u32,
    pub format_version: u32,
    pub assembly_count: u32,
    pub root_manifest_path_type: u32,
    pub root_manifest_path_chars: u32,
    pub root_configuration_path_type: u32,
    pub root_configuration_path_chars: u32,
    pub application_directory_path_type: u32,
    pub application_directory_path_chars: u32,
    pub padding: u32,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub root_manifest_path: u64,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub root_configuration_path: u64,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub application_directory_path: u64,
}

/// x64 `ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextAssemblyDetailedInformation64 {
    pub flags: u32,
    pub encoded_assembly_identity_length: u32,
    pub manifest_path_type: u32,
    pub manifest_path_length: u32,
    pub manifest_last_write_time: i64,
    pub policy_path_type: u32,
    pub policy_path_length: u32,
    pub policy_last_write_time: i64,
    pub metadata_satellite_roster_index: u32,
    pub manifest_version_major: u32,
    pub manifest_version_minor: u32,
    pub policy_version_major: u32,
    pub policy_version_minor: u32,
    pub assembly_directory_name_length: u32,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub encoded_assembly_identity: u64,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub manifest_path: u64,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub policy_path: u64,
    /// Relative while packed; an absolute pointer in the exported ABI.
    pub assembly_directory_name: u64,
    pub file_count: u32,
    pub padding: u32,
}

const _: () = assert!(size_of::<ActivationContextDetailedInformation64>() == 0x40);
const _: () =
    assert!(offset_of!(ActivationContextDetailedInformation64, root_manifest_path) == 0x28);
const _: () = assert!(
    offset_of!(
        ActivationContextDetailedInformation64,
        root_configuration_path
    ) == 0x30
);
const _: () = assert!(
    offset_of!(
        ActivationContextDetailedInformation64,
        application_directory_path
    ) == 0x38
);

const _: () = assert!(size_of::<ActivationContextAssemblyDetailedInformation64>() == 0x68);
const _: () = assert!(
    offset_of!(
        ActivationContextAssemblyDetailedInformation64,
        manifest_last_write_time
    ) == 0x10
);
const _: () = assert!(
    offset_of!(
        ActivationContextAssemblyDetailedInformation64,
        policy_last_write_time
    ) == 0x20
);
const _: () = assert!(
    offset_of!(
        ActivationContextAssemblyDetailedInformation64,
        encoded_assembly_identity
    ) == 0x40
);
const _: () = assert!(
    offset_of!(
        ActivationContextAssemblyDetailedInformation64,
        manifest_path
    ) == 0x48
);
const _: () =
    assert!(offset_of!(ActivationContextAssemblyDetailedInformation64, policy_path) == 0x50);
const _: () = assert!(
    offset_of!(
        ActivationContextAssemblyDetailedInformation64,
        assembly_directory_name
    ) == 0x58
);
const _: () =
    assert!(offset_of!(ActivationContextAssemblyDetailedInformation64, file_count) == 0x60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetailedQuery<'a> {
    pub format_version: u32,
    pub assembly_count: u32,
    pub root_manifest_path_type: u32,
    pub root_manifest_path: Option<&'a [u16]>,
    pub root_configuration_path_type: u32,
    pub root_configuration_path: Option<&'a [u16]>,
    pub application_directory_path_type: u32,
    pub application_directory_path: Option<&'a [u16]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssemblyDetailedQuery<'a> {
    pub encoded_assembly_identity: Option<&'a [u16]>,
    pub manifest_path_type: u32,
    pub manifest_path: Option<&'a [u16]>,
    pub assembly_directory_name: Option<&'a [u16]>,
    pub file_count: u32,
}

/// Convert the native one-based assembly roster index to a zero-based model index.
pub fn validate_roster_index(roster_index: u32, assembly_count: u32) -> Result<usize, NtStatus> {
    if roster_index == 0 || roster_index > assembly_count {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((roster_index - 1) as usize)
}

pub fn detailed_required_size(query: &DetailedQuery<'_>) -> Result<usize, NtStatus> {
    checked_required_size(
        size_of::<ActivationContextDetailedInformation64>(),
        &[
            query.root_manifest_path,
            query.root_configuration_path,
            query.application_directory_path,
        ],
    )
}

pub fn assembly_detailed_required_size(
    query: &AssemblyDetailedQuery<'_>,
) -> Result<usize, NtStatus> {
    for value in [
        query.encoded_assembly_identity,
        query.manifest_path,
        query.assembly_directory_name,
    ]
    .into_iter()
    .flatten()
    {
        checked_u16_byte_count(value)?;
    }
    checked_required_size(
        size_of::<ActivationContextAssemblyDetailedInformation64>(),
        &[
            query.encoded_assembly_identity,
            query.manifest_path,
            query.assembly_directory_name,
        ],
    )
}

pub fn pack_detailed(query: &DetailedQuery<'_>) -> Result<Vec<u8>, NtStatus> {
    let required = detailed_required_size(query)?;
    let mut buffer = allocate_zeroed(required)?;
    pack_detailed_into(query, &mut buffer)?;
    Ok(buffer)
}

pub fn pack_assembly_detailed(query: &AssemblyDetailedQuery<'_>) -> Result<Vec<u8>, NtStatus> {
    let required = assembly_detailed_required_size(query)?;
    let mut buffer = allocate_zeroed(required)?;
    pack_assembly_detailed_into(query, &mut buffer)?;
    Ok(buffer)
}

/// Pack class 2 into a caller-owned buffer. A short buffer is not modified.
pub fn pack_detailed_into(query: &DetailedQuery<'_>, buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required = detailed_required_size(query)?;
    if buffer.len() < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    buffer[..required].fill(0);

    write_u32(buffer, 0x04, query.format_version);
    write_u32(buffer, 0x08, query.assembly_count);
    write_u32(buffer, 0x0c, query.root_manifest_path_type);
    write_optional_char_count(buffer, 0x10, query.root_manifest_path)?;
    write_u32(buffer, 0x14, query.root_configuration_path_type);
    write_optional_char_count(buffer, 0x18, query.root_configuration_path)?;
    write_u32(buffer, 0x1c, query.application_directory_path_type);
    write_optional_char_count(buffer, 0x20, query.application_directory_path)?;

    let mut cursor = size_of::<ActivationContextDetailedInformation64>();
    cursor = write_optional_utf16(buffer, cursor, 0x28, query.root_manifest_path)?;
    cursor = write_optional_utf16(buffer, cursor, 0x30, query.root_configuration_path)?;
    cursor = write_optional_utf16(buffer, cursor, 0x38, query.application_directory_path)?;
    debug_assert_eq!(cursor, required);
    Ok(required)
}

/// Pack class 3 into a caller-owned buffer. A short buffer is not modified.
pub fn pack_assembly_detailed_into(
    query: &AssemblyDetailedQuery<'_>,
    buffer: &mut [u8],
) -> Result<usize, NtStatus> {
    let required = assembly_detailed_required_size(query)?;
    if buffer.len() < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    buffer[..required].fill(0);

    write_optional_byte_count(buffer, 0x04, query.encoded_assembly_identity)?;
    write_u32(buffer, 0x08, query.manifest_path_type);
    write_optional_byte_count(buffer, 0x0c, query.manifest_path)?;
    // Timestamps remain zero. No policy is modeled, so its type is NONE and its length/pointer zero.
    write_u32(buffer, 0x18, ACTIVATION_CONTEXT_PATH_TYPE_NONE);
    write_u32(buffer, 0x2c, 1); // manifest version 1.0
    write_optional_byte_count(buffer, 0x3c, query.assembly_directory_name)?;
    write_u32(buffer, 0x60, query.file_count);

    let mut cursor = size_of::<ActivationContextAssemblyDetailedInformation64>();
    cursor = write_optional_utf16(buffer, cursor, 0x40, query.encoded_assembly_identity)?;
    cursor = write_optional_utf16(buffer, cursor, 0x48, query.manifest_path)?;
    cursor = write_optional_utf16(buffer, cursor, 0x58, query.assembly_directory_name)?;
    debug_assert_eq!(cursor, required);
    Ok(required)
}

fn allocate_zeroed(length: usize) -> Result<Vec<u8>, NtStatus> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| STATUS_NO_MEMORY)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn checked_required_size(base: usize, strings: &[Option<&[u16]>]) -> Result<usize, NtStatus> {
    let mut required = base;
    for value in strings.iter().flatten() {
        validate_string(value)?;
        let bytes = value
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(size_of::<u16>()))
            .ok_or(STATUS_NO_MEMORY)?;
        required = required.checked_add(bytes).ok_or(STATUS_NO_MEMORY)?;
    }
    Ok(required)
}

fn validate_string(value: &[u16]) -> Result<(), NtStatus> {
    if value.contains(&0) || u32::try_from(value.len()).is_err() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn write_optional_char_count(
    buffer: &mut [u8],
    offset: usize,
    value: Option<&[u16]>,
) -> Result<(), NtStatus> {
    let count = value.map_or(Ok(0), |value| {
        u32::try_from(value.len()).map_err(|_| STATUS_INVALID_PARAMETER)
    })?;
    write_u32(buffer, offset, count);
    Ok(())
}

fn write_optional_byte_count(
    buffer: &mut [u8],
    offset: usize,
    value: Option<&[u16]>,
) -> Result<(), NtStatus> {
    let count = value.map_or(Ok(0), checked_u16_byte_count)?;
    write_u32(buffer, offset, count);
    Ok(())
}

fn checked_u16_byte_count(value: &[u16]) -> Result<u32, NtStatus> {
    value
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or(STATUS_NO_MEMORY)
}

fn write_optional_utf16(
    buffer: &mut [u8],
    cursor: usize,
    pointer_field: usize,
    value: Option<&[u16]>,
) -> Result<usize, NtStatus> {
    let Some(value) = value else {
        return Ok(cursor);
    };
    write_u64(
        buffer,
        pointer_field,
        u64::try_from(cursor).map_err(|_| STATUS_NO_MEMORY)?,
    );
    let mut position = cursor;
    for unit in value.iter().copied().chain(core::iter::once(0)) {
        buffer[position..position + 2].copy_from_slice(&unit.to_le_bytes());
        position += 2;
    }
    Ok(position)
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn u32_at(buffer: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(buffer: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap())
    }

    fn utf16_z_at(buffer: &[u8], offset: usize) -> Vec<u16> {
        let mut output = Vec::new();
        let mut cursor = offset;
        loop {
            let unit = u16::from_le_bytes(buffer[cursor..cursor + 2].try_into().unwrap());
            cursor += 2;
            if unit == 0 {
                return output;
            }
            output.push(unit);
        }
    }

    #[test]
    fn x64_layouts_match_the_native_abi() {
        assert_eq!(size_of::<ActivationContextDetailedInformation64>(), 0x40);
        assert_eq!(DETAILED_INFORMATION_POINTER_FIELDS, [0x28, 0x30, 0x38]);
        assert_eq!(
            size_of::<ActivationContextAssemblyDetailedInformation64>(),
            0x68
        );
        assert_eq!(
            ASSEMBLY_DETAILED_INFORMATION_POINTER_FIELDS,
            [0x40, 0x48, 0x50, 0x58]
        );
    }

    #[test]
    fn empty_detailed_information_has_only_fixed_metadata() {
        let query = DetailedQuery {
            format_version: 0,
            assembly_count: 0,
            root_manifest_path_type: 0,
            root_manifest_path: None,
            root_configuration_path_type: ACTIVATION_CONTEXT_PATH_TYPE_NONE,
            root_configuration_path: None,
            application_directory_path_type: 0,
            application_directory_path: None,
        };
        let packed = pack_detailed(&query).unwrap();
        assert_eq!(packed.len(), 0x40);
        assert_eq!(u32_at(&packed, 0x14), ACTIVATION_CONTEXT_PATH_TYPE_NONE);
        for field in DETAILED_INFORMATION_POINTER_FIELDS {
            assert_eq!(u64_at(&packed, field), 0);
        }
    }

    #[test]
    fn detailed_strings_are_nul_terminated_and_packed_in_abi_order() {
        let manifest = wide("C:\\app\\demo.exe");
        let config = wide("C:\\app\\demo.exe.config");
        let appdir = wide("C:\\app\\");
        let query = DetailedQuery {
            format_version: 1,
            assembly_count: 1,
            root_manifest_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            root_manifest_path: Some(&manifest),
            root_configuration_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            root_configuration_path: Some(&config),
            application_directory_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            application_directory_path: Some(&appdir),
        };
        let packed = pack_detailed(&query).unwrap();
        let manifest_offset = 0x40;
        let config_offset = manifest_offset + (manifest.len() + 1) * 2;
        let appdir_offset = config_offset + (config.len() + 1) * 2;
        assert_eq!(packed.len(), appdir_offset + (appdir.len() + 1) * 2);
        assert_eq!(u32_at(&packed, 0x10), manifest.len() as u32);
        assert_eq!(u32_at(&packed, 0x18), config.len() as u32);
        assert_eq!(u32_at(&packed, 0x20), appdir.len() as u32);
        assert_eq!(u64_at(&packed, 0x28), manifest_offset as u64);
        assert_eq!(u64_at(&packed, 0x30), config_offset as u64);
        assert_eq!(u64_at(&packed, 0x38), appdir_offset as u64);
        assert_eq!(utf16_z_at(&packed, manifest_offset), manifest);
        assert_eq!(utf16_z_at(&packed, config_offset), config);
        assert_eq!(utf16_z_at(&packed, appdir_offset), appdir);
    }

    #[test]
    fn short_detailed_buffer_is_not_modified() {
        let manifest = wide("a.manifest");
        let query = DetailedQuery {
            format_version: 1,
            assembly_count: 1,
            root_manifest_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            root_manifest_path: Some(&manifest),
            root_configuration_path_type: ACTIVATION_CONTEXT_PATH_TYPE_NONE,
            root_configuration_path: None,
            application_directory_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            application_directory_path: None,
        };
        let required = detailed_required_size(&query).unwrap();
        let mut short = alloc::vec![0xa5; required - 1];
        assert_eq!(
            pack_detailed_into(&query, &mut short),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));
        let mut exact = alloc::vec![0; required];
        assert_eq!(pack_detailed_into(&query, &mut exact), Ok(required));
    }

    #[test]
    fn assembly_lengths_are_bytes_and_reserved_fields_are_zero() {
        let identity = wide("demo,type=\"win32\",version=\"1.0.0.0\"");
        let manifest = wide("C:\\app\\demo.exe");
        let directory = wide("x86_demo_deadbeef_1.0.0.0_none_deadbeef");
        let query = AssemblyDetailedQuery {
            encoded_assembly_identity: Some(&identity),
            manifest_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            manifest_path: Some(&manifest),
            assembly_directory_name: Some(&directory),
            file_count: 7,
        };
        let packed = pack_assembly_detailed(&query).unwrap();
        let identity_offset = 0x68;
        let manifest_offset = identity_offset + (identity.len() + 1) * 2;
        let directory_offset = manifest_offset + (manifest.len() + 1) * 2;
        assert_eq!(packed.len(), directory_offset + (directory.len() + 1) * 2);
        assert_eq!(u32_at(&packed, 0x04), (identity.len() * 2) as u32);
        assert_eq!(u32_at(&packed, 0x0c), (manifest.len() * 2) as u32);
        assert_eq!(u32_at(&packed, 0x3c), (directory.len() * 2) as u32);
        assert_eq!(u64_at(&packed, 0x40), identity_offset as u64);
        assert_eq!(u64_at(&packed, 0x48), manifest_offset as u64);
        assert_eq!(u64_at(&packed, 0x50), 0);
        assert_eq!(u64_at(&packed, 0x58), directory_offset as u64);
        assert_eq!(u32_at(&packed, 0x18), ACTIVATION_CONTEXT_PATH_TYPE_NONE);
        assert_eq!(u32_at(&packed, 0x2c), 1);
        assert_eq!(u32_at(&packed, 0x60), 7);
        assert!(packed[0x10..0x18].iter().all(|byte| *byte == 0));
        assert!(packed[0x20..0x28].iter().all(|byte| *byte == 0));
        assert_eq!(utf16_z_at(&packed, identity_offset), identity);
        assert_eq!(utf16_z_at(&packed, manifest_offset), manifest);
        assert_eq!(utf16_z_at(&packed, directory_offset), directory);
    }

    #[test]
    fn short_assembly_buffer_is_not_modified() {
        let identity = wide("demo,version=\"1.0.0.0\"");
        let query = AssemblyDetailedQuery {
            encoded_assembly_identity: Some(&identity),
            manifest_path_type: ACTIVATION_CONTEXT_PATH_TYPE_NONE,
            manifest_path: None,
            assembly_directory_name: None,
            file_count: 0,
        };
        let required = assembly_detailed_required_size(&query).unwrap();
        let mut short = alloc::vec![0x5a; required - 1];
        assert_eq!(
            pack_assembly_detailed_into(&query, &mut short),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert!(short.iter().all(|byte| *byte == 0x5a));
        let mut exact = alloc::vec![0; required];
        assert_eq!(
            pack_assembly_detailed_into(&query, &mut exact),
            Ok(required)
        );
    }

    #[test]
    fn roster_indices_are_one_based() {
        assert_eq!(validate_roster_index(1, 2), Ok(0));
        assert_eq!(validate_roster_index(2, 2), Ok(1));
        assert_eq!(validate_roster_index(0, 2), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(validate_roster_index(3, 2), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn embedded_nuls_are_rejected() {
        let invalid = [b'a' as u16, 0, b'b' as u16];
        let query = AssemblyDetailedQuery {
            encoded_assembly_identity: Some(&invalid),
            manifest_path_type: ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE,
            manifest_path: None,
            assembly_directory_name: None,
            file_count: 0,
        };
        assert_eq!(
            assembly_detailed_required_size(&query),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn checked_size_arithmetic_reports_no_memory() {
        assert_eq!(
            checked_required_size(usize::MAX, &[Some(&[])]),
            Err(STATUS_NO_MEMORY)
        );
    }
}
