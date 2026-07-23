//! Activation-context string-section construction and lookup.

use alloc::vec::Vec;

use crate::NtStatus;

use super::{
    activation::DllRedirect,
    activation_manifest::{ManifestClrSurrogate, ManifestWindowClass},
    guid::Guid,
    strings,
};

pub const STRSECTION_MAGIC: u32 = 0x6448_7353;
pub const GUIDSECTION_MAGIC: u32 = 0x6448_7347;
pub const DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME: u32 = 0x01;
pub const DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT: u32 = 0x02;
pub const DLL_REDIRECTION_PATH_EXPAND: u32 = 0x04;
pub const DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL: u32 = 0x08;

pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
pub const STATUS_SXS_INVALID_ACTCTXDATA_FORMAT: NtStatus = 0xC015_0003;

const HEADER_SIZE: usize = 44;
const INDEX_SIZE: usize = 24;
const REDIRECTION_SIZE: usize = 20;
const PATH_SEGMENT_SIZE: usize = 8;
const WINDOW_CLASS_REDIRECTION_SIZE: usize = 24;
const HASH_ALGORITHM_X65599: u32 = 1;
const GUID_HEADER_SIZE: usize = 40;
const GUID_INDEX_SIZE: usize = 28;
const CLR_SURROGATE_SIZE: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DllRedirectionSection {
    pub count: u32,
    pub index_offset: u32,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DllRedirectionMatch {
    pub index_offset: u32,
    pub name_offset: u32,
    pub name_length: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub assembly_roster_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DllRedirectionData {
    pub flags: u32,
    pub path_segments: Vec<Vec<u16>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DllRedirectAssembly<'a> {
    pub redirects: &'a [DllRedirect],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowClassAssembly<'a> {
    pub version: [u16; 4],
    pub files: &'a [DllRedirect],
    pub classes: &'a [ManifestWindowClass],
}

#[derive(Clone, Copy)]
struct WindowClassSectionEntry<'a> {
    name: &'a [u16],
    module: &'a [u16],
    assembly_version: [u16; 4],
    versioned: bool,
    assembly_roster_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowClassRedirectionSection {
    pub count: u32,
    pub index_offset: u32,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowClassRedirectionMatch {
    pub index_offset: u32,
    pub name_offset: u32,
    pub name_length: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub versioned_name_offset: u32,
    pub versioned_name_length: u32,
    pub module_offset: u32,
    pub module_length: u32,
    pub assembly_roster_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClrSurrogateAssembly<'a> {
    pub surrogates: &'a [ManifestClrSurrogate],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClrSurrogateMatch {
    pub data_offset: u32,
    /// Unpadded payload length returned through `ACTCTX_SECTION_KEYED_DATA`.
    pub data_length: u32,
    pub assembly_roster_index: u32,
}

/// Build the exact ReactOS DLL-redirection string-section representation.
pub fn build_dll_redirection_section(redirects: &[DllRedirect]) -> Result<Vec<u8>, NtStatus> {
    build_dll_redirection_section_for_assemblies(&[DllRedirectAssembly { redirects }])
}

/// Build a DLL-redirection string section for an activation-context assembly roster.
///
/// Assembly roster indices are one-based and empty assemblies retain their position.
pub fn build_dll_redirection_section_for_assemblies(
    assemblies: &[DllRedirectAssembly<'_>],
) -> Result<Vec<u8>, NtStatus> {
    let redirect_count = assemblies.iter().try_fold(0usize, |count, assembly| {
        count
            .checked_add(assembly.redirects.len())
            .ok_or(STATUS_NO_MEMORY)
    })?;
    let count = u32::try_from(redirect_count).map_err(|_| STATUS_NO_MEMORY)?;
    let index_bytes = redirect_count
        .checked_mul(INDEX_SIZE)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut total = HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;

    for assembly in assemblies {
        for redirect in assembly.redirects {
            if redirect.name.is_empty()
                || redirect.name.contains(&0)
                || redirect
                    .load_from
                    .as_ref()
                    .is_some_and(|value| value.contains(&0))
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            let name_bytes = utf16_bytes_len(redirect.name.len())?;
            let name_with_nul = name_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?;
            total = total
                .checked_add(align4(name_with_nul).ok_or(STATUS_NO_MEMORY)?)
                .and_then(|value| value.checked_add(REDIRECTION_SIZE))
                .ok_or(STATUS_NO_MEMORY)?;
            if let Some(load_from) = &redirect.load_from {
                let path_bytes = utf16_bytes_len(load_from.len())?;
                total = total
                    .checked_add(PATH_SEGMENT_SIZE)
                    .and_then(|value| value.checked_add(align4(path_bytes)?))
                    .ok_or(STATUS_NO_MEMORY)?;
            }
        }
    }
    let total_u32 = u32::try_from(total).map_err(|_| STATUS_NO_MEMORY)?;

    let mut section = Vec::new();
    section
        .try_reserve_exact(total)
        .map_err(|_| STATUS_NO_MEMORY)?;
    section.resize(total, 0);

    write_u32(&mut section, 0, STRSECTION_MAGIC)?;
    write_u32(&mut section, 4, HEADER_SIZE as u32)?;
    write_u32(&mut section, 20, count)?;
    write_u32(&mut section, 24, HEADER_SIZE as u32)?;

    let mut cursor = HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut position = 0usize;
    for (assembly_index, assembly) in assemblies.iter().enumerate() {
        let assembly_roster_index = assembly_index
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(STATUS_NO_MEMORY)?;
        for redirect in assembly.redirects {
            let index_offset = HEADER_SIZE
                .checked_add(position.checked_mul(INDEX_SIZE).ok_or(STATUS_NO_MEMORY)?)
                .ok_or(STATUS_NO_MEMORY)?;
            let name_bytes = utf16_bytes_len(redirect.name.len())?;
            let name_storage =
                align4(name_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?).ok_or(STATUS_NO_MEMORY)?;
            let name_offset = cursor;
            let data_offset = name_offset
                .checked_add(name_storage)
                .ok_or(STATUS_NO_MEMORY)?;
            let hash = strings::hash_unicode_string(&redirect.name, true, HASH_ALGORITHM_X65599)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

            write_u32(&mut section, index_offset, hash)?;
            write_u32(&mut section, index_offset + 4, to_u32(name_offset)?)?;
            write_u32(&mut section, index_offset + 8, to_u32(name_bytes)?)?;
            write_u32(&mut section, index_offset + 12, to_u32(data_offset)?)?;
            // ReactOS leaves this at the fixed redirection-header size even when a path segment exists.
            write_u32(&mut section, index_offset + 16, REDIRECTION_SIZE as u32)?;
            write_u32(
                &mut section,
                index_offset + 20,
                assembly_roster_index,
            )?;
            write_utf16(&mut section, name_offset, &redirect.name)?;

            if redirect.load_from.is_none() {
                write_u32(&mut section, data_offset, REDIRECTION_SIZE as u32)?;
                write_u32(
                    &mut section,
                    data_offset + 4,
                    DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT,
                )?;
                cursor = data_offset
                    .checked_add(REDIRECTION_SIZE)
                    .ok_or(STATUS_NO_MEMORY)?;
            } else {
                let load_from = redirect
                    .load_from
                    .as_ref()
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
                let path_bytes = utf16_bytes_len(load_from.len())?;
                let path_storage = align4(path_bytes).ok_or(STATUS_NO_MEMORY)?;
                let data_size = REDIRECTION_SIZE
                    .checked_add(PATH_SEGMENT_SIZE)
                    .ok_or(STATUS_NO_MEMORY)?;
                let path_segment_offset = data_offset
                    .checked_add(REDIRECTION_SIZE)
                    .ok_or(STATUS_NO_MEMORY)?;
                let path_offset = data_offset.checked_add(data_size).ok_or(STATUS_NO_MEMORY)?;
                let mut flags = 0;
                if load_from.iter().any(|unit| *unit == b'%' as u16) {
                    flags |= DLL_REDIRECTION_PATH_EXPAND;
                }
                if !load_from.is_empty()
                    && !load_from
                        .last()
                        .copied()
                        .is_some_and(|unit| unit == b'\\' as u16 || unit == b'/' as u16)
                {
                    flags |= DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME;
                }

                write_u32(&mut section, data_offset, to_u32(data_size)?)?;
                write_u32(&mut section, data_offset + 4, flags)?;
                write_u32(&mut section, data_offset + 8, to_u32(path_storage)?)?;
                write_u32(&mut section, data_offset + 12, 1)?;
                write_u32(&mut section, data_offset + 16, to_u32(path_segment_offset)?)?;
                write_u32(&mut section, path_segment_offset, to_u32(path_bytes)?)?;
                write_u32(&mut section, path_segment_offset + 4, to_u32(path_offset)?)?;
                write_utf16(&mut section, path_offset, load_from)?;
                cursor = path_offset
                    .checked_add(path_storage)
                    .ok_or(STATUS_NO_MEMORY)?;
            }
            position = position.checked_add(1).ok_or(STATUS_NO_MEMORY)?;
        }
    }

    if position != redirect_count || cursor != total || total_u32 as usize != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    validate_dll_redirection_section(&section)?;
    Ok(section)
}

/// Validate a complete DLL-redirection string section before any lookup result is exposed.
pub fn validate_dll_redirection_section(section: &[u8]) -> Result<DllRedirectionSection, NtStatus> {
    let length = u32::try_from(section.len()).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    if section.len() < HEADER_SIZE
        || read_u32(section, 0)? != STRSECTION_MAGIC
        || read_u32(section, 4)? != HEADER_SIZE as u32
        || read_u32(section, 36)? != 0
        || read_u32(section, 40)? != 0
    {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let count = read_u32(section, 20)?;
    let index_offset = read_u32(section, 24)?;
    if index_offset != HEADER_SIZE as u32 {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let index_bytes = usize::try_from(count)
        .ok()
        .and_then(|value| value.checked_mul(INDEX_SIZE))
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    usize::try_from(index_offset)
        .ok()
        .and_then(|value| value.checked_add(index_bytes))
        .filter(|value| *value <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

    for position in 0..count as usize {
        let index = HEADER_SIZE
            .checked_add(
                position
                    .checked_mul(INDEX_SIZE)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let stored_hash = read_u32(section, index)?;
        let name_offset = read_offset(section, index + 4)?;
        let name_length = read_offset(section, index + 8)?;
        let data_offset = read_offset(section, index + 12)?;
        let index_data_length = read_offset(section, index + 16)?;
        let roster_index = read_u32(section, index + 20)?;

        if name_length == 0
            || name_length % 2 != 0
            || index_data_length != REDIRECTION_SIZE
            || roster_index == 0
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let name_with_nul = name_length
            .checked_add(2)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if name_offset
            .checked_add(name_with_nul)
            .filter(|end| *end <= section.len())
            .is_none()
            || data_offset
                .checked_add(REDIRECTION_SIZE)
                .filter(|end| *end <= section.len())
                .is_none()
            || section_contains_unit(section, name_offset, name_length, 0)?
            || read_u16(
                section,
                name_offset
                    .checked_add(name_length)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )? != 0
            || hash_section_name(section, name_offset, name_length)? != stored_hash
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }

        let data_size = read_offset(section, data_offset)?;
        let flags = read_u32(section, data_offset + 4)?;
        let total_path_length = read_offset(section, data_offset + 8)?;
        let path_count = read_u32(section, data_offset + 12)?;
        let path_segment_offset = read_offset(section, data_offset + 16)?;
        let allowed_flags = DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME
            | DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT
            | DLL_REDIRECTION_PATH_EXPAND
            | DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL;
        if flags & !allowed_flags != 0
            || flags & DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT != 0
                && flags & DLL_REDIRECTION_PATH_EXPAND != 0
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        if path_count == 0 {
            if data_size != REDIRECTION_SIZE
                || flags & DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT == 0
                || flags & (DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME | DLL_REDIRECTION_PATH_EXPAND)
                    != 0
                || total_path_length != 0
                || path_segment_offset != 0
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
        } else {
            let path_count =
                usize::try_from(path_count).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            let path_array_size = path_count
                .checked_mul(PATH_SEGMENT_SIZE)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            let expected_data_size = REDIRECTION_SIZE
                .checked_add(path_array_size)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            if data_size != expected_data_size
                || data_offset
                    .checked_add(data_size)
                    .filter(|end| *end <= section.len())
                    .is_none()
                || path_segment_offset
                    .checked_add(path_array_size)
                    .filter(|end| *end <= section.len())
                    .is_none()
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            let mut raw_total_path_length = 0usize;
            let mut aligned_total_path_length = 0usize;
            let mut aligned_spans_in_bounds = true;
            for segment_index in 0..path_count {
                let segment_offset = path_segment_offset
                    .checked_add(
                        segment_index
                            .checked_mul(PATH_SEGMENT_SIZE)
                            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                    )
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
                let path_length = read_offset(section, segment_offset)?;
                let path_offset = read_offset(section, segment_offset + 4)?;
                let path_storage =
                    align4(path_length).ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
                if path_length % 2 != 0
                    || path_offset
                        .checked_add(path_length)
                        .filter(|end| *end <= section.len())
                        .is_none()
                    || section_contains_unit(section, path_offset, path_length, 0)?
                {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                aligned_spans_in_bounds &= path_offset
                    .checked_add(path_storage)
                    .is_some_and(|end| end <= section.len());
                raw_total_path_length = raw_total_path_length
                    .checked_add(path_length)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
                aligned_total_path_length = aligned_total_path_length
                    .checked_add(path_storage)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            }
            if total_path_length != raw_total_path_length
                && total_path_length != aligned_total_path_length
                || total_path_length == aligned_total_path_length && !aligned_spans_in_bounds
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
        }
    }
    Ok(DllRedirectionSection {
        count,
        index_offset,
        length,
    })
}

/// Case-insensitively find an exact counted UTF-16 DLL name in a validated section.
pub fn find_dll_redirection(
    section: &[u8],
    name: &[u16],
) -> Result<Option<DllRedirectionMatch>, NtStatus> {
    let metadata = validate_dll_redirection_section(section)?;
    let hash = strings::hash_unicode_string(name, true, HASH_ALGORITHM_X65599)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

    for position in 0..metadata.count as usize {
        let index_offset = usize::try_from(metadata.index_offset)
            .ok()
            .and_then(|base| {
                position
                    .checked_mul(INDEX_SIZE)
                    .and_then(|delta| base.checked_add(delta))
            })
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if read_u32(section, index_offset)? != hash {
            continue;
        }
        let name_offset = read_offset(section, index_offset + 4)?;
        let name_length = read_offset(section, index_offset + 8)?;
        if !section_name_eq(section, name_offset, name_length, name)? {
            continue;
        }
        let data_offset = read_offset(section, index_offset + 12)?;
        return Ok(Some(DllRedirectionMatch {
            index_offset: to_u32(index_offset).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            name_offset: to_u32(name_offset).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            name_length: to_u32(name_length).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            data_offset: to_u32(data_offset).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            data_length: read_u32(section, data_offset)?,
            assembly_roster_index: read_u32(section, index_offset + 20)?,
        }));
    }
    Ok(None)
}

/// Decode the validated redirection payload returned by [`find_dll_redirection`].
pub fn decode_dll_redirection(
    section: &[u8],
    matched: DllRedirectionMatch,
) -> Result<DllRedirectionData, NtStatus> {
    validate_dll_redirection_section(section)?;
    let data_offset =
        usize::try_from(matched.data_offset).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    if read_u32(section, data_offset)? != matched.data_length {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let flags = read_u32(section, data_offset + 4)?;
    let path_count = read_u32(section, data_offset + 12)?;
    let mut path_segments = Vec::new();
    path_segments
        .try_reserve_exact(path_count as usize)
        .map_err(|_| STATUS_NO_MEMORY)?;
    let path_array_offset = read_offset(section, data_offset + 16)?;
    for segment_index in 0..path_count as usize {
        let segment_offset = path_array_offset
            .checked_add(
                segment_index
                    .checked_mul(PATH_SEGMENT_SIZE)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let path_length = read_offset(section, segment_offset)?;
        let path_offset = read_offset(section, segment_offset + 4)?;
        let unit_count = path_length / 2;
        let mut path = Vec::new();
        path.try_reserve_exact(unit_count)
            .map_err(|_| STATUS_NO_MEMORY)?;
        for index in 0..unit_count {
            path.push(read_u16(section, path_offset + index * 2)?);
        }
        path_segments.push(path);
    }
    Ok(DllRedirectionData {
        flags,
        path_segments,
    })
}

/// Build the ReactOS window-class redirection string section in caller-supplied
/// assembly/file/entity order.
pub fn build_window_class_redirection_section(
    assemblies: &[WindowClassAssembly<'_>],
) -> Result<Vec<u8>, NtStatus> {
    let _assembly_count = u32::try_from(assemblies.len()).map_err(|_| STATUS_NO_MEMORY)?;
    let class_count = assemblies.iter().try_fold(0usize, |count, assembly| {
        count
            .checked_add(assembly.classes.len())
            .ok_or(STATUS_NO_MEMORY)
    })?;
    let count = u32::try_from(class_count).map_err(|_| STATUS_NO_MEMORY)?;
    let index_bytes = class_count
        .checked_mul(INDEX_SIZE)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut total = HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;

    for (assembly_index, assembly) in assemblies.iter().enumerate() {
        let roster_index = u32::try_from(assembly_index.checked_add(1).ok_or(STATUS_NO_MEMORY)?)
            .map_err(|_| STATUS_NO_MEMORY)?;
        for class in assembly.classes {
            let file = assembly
                .files
                .get(class.file_index)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            let entry = WindowClassSectionEntry {
                name: &class.name,
                module: &file.name,
                assembly_version: assembly.version,
                versioned: class.versioned,
                assembly_roster_index: roster_index,
            };
            validate_window_class_entry(&entry)?;
            let original_bytes = utf16_bytes_len(entry.name.len())?;
            let redirected_bytes = utf16_bytes_len(redirected_class_units(&entry)?)?;
            let module_bytes = utf16_bytes_len(entry.module.len())?;
            let original_storage = align4(original_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?)
                .ok_or(STATUS_NO_MEMORY)?;
            let string_storage = align4(
                redirected_bytes
                    .checked_add(module_bytes)
                    .and_then(|value| value.checked_add(4))
                    .ok_or(STATUS_NO_MEMORY)?,
            )
            .ok_or(STATUS_NO_MEMORY)?;
            total = total
                .checked_add(original_storage)
                .and_then(|value| value.checked_add(WINDOW_CLASS_REDIRECTION_SIZE))
                .and_then(|value| value.checked_add(string_storage))
                .ok_or(STATUS_NO_MEMORY)?;
        }
    }
    let _total_u32 = checked_section_size(total)?;

    let mut section = Vec::new();
    section
        .try_reserve_exact(total)
        .map_err(|_| STATUS_NO_MEMORY)?;
    section.resize(total, 0);
    write_u32(&mut section, 0, STRSECTION_MAGIC)?;
    write_u32(&mut section, 4, HEADER_SIZE as u32)?;
    write_u32(&mut section, 20, count)?;
    write_u32(&mut section, 24, HEADER_SIZE as u32)?;

    let mut cursor = HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut position = 0usize;
    for (assembly_index, assembly) in assemblies.iter().enumerate() {
        let roster_index = u32::try_from(assembly_index.checked_add(1).ok_or(STATUS_NO_MEMORY)?)
            .map_err(|_| STATUS_NO_MEMORY)?;
        for class in assembly.classes {
            let file = assembly
                .files
                .get(class.file_index)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            let entry = WindowClassSectionEntry {
                name: &class.name,
                module: &file.name,
                assembly_version: assembly.version,
                versioned: class.versioned,
                assembly_roster_index: roster_index,
            };
            let redirected = build_redirected_class_name(&entry)?;
            let index_offset = HEADER_SIZE
                .checked_add(position.checked_mul(INDEX_SIZE).ok_or(STATUS_NO_MEMORY)?)
                .ok_or(STATUS_NO_MEMORY)?;
            let original_bytes = utf16_bytes_len(entry.name.len())?;
            let redirected_bytes = utf16_bytes_len(redirected.len())?;
            let module_bytes = utf16_bytes_len(entry.module.len())?;
            let original_storage = align4(original_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?)
                .ok_or(STATUS_NO_MEMORY)?;
            let combined_strings = redirected_bytes
                .checked_add(module_bytes)
                .and_then(|value| value.checked_add(4))
                .ok_or(STATUS_NO_MEMORY)?;
            let string_storage = align4(combined_strings).ok_or(STATUS_NO_MEMORY)?;
            let name_offset = cursor;
            let data_offset = name_offset
                .checked_add(original_storage)
                .ok_or(STATUS_NO_MEMORY)?;
            let redirected_offset = data_offset
                .checked_add(WINDOW_CLASS_REDIRECTION_SIZE)
                .ok_or(STATUS_NO_MEMORY)?;
            let module_offset = redirected_offset
                .checked_add(redirected_bytes)
                .and_then(|value| value.checked_add(2))
                .ok_or(STATUS_NO_MEMORY)?;
            let data_length = WINDOW_CLASS_REDIRECTION_SIZE
                .checked_add(combined_strings)
                .ok_or(STATUS_NO_MEMORY)?;
            let hash = strings::hash_unicode_string(entry.name, true, HASH_ALGORITHM_X65599)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

            write_u32(&mut section, index_offset, hash)?;
            write_u32(&mut section, index_offset + 4, to_u32(name_offset)?)?;
            write_u32(&mut section, index_offset + 8, to_u32(original_bytes)?)?;
            write_u32(&mut section, index_offset + 12, to_u32(data_offset)?)?;
            write_u32(&mut section, index_offset + 16, to_u32(data_length)?)?;
            write_u32(&mut section, index_offset + 20, entry.assembly_roster_index)?;
            write_utf16(&mut section, name_offset, entry.name)?;

            write_u32(
                &mut section,
                data_offset,
                WINDOW_CLASS_REDIRECTION_SIZE as u32,
            )?;
            write_u32(&mut section, data_offset + 8, to_u32(redirected_bytes)?)?;
            write_u32(
                &mut section,
                data_offset + 12,
                WINDOW_CLASS_REDIRECTION_SIZE as u32,
            )?;
            write_u32(&mut section, data_offset + 16, to_u32(module_bytes)?)?;
            write_u32(&mut section, data_offset + 20, to_u32(module_offset)?)?;
            write_utf16(&mut section, redirected_offset, &redirected)?;
            write_utf16(&mut section, module_offset, entry.module)?;

            cursor = data_offset
                .checked_add(WINDOW_CLASS_REDIRECTION_SIZE)
                .and_then(|value| value.checked_add(string_storage))
                .ok_or(STATUS_NO_MEMORY)?;
            position += 1;
        }
    }

    if position != class_count || cursor != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(section)
}

/// Structurally validate a builder-owned window-class section before exposing
/// pointers into context-owned storage.
///
/// The assembly models are trusted object state and are not retained in this byte
/// validator; `assembly_count` bounds roster references. Native alignment padding
/// is intentionally ignored because ReactOS does not initialize it.
pub fn validate_window_class_redirection_section(
    section: &[u8],
    assembly_count: u32,
) -> Result<WindowClassRedirectionSection, NtStatus> {
    let length = u32::try_from(section.len()).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    if section.len() < HEADER_SIZE
        || read_u32(section, 0)? != STRSECTION_MAGIC
        || read_u32(section, 4)? != HEADER_SIZE as u32
        || read_u32(section, 8)? != 0
        || read_u32(section, 12)? != 0
        || read_u32(section, 16)? != 0
        || read_u32(section, 28)? != 0
        || read_u32(section, 32)? != 0
        || read_u32(section, 36)? != 0
        || read_u32(section, 40)? != 0
    {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let count = read_u32(section, 20)?;
    let index_offset = read_u32(section, 24)?;
    if index_offset != HEADER_SIZE as u32 {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let index_bytes = usize::try_from(count)
        .ok()
        .and_then(|value| value.checked_mul(INDEX_SIZE))
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut expected = HEADER_SIZE
        .checked_add(index_bytes)
        .filter(|value| *value <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

    for position in 0..count as usize {
        let index = HEADER_SIZE
            .checked_add(
                position
                    .checked_mul(INDEX_SIZE)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let stored_hash = read_u32(section, index)?;
        let name_offset = read_offset(section, index + 4)?;
        let name_length = read_offset(section, index + 8)?;
        let data_offset = read_offset(section, index + 12)?;
        let index_data_length = read_offset(section, index + 16)?;
        let roster_index = read_u32(section, index + 20)?;
        if name_offset != expected
            || name_length == 0
            || name_length % 2 != 0
            || roster_index == 0
            || roster_index > assembly_count
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let original_storage = align4(
            name_length
                .checked_add(2)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
        )
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if data_offset
            != name_offset
                .checked_add(original_storage)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
            || section_contains_unit(section, name_offset, name_length, 0)?
            || read_u16(
                section,
                name_offset
                    .checked_add(name_length)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )? != 0
            || hash_section_name(section, name_offset, name_length)? != stored_hash
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }

        let data_size = read_offset(section, data_offset)?;
        let reserved = read_u32(section, data_offset + 4)?;
        let redirected_length = read_offset(section, data_offset + 8)?;
        let redirected_relative_offset = read_offset(section, data_offset + 12)?;
        let module_length = read_offset(section, data_offset + 16)?;
        let module_offset = read_offset(section, data_offset + 20)?;
        let redirected_offset = data_offset
            .checked_add(WINDOW_CLASS_REDIRECTION_SIZE)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let expected_module_offset = redirected_offset
            .checked_add(redirected_length)
            .and_then(|value| value.checked_add(2))
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let combined_strings = redirected_length
            .checked_add(module_length)
            .and_then(|value| value.checked_add(4))
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let expected_data_length = WINDOW_CLASS_REDIRECTION_SIZE
            .checked_add(combined_strings)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let string_storage =
            align4(combined_strings).ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        expected = data_offset
            .checked_add(WINDOW_CLASS_REDIRECTION_SIZE)
            .and_then(|value| value.checked_add(string_storage))
            .filter(|value| *value <= section.len())
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;

        if data_size != WINDOW_CLASS_REDIRECTION_SIZE
            || reserved != 0
            || redirected_length == 0
            || redirected_length % 2 != 0
            || redirected_relative_offset != WINDOW_CLASS_REDIRECTION_SIZE
            || module_length == 0
            || module_length % 2 != 0
            || module_offset != expected_module_offset
            || index_data_length != expected_data_length
            || section_contains_unit(section, redirected_offset, redirected_length, 0)?
            || read_u16(
                section,
                redirected_offset
                    .checked_add(redirected_length)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )? != 0
            || section_contains_unit(section, module_offset, module_length, 0)?
            || read_u16(
                section,
                module_offset
                    .checked_add(module_length)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )? != 0
            || !redirected_class_name_is_valid(
                section,
                name_offset,
                name_length,
                redirected_offset,
                redirected_length,
            )?
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
    }

    if expected != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(WindowClassRedirectionSection {
        count,
        index_offset,
        length,
    })
}

/// Case-insensitively find the first exact original class key in a validated section.
pub fn find_window_class_redirection(
    section: &[u8],
    assembly_count: u32,
    name: &[u16],
) -> Result<Option<WindowClassRedirectionMatch>, NtStatus> {
    let metadata = validate_window_class_redirection_section(section, assembly_count)?;
    let hash = strings::hash_unicode_string(name, true, HASH_ALGORITHM_X65599)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    for position in 0..metadata.count as usize {
        let index_offset = usize::try_from(metadata.index_offset)
            .ok()
            .and_then(|base| {
                position
                    .checked_mul(INDEX_SIZE)
                    .and_then(|delta| base.checked_add(delta))
            })
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if read_u32(section, index_offset)? != hash {
            continue;
        }
        let name_offset = read_offset(section, index_offset + 4)?;
        let name_length = read_offset(section, index_offset + 8)?;
        if !section_name_eq(section, name_offset, name_length, name)? {
            continue;
        }
        let data_offset = read_offset(section, index_offset + 12)?;
        let redirected_length = read_u32(section, data_offset + 8)?;
        let redirected_relative_offset = read_offset(section, data_offset + 12)?;
        return Ok(Some(WindowClassRedirectionMatch {
            index_offset: invalid_to_u32(index_offset)?,
            name_offset: invalid_to_u32(name_offset)?,
            name_length: invalid_to_u32(name_length)?,
            data_offset: invalid_to_u32(data_offset)?,
            data_length: read_u32(section, index_offset + 16)?,
            versioned_name_offset: invalid_to_u32(
                data_offset
                    .checked_add(redirected_relative_offset)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )?,
            versioned_name_length: redirected_length,
            module_offset: read_u32(section, data_offset + 20)?,
            module_length: read_u32(section, data_offset + 16)?,
            assembly_roster_index: read_u32(section, index_offset + 20)?,
        }));
    }
    Ok(None)
}

/// Build a GUID-keyed CLR-surrogate activation-context section in assembly/entity order.
pub fn build_clr_surrogate_section(
    assemblies: &[ClrSurrogateAssembly<'_>],
) -> Result<Vec<u8>, NtStatus> {
    let count = assemblies.iter().try_fold(0usize, |count, assembly| {
        count
            .checked_add(assembly.surrogates.len())
            .ok_or(STATUS_NO_MEMORY)
    })?;
    let index_bytes = count.checked_mul(GUID_INDEX_SIZE).ok_or(STATUS_NO_MEMORY)?;
    let mut total = GUID_HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;
    for assembly in assemblies {
        for surrogate in assembly.surrogates {
            validate_clr_surrogate(surrogate)?;
            total = total
                .checked_add(clr_surrogate_storage_size(surrogate)?)
                .ok_or(STATUS_NO_MEMORY)?;
        }
    }
    let _total_u32 = checked_section_size(total)?;
    let count_u32 = u32::try_from(count).map_err(|_| STATUS_NO_MEMORY)?;

    let mut section = Vec::new();
    section
        .try_reserve_exact(total)
        .map_err(|_| STATUS_NO_MEMORY)?;
    section.resize(total, 0);
    write_u32(&mut section, 0, GUIDSECTION_MAGIC)?;
    write_u32(&mut section, 4, GUID_HEADER_SIZE as u32)?;
    write_u32(&mut section, 20, count_u32)?;
    write_u32(&mut section, 24, GUID_HEADER_SIZE as u32)?;

    let mut cursor = GUID_HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut position = 0usize;
    for (assembly_index, assembly) in assemblies.iter().enumerate() {
        let roster_index = u32::try_from(assembly_index.checked_add(1).ok_or(STATUS_NO_MEMORY)?)
            .map_err(|_| STATUS_NO_MEMORY)?;
        for surrogate in assembly.surrogates {
            let index_offset = GUID_HEADER_SIZE
                .checked_add(
                    position
                        .checked_mul(GUID_INDEX_SIZE)
                        .ok_or(STATUS_NO_MEMORY)?,
                )
                .ok_or(STATUS_NO_MEMORY)?;
            let storage_size = clr_surrogate_storage_size(surrogate)?;
            let data_length = clr_surrogate_data_length(surrogate)?;
            let version_bytes = surrogate
                .runtime_version
                .as_ref()
                .map(|version| utf16_bytes_len(version.len()))
                .transpose()?
                .unwrap_or(0);
            let name_bytes = utf16_bytes_len(surrogate.name.len())?;
            let version_offset = if version_bytes == 0 {
                0
            } else {
                CLR_SURROGATE_SIZE
            };
            let name_offset = CLR_SURROGATE_SIZE
                .checked_add(if version_bytes == 0 {
                    0
                } else {
                    version_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?
                })
                .ok_or(STATUS_NO_MEMORY)?;

            write_guid(&mut section, index_offset, surrogate.clsid)?;
            write_u32(&mut section, index_offset + 16, to_u32(cursor)?)?;
            write_u32(&mut section, index_offset + 20, to_u32(storage_size)?)?;
            write_u32(&mut section, index_offset + 24, roster_index)?;

            write_u32(&mut section, cursor, CLR_SURROGATE_SIZE as u32)?;
            write_guid(&mut section, cursor + 8, surrogate.clsid)?;
            write_u32(&mut section, cursor + 24, to_u32(version_offset)?)?;
            write_u32(&mut section, cursor + 28, to_u32(version_bytes)?)?;
            write_u32(&mut section, cursor + 32, to_u32(name_offset)?)?;
            write_u32(&mut section, cursor + 36, to_u32(name_bytes)?)?;
            if version_bytes != 0 {
                write_utf16(
                    &mut section,
                    cursor + version_offset,
                    surrogate.runtime_version.as_ref().unwrap(),
                )?;
            }
            write_utf16(&mut section, cursor + name_offset, &surrogate.name)?;

            debug_assert!(data_length <= storage_size);
            cursor = cursor.checked_add(storage_size).ok_or(STATUS_NO_MEMORY)?;
            position += 1;
        }
    }
    if position != count || cursor != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(section)
}

/// Find an exact GUID in a structurally validated CLR-surrogate section.
pub fn find_clr_surrogate(
    section: &[u8],
    clsid: &Guid,
) -> Result<Option<ClrSurrogateMatch>, NtStatus> {
    if section.len() < GUID_HEADER_SIZE
        || read_u32(section, 0)? != GUIDSECTION_MAGIC
        || read_u32(section, 4)? != GUID_HEADER_SIZE as u32
        || read_u32(section, 8)? != 0
        || read_u32(section, 12)? != 0
        || read_u32(section, 16)? != 0
        || read_u32(section, 28)? != 0
        || read_u32(section, 32)? != 0
        || read_u32(section, 36)? != 0
        || read_u32(section, 24)? != GUID_HEADER_SIZE as u32
    {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let count = read_offset(section, 20)?;
    let index_bytes = count
        .checked_mul(GUID_INDEX_SIZE)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut expected = GUID_HEADER_SIZE
        .checked_add(index_bytes)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut found = None;

    for position in 0..count {
        let index = GUID_HEADER_SIZE
            .checked_add(
                position
                    .checked_mul(GUID_INDEX_SIZE)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let index_guid = read_guid(section, index)?;
        let data_offset = read_offset(section, index + 16)?;
        let stored_data_length = read_offset(section, index + 20)?;
        let roster_index = read_u32(section, index + 24)?;
        if data_offset != expected
            || stored_data_length < CLR_SURROGATE_SIZE
            || stored_data_length % 4 != 0
            || roster_index == 0
            || data_offset
                .checked_add(stored_data_length)
                .filter(|end| *end <= section.len())
                .is_none()
            || read_u32(section, data_offset)? != CLR_SURROGATE_SIZE as u32
            || read_u32(section, data_offset + 4)? != 0
            || read_guid(section, data_offset + 8)? != index_guid
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let version_offset = read_offset(section, data_offset + 24)?;
        let version_length = read_offset(section, data_offset + 28)?;
        let name_offset = read_offset(section, data_offset + 32)?;
        let name_length = read_offset(section, data_offset + 36)?;
        let version_storage = if version_length == 0 {
            if version_offset != 0 {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            0
        } else {
            if version_offset != CLR_SURROGATE_SIZE
                || version_length % 2 != 0
                || section_contains_unit(section, data_offset + version_offset, version_length, 0)?
                || read_u16(
                    section,
                    data_offset
                        .checked_add(version_offset)
                        .and_then(|value| value.checked_add(version_length))
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                )? != 0
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            version_length
                .checked_add(2)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
        };
        if name_offset
            != CLR_SURROGATE_SIZE
                .checked_add(version_storage)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
            || name_length == 0
            || name_length % 2 != 0
            || section_contains_unit(section, data_offset + name_offset, name_length, 0)?
            || read_u16(
                section,
                data_offset
                    .checked_add(name_offset)
                    .and_then(|value| value.checked_add(name_length))
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )? != 0
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let data_length = name_offset
            .checked_add(name_length)
            .and_then(|value| value.checked_add(2))
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let canonical_storage = align4(data_length).ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let explicit_empty_version_storage =
            align4(data_length + 2).ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if stored_data_length != canonical_storage
            && !(version_length == 0 && stored_data_length == explicit_empty_version_storage)
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        if found.is_none() && index_guid == *clsid {
            found = Some(ClrSurrogateMatch {
                data_offset: invalid_to_u32(data_offset)?,
                data_length: invalid_to_u32(data_length)?,
                assembly_roster_index: roster_index,
            });
        }
        expected = data_offset
            .checked_add(stored_data_length)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    }
    if expected != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(found)
}

fn validate_clr_surrogate(surrogate: &ManifestClrSurrogate) -> Result<(), NtStatus> {
    if surrogate.name.is_empty()
        || surrogate.name.contains(&0)
        || surrogate
            .runtime_version
            .as_ref()
            .is_some_and(|version| version.contains(&0))
    {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(())
}

fn clr_surrogate_data_length(surrogate: &ManifestClrSurrogate) -> Result<usize, NtStatus> {
    let version_bytes = surrogate
        .runtime_version
        .as_ref()
        .map(|version| utf16_bytes_len(version.len()))
        .transpose()?
        .unwrap_or(0);
    let name_bytes = utf16_bytes_len(surrogate.name.len())?;
    CLR_SURROGATE_SIZE
        .checked_add(if version_bytes == 0 {
            0
        } else {
            version_bytes.checked_add(2).ok_or(STATUS_NO_MEMORY)?
        })
        .and_then(|value| value.checked_add(name_bytes))
        .and_then(|value| value.checked_add(2))
        .ok_or(STATUS_NO_MEMORY)
}

fn clr_surrogate_storage_size(surrogate: &ManifestClrSurrogate) -> Result<usize, NtStatus> {
    let data_length = clr_surrogate_data_length(surrogate)?;
    let explicit_empty_version = surrogate
        .runtime_version
        .as_ref()
        .is_some_and(Vec::is_empty);
    align4(
        data_length
            .checked_add(if explicit_empty_version { 2 } else { 0 })
            .ok_or(STATUS_NO_MEMORY)?,
    )
    .ok_or(STATUS_NO_MEMORY)
}

fn validate_window_class_entry(entry: &WindowClassSectionEntry<'_>) -> Result<(), NtStatus> {
    if entry.name.is_empty()
        || entry.name.contains(&0)
        || entry.module.is_empty()
        || entry.module.contains(&0)
        || entry.assembly_roster_index == 0
    {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok(())
}

fn build_redirected_class_name(entry: &WindowClassSectionEntry<'_>) -> Result<Vec<u16>, NtStatus> {
    let mut output = Vec::new();
    let capacity = entry.name.len().checked_add(24).ok_or(STATUS_NO_MEMORY)?;
    output.try_reserve(capacity).map_err(|_| STATUS_NO_MEMORY)?;
    if entry.versioned {
        for (position, component) in entry.assembly_version.iter().copied().enumerate() {
            if position != 0 {
                output.push(b'.' as u16);
            }
            push_decimal_u16(&mut output, component)?;
        }
        output.push(b'!' as u16);
    }
    output.extend_from_slice(entry.name);
    Ok(output)
}

fn redirected_class_units(entry: &WindowClassSectionEntry<'_>) -> Result<usize, NtStatus> {
    if !entry.versioned {
        return Ok(entry.name.len());
    }
    entry
        .assembly_version
        .iter()
        .copied()
        .try_fold(4usize, |units, component| {
            units
                .checked_add(decimal_u16_digits(component))
                .ok_or(STATUS_NO_MEMORY)
        })?
        .checked_add(entry.name.len())
        .ok_or(STATUS_NO_MEMORY)
}

fn decimal_u16_digits(value: u16) -> usize {
    match value {
        0..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1_000..=9_999 => 4,
        _ => 5,
    }
}

fn push_decimal_u16(output: &mut Vec<u16>, value: u16) -> Result<(), NtStatus> {
    let mut digits = [0u16; 5];
    let mut remaining = value;
    let mut count = 0usize;
    loop {
        digits[count] = b'0' as u16 + remaining % 10;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    output.try_reserve(count).map_err(|_| STATUS_NO_MEMORY)?;
    output.extend(digits[..count].iter().rev().copied());
    Ok(())
}

fn redirected_class_name_is_valid(
    section: &[u8],
    original_offset: usize,
    original_length: usize,
    redirected_offset: usize,
    redirected_length: usize,
) -> Result<bool, NtStatus> {
    if section_regions_equal(
        section,
        original_offset,
        original_length,
        redirected_offset,
        redirected_length,
    )? {
        return Ok(true);
    }
    let suffix_offset = match redirected_offset.checked_add(
        redirected_length
            .checked_sub(original_length)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
    ) {
        Some(offset) => offset,
        None => return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
    };
    let minimum_suffix = redirected_offset
        .checked_add(2)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    if suffix_offset < minimum_suffix
        || read_u16(section, suffix_offset - 2)? != b'!' as u16
        || !section_regions_equal(
            section,
            original_offset,
            original_length,
            suffix_offset,
            original_length,
        )?
    {
        return Ok(false);
    }
    parse_canonical_assembly_version(section, redirected_offset, suffix_offset - 2)
}

fn parse_canonical_assembly_version(
    section: &[u8],
    start: usize,
    end: usize,
) -> Result<bool, NtStatus> {
    let mut cursor = start;
    for component in 0..4 {
        let component_start = cursor;
        let mut value = 0u32;
        while cursor < end {
            let unit = read_u16(section, cursor)?;
            if !(b'0' as u16..=b'9' as u16).contains(&unit) {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u32::from(unit - b'0' as u16)))
                .unwrap_or(u32::MAX);
            cursor += 2;
        }
        if cursor == component_start
            || value > u16::MAX as u32
            || (cursor - component_start > 2 && read_u16(section, component_start)? == b'0' as u16)
        {
            return Ok(false);
        }
        if component == 3 {
            return Ok(cursor == end);
        }
        if cursor >= end || read_u16(section, cursor)? != b'.' as u16 {
            return Ok(false);
        }
        cursor += 2;
    }
    Ok(false)
}

fn section_regions_equal(
    section: &[u8],
    left_offset: usize,
    left_length: usize,
    right_offset: usize,
    right_length: usize,
) -> Result<bool, NtStatus> {
    if left_length != right_length || left_length % 2 != 0 {
        return Ok(false);
    }
    let left_end = left_offset
        .checked_add(left_length)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let right_end = right_offset
        .checked_add(right_length)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut left = left_offset;
    let mut right = right_offset;
    while left < left_end && right < right_end {
        if read_u16(section, left)? != read_u16(section, right)? {
            return Ok(false);
        }
        left += 2;
        right += 2;
    }
    Ok(left == left_end && right == right_end)
}

fn invalid_to_u32(value: usize) -> Result<u32, NtStatus> {
    u32::try_from(value).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
}

fn checked_section_size(value: usize) -> Result<u32, NtStatus> {
    u32::try_from(value).map_err(|_| STATUS_NO_MEMORY)
}

fn utf16_bytes_len(units: usize) -> Result<usize, NtStatus> {
    units.checked_mul(2).ok_or(STATUS_NO_MEMORY)
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn to_u32(value: usize) -> Result<u32, NtStatus> {
    u32::try_from(value).map_err(|_| STATUS_NO_MEMORY)
}

fn write_u32(section: &mut [u8], offset: usize, value: u32) -> Result<(), NtStatus> {
    let end = offset.checked_add(4).ok_or(STATUS_NO_MEMORY)?;
    let destination = section.get_mut(offset..end).ok_or(STATUS_NO_MEMORY)?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_guid(section: &mut [u8], offset: usize, value: Guid) -> Result<(), NtStatus> {
    let end = offset.checked_add(16).ok_or(STATUS_NO_MEMORY)?;
    let destination = section.get_mut(offset..end).ok_or(STATUS_NO_MEMORY)?;
    destination.copy_from_slice(&value.to_windows_bytes());
    Ok(())
}

fn write_utf16(section: &mut [u8], offset: usize, value: &[u16]) -> Result<(), NtStatus> {
    let byte_length = utf16_bytes_len(value.len())?;
    let end = offset.checked_add(byte_length).ok_or(STATUS_NO_MEMORY)?;
    let destination = section.get_mut(offset..end).ok_or(STATUS_NO_MEMORY)?;
    for (chunk, unit) in destination.chunks_exact_mut(2).zip(value) {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

fn read_u32(section: &[u8], offset: usize) -> Result<u32, NtStatus> {
    let end = offset
        .checked_add(4)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let bytes = section
        .get(offset..end)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_guid(section: &[u8], offset: usize) -> Result<Guid, NtStatus> {
    let end = offset
        .checked_add(16)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let bytes = section
        .get(offset..end)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut encoded = [0u8; 16];
    encoded.copy_from_slice(bytes);
    Ok(Guid::from_windows_bytes(encoded))
}

fn read_offset(section: &[u8], offset: usize) -> Result<usize, NtStatus> {
    usize::try_from(read_u32(section, offset)?).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
}

fn read_u16(section: &[u8], offset: usize) -> Result<u16, NtStatus> {
    let end = offset
        .checked_add(2)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let bytes = section
        .get(offset..end)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn hash_section_name(section: &[u8], offset: usize, length: usize) -> Result<u32, NtStatus> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut hash = 0u32;
    let mut cursor = offset;
    while cursor < end {
        let unit = strings::upcase_char(read_u16(section, cursor)?);
        hash = hash.wrapping_mul(65_599).wrapping_add(unit as u32);
        cursor += 2;
    }
    Ok(hash)
}

fn section_name_eq(
    section: &[u8],
    offset: usize,
    length: usize,
    name: &[u16],
) -> Result<bool, NtStatus> {
    let Some(name_bytes) = name.len().checked_mul(2) else {
        return Ok(false);
    };
    if name_bytes != length {
        return Ok(false);
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut cursor = offset;
    for &expected in name {
        if strings::upcase_char(read_u16(section, cursor)?) != strings::upcase_char(expected) {
            return Ok(false);
        }
        cursor += 2;
    }
    Ok(cursor == end)
}

fn section_contains_unit(
    section: &[u8],
    offset: usize,
    length: usize,
    needle: u16,
) -> Result<bool, NtStatus> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= section.len())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut cursor = offset;
    while cursor < end {
        if read_u16(section, cursor)? == needle {
            return Ok(true);
        }
        cursor += 2;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn surrogate_guid(last: u8) -> Guid {
        Guid {
            data1: 0x9666_6666,
            data2: 0x8888,
            data3: 0x7777,
            data4: [0x66, 0x66, 0x55, 0x55, 0x55, 0x55, 0x55, last],
        }
    }

    #[test]
    fn builds_exact_clr_surrogate_guid_section() {
        let surrogates = [ManifestClrSurrogate {
            clsid: surrogate_guid(0x55),
            name: wide("testsurrogate"),
            runtime_version: Some(wide("v2.0.50727")),
        }];
        let section = build_clr_surrogate_section(&[ClrSurrogateAssembly {
            surrogates: &surrogates,
        }])
        .unwrap();
        assert_eq!(section.len(), 160);
        assert_eq!(read_u32(&section, 0), Ok(GUIDSECTION_MAGIC));
        assert_eq!(read_u32(&section, 4), Ok(40));
        assert_eq!(read_u32(&section, 20), Ok(1));
        assert_eq!(read_u32(&section, 24), Ok(40));
        assert_eq!(read_guid(&section, 40), Ok(surrogate_guid(0x55)));
        assert_eq!(read_u32(&section, 56), Ok(68));
        assert_eq!(read_u32(&section, 60), Ok(92));
        assert_eq!(read_u32(&section, 64), Ok(1));
        assert_eq!(read_u32(&section, 68), Ok(40));
        assert_eq!(read_guid(&section, 76), Ok(surrogate_guid(0x55)));
        assert_eq!(read_u32(&section, 92), Ok(40));
        assert_eq!(read_u32(&section, 96), Ok(20));
        assert_eq!(read_u32(&section, 100), Ok(62));
        assert_eq!(read_u32(&section, 104), Ok(26));
        assert_eq!(read_wide(&section, 108, 20), wide("v2.0.50727"));
        assert_eq!(read_wide(&section, 130, 26), wide("testsurrogate"));
        assert_eq!(
            find_clr_surrogate(&section, &surrogate_guid(0x55)),
            Ok(Some(ClrSurrogateMatch {
                data_offset: 68,
                data_length: 90,
                assembly_roster_index: 1,
            }))
        );
        assert_eq!(
            find_clr_surrogate(&section, &surrogate_guid(0x54)),
            Ok(None)
        );
    }

    #[test]
    fn clr_surrogate_sections_preserve_rosters_and_empty_version_storage() {
        let absent = [ManifestClrSurrogate {
            clsid: surrogate_guid(0x55),
            name: wide("plain"),
            runtime_version: None,
        }];
        let empty = [ManifestClrSurrogate {
            clsid: surrogate_guid(0x56),
            name: wide("empty"),
            runtime_version: Some(Vec::new()),
        }];
        let section = build_clr_surrogate_section(&[
            ClrSurrogateAssembly { surrogates: &[] },
            ClrSurrogateAssembly {
                surrogates: &absent,
            },
            ClrSurrogateAssembly { surrogates: &empty },
        ])
        .unwrap();
        let absent_match = find_clr_surrogate(&section, &surrogate_guid(0x55))
            .unwrap()
            .unwrap();
        let empty_match = find_clr_surrogate(&section, &surrogate_guid(0x56))
            .unwrap()
            .unwrap();
        assert_eq!(absent_match.assembly_roster_index, 2);
        assert_eq!(empty_match.assembly_roster_index, 3);
        assert_eq!(absent_match.data_length, 52);
        assert_eq!(empty_match.data_length, 52);
        let first_storage = read_u32(&section, GUID_HEADER_SIZE + 20).unwrap();
        let second_storage = read_u32(&section, GUID_HEADER_SIZE + GUID_INDEX_SIZE + 20).unwrap();
        assert_eq!(first_storage, 52);
        assert_eq!(second_storage, 56);
    }

    #[test]
    fn clr_surrogate_builder_and_finder_reject_invalid_data() {
        let invalid = [ManifestClrSurrogate {
            clsid: Guid::default(),
            name: Vec::new(),
            runtime_version: None,
        }];
        assert_eq!(
            build_clr_surrogate_section(&[ClrSurrogateAssembly {
                surrogates: &invalid,
            }]),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );

        let valid = [ManifestClrSurrogate {
            clsid: surrogate_guid(0x55),
            name: wide("testsurrogate"),
            runtime_version: Some(wide("v2.0.50727")),
        }];
        let original =
            build_clr_surrogate_section(&[ClrSurrogateAssembly { surrogates: &valid }]).unwrap();
        for (offset, value) in [
            (0, 0),
            (8, 1),
            (24, 0),
            (56, 0),
            (60, 88),
            (64, 0),
            (68, 0),
            (72, 1),
            (92, 0),
            (96, 21),
            (100, 40),
            (104, 0),
        ] {
            let mut section = original.clone();
            write_u32(&mut section, offset, value).unwrap();
            assert_eq!(
                find_clr_surrogate(&section, &surrogate_guid(0x55)),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
                "offset {offset}"
            );
        }
        let mut truncated = original.clone();
        truncated.pop();
        assert_eq!(
            find_clr_surrogate(&truncated, &surrogate_guid(0x55)),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            find_clr_surrogate(&trailing, &surrogate_guid(0x55)),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn builds_exact_header_index_and_header_only_redirection() {
        let section = build_dll_redirection_section(&[DllRedirect {
            name: wide("Test.dll"),
            load_from: None,
        }])
        .unwrap();

        assert_eq!(section.len(), 108);
        assert_eq!(read_u32(&section, 0), Ok(STRSECTION_MAGIC));
        assert_eq!(read_u32(&section, 4), Ok(44));
        assert_eq!(read_u32(&section, 20), Ok(1));
        assert_eq!(read_u32(&section, 24), Ok(44));
        assert_eq!(read_u32(&section, 48), Ok(68));
        assert_eq!(read_u32(&section, 52), Ok(16));
        assert_eq!(read_u32(&section, 56), Ok(88));
        assert_eq!(read_u32(&section, 60), Ok(20));
        assert_eq!(read_u32(&section, 64), Ok(1));
        assert_eq!(read_u32(&section, 88), Ok(20));
        assert_eq!(
            read_u32(&section, 92),
            Ok(DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT)
        );
        assert_eq!(
            validate_dll_redirection_section(&section),
            Ok(DllRedirectionSection {
                count: 1,
                index_offset: 44,
                length: 108,
            })
        );
    }

    #[test]
    fn builds_dll_redirection_for_two_assemblies_in_declaration_order() {
        let root = [DllRedirect {
            name: wide("root.dll"),
            load_from: None,
        }];
        let dependency = [DllRedirect {
            name: wide("dependency.dll"),
            load_from: Some(wide("side\\dependency.dll")),
        }];
        let section = build_dll_redirection_section_for_assemblies(&[
            DllRedirectAssembly { redirects: &root },
            DllRedirectAssembly {
                redirects: &dependency,
            },
        ])
        .unwrap();

        assert_eq!(
            validate_dll_redirection_section(&section),
            Ok(DllRedirectionSection {
                count: 2,
                index_offset: 44,
                length: section.len() as u32,
            })
        );
        let root_match = find_dll_redirection(&section, &wide("ROOT.DLL"))
            .unwrap()
            .unwrap();
        let dependency_match = find_dll_redirection(&section, &wide("DEPENDENCY.DLL"))
            .unwrap()
            .unwrap();
        assert_eq!(root_match.index_offset, HEADER_SIZE as u32);
        assert_eq!(root_match.assembly_roster_index, 1);
        assert_eq!(
            dependency_match.index_offset,
            (HEADER_SIZE + INDEX_SIZE) as u32
        );
        assert_eq!(dependency_match.assembly_roster_index, 2);
    }

    #[test]
    fn empty_dll_redirect_assemblies_retain_their_roster_positions() {
        let redirects = [DllRedirect {
            name: wide("only.dll"),
            load_from: None,
        }];
        let empty = DllRedirectAssembly { redirects: &[] };

        let empty_first = build_dll_redirection_section_for_assemblies(&[
            empty,
            DllRedirectAssembly {
                redirects: &redirects,
            },
        ])
        .unwrap();
        assert_eq!(
            find_dll_redirection(&empty_first, &wide("only.dll"))
                .unwrap()
                .unwrap()
                .assembly_roster_index,
            2
        );

        let empty_second = build_dll_redirection_section_for_assemblies(&[
            DllRedirectAssembly {
                redirects: &redirects,
            },
            empty,
        ])
        .unwrap();
        assert_eq!(
            find_dll_redirection(&empty_second, &wide("only.dll"))
                .unwrap()
                .unwrap()
                .assembly_roster_index,
            1
        );
    }

    #[test]
    fn duplicate_dll_name_across_assemblies_returns_roster_one() {
        let root = [DllRedirect {
            name: wide("same.dll"),
            load_from: None,
        }];
        let dependency = [DllRedirect {
            name: wide("SAME.DLL"),
            load_from: Some(wide("dependency.dll")),
        }];
        let section = build_dll_redirection_section_for_assemblies(&[
            DllRedirectAssembly { redirects: &root },
            DllRedirectAssembly {
                redirects: &dependency,
            },
        ])
        .unwrap();

        let found = find_dll_redirection(&section, &wide("same.dll"))
            .unwrap()
            .unwrap();
        assert_eq!(found.index_offset, HEADER_SIZE as u32);
        assert_eq!(found.data_length, REDIRECTION_SIZE as u32);
        assert_eq!(found.assembly_roster_index, 1);
    }

    #[test]
    fn validates_multi_assembly_dll_roster_indices() {
        let root = [DllRedirect {
            name: wide("root.dll"),
            load_from: None,
        }];
        let dependency = [DllRedirect {
            name: wide("dependency.dll"),
            load_from: None,
        }];
        let mut section = build_dll_redirection_section_for_assemblies(&[
            DllRedirectAssembly { redirects: &root },
            DllRedirectAssembly {
                redirects: &dependency,
            },
        ])
        .unwrap();

        assert_eq!(read_u32(&section, HEADER_SIZE + 20), Ok(1));
        assert_eq!(
            read_u32(&section, HEADER_SIZE + INDEX_SIZE + 20),
            Ok(2)
        );
        write_u32(&mut section, HEADER_SIZE + INDEX_SIZE + 20, 0).unwrap();
        assert_eq!(
            validate_dll_redirection_section(&section),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn lookup_is_case_insensitive_but_exactly_counted() {
        let mut stored_name = wide("Test.dll");
        stored_name[1] = 0x00e9;
        let section = build_dll_redirection_section(&[DllRedirect {
            name: stored_name,
            load_from: None,
        }])
        .unwrap();

        let mut query = wide("tEST.DLL");
        query[1] = 0x00c9;
        let found = find_dll_redirection(&section, &query).unwrap().unwrap();
        assert_eq!(found.index_offset, 44);
        assert_eq!(found.name_offset, 68);
        assert_eq!(found.data_length, 20);
        assert_eq!(found.assembly_roster_index, 1);
        let mut short_query = wide("tEst");
        short_query[1] = 0x00c9;
        assert_eq!(find_dll_redirection(&section, &short_query), Ok(None));
        let mut nul_terminated = query;
        nul_terminated.push(0);
        assert_eq!(find_dll_redirection(&section, &nul_terminated), Ok(None));
    }

    #[test]
    fn emits_one_relative_path_segment_and_expand_flag() {
        let section = build_dll_redirection_section(&[DllRedirect {
            name: wide("mapped.dll"),
            load_from: Some(wide("%ROOT%\\side\\mapped.dll")),
        }])
        .unwrap();
        let found = find_dll_redirection(&section, &wide("MAPPED.DLL"))
            .unwrap()
            .unwrap();
        let data = found.data_offset as usize;

        assert_eq!(found.data_length, 28);
        assert_eq!(read_u32(&section, 60), Ok(20));
        assert_eq!(read_u32(&section, data), Ok(28));
        assert_eq!(
            read_u32(&section, data + 4),
            Ok(DLL_REDIRECTION_PATH_EXPAND | DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME)
        );
        assert_eq!(read_u32(&section, data + 12), Ok(1));
        assert_eq!(read_u32(&section, data + 16), Ok((data + 20) as u32));
        assert_eq!(read_u32(&section, data + 24), Ok((data + 28) as u32));
    }

    #[test]
    fn explicit_empty_load_from_still_emits_a_path_segment() {
        let section = build_dll_redirection_section(&[DllRedirect {
            name: wide("empty.dll"),
            load_from: Some(Vec::new()),
        }])
        .unwrap();
        let found = find_dll_redirection(&section, &wide("empty.dll"))
            .unwrap()
            .unwrap();
        let data = found.data_offset as usize;

        assert_eq!(found.data_length, 28);
        assert_eq!(read_u32(&section, data + 4), Ok(0));
        assert_eq!(read_u32(&section, data + 8), Ok(0));
        assert_eq!(read_u32(&section, data + 12), Ok(1));
        assert_eq!(read_u32(&section, data + 20), Ok(0));
        assert_eq!(read_u32(&section, data + 24), Ok((data + 28) as u32));
        assert_eq!(section.len(), data + 28);
    }

    #[test]
    fn validates_and_decodes_multiple_native_path_segments() {
        let mut section = build_dll_redirection_section(&[DllRedirect {
            name: wide("mapped.dll"),
            load_from: Some(wide("ab")),
        }])
        .unwrap();
        let found = find_dll_redirection(&section, &wide("mapped.dll"))
            .unwrap()
            .unwrap();
        let data = found.data_offset as usize;
        section.truncate(data + 20);
        section.resize(data + 44, 0);
        write_u32(&mut section, data, 36).unwrap();
        write_u32(
            &mut section,
            data + 4,
            DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
        )
        .unwrap();
        write_u32(&mut section, data + 8, 8).unwrap();
        write_u32(&mut section, data + 12, 2).unwrap();
        write_u32(&mut section, data + 16, (data + 20) as u32).unwrap();
        write_u32(&mut section, data + 20, 2).unwrap();
        write_u32(&mut section, data + 24, (data + 36) as u32).unwrap();
        write_u32(&mut section, data + 28, 2).unwrap();
        write_u32(&mut section, data + 32, (data + 40) as u32).unwrap();
        write_utf16(&mut section, data + 36, &wide("a")).unwrap();
        write_utf16(&mut section, data + 40, &wide("b")).unwrap();

        let found = find_dll_redirection(&section, &wide("mapped.dll"))
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_dll_redirection(&section, found),
            Ok(DllRedirectionData {
                flags: DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME,
                path_segments: vec![wide("a"), wide("b")],
            })
        );
    }

    #[test]
    fn returns_first_duplicate_in_manifest_order() {
        let section = build_dll_redirection_section(&[
            DllRedirect {
                name: wide("same.dll"),
                load_from: None,
            },
            DllRedirect {
                name: wide("SAME.DLL"),
                load_from: Some(wide("other.dll")),
            },
        ])
        .unwrap();
        let found = find_dll_redirection(&section, &wide("same.dll"))
            .unwrap()
            .unwrap();
        assert_eq!(found.index_offset, 44);
        assert_eq!(found.data_length, 20);
    }

    #[test]
    fn validation_rejects_corrupt_offsets_hashes_and_records() {
        let original = build_dll_redirection_section(&[DllRedirect {
            name: wide("test.dll"),
            load_from: Some(wide("side.dll")),
        }])
        .unwrap();
        for (offset, value) in [(0, 0), (44, 0), (48, u32::MAX), (56, u32::MAX), (64, 0)] {
            let mut section = original.clone();
            write_u32(&mut section, offset, value).unwrap();
            assert_eq!(
                validate_dll_redirection_section(&section),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
        let mut truncated = original.clone();
        truncated.pop();
        assert_eq!(
            find_dll_redirection(&truncated, &wide("test.dll")),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn checked_alignment_rejects_overflow() {
        assert_eq!(align4(usize::MAX), None);
        assert_eq!(utf16_bytes_len(usize::MAX), Err(STATUS_NO_MEMORY));
        assert_eq!(
            build_dll_redirection_section(&[DllRedirect {
                name: Vec::new(),
                load_from: None,
            }]),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            build_dll_redirection_section(&[DllRedirect {
                name: vec![b'a' as u16, 0, b'b' as u16],
                load_from: None,
            }]),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            build_dll_redirection_section(&[]),
            Ok(vec![
                0x53, 0x73, 0x48, 0x64, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])
        );
    }

    fn window_section(version: [u16; 4], class: &str, module: &str, versioned: bool) -> Vec<u8> {
        let files = [DllRedirect {
            name: wide(module),
            load_from: Some(wide("ignored-load-from.dll")),
        }];
        let classes = [ManifestWindowClass {
            file_index: 0,
            name: wide(class),
            versioned,
        }];
        build_window_class_redirection_section(&[WindowClassAssembly {
            version,
            files: &files,
            classes: &classes,
        }])
        .unwrap()
    }

    fn read_wide(section: &[u8], offset: usize, length: usize) -> Vec<u16> {
        (offset..offset + length)
            .step_by(2)
            .map(|position| read_u16(section, position).unwrap())
            .collect()
    }

    #[test]
    fn builds_exact_versioned_window_class_layout() {
        let files = [DllRedirect {
            name: wide("testlib1.dll"),
            load_from: None,
        }];
        let classes = [ManifestWindowClass {
            file_index: 0,
            name: wide("wndClass1"),
            versioned: true,
        }];
        let empty_files = [];
        let empty_classes = [];
        let section = build_window_class_redirection_section(&[
            WindowClassAssembly {
                version: [0; 4],
                files: &empty_files,
                classes: &empty_classes,
            },
            WindowClassAssembly {
                version: [1, 2, 3, 4],
                files: &files,
                classes: &classes,
            },
        ])
        .unwrap();

        assert_eq!(section.len(), 176);
        assert_eq!(read_u32(&section, 20), Ok(1));
        assert_eq!(read_u32(&section, 24), Ok(44));
        assert_eq!(read_u32(&section, 48), Ok(68));
        assert_eq!(read_u32(&section, 52), Ok(18));
        assert_eq!(read_u32(&section, 56), Ok(88));
        assert_eq!(read_u32(&section, 60), Ok(86));
        assert_eq!(read_u32(&section, 64), Ok(2));
        assert_eq!(read_u32(&section, 88), Ok(24));
        assert_eq!(read_u32(&section, 96), Ok(34));
        assert_eq!(read_u32(&section, 100), Ok(24));
        assert_eq!(read_u32(&section, 104), Ok(24));
        assert_eq!(read_u32(&section, 108), Ok(148));
        assert_eq!(read_wide(&section, 112, 34), wide("1.2.3.4!wndClass1"));
        assert_eq!(read_wide(&section, 148, 24), wide("testlib1.dll"));
        assert_eq!(
            validate_window_class_redirection_section(&section, 2),
            Ok(WindowClassRedirectionSection {
                count: 1,
                index_offset: 44,
                length: 176,
            })
        );
    }

    #[test]
    fn builds_unversioned_window_class_and_uses_file_name() {
        let section = window_section([4, 3, 2, 1], "wndClass3", "testlib2.dll", false);
        assert_eq!(section.len(), 160);
        let found = find_window_class_redirection(&section, 1, &wide("WNDcLASS3"))
            .unwrap()
            .unwrap();
        assert_eq!(found.data_offset, 88);
        assert_eq!(found.data_length, 70);
        assert_eq!(found.versioned_name_offset, 112);
        assert_eq!(found.versioned_name_length, 18);
        assert_eq!(found.module_offset, 132);
        assert_eq!(found.module_length, 24);
        assert_eq!(found.assembly_roster_index, 1);
        assert_eq!(read_wide(&section, 112, 18), wide("wndClass3"));
        assert_eq!(read_wide(&section, 132, 24), wide("testlib2.dll"));
    }

    #[test]
    fn preserves_assembly_order_empty_rosters_and_first_duplicate() {
        let root_files = [DllRedirect {
            name: wide("root.dll"),
            load_from: None,
        }];
        let root_classes = [ManifestWindowClass {
            file_index: 0,
            name: wide("SharedClass"),
            versioned: false,
        }];
        let dependency_files = [DllRedirect {
            name: wide("dependency.dll"),
            load_from: None,
        }];
        let dependency_classes = [ManifestWindowClass {
            file_index: 0,
            name: wide("sHAREDcLASS"),
            versioned: true,
        }];
        let section = build_window_class_redirection_section(&[
            WindowClassAssembly {
                version: [1, 0, 0, 0],
                files: &root_files,
                classes: &root_classes,
            },
            WindowClassAssembly {
                version: [2, 0, 0, 0],
                files: &[],
                classes: &[],
            },
            WindowClassAssembly {
                version: [3, 0, 0, 0],
                files: &dependency_files,
                classes: &dependency_classes,
            },
        ])
        .unwrap();
        let found = find_window_class_redirection(&section, 3, &wide("sharedclass"))
            .unwrap()
            .unwrap();
        assert_eq!(found.assembly_roster_index, 1);
        assert_eq!(
            read_wide(
                &section,
                found.module_offset as usize,
                found.module_length as usize
            ),
            wide("root.dll")
        );
        let dependency_index = HEADER_SIZE + INDEX_SIZE;
        assert_eq!(read_u32(&section, dependency_index + 20), Ok(3));
        let dependency_data = read_offset(&section, dependency_index + 12).unwrap();
        let dependency_module = read_offset(&section, dependency_data + 20).unwrap();
        let dependency_module_length = read_offset(&section, dependency_data + 16).unwrap();
        assert_eq!(
            read_wide(&section, dependency_module, dependency_module_length),
            wide("dependency.dll")
        );
        assert_eq!(
            validate_window_class_redirection_section(&section, 2),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn window_class_lookup_is_exactly_counted_and_formats_version_bounds() {
        for (version, expected) in [
            ([0; 4], "0.0.0.0!Class"),
            ([u16::MAX; 4], "65535.65535.65535.65535!Class"),
        ] {
            let section = window_section(version, "Class", "module.dll", true);
            let found = find_window_class_redirection(&section, 1, &wide("class"))
                .unwrap()
                .unwrap();
            assert_eq!(
                read_wide(
                    &section,
                    found.versioned_name_offset as usize,
                    found.versioned_name_length as usize,
                ),
                wide(expected)
            );
            let mut counted_with_nul = wide("Class");
            counted_with_nul.push(0);
            assert_eq!(
                find_window_class_redirection(&section, 1, &counted_with_nul),
                Ok(None)
            );
        }
    }

    #[test]
    fn window_class_builder_rejects_invalid_model_input() {
        let files = [DllRedirect {
            name: wide("module.dll"),
            load_from: None,
        }];
        for class in [
            ManifestWindowClass {
                file_index: 1,
                name: wide("Class"),
                versioned: false,
            },
            ManifestWindowClass {
                file_index: 0,
                name: Vec::new(),
                versioned: false,
            },
            ManifestWindowClass {
                file_index: 0,
                name: vec![b'C' as u16, 0],
                versioned: false,
            },
        ] {
            assert_eq!(
                build_window_class_redirection_section(&[WindowClassAssembly {
                    version: [1; 4],
                    files: &files,
                    classes: &[class],
                }]),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
        let bad_file = [DllRedirect {
            name: Vec::new(),
            load_from: None,
        }];
        let class = [ManifestWindowClass {
            file_index: 0,
            name: wide("Class"),
            versioned: false,
        }];
        assert_eq!(
            build_window_class_redirection_section(&[WindowClassAssembly {
                version: [1; 4],
                files: &bad_file,
                classes: &class,
            }]),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        let nul_file = [DllRedirect {
            name: vec![b'm' as u16, 0, b'd' as u16],
            load_from: None,
        }];
        assert_eq!(
            build_window_class_redirection_section(&[WindowClassAssembly {
                version: [1; 4],
                files: &nul_file,
                classes: &class,
            }]),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            build_window_class_redirection_section(&[]),
            Ok(vec![
                0x53, 0x73, 0x48, 0x64, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])
        );
    }

    #[test]
    fn window_class_validation_rejects_corruption_and_trailing_bytes() {
        let original = window_section([1, 2, 3, 4], "wndClass1", "testlib1.dll", true);
        for (offset, value) in [
            (0, 0),
            (8, 1),
            (44, 0),
            (48, u32::MAX),
            (52, 17),
            (56, u32::MAX),
            (60, 1),
            (64, 0),
            (88, 20),
            (92, 1),
            (96, 0),
            (100, 0),
            (104, 0),
            (108, 0),
        ] {
            let mut section = original.clone();
            write_u32(&mut section, offset, value).unwrap();
            assert_eq!(
                validate_window_class_redirection_section(&section, 1),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
                "offset {offset}"
            );
        }
        let mut bad_redirected_name = original.clone();
        let bang_offset = 112 + wide("1.2.3.4").len() * 2;
        bad_redirected_name[bang_offset..bang_offset + 2]
            .copy_from_slice(&(b'.' as u16).to_le_bytes());
        assert_eq!(
            validate_window_class_redirection_section(&bad_redirected_name, 1),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        for (offset, value) in [
            (86, b'X' as u16),  // original-name terminator
            (114, 0),           // redirected-name interior NUL
            (120, b'x' as u16), // non-decimal version component
            (144, b'X' as u16), // redirected suffix differs from original
            (172, b'X' as u16), // module-name terminator
        ] {
            let mut section = original.clone();
            section[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                validate_window_class_redirection_section(&section, 1),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
                "UTF-16 offset {offset}"
            );
        }
        let mut truncated = original.clone();
        truncated.pop();
        assert_eq!(
            find_window_class_redirection(&truncated, 1, &wide("wndClass1")),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            validate_window_class_redirection_section(&trailing, 1),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        if let Ok(too_large) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(checked_section_size(too_large), Err(STATUS_NO_MEMORY));
        }
    }
}
