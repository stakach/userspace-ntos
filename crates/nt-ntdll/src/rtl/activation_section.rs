//! Activation-context DLL-redirection string-section construction and lookup.

use alloc::vec::Vec;

use crate::NtStatus;

use super::{activation::DllRedirect, strings};

pub const STRSECTION_MAGIC: u32 = 0x6448_7353;
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
const HASH_ALGORITHM_X65599: u32 = 1;

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

/// Build the exact ReactOS DLL-redirection string-section representation.
///
/// The bounded manifest parser supports one assembly, so every emitted index has roster index 1.
pub fn build_dll_redirection_section(redirects: &[DllRedirect]) -> Result<Vec<u8>, NtStatus> {
    let count = u32::try_from(redirects.len()).map_err(|_| STATUS_NO_MEMORY)?;
    let index_bytes = redirects
        .len()
        .checked_mul(INDEX_SIZE)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut total = HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or(STATUS_NO_MEMORY)?;

    for redirect in redirects {
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
    for (position, redirect) in redirects.iter().enumerate() {
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
        write_u32(&mut section, index_offset + 20, 1)?;
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
            let flags = if load_from.iter().any(|unit| *unit == b'%' as u16) {
                DLL_REDIRECTION_PATH_EXPAND
            } else {
                0
            };

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
    }

    if cursor != total || total_u32 as usize != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
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
    let mut expected = usize::try_from(index_offset)
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

        if name_offset != expected
            || name_length == 0
            || name_length % 2 != 0
            || index_data_length != REDIRECTION_SIZE
            || roster_index == 0
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let name_with_nul = name_length
            .checked_add(2)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let name_storage = align4(name_with_nul).ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        let expected_data = name_offset
            .checked_add(name_storage)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if data_offset != expected_data
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
        expected = if path_count == 0 {
            if data_size != REDIRECTION_SIZE
                || flags != DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT
                || total_path_length != 0
                || path_segment_offset != 0
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            data_offset
                .checked_add(REDIRECTION_SIZE)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
        } else if path_count == 1 {
            let expected_data_size = REDIRECTION_SIZE
                .checked_add(PATH_SEGMENT_SIZE)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            if data_size != expected_data_size
                || flags & !DLL_REDIRECTION_PATH_EXPAND != 0
                || path_segment_offset
                    != data_offset
                        .checked_add(REDIRECTION_SIZE)
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            let path_length = read_offset(section, path_segment_offset)?;
            let path_offset = read_offset(
                section,
                path_segment_offset
                    .checked_add(4)
                    .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
            )?;
            let expected_path_offset = data_offset
                .checked_add(expected_data_size)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            if path_offset != expected_path_offset
                || path_length % 2 != 0
                || align4(path_length) != Some(total_path_length)
                || path_offset
                    .checked_add(total_path_length)
                    .filter(|end| *end <= section.len())
                    .is_none()
                || section_contains_unit(section, path_offset, path_length, 0)?
                || path_has_percent(section, path_offset, path_length)?
                    != (flags & DLL_REDIRECTION_PATH_EXPAND != 0)
            {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            path_offset
                .checked_add(total_path_length)
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?
        } else {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        };
    }

    if expected != section.len() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
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

fn path_has_percent(section: &[u8], offset: usize, length: usize) -> Result<bool, NtStatus> {
    section_contains_unit(section, offset, length, b'%' as u16)
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
            Ok(DLL_REDIRECTION_PATH_EXPAND)
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
}
