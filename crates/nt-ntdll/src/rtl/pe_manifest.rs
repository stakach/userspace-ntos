//! Raw PE manifest-resource extraction for file-backed activation contexts.

use alloc::vec::Vec;

use super::pe_resource::{self, FindStatus, ResName};
use crate::{NtStatus, STATUS_INVALID_PARAMETER};

pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = 0xC000_007B;
pub const STATUS_RESOURCE_DATA_NOT_FOUND: NtStatus = 0xC000_0089;
pub const STATUS_RESOURCE_TYPE_NOT_FOUND: NtStatus = 0xC000_008A;
pub const STATUS_RESOURCE_NAME_NOT_FOUND: NtStatus = 0xC000_008B;
pub const STATUS_RESOURCE_LANG_NOT_FOUND: NtStatus = 0xC000_00A2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestResourceName {
    Id(u16),
    Name(Vec<u16>),
}

impl ManifestResourceName {
    fn as_res_name(&self) -> ResName<'_> {
        match self {
            Self::Id(id) => ResName::Id(*id),
            Self::Name(name) => ResName::Name(name),
        }
    }
}

/// Interpret a pointer-form resource name. A leading `#` is a decimal integer resource id.
pub fn parse_manifest_resource_name(name: &[u16]) -> Result<ManifestResourceName, NtStatus> {
    if name.first().copied() != Some(b'#' as u16) {
        return Ok(ManifestResourceName::Name(name.to_vec()));
    }
    if name.len() == 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut value = 0u32;
    for &unit in &name[1..] {
        if !(b'0' as u16..=b'9' as u16).contains(&unit) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add((unit - b'0' as u16) as u32))
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if value > u16::MAX as u32 {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(ManifestResourceName::Id(value as u16))
}

fn language_candidates(language: u16) -> ([u16; 4], usize, bool) {
    let primary = language & 0x03ff;
    let neutral_first = primary == 0;
    let mut candidates = [0u16; 4];
    let mut count = 0usize;
    for candidate in [language, primary, 0] {
        if !candidates[..count].contains(&candidate) {
            candidates[count] = candidate;
            count += 1;
        }
    }
    if neutral_first && !candidates[..count].contains(&0x0409) {
        candidates[count] = 0x0409;
        count += 1;
    }
    (candidates, count, neutral_first)
}

fn find_status(status: FindStatus) -> NtStatus {
    match status {
        FindStatus::TypeNotFound => STATUS_RESOURCE_TYPE_NOT_FOUND,
        FindStatus::NameNotFound => STATUS_RESOURCE_NAME_NOT_FOUND,
        FindStatus::LangNotFound => STATUS_RESOURCE_LANG_NOT_FOUND,
        FindStatus::InvalidParameter => STATUS_INVALID_PARAMETER,
        FindStatus::DataNotFound | FindStatus::Success => STATUS_RESOURCE_DATA_NOT_FOUND,
    }
}

/// Extract `RT_MANIFEST` from a raw PE32+ file. Directory offsets are relative to the resource
/// root, while the final data entry contains an image RVA; both translations are checked.
pub fn extract_manifest_resource<'a>(
    image: &'a [u8],
    resource_name: &ManifestResourceName,
    language: u16,
) -> Result<&'a [u8], NtStatus> {
    let pe = nt_pe_loader::PeFile::parse(image).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let directory = pe
        .headers()
        .data_directory(nt_pe_loader::DIRECTORY_ENTRY_RESOURCE);
    if directory.virtual_address == 0 || directory.size < pe_resource::DIR_SIZE as u32 {
        return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
    }
    let rsrc = pe
        .bytes_at_rva(directory.virtual_address, directory.size as usize)
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    let (languages, language_count, neutral_first) = language_candidates(language);
    let found = pe_resource::find_entry(
        rsrc,
        &ResName::Id(24),
        &resource_name.as_res_name(),
        &languages[..language_count],
        neutral_first,
        3,
        false,
    )
    .map_err(find_status)?;
    let (data_rva, size) =
        pe_resource::data_entry(rsrc, found.offset).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    pe.bytes_at_rva(data_rva, size as usize)
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)
}

/// Extract the first numeric `RT_MANIFEST` name and its first language leaf.
///
/// ReactOS uses this order for private assembly DLLs when no resource name is supplied.
pub fn extract_first_manifest_resource(image: &[u8]) -> Result<&[u8], NtStatus> {
    let pe = nt_pe_loader::PeFile::parse(image).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let directory = pe
        .headers()
        .data_directory(nt_pe_loader::DIRECTORY_ENTRY_RESOURCE);
    if directory.virtual_address == 0 || directory.size < pe_resource::DIR_SIZE as u32 {
        return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
    }
    let rsrc = pe
        .bytes_at_rva(directory.virtual_address, directory.size as usize)
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    let manifest_directory =
        pe_resource::find_entry(rsrc, &ResName::Id(24), &ResName::Id(0), &[], false, 1, true)
            .map_err(find_status)?;
    let name_directory = pe_resource::find_first_id_entry(rsrc, manifest_directory.offset, true)
        .ok_or(STATUS_RESOURCE_NAME_NOT_FOUND)?;
    let data_entry = pe_resource::find_first_entry(rsrc, name_directory, false)
        .ok_or(STATUS_RESOURCE_LANG_NOT_FOUND)?;
    let (data_rva, size) =
        pe_resource::data_entry(rsrc, data_entry).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    pe.bytes_at_rva(data_rva, size as usize)
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const NT_OFFSET: usize = 0x40;
    const OPTIONAL_OFFSET: usize = 0x58;
    const SECTION_TABLE: usize = 0x148;
    const RAW_OFFSET: usize = 0x200;
    const RESOURCE_RVA: u32 = 0x3000;
    const PAYLOAD_OFFSET: usize = 0x80;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn manifest_pe(resource_name: Option<&[u16]>, language: u16, payload: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; RAW_OFFSET + 0x200];
        put_u16(&mut image, 0, 0x5a4d);
        put_u32(&mut image, 0x3c, NT_OFFSET as u32);
        put_u32(&mut image, NT_OFFSET, 0x0000_4550);
        put_u16(&mut image, NT_OFFSET + 4, 0x8664);
        put_u16(&mut image, NT_OFFSET + 6, 1);
        put_u16(&mut image, NT_OFFSET + 20, 240);
        put_u16(&mut image, NT_OFFSET + 22, 2);
        put_u16(&mut image, OPTIONAL_OFFSET, 0x020b);
        put_u64(&mut image, OPTIONAL_OFFSET + 24, 0x1_4000_0000);
        put_u32(&mut image, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut image, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 56, 0x4000);
        put_u32(&mut image, OPTIONAL_OFFSET + 60, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 108, 16);
        put_u32(&mut image, OPTIONAL_OFFSET + 112 + 2 * 8, RESOURCE_RVA);
        put_u32(&mut image, OPTIONAL_OFFSET + 112 + 2 * 8 + 4, 0x100);
        image[SECTION_TABLE..SECTION_TABLE + 8].copy_from_slice(b".rsrc\0\0\0");
        put_u32(&mut image, SECTION_TABLE + 8, 0x200);
        put_u32(&mut image, SECTION_TABLE + 12, RESOURCE_RVA);
        put_u32(&mut image, SECTION_TABLE + 16, 0x200);
        put_u32(&mut image, SECTION_TABLE + 20, RAW_OFFSET as u32);
        put_u32(&mut image, SECTION_TABLE + 36, 0x4000_0040);

        let root = RAW_OFFSET;
        put_u16(&mut image, root + 14, 1);
        put_u32(&mut image, root + 16, 24);
        put_u32(&mut image, root + 20, 0x8000_0018);
        if let Some(name) = resource_name {
            put_u16(&mut image, root + 0x18 + 12, 1);
            put_u32(&mut image, root + 0x28, 0x8000_0060);
            let string = root + 0x60;
            put_u16(&mut image, string, name.len() as u16);
            for (index, unit) in name.iter().copied().enumerate() {
                put_u16(&mut image, string + 2 + index * 2, unit);
            }
        } else {
            put_u16(&mut image, root + 0x18 + 14, 1);
            put_u32(&mut image, root + 0x28, 1);
        }
        put_u32(&mut image, root + 0x2c, 0x8000_0030);
        put_u16(&mut image, root + 0x30 + 14, 1);
        put_u32(&mut image, root + 0x40, language as u32);
        put_u32(&mut image, root + 0x44, 0x48);
        put_u32(
            &mut image,
            root + 0x48,
            RESOURCE_RVA + PAYLOAD_OFFSET as u32,
        );
        put_u32(&mut image, root + 0x4c, payload.len() as u32);
        image[root + PAYLOAD_OFFSET..root + PAYLOAD_OFFSET + payload.len()]
            .copy_from_slice(payload);
        image
    }

    #[test]
    fn resource_name_strings_support_decimal_ids() {
        assert_eq!(
            parse_manifest_resource_name(&"#123".encode_utf16().collect::<Vec<_>>()),
            Ok(ManifestResourceName::Id(123))
        );
        assert_eq!(
            parse_manifest_resource_name(&"LOGIN".encode_utf16().collect::<Vec<_>>()),
            Ok(ManifestResourceName::Name(
                "LOGIN".encode_utf16().collect::<Vec<_>>()
            ))
        );
        assert_eq!(
            parse_manifest_resource_name(&"#65536".encode_utf16().collect::<Vec<_>>()),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            parse_manifest_resource_name(&"#12x".encode_utf16().collect::<Vec<_>>()),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn extracts_numeric_and_named_resources_using_rva_translation() {
        let numeric = manifest_pe(None, 0x0409, b"numeric");
        assert_eq!(
            extract_manifest_resource(&numeric, &ManifestResourceName::Id(1), 0x0409),
            Ok(&b"numeric"[..])
        );

        let name = "Login".encode_utf16().collect::<Vec<_>>();
        let named = manifest_pe(Some(&name), 0x0409, b"named");
        assert_eq!(
            extract_manifest_resource(
                &named,
                &ManifestResourceName::Name("login".encode_utf16().collect()),
                0x0409,
            ),
            Ok(&b"named"[..])
        );
    }

    #[test]
    fn neutral_language_uses_the_first_resource_language() {
        let image = manifest_pe(None, 0x0411, b"neutral");
        assert_eq!(
            extract_manifest_resource(&image, &ManifestResourceName::Id(1), 0),
            Ok(&b"neutral"[..])
        );
        assert_eq!(extract_first_manifest_resource(&image), Ok(&b"neutral"[..]));
    }

    #[test]
    fn rejects_invalid_pe_and_resource_spans() {
        assert_eq!(
            extract_manifest_resource(&[0; 64], &ManifestResourceName::Id(1), 0),
            Err(STATUS_INVALID_IMAGE_FORMAT)
        );
        let mut image = manifest_pe(None, 0, b"bad-span");
        put_u32(&mut image, OPTIONAL_OFFSET + 112 + 2 * 8 + 4, 0x300);
        assert_eq!(
            extract_manifest_resource(&image, &ManifestResourceName::Id(1), 0),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );
    }
}
