//! NT5 revision-1 canonical import-table hashing.

use alloc::vec::Vec;
use core::cmp::Ordering;

use nt_pe_loader::PeFile;

use crate::crypto::{md5_final, md5_init, md5_update, Md5Context};

const IMPORT_DIRECTORY_INDEX: usize = 1;
const IMPORT_DESCRIPTOR_SIZE: u32 = 20;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const MAX_MODULES: usize = 256;
const MAX_FUNCTIONS_PER_MODULE: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportTableHashError {
    UnknownRevision,
    ResourceDataNotFound,
    ResourceNameNotFound,
    NoMemory,
}

struct CanonicalModule<'a> {
    name: &'a [u8],
    functions: Vec<&'a [u8]>,
}

/// Computes the revision-1 MD5 over case-insensitively ordered import names.
pub fn compute_import_table_hash(
    image: &[u8],
    revision: u32,
) -> Result<[u8; 16], ImportTableHashError> {
    if revision != 1 {
        return Err(ImportTableHashError::UnknownRevision);
    }
    let pe = PeFile::parse(image).map_err(|_| ImportTableHashError::ResourceDataNotFound)?;
    let directory = pe.headers().data_directory(IMPORT_DIRECTORY_INDEX);
    if directory.virtual_address == 0 || directory.size == 0 {
        return Err(ImportTableHashError::ResourceDataNotFound);
    }

    let mut modules = Vec::new();
    modules
        .try_reserve(MAX_MODULES.min(8))
        .map_err(|_| ImportTableHashError::NoMemory)?;
    let mut descriptor_rva = directory.virtual_address;
    let mut terminated = false;
    for _ in 0..MAX_MODULES {
        let descriptor = pe
            .bytes_at_rva(descriptor_rva, IMPORT_DESCRIPTOR_SIZE as usize)
            .ok_or(ImportTableHashError::ResourceNameNotFound)?;
        let original_first_thunk = read_u32(descriptor, 0)?;
        let name_rva = read_u32(descriptor, 12)?;
        let first_thunk = read_u32(descriptor, 16)?;
        if name_rva == 0 || first_thunk == 0 {
            terminated = true;
            break;
        }

        let name = pe
            .cstr_bytes_at_rva(name_rva)
            .map_err(|_| ImportTableHashError::ResourceNameNotFound)?;
        let thunk_table = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut functions = Vec::new();
        functions
            .try_reserve(8)
            .map_err(|_| ImportTableHashError::NoMemory)?;
        let mut function_terminated = false;
        for index in 0..MAX_FUNCTIONS_PER_MODULE {
            let thunk_rva = thunk_table
                .checked_add(
                    u32::try_from(index)
                        .ok()
                        .and_then(|index| index.checked_mul(8))
                        .ok_or(ImportTableHashError::ResourceNameNotFound)?,
                )
                .ok_or(ImportTableHashError::ResourceNameNotFound)?;
            let thunk = pe
                .bytes_at_rva(thunk_rva, 8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or(ImportTableHashError::ResourceNameNotFound)?;
            if thunk == 0 {
                function_terminated = true;
                break;
            }
            if thunk & IMAGE_ORDINAL_FLAG64 == 0 {
                let import_by_name =
                    u32::try_from(thunk).map_err(|_| ImportTableHashError::ResourceNameNotFound)?;
                let function_name_rva = import_by_name
                    .checked_add(2)
                    .ok_or(ImportTableHashError::ResourceNameNotFound)?;
                let function_name = pe
                    .cstr_bytes_at_rva(function_name_rva)
                    .map_err(|_| ImportTableHashError::ResourceNameNotFound)?;
                insert_nt5_sorted(&mut functions, function_name)?;
            }
        }
        if !function_terminated {
            return Err(ImportTableHashError::ResourceNameNotFound);
        }
        insert_module_nt5_sorted(&mut modules, CanonicalModule { name, functions })?;
        descriptor_rva = descriptor_rva
            .checked_add(IMPORT_DESCRIPTOR_SIZE)
            .ok_or(ImportTableHashError::ResourceNameNotFound)?;
    }
    if !terminated {
        return Err(ImportTableHashError::ResourceNameNotFound);
    }

    Ok(hash_canonical_modules(&modules))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ImportTableHashError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ImportTableHashError::ResourceNameNotFound)
}

fn ascii_case_insensitive_cmp(left: &[u8], right: &[u8]) -> Ordering {
    for (&left, &right) in left.iter().zip(right.iter()) {
        match left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    left.len().cmp(&right.len())
}

/// Reproduces NT5's linked-list insertion, including its unusual equal-key ordering.
fn nt5_insertion_index<T>(
    items: &[T],
    value: &T,
    compare: impl Fn(&T, &T) -> Ordering,
) -> usize {
    if items.is_empty() || compare(&items[0], value).is_gt() {
        return 0;
    }
    items[1..]
        .iter()
        .position(|item| !compare(item, value).is_lt())
        .map_or(items.len(), |index| index + 1)
}

fn insert_nt5_sorted<'a>(
    items: &mut Vec<&'a [u8]>,
    value: &'a [u8],
) -> Result<(), ImportTableHashError> {
    let index = nt5_insertion_index(items, &value, |left, right| {
        ascii_case_insensitive_cmp(left, right)
    });
    items
        .try_reserve(1)
        .map_err(|_| ImportTableHashError::NoMemory)?;
    items.insert(index, value);
    Ok(())
}

fn insert_module_nt5_sorted<'a>(
    items: &mut Vec<CanonicalModule<'a>>,
    value: CanonicalModule<'a>,
) -> Result<(), ImportTableHashError> {
    let index = nt5_insertion_index(items, &value, |left, right| {
        ascii_case_insensitive_cmp(left.name, right.name)
    });
    items
        .try_reserve(1)
        .map_err(|_| ImportTableHashError::NoMemory)?;
    items.insert(index, value);
    Ok(())
}

fn hash_canonical_modules(modules: &[CanonicalModule<'_>]) -> [u8; 16] {
    let mut context = Md5Context::zeroed();
    md5_init(&mut context);
    for module in modules {
        md5_update(&mut context, module.name);
        for function in &module.functions {
            md5_update(&mut context, function);
        }
    }
    md5_final(&mut context);
    context.digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const NT_OFFSET: usize = 0x80;
    const OPTIONAL_OFFSET: usize = NT_OFFSET + 24;
    const RAW_OFFSET: usize = 0x200;
    const SECTION_RVA: u32 = 0x1000;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn image_with_imports(function_thunks: &[u64]) -> Vec<u8> {
        let mut image = vec![0u8; 0x800];
        put_u16(&mut image, 0, 0x5a4d);
        put_u32(&mut image, 0x3c, NT_OFFSET as u32);
        put_u32(&mut image, NT_OFFSET, 0x0000_4550);
        put_u16(&mut image, NT_OFFSET + 4, 0x8664);
        put_u16(&mut image, NT_OFFSET + 6, 1);
        put_u16(&mut image, NT_OFFSET + 20, 0xf0);
        put_u16(&mut image, OPTIONAL_OFFSET, 0x20b);
        put_u64(&mut image, OPTIONAL_OFFSET + 24, 0x1_4000_0000);
        put_u32(&mut image, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut image, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 56, 0x2000);
        put_u32(&mut image, OPTIONAL_OFFSET + 60, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 108, 16);
        put_u32(&mut image, OPTIONAL_OFFSET + 120, SECTION_RVA);
        put_u32(&mut image, OPTIONAL_OFFSET + 124, 40);

        let section = OPTIONAL_OFFSET + 0xf0;
        image[section..section + 8].copy_from_slice(b".rdata\0\0");
        put_u32(&mut image, section + 8, 0x600);
        put_u32(&mut image, section + 12, SECTION_RVA);
        put_u32(&mut image, section + 16, 0x600);
        put_u32(&mut image, section + 20, RAW_OFFSET as u32);
        put_u32(&mut image, section + 36, 0x4000_0040);

        put_u32(&mut image, RAW_OFFSET, SECTION_RVA + 0x100);
        put_u32(&mut image, RAW_OFFSET + 12, SECTION_RVA + 0x80);
        put_u32(&mut image, RAW_OFFSET + 16, SECTION_RVA + 0x180);
        image[RAW_OFFSET + 0x80..RAW_OFFSET + 0x8d].copy_from_slice(b"KERNEL32.dll\0");
        for (index, thunk) in function_thunks.iter().enumerate() {
            put_u64(&mut image, RAW_OFFSET + 0x100 + index * 8, *thunk);
        }
        image
    }

    #[test]
    fn rejects_unknown_revision_before_parsing() {
        assert_eq!(
            compute_import_table_hash(b"not a PE", 0),
            Err(ImportTableHashError::UnknownRevision)
        );
    }

    #[test]
    fn missing_import_directory_is_reported() {
        let mut image = image_with_imports(&[0]);
        put_u32(&mut image, OPTIONAL_OFFSET + 120, 0);
        put_u32(&mut image, OPTIONAL_OFFSET + 124, 0);
        assert_eq!(
            compute_import_table_hash(&image, 1),
            Err(ImportTableHashError::ResourceDataNotFound)
        );
    }

    #[test]
    fn hashes_named_imports_and_ignores_ordinals() {
        let mut image = image_with_imports(&[
            (SECTION_RVA + 0x220) as u64,
            IMAGE_ORDINAL_FLAG64 | 7,
            (SECTION_RVA + 0x200) as u64,
            0,
        ]);
        image[RAW_OFFSET + 0x202..RAW_OFFSET + 0x208].copy_from_slice(b"alpha\0");
        image[RAW_OFFSET + 0x222..RAW_OFFSET + 0x227].copy_from_slice(b"Zeta\0");
        assert_eq!(
            compute_import_table_hash(&image, 1).unwrap(),
            [
                0x68, 0x21, 0xb0, 0x9e, 0x2a, 0x6c, 0x3f, 0x18, 0xfb, 0x35, 0xe6, 0x2f, 0x57, 0x3e,
                0xcc, 0x2e,
            ]
        );
    }

    #[test]
    fn equal_case_keys_follow_nt5_insertion_order() {
        let mut values = Vec::new();
        insert_nt5_sorted(&mut values, b"Name").unwrap();
        insert_nt5_sorted(&mut values, b"NAME").unwrap();
        insert_nt5_sorted(&mut values, b"name").unwrap();
        assert_eq!(values, vec![b"Name".as_slice(), b"name", b"NAME"]);
    }
}
