//! Extended-attribute capture validation shared by native file creates and I/O providers.

use nt_types::AccessMask;

const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;

/// Captured `NtQueryEaFile` parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryEaParameters {
    pub length: u32,
    pub ea_list_length: u32,
    pub ea_index: u32,
}

/// Captured `NtSetEaFile` parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SetEaParameters {
    pub length: u32,
}

/// The byte offset of the first malformed `FILE_FULL_EA_INFORMATION` record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EaValidationError {
    pub offset: usize,
}

/// Validate a packed `FILE_GET_EA_INFORMATION` name-list chain.
///
/// Nonterminal records must use the exact four-byte-aligned record size. Extra
/// storage after the terminal record is accepted, matching the NT5 capture
/// loop.
pub fn validate_get_ea_buffer(bytes: &[u8]) -> Result<(), EaValidationError> {
    const EA_NAME_OFFSET: usize = 5;

    let mut offset = 0usize;
    loop {
        let remaining = bytes.get(offset..).ok_or(EaValidationError { offset })?;
        if remaining.len() < EA_NAME_OFFSET {
            return Err(EaValidationError { offset });
        }
        let name_len = remaining[4] as usize;
        let record_len = EA_NAME_OFFSET
            .checked_add(name_len)
            .and_then(|length| length.checked_add(1))
            .ok_or(EaValidationError { offset })?;
        if record_len > remaining.len() {
            return Err(EaValidationError { offset });
        }
        let next = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
        if next == 0 {
            return Ok(());
        }
        let aligned = record_len
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or(EaValidationError { offset })?;
        if next != aligned || next > remaining.len() {
            return Err(EaValidationError { offset });
        }
        offset = offset
            .checked_add(next)
            .ok_or(EaValidationError { offset })?;
    }
}

/// Validate a packed `FILE_FULL_EA_INFORMATION` chain using the NT I/O Manager rules.
///
/// The final entry has `NextEntryOffset == 0`; earlier entries must advance by the exact
/// four-byte-aligned size of the current record. Extra bytes after the final record are allowed,
/// matching `IoCheckEaBufferValidity`.
pub fn validate_ea_buffer(bytes: &[u8]) -> Result<(), EaValidationError> {
    const EA_NAME_OFFSET: usize = 8;

    let mut offset = 0usize;
    loop {
        let remaining = bytes.len().saturating_sub(offset);
        if remaining < EA_NAME_OFFSET {
            return Err(EaValidationError { offset });
        }
        let record = &bytes[offset..];
        let next = u32::from_le_bytes(record[0..4].try_into().unwrap()) as usize;
        let name_len = record[5] as usize;
        let value_len = u16::from_le_bytes(record[6..8].try_into().unwrap()) as usize;
        let computed = EA_NAME_OFFSET
            .checked_add(name_len)
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(value_len))
            .ok_or(EaValidationError { offset })?;
        if computed > remaining || record[EA_NAME_OFFSET + name_len] != 0 {
            return Err(EaValidationError { offset });
        }
        if next == 0 {
            return Ok(());
        }
        let aligned = computed
            .checked_add(3)
            .map(|len| len & !3)
            .ok_or(EaValidationError { offset })?;
        if next != aligned || next > remaining {
            return Err(EaValidationError { offset });
        }
        offset = offset
            .checked_add(next)
            .ok_or(EaValidationError { offset })?;
    }
}

/// NT5 references an EA-query File with `FILE_READ_EA` access.
pub fn query_ea_access_granted(granted: AccessMask) -> bool {
    granted.contains(AccessMask::GENERIC_ALL)
        || granted.contains(AccessMask::GENERIC_READ)
        || granted.bits() & FILE_READ_EA != 0
}

/// NT5 references an EA-update File with `FILE_WRITE_EA` access.
pub fn set_ea_access_granted(granted: AccessMask) -> bool {
    granted.contains(AccessMask::GENERIC_ALL)
        || granted.contains(AccessMask::GENERIC_WRITE)
        || granted.bits() & FILE_WRITE_EA != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(next: u32, name: &[u8], value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.push(0);
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend_from_slice(value);
        bytes
    }

    fn get_entry(next: u32, name: &[u8]) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes
    }

    #[test]
    fn validates_get_ea_name_chains_and_reports_offsets() {
        let mut bytes = get_entry(8, b"a");
        bytes.resize(8, 0);
        bytes.extend_from_slice(&get_entry(0, b"author"));
        assert_eq!(validate_get_ea_buffer(&bytes), Ok(()));

        bytes[8..12].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            validate_get_ea_buffer(&bytes),
            Err(EaValidationError { offset: 8 })
        );
    }

    #[test]
    fn accepts_one_entry_and_trailing_storage() {
        let mut bytes = entry(0, b"author", b"reactos");
        bytes.extend_from_slice(&[0xaa; 7]);
        assert_eq!(validate_ea_buffer(&bytes), Ok(()));
    }

    #[test]
    fn accepts_exact_aligned_chain() {
        let mut first = entry(12, b"a", b"x");
        first.resize(12, 0);
        first.extend_from_slice(&entry(0, b"second", b"value"));
        assert_eq!(validate_ea_buffer(&first), Ok(()));
    }

    #[test]
    fn reports_the_malformed_record_offset() {
        let mut first = entry(12, b"a", b"x");
        first.resize(12, 0);
        let mut second = entry(0, b"bad", b"value");
        second[8 + 3] = b'!';
        first.extend_from_slice(&second);
        assert_eq!(
            validate_ea_buffer(&first),
            Err(EaValidationError { offset: 12 })
        );
    }

    #[test]
    fn rejects_short_records_and_noncanonical_offsets() {
        assert_eq!(
            validate_ea_buffer(&[0; 7]),
            Err(EaValidationError { offset: 0 })
        );
        let bytes = entry(16, b"a", b"x");
        assert_eq!(
            validate_ea_buffer(&bytes),
            Err(EaValidationError { offset: 0 })
        );
    }

    #[test]
    fn ea_access_contracts_use_file_specific_rights() {
        assert!(query_ea_access_granted(AccessMask::from_bits_retain(
            FILE_READ_EA
        )));
        assert!(query_ea_access_granted(AccessMask::GENERIC_READ));
        assert!(!query_ea_access_granted(AccessMask::GENERIC_WRITE));
        assert!(set_ea_access_granted(AccessMask::from_bits_retain(
            FILE_WRITE_EA
        )));
        assert!(set_ea_access_granted(AccessMask::GENERIC_WRITE));
        assert!(!set_ea_access_granted(AccessMask::GENERIC_READ));
    }
}
