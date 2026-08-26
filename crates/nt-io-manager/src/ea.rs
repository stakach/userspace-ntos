//! Extended-attribute capture validation shared by native file creates and I/O providers.

/// The byte offset of the first malformed `FILE_FULL_EA_INFORMATION` record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EaValidationError {
    pub offset: usize,
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
}
