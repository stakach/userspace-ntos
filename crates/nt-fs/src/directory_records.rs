//! Walk the NextEntryOffset chain of an encoded FILE_*_INFORMATION directory buffer.

/// Count the records in the first `information` bytes of a directory query output. The reader
/// returns the NextEntryOffset stored at a record offset. A malformed chain (unaligned, empty or
/// beyond `information`) or a failed read is `None`, never a partial count.
pub fn directory_record_count(
    information: usize,
    mut next_entry_offset: impl FnMut(usize) -> Option<u32>,
) -> Option<usize> {
    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < information {
        count += 1;
        let next = next_entry_offset(offset)? as usize;
        if next == 0 {
            return Some(count);
        }
        if next % 8 != 0 {
            return None;
        }
        offset = offset.checked_add(next)?;
    }
    // Information was nonzero but the chain left it without a terminal record.
    (information == 0).then_some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn reader(bytes: &[u8]) -> impl FnMut(usize) -> Option<u32> + '_ {
        |offset| bytes.get(offset..offset + 4).map(|field| u32::from_le_bytes(field.try_into().unwrap()))
    }

    #[test]
    fn counts_the_encoder_chain_exactly() {
        let mut state = crate::DirectoryQueryState::new();
        let mut entries = vec![];
        for name in [".", "..", "arial.ttf", "tahoma.ttf"] {
            let mut entry = crate::DirectoryEntry::default();
            assert!(entry.set_name(&name.encode_utf16().collect::<alloc::vec::Vec<_>>()));
            entries.push(entry);
        }
        let mut output = vec![0u8; 1024];
        let result = crate::query_directory(&mut state, &entries,
            crate::FILE_DIRECTORY_INFORMATION, false, None, true, &mut output);
        assert_eq!(result.status, 0);
        assert_eq!(directory_record_count(result.information, reader(&output)), Some(4));
        assert_eq!(directory_record_count(0, reader(&output)), Some(0), "an empty result has no records");
    }

    #[test]
    fn malformed_or_unreadable_chains_have_no_count() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&12u32.to_le_bytes());
        assert_eq!(directory_record_count(64, reader(&bytes)), None, "unaligned NextEntryOffset");
        bytes[0..4].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(directory_record_count(64, reader(&bytes)), None, "a record beyond Information");
        assert_eq!(directory_record_count(64, |_| None), None, "a failed read is not zero records");
        bytes[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(directory_record_count(64, reader(&bytes)), Some(1));
    }
}
