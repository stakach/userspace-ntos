//! Pure `Rtl*` memory helpers.

/// `RtlCompareMemoryUlong`: compare complete ULONG slots against `value` and return the number of
/// equal leading bytes. ReactOS ignores a trailing partial ULONG.
pub fn compare_memory_ulong(source: &[u8], value: u32) -> usize {
    let mut matched = 0usize;
    for chunk in source.chunks_exact(4) {
        let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if word != value {
            break;
        }
        matched += 4;
    }
    matched
}

/// Copy mapped memory for valid, already-mapped buffers. The SEH/in-page-error distinction lives at
/// the raw ntdll wrapper; this pure helper covers the successful copy path.
pub fn copy_mapped_memory(destination: &mut [u8], source: &[u8]) -> bool {
    if destination.len() < source.len() {
        return false;
    }
    destination[..source.len()].copy_from_slice(source);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_memory_ulong_counts_equal_complete_words() {
        let bytes = [
            0x44, 0x33, 0x22, 0x11, 0x44, 0x33, 0x22, 0x11, 0x99, 0x33, 0x22, 0x11,
        ];
        assert_eq!(compare_memory_ulong(&bytes, 0x1122_3344), 8);
    }

    #[test]
    fn compare_memory_ulong_ignores_trailing_partial_word() {
        let bytes = [0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE];
        assert_eq!(compare_memory_ulong(&bytes, 0xDEAD_BEEF), 4);
    }

    #[test]
    fn copy_mapped_memory_copies_success_path() {
        let mut out = [0u8; 5];
        assert!(copy_mapped_memory(&mut out, b"hello"));
        assert_eq!(&out, b"hello");

        let mut short = [0u8; 2];
        assert!(!copy_mapped_memory(&mut short, b"hello"));
    }
}
