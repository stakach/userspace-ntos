//! Case-preserving decoding of explicitly terminated REG_SZ metadata.

use alloc::{string::String, vec::Vec};

pub fn decode_terminated_reg_sz(value_type: u32, data: &[u8]) -> Option<String> {
    if value_type != 1 || data.len() < 2 || data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<_> = data.chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
    let (terminator, value) = units.split_last()?;
    if *terminator != 0 || value.contains(&0) { return None; }
    String::from_utf16(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: &str) -> Vec<u8> {
        value.encode_utf16().chain(core::iter::once(0))
            .flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn preserves_device_and_case_sensitive_export_identity() {
        for value in [r"\Device\SourceIrpProbe", "SourceIrpProbe", "caf\u{e9}"] {
            assert_eq!(decode_terminated_reg_sz(1, &encoded(value)).as_deref(), Some(value));
        }
    }

    #[test]
    fn rejects_wrong_type_unterminated_embedded_nul_and_invalid_utf16() {
        assert_eq!(decode_terminated_reg_sz(2, &encoded("Export")), None);
        for data in [alloc::vec![], alloc::vec![0], alloc::vec![65, 0],
            alloc::vec![0, 0, 65, 0, 0, 0], alloc::vec![0, 0xd8, 0, 0]] {
            assert_eq!(decode_terminated_reg_sz(1, &data), None);
        }
        assert_eq!(decode_terminated_reg_sz(1, &[0, 0]).as_deref(), Some(""));
    }
}
