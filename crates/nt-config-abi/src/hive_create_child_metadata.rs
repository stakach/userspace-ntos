//! Two LE u32 lengths, UTF-16LE class bytes, then assigned security descriptor bytes.

pub const HEADER_BYTES: usize = 8;

pub fn header(class_len: u32, descriptor_len: u32) -> [u8; HEADER_BYTES] {
    let mut result = [0u8; HEADER_BYTES];
    result[..4].copy_from_slice(&class_len.to_le_bytes());
    result[4..].copy_from_slice(&descriptor_len.to_le_bytes());
    result
}

/// Validate framing, not class text or native security semantics.
pub fn split(data: &[u8], class_present: bool) -> Option<(&[u8], &[u8])> {
    let class_len = u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize;
    let descriptor_len = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    if class_len % 2 != 0 || (!class_present && class_len != 0) || descriptor_len == 0 {
        return None;
    }
    let class_end = HEADER_BYTES.checked_add(class_len)?;
    if class_end.checked_add(descriptor_len)? != data.len() {
        return None;
    }
    Some((data.get(HEADER_BYTES..class_end)?, data.get(class_end..)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_framing_preserves_explicit_empty_class() {
        let data = [0, 0, 0, 0, 1, 0, 0, 0, 42];
        assert_eq!(header(0, 1), data[..8]);
        for present in [true, false] {
            assert_eq!(split(&data, present), Some((&[][..], &[42][..])));
        }
        for end in 0..data.len() {
            assert!(split(&data[..end], true).is_none());
        }
        let data = [2, 0, 0, 0, 1, 0, 0, 0, 65, 0, 42];
        assert!(split(&data, false).is_none());
        assert_eq!(split(&data, true), Some((&[65, 0][..], &[42][..])));
        assert!(split(&[1, 0, 0, 0, 1, 0, 0, 0, 65, 42], true).is_none());
        assert!(split(&header(0, 0), true).is_none());
    }
}
