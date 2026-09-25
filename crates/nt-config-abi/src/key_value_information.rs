//! Native KEY_VALUE_FULL_INFORMATION layout for hosted registry callers.

pub const FULL_INFORMATION_CLASS: u32 = 1;
const HEADER_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullValueLayout {
    pub data_offset: usize,
    pub required_length: usize,
}

impl FullValueLayout {
    pub fn for_ascii_name(name: &[u8], data: &[u8]) -> Option<Self> {
        let name_end = HEADER_BYTES.checked_add(name.len().checked_mul(2)?)?;
        let data_offset = name_end.checked_add(3)? & !3;
        let required_length = data_offset.checked_add(data.len())?;
        u32::try_from(name.len().checked_mul(2)?).ok()?;
        u32::try_from(data.len()).ok()?;
        u32::try_from(data_offset).ok()?;
        u32::try_from(required_length).ok()?;
        Some(Self { data_offset, required_length })
    }

    pub fn encode_ascii(self, name: &[u8], value_type: u32, data: &[u8], out: &mut [u8]) -> bool {
        if Self::for_ascii_name(name, data) != Some(self) || out.len() < self.required_length {
            return false;
        }
        out[..self.required_length].fill(0);
        out[4..8].copy_from_slice(&value_type.to_le_bytes());
        out[8..12].copy_from_slice(&(self.data_offset as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
        out[16..20].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        for (index, byte) in name.iter().enumerate() {
            out[HEADER_BYTES + index * 2] = *byte;
        }
        out[self.data_offset..self.required_length].copy_from_slice(data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_information_has_aligned_data_and_utf16_name() {
        let name = b"ProviderOrder";
        let data = b"LanmanWorkstation\0";
        let layout = FullValueLayout::for_ascii_name(name, data).unwrap();
        assert_eq!(layout.data_offset, 48);
        let mut bytes = [0u8; 80];
        assert!(layout.encode_ascii(name, 1, data, &mut bytes));
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 48);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), data.len() as u32);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 26);
        assert_eq!(&bytes[20..24], &[b'P', 0, b'r', 0]);
        assert_eq!(&bytes[48..48 + data.len()], data);
        assert!(!layout.encode_ascii(name, 1, data, &mut bytes[..layout.required_length - 1]));
    }

    #[test]
    fn full_information_accepts_empty_and_single_byte_values() {
        assert!(FullValueLayout::for_ascii_name(b"", b"").is_some());
        assert!(FullValueLayout::for_ascii_name(b"a", b"b").is_some());
    }
}
