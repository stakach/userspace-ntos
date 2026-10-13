//! Bounded native `KEY_VALUE_INFORMATION` copyout shared by registry transports.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyStatus {
    Success,
    BufferOverflow,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyResult {
    pub required_length: u32,
    pub status: CopyStatus,
}

/// `minimum_length` is the fixed header for the selected information class. The full encoded
/// record is returned in `required_length`, even when only a prefix fits the caller's buffer.
pub fn copy_value_information(
    encoded: &[u8],
    minimum_length: usize,
    output: &mut [u8],
) -> Option<CopyResult> {
    let required_length = u32::try_from(encoded.len()).ok()?;
    if minimum_length > encoded.len() {
        return None;
    }
    let status = if output.len() < minimum_length {
        CopyStatus::BufferTooSmall
    } else {
        let count = output.len().min(encoded.len());
        output[..count].copy_from_slice(&encoded[..count]);
        if count < encoded.len() {
            CopyStatus::BufferOverflow
        } else {
            CopyStatus::Success
        }
    };
    Some(CopyResult {
        required_length,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ReactOS kbdclass/mouclass enumerate DEVICEMAP port names with KeyValueBasicInformation.
    // Its fixed header is 12 bytes; both drivers pass the returned NameLength and Name onward.
    #[test]
    fn class_port_basic_information_preserves_utf16_name_and_buffer_status() {
        let mut encoded = [0u8; 54];
        encoded[4..8].copy_from_slice(&1u32.to_le_bytes());
        encoded[8..12].copy_from_slice(&42u32.to_le_bytes());
        for (index, unit) in "\\Device\\KeyboardPort0".encode_utf16().enumerate() {
            encoded[12 + index * 2..14 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        let mut short = [0xa5u8; 11];
        assert_eq!(
            copy_value_information(&encoded, 12, &mut short),
            Some(CopyResult {
                required_length: 54,
                status: CopyStatus::BufferTooSmall,
            })
        );
        assert_eq!(short, [0xa5; 11]);
        let mut partial = [0u8; 20];
        assert_eq!(
            copy_value_information(&encoded, 12, &mut partial),
            Some(CopyResult {
                required_length: 54,
                status: CopyStatus::BufferOverflow,
            })
        );
        assert_eq!(&partial, &encoded[..20]);
        let mut full = [0u8; 54];
        assert_eq!(
            copy_value_information(&encoded, 12, &mut full),
            Some(CopyResult {
                required_length: 54,
                status: CopyStatus::Success,
            })
        );
        assert_eq!(u32::from_le_bytes(full[8..12].try_into().unwrap()), 42);
        assert_eq!(&full[12..], &encoded[12..]);
    }
}
