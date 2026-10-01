//! Bounded capture of the x64 `UNICODE_STRING` passed to `ZwLoadDriver`.
//!
//! The caller of this module must copy the header and buffer from the same authenticated address
//! space. It may do so in two reads, but must retain the source thread while capturing them.

use alloc::string::String;

pub const DRIVER_SERVICE_PATH_MAX_BYTES: usize = 1024;

const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
const STATUS_OBJECT_PATH_SYNTAX_BAD: i32 = 0xC000_003Bu32 as i32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverServiceNameBuffer {
    pub address: u64,
    pub byte_length: usize,
}

/// Inspect the fixed x64 structure before copying the variable-length string. A null structure
/// pointer is handled by the native caller, which cannot obtain this header in that case.
pub fn inspect_driver_service_name(header: &[u8; 16]) -> Result<DriverServiceNameBuffer, i32> {
    let byte_length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let maximum_length = u16::from_le_bytes([header[2], header[3]]) as usize;
    let address = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if byte_length == 0 || address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if byte_length & 1 != 0 || byte_length > maximum_length {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if byte_length > DRIVER_SERVICE_PATH_MAX_BYTES {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    if address.checked_add(byte_length as u64).is_none() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(DriverServiceNameBuffer {
        address,
        byte_length,
    })
}

/// Finish the capture from exactly the inspected byte extent. CM performs the authoritative
/// active-service path resolution; this stage only validates the NT string representation.
pub fn decode_driver_service_name(
    descriptor: DriverServiceNameBuffer,
    copied: &[u8],
) -> Result<String, i32> {
    if copied.len() != descriptor.byte_length
        || copied.len() > DRIVER_SERVICE_PATH_MAX_BYTES
        || copied.len() & 1 != 0
    {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut units = [0u16; DRIVER_SERVICE_PATH_MAX_BYTES / 2];
    for (index, pair) in copied.chunks_exact(2).enumerate() {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        units[index] = unit;
    }
    String::from_utf16(&units[..copied.len() / 2]).map_err(|_| STATUS_OBJECT_NAME_INVALID)
}

/// Capture once from one authenticated address space. The reader must reject unmapped or
/// differently owned bytes rather than filling them from a process-independent fallback.
pub fn capture_driver_service_name(
    structure_address: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<String, i32> {
    if structure_address == 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut header = [0u8; 16];
    if !read(structure_address, &mut header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let descriptor = inspect_driver_service_name(&header)?;
    let mut bytes = [0u8; DRIVER_SERVICE_PATH_MAX_BYTES];
    let copied = &mut bytes[..descriptor.byte_length];
    if !read(descriptor.address, copied) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    decode_driver_service_name(descriptor, copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn request(path: &str) -> ([u8; 16], Vec<u8>) {
        let mut bytes = Vec::new();
        for unit in path.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let mut header = [0u8; 16];
        header[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        header[2..4].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        header[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        (header, bytes)
    }

    #[test]
    fn captures_fs_rec_service_key_without_changing_identity() {
        let path = r"\Registry\Machine\System\CurrentControlSet\Services\Fastfat";
        let (header, bytes) = request(path);
        let descriptor = inspect_driver_service_name(&header).unwrap();
        assert_eq!(descriptor.byte_length, bytes.len());
        assert_eq!(
            decode_driver_service_name(descriptor, &bytes).unwrap(),
            path
        );
    }

    #[test]
    fn rejects_odd_oversized_null_and_wrapping_extents() {
        let (mut header, bytes) = request("driver");
        header[0] |= 1;
        assert_eq!(
            inspect_driver_service_name(&header),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        header[0] &= !1;
        header[2..4].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            inspect_driver_service_name(&header),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        header[0..2].copy_from_slice(&1026u16.to_le_bytes());
        header[2..4].copy_from_slice(&1026u16.to_le_bytes());
        assert_eq!(
            inspect_driver_service_name(&header),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        header[0..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        header[2..4].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        header[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            inspect_driver_service_name(&header),
            Err(STATUS_ACCESS_VIOLATION)
        );
        header[8..16].fill(0);
        assert_eq!(
            inspect_driver_service_name(&header),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn rejects_short_copy_embedded_null_and_invalid_utf16() {
        let (header, mut bytes) = request("driver");
        let descriptor = inspect_driver_service_name(&header).unwrap();
        assert_eq!(
            decode_driver_service_name(descriptor, &bytes[..2]),
            Err(STATUS_ACCESS_VIOLATION)
        );
        bytes[2..4].fill(0);
        assert_eq!(
            decode_driver_service_name(descriptor, &bytes),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        bytes[2..4].copy_from_slice(&0xD800u16.to_le_bytes());
        assert_eq!(
            decode_driver_service_name(descriptor, &bytes),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
    }

    #[test]
    fn reader_capture_uses_two_exact_bounded_reads_and_rejects_missing_pages() {
        let path = r"\Registry\Machine\System\CurrentControlSet\Services\Fastfat";
        let (header, bytes) = request(path);
        let mut reads = 0;
        let value = capture_driver_service_name(0x2000, |address, output| {
            reads += 1;
            match address {
                0x2000 if output.len() == 16 => output.copy_from_slice(&header),
                0x1000 if output.len() == bytes.len() => output.copy_from_slice(&bytes),
                _ => return false,
            }
            true
        });
        assert_eq!(value.as_deref(), Ok(path));
        assert_eq!(reads, 2);
        assert_eq!(
            capture_driver_service_name(0x2000, |address, output| {
                if address == 0x2000 {
                    output.copy_from_slice(&header);
                    true
                } else {
                    false
                }
            }),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}
