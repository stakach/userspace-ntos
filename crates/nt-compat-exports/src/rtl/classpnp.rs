//! Allocation-free RTL wire conversions shared by hosted storage drivers.
//!
//! Native trampolines own pointer validation and pool allocation. Keeping the
//! conversions here lets all driver classes use one implementation.

use super::NT_VERSION;

/// `RtlStringFromGUID` writes 38 visible UTF-16 units and one NUL (78 bytes).
pub const GUID_STRING_UNITS: usize = 39;
pub const GUID_STRING_LENGTH_BYTES: u16 = 76;
pub const GUID_STRING_CAPACITY_BYTES: u16 = 78;

/// Format a Windows GUID's 16-byte memory representation as `{8-4-4-4-12}`.
/// The first three fields are little-endian in memory; all hex is lowercase,
/// matching ReactOS `sdk/lib/rtl/unicode.c`'s `RtlStringFromGUID` format.
pub fn format_guid_utf16(guid: &[u8; 16]) -> [u16; GUID_STRING_UNITS] {
    let mut output = [0u16; GUID_STRING_UNITS];
    output[0] = b'{' as u16;
    output[9] = b'-' as u16;
    output[14] = b'-' as u16;
    output[19] = b'-' as u16;
    output[24] = b'-' as u16;
    output[37] = b'}' as u16;
    let ordered = [
        guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6],
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    ];
    let mut offset = 1;
    for byte in ordered {
        while matches!(offset, 9 | 14 | 19 | 24) {
            offset += 1;
        }
        output[offset] = lower_hex(byte >> 4);
        output[offset + 1] = lower_hex(byte & 0x0f);
        offset += 2;
    }
    output
}

fn lower_hex(nibble: u8) -> u16 {
    (if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 }) as u16
}

/// The only two layouts safely accepted by the native `RtlGetVersion` export.
pub const VERSION_INFO_BASE_BYTES: usize = 0x114;
pub const VERSION_INFO_EXTENDED_BYTES: usize = 0x11c;

/// Populate a sized `RTL_OSVERSIONINFO[EX]W` byte buffer in little-endian form.
/// Returns the number of bytes required, or `None` without modifying the buffer
/// when the declared size is unsupported or its backing storage is too short.
pub fn write_version_info(output: &mut [u8]) -> Option<usize> {
    let declared = u32::from_le_bytes(output.get(..4)?.try_into().ok()?) as usize;
    if !matches!(declared, VERSION_INFO_BASE_BYTES | VERSION_INFO_EXTENDED_BYTES)
        || output.len() < declared
    {
        return None;
    }
    output[4..8].copy_from_slice(&NT_VERSION.major.to_le_bytes());
    output[8..12].copy_from_slice(&NT_VERSION.minor.to_le_bytes());
    output[12..16].copy_from_slice(&NT_VERSION.build.to_le_bytes());
    output[16..20].copy_from_slice(&NT_VERSION.platform_id.to_le_bytes());
    if declared == VERSION_INFO_EXTENDED_BYTES {
        output[0x114..0x11a].fill(0);
        output[0x11a] = 1; // VER_NT_WORKSTATION
        output[0x11b] = 0;
    }
    Some(declared)
}
