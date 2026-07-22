//! Pure policy for Image File Execution Options loader queries.

use crate::NtStatus;

pub const REG_SZ: u32 = 1;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC000_0004;
pub const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005;
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = 0xC000_0024;

const PARTIAL_INFORMATION_DATA_OFFSET: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageFileOptionOutput<'a> {
    Bytes(&'a [u8]),
    Dword(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFileOptionQuery<'a> {
    pub status: NtStatus,
    pub returned_length: Option<u32>,
    pub output: Option<ImageFileOptionOutput<'a>>,
}

impl ImageFileOptionQuery<'_> {
    fn without_output(status: NtStatus, returned_length: Option<u32>) -> Self {
        Self {
            status,
            returned_length,
            output: None,
        }
    }
}

/// Return the final backslash-delimited component of a counted image path.
pub fn image_file_options_subkey(path: &[u16]) -> &[u16] {
    match path.iter().rposition(|unit| *unit == b'\\' as u16) {
        Some(separator) => &path[separator + 1..],
        None => path,
    }
}

fn unicode_le_string_to_integer(data: &[u8]) -> u32 {
    let units = data.len() / 2;
    let unit = |index: usize| {
        let offset = index * 2;
        u16::from_le_bytes([data[offset], data[offset + 1]])
    };
    let mut index = 0usize;
    while index < units && unit(index) <= b' ' as u16 {
        index += 1;
    }
    let negative = if index < units && unit(index) == b'+' as u16 {
        index += 1;
        false
    } else if index < units && unit(index) == b'-' as u16 {
        index += 1;
        true
    } else {
        false
    };
    let mut base = 10u32;
    if index + 1 < units && unit(index) == b'0' as u16 {
        base = match unit(index + 1) {
            c if c == b'b' as u16 => 2,
            c if c == b'o' as u16 => 8,
            c if c == b'x' as u16 => 16,
            _ => 10,
        };
        if base != 10 {
            index += 2;
        }
    }
    let mut value = 0u32;
    while index < units {
        let digit = match unit(index) {
            0x30..=0x39 => (unit(index) - 0x30) as u32,
            0x41..=0x5a => (unit(index) - 0x41 + 10) as u32,
            0x61..=0x7a => (unit(index) - 0x61 + 10) as u32,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value.wrapping_mul(base).wrapping_add(digit);
        index += 1;
    }
    if negative {
        0u32.wrapping_sub(value)
    } else {
        value
    }
}

/// Plan the copy/conversion performed by ReactOS `LdrQueryImageFileKeyOption`.
///
/// `partial` is a `KEY_VALUE_PARTIAL_INFORMATION` returned by the kernel. Keeping pointer writes
/// out of this function makes every type, length, and truncation rule host-testable.
pub fn plan_key_option(
    partial: &[u8],
    requested_type: u32,
    buffer_present: bool,
    buffer_size: u32,
) -> ImageFileOptionQuery<'_> {
    if partial.len() < PARTIAL_INFORMATION_DATA_OFFSET {
        return ImageFileOptionQuery::without_output(STATUS_INFO_LENGTH_MISMATCH, None);
    }
    let actual_type = u32::from_le_bytes(partial[4..8].try_into().unwrap());
    let data_length = u32::from_le_bytes(partial[8..12].try_into().unwrap());
    let Some(data_end) = PARTIAL_INFORMATION_DATA_OFFSET.checked_add(data_length as usize) else {
        return ImageFileOptionQuery::without_output(STATUS_INFO_LENGTH_MISMATCH, None);
    };
    if data_end > partial.len() {
        return ImageFileOptionQuery::without_output(STATUS_INFO_LENGTH_MISMATCH, None);
    }
    let data = &partial[PARTIAL_INFORMATION_DATA_OFFSET..data_end];

    match actual_type {
        REG_BINARY => {
            if buffer_present && data_length <= buffer_size {
                ImageFileOptionQuery {
                    status: STATUS_SUCCESS,
                    returned_length: Some(data_length),
                    output: Some(ImageFileOptionOutput::Bytes(data)),
                }
            } else {
                ImageFileOptionQuery::without_output(STATUS_BUFFER_OVERFLOW, Some(data_length))
            }
        }
        REG_DWORD => {
            if requested_type != REG_DWORD {
                return ImageFileOptionQuery::without_output(STATUS_OBJECT_TYPE_MISMATCH, None);
            }
            if !buffer_present || buffer_size != 4 || data_length > 4 {
                ImageFileOptionQuery::without_output(STATUS_BUFFER_OVERFLOW, Some(data_length))
            } else {
                ImageFileOptionQuery {
                    status: STATUS_SUCCESS,
                    returned_length: Some(data_length),
                    output: Some(ImageFileOptionOutput::Bytes(data)),
                }
            }
        }
        REG_SZ if requested_type == REG_DWORD => {
            if buffer_size != 4 {
                return ImageFileOptionQuery::without_output(
                    STATUS_INFO_LENGTH_MISMATCH,
                    Some(data_length),
                );
            }
            if !buffer_present || data.len() < 2 || data.len() & 1 != 0 {
                return ImageFileOptionQuery::without_output(
                    STATUS_INFO_LENGTH_MISMATCH,
                    Some(data_length),
                );
            }
            let value = unicode_le_string_to_integer(&data[..data.len() - 2]);
            ImageFileOptionQuery {
                status: STATUS_SUCCESS,
                returned_length: Some(data_length),
                output: Some(ImageFileOptionOutput::Dword(value)),
            }
        }
        REG_SZ => {
            if !buffer_present && buffer_size != 0 {
                return ImageFileOptionQuery::without_output(
                    STATUS_BUFFER_OVERFLOW,
                    Some(data_length),
                );
            }
            let copied = data_length.min(buffer_size) as usize;
            ImageFileOptionQuery {
                status: if data_length > buffer_size {
                    STATUS_BUFFER_OVERFLOW
                } else {
                    STATUS_SUCCESS
                },
                returned_length: Some(data_length),
                output: Some(ImageFileOptionOutput::Bytes(&data[..copied])),
            }
        }
        _ => ImageFileOptionQuery::without_output(STATUS_OBJECT_TYPE_MISMATCH, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn partial(value_type: u32, data: &[u8]) -> Vec<u8> {
        let mut value = vec![0u8; PARTIAL_INFORMATION_DATA_OFFSET];
        value[4..8].copy_from_slice(&value_type.to_le_bytes());
        value[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        value.extend_from_slice(data);
        value
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn wide_bytes(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .chain(core::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn extracts_counted_backslash_basename() {
        assert_eq!(
            image_file_options_subkey(&wide(r"C:\ReactOS\smss.exe")),
            wide("smss.exe")
        );
        assert_eq!(
            image_file_options_subkey(&wide("winlogon.exe")),
            wide("winlogon.exe")
        );
        assert!(image_file_options_subkey(&wide("C:\\")).is_empty());
        assert_eq!(
            image_file_options_subkey(&wide("C:/bin/app.exe")),
            wide("C:/bin/app.exe")
        );
    }

    #[test]
    fn rejects_malformed_partial_information() {
        assert_eq!(
            plan_key_option(&[0; 11], REG_BINARY, true, 4).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        let mut value = partial(REG_BINARY, &[1, 2]);
        value[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            plan_key_option(&value, REG_BINARY, true, 4).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        let mut padded = partial(REG_BINARY, &[1, 2]);
        padded.extend_from_slice(&[9, 9]);
        assert_eq!(
            plan_key_option(&padded, REG_BINARY, true, 2).output,
            Some(ImageFileOptionOutput::Bytes(&[1, 2]))
        );
    }

    #[test]
    fn binary_ignores_requested_type_but_requires_full_capacity() {
        let value = partial(REG_BINARY, &[1, 2, 3]);
        assert_eq!(
            plan_key_option(&value, REG_SZ, true, 3),
            ImageFileOptionQuery {
                status: STATUS_SUCCESS,
                returned_length: Some(3),
                output: Some(ImageFileOptionOutput::Bytes(&[1, 2, 3])),
            }
        );
        let short = plan_key_option(&value, REG_BINARY, true, 2);
        assert_eq!(short.status, STATUS_BUFFER_OVERFLOW);
        assert_eq!(short.returned_length, Some(3));
        assert_eq!(short.output, None);
        assert_eq!(
            plan_key_option(&value, REG_BINARY, false, 3).status,
            STATUS_BUFFER_OVERFLOW
        );
    }

    #[test]
    fn dword_requires_matching_type_and_exact_destination_size() {
        let value = partial(REG_DWORD, &42u32.to_le_bytes());
        assert_eq!(
            plan_key_option(&value, REG_DWORD, true, 4).output,
            Some(ImageFileOptionOutput::Bytes(&42u32.to_le_bytes()))
        );
        for size in [0, 3, 8] {
            assert_eq!(
                plan_key_option(&value, REG_DWORD, true, size).status,
                STATUS_BUFFER_OVERFLOW
            );
        }
        let mismatch = plan_key_option(&value, REG_SZ, true, 4);
        assert_eq!(mismatch.status, STATUS_OBJECT_TYPE_MISMATCH);
        assert_eq!(mismatch.returned_length, None);
    }

    #[test]
    fn string_copy_includes_nul_and_truncates_on_overflow() {
        let data = wide_bytes("debugger.exe");
        let value = partial(REG_SZ, &data);
        assert_eq!(
            plan_key_option(&value, REG_SZ, true, data.len() as u32).output,
            Some(ImageFileOptionOutput::Bytes(&data))
        );
        let short = plan_key_option(&value, REG_SZ, true, 6);
        assert_eq!(short.status, STATUS_BUFFER_OVERFLOW);
        assert_eq!(short.returned_length, Some(data.len() as u32));
        assert_eq!(short.output, Some(ImageFileOptionOutput::Bytes(&data[..6])));
    }

    #[test]
    fn converts_string_dword_with_native_prefix_and_sign_rules() {
        for (text, expected) in [("42", 42), ("0x2a", 42), ("0b101", 5), ("-1", u32::MAX)] {
            let value = partial(REG_SZ, &wide_bytes(text));
            assert_eq!(
                plan_key_option(&value, REG_DWORD, true, 4).output,
                Some(ImageFileOptionOutput::Dword(expected))
            );
        }
        let value = partial(REG_SZ, &wide_bytes("42"));
        let wrong_size = plan_key_option(&value, REG_DWORD, true, 8);
        assert_eq!(wrong_size.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(wrong_size.returned_length, Some(6));
        assert_eq!(
            plan_key_option(&partial(REG_SZ, &[0]), REG_DWORD, true, 4).status,
            STATUS_INFO_LENGTH_MISMATCH
        );
    }

    #[test]
    fn unknown_registry_type_is_a_type_mismatch_without_length() {
        let value = partial(7, &[0]);
        let result = plan_key_option(&value, 7, true, 1);
        assert_eq!(result.status, STATUS_OBJECT_TYPE_MISMATCH);
        assert_eq!(result.returned_length, None);
    }
}
