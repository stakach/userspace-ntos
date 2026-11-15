//! `ObjectNameInformation` as `ObQueryNameString` answers it from the object header.

use nt_status::NtStatus;

/// x64 `OBJECT_NAME_INFORMATION`: one `UNICODE_STRING` header, the name follows it.
pub const OBJECT_NAME_INFORMATION_BYTES: usize = 16;

/// The namespace path `ObQueryNameString` reports for an object of type `type_name` whose
/// header name is `namespace_path`; an unnamed object has the empty path.
pub fn header_object_name<'a>(
    _type_name: &[u8],
    namespace_path: &'a [u8],
) -> Result<&'a [u8], NtStatus> {
    Ok(namespace_path)
}

/// Size of the record for `name`: an unnamed object is the bare header, a named one adds the
/// NUL-terminated UTF-16 name.
pub fn object_name_information_bytes(name: &[u8]) -> usize {
    if name.is_empty() {
        OBJECT_NAME_INFORMATION_BYTES
    } else {
        OBJECT_NAME_INFORMATION_BYTES + name.len() * 2 + 2
    }
}

/// Encode the record for the ASCII `name` into `output`, which the caller copies to the
/// destination address `information`. Returns the bytes used, or `None` when `output` is short
/// or the name does not fit a `UNICODE_STRING`.
pub fn write_object_name_information(
    name: &[u8],
    information: u64,
    output: &mut [u8],
) -> Option<usize> {
    let used = object_name_information_bytes(name);
    let record = output.get_mut(..used)?;
    record.fill(0);
    if name.is_empty() {
        return Some(used);
    }
    let name_bytes = u16::try_from(name.len() * 2).ok()?;
    let maximum = name_bytes.checked_add(2)?;
    let buffer = information.checked_add(OBJECT_NAME_INFORMATION_BYTES as u64)?;
    record[0..2].copy_from_slice(&name_bytes.to_le_bytes());
    record[2..4].copy_from_slice(&maximum.to_le_bytes());
    record[8..16].copy_from_slice(&buffer.to_le_bytes());
    for (unit, &byte) in record[OBJECT_NAME_INFORMATION_BYTES..]
        .chunks_exact_mut(2)
        .zip(name)
    {
        unit.copy_from_slice(&u16::from(byte).to_le_bytes());
    }
    Some(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_object_reports_its_namespace_path_after_the_header() {
        let name = header_object_name(b"Event", b"\\BaseNamedObjects\\x").unwrap();
        let mut output = [0xa5u8; 64];
        let used = write_object_name_information(name, 0x7000, &mut output).unwrap();
        assert_eq!(used, object_name_information_bytes(name));
        assert_eq!(used, 16 + 19 * 2 + 2);
        assert_eq!(u16::from_le_bytes([output[0], output[1]]), 38);
        assert_eq!(u16::from_le_bytes([output[2], output[3]]), 40);
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            0x7010
        );
        assert_eq!(&output[16..20], &[b'\\', 0, b'B', 0]);
        assert_eq!(&output[used - 2..used], &[0, 0]);
    }

    #[test]
    fn unnamed_object_reports_the_empty_string() {
        let name = header_object_name(b"Process", b"").unwrap();
        let mut output = [0xa5u8; 16];
        assert_eq!(
            write_object_name_information(name, 0x7000, &mut output),
            Some(16)
        );
        assert_eq!(output, [0; 16]);
    }

    #[test]
    fn short_output_publishes_nothing() {
        let mut output = [0xa5u8; 17];
        assert_eq!(
            write_object_name_information(b"\\a", 0x7000, &mut output),
            None
        );
        assert_eq!(output, [0xa5; 17]);
    }
}
