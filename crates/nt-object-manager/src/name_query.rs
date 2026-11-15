//! `ObjectNameInformation` as `ObQueryNameString` answers it from the object header.

use nt_status::NtStatus;

/// x64 `OBJECT_NAME_INFORMATION`: one `UNICODE_STRING` header, the name follows it.
pub const OBJECT_NAME_INFORMATION_BYTES: usize = 16;

/// The namespace path `ObQueryNameString` reports for an object of type `type_name` whose
/// header name is `namespace_path`; an unnamed object has the empty path.
///
/// A File is named by its type's QueryName procedure (`IopQueryNameFile`: the device name
/// followed by the filesystem's FileNameInformation), never by its header. A caller that can
/// only read the header has no name to report for one, and the empty string is not that name.
pub fn header_object_name<'a>(
    type_name: &[u8],
    namespace_path: &'a [u8],
) -> Result<&'a [u8], NtStatus> {
    if type_name == b"File" {
        return Err(NtStatus::NOT_SUPPORTED);
    }
    Ok(namespace_path)
}

/// `OBJECT_BASIC_INFORMATION.NameInfoSize` (`ObpQueryNameInfoSize`): what the object header's
/// name needs, and zero for an object the header does not name. A File or a Key has no header
/// name; its `ObjectNameInformation` comes from its type's QueryName procedure.
pub fn basic_name_info_size(header_name: &[u8]) -> u32 {
    if header_name.is_empty() {
        0
    } else {
        object_name_information_bytes(header_name) as u32
    }
}

/// The name `CmpQueryKeyName` reports for a key whose canonical (case-folded) path is
/// `canonical`. The namespace's own components are spelled as the Configuration Manager
/// creates them, `\REGISTRY\MACHINE` and `\REGISTRY\USER`; `None` for a path outside
/// `\REGISTRY`.
pub fn key_object_name(canonical: &str) -> Option<alloc::string::String> {
    let mut components = canonical.split('\\').filter(|component| !component.is_empty());
    if !components.next()?.eq_ignore_ascii_case("registry") {
        return None;
    }
    let mut name = alloc::string::String::new();
    name.try_reserve(canonical.len() + 1).ok()?;
    name.push_str("\\REGISTRY");
    for (depth, component) in components.enumerate() {
        name.push('\\');
        if depth == 0 && component.eq_ignore_ascii_case("machine") {
            name.push_str("MACHINE");
        } else if depth == 0 && component.eq_ignore_ascii_case("user") {
            name.push_str("USER");
        } else {
            name.push_str(component);
        }
    }
    Some(name)
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

/// The whole record for a name that need not be ASCII, as the caller will see it at
/// `information`. `None` when the name does not fit a `UNICODE_STRING` or memory is short.
pub fn encode_object_name_information(name: &str, information: u64) -> Option<alloc::vec::Vec<u8>> {
    let mut record = alloc::vec::Vec::new();
    if name.is_empty() {
        record.try_reserve_exact(OBJECT_NAME_INFORMATION_BYTES).ok()?;
        record.resize(OBJECT_NAME_INFORMATION_BYTES, 0);
        return Some(record);
    }
    let units = name.encode_utf16().count();
    let name_bytes = u16::try_from(units.checked_mul(2)?).ok()?;
    let maximum = name_bytes.checked_add(2)?;
    let buffer = information.checked_add(OBJECT_NAME_INFORMATION_BYTES as u64)?;
    record
        .try_reserve_exact(OBJECT_NAME_INFORMATION_BYTES + usize::from(maximum))
        .ok()?;
    record.extend_from_slice(&name_bytes.to_le_bytes());
    record.extend_from_slice(&maximum.to_le_bytes());
    record.extend_from_slice(&[0; 4]);
    record.extend_from_slice(&buffer.to_le_bytes());
    for unit in name.encode_utf16() {
        record.extend_from_slice(&unit.to_le_bytes());
    }
    record.extend_from_slice(&[0, 0]);
    Some(record)
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

    /// kernel32 `GetFinalPathNameByHandleW` reads `Name.Buffer[8..]` after a successful query
    /// on a File handle; an empty header name returned as success is a NULL `Buffer` there.
    #[test]
    fn file_is_not_named_by_its_object_header() {
        assert_eq!(
            header_object_name(b"File", b""),
            Err(NtStatus::NOT_SUPPORTED)
        );
        assert_eq!(
            header_object_name(b"File", b"\\Device\\x"),
            Err(NtStatus::NOT_SUPPORTED)
        );
    }

    #[test]
    fn basic_information_sizes_only_a_header_name() {
        assert_eq!(basic_name_info_size(b""), 0);
        assert_eq!(basic_name_info_size(b"\\BaseNamedObjects\\x"), 16 + 19 * 2 + 2);
    }

    #[test]
    fn key_is_named_by_its_full_registry_path() {
        assert_eq!(
            key_object_name("\\registry\\machine\\software\\classes").as_deref(),
            Some("\\REGISTRY\\MACHINE\\software\\classes")
        );
        assert_eq!(
            key_object_name("\\registry\\user\\s-1-5-18").as_deref(),
            Some("\\REGISTRY\\USER\\s-1-5-18")
        );
        assert_eq!(key_object_name("\\Registry\\Machine").as_deref(), Some("\\REGISTRY\\MACHINE"));
        assert_eq!(key_object_name("\\registry").as_deref(), Some("\\REGISTRY"));
        // A hive mounted under another root keeps the name it was linked at.
        assert_eq!(
            key_object_name("\\registry\\a\\b").as_deref(),
            Some("\\REGISTRY\\a\\b")
        );
        assert_eq!(key_object_name("\\registryx\\machine"), None);
        assert_eq!(key_object_name("\\device\\x"), None);
        assert_eq!(key_object_name(""), None);
    }

    #[test]
    fn a_name_outside_ascii_is_encoded_as_utf16() {
        let record = encode_object_name_information("\\REGISTRY\\USER\\\u{e9}t\u{e9}", 0x9000).unwrap();
        let units = 15 + 3;
        assert_eq!(record.len(), 16 + units * 2 + 2);
        assert_eq!(u16::from_le_bytes([record[0], record[1]]) as usize, units * 2);
        assert_eq!(u16::from_le_bytes([record[2], record[3]]) as usize, units * 2 + 2);
        assert_eq!(u64::from_le_bytes(record[8..16].try_into().unwrap()), 0x9010);
        assert_eq!(&record[16 + 15 * 2..16 + 16 * 2], &0xe9u16.to_le_bytes());
        assert_eq!(&record[record.len() - 2..], &[0, 0]);
        // The same bytes as the ASCII encoder where both apply.
        let mut ascii = [0u8; 64];
        let used = write_object_name_information(b"\\a\\b", 0x9000, &mut ascii).unwrap();
        assert_eq!(encode_object_name_information("\\a\\b", 0x9000).unwrap(), &ascii[..used]);
        assert_eq!(encode_object_name_information("", 0x9000).unwrap(), [0u8; 16]);
        let long: alloc::string::String = core::iter::repeat('x').take(0x8000).collect();
        assert_eq!(encode_object_name_information(&long, 0x9000), None);
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
