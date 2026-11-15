//! File ObjectNameInformation from a named Device and live FileNameInformation.

pub const OBJECT_NAME_INFORMATION_HEADER_BYTES: usize = 16;
pub const FILE_NAME_INFORMATION_HEADER_BYTES: usize = 4;
pub const FILE_OBJECT_NAME_SCRATCH_BYTES: usize = 65_540;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileObjectNameError {
    InvalidDeviceName,
    InvalidFileName,
    InvalidFileInformation,
    NameTooLong,
    BufferTooSmall { required: usize },
}

/// Decode the filesystem's FileNameInformation without trusting its length field alone.
pub fn file_name_information_units(
    bytes: &[u8],
    information: u64,
) -> Result<&[u8], FileObjectNameError> {
    let used =
        usize::try_from(information).map_err(|_| FileObjectNameError::InvalidFileInformation)?;
    if used < FILE_NAME_INFORMATION_HEADER_BYTES || used > bytes.len() {
        return Err(FileObjectNameError::InvalidFileInformation);
    }
    let name_bytes = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let end = FILE_NAME_INFORMATION_HEADER_BYTES
        .checked_add(name_bytes)
        .ok_or(FileObjectNameError::InvalidFileInformation)?;
    if name_bytes % 2 != 0 || end > used {
        return Err(FileObjectNameError::InvalidFileInformation);
    }
    let name = &bytes[4..end];
    if !name.is_empty() && name[..2] != (b'\\' as u16).to_le_bytes() {
        return Err(FileObjectNameError::InvalidFileName);
    }
    Ok(name)
}

/// Format the x64 OBJECT_NAME_INFORMATION; `output_address` is the destination VA, not the
/// address of the temporary buffer used by the broker. On a short buffer, return the full size.
pub fn write_file_object_name(
    device_name: &[u16],
    file_name_le: &[u8],
    output_address: u64,
    output: &mut [u8],
) -> Result<usize, FileObjectNameError> {
    if !device_name.is_empty()
        && (device_name.first() != Some(&(b'\\' as u16))
            || device_name.last() == Some(&(b'\\' as u16)))
    {
        return Err(FileObjectNameError::InvalidDeviceName);
    }
    if file_name_le.len() % 2 != 0
        || (!file_name_le.is_empty() && file_name_le[..2] != (b'\\' as u16).to_le_bytes())
    {
        return Err(FileObjectNameError::InvalidFileName);
    }
    let name_bytes = device_name
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(file_name_le.len()))
        .ok_or(FileObjectNameError::NameTooLong)?;
    let maximum = name_bytes
        .checked_add(if name_bytes == 0 { 0 } else { 2 })
        .ok_or(FileObjectNameError::NameTooLong)?;
    let required = OBJECT_NAME_INFORMATION_HEADER_BYTES
        .checked_add(maximum)
        .ok_or(FileObjectNameError::NameTooLong)?;
    let name_length = u16::try_from(name_bytes).map_err(|_| FileObjectNameError::NameTooLong)?;
    let max_length = u16::try_from(maximum).map_err(|_| FileObjectNameError::NameTooLong)?;
    let name_address = output_address
        .checked_add(OBJECT_NAME_INFORMATION_HEADER_BYTES as u64)
        .ok_or(FileObjectNameError::NameTooLong)?;
    if output.len() < required {
        return Err(FileObjectNameError::BufferTooSmall { required });
    }
    output[..required].fill(0);
    output[..2].copy_from_slice(&name_length.to_le_bytes());
    output[2..4].copy_from_slice(&max_length.to_le_bytes());
    if name_bytes != 0 {
        output[8..16].copy_from_slice(&name_address.to_le_bytes());
    }
    let mut offset = OBJECT_NAME_INFORMATION_HEADER_BYTES;
    for &unit in device_name {
        output[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        offset += 2;
    }
    output[offset..offset + file_name_le.len()].copy_from_slice(file_name_le);
    Ok(required)
}

/// What a File `ObjectNameInformation` query answers: the status, how many bytes of the
/// formatted record to copy to the caller, and the `ReturnLength` to report, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileObjectNameAnswer {
    pub status: u32,
    pub copy: usize,
    pub return_length: Option<u32>,
}

/// `IopQueryNameFile`: name a File by its Device's name followed by the filesystem's
/// `FileNameInformation`. `query_status` and `query_information` are the terminal result of
/// that query and `file_information` its output. `output` is scratch as large as the caller's
/// buffer (`length` bytes, capped at the largest record); `output_address` is where the caller
/// will see it.
pub fn answer_file_object_name(
    device_name: &[u16],
    query_status: u32,
    file_information: &[u8],
    query_information: u64,
    output_address: u64,
    length: u32,
    output: &mut [u8],
) -> FileObjectNameAnswer {
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    const STATUS_DATA_ERROR: u32 = 0xC000_003E;
    const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
    let refused = |status| FileObjectNameAnswer { status, copy: 0, return_length: None };
    let file_name = match query_status {
        0 => match file_name_information_units(file_information, query_information) {
            Ok(name) => name,
            Err(_) => return refused(STATUS_DATA_ERROR),
        },
        // The device has no filesystem name to add: invalid parameter, invalid device
        // request, not implemented, invalid information class.
        0xC000_000D | 0xC000_0010 | 0xC000_0002 | 0xC000_0003 => &[][..],
        status => return refused(status),
    };
    let capacity = output.len().min(length as usize);
    match write_file_object_name(device_name, file_name, output_address, &mut output[..capacity]) {
        Ok(used) => FileObjectNameAnswer { status: 0, copy: used, return_length: Some(used as u32) },
        Err(FileObjectNameError::BufferTooSmall { required }) => FileObjectNameAnswer {
            status: if (length as usize) < OBJECT_NAME_INFORMATION_HEADER_BYTES {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                STATUS_BUFFER_OVERFLOW
            },
            copy: 0,
            return_length: Some(required as u32),
        },
        Err(FileObjectNameError::NameTooLong) => refused(STATUS_NAME_TOO_LONG),
        Err(_) => refused(STATUS_DATA_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec::Vec};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    fn le(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    #[test]
    fn names_file_with_canonical_device_and_live_filesystem_suffix() {
        let suffix = le(&wide("\\Fonts\\arial.ttf"));
        let mut file_info = Vec::from((suffix.len() as u32).to_le_bytes());
        file_info.extend_from_slice(&suffix);
        let name = file_name_information_units(&file_info, file_info.len() as u64).unwrap();
        let mut output = [0u8; 128];
        let used = write_file_object_name(
            &wide("\\Device\\HarddiskVolume1"),
            name,
            0x1000,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            u16::from_le_bytes(output[..2].try_into().unwrap()) as usize,
            used - 18
        );
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            0x1010
        );
        assert_eq!(&output[used - 2..used], &[0, 0]);
        assert_eq!(
            String::from_utf16(
                &output[16..used - 2]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            "\\Device\\HarddiskVolume1\\Fonts\\arial.ttf"
        );
    }

    #[test]
    fn reports_full_required_length_without_publishing_partial_name() {
        let mut output = [0xa5; 16];
        assert_eq!(
            write_file_object_name(
                &wide("\\Device\\Disk"),
                &le(&wide("\\a")),
                0x1000,
                &mut output
            ),
            Err(FileObjectNameError::BufferTooSmall {
                required: 16 + (12 + 2) * 2 + 2
            })
        );
        assert_eq!(output, [0xa5; 16]);
    }

    #[test]
    fn rejects_truncated_or_nonabsolute_filesystem_names() {
        let mut info = Vec::from(4u32.to_le_bytes());
        info.extend_from_slice(&le(&wide("\\a")));
        assert_eq!(
            file_name_information_units(&info, 5),
            Err(FileObjectNameError::InvalidFileInformation)
        );
        info[4..6].copy_from_slice(&(b'a' as u16).to_le_bytes());
        assert_eq!(
            file_name_information_units(&info, info.len() as u64),
            Err(FileObjectNameError::InvalidFileName)
        );
    }

    #[test]
    fn unnamed_device_and_unsupported_filesystem_have_defined_names() {
        let mut output = [0u8; 96];
        let used =
            write_file_object_name(&[], &le(&wide("\\Fonts\\x.ttf")), 0x2000, &mut output).unwrap();
        assert!(used > 16);
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            0x2010
        );

        let used =
            write_file_object_name(&wide("\\Device\\Disk"), &[], 0x2000, &mut output).unwrap();
        assert_eq!(used, 16 + 12 * 2 + 2);

        let used = write_file_object_name(&[], &[], 0x2000, &mut output).unwrap();
        assert_eq!(used, 16);
        assert_eq!(output[..16], [0; 16]);
    }

    fn file_information(path: &str) -> Vec<u8> {
        let suffix = le(&wide(path));
        let mut info = Vec::from((suffix.len() as u32).to_le_bytes());
        info.extend_from_slice(&suffix);
        info
    }

    #[test]
    fn answer_is_the_record_and_its_exact_length() {
        let info = file_information("\\Windows\\explorer.exe");
        let mut output = [0xa5u8; 256];
        let answer = answer_file_object_name(
            &wide("\\Device\\HarddiskVolume1"), 0, &info, info.len() as u64, 0x2000, 256,
            &mut output,
        );
        let expected = 16 + ("\\Device\\HarddiskVolume1\\Windows\\explorer.exe".len() + 1) * 2;
        assert_eq!(
            answer,
            FileObjectNameAnswer { status: 0, copy: expected, return_length: Some(expected as u32) }
        );
        assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 0x2010);
    }

    #[test]
    fn answer_reports_the_full_size_when_the_buffer_is_short() {
        let info = file_information("\\a");
        let device = wide("\\Device\\X");
        let required = (16 + (9 + 2 + 1) * 2) as u32;
        let mut output = [0u8; 20];
        assert_eq!(
            answer_file_object_name(&device, 0, &info, info.len() as u64, 0x2000, 20, &mut output),
            FileObjectNameAnswer { status: 0x8000_0005, copy: 0, return_length: Some(required) }
        );
        // Below the header the query is a length mismatch.
        assert_eq!(
            answer_file_object_name(&device, 0, &info, info.len() as u64, 0x2000, 8, &mut output[..8]),
            FileObjectNameAnswer { status: 0xC000_0004, copy: 0, return_length: Some(required) }
        );
    }

    #[test]
    fn a_device_that_serves_no_file_name_is_named_by_the_device_alone() {
        let device = wide("\\Device\\Null");
        for refusal in [0xC000_000Du32, 0xC000_0010, 0xC000_0002, 0xC000_0003] {
            let mut output = [0u8; 64];
            let answer = answer_file_object_name(&device, refusal, &[], 0, 0x2000, 64, &mut output);
            assert_eq!(answer.status, 0);
            assert_eq!(answer.copy, 16 + (12 + 1) * 2);
        }
    }

    #[test]
    fn a_failed_file_name_query_is_the_answer_and_names_nothing() {
        let mut output = [0xa5u8; 64];
        assert_eq!(
            answer_file_object_name(&wide("\\Device\\X"), 0xC000_0120, &[], 0, 0x2000, 64, &mut output),
            FileObjectNameAnswer { status: 0xC000_0120, copy: 0, return_length: None }
        );
        // Success with malformed information is not a name either.
        let answer =
            answer_file_object_name(&wide("\\Device\\X"), 0, &[9, 0, 0, 0, 1], 5, 0x2000, 64, &mut output);
        assert_eq!((answer.status, answer.copy), (0xC000_003E, 0));
    }
}
