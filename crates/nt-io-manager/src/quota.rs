//! Native quota-buffer validation and IRP parameter contracts.

use nt_types::AccessMask;

const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: usize = 15;
const SID_HEADER_LENGTH: usize = 8;
const FILE_GET_QUOTA_SID_OFFSET: usize = 8;
const FILE_QUOTA_SID_OFFSET: usize = 40;
const FILE_WRITE_DATA: u32 = 0x0000_0002;

/// The first malformed quota-list entry and its byte offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaValidationError {
    pub offset: usize,
}

/// Captured `NtQueryQuotaInformationFile` parameters.
///
/// The transfer buffer contains the SID list followed by four-byte padding and
/// the optional start SID. The output buffer remains a distinct IRP surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryQuotaParameters {
    pub length: u32,
    pub sid_list_length: u32,
    pub start_sid_length: u32,
}

impl QueryQuotaParameters {
    pub fn start_sid_offset(self) -> Option<u32> {
        self.sid_list_length
            .checked_add(3)
            .map(|length| length & !3)
    }

    pub fn input_length(self) -> Option<u32> {
        self.start_sid_offset()?.checked_add(self.start_sid_length)
    }

    pub fn valid_transfer_length(self, length: usize) -> bool {
        self.input_length()
            .and_then(|length| usize::try_from(length).ok())
            == Some(length)
    }
}

/// Captured `NtSetQuotaInformationFile` parameters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetQuotaParameters {
    pub length: u32,
}

/// Return the exact byte length of a valid SID at the beginning of `bytes`.
pub fn sid_length(bytes: &[u8]) -> Result<usize, QuotaValidationError> {
    if bytes.len() < SID_HEADER_LENGTH || bytes[0] != SID_REVISION {
        return Err(QuotaValidationError { offset: 0 });
    }
    let sub_authorities = bytes[1] as usize;
    if sub_authorities > SID_MAX_SUB_AUTHORITIES {
        return Err(QuotaValidationError { offset: 0 });
    }
    let length = SID_HEADER_LENGTH
        .checked_add(
            sub_authorities
                .checked_mul(4)
                .ok_or(QuotaValidationError { offset: 0 })?,
        )
        .ok_or(QuotaValidationError { offset: 0 })?;
    if length > bytes.len() {
        return Err(QuotaValidationError { offset: 0 });
    }
    Ok(length)
}

/// Validate a `FILE_GET_QUOTA_INFORMATION` chain captured for a query IRP.
pub fn validate_get_quota_buffer(bytes: &[u8]) -> Result<(), QuotaValidationError> {
    let mut offset = 0usize;
    loop {
        let remaining = bytes.get(offset..).ok_or(QuotaValidationError { offset })?;
        // NT5 requires the fixed fields, SID header, and one sub-authority-sized
        // word to be addressable before calling RtlValidSid.
        if remaining.len() < FILE_GET_QUOTA_SID_OFFSET + SID_HEADER_LENGTH + 4 {
            return Err(QuotaValidationError { offset });
        }
        let sid_length = sid_length(&remaining[FILE_GET_QUOTA_SID_OFFSET..])
            .map_err(|_| QuotaValidationError { offset })?;
        let entry_length = FILE_GET_QUOTA_SID_OFFSET
            .checked_add(sid_length)
            .ok_or(QuotaValidationError { offset })?;
        let next = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
        if next == 0 {
            if entry_length > remaining.len() {
                return Err(QuotaValidationError { offset });
            }
            return Ok(());
        }
        if next < entry_length || next & 3 != 0 || next > remaining.len() {
            return Err(QuotaValidationError { offset });
        }
        offset = offset
            .checked_add(next)
            .ok_or(QuotaValidationError { offset })?;
    }
}

/// Validate an x64 `FILE_QUOTA_INFORMATION` chain captured for a set IRP.
pub fn validate_set_quota_buffer(bytes: &[u8]) -> Result<(), QuotaValidationError> {
    let mut offset = 0usize;
    loop {
        let remaining = bytes.get(offset..).ok_or(QuotaValidationError { offset })?;
        if remaining.len() < FILE_QUOTA_SID_OFFSET + SID_HEADER_LENGTH {
            return Err(QuotaValidationError { offset });
        }
        let sid_length = sid_length(&remaining[FILE_QUOTA_SID_OFFSET..])
            .map_err(|_| QuotaValidationError { offset })?;
        let encoded_sid_length = u32::from_le_bytes(remaining[4..8].try_into().unwrap()) as usize;
        let entry_length = FILE_QUOTA_SID_OFFSET
            .checked_add(sid_length)
            .ok_or(QuotaValidationError { offset })?;
        if encoded_sid_length != sid_length || entry_length > remaining.len() {
            return Err(QuotaValidationError { offset });
        }
        let next = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
        if next == 0 {
            return Ok(());
        }
        if next < entry_length || next & 7 != 0 || next > remaining.len() {
            return Err(QuotaValidationError { offset });
        }
        offset = offset
            .checked_add(next)
            .ok_or(QuotaValidationError { offset })?;
    }
}

/// NT5 references a quota-set File with `FILE_WRITE_DATA` access.
pub fn set_quota_access_granted(granted: AccessMask) -> bool {
    granted.contains(AccessMask::GENERIC_ALL)
        || granted.contains(AccessMask::GENERIC_WRITE)
        || granted.bits() & FILE_WRITE_DATA != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(sub_authorities: &[u32]) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, 5];
        for value in sub_authorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn query_quota_extents_keep_start_sid_separate() {
        let parameters = QueryQuotaParameters {
            length: 256,
            sid_list_length: 21,
            start_sid_length: 12,
        };
        assert_eq!(parameters.start_sid_offset(), Some(24));
        assert_eq!(parameters.input_length(), Some(36));
        assert!(parameters.valid_transfer_length(36));
        assert!(!parameters.valid_transfer_length(33));
    }

    #[test]
    fn validates_get_quota_chains_and_reports_entry_offset() {
        let first_sid = sid(&[500]);
        let second_sid = sid(&[501]);
        let mut bytes = alloc::vec![0; 24 + 8 + second_sid.len()];
        bytes[0..4].copy_from_slice(&24u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(first_sid.len() as u32).to_le_bytes());
        bytes[8..8 + first_sid.len()].copy_from_slice(&first_sid);
        bytes[28..32].copy_from_slice(&(second_sid.len() as u32).to_le_bytes());
        bytes[32..32 + second_sid.len()].copy_from_slice(&second_sid);
        assert_eq!(validate_get_quota_buffer(&bytes), Ok(()));

        bytes[24] = 2;
        assert_eq!(
            validate_get_quota_buffer(&bytes),
            Err(QuotaValidationError { offset: 24 })
        );
    }

    #[test]
    fn validates_set_quota_x64_records() {
        let first_sid = sid(&[500]);
        let second_sid = sid(&[501]);
        let mut bytes = alloc::vec![0; 56 + 40 + second_sid.len()];
        bytes[0..4].copy_from_slice(&56u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(first_sid.len() as u32).to_le_bytes());
        bytes[40..40 + first_sid.len()].copy_from_slice(&first_sid);
        bytes[60..64].copy_from_slice(&(second_sid.len() as u32).to_le_bytes());
        bytes[96..96 + second_sid.len()].copy_from_slice(&second_sid);
        assert_eq!(validate_set_quota_buffer(&bytes), Ok(()));

        bytes[60..64].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            validate_set_quota_buffer(&bytes),
            Err(QuotaValidationError { offset: 56 })
        );
    }

    #[test]
    fn set_quota_requires_write_data() {
        assert!(set_quota_access_granted(AccessMask::from_bits_retain(
            FILE_WRITE_DATA
        )));
        assert!(set_quota_access_granted(AccessMask::GENERIC_WRITE));
        assert!(!set_quota_access_granted(AccessMask::GENERIC_READ));
    }
}
