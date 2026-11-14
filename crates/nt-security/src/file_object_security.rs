//! File-object security when the file's driver has no security dispatch.
//!
//! `NtQuerySecurityObject` / `NtSetSecurityObject` on a file send
//! `IRP_MJ_QUERY_SECURITY` / `IRP_MJ_SET_SECURITY` to the file's device. A driver
//! without those majors (FAT, for one) answers `STATUS_INVALID_DEVICE_REQUEST`,
//! and the I/O manager then completes the request itself: a query reads the
//! world descriptor, a set succeeds with nothing stored
//! (`IopGetSetSecurityObject`, `ntoskrnl/io/iomgr/file.c`). Every other driver
//! status is the caller's result unchanged.

use alloc::vec::Vec;

use crate::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION, STATUS_ACCESS_DENIED,
};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;

const HEADER_LENGTH: usize = 0x14;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;
/// `S-1-1-0`.
const WORLD_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const ACL_REVISION: u8 = 2;
const ACL_LENGTH: usize = 8 + 8 + WORLD_SID.len();
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
const AUDIT_SUCCESS_AND_FAILURE: u8 = 0x40 | 0x80;
const GENERIC_ALL: u32 = 0x1000_0000;
const AUDIT_MASK: u32 = 0x0100_0000 | 0x001F_0000;

/// The result of `NtSetSecurityObject` on a file whose driver answered `driver_status`.
pub const fn file_set_security_status(driver_status: u32) -> u32 {
    if driver_status == STATUS_INVALID_DEVICE_REQUEST {
        STATUS_SUCCESS
    } else {
        driver_status
    }
}

/// The descriptor `NtQuerySecurityObject` reads from a file whose driver answered
/// `driver_status` without producing one.
pub fn file_query_security_descriptor(
    driver_status: u32,
    security_information: u32,
) -> Result<Vec<u8>, u32> {
    if driver_status != STATUS_INVALID_DEVICE_REQUEST {
        return Err(driver_status);
    }
    world_security_descriptor(security_information)
}

/// `SeSetWorldSecurityDescriptor`: Everyone as owner and group, a DACL granting
/// Everyone `GENERIC_ALL`, and a SACL auditing Everyone, each only when requested.
fn world_security_descriptor(security_information: u32) -> Result<Vec<u8>, u32> {
    if security_information == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let mut descriptor = Vec::with_capacity(HEADER_LENGTH + 2 * WORLD_SID.len() + 2 * ACL_LENGTH);
    descriptor.resize(HEADER_LENGTH, 0);
    descriptor[0] = 1;
    let mut control = SE_SELF_RELATIVE;
    for (information, field) in
        [(OWNER_SECURITY_INFORMATION, 0x04), (GROUP_SECURITY_INFORMATION, 0x08)]
    {
        if security_information & information != 0 {
            set_offset(&mut descriptor, field);
            descriptor.extend_from_slice(&WORLD_SID);
        }
    }
    if security_information & DACL_SECURITY_INFORMATION != 0 {
        control |= SE_DACL_PRESENT;
        set_offset(&mut descriptor, 0x10);
        push_world_acl(&mut descriptor, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL);
    }
    if security_information & SACL_SECURITY_INFORMATION != 0 {
        control |= SE_SACL_PRESENT;
        set_offset(&mut descriptor, 0x0c);
        push_world_acl(
            &mut descriptor,
            SYSTEM_AUDIT_ACE_TYPE,
            AUDIT_SUCCESS_AND_FAILURE,
            AUDIT_MASK,
        );
    }
    descriptor[2..4].copy_from_slice(&control.to_le_bytes());
    Ok(descriptor)
}

/// Point the header's offset `field` at the current end of the descriptor.
fn set_offset(descriptor: &mut [u8], field: usize) {
    let offset = descriptor.len() as u32;
    descriptor[field..field + 4].copy_from_slice(&offset.to_le_bytes());
}

fn push_world_acl(descriptor: &mut Vec<u8>, ace_type: u8, ace_flags: u8, mask: u32) {
    let ace_length = (8 + WORLD_SID.len()) as u16;
    descriptor.extend_from_slice(&[ACL_REVISION, 0]);
    descriptor.extend_from_slice(&(ACL_LENGTH as u16).to_le_bytes());
    descriptor.extend_from_slice(&[1, 0, 0, 0]);
    descriptor.extend_from_slice(&[ace_type, ace_flags]);
    descriptor.extend_from_slice(&ace_length.to_le_bytes());
    descriptor.extend_from_slice(&mask.to_le_bytes());
    descriptor.extend_from_slice(&WORLD_SID);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{query_security_descriptor_bytes, validate_security_descriptor_bytes};

    #[test]
    fn a_driver_without_the_security_major_accepts_a_set_and_stores_nothing() {
        assert_eq!(file_set_security_status(STATUS_INVALID_DEVICE_REQUEST), 0);
    }

    #[test]
    fn every_other_driver_status_is_the_callers_result() {
        for status in [0, 0x103, 0xC000_0022, 0xC000_0002, 0xC000_0008] {
            assert_eq!(file_set_security_status(status), status);
            if status != STATUS_INVALID_DEVICE_REQUEST {
                assert_eq!(
                    file_query_security_descriptor(status, DACL_SECURITY_INFORMATION),
                    Err(status)
                );
            }
        }
    }

    #[test]
    fn query_without_driver_support_reads_the_world_dacl() {
        let descriptor =
            file_query_security_descriptor(STATUS_INVALID_DEVICE_REQUEST, DACL_SECURITY_INFORMATION)
                .unwrap();
        let mut expected = alloc::vec![1, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(&0x14u32.to_le_bytes());
        expected.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
        expected.extend_from_slice(&[0, 0, 20, 0, 0, 0, 0, 0x10]);
        expected.extend_from_slice(&WORLD_SID);
        assert_eq!(descriptor, expected);
        validate_security_descriptor_bytes(&descriptor).unwrap();
    }

    #[test]
    fn every_requested_component_is_laid_out_without_overlap() {
        let all = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | SACL_SECURITY_INFORMATION;
        let descriptor = file_query_security_descriptor(STATUS_INVALID_DEVICE_REQUEST, all).unwrap();
        let offset = |field: usize| {
            u32::from_le_bytes(descriptor[field..field + 4].try_into().unwrap()) as usize
        };
        assert_eq!(u16::from_le_bytes([descriptor[2], descriptor[3]]), 0x8014);
        assert_eq!((offset(0x04), offset(0x08)), (0x14, 0x20));
        assert_eq!((offset(0x10), offset(0x0c)), (0x2c, 0x48));
        assert_eq!(descriptor.len(), 0x64);
        assert_eq!(&descriptor[0x48 + 8..0x48 + 16], &[2, 0xc0, 20, 0, 0, 0, 0x1f, 0x01]);
        validate_security_descriptor_bytes(&descriptor).unwrap();
        // The object-query path accepts it as an ordinary stored descriptor.
        let owner = query_security_descriptor_bytes(&descriptor, OWNER_SECURITY_INFORMATION).unwrap();
        assert_eq!(&owner[0x14..], &WORLD_SID);
    }

    #[test]
    fn empty_security_information_is_access_denied() {
        assert_eq!(
            file_query_security_descriptor(STATUS_INVALID_DEVICE_REQUEST, 0),
            Err(STATUS_ACCESS_DENIED)
        );
    }
}
