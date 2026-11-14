//! Byte-exact RTL helpers for native SID and security-descriptor storage.
//!
//! The ntdll and hosted-kernel ABIs both expose these layouts. Policy and ACL
//! interpretation remain with the Security Reference Monitor.

/// Offset of `SID.SubAuthority[index]` in a native SID with at most 15 authorities.
pub const fn sub_authority_offset(index: u32) -> Option<usize> {
    if index < 15 {
        Some(8 + index as usize * 4)
    } else {
        None
    }
}

/// Bytes needed for a native SID with the requested number of sub-authorities.
pub const fn required_sid_length(sub_authority_count: u32) -> u32 {
    8u32.wrapping_add(sub_authority_count.wrapping_mul(4))
}

/// Write the fixed SID header; the caller owns the sub-authority storage.
pub fn initialize_sid_header(
    sid_header: &mut [u8],
    authority: &[u8; 6],
    sub_authority_count: u8,
) -> Result<(), ()> {
    if sid_header.len() < 8 {
        return Err(());
    }
    sid_header[0] = 1;
    sid_header[1] = sub_authority_count;
    sid_header[2..8].copy_from_slice(authority);
    Ok(())
}

#[cfg(test)]
mod sid_header_tests {
    use super::*;

    #[test]
    fn sid_header_and_required_length_match_native_layout() {
        let authority = [0, 0, 0, 0, 0, 5];
        let mut sid = [0xa5u8; 20];
        assert_eq!(required_sid_length(3), 20);
        initialize_sid_header(&mut sid[..8], &authority, 3).unwrap();
        assert_eq!(&sid[..8], &[1, 3, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&sid[8..], &[0xa5; 12]);
        assert_eq!(sub_authority_offset(2), Some(16));
        assert_eq!(sub_authority_offset(15), None);
    }
}

const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_UNKNOWN_REVISION: u32 = 0xc000_0058;
const STATUS_INVALID_SECURITY_DESCR: u32 = 0xc000_0079;
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SE_SELF_RELATIVE: u16 = 0x8000;
const ABSOLUTE_HEADER_LENGTH: usize = 0x28;
const SELF_RELATIVE_HEADER_LENGTH: usize = 0x14;

/// One of the two access-control lists a security descriptor carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorAcl {
    Sacl,
    Dacl,
}

impl DescriptorAcl {
    const fn present_bit(self) -> u16 {
        match self {
            Self::Dacl => 0x0004,
            Self::Sacl => 0x0010,
        }
    }

    /// `SE_*_DEFAULTED` is the bit directly above `SE_*_PRESENT`.
    const fn defaulted_bit(self) -> u16 {
        self.present_bit() << 1
    }

    /// Offset of the pointer in the x64 absolute layout.
    const fn absolute_field(self) -> usize {
        match self {
            Self::Sacl => 0x18,
            Self::Dacl => 0x20,
        }
    }

    /// Offset of the 32-bit offset in the self-relative layout.
    const fn relative_field(self) -> usize {
        match self {
            Self::Sacl => 0x0c,
            Self::Dacl => 0x10,
        }
    }
}

/// What `RtlGet{Dacl,Sacl}SecurityDescriptor` reports for one ACL.
///
/// `address` is meaningful only when `present`; zero is a present NULL ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorAclView {
    pub present: bool,
    pub defaulted: bool,
    pub address: u64,
}

/// Header length selected by the descriptor's own form, from its first four bytes.
///
/// A descriptor read back from the kernel is self-relative (20-byte header of
/// offsets); one built with `RtlCreateSecurityDescriptor` is absolute (pointers).
pub fn descriptor_header_length(prefix: &[u8]) -> Result<usize, u32> {
    if prefix.len() < 4 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    if prefix[0] != SECURITY_DESCRIPTOR_REVISION {
        return Err(STATUS_UNKNOWN_REVISION);
    }
    if u16::from_le_bytes([prefix[2], prefix[3]]) & SE_SELF_RELATIVE != 0 {
        Ok(SELF_RELATIVE_HEADER_LENGTH)
    } else {
        Ok(ABSOLUTE_HEADER_LENGTH)
    }
}

/// Locate one ACL of the descriptor whose header is `header` and which is stored
/// at `descriptor_address`.
///
/// A self-relative descriptor names its ACL by offset from its own base, an
/// absolute one by pointer; the two layouts overlap, so the control word decides.
pub fn descriptor_acl(
    header: &[u8],
    descriptor_address: u64,
    acl: DescriptorAcl,
) -> Result<DescriptorAclView, u32> {
    let length = descriptor_header_length(header)?;
    if header.len() < length {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    let control = u16::from_le_bytes([header[2], header[3]]);
    if control & acl.present_bit() == 0 {
        return Ok(DescriptorAclView { present: false, defaulted: false, address: 0 });
    }
    let address = if control & SE_SELF_RELATIVE != 0 {
        let field = acl.relative_field();
        match u32::from_le_bytes([
            header[field],
            header[field + 1],
            header[field + 2],
            header[field + 3],
        ]) {
            0 => 0,
            offset => descriptor_address.wrapping_add(offset as u64),
        }
    } else {
        let field = acl.absolute_field();
        let mut pointer = [0u8; 8];
        pointer.copy_from_slice(&header[field..field + 8]);
        u64::from_le_bytes(pointer)
    };
    Ok(DescriptorAclView {
        present: true,
        defaulted: control & acl.defaulted_bit() != 0,
        address,
    })
}

/// Update one ACL of a writable x64 absolute `SECURITY_DESCRIPTOR`.
///
/// The caller owns the ACL pointer. This changes the descriptor's pointer and
/// control bits only; ACL validation occurs when the descriptor is consumed.
fn set_absolute_acl(
    descriptor: &mut [u8],
    acl: DescriptorAcl,
    present: bool,
    acl_pointer: u64,
    defaulted: bool,
) -> Result<(), u32> {
    // The form is decided before the length: a self-relative header is shorter
    // than an absolute one and must be refused as such.
    match descriptor_header_length(descriptor) {
        Ok(ABSOLUTE_HEADER_LENGTH) => {}
        Ok(_) => return Err(STATUS_INVALID_SECURITY_DESCR),
        Err(STATUS_UNKNOWN_REVISION) => return Err(STATUS_UNKNOWN_REVISION),
        Err(_) => return Err(STATUS_INVALID_PARAMETER),
    }
    if descriptor.len() < ABSOLUTE_HEADER_LENGTH {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut control = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    if !present {
        control &= !acl.present_bit();
        descriptor[2..4].copy_from_slice(&control.to_le_bytes());
        return Ok(());
    }
    let field = acl.absolute_field();
    descriptor[field..field + 8].copy_from_slice(&acl_pointer.to_le_bytes());
    control |= acl.present_bit();
    control &= !acl.defaulted_bit();
    if defaulted {
        control |= acl.defaulted_bit();
    }
    descriptor[2..4].copy_from_slice(&control.to_le_bytes());
    Ok(())
}

/// `RtlSetSaclSecurityDescriptor` over a writable x64 absolute descriptor.
pub fn set_absolute_sacl(
    descriptor: &mut [u8],
    present: bool,
    sacl_pointer: u64,
    defaulted: bool,
) -> Result<(), u32> {
    set_absolute_acl(descriptor, DescriptorAcl::Sacl, present, sacl_pointer, defaulted)
}

/// `RtlSetDaclSecurityDescriptor` over a writable x64 absolute descriptor.
pub fn set_absolute_dacl(
    descriptor: &mut [u8],
    present: bool,
    dacl_pointer: u64,
    defaulted: bool,
) -> Result<(), u32> {
    set_absolute_acl(descriptor, DescriptorAcl::Dacl, present, dacl_pointer, defaulted)
}

#[cfg(test)]
mod descriptor_acl_tests {
    use super::*;

    const STATUS_UNKNOWN_REVISION: u32 = 0xc000_0058;
    const STATUS_INVALID_SECURITY_DESCR: u32 = 0xc000_0079;

    /// What `NtQuerySecurityObject(DACL_SECURITY_INFORMATION)` returns: a 20-byte
    /// self-relative header whose DACL starts directly behind it.
    fn self_relative_with_dacl() -> [u8; 0x30] {
        let mut sd = [0u8; 0x30];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        sd[0x10..0x14].copy_from_slice(&0x14u32.to_le_bytes());
        // ACL header, then one ACE whose mask and SID occupy the bytes an
        // absolute descriptor would hold its DACL pointer in.
        sd[0x14..0x1c].copy_from_slice(&[2, 0, 0x1c, 0, 1, 0, 0, 0]);
        sd[0x1c..0x20].copy_from_slice(&[0, 0, 0x14, 0]);
        sd[0x20..0x24].copy_from_slice(&0x0002_0003u32.to_le_bytes());
        sd[0x24..0x30].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        sd
    }

    #[test]
    fn self_relative_dacl_is_the_descriptor_base_plus_its_offset() {
        let sd = self_relative_with_dacl();
        let length = descriptor_header_length(&sd[..4]).unwrap();
        assert_eq!(length, 0x14);
        let view = descriptor_acl(&sd[..length], 0x100_302d_79f0, DescriptorAcl::Dacl).unwrap();
        assert_eq!(
            view,
            DescriptorAclView { present: true, defaulted: false, address: 0x100_302d_7a04 }
        );
        // The bytes an absolute reader would take for the pointer are ACE contents.
        assert_eq!(
            u64::from_le_bytes(sd[0x20..0x28].try_into().unwrap()),
            0x0000_0101_0002_0003
        );
    }

    #[test]
    fn self_relative_zero_offset_is_a_present_null_acl() {
        let mut sd = self_relative_with_dacl();
        sd[0x10..0x14].fill(0);
        let view = descriptor_acl(&sd[..0x14], 0x1000, DescriptorAcl::Dacl).unwrap();
        assert_eq!(view, DescriptorAclView { present: true, defaulted: false, address: 0 });
    }

    #[test]
    fn absolute_acl_is_the_stored_pointer_and_absent_acl_reports_nothing() {
        let mut sd = [0u8; 0x28];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x000cu16.to_le_bytes());
        sd[0x18..0x20].copy_from_slice(&0x1111u64.to_le_bytes());
        sd[0x20..0x28].copy_from_slice(&0x2222u64.to_le_bytes());
        assert_eq!(descriptor_header_length(&sd[..4]), Ok(0x28));
        assert_eq!(
            descriptor_acl(&sd, 0x9000, DescriptorAcl::Dacl),
            Ok(DescriptorAclView { present: true, defaulted: true, address: 0x2222 })
        );
        assert_eq!(
            descriptor_acl(&sd, 0x9000, DescriptorAcl::Sacl),
            Ok(DescriptorAclView { present: false, defaulted: false, address: 0 })
        );
    }

    #[test]
    fn unknown_revision_and_short_headers_are_rejected() {
        assert_eq!(descriptor_header_length(&[2, 0, 4, 0x80]), Err(STATUS_UNKNOWN_REVISION));
        assert_eq!(descriptor_header_length(&[1, 0]), Err(STATUS_INVALID_SECURITY_DESCR));
        let sd = self_relative_with_dacl();
        assert_eq!(
            descriptor_acl(&sd[..0x10], 0, DescriptorAcl::Dacl),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );
    }

    #[test]
    fn absolute_dacl_set_follows_the_native_control_rules() {
        let mut sd = [0u8; 0x28];
        sd[0] = 1;
        set_absolute_dacl(&mut sd, true, 0x4000, true).unwrap();
        assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x000c);
        assert_eq!(u64::from_le_bytes(sd[0x20..0x28].try_into().unwrap()), 0x4000);
        set_absolute_dacl(&mut sd, true, 0x5000, false).unwrap();
        assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x0004);
        // Removing the DACL clears only the present bit; the pointer is left alone.
        set_absolute_dacl(&mut sd, false, 0, false).unwrap();
        assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x0000);
        assert_eq!(u64::from_le_bytes(sd[0x20..0x28].try_into().unwrap()), 0x5000);
        // The SACL words are untouched throughout.
        assert_eq!(&sd[0x18..0x20], &[0; 8]);

        let mut relative = self_relative_with_dacl();
        assert_eq!(
            set_absolute_dacl(&mut relative, true, 0x4000, false),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );
        // ...also when only its own 20-byte header is addressable.
        assert_eq!(
            set_absolute_dacl(&mut relative[..0x14], true, 0x4000, false),
            Err(STATUS_INVALID_SECURITY_DESCR)
        );
        assert_eq!(set_absolute_dacl(&mut [1, 0, 0, 0], true, 0, false), Err(0xc000_000d));
        sd[0] = 2;
        assert_eq!(set_absolute_dacl(&mut sd, true, 0, false), Err(STATUS_UNKNOWN_REVISION));
    }
}
