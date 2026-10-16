//! Byte-exact RTL helpers for native SID and absolute security-descriptor storage.
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

/// Update the SACL fields of a writable x64 absolute `SECURITY_DESCRIPTOR`.
///
/// The caller owns the ACL pointer. This changes the descriptor's pointer and
/// control bits only; ACL validation occurs when the descriptor is consumed.
pub fn set_absolute_sacl(
    descriptor: &mut [u8],
    present: bool,
    sacl_pointer: u64,
    defaulted: bool,
) -> Result<(), u32> {
    const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
    const STATUS_UNKNOWN_REVISION: u32 = 0xc000_0058;
    const STATUS_INVALID_SECURITY_DESCR: u32 = 0xc000_0079;
    const SE_SACL_PRESENT: u16 = 0x0010;
    const SE_SACL_DEFAULTED: u16 = 0x0020;
    const SE_SELF_RELATIVE: u16 = 0x8000;

    if descriptor.len() < 0x28 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if descriptor[0] != 1 {
        return Err(STATUS_UNKNOWN_REVISION);
    }
    let mut control = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    if control & SE_SELF_RELATIVE != 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    if !present {
        control &= !SE_SACL_PRESENT;
        descriptor[2..4].copy_from_slice(&control.to_le_bytes());
        return Ok(());
    }
    descriptor[0x18..0x20].copy_from_slice(&sacl_pointer.to_le_bytes());
    control |= SE_SACL_PRESENT;
    control &= !SE_SACL_DEFAULTED;
    if defaulted {
        control |= SE_SACL_DEFAULTED;
    }
    descriptor[2..4].copy_from_slice(&control.to_le_bytes());
    Ok(())
}
