//! ReactOS x64 `WIN32_PARSEMETHOD_PARAMETERS` passed to the win32k parse callout.
//!
//! Every address belongs to the provider's address space. The native adapter must validate the
//! pointed-to access state and retain its token references before invoking the callout.

use crate::GuestAddr;
use bytemuck::{Pod, Zeroable};
use core::mem::{offset_of, size_of};

/// Natural x64 packing: `KPROCESSOR_MODE` is one byte, so `Attributes` follows at 0x1c. The pinned
/// LiberNT `IntWinStaObjectParse` reads RemainingName at +0x28 and Object at +0x40 (boot
/// 44471147330 faulted writing `*Object` when the block used a padded 0x50-byte layout).
pub const WIN32_PARSE_METHOD_PARAMETERS_SIZE: usize = 0x48;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Win32ParseMethodParameters {
    pub parse_object: GuestAddr,
    pub object_type: GuestAddr,
    pub access_state: GuestAddr,
    pub access_mode: u8,
    _access_mode_padding: [u8; 3],
    pub attributes: u32,
    pub complete_name: GuestAddr,
    pub remaining_name: GuestAddr,
    pub context: GuestAddr,
    pub security_qos: GuestAddr,
    pub object_out: GuestAddr,
}

impl Win32ParseMethodParameters {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        parse_object: GuestAddr,
        object_type: GuestAddr,
        access_state: GuestAddr,
        access_mode: u8,
        attributes: u32,
        complete_name: GuestAddr,
        remaining_name: GuestAddr,
        context: GuestAddr,
        security_qos: GuestAddr,
        object_out: GuestAddr,
    ) -> Self {
        Self {
            parse_object,
            object_type,
            access_state,
            access_mode,
            _access_mode_padding: [0; 3],
            attributes,
            complete_name,
            remaining_name,
            context,
            security_qos,
            object_out,
        }
    }
}

const _: () = {
    assert!(size_of::<Win32ParseMethodParameters>() == WIN32_PARSE_METHOD_PARAMETERS_SIZE);
    assert!(offset_of!(Win32ParseMethodParameters, access_mode) == 0x18);
    assert!(offset_of!(Win32ParseMethodParameters, attributes) == 0x1c);
    assert!(offset_of!(Win32ParseMethodParameters, complete_name) == 0x20);
    assert!(offset_of!(Win32ParseMethodParameters, remaining_name) == 0x28);
    assert!(offset_of!(Win32ParseMethodParameters, context) == 0x30);
    assert!(offset_of!(Win32ParseMethodParameters, security_qos) == 0x38);
    assert!(offset_of!(Win32ParseMethodParameters, object_out) == 0x40);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_callout_parameters_have_reactos_x64_layout() {
        let parameters = Win32ParseMethodParameters::new(
            GuestAddr(1),
            GuestAddr(2),
            GuestAddr(3),
            4,
            5,
            GuestAddr(6),
            GuestAddr(7),
            GuestAddr(8),
            GuestAddr(9),
            GuestAddr(10),
        );
        let bytes = bytemuck::bytes_of(&parameters);
        assert_eq!(bytes.len(), WIN32_PARSE_METHOD_PARAMETERS_SIZE);
        // Offsets read by the pinned LiberNT IntWinStaObjectParse (win32k RVA 0xba6c0).
        for (offset, value) in [
            (0x00, 1),
            (0x08, 2),
            (0x10, 3),
            (0x20, 6),
            (0x28, 7),
            (0x30, 8),
            (0x38, 9),
            (0x40, 10),
        ] {
            assert_eq!(
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                value
            );
        }
        assert_eq!(bytes[0x18], 4);
        assert_eq!(&bytes[0x19..0x1c], &[0; 3]);
        assert_eq!(u32::from_le_bytes(bytes[0x1c..0x20].try_into().unwrap()), 5);
    }
}
