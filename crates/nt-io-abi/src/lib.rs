//! # `nt-io-abi` — the NT I/O Manager wire ABI
//!
//! Fixed-layout, `no_std`, allocation-free definitions shared across the I/O
//! Manager's client-facing service and its driver-peer dispatch: SURT opcodes,
//! request/reply payload structs, IRP major-function codes, IOCTL `CTL_CODE`
//! helpers, and the generation-protected I/O id types. No pointers, no `usize`,
//! no seL4 or Object Manager dependency — just the bytes on the wire. Path
//! payloads are UTF-16LE code units by definition.

#![no_std]

pub mod ioctl;
pub mod major;
pub mod opcodes;
pub mod projection;
pub mod wire;

pub use projection::{
    DeviceObjectProjection, DriverObjectProjection, FileObjectProjection, IoStackLocationProjection,
};
pub use wire::{
    IoCancelRequest, IoDeviceControlRequest, IoFileRequest, IoOpenRequest, IoReadWriteRequest,
    IoReply, IrpDispatchRequest,
};

/// ABI version of this wire contract; bumped on any incompatible change.
pub const IO_ABI_VERSION: u32 = 11;

/// Validate native byte-range lock parameters. Other major functions must not carry lock state.
pub const fn valid_lock_control_parameters(
    major_function: u8,
    minor_function: u8,
    stack_flags: u8,
    byte_offset: u64,
    length: u64,
    key: u32,
) -> bool {
    if major_function != major::IRP_MJ_LOCK_CONTROL {
        return byte_offset == 0 && length == 0 && key == 0;
    }
    match minor_function {
        1 => stack_flags & !0x03 == 0,
        2 => stack_flags == 0,
        _ => false,
    }
}

/// Validate the raw `IO_STACK_LOCATION.Parameters.SetFile` control union.
/// `information_class` is the class carried in `IrpDispatchRequest::ioctl_code`.
pub const fn valid_set_information_control(
    major_function: u8,
    information_class: u32,
    value: u32,
) -> bool {
    if major_function != major::IRP_MJ_SET_INFORMATION {
        return value == 0;
    }
    match information_class {
        10 | 11 => value <= 1,
        31 => true,
        _ => value == 0,
    }
}

/// Validate quota-specific IRP stack parameters against the major function and
/// the canonical combined auxiliary-buffer extent.
pub const fn valid_quota_parameters(
    major_function: u8,
    sid_list_length: u32,
    start_sid_length: u32,
    input_length: u32,
) -> bool {
    if major_function == major::IRP_MJ_QUERY_QUOTA {
        let start_offset = match sid_list_length.checked_add(3) {
            Some(length) => length & !3,
            None => return false,
        };
        match start_offset.checked_add(start_sid_length) {
            Some(length) => length == input_length,
            None => false,
        }
    } else {
        sid_list_length == 0 && start_sid_length == 0
    }
}

/// Validate query-EA-specific parameters against the canonical auxiliary
/// buffer extent. Other major functions must not carry EA query state.
pub const fn valid_ea_parameters(
    major_function: u8,
    ea_list_length: u32,
    ea_index: u32,
    input_length: u32,
) -> bool {
    if major_function == major::IRP_MJ_QUERY_EA {
        ea_list_length == input_length
    } else {
        ea_list_length == 0 && ea_index == 0
    }
}

/// Validate the class and buffer direction carried by native volume-information IRPs.
pub const fn valid_volume_information_parameters(
    major_function: u8,
    information_class: u32,
    input_length: u32,
    output_length: u32,
) -> bool {
    match major_function {
        major::IRP_MJ_QUERY_VOLUME_INFORMATION => {
            if input_length != 0 {
                return false;
            }
            let minimum = match information_class {
                1 => 24,
                3 => 24,
                4 => 8,
                5 => 16,
                6 => 48,
                7 => 32,
                8 => 64,
                9 => 12,
                _ => return false,
            };
            output_length >= minimum
        }
        major::IRP_MJ_SET_VOLUME_INFORMATION => {
            if output_length != 0 {
                return false;
            }
            let minimum = match information_class {
                2 => 8,
                6 => 48,
                8 => 64,
                _ => return false,
            };
            input_length >= minimum
        }
        _ => true,
    }
}

/// Generation bits in an I/O id (spec §9: high 24 gen / low 40 slot).
pub const IO_ID_GEN_BITS: u32 = 24;
/// Slot-index bits in an I/O id.
pub const IO_ID_SLOT_BITS: u32 = 40;

const GEN_MASK: u64 = (1u64 << IO_ID_GEN_BITS) - 1;
const SLOT_MASK: u64 = (1u64 << IO_ID_SLOT_BITS) - 1;

/// Declare a generation-protected `(generation, slot)` u64 id newtype.
macro_rules! io_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[repr(transparent)]
        #[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub u64);

        impl $name {
            /// The reserved null value.
            pub const NULL: $name = $name(0);

            /// Pack a `generation` (low [`IO_ID_GEN_BITS`]) and `slot` (low
            /// [`IO_ID_SLOT_BITS`]).
            #[inline]
            pub const fn new(generation: u32, slot: u64) -> $name {
                $name((((generation as u64) & GEN_MASK) << IO_ID_SLOT_BITS) | (slot & SLOT_MASK))
            }

            /// The generation field.
            #[inline]
            pub const fn generation(self) -> u32 {
                ((self.0 >> IO_ID_SLOT_BITS) & GEN_MASK) as u32
            }

            /// The slot-index field.
            #[inline]
            pub const fn slot(self) -> u64 {
                self.0 & SLOT_MASK
            }

            /// The raw packed value (as carried on the wire).
            #[inline]
            pub const fn raw(self) -> u64 {
                self.0
            }

            /// True if this is the reserved null value.
            #[inline]
            pub const fn is_null(self) -> bool {
                self.0 == 0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($name), "(gen={}, slot={})"),
                    self.generation(),
                    self.slot()
                )
            }
        }
    };
}

io_id! {
    /// Canonical I/O Manager driver-record id.
    DriverId
}
io_id! {
    /// Canonical I/O Manager device-record id.
    DeviceId
}
io_id! {
    /// Canonical I/O Manager file-record id.
    FileId
}
io_id! {
    /// Canonical I/O Manager IRP-record id.
    IrpId
}
io_id! {
    /// Generation-protected identity for one isolated hosted-driver address domain.
    HostedDomainId
}
io_id! {
    /// A client-facing I/O request id (correlates a submission + completion).
    IoRequestId
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn id_pack_roundtrip() {
        let id = IrpId::new(0x00AB_CDEF & (u32::MAX >> 8), 0x00FF_1234_5678 & SLOT_MASK);
        assert_eq!(id.generation(), 0x00AB_CDEF & (u32::MAX >> 8));
        assert_eq!(id.slot(), 0x00FF_1234_5678 & SLOT_MASK);
        assert!(!id.is_null());
        assert!(DeviceId::NULL.is_null());
        assert!(HostedDomainId::NULL.is_null());
        // Distinct newtypes with the same bit pattern are not interchangeable.
        assert_eq!(DriverId::new(3, 7).raw(), FileId::new(3, 7).raw());
    }

    #[test]
    fn opcode_ranges() {
        assert!(opcodes::is_client_opcode(opcodes::client::IO_OP_OPEN));
        assert!(!opcodes::is_client_opcode(
            opcodes::driver::IODRV_OP_DISPATCH_IRP
        ));
        assert!(opcodes::is_driver_opcode(
            opcodes::driver::IODRV_OP_DISPATCH_IRP
        ));
        assert!(opcodes::is_driver_opcode(
            opcodes::peer::IODRV_OP_COMPLETE_IRP
        ));
        assert!(!opcodes::is_driver_opcode(opcodes::client::IO_OP_PING));
    }

    #[test]
    fn ctl_code_pack_unpack() {
        // FILE_DEVICE_UNKNOWN=0x22, function 0x800, buffered, any access.
        let code = ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS);
        assert_eq!(ioctl::device_type(code), 0x22);
        assert_eq!(ioctl::function(code), 0x800);
        assert_eq!(ioctl::method(code), ioctl::METHOD_BUFFERED);
        assert_eq!(ioctl::access(code), ioctl::FILE_ANY_ACCESS);
    }

    #[test]
    fn major_codes() {
        assert_eq!(major::IRP_MJ_CREATE, 0);
        assert_eq!(major::IRP_MJ_DEVICE_CONTROL, 0x0e);
        assert_eq!(major::IRP_MJ_PNP, 0x1b);
        assert!(major::is_valid_major(major::IRP_MJ_PNP));
        assert!(!major::is_valid_major(major::IO_MAJOR_FUNCTION_COUNT as u8));
    }

    #[test]
    fn volume_information_parameters_match_native_classes_and_directions() {
        assert!(valid_volume_information_parameters(
            major::IRP_MJ_QUERY_VOLUME_INFORMATION,
            4,
            0,
            8,
        ));
        assert!(!valid_volume_information_parameters(
            major::IRP_MJ_QUERY_VOLUME_INFORMATION,
            2,
            0,
            8,
        ));
        assert!(valid_volume_information_parameters(
            major::IRP_MJ_SET_VOLUME_INFORMATION,
            2,
            8,
            0,
        ));
        assert!(!valid_volume_information_parameters(
            major::IRP_MJ_SET_VOLUME_INFORMATION,
            2,
            8,
            1,
        ));
        assert!(valid_volume_information_parameters(
            major::IRP_MJ_QUERY_INFORMATION,
            0,
            0,
            0,
        ));
    }

    #[test]
    fn set_information_control_union_is_class_specific() {
        assert!(valid_set_information_control(
            major::IRP_MJ_SET_INFORMATION,
            10,
            1
        ));
        assert!(!valid_set_information_control(
            major::IRP_MJ_SET_INFORMATION,
            10,
            2
        ));
        assert!(valid_set_information_control(
            major::IRP_MJ_SET_INFORMATION,
            31,
            u32::MAX
        ));
        assert!(!valid_set_information_control(
            major::IRP_MJ_SET_INFORMATION,
            32,
            1
        ));
        assert!(!valid_set_information_control(major::IRP_MJ_READ, 31, 1));
    }

    #[test]
    fn lock_control_parameters_are_minor_and_major_specific() {
        assert!(valid_lock_control_parameters(
            major::IRP_MJ_LOCK_CONTROL,
            1,
            0x03,
            0x1234,
            0x5678,
            9,
        ));
        assert!(valid_lock_control_parameters(
            major::IRP_MJ_LOCK_CONTROL,
            2,
            0,
            0x1234,
            0x5678,
            9,
        ));
        assert!(!valid_lock_control_parameters(
            major::IRP_MJ_LOCK_CONTROL,
            2,
            1,
            0,
            0,
            0,
        ));
        assert!(!valid_lock_control_parameters(
            major::IRP_MJ_READ,
            0,
            0,
            1,
            0,
            0,
        ));
    }

    #[test]
    fn wire_roundtrips_through_bytes() {
        let req = IoOpenRequest {
            abi_size: core::mem::size_of::<IoOpenRequest>() as u16,
            desired_access: 0x8000_0000,
            path_offset: 28,
            path_len_bytes: 24,
            ..Default::default()
        };
        let bytes = bytemuck::bytes_of(&req);
        let back: IoOpenRequest = bytemuck::pod_read_unaligned(bytes);
        assert_eq!(req, back);

        let irp = IrpDispatchRequest {
            abi_version: IO_ABI_VERSION as u16,
            abi_size: core::mem::size_of::<IrpDispatchRequest>() as u16,
            major: major::IRP_MJ_PNP,
            minor: 7,
            flags: 0x82_01,
            target_domain_id: HostedDomainId::new(2, 4).raw(),
            target_domain_cookie: 0x44,
            provider_domain_id: HostedDomainId::new(3, 5).raw(),
            provider_cookie: 0x55,
            irp_id: 0x100,
            driver_id: 0x200,
            device_id: 0x300,
            file_id: 0x400,
            related_file_id: 0x500,
            target_file_id: 0x600,
            set_information_control: 0x1234,
            quota_sid_list_length: 24,
            quota_start_sid_length: 12,
            ea_list_length: 16,
            ea_index: 7,
            stack_location: 1,
            stack_count: 3,
            ..Default::default()
        };
        let bytes = bytemuck::bytes_of(&irp);
        let back: IrpDispatchRequest = bytemuck::pod_read_unaligned(bytes);
        assert_eq!(irp, back);
    }

    #[test]
    fn quota_parameters_are_major_specific_and_overflow_checked() {
        assert!(valid_quota_parameters(
            major::IRP_MJ_QUERY_QUOTA,
            21,
            12,
            36
        ));
        assert!(!valid_quota_parameters(
            major::IRP_MJ_QUERY_QUOTA,
            21,
            12,
            33
        ));
        assert!(!valid_quota_parameters(
            major::IRP_MJ_QUERY_QUOTA,
            u32::MAX,
            1,
            0
        ));
        assert!(valid_quota_parameters(major::IRP_MJ_SET_QUOTA, 0, 0, 56));
        assert!(!valid_quota_parameters(major::IRP_MJ_SET_QUOTA, 8, 0, 56));
    }

    #[test]
    fn ea_parameters_are_query_major_specific() {
        assert!(valid_ea_parameters(major::IRP_MJ_QUERY_EA, 16, 7, 16));
        assert!(!valid_ea_parameters(major::IRP_MJ_QUERY_EA, 16, 7, 12));
        assert!(valid_ea_parameters(major::IRP_MJ_SET_EA, 0, 0, 32));
        assert!(!valid_ea_parameters(major::IRP_MJ_SET_EA, 16, 0, 32));
    }
}
