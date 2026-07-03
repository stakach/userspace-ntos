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
pub mod wire;

pub use wire::{
    IoCancelRequest, IoDeviceControlRequest, IoFileRequest, IoOpenRequest, IoReadWriteRequest,
    IoReply, IrpDispatchRequest,
};

/// ABI version of this wire contract; bumped on any incompatible change.
pub const IO_ABI_VERSION: u32 = 1;

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
    }
}
