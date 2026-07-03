//! # `nt-types` — common NT primitive types
//!
//! The scalar building blocks shared across the userspace-ntos NT personality:
//! generation-protected ids ([`ObjectId`], [`HandleValue`]), access masks
//! ([`AccessMask`], [`GenericMapping`]), the access mode / case-sensitivity
//! enums, and (behind `alloc`) the owned [`UnicodeString`] and [`NtPath`]
//! parser.
//!
//! `no_std`. The `alloc` feature (on by default) enables the owned string/path/
//! attributes types; the id and mask types need no allocator.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod object;
#[cfg(feature = "alloc")]
mod path;

#[cfg(feature = "alloc")]
pub use object::ObjectAttributes;
pub use object::{
    ClientId, Generation, HandleValue, ObjAttrFlags, ObjectId, ObjectTypeId, GEN_BITS, SLOT_BITS,
};
#[cfg(feature = "alloc")]
pub use path::{NtPath, UnicodeString};

bitflags::bitflags! {
    /// A Windows access mask. The named bits are the standard + generic rights
    /// (real Windows values); object-specific rights live in the low 16 bits and
    /// are interpreted per object type, so arbitrary bits are preserved
    /// (`from_bits_retain`).
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct AccessMask: u32 {
        const DELETE = 0x0001_0000;
        const READ_CONTROL = 0x0002_0000;
        const WRITE_DAC = 0x0004_0000;
        const WRITE_OWNER = 0x0008_0000;
        const SYNCHRONIZE = 0x0010_0000;
        const ACCESS_SYSTEM_SECURITY = 0x0100_0000;
        const MAXIMUM_ALLOWED = 0x0200_0000;
        const GENERIC_ALL = 0x1000_0000;
        const GENERIC_EXECUTE = 0x2000_0000;
        const GENERIC_WRITE = 0x4000_0000;
        const GENERIC_READ = 0x8000_0000;
    }
}

impl AccessMask {
    /// `STANDARD_RIGHTS_REQUIRED` — DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER.
    pub const STANDARD_RIGHTS_REQUIRED: AccessMask = AccessMask::from_bits_retain(0x000F_0000);
    /// Bits that are generic (`GENERIC_*`) and must be mapped away before use.
    pub const GENERIC_BITS: AccessMask = AccessMask::from_bits_retain(0xF000_0000);

    /// True if any `GENERIC_*` bit is set (i.e. the mask still needs mapping).
    #[inline]
    pub const fn has_generic(self) -> bool {
        self.bits() & Self::GENERIC_BITS.bits() != 0
    }
}

/// Maps the four `GENERIC_*` bits of an access mask to type-specific rights, the
/// way `RtlMapGenericMask` does. Each object type registers its mapping.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GenericMapping {
    pub generic_read: AccessMask,
    pub generic_write: AccessMask,
    pub generic_execute: AccessMask,
    pub generic_all: AccessMask,
}

impl GenericMapping {
    /// Replace any `GENERIC_*` bits in `mask` with this type's specific rights.
    pub fn map(&self, mask: AccessMask) -> AccessMask {
        let mut out = AccessMask::from_bits_retain(mask.bits() & !AccessMask::GENERIC_BITS.bits());
        if mask.contains(AccessMask::GENERIC_READ) {
            out |= self.generic_read;
        }
        if mask.contains(AccessMask::GENERIC_WRITE) {
            out |= self.generic_write;
        }
        if mask.contains(AccessMask::GENERIC_EXECUTE) {
            out |= self.generic_execute;
        }
        if mask.contains(AccessMask::GENERIC_ALL) {
            out |= self.generic_all;
        }
        out
    }
}

/// The processor mode a request originates from (governs access-check policy).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum AccessMode {
    KernelMode,
    UserMode,
}

/// Whether a name lookup is case sensitive (`OBJ_CASE_INSENSITIVE` clear) or not.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CaseSensitivity {
    CaseSensitive,
    CaseInsensitive,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mask_values() {
        assert_eq!(AccessMask::DELETE.bits(), 0x0001_0000);
        assert_eq!(AccessMask::GENERIC_READ.bits(), 0x8000_0000);
        assert_eq!(AccessMask::STANDARD_RIGHTS_REQUIRED.bits(), 0x000F_0000);
    }

    #[test]
    fn generic_mapping_replaces_generic_bits() {
        // A Directory-like mapping.
        const QUERY: AccessMask = AccessMask::from_bits_retain(0x0001);
        const TRAVERSE: AccessMask = AccessMask::from_bits_retain(0x0002);
        let m = GenericMapping {
            generic_read: QUERY,
            generic_write: TRAVERSE,
            generic_execute: TRAVERSE,
            generic_all: AccessMask::from_bits_retain(0x000F | 0x000F_0000),
        };
        let mapped = m.map(AccessMask::GENERIC_READ | AccessMask::SYNCHRONIZE);
        assert!(!mapped.has_generic());
        assert!(mapped.contains(QUERY));
        assert!(mapped.contains(AccessMask::SYNCHRONIZE));
    }
}
