//! Generation-protected ids and object attributes.

/// Number of generation bits in an [`ObjectId`] / [`HandleValue`].
pub const GEN_BITS: u32 = 24;
/// Number of slot-index bits in an [`ObjectId`] / [`HandleValue`].
pub const SLOT_BITS: u32 = 40;

const GEN_MASK: u32 = (1u32 << GEN_BITS) - 1;
const SLOT_MASK: u64 = (1u64 << SLOT_BITS) - 1;

/// A monotonically-advancing counter used to invalidate reused slots. Wraps
/// within [`GEN_BITS`]; a wrap only aliases after 2^24 reuses of one slot, which
/// the store treats as astronomically unlikely for v0.1.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct Generation(pub u32);

impl Generation {
    /// The next generation (wrapping within `GEN_BITS`), never zero so that a
    /// zero id stays reserved as "null".
    #[inline]
    pub const fn next(self) -> Generation {
        let n = self.0.wrapping_add(1) & GEN_MASK;
        Generation(if n == 0 { 1 } else { n })
    }
}

/// Build the `id`-style accessors for a `(generation, slot)` packed u64 newtype.
macro_rules! packed_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[repr(transparent)]
        #[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub u64);

        impl $name {
            /// The reserved null value.
            pub const NULL: $name = $name(0);

            /// Pack a `generation` (low `GEN_BITS`) and `slot` (low `SLOT_BITS`).
            #[inline]
            pub const fn new(generation: Generation, slot: u64) -> $name {
                $name((((generation.0 & GEN_MASK) as u64) << SLOT_BITS) | (slot & SLOT_MASK))
            }

            /// The generation field.
            #[inline]
            pub const fn generation(self) -> Generation {
                Generation((self.0 >> SLOT_BITS) as u32 & GEN_MASK)
            }

            /// The slot-index field.
            #[inline]
            pub const fn slot(self) -> u64 {
                self.0 & SLOT_MASK
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
                    self.generation().0,
                    self.slot()
                )
            }
        }
    };
}

packed_id! {
    /// Canonical, generation-protected identity of an object. Stable across a
    /// component boundary; a stale id (old generation) never resolves to a new
    /// object.
    ObjectId
}

packed_id! {
    /// A per-client handle. Meaningful only in the issuing client's context;
    /// never an [`ObjectId`], never valid across clients.
    HandleValue
}

/// Identifies a registered object type (Directory, SymbolicLink, …).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ObjectTypeId(pub u32);

/// Identifies a connected client component.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ClientId(pub u64);

bitflags::bitflags! {
    /// `OBJ_*` object-attribute flags (real Windows values) supplied on create/open.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct ObjAttrFlags: u32 {
        const INHERIT = 0x0000_0002;
        const PERMANENT = 0x0000_0010;
        const EXCLUSIVE = 0x0000_0020;
        const CASE_INSENSITIVE = 0x0000_0040;
        const OPEN_IF = 0x0000_0080;
        const OPEN_LINK = 0x0000_0100;
        const KERNEL_HANDLE = 0x0000_0200;
    }
}

#[cfg(feature = "alloc")]
use crate::path::UnicodeString;

/// The NT `OBJECT_ATTRIBUTES` a create/open request carries.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default)]
pub struct ObjectAttributes {
    /// A handle to the directory the (relative) name is resolved against; `None`
    /// means `object_name` is an absolute NT path.
    pub root_directory: Option<HandleValue>,
    /// The object name / path. `None` for an unnamed object.
    pub object_name: Option<UnicodeString>,
    /// `OBJ_*` flags.
    pub attributes: ObjAttrFlags,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let gen = Generation(0x00AB_CDEF & ((1 << GEN_BITS) - 1));
        let slot = 0x0000_00FF_1234_5678 & ((1u64 << SLOT_BITS) - 1);
        let id = ObjectId::new(gen, slot);
        assert_eq!(id.generation(), gen);
        assert_eq!(id.slot(), slot);
        assert!(!id.is_null());
        assert!(ObjectId::NULL.is_null());
    }

    #[test]
    fn generation_next_skips_zero_on_wrap() {
        let max = Generation((1 << GEN_BITS) - 1);
        assert_eq!(max.next(), Generation(1)); // wraps past 0
        assert_eq!(Generation(5).next(), Generation(6));
    }

    #[test]
    fn ids_are_distinct_types() {
        // Same bits, different newtypes — a handle is not an object id.
        let h = HandleValue::new(Generation(3), 7);
        assert_eq!(h.generation(), Generation(3));
        assert_eq!(h.slot(), 7);
    }
}
