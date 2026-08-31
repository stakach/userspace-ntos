//! Executive virtual-address ownership.
//!
//! Dynamic mappings in the root executive must lease from a named arena. They must never derive a
//! root VSpace address from a component or hosted-process layout: those numeric ranges can coexist
//! only because the corresponding components have separate VSpaces.

use nt_pnp_context::{
    AddressSlotAllocator, AddressSlotReleaseError, AddressSlotReservation, SlotError,
};

const EXECUTIVE_DEVICE_MAPPING_STRIDE: u64 = 0x20_0000;
const EXECUTIVE_DEVICE_MAPPING_BASE: u64 = 0x0000_4000_0000_0000;
const EXECUTIVE_DEVICE_MAPPING_LIMIT: u64 = 0x0000_4001_0000_0000;

const _: () = {
    assert!(EXECUTIVE_DEVICE_MAPPING_BASE > crate::driver_launch::FSD_EXEC_LIMIT);
    assert!(EXECUTIVE_DEVICE_MAPPING_LIMIT <= 0x0000_7fff_ffff_f000);
};

static mut EXECUTIVE_DEVICE_MAPPINGS: AddressSlotAllocator = AddressSlotAllocator::new(
    EXECUTIVE_DEVICE_MAPPING_BASE,
    EXECUTIVE_DEVICE_MAPPING_LIMIT,
    EXECUTIVE_DEVICE_MAPPING_STRIDE,
);

/// Lease a root-executive VA span for retained device or firmware memory.
pub(crate) unsafe fn reserve_executive_device_mapping(
    bytes: u64,
) -> Result<AddressSlotReservation, SlotError> {
    (&mut *core::ptr::addr_of_mut!(EXECUTIVE_DEVICE_MAPPINGS)).allocate(bytes)
}

/// Release a device-mapping span after every mapped capability in it has been retired.
pub(crate) unsafe fn release_executive_device_mapping(
    reservation: AddressSlotReservation,
) -> Result<(), AddressSlotReleaseError> {
    (&mut *core::ptr::addr_of_mut!(EXECUTIVE_DEVICE_MAPPINGS)).release(reservation)
}
