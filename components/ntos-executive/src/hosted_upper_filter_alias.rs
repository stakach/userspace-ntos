//! Component-local class PDO and foreign lower-device shape.
//!
//! The executive authenticates both exact projection allocations and registrations before
//! entering this component selector. This operation changes only the class component's WDM
//! memory; the port FDO is already attached canonically and must not be attached a second time.

use core::ptr::{read_unaligned, write_unaligned};
use nt_io_manager::WDM_X64_IO_TYPE_DEVICE;

const ATTACHED_DEVICE: u64 = 0x18;
const FLAGS: u64 = 0x30;
const CHARACTERISTICS: u64 = 0x34;
const DEVICE_TYPE: u64 = 0x48;
const STACK_SIZE: u64 = 0x4c;
const DRIVER_OBJECT: u64 = 0x08;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;

/// Called by the component projection-control selector after its pool-range validation. `pdo`
/// and `lower` are fresh aliases, not driver-owned FDOs. No canonical I/O Manager state changes.
/// The return value is the observed PDO address, for the executive's exact acknowledgement.
pub(crate) unsafe fn configure_class_lower_alias(
    pdo: u64,
    lower: u64,
    lower_type: u32,
    lower_flags: u32,
    lower_characteristics: u32,
    lower_stack_size: u8,
) -> Result<u64, i32> {
    if pdo == 0
        || lower == 0
        || pdo == lower
        || lower_stack_size == 0
        || lower_stack_size == u8::MAX
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    for object in [pdo, lower] {
        if read_unaligned(object as *const i16) != WDM_X64_IO_TYPE_DEVICE
            || read_unaligned((object + DRIVER_OBJECT) as *const u64) != 0
            || read_unaligned((object + ATTACHED_DEVICE) as *const u64) != 0
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
    }
    if read_unaligned((pdo + STACK_SIZE) as *const u8) != 1 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    write_unaligned((lower + DEVICE_TYPE) as *mut u32, lower_type);
    write_unaligned((lower + FLAGS) as *mut u32, lower_flags);
    write_unaligned((lower + CHARACTERISTICS) as *mut u32, lower_characteristics);
    write_unaligned((lower + STACK_SIZE) as *mut u8, lower_stack_size);
    write_unaligned((pdo + ATTACHED_DEVICE) as *mut u64, lower);
    Ok(pdo)
}
