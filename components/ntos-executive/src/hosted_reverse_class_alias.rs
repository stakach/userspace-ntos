//! Port-component memory shape for the two class objects retained by CONNECT.
//!
//! These are foreign aliases. The port may store their addresses, but any HOOK or class
//! callback must translate back to the exact source registration before class execution.

use core::ptr::{read_unaligned, write_unaligned};
use nt_io_manager::WDM_X64_IO_TYPE_DEVICE;

const DRIVER_OBJECT: u64 = 0x08;
const ATTACHED_DEVICE: u64 = 0x18;
const FLAGS: u64 = 0x30;
const CHARACTERISTICS: u64 = 0x34;
const DEVICE_TYPE: u64 = 0x48;
const STACK_SIZE: u64 = 0x4c;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;

#[derive(Clone, Copy)]
pub(crate) struct ClassAliasShape {
    pub(crate) device_type: u32,
    pub(crate) flags: u32,
    pub(crate) characteristics: u32,
    pub(crate) stack_size: u8,
}

/// The component selector must check that both complete DEVICE_OBJECT headers are in its own
/// live pool before calling this function. No canonical topology or source memory is mutated.
pub(crate) unsafe fn configure_reverse_class_aliases(
    port_do: u64,
    class_do: u64,
    port_shape: ClassAliasShape,
    class_shape: ClassAliasShape,
) -> Result<u64, i32> {
    if port_do == 0 || class_do == 0 || port_do == class_do
        || port_shape.stack_size == 0 || class_shape.stack_size == 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    for address in [port_do, class_do] {
        if read_unaligned(address as *const i16) != WDM_X64_IO_TYPE_DEVICE
            || read_unaligned((address + DRIVER_OBJECT) as *const u64) != 0
            || read_unaligned((address + ATTACHED_DEVICE) as *const u64) != 0
            || read_unaligned((address + STACK_SIZE) as *const u8) != 1
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
    }
    for (address, shape) in [(port_do, port_shape), (class_do, class_shape)] {
        write_unaligned((address + DEVICE_TYPE) as *mut u32, shape.device_type);
        write_unaligned((address + FLAGS) as *mut u32, shape.flags);
        write_unaligned((address + CHARACTERISTICS) as *mut u32, shape.characteristics);
        write_unaligned((address + STACK_SIZE) as *mut u8, shape.stack_size);
    }
    Ok(port_do)
}
