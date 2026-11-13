//! Bounded, pointer-free named Event create from the win32k component.
use super::*;

const BASE: u64 = WIN32K_LPC_VADDR + 0x400;
const ROOT: u64 = 0;
const ACCESS_ATTRIBUTES: u64 = 8;
const TYPE_STATE: u64 = 16;
const NAME_LENGTH: u64 = 24;
const SD_LENGTH: u64 = 32;
const NAME: u64 = 0x40;
const SD: u64 = NAME + (nt_user_host::provider_named_event::MAX_NAME_UNITS as u64) * 2;
const _: () = assert!(0x400 + SD as usize
    + nt_user_host::provider_named_event::MAX_DESCRIPTOR_BYTES <= WIN32K_LPC_BYTES);

struct ComponentMemory;
impl nt_security::ClientMemory for ComponentMemory {
    fn read(&self, address: u64, out: &mut [u8]) -> bool {
        if address == 0 || address.checked_add(out.len() as u64).is_none() { return false; }
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = unsafe { read_volatile((address + index as u64) as *const u8) };
        }
        true
    }
}

pub(super) fn create_named_event(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
    event_type: u32,
    initial_state: bool,
) -> i32 {
    unsafe {
        if read_unaligned(object_attributes as *const u32) < 0x30 {
            return STATUS_INVALID_PARAMETER_I32;
        }
        let root = read_unaligned((object_attributes + 8) as *const u64);
        let name_ptr = read_unaligned((object_attributes + 16) as *const u64);
        let attributes = read_unaligned((object_attributes + 24) as *const u32);
        let sd_ptr = read_unaligned((object_attributes + 32) as *const u64);
        let qos_ptr = read_unaligned((object_attributes + 40) as *const u64);
        if qos_ptr != 0 || name_ptr == 0 { return STATUS_INVALID_PARAMETER_I32; }
        let length = read_unaligned(name_ptr as *const u16) as usize;
        let maximum = read_unaligned((name_ptr + 2) as *const u16) as usize;
        let buffer = read_unaligned((name_ptr + 8) as *const u64);
        if length == 0 || length & 1 != 0 || length > maximum || buffer == 0
            || length > nt_user_host::provider_named_event::MAX_NAME_UNITS * 2
        {
            return nt_user_host::provider_named_event::STATUS_OBJECT_NAME_INVALID as i32;
        }
        let mut name = [0u16; nt_user_host::provider_named_event::MAX_NAME_UNITS];
        for (index, unit) in name[..length / 2].iter_mut().enumerate() {
            *unit = read_volatile((buffer + (index * 2) as u64) as *const u16);
        }
        let sd = if sd_ptr == 0 { alloc::vec::Vec::new() } else {
            match nt_security::capture_security_descriptor_bytes(&ComponentMemory, sd_ptr) {
                Ok(sd) => sd,
                Err(status) => return status as i32,
            }
        };
        let capture = match nt_user_host::provider_named_event::NamedEventCreate::capture(
            (), root, attributes, desired_access, event_type, initial_state,
            &name[..length / 2], &sd,
        ) {
            Ok(capture) => capture,
            Err(status) => return status as i32,
        };
        write_unaligned(handle_out, 0);
        write_volatile((BASE + ROOT) as *mut u64, capture.root_directory);
        write_volatile((BASE + ACCESS_ATTRIBUTES) as *mut u64,
            (u64::from(capture.attributes) << 32) | u64::from(capture.desired_access));
        write_volatile((BASE + TYPE_STATE) as *mut u64,
            u64::from(capture.event_type) | (u64::from(capture.initial_state) << 32));
        write_volatile((BASE + NAME_LENGTH) as *mut u64, capture.name.len() as u64);
        write_volatile((BASE + SD_LENGTH) as *mut u64, capture.security_descriptor.len() as u64);
        for (index, &unit) in capture.name.iter().enumerate() {
            write_volatile((BASE + NAME + (index * 2) as u64) as *mut u16, unit);
        }
        for (index, &byte) in capture.security_descriptor.iter().enumerate() {
            write_volatile((BASE + SD + index as u64) as *mut u8, byte);
        }
        let (status, handle, _, _) = win32k_event_broker_call(W32_EVENT_OP_CREATE_NAMED,
            capture.name.len() as u64, capture.security_descriptor.len() as u64, 0);
        if status >= 0 && handle != 0 {
            write_unaligned(handle_out, handle);
        }
        status
    }
}

pub(crate) unsafe fn read_owned<O: Copy + Eq>(
    owner: O,
    name_len: u64,
    sd_len: u64,
) -> Result<nt_user_host::provider_named_event::NamedEventCreate<O>, u32> {
    use nt_user_host::provider_named_event::{NamedEventCreate, MAX_DESCRIPTOR_BYTES, MAX_NAME_UNITS};
    if name_len == 0 || name_len > MAX_NAME_UNITS as u64
        || sd_len > MAX_DESCRIPTOR_BYTES as u64
        || read_volatile((BASE + NAME_LENGTH) as *const u64) != name_len
        || read_volatile((BASE + SD_LENGTH) as *const u64) != sd_len
    {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let mut name = [0u16; MAX_NAME_UNITS];
    for (index, unit) in name[..name_len as usize].iter_mut().enumerate() {
        *unit = read_volatile((BASE + NAME + (index * 2) as u64) as *const u16);
    }
    let mut sd = [0u8; MAX_DESCRIPTOR_BYTES];
    for (index, byte) in sd[..sd_len as usize].iter_mut().enumerate() {
        *byte = read_volatile((BASE + SD + index as u64) as *const u8);
    }
    let packed = read_volatile((BASE + ACCESS_ATTRIBUTES) as *const u64);
    let kind = read_volatile((BASE + TYPE_STATE) as *const u64);
    if kind >> 32 > 1 { return Err(nt_process::STATUS_INVALID_PARAMETER); }
    NamedEventCreate::capture(owner,
        read_volatile((BASE + ROOT) as *const u64), (packed >> 32) as u32,
        packed as u32, kind as u32, kind >> 32 != 0,
        &name[..name_len as usize], &sd[..sd_len as usize])
}
