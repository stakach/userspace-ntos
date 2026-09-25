//! AMD64 native exception-call records. These are ABI layouts, not a live dispatcher.
//!
//! `EXCEPTION_RECORD` and `EXCEPTION_POINTERS` follow NT5 `wdm.w`; the 0x50-byte
//! `DISPATCHER_CONTEXT` includes ReactOS's `ScopeIndex` extension to the NT5 0x48-byte prefix.

use core::mem::{align_of, offset_of, size_of};

pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub chained_record: u64,
    pub address: u64,
    pub parameter_count: u32,
    pub alignment: u32,
    pub information: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl RawExceptionRecord {
    pub const fn software_raise(code: u32, flags: u32, address: u64) -> Self {
        Self {
            code,
            flags,
            chained_record: 0,
            address,
            parameter_count: 0,
            alignment: 0,
            information: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RawDispatcherContext {
    pub control_pc: u64,
    pub image_base: u64,
    pub function_entry: u64,
    pub establisher_frame: u64,
    pub target_ip: u64,
    pub context_record: u64,
    pub language_handler: u64,
    pub handler_data: u64,
    pub history_table: u64,
    pub scope_index: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RawExceptionPointers {
    pub exception_record: u64,
    pub context_record: u64,
}

const _: () = {
    assert!(size_of::<RawExceptionRecord>() == 0x98);
    assert!(align_of::<RawExceptionRecord>() == 8);
    assert!(offset_of!(RawExceptionRecord, code) == 0);
    assert!(offset_of!(RawExceptionRecord, flags) == 4);
    assert!(offset_of!(RawExceptionRecord, chained_record) == 8);
    assert!(offset_of!(RawExceptionRecord, address) == 0x10);
    assert!(offset_of!(RawExceptionRecord, parameter_count) == 0x18);
    assert!(offset_of!(RawExceptionRecord, information) == 0x20);

    assert!(size_of::<RawDispatcherContext>() == 0x50);
    assert!(align_of::<RawDispatcherContext>() == 8);
    assert!(offset_of!(RawDispatcherContext, control_pc) == 0);
    assert!(offset_of!(RawDispatcherContext, image_base) == 8);
    assert!(offset_of!(RawDispatcherContext, function_entry) == 0x10);
    assert!(offset_of!(RawDispatcherContext, establisher_frame) == 0x18);
    assert!(offset_of!(RawDispatcherContext, target_ip) == 0x20);
    assert!(offset_of!(RawDispatcherContext, context_record) == 0x28);
    assert!(offset_of!(RawDispatcherContext, language_handler) == 0x30);
    assert!(offset_of!(RawDispatcherContext, handler_data) == 0x38);
    assert!(offset_of!(RawDispatcherContext, history_table) == 0x40);
    assert!(offset_of!(RawDispatcherContext, scope_index) == 0x48);

    assert!(size_of::<RawExceptionPointers>() == 0x10);
    assert!(align_of::<RawExceptionPointers>() == 8);
    assert!(offset_of!(RawExceptionPointers, exception_record) == 0);
    assert!(offset_of!(RawExceptionPointers, context_record) == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_raise_record_has_exact_zeroed_tail_and_native_offsets() {
        let record = RawExceptionRecord::software_raise(0xc000_0022, 1, 0x1234_5678);
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&record as *const RawExceptionRecord).cast::<u8>(),
                size_of::<RawExceptionRecord>(),
            )
        };
        assert_eq!(&bytes[0..4], &0xc000_0022u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
        assert_eq!(&bytes[0x10..0x18], &0x1234_5678u64.to_le_bytes());
        assert!(bytes[0x20..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn dispatcher_scope_index_follows_the_nt5_prefix() {
        let dispatcher = RawDispatcherContext {
            scope_index: 7,
            ..RawDispatcherContext::default()
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&dispatcher as *const RawDispatcherContext).cast::<u8>(),
                size_of::<RawDispatcherContext>(),
            )
        };
        assert_eq!(&bytes[0x48..0x4c], &7u32.to_le_bytes());
    }
}
