//! Component-side C language handler for hosted PE drivers.
//!
//! The executive owns the exception packet, but filters and termination handlers must execute in
//! the driver's address space and on its paused thread. Keep the scope walk here and share only
//! the policy decisions with `nt-unwind`.

use nt_unwind::{
    next_c_scope, CScopeAction, Disposition, ScopeRecord, EXCEPTION_NONCONTINUABLE,
    EXCEPTION_UNWIND,
};

use super::{FSD_CODE_VA, FSD_POOL_VADDR};

#[repr(C)]
struct DispatcherContext {
    control_pc: u64,
    image_base: u64,
    function_entry: u64,
    establisher_frame: u64,
    target_ip: u64,
    context_record: u64,
    language_handler: u64,
    handler_data: u64,
    history_table: u64,
    scope_index: u32,
    fill: u32,
}

#[repr(C)]
struct ExceptionPointers {
    record: u64,
    context: u64,
}

struct Image {
    base: u64,
    size: u64,
    sections: u64,
    section_count: u16,
}

impl Image {
    unsafe fn admit(base: u64) -> Option<Self> {
        if base < FSD_CODE_VA || base & 0xfff != 0 || base >= FSD_POOL_VADDR {
            return None;
        }
        if unsafe { read_u16(base) } != 0x5a4d {
            return None;
        }
        let pe = u64::from(unsafe { read_u32(base + 0x3c) });
        if !(0x40..=0x800).contains(&pe) || unsafe { read_u32(base + pe) } != 0x0000_4550 {
            return None;
        }
        let section_count = unsafe { read_u16(base + pe + 6) };
        let optional_size = u64::from(unsafe { read_u16(base + pe + 20) });
        if section_count == 0 || section_count > 96 || optional_size < 0x70 {
            return None;
        }
        let optional = pe + 24;
        if unsafe { read_u16(base + optional) } != 0x20b {
            return None;
        }
        let size = u64::from(unsafe { read_u32(base + optional + 0x38) });
        let sections = optional.checked_add(optional_size)?;
        let headers_end = sections.checked_add(u64::from(section_count) * 40)?;
        if size == 0 || headers_end > size || base.checked_add(size)? > FSD_POOL_VADDR {
            return None;
        }
        Some(Self {
            base,
            size,
            sections: base + sections,
            section_count,
        })
    }

    fn contains(&self, address: u64, length: u64) -> bool {
        address >= self.base
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.base + self.size)
    }

    unsafe fn code_address(&self, rva: u32) -> Option<u64> {
        let address = self.base.checked_add(u64::from(rva))?;
        if !self.contains(address, 1) {
            return None;
        }
        for i in 0..self.section_count {
            let section = self.sections + u64::from(i) * 40;
            let virtual_size = u64::from(unsafe { read_u32(section + 8) });
            let virtual_address = u64::from(unsafe { read_u32(section + 12) });
            let characteristics = unsafe { read_u32(section + 36) };
            if characteristics & 0x2000_0000 == 0 {
                continue;
            }
            let end = virtual_address.checked_add(virtual_size)?;
            if u64::from(rva) >= virtual_address && u64::from(rva) < end {
                return Some(address);
            }
        }
        None
    }
}

unsafe fn read_u16(address: u64) -> u16 {
    unsafe { core::ptr::read_unaligned(address as *const u16) }
}

unsafe fn read_u32(address: u64) -> u32 {
    unsafe { core::ptr::read_unaligned(address as *const u32) }
}

unsafe fn read_u64(address: u64) -> u64 {
    unsafe { core::ptr::read_unaligned(address as *const u64) }
}

unsafe fn scope(table: u64, index: u32) -> ScopeRecord {
    let entry = table + 4 + u64::from(index) * 16;
    ScopeRecord {
        begin: unsafe { read_u32(entry) },
        end: unsafe { read_u32(entry + 4) },
        handler: unsafe { read_u32(entry + 8) },
        target: unsafe { read_u32(entry + 12) },
    }
}

/// Native x64 exception-routine ABI. Input packet/dispatcher pointers come from the executive's
/// owned handler command, not from an untrusted driver call.
pub(super) unsafe fn dispatch(
    exception_record: u64,
    establisher_frame: u64,
    context_record: u64,
    dispatcher_context: u64,
) -> i32 {
    if exception_record == 0 || context_record == 0 || dispatcher_context == 0 {
        panic!("hosted C handler received a null exception packet");
    }
    let dispatcher = dispatcher_context as *mut DispatcherContext;
    let image_base =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).image_base)) };
    let image = unsafe { Image::admit(image_base) }
        .expect("hosted C handler image is not a mapped PE image");
    let table =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).handler_data)) };
    if !image.contains(table, 4) {
        panic!("hosted C handler scope table is outside its PE image");
    }
    let count = unsafe { read_u32(table) };
    let table_len = u64::from(count)
        .checked_mul(16)
        .and_then(|n| n.checked_add(4))
        .expect("hosted C handler scope table overflows");
    if count > 4096 || !image.contains(table, table_len) {
        panic!("hosted C handler scope table exceeds its PE image");
    }
    let control_pc =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).control_pc)) };
    if !image.contains(control_pc, 1) {
        panic!("hosted C handler control PC is outside its PE image");
    }
    let target_ip =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).target_ip)) };
    let target_rva = if target_ip == 0 {
        u64::MAX
    } else {
        target_ip.checked_sub(image.base).unwrap_or(u64::MAX)
    };
    let flags = unsafe { read_u32(exception_record + 4) };

    loop {
        let mut index =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).scope_index)) };
        let action = next_c_scope(
            control_pc - image.base,
            target_rva,
            flags,
            count,
            &mut index,
            |i| unsafe { scope(table, i) },
        );
        unsafe {
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*dispatcher).scope_index), index)
        };
        match action {
            CScopeAction::ContinueSearch => return Disposition::ContinueSearch.as_raw(),
            CScopeAction::Filter {
                handler_rva,
                target_rva,
                ..
            } => {
                let filter = unsafe { image.code_address(handler_rva) }
                    .expect("hosted C handler filter is not executable image code");
                let target = unsafe { image.code_address(target_rva) }
                    .expect("hosted C handler target is not executable image code");
                let pointers = ExceptionPointers {
                    record: exception_record,
                    context: context_record,
                };
                let filter: unsafe extern "win64" fn(*const ExceptionPointers, u64) -> i32 =
                    unsafe { core::mem::transmute(filter as usize) };
                let verdict = unsafe { filter(&pointers, establisher_frame) };
                if verdict < 0 {
                    if flags & EXCEPTION_NONCONTINUABLE != 0 {
                        panic!("hosted C handler resumed a noncontinuable exception");
                    }
                    return Disposition::ContinueExecution.as_raw();
                }
                if verdict > 0 {
                    execute_handler_unwind(
                        establisher_frame,
                        target,
                        exception_record,
                        context_record,
                        dispatcher,
                    );
                }
            }
            CScopeAction::ExecuteHandler { target_rva, .. } => {
                let target = unsafe { image.code_address(target_rva) }
                    .expect("hosted C handler target is not executable image code");
                execute_handler_unwind(
                    establisher_frame,
                    target,
                    exception_record,
                    context_record,
                    dispatcher,
                );
            }
            CScopeAction::Finally {
                handler_rva,
                end_rva,
            } => {
                if flags & EXCEPTION_UNWIND == 0 {
                    panic!("hosted C handler selected termination outside unwind");
                }
                let finalizer = unsafe { image.code_address(handler_rva) }
                    .expect("hosted C handler finalizer is not executable image code");
                let end_pc = image.base + u64::from(end_rva);
                if !image.contains(end_pc.saturating_sub(1), 1) {
                    panic!("hosted C handler scope end is outside its PE image");
                }
                unsafe {
                    core::ptr::write_unaligned(
                        core::ptr::addr_of_mut!((*dispatcher).control_pc),
                        end_pc,
                    )
                };
                let finalizer: unsafe extern "win64" fn(u8, u64) =
                    unsafe { core::mem::transmute(finalizer as usize) };
                unsafe { finalizer(1, establisher_frame) };
            }
        }
    }
}

fn execute_handler_unwind(
    _establisher_frame: u64,
    _target_ip: u64,
    _exception_record: u64,
    _context_record: u64,
    _dispatcher: *mut DispatcherContext,
) -> ! {
    // The search result is real, but returning from this branch would skip the required target
    // unwind and claim a catch that never ran. This is replaced by the owned restore continuation.
    panic!("hosted C handler target unwind is not connected")
}
