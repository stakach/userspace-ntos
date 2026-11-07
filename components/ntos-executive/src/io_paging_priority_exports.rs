//! Direct native `IoGetPagingIoPriority` export for caller-owned IRPs.

use nt_compat_exports::DriverExportRegistry;

const IRP_FLAGS_OFFSET: u64 = 0x10;

pub(super) extern "win64" fn io_get_paging_io_priority(irp: u64) -> u32 {
    assert!(irp != 0 && irp.checked_add(IRP_FLAGS_OFFSET + 4).is_some(),
        "IoGetPagingIoPriority invalid IRP address");
    let flags = unsafe { core::ptr::read_unaligned((irp + IRP_FLAGS_OFFSET) as *const u32) };
    nt_io_manager::io_paging_priority::paging_io_priority(flags) as u32
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("IoGetPagingIoPriority", io_get_paging_io_priority as usize as u64);
}
