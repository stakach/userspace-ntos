//! `IoGetPagingIoPriority` policy for native IRP flags.

const IRP_PAGING_IO: u32 = 0x0000_0002;
const IRP_CLASS_CACHE_OPERATION: u32 = 0x0000_8000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IoPagingPriority {
    Invalid = 0,
    Normal = 1,
    High = 2,
}

pub const fn paging_io_priority(irp_flags: u32) -> IoPagingPriority {
    if irp_flags & IRP_CLASS_CACHE_OPERATION != 0 {
        IoPagingPriority::High
    } else if irp_flags & IRP_PAGING_IO != 0 {
        IoPagingPriority::Normal
    } else {
        IoPagingPriority::Invalid
    }
}
