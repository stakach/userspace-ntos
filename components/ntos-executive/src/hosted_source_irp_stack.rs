//! Validate the current/next WDM stack locations in one retained source IRP allocation.

use nt_io_manager::source_irp_ledger::SourceIrpAllocation;
use nt_kernel_abi::Irp;

pub(super) fn next_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    if irp.type_ != super::WDM_X64_IO_TYPE_IRP as i16 || irp.size as u64 != allocation.bytes {
        return None;
    }
    let location = u8::try_from(irp.current_location).ok()?;
    if location < 2 || location > allocation.stack_count.saturating_add(1)
        || irp.stack_count != allocation.stack_count as i8 {
        return None;
    }
    let stack_base = allocation.component_address.checked_add(super::WDM_X64_IRP_SIZE as u64)?;
    let current = stack_base.checked_add(
        (location as u64 - 1).checked_mul(super::WDM_X64_IO_STACK_LOCATION_SIZE as u64)?)?;
    if irp.current_stack_location.0 != current { return None; }
    current.checked_sub(super::WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}
