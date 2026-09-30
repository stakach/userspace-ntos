//! Child allocations and pinned transfer targets owned by one exact source IRP.

use super::*;
use nt_io_manager::provider_source_irp::{ProviderSourceIrpAllocation, ProviderSourceIrpTicket};

pub(super) struct SourceIrpAuxiliary {
    pub source: ProviderSourceIrpAllocation,
    pub ticket: ProviderSourceIrpTicket,
    pub system_buffer: Option<source_irp::PinnedSystemBuffer>,
    pub mdl: Option<source_irp::PinnedSystemBuffer>,
    pub input_target: Option<(u64, u64, provider_input::PinnedInput)>,
    pub output_target: Option<(u64, u64, file_ioctl_target::PinnedIoctlOutput)>,
}

static mut SOURCE_AUXILIARIES: Vec<SourceIrpAuxiliary> = Vec::new();

pub(super) unsafe fn register(auxiliary: SourceIrpAuxiliary) -> Result<(), SourceIrpAuxiliary> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(SOURCE_AUXILIARIES);
    if rows.iter().any(|row| {
        row.source.catalog.base == auxiliary.source.catalog.base
            || row.ticket == auxiliary.ticket
    }) || rows.try_reserve(1).is_err()
    {
        return Err(auxiliary);
    }
    rows.push(auxiliary);
    Ok(())
}

pub(super) unsafe fn contains_exact(
    ticket: ProviderSourceIrpTicket,
    source: ProviderSourceIrpAllocation,
) -> bool {
    let _metadata = ProviderMetadataGuard::acquire();
    contains_exact_unlocked(ticket, source)
}

/// Caller holds the provider metadata lock.
pub(super) unsafe fn contains_exact_unlocked(
    ticket: ProviderSourceIrpTicket,
    source: ProviderSourceIrpAllocation,
) -> bool {
    (&*core::ptr::addr_of!(SOURCE_AUXILIARIES))
        .iter()
        .any(|row| row.ticket == ticket && row.source == source)
}

unsafe fn take_exact(
    ticket: ProviderSourceIrpTicket,
    source: ProviderSourceIrpAllocation,
) -> Option<SourceIrpAuxiliary> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(SOURCE_AUXILIARIES);
    let index = rows
        .iter()
        .position(|row| row.ticket == ticket && row.source == source)?;
    Some(rows.swap_remove(index))
}

/// Once an auxiliary row is removed, cleanup is a commit: any uncertain native
/// release is fatal rather than authorizing a second attempt against a reused VA.
pub(super) unsafe fn retire_exact(
    ticket: ProviderSourceIrpTicket,
    source: ProviderSourceIrpAllocation,
) -> bool {
    let Some(auxiliary) = take_exact(ticket, source) else {
        return false;
    };
    rollback_unpublished(auxiliary);
    true
}

pub(super) unsafe fn rollback_unpublished(auxiliary: SourceIrpAuxiliary) {
    if let Some((_, _, pin)) = auxiliary.output_target {
        file_ioctl_target::release_output(pin);
    }
    if let Some((_, _, pin)) = auxiliary.input_target {
        provider_input::release_input(pin, W32_SOURCE_IOCTL_LABEL);
    }
    if let Some(mdl) = auxiliary.mdl {
        let address = mdl.address();
        if !source_irp::release_system_buffer(mdl) || !provider_pool_free(address) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, address, 0, 18]);
        }
    }
    if let Some(buffer) = auxiliary.system_buffer {
        let address = buffer.address();
        if !source_irp::release_system_buffer(buffer) || !provider_pool_free(address) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, address, 0, 19]);
        }
    }
}
