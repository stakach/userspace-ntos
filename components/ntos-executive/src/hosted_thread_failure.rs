//! Constructors remain owned by their original runtime reservation through publication or cleanup.
use super::*;
use nt_user_host::thread_binding::ThreadBinding;
use nt_user_host::thread_construction::{MemoryConstructionProgress, ThreadConstructionInventory};

pub(crate) enum ThreadConstructionError {
    Native(u64),
    Codec(nt_thread_start::amd64_context::CodecError),
    Admission(&'static str),
}

pub(crate) fn record_hosted_thread_construction_failure(
    binding: &ThreadBinding<HostedThreadRole>,
    phase: &'static [u8],
    error: ThreadConstructionError,
    target: u64,
) {
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let (generation_kind, generation) = match binding.process.generation {
        nt_types::ProcessGeneration::Hosted(value) => ("hosted", value),
        nt_types::ProcessGeneration::Temporary(value) => ("temporary", value),
    };
    let _ = write!(record,
        "[thread-construction-failure] pi={} pid={} generation-kind={} generation={} tid={} badge={} phase={} target=0x{:016x}",
        binding.pi, binding.process.pid, generation_kind, generation, binding.tid, binding.badge,
        core::str::from_utf8(phase).expect("static construction phase"), target);
    match error {
        ThreadConstructionError::Native(error) => {
            let _ = write!(record, " error-kind=native error=0x{error:016x}");
        }
        ThreadConstructionError::Codec(error) => {
            let _ = write!(
                record,
                " error-kind=codec error={error:?} status=0x{:08x}",
                error.status()
            );
        }
        ThreadConstructionError::Admission(reason) => {
            let _ = write!(record, " error-kind=admission reason={reason}");
        }
    }
    let _ = writeln!(record);
    sel4_rt::print_record(if record.overflowed() {
        b"[thread-construction-failure] record-truncated\n"
    } else {
        record.bytes()
    });
}

#[derive(Debug)]
pub(crate) enum ThreadReconciliationError {
    OwnerChanged,
    OwnershipConflict,
    Registry(nt_user_host::thread_reconciliation::ReconciliationError),
    Aliases(u32),
}

impl ThreadReconciliationError {
    pub(crate) fn status(&self) -> u32 {
        use nt_user_host::thread_reconciliation::ReconciliationError;
        use nt_user_host::thread_registry::ThreadRegistryError;
        use nt_user_host::thread_rollback::ThreadRollbackError;
        match self {
            Self::Aliases(status) => *status,
            Self::Registry(ReconciliationError::Registry(
                ThreadRegistryError::InsufficientResources
                | ThreadRegistryError::Resources(ThreadRollbackError::InsufficientResources),
            )) => nt_process::STATUS_INSUFFICIENT_RESOURCES,
            Self::OwnerChanged | Self::OwnershipConflict | Self::Registry(_) => {
                nt_process::STATUS_INVALID_PARAMETER
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct RetainedHostedThreadConstruction {
    pub(crate) binding: ThreadBinding<HostedThreadRole>,
    pub(crate) resources: HostedThreadResources,
    pub(crate) construction: ThreadConstructionInventory,
    pub(crate) memory_progress: MemoryConstructionProgress<TP_WORKER_STACK_FRAME_COUNT>,
    pub(crate) teb_alias: u64,
}

/// Unlike the general copy helper, a failed copy returns its still-owned empty slot. The
/// constructor must retain it rather than publish it to a possibly failing recycle list.
pub(crate) unsafe fn copy_thread_construction_cap(source: u64) -> (u64, u64) {
    let Some(slot) = try_alloc_slot() else {
        return (0, 4);
    };
    (slot, copy_cap_into_r(source, slot))
}
