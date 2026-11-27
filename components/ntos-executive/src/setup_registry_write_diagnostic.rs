//! Read-only evidence for the dynamic setup child's two SYSTEM Setup writes.

use crate::*;
use nt_hosted_runtime::{AckedSetupWrite, SetupOwnerIdentity, SetupValueName,
    SetupWriteCandidate, SetupWriteStorage};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

static CM_ACK_REPORTS: AtomicU64 = AtomicU64::new(0);
const MAX_REPORTS: u64 = 32;

pub(crate) fn capture(
    handler: &ExecNtHandler,
    logical: ProviderLogicalCaller,
    path: &str,
    name: &str,
    value_type: u32,
    data: &[u8],
) -> Option<SetupWriteCandidate> {
    let process = logical.process();
    let nt_types::ProcessGeneration::Hosted(generation) = process.generation else { return None; };
    SetupWriteCandidate::capture_lazy(
        SetupOwnerIdentity { process_index: logical.pi(), pid: process.pid, generation },
        path, name, value_type, data,
        || {
            (handler.capture_process_identity(logical.pi()) == Some(process))
                .then(|| native_process_time_census::observed_logon_child_identity(handler))
                .flatten()
        },
    )
}

/// A successful CM ACK is a mutation receipt, not proof of an anchored batch.
pub(crate) unsafe fn cm_acked(work_id: u64, acked: AckedSetupWrite, status: u32, cancelled: bool) {
    if CM_ACK_REPORTS.fetch_add(1, Ordering::Relaxed) >= MAX_REPORTS { return; }
    let candidate = acked.candidate();
    print_str(b"[setup-registry-write] stage=cm-acked id/pi/pid/gen=");
    for (index, value) in [work_id, candidate.owner().process_index as u64,
        u64::from(candidate.owner().pid), candidate.owner().generation]
        .into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    print_str(b" name=");
    print_str(match candidate.name() {
        SetupValueName::SystemSetupInProgress => b"SystemSetupInProgress",
        SetupValueName::SetupType => b"SetupType",
    });
    print_str(b" value="); print_u64(u64::from(candidate.value()));
    print_str(b" cm-generation="); print_u64(acked.generation());
    print_str(b" storage=");
    match acked.storage() {
        SetupWriteStorage::PerRow => print_str(b"per-row"),
        SetupWriteStorage::Batch { epoch, cm_mount } => {
            print_str(b"batch epoch/cm-mount=");
            print_u64(epoch); print_str(b"/"); print_u64(cm_mount);
            let watched = writable_fs::system_wal_batch_native::watch_setup_generation(
                epoch, cm_mount, acked.generation());
            print_str(b" watch="); print_u64(u64::from(watched));
        }
    }
    print_str(b" status=0x"); print_hex(status);
    print_str(b" cancelled="); print_u64(u64::from(cancelled)); print_str(b"\n");
}
