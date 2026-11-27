//! One exact, preflighted FileBasic publication: primary delivery row plus prepared sidecar.

use super::*;

pub(super) unsafe fn publish_basic_preflighted(
    table: &mut nt_io_manager::PendingFileIoTable,
    primary: nt_io_manager::PendingBasicPrimaryReservation,
    sidecar: nt_io_manager::PendingBasicPreparedReservation,
    pending: nt_io_manager::PendingFileIo,
    owner: nt_io_manager::PendingBasicPreparedOwner<crate::writable_fs::BasicFileReference>,
) -> nt_io_manager::PendingFileIoIdentity {
    // `try_set_local_file_information` validated this exact move-only primary, the reserved
    // sidecar, the canonical Basic and inline shapes, Busy, and the reserved Reply before its
    // extra File retain or signal reset. The native tail does not call out or mutate either table
    // before this combined commit. No fallback publication can repair a broken exact claim.
    match (&mut *core::ptr::addr_of_mut!(PENDING_BASIC_PREPARED))
        .try_admit_pre_reserved_exact(table, sidecar, primary, pending, owner)
    {
        Ok(identity) => {
            crate::pending_file_caller::publish_identity(identity, pending);
            identity
        }
        Err((reason, row, owner, primary, sidecar)) => {
            use nt_io_manager::{PendingBasicPreparedAdmissionError as BasicError,
                PendingFileIoParkError as ParkError};
            let diagnostic = match reason {
                BasicError::SidecarUnavailable => 1,
                BasicError::PendingRow(ParkError::StaleReservation) => 2,
                BasicError::PendingRow(ParkError::OccupiedReservation) => 3,
                BasicError::PendingRow(ParkError::InvalidRecord) => 4,
                BasicError::PendingRow(ParkError::DuplicateIrp) => 5,
            };
            print_str(b"[basic-preflight-invariant] reason/slot/reply=");
            print_u64(diagnostic);
            print_str(b"/"); print_u64(primary.identity().slot() as u64);
            print_str(b"/"); print_u64(row.reply_cap);
            print_str(b"\n");
            // An internal mutation after the pre-effect proof is corruption, not a guest
            // admission refusal. Do not drop a File or reuse a Reply/claim while reporting it.
            core::mem::forget((owner, primary, sidecar));
            panic!("preflighted Basic File owner changed before its atomic commit");
        }
    }
}
