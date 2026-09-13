//! Followups to an already-consumed non-handle File reference.

use crate::*;

pub(crate) fn followup(
    handler: &mut ExecNtHandler,
    release: nt_io_completion::FileReferenceRelease,
) -> Result<(), u32> {
    // Normal body references cannot authorize CLEANUP. close_required describes policy-row
    // retirement, not permission to issue a second driver CLOSE.
    if release.cleanup_required {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    if let Some(port) = release.port_id {
        handler.try_release_io_completion_reference(port)?;
    }
    Ok(())
}
