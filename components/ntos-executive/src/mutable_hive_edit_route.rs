//! Which owner makes a hosted caller's edit of a mutable (non-SYSTEM) hive durable.
//!
//! On the boot block source, the synchronous hive journal serves the edit inside the call.
//! After the volume moves to the native disk stack, only an exact record anchored in the native
//! WAL may publish. The legacy sidecar append refuses there. So the caller and its Reply wait in
//! `mutable_hive_mutation_work` until the record is anchored. While the boot source drains
//! to the native stack, no WAL entry is admitted.

use nt_fs::BlockSourceKind;

/// `STATUS_DEVICE_NOT_READY`: the edit had no effect and the caller may retry it.
pub(crate) const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostedEditOwner {
    /// The synchronous journal (legacy sidecar or boot WAL) serves the edit inside the call.
    Synchronous,
    /// The boot source is draining to the native stack: [`STATUS_DEVICE_NOT_READY`].
    NotReady,
    /// The caller waits in the native WAL work until its exact record is anchored.
    NativeWal,
}

/// The owner for a hosted edit on the mounted volume's current block route.
pub(crate) const fn hosted_edit_owner(route: Option<BlockSourceKind>) -> HostedEditOwner {
    match route {
        Some(BlockSourceKind::Native) => HostedEditOwner::NativeWal,
        Some(BlockSourceKind::Draining) => HostedEditOwner::NotReady,
        Some(BlockSourceKind::Boot) | None => HostedEditOwner::Synchronous,
    }
}
