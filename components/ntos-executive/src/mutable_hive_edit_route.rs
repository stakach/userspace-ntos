//! Which owner makes an edit of a mutable (non-SYSTEM) hive durable.
//!
//! NT gives every caller the same durability: a hosted thread's `NtSetValueKey`, a kernel
//! driver's `ZwSetValueKey` and win32k's registry writes all reach the hive log. So the owner
//! depends only on the mounted volume, never on who asked. On the boot block source the edit is
//! journalled inside the call: by the Boot-route WAL on a WAL volume, else by the legacy sidecar.
//! After the volume moves to the native disk stack, only an exact record anchored in the native
//! WAL may publish, so the caller waits in `mutable_hive_mutation_work` with its Reply (hosted)
//! or its parked service lane (driver or win32k). While the boot source drains to the native
//! stack, no WAL entry is admitted.

use nt_fs::BlockSourceKind;

/// `STATUS_DEVICE_NOT_READY`: the edit had no effect and the caller may retry it.
pub(crate) const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EditOwner {
    /// A pre-WAL volume on the boot source: the legacy sidecar journal, inside the call.
    LegacyJournal,
    /// A WAL volume on the boot source: the Boot-route WAL anchors the record inside the call.
    BootWal,
    /// The boot source is draining to the native stack: [`STATUS_DEVICE_NOT_READY`].
    NotReady,
    /// The caller waits in the native WAL work until its exact record is anchored.
    NativeWal,
}

/// The owner of any caller's set-value, delete-value or delete-key edit on the mounted
/// volume's current block route. `wal_volume` is the mounted snapshot format.
pub(crate) const fn edit_owner(route: Option<BlockSourceKind>, wal_volume: bool) -> EditOwner {
    match route {
        Some(BlockSourceKind::Native) => EditOwner::NativeWal,
        Some(BlockSourceKind::Draining) => EditOwner::NotReady,
        Some(BlockSourceKind::Boot) if wal_volume => EditOwner::BootWal,
        Some(BlockSourceKind::Boot) | None => EditOwner::LegacyJournal,
    }
}
