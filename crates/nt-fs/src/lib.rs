//! # `nt-fs` — NT File Object + File System Runtime
//!
//! The NT filesystem layer (spec: NT File Object + File System Runtime): an NT path/mount
//! resolver ([`MountManager`]), an in-memory file system ([`MemFs`]) implementing the native
//! [`NtFileSystemRuntime`] semantics, the Zw* native file API surface on a [`FileSystem`] facade
//! (`ZwCreateFile`/`ZwReadFile`/`ZwWriteFile`/`ZwFlushBuffersFile`/`ZwQueryInformationFile`/
//! `ZwClose`), and a real [`NtFileHiveIoProvider`] that persists a hive image + log through those
//! file APIs — the storage seam the M21 Hive Manager stub reserved. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

mod byte_lock;
mod directory;
mod fat_directory;
mod fat_directory_walk;
mod file_backing;
mod flush;
mod fs;
mod hive_provider;
mod layered_directory;
mod layered_open;
mod notify;
mod partition;
mod path;
mod query;
mod snapshot_store;
mod snapshot_reserve;
#[cfg(test)]
mod snapshot_test_device;
mod status;
mod volume;

pub use byte_lock::*;
pub use directory::*;
pub use fat_directory::*;
pub use fat_directory_walk::*;
pub use file_backing::FileBacking;
pub use flush::file_flush_access_allowed;
pub use fs::{
    installed_file_open_action, layered_file_open_decision,
    parse_file_basic_information_attributes,
    parse_move_cluster_information, parse_set_file_name_information, parse_short_name_information,
    validate_file_create_parameters, CreateResult, FileCleanupEffects, FileIoState, FileMetadata,
    FileObjectInformation, FileOpenPrivileges, FileRenameRoot, FileShareAccess, FileSystem,
    InstalledFileOpenAction, LayeredFileOpenDecision, MemFs, MemFsBlobCompactError,
    MemFsBlobCompaction, MemFsSnapshotError,
    MemFsSnapshotInfo, MoveClusterInformation, SetFileNameInformation, StandardInformation,
    INVALID_HANDLE, SnapshotJournal, SnapshotJournalDurability, SnapshotJournalError,
    SnapshotJournalOpenError, SnapshotJournalPhase, OwnedSnapshotJournal, OwnedSnapshotJournalOpenError,
};
pub use hive_provider::NtFileHiveIoProvider;
pub use layered_directory::merge_layered_directory_entries;
pub use layered_open::{
    LayeredOpenContextId, LayeredOpenRecord, LayeredOpenSource, LayeredOpenTable,
    LAYERED_OPEN_NAME_CAP,
};
pub use notify::*;
pub use partition::*;
pub use path::{
    is_named_pipe_path, is_under_prefix, normalize_separators, nt_file_relative_path_into,
    nt_path_to_volume_relative, nt_path_to_volume_relative_into, writable_mount_relative,
    writable_mount_relative_into, MountError, MountManager, DOS_DRIVE_FIXED, MEMFS_VOLUME,
};
pub use query::*;
pub use snapshot_store::{
    PayloadSectorReader, PayloadSectorWriter, SnapshotBlockDevice, SnapshotBlockStore,
    SnapshotBlockStoreError, SnapshotPayloadReader, SnapshotPayloadSink, StoredSnapshot,
};
pub use snapshot_reserve::{SnapshotReserve, SnapshotReserveLease};
pub use status::*;
pub use volume::*;

#[cfg(test)]
mod tests;
