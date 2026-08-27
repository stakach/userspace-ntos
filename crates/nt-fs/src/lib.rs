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

mod directory;
mod fat_directory;
mod file_backing;
mod fs;
mod hive_provider;
mod path;
mod query;
mod snapshot_store;
mod status;

pub use directory::*;
pub use fat_directory::*;
pub use file_backing::FileBacking;
pub use fs::{
    parse_file_basic_information_attributes, parse_set_file_name_information, CreateResult,
    installed_file_open_action, FileMetadata, FileRenameRoot, FileSystem,
    InstalledFileOpenAction, MemFs, MemFsBlobCompactError, MemFsBlobCompaction,
    MemFsSnapshotError, MemFsSnapshotInfo, SetFileNameInformation, StandardInformation,
    INVALID_HANDLE,
};
pub use hive_provider::NtFileHiveIoProvider;
pub use path::{
    is_named_pipe_path, is_under_prefix, normalize_separators, nt_file_relative_path_into,
    nt_path_to_volume_relative, nt_path_to_volume_relative_into, writable_mount_relative,
    writable_mount_relative_into, MountManager, DOS_DRIVE_FIXED, MEMFS_VOLUME,
};
pub use query::*;
pub use snapshot_store::{
    PayloadSectorReader, PayloadSectorWriter, SnapshotBlockDevice, SnapshotBlockStore,
    SnapshotBlockStoreError, SnapshotPayloadReader, SnapshotPayloadSink, StoredSnapshot,
};
pub use status::*;

#[cfg(test)]
mod tests;
