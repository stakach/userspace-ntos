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
mod boot_paths;
mod async_block_route;
mod bounded_read;
mod directory;
mod fat_directory;
mod fat_directory_walk;
mod fat_path_lookup;
mod fat_directory_lookup;
mod fat_range_lookup;
mod fat_overlay_prepare;
mod fat_range_cursor;
mod fat_sector_cache;
mod file_backing;
mod file_mode;
mod flush;
mod fs;
mod hive_provider;
mod installation_root;
mod layered_directory;
mod layered_directory_open;
mod layered_open;
mod notify;
mod partition;
mod path;
mod query;
mod snapshot_store;
mod snapshot_reserve;
mod snapshot_region;
mod registry_wal_store;
mod hive_wal_publication;
mod volume_wal_payload;
#[cfg(test)]
mod snapshot_test_device;
mod status;
mod volume;

pub use byte_lock::*;
pub use boot_paths::*;
pub use async_block_route::*;
pub use bounded_read::published_file_size;
pub use directory::*;
pub use fat_directory::*;
pub use fat_directory_walk::*;
pub use fat_path_lookup::*;
pub use fat_directory_lookup::*;
pub use fat_range_lookup::*;
pub use fat_overlay_prepare::*;
pub use fat_range_cursor::{FatRangeBatch, FatRangeCursor, FatRangeCursorSet};
pub use fat_sector_cache::FatSectorCache;
pub use file_backing::FileBacking;
pub use file_mode::FileModeState;
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
pub use installation_root::*;
pub use layered_directory::merge_layered_directory_entries;
pub use layered_directory_open::{layered_directory_open_decision, LayeredDirectoryOpenDecision};
pub use layered_open::{
    join_layered_relative_name_into, LayeredOpenContextId, LayeredOpenRecord, LayeredOpenSource,
    LayeredOpenTable, LAYERED_OPEN_NAME_CAP,
};
pub use notify::*;
pub use partition::*;
pub use path::{
    is_named_pipe_path, is_under_prefix, normalize_separators, nt_file_relative_path_into,
    nt_path_to_volume_relative, nt_path_to_volume_relative_into, writable_mount_relative,
    writable_mount_relative_into, process_device_map_from_links, MountError, MountManager,
    DOS_DRIVE_FIXED, MEMFS_VOLUME,
};
pub use query::*;
pub use snapshot_store::{
    AnchoredWalPublication, AsyncSnapshotCommit, AsyncSnapshotCommitError, AsyncSnapshotHeaderRecheck,
    AsyncSnapshotIoKind, AsyncSnapshotRequest, AsyncWalSnapshotAnchorUpdate, AsyncWalEpochRollover,
    RecheckedPairedWalSnapshot, BootSnapshotRecovery,
    PayloadSectorReader, PayloadSectorWriter, SnapshotBlockDevice, SnapshotBlockStore,
    SnapshotBlockStoreError, SnapshotPayloadReader, SnapshotPayloadSink, SnapshotReadFormat,
    StoredSnapshot, StoredSnapshotMetadata, StoredWalSnapshot, WalSnapshotAnchor,
    WalSnapshotAnchorUpdate, WalSnapshotEpochRollover, WalSnapshotManifest, VerifiedPairedWalSnapshot,
};
pub use snapshot_reserve::{SnapshotReserve, SnapshotReserveLease};
pub use snapshot_region::{BoundedBlockRange, OwnedBoundedBlockRange};
pub use registry_wal_store::{AsyncWalIoKind, AsyncWalIoRequest, AsyncWalRefusal, RegistryWal, RegistryWalContinuation, RegistryWalError, RegistryWalRecord, RegistryWalState, RegistryWalVerifiedDevice, RegistryWalVerifiedPrefix};
pub use hive_wal_publication::{publish_anchored_hive_value, HiveWalPublicationError, HiveWalPublicationRefusal};
pub use volume_wal_payload::{decode_volume_wal_payload, encode_hive_log_wal_payload, HiveLogWalPayload, HiveLogWalReplay, HiveLogWalReplayError, VolumeWalPayload, VolumeWalPayloadError};
mod snapshot_baseline_repair;
pub use snapshot_baseline_repair::WalSnapshotBaselineRepair;
pub use status::*;
pub use volume::*;

#[cfg(test)]
mod tests;
