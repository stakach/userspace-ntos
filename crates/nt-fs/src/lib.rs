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

mod file_backing;
mod directory;
mod fat_directory;
mod fs;
mod hive_provider;
mod path;
mod query;
mod status;

pub use file_backing::FileBacking;
pub use directory::*;
pub use fat_directory::*;
pub use fs::{CreateResult, FileSystem, MemFs, StandardInformation, INVALID_HANDLE};
pub use hive_provider::NtFileHiveIoProvider;
pub use path::{
    is_named_pipe_path, normalize_separators, nt_path_to_volume_relative, MountManager,
    MEMFS_VOLUME,
};
pub use query::*;
pub use status::*;

#[cfg(test)]
mod tests;
