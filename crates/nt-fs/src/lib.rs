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
mod fs;
mod hive_provider;
mod path;
mod status;

pub use file_backing::FileBacking;
pub use fs::{CreateResult, FileSystem, MemFs, StandardInformation, INVALID_HANDLE};
pub use hive_provider::NtFileHiveIoProvider;
pub use path::{normalize_separators, MountManager, MEMFS_VOLUME};
pub use status::*;

#[cfg(test)]
mod tests;
