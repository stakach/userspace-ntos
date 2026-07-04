//! `NtFileHiveIoProvider` (spec §14.1) — the real hive I/O provider that persists a hive image +
//! log through the Zw* file APIs on a mounted file system. This is the seam the M21
//! `nt_hive_core::NtFileHiveIoProvider` stub reserved: with a `FileSystem` present, hive
//! image/log survive a Hive Manager restart (as long as the volume's memory survives, spec §14.3).

use core::cell::RefCell;

use alloc::string::String;
use alloc::vec::Vec;

use nt_hive_core::{HiveIoError, HiveIoProvider, HiveIoProviderKind, HiveIoStatus};

use crate::fs::FileSystem;
use crate::status::*;

/// A hive I/O provider backed by a file on a [`FileSystem`] (spec §14.1). The hive image lives at
/// `hive_path`; the log lives alongside it at `hive_path` + `.LOG`.
pub struct NtFileHiveIoProvider<'a> {
    fs: &'a RefCell<FileSystem>,
    image_path: String,
    log_path: String,
}

impl<'a> NtFileHiveIoProvider<'a> {
    /// Bind a provider to `hive_path` (e.g. `\SystemRoot\System32\Config\SYSTEM`) on `fs`.
    pub fn open(fs: &'a RefCell<FileSystem>, hive_path: &str) -> Self {
        NtFileHiveIoProvider {
            fs,
            image_path: hive_path.into(),
            log_path: alloc::format!("{hive_path}.LOG"),
        }
    }

    /// Read a whole file's bytes (`None` if it doesn't exist / is empty).
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, HiveIoError> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(path, FILE_READ_DATA | SYNCHRONIZE, 0, 0, FILE_OPEN, 0);
        if r.status != STATUS_SUCCESS {
            return Ok(None); // not present yet
        }
        let size = fs
            .zw_query_standard_information(r.handle)
            .map(|i| i.end_of_file)
            .unwrap_or(0);
        if size == 0 {
            fs.zw_close(r.handle);
            return Ok(None);
        }
        let (st, bytes) = fs.zw_read_file(r.handle, Some(0), size as usize);
        fs.zw_close(r.handle);
        if st != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }
        Ok(Some(bytes))
    }

    /// Truncate-or-create `path` and write `bytes`, then flush.
    fn write_file(&self, path: &str, bytes: &[u8]) -> Result<(), HiveIoError> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(
            path,
            FILE_WRITE_DATA | SYNCHRONIZE,
            0,
            0,
            FILE_OVERWRITE_IF,
            0,
        );
        if r.status != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }
        let (st, _) = fs.zw_write_file(r.handle, Some(0), bytes);
        fs.zw_flush_buffers_file(r.handle);
        fs.zw_close(r.handle);
        (st == STATUS_SUCCESS).then_some(()).ok_or(HiveIoError::Io)
    }
}

impl HiveIoProvider for NtFileHiveIoProvider<'_> {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::NtFile
    }
    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        self.read_file(&self.image_path.clone())
    }
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.write_file(&self.image_path.clone(), bytes)
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        Ok(self.read_file(&self.log_path.clone())?.unwrap_or_default())
    }
    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(
            &self.log_path,
            FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE,
            0,
            0,
            FILE_OPEN_IF,
            0,
        );
        if r.status != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }
        let end = fs
            .zw_query_standard_information(r.handle)
            .map(|i| i.end_of_file)
            .unwrap_or(0);
        let (st, _) = fs.zw_write_file(r.handle, Some(end), bytes);
        fs.zw_flush_buffers_file(r.handle);
        fs.zw_close(r.handle);
        (st == STATUS_SUCCESS).then_some(()).ok_or(HiveIoError::Io)
    }
    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.write_file(&self.log_path.clone(), &[])
    }
    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }
    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }
    fn get_status(&self) -> HiveIoStatus {
        let present = self
            .read_file(&self.image_path.clone())
            .ok()
            .flatten()
            .is_some();
        HiveIoStatus {
            image_present: present,
            log_len: 0,
        }
    }
}
