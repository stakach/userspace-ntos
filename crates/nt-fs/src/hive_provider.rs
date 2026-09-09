//! `NtFileHiveIoProvider` (spec §14.1) — the real hive I/O provider that persists a hive image +
//! log through the Zw* file APIs on a mounted file system. With a `FileSystem` present, hive
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

    fn with_read_file<T>(
        &self,
        path: &str,
        read: impl FnOnce(&FileSystem) -> Result<Option<T>, u32>,
    ) -> Result<Option<T>, HiveIoError> {
        let mut fs = self.fs.try_borrow_mut().map_err(|_| HiveIoError::Io)?;
        // A missing parent is not an absent hive. Keep the checked probe and the admitted open
        // under one exclusive volume borrow, including the subsequent extent copy and close.
        if fs
            .try_file_len(path)
            .map_err(|_| HiveIoError::Io)?
            .is_none()
        {
            return Ok(None);
        }
        let opened = fs.zw_create_file(
            path,
            FILE_READ_DATA | SYNCHRONIZE,
            0,
            0,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        );
        if opened.status != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }
        let result = read(&fs).map_err(|_| HiveIoError::Io);
        let close = fs.zw_close(opened.handle);
        if close != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }
        result
    }

    /// Read a whole file without converting wrong-kind, allocation, or storage errors to absence.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, HiveIoError> {
        self.with_read_file(path, |fs| fs.try_file_bytes_owned(path))
    }

    fn file_size(&self, path: &str) -> Result<Option<usize>, HiveIoError> {
        self.with_read_file(path, |fs| fs.try_file_len(path))?
            .map(|len| usize::try_from(len).map_err(|_| HiveIoError::Io))
            .transpose()
    }

    fn rename_information(
        replace_if_exists: bool,
        root_directory: u64,
        target_path: &str,
    ) -> Result<Vec<u8>, HiveIoError> {
        let units = target_path.encode_utf16().count();
        let name_len = units.checked_mul(2).ok_or(HiveIoError::Io)?;
        let name_len_u32 = u32::try_from(name_len).map_err(|_| HiveIoError::Io)?;
        let total_len = 20usize.checked_add(name_len).ok_or(HiveIoError::Io)?;
        let mut info = Vec::new();
        info.try_reserve_exact(total_len)
            .map_err(|_| HiveIoError::Io)?;
        info.resize(20, 0);
        info[0] = u8::from(replace_if_exists);
        info[8..16].copy_from_slice(&root_directory.to_le_bytes());
        info[16..20].copy_from_slice(&name_len_u32.to_le_bytes());
        for unit in target_path.encode_utf16() {
            info.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(info)
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
        self.read_file(&self.image_path)
    }
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        let tmp_path = alloc::format!("{}.TMP", self.image_path);
        self.write_file(&tmp_path, bytes)?;

        let rename = Self::rename_information(true, 0, &self.image_path)?;
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(&tmp_path, FILE_WRITE_DATA | SYNCHRONIZE, 0, 0, FILE_OPEN, 0);
        if r.status != STATUS_SUCCESS {
            return Err(HiveIoError::Io);
        }

        let status = fs.zw_set_information_file(r.handle, FILE_RENAME_INFORMATION, &rename);
        if status != STATUS_SUCCESS {
            let _ = fs.zw_set_information_file(r.handle, FILE_DISPOSITION_INFORMATION, &[1]);
            fs.zw_close(r.handle);
            return Err(HiveIoError::Io);
        }
        let _ = fs.zw_flush_buffers_file(r.handle);
        fs.zw_close(r.handle);
        Ok(())
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        Ok(self.read_file(&self.log_path)?.unwrap_or_default())
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
        let (st, written) = fs.zw_append_file(r.handle, bytes);
        fs.zw_flush_buffers_file(r.handle);
        fs.zw_close(r.handle);
        (st == STATUS_SUCCESS && written == bytes.len())
            .then_some(())
            .ok_or(HiveIoError::Io)
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
    fn get_status(&self) -> Result<HiveIoStatus, HiveIoError> {
        let image_len = self.file_size(&self.image_path)?;
        let log_len = self.file_size(&self.log_path)?.unwrap_or(0);
        Ok(HiveIoStatus {
            image_present: image_len.is_some(),
            log_len,
        })
    }
}
