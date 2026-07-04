//! `FileBacking` (spec §22.5) — a Cache Manager backing store over a file on a [`FileSystem`],
//! so a `SharedCacheMap` can cache a MemFs file's bytes through the Zw* APIs.

use core::cell::RefCell;

use alloc::string::String;

use nt_cache_manager::CachedStreamBacking;

use crate::fs::FileSystem;
use crate::status::*;

/// A cache backing bound to a file path on `fs` (spec §22.5). `read_at`/`write_at` operate on the
/// file's bytes through `ZwReadFile`/`ZwWriteFile`; `flush` is `ZwFlushBuffersFile`.
pub struct FileBacking<'a> {
    fs: &'a RefCell<FileSystem>,
    path: String,
}

impl<'a> FileBacking<'a> {
    pub fn open(fs: &'a RefCell<FileSystem>, path: &str) -> Self {
        FileBacking {
            fs,
            path: path.into(),
        }
    }
}

impl CachedStreamBacking for FileBacking<'_> {
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, u32> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(&self.path, FILE_READ_DATA, 0, 0, FILE_OPEN, 0);
        if r.status != STATUS_SUCCESS {
            return Ok(0); // no file yet → nothing to read
        }
        let (st, bytes) = fs.zw_read_file(r.handle, Some(offset), dst.len());
        fs.zw_close(r.handle);
        match st {
            STATUS_SUCCESS => {
                let n = bytes.len().min(dst.len());
                dst[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            STATUS_END_OF_FILE => Ok(0),
            e => Err(e),
        }
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> Result<usize, u32> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(&self.path, FILE_WRITE_DATA, 0, 0, FILE_OPEN_IF, 0);
        if r.status != STATUS_SUCCESS {
            return Err(r.status);
        }
        let (st, n) = fs.zw_write_file(r.handle, Some(offset), src);
        fs.zw_close(r.handle);
        (st == STATUS_SUCCESS).then_some(n).ok_or(st)
    }

    fn flush(&mut self) -> Result<(), u32> {
        let mut fs = self.fs.borrow_mut();
        let r = fs.zw_create_file(&self.path, FILE_READ_DATA, 0, 0, FILE_OPEN_IF, 0);
        if r.status != STATUS_SUCCESS {
            return Err(r.status);
        }
        let st = fs.zw_flush_buffers_file(r.handle);
        fs.zw_close(r.handle);
        (st == STATUS_SUCCESS).then_some(()).ok_or(st)
    }

    fn set_file_size(&mut self, _file_size: u64) -> Result<(), u32> {
        // MemFs grows on write + has no truncate-to API in v0.1; the cache tracks the logical
        // size and only writes valid bytes, so this is a trace-only no-op (spec §22.4).
        Ok(())
    }
}
