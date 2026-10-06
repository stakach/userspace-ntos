//! Scoped canonical File references for syscall argument capture.

use super::*;
use core::sync::atomic::AtomicBool;
use nt_io_manager::file_io_capture::{FileIoCapture, FileIoCaptureTable};

static mut CAPTURES: FileIoCaptureTable = FileIoCaptureTable::new();
static FAILURES: AtomicU64 = AtomicU64::new(0);
static RETRY_PENDING: AtomicBool = AtomicBool::new(false);

pub(crate) struct Capture(FileIoCapture);

impl Capture {
    pub(crate) fn file_id(&self) -> u64 {
        self.0.file_id().raw()
    }

    pub(crate) fn device_id(&self) -> u64 {
        self.0.device_id().raw()
    }

    pub(crate) fn fs_context(&self) -> u64 {
        self.0.fs_context()
    }

    pub(crate) fn granted_access(&self) -> u32 {
        self.0.granted_access()
    }

    /// Display metadata copied from this retained canonical File, never an image lookup key.
    pub(crate) fn owned_image_path(&self) -> Result<alloc::vec::Vec<u8>, u32> {
        let io = io_manager_mut();
        let file = io.file(FileId(self.file_id())).ok_or(STATUS_INVALID_HANDLE as u32)?;
        if file.device_id.raw() != self.device_id()
            || file.driver_context.unwrap_or(0) != self.fs_context()
        {
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        let units = file.file_name.as_units();
        if units.is_empty() {
            return Err(0xc000_00bbu32);
        }
        let capacity = units.len().checked_mul(3).ok_or(0xc000_009au32)?;
        let mut path = alloc::vec::Vec::new();
        path.try_reserve_exact(capacity).map_err(|_| 0xc000_009au32)?;
        for character in core::char::decode_utf16(units.iter().copied()) {
            let character = character.map_err(|_| 0xc000_000du32)?;
            if character == '\0' {
                return Err(0xc000_000du32);
            }
            let mut bytes = [0u8; 4];
            path.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
        }
        Ok(path)
    }
}

pub(crate) fn capture(file_id: u64, device_id: u64, granted_access: u32) -> Result<Capture, u32> {
    let _durable = crate::allocator::enter_durable();
    let io = io_manager_mut();
    let file = io
        .file(FileId(file_id))
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    if file.client_id != ClientId(IO_MANAGER_COMPONENT_ID) {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CAPTURES))
            .capture(
                io,
                FileId(file_id),
                nt_io_manager::DeviceId(device_id),
                granted_access,
            )
            .map(Capture)
            .map_err(|status| status.raw() as u32)
    }
}

/// The native Section caller has already authenticated a real file handle in its own table.
/// Its source token supplies the granted access; the canonical File reference still validates
/// the exact open FileId and device before surviving provider metadata I/O.
pub(crate) fn capture_native_section_source(
    source: nt_process::NativeSectionFileSource,
) -> Result<Capture, u32> {
    let nt_process::HandleObject::RoutedFile { file_id, device_id } = source.object() else {
        return Err(STATUS_INVALID_HANDLE as u32);
    };
    let _durable = crate::allocator::enter_durable();
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CAPTURES))
            .capture(
                io_manager_mut(),
                FileId(file_id),
                nt_io_manager::DeviceId(device_id),
                source.granted_access(),
            )
            .map(Capture)
            .map_err(|status| status.raw() as u32)
    }
}

/// Extend an existing canonical pointer/IRP lifetime across a transaction continuation.
pub(crate) fn capture_owned(
    file_id: u64,
    device_id: u64,
    granted_access: u32,
) -> Result<Capture, u32> {
    let _durable = crate::allocator::enter_durable();
    let io = io_manager_mut();
    let file = io
        .file(FileId(file_id))
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    if file.client_id != ClientId(IO_MANAGER_COMPONENT_ID) {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CAPTURES))
            .capture_owned(
                io,
                FileId(file_id),
                nt_io_manager::DeviceId(device_id),
                granted_access,
            )
            .map(Capture)
            .map_err(|status| status.raw() as u32)
    }
}

fn report(file: u64, status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[file-capture] reference retirement retained file=0x");
        print_hex64(file);
        print_str(b" status=0x");
        print_hex64(status as u64);
        print_str(b"\n");
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            let table = &mut *core::ptr::addr_of_mut!(CAPTURES);
            let identity = self.0.identity();
            // Retirement cannot allocate or call a driver. A refused canonical release
            // keeps the FileReference in its admitted row for the ordinary manager pump.
            table
                .retire(&mut self.0)
                .expect("File capture lost its exact active owner");
            if let Err(status) = table.release_retired(io_manager_mut(), identity) {
                RETRY_PENDING.store(true, Ordering::Release);
                report(self.file_id(), status.raw() as u32);
            }
        }
    }
}

pub(super) fn redrive(io: &mut ExecutiveIoManager) {
    if !RETRY_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    unsafe {
        let report = (&mut *core::ptr::addr_of_mut!(CAPTURES)).redrive(io, 64);
        if report.refused != 0 || report.attempted == 64 {
            RETRY_PENDING.store(true, Ordering::Release);
        }
    }
}
