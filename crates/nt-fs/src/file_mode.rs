//! Mutable FILE_OBJECT mode, distinct from immutable CREATE admission options.

use nt_io_completion::FileIoMode;
use nt_status::NtStatus;

const SYNCHRONOUS: u32 = crate::FILE_SYNCHRONOUS_IO_ALERT | crate::FILE_SYNCHRONOUS_IO_NONALERT;
const VALID_SET_FLAGS: u32 = crate::FILE_WRITE_THROUGH | crate::FILE_SEQUENTIAL_ONLY | SYNCHRONOUS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileModeState {
    bits: u32,
}

impl FileModeState {
    pub const fn from_create_options(options: u32) -> Self {
        Self { bits: crate::file_mode_from_create_options(options) }
    }

    pub const fn query_bits(self) -> u32 { self.bits }

    pub fn io_mode(self) -> Result<FileIoMode, NtStatus> {
        match self.bits & SYNCHRONOUS {
            0 => Ok(FileIoMode::Asynchronous),
            crate::FILE_SYNCHRONOUS_IO_ALERT => Ok(FileIoMode::SynchronousAlertable),
            crate::FILE_SYNCHRONOUS_IO_NONALERT => Ok(FileIoMode::SynchronousNonAlertable),
            _ => Err(NtStatus::INVALID_PARAMETER),
        }
    }

    /// Translate only mode-owned bits; all unrelated provider FILE_OBJECT flags remain owned
    /// by the provider when these bits are published.
    pub fn wdm_mode_flags(self) -> Result<u32, NtStatus> {
        let io_mode = self.io_mode()?;
        let mut flags = 0;
        if io_mode.is_synchronous() { flags |= 0x0000_0002; }
        if io_mode.is_alertable() { flags |= 0x0000_0004; }
        if self.bits & crate::FILE_NO_INTERMEDIATE_BUFFERING != 0 { flags |= 0x0000_0008; }
        if self.bits & crate::FILE_WRITE_THROUGH != 0 { flags |= 0x0000_0010; }
        if self.bits & crate::FILE_SEQUENTIAL_ONLY != 0 { flags |= 0x0000_0020; }
        if self.bits & crate::FILE_DELETE_ON_CLOSE != 0 { flags |= 0x0001_0000; }
        Ok(flags)
    }

    /// NT5 permits mask 0x36 only. Sync-vs-async, unbuffered and delete-on-close cannot
    /// change; an unbuffered File also retains its original write-through state.
    pub fn transition(self, requested: u32) -> Result<Self, NtStatus> {
        let was_synchronous = self.io_mode()?.is_synchronous();
        let requested_sync = requested & SYNCHRONOUS;
        if requested & !VALID_SET_FLAGS != 0
            || requested_sync == SYNCHRONOUS
            || (requested_sync != 0) != was_synchronous
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mut mutable = crate::FILE_SEQUENTIAL_ONLY | SYNCHRONOUS;
        if self.bits & crate::FILE_NO_INTERMEDIATE_BUFFERING == 0 {
            mutable |= crate::FILE_WRITE_THROUGH;
        }
        Ok(Self { bits: (self.bits & !mutable) | (requested & mutable) })
    }
}
