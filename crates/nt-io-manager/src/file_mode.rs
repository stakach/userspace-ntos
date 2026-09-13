//! Canonical mutable File mode, independent of the original CREATE options.

use crate::CreateOptions;
use nt_io_completion::FileIoMode;
use nt_status::NtStatus;

const SYNCHRONOUS: u32 = nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT;
const VALID_SET_FLAGS: u32 = nt_fs::FILE_WRITE_THROUGH | nt_fs::FILE_SEQUENTIAL_ONLY | SYNCHRONOUS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileModeState {
    bits: u32,
}

impl FileModeState {
    /// Capture initial mode without changing CREATE admission. Invalid simultaneous sync flags
    /// remain observable, but cannot become an I/O policy or an accepted mode transition.
    pub const fn from_create_options(options: CreateOptions) -> Self {
        Self {
            bits: nt_fs::file_mode_from_create_options(options.bits()),
        }
    }

    pub const fn query_bits(self) -> u32 {
        self.bits
    }

    /// Translate already-admitted canonical mode, not a fresh handle grant.
    pub fn io_mode(self) -> Result<FileIoMode, NtStatus> {
        match self.bits & SYNCHRONOUS {
            0 => Ok(FileIoMode::Asynchronous),
            nt_fs::FILE_SYNCHRONOUS_IO_ALERT => Ok(FileIoMode::SynchronousAlertable),
            nt_fs::FILE_SYNCHRONOUS_IO_NONALERT => Ok(FileIoMode::SynchronousNonAlertable),
            _ => Err(NtStatus::INVALID_PARAMETER),
        }
    }

    /// Canonical mode bits in NT FILE_OBJECT.Flags numbering, not the provider's full Flags word.
    pub fn wdm_mode_flags(self) -> Result<u32, NtStatus> {
        let io_mode = self.io_mode()?;
        let mut flags = 0;
        if io_mode.is_synchronous() {
            flags |= 0x0000_0002;
        }
        if io_mode.is_alertable() {
            flags |= 0x0000_0004;
        }
        if self.bits & nt_fs::FILE_NO_INTERMEDIATE_BUFFERING != 0 {
            flags |= 0x0000_0008;
        }
        if self.bits & nt_fs::FILE_WRITE_THROUGH != 0 {
            flags |= 0x0000_0010;
        }
        if self.bits & nt_fs::FILE_SEQUENTIAL_ONLY != 0 {
            flags |= 0x0000_0020;
        }
        if self.bits & nt_fs::FILE_DELETE_ON_CLOSE != 0 {
            flags |= 0x0001_0000;
        }
        Ok(flags)
    }

    /// NT5 FileModeInformation permits only mask 0x36. Sync-vs-async, unbuffered, and
    /// delete-on-close state cannot change; unbuffered Files also retain write-through.
    pub fn transition(self, requested: u32) -> Result<Self, NtStatus> {
        let was_synchronous = self.io_mode()?.is_synchronous();
        let requested_sync = requested & SYNCHRONOUS;
        if requested & !VALID_SET_FLAGS != 0
            || requested_sync == SYNCHRONOUS
            || (requested_sync != 0) != was_synchronous
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mut mutable = nt_fs::FILE_SEQUENTIAL_ONLY | SYNCHRONOUS;
        if self.bits & nt_fs::FILE_NO_INTERMEDIATE_BUFFERING == 0 {
            mutable |= nt_fs::FILE_WRITE_THROUGH;
        }
        Ok(Self {
            bits: (self.bits & !mutable) | (requested & mutable),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_valid_initial_mode_and_low_byte_request_matches_nt5_transition_rules() {
        let flags = [2, 4, 8, 16, 32, 0x1000];
        for combination in 0..64 {
            let initial = flags.iter().enumerate().fold(0, |bits, (index, flag)| {
                bits | if combination & (1 << index) != 0 {
                    *flag
                } else {
                    0
                }
            });
            let state =
                FileModeState::from_create_options(CreateOptions::from_bits_retain(initial));
            assert_eq!(state.query_bits(), initial);
            for request in 0..256 {
                let valid = initial & 0x30 != 0x30
                    && request & !0x36 == 0
                    && request & 0x30 != 0x30
                    && (initial & 0x30 != 0) == (request & 0x30 != 0);
                let result = state.transition(request);
                if !valid {
                    assert_eq!(result, Err(NtStatus::INVALID_PARAMETER));
                    continue;
                }
                let next = result.unwrap();
                let expected = (initial & (8 | 0x1000))
                    | (request & 0x34)
                    | if initial & 8 != 0 {
                        initial & 2
                    } else {
                        request & 2
                    };
                assert_eq!(next.query_bits(), expected);
                assert_eq!(
                    next.io_mode().unwrap().is_synchronous(),
                    initial & 0x30 != 0
                );
                assert_eq!(state.query_bits(), initial);
            }
        }
    }

    #[test]
    fn every_high_request_bit_is_rejected_without_a_transition() {
        for options in [
            CreateOptions::empty(),
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ] {
            let state = FileModeState::from_create_options(options);
            for bit in 8..32 {
                assert_eq!(
                    state.transition(options.bits() | (1 << bit)),
                    Err(NtStatus::INVALID_PARAMETER)
                );
                assert_eq!(state.query_bits(), options.bits());
            }
        }
    }

    #[test]
    fn wdm_mode_flags_use_nt_bits_and_reject_invalid_sync_state() {
        for (options, flags) in [
            (0, 0),
            (2, 0x10),
            (4, 0x20),
            (8, 8),
            (0x10, 6),
            (0x20, 2),
            (0x1000, 0x10000),
            (0x101e, 0x1003e),
        ] {
            assert_eq!(
                FileModeState::from_create_options(CreateOptions::from_bits_retain(options),)
                    .wdm_mode_flags(),
                Ok(flags)
            );
        }
        assert_eq!(
            FileModeState::from_create_options(
                CreateOptions::SYNCHRONOUS_IO_ALERT | CreateOptions::SYNCHRONOUS_IO_NONALERT,
            )
            .wdm_mode_flags(),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn original_options_are_filtered_and_invalid_initial_sync_is_not_normalized() {
        let state = FileModeState::from_create_options(CreateOptions::from_bits_retain(u32::MAX));
        assert_eq!(state.query_bits(), 0x103e);
        assert_eq!(state.io_mode(), Err(NtStatus::INVALID_PARAMETER));
        assert_eq!(state.transition(0x20), Err(NtStatus::INVALID_PARAMETER));
        let alert = FileModeState::from_create_options(CreateOptions::SYNCHRONOUS_IO_ALERT);
        assert_eq!(alert.io_mode(), Ok(FileIoMode::SynchronousAlertable));
        assert_eq!(
            alert.transition(0x20).unwrap().io_mode(),
            Ok(FileIoMode::SynchronousNonAlertable)
        );
    }
}
