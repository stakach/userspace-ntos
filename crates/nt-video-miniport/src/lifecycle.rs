//! Per-Device VideoPort discovery and first-open initialization policy.
//!
//! The native owner atomically publishes the first eight serialized bytes before entering a
//! miniport callback. No enum is loaded directly from guest memory, and no transition resets a
//! previously completed initialization. PnP restart needs its own explicit lifetime protocol.

use core::sync::atomic::{AtomicU64, Ordering};

pub const VIDEO_PORT_DEVICE_STATE_SIZE: usize = 16;

const STATUS_SUCCESS: u32 = 0;
const STATUS_DEVICE_CONFIGURATION_ERROR: u32 = 0xC000_0182;
const FILE_OPEN: u64 = 1;
const FILE_READ_ATTRIBUTES: u32 = 0x80;

/// VideoPort exposes only the three public brightness controls to user-mode requestors.
/// The native caller must supply the captured IRP RequestorMode, not infer it from the IOCTL.
pub fn validate_device_control_requestor(requestor_mode: u8, code: u32) -> Result<(), u32> {
    match requestor_mode {
        0 => Ok(()),
        1 if matches!(code, 0x0023_0494 | 0x0023_0498 | 0x0023_049C) => Ok(()),
        1 => Err(0xC000_0022), // STATUS_ACCESS_DENIED
        _ => Err(0xC000_000D), // STATUS_INVALID_PARAMETER
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoAdapterDiscoveryState {
    NotCalled,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoHardwareInitializationState {
    NotCalled,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoPortLifecycleError {
    BufferTooSmall { needed: usize },
    InvalidSnapshot,
    InvalidRequestorMode,
    InvalidTransition,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoOpenCompletion {
    pub status: u32,
    pub information: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoOpenAction {
    Complete { status: u32, information: u64 },
    Initialize,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoPortDeviceState {
    discovery: VideoAdapterDiscoveryState,
    initialization: VideoHardwareInitializationState,
}

/// Native Device-extension prefix. Fields remain integer atomics, never unchecked enum values.
#[repr(C, align(16))]
pub struct VideoPortDeviceStateCell {
    state: AtomicU64,
    reserved: AtomicU64,
}

const _: () =
    assert!(core::mem::size_of::<VideoPortDeviceStateCell>() == VIDEO_PORT_DEVICE_STATE_SIZE);
const _: () = assert!(core::mem::align_of::<VideoPortDeviceStateCell>() == 16);

impl Default for VideoPortDeviceStateCell {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoPortDeviceStateCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            reserved: AtomicU64::new(0),
        }
    }

    fn decode(&self, word: u64) -> Result<VideoPortDeviceState, VideoPortLifecycleError> {
        let mut bytes = [0; VIDEO_PORT_DEVICE_STATE_SIZE];
        bytes[..8].copy_from_slice(&word.to_le_bytes());
        bytes[8..].copy_from_slice(&self.reserved.load(Ordering::Acquire).to_le_bytes());
        VideoPortDeviceState::parse(&bytes)
    }

    pub fn snapshot(&self) -> Result<VideoPortDeviceState, VideoPortLifecycleError> {
        self.decode(self.state.load(Ordering::Acquire))
    }

    /// Atomically publish a validated state transition. The closure may run multiple times and
    /// must only modify its supplied snapshot; invoke native callbacks after this method returns.
    pub fn update<T>(
        &self,
        mut transition: impl FnMut(&mut VideoPortDeviceState) -> Result<T, VideoPortLifecycleError>,
    ) -> Result<T, VideoPortLifecycleError> {
        let mut observed = self.state.load(Ordering::Acquire);
        loop {
            let mut state = self.decode(observed)?;
            let result = transition(&mut state)?;
            let mut bytes = [0; VIDEO_PORT_DEVICE_STATE_SIZE];
            state.write(&mut bytes)?;
            let desired = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            match self.state.compare_exchange_weak(
                observed,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(result),
                Err(current) => observed = current,
            }
        }
    }
}

impl Default for VideoPortDeviceState {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoPortDeviceState {
    pub const fn new() -> Self {
        Self {
            discovery: VideoAdapterDiscoveryState::NotCalled,
            initialization: VideoHardwareInitializationState::NotCalled,
        }
    }

    pub const fn discovery_state(&self) -> VideoAdapterDiscoveryState {
        self.discovery
    }

    pub const fn find_adapter_succeeded(&self) -> bool {
        matches!(self.discovery, VideoAdapterDiscoveryState::Succeeded)
    }

    pub const fn initialization_state(&self) -> VideoHardwareInitializationState {
        self.initialization
    }

    /// A zero-filled prefix is fresh. All mutable state fits within the first atomic u64;
    /// the remaining eight bytes are reserved and must remain zero.
    pub fn parse(bytes: &[u8]) -> Result<Self, VideoPortLifecycleError> {
        if bytes.len() < VIDEO_PORT_DEVICE_STATE_SIZE {
            return Err(VideoPortLifecycleError::BufferTooSmall {
                needed: VIDEO_PORT_DEVICE_STATE_SIZE,
            });
        }
        let discovery = match u32::from_le_bytes(bytes[0..4].try_into().unwrap()) {
            0 => VideoAdapterDiscoveryState::NotCalled,
            1 => VideoAdapterDiscoveryState::Running,
            2 => VideoAdapterDiscoveryState::Succeeded,
            3 => VideoAdapterDiscoveryState::Failed,
            _ => return Err(VideoPortLifecycleError::InvalidSnapshot),
        };
        let initialization = match u32::from_le_bytes(bytes[4..8].try_into().unwrap()) {
            0 => VideoHardwareInitializationState::NotCalled,
            1 => VideoHardwareInitializationState::Running,
            2 => VideoHardwareInitializationState::Succeeded,
            3 => VideoHardwareInitializationState::Failed,
            _ => return Err(VideoPortLifecycleError::InvalidSnapshot),
        };
        if bytes[8..16].iter().any(|byte| *byte != 0)
            || initialization != VideoHardwareInitializationState::NotCalled
                && discovery != VideoAdapterDiscoveryState::Succeeded
        {
            return Err(VideoPortLifecycleError::InvalidSnapshot);
        }
        Ok(Self {
            discovery,
            initialization,
        })
    }

    pub fn write(&self, bytes: &mut [u8]) -> Result<usize, VideoPortLifecycleError> {
        if bytes.len() < VIDEO_PORT_DEVICE_STATE_SIZE {
            return Err(VideoPortLifecycleError::BufferTooSmall {
                needed: VIDEO_PORT_DEVICE_STATE_SIZE,
            });
        }
        let discovery: u32 = match self.discovery {
            VideoAdapterDiscoveryState::NotCalled => 0,
            VideoAdapterDiscoveryState::Running => 1,
            VideoAdapterDiscoveryState::Succeeded => 2,
            VideoAdapterDiscoveryState::Failed => 3,
        };
        let initialization: u32 = match self.initialization {
            VideoHardwareInitializationState::NotCalled => 0,
            VideoHardwareInitializationState::Running => 1,
            VideoHardwareInitializationState::Succeeded => 2,
            VideoHardwareInitializationState::Failed => 3,
        };
        bytes[..4].copy_from_slice(&discovery.to_le_bytes());
        bytes[4..8].copy_from_slice(&initialization.to_le_bytes());
        bytes[8..16].fill(0);
        Ok(VIDEO_PORT_DEVICE_STATE_SIZE)
    }

    pub fn begin_find_adapter(&mut self) -> Result<(), VideoPortLifecycleError> {
        if self.discovery == VideoAdapterDiscoveryState::Running
            || self.initialization == VideoHardwareInitializationState::Running
        {
            return Err(VideoPortLifecycleError::Busy);
        }
        if self.initialization != VideoHardwareInitializationState::NotCalled
            || self.discovery == VideoAdapterDiscoveryState::Succeeded
        {
            return Err(VideoPortLifecycleError::InvalidTransition);
        }
        self.discovery = VideoAdapterDiscoveryState::Running;
        Ok(())
    }

    pub fn record_find_adapter(&mut self, succeeded: bool) -> Result<(), VideoPortLifecycleError> {
        if self.discovery != VideoAdapterDiscoveryState::Running
            || self.initialization != VideoHardwareInitializationState::NotCalled
        {
            return Err(VideoPortLifecycleError::InvalidTransition);
        }
        self.discovery = if succeeded {
            VideoAdapterDiscoveryState::Succeeded
        } else {
            VideoAdapterDiscoveryState::Failed
        };
        Ok(())
    }

    pub fn begin_open(
        &mut self,
        requestor_mode: u8,
        desired_access: u32,
    ) -> Result<VideoOpenAction, VideoPortLifecycleError> {
        if requestor_mode > 1 {
            return Err(VideoPortLifecycleError::InvalidRequestorMode);
        }
        if requestor_mode == 1 {
            return Ok(VideoOpenAction::Complete {
                status: STATUS_SUCCESS,
                information: 0,
            });
        }
        if desired_access == FILE_READ_ATTRIBUTES {
            return Ok(VideoOpenAction::Complete {
                status: STATUS_SUCCESS,
                information: FILE_OPEN,
            });
        }
        if self.discovery == VideoAdapterDiscoveryState::Running {
            return Ok(VideoOpenAction::Busy);
        }
        if !self.find_adapter_succeeded() {
            return Ok(VideoOpenAction::Complete {
                status: STATUS_DEVICE_CONFIGURATION_ERROR,
                information: FILE_OPEN,
            });
        }
        Ok(match self.initialization {
            VideoHardwareInitializationState::NotCalled => {
                self.initialization = VideoHardwareInitializationState::Running;
                VideoOpenAction::Initialize
            }
            VideoHardwareInitializationState::Running => VideoOpenAction::Busy,
            VideoHardwareInitializationState::Succeeded => VideoOpenAction::Complete {
                status: STATUS_SUCCESS,
                information: FILE_OPEN,
            },
            VideoHardwareInitializationState::Failed => VideoOpenAction::Complete {
                status: STATUS_DEVICE_CONFIGURATION_ERROR,
                information: FILE_OPEN,
            },
        })
    }

    pub fn finish_initialize(
        &mut self,
        succeeded: bool,
    ) -> Result<VideoOpenCompletion, VideoPortLifecycleError> {
        if self.initialization != VideoHardwareInitializationState::Running {
            return Err(VideoPortLifecycleError::InvalidTransition);
        }
        self.initialization = if succeeded {
            VideoHardwareInitializationState::Succeeded
        } else {
            VideoHardwareInitializationState::Failed
        };
        Ok(VideoOpenCompletion {
            status: if succeeded {
                STATUS_SUCCESS
            } else {
                STATUS_DEVICE_CONFIGURATION_ERROR
            },
            information: FILE_OPEN,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::vec::Vec;

    fn found() -> VideoPortDeviceState {
        let mut state = VideoPortDeviceState::new();
        state.begin_find_adapter().unwrap();
        state.record_find_adapter(true).unwrap();
        state
    }

    fn assert_roundtrip(state: VideoPortDeviceState) {
        let mut bytes = [0xA5; 20];
        assert_eq!(state.write(&mut bytes), Ok(VIDEO_PORT_DEVICE_STATE_SIZE));
        assert_eq!(&bytes[8..16], &[0; 8]);
        assert_eq!(&bytes[16..], &[0xA5; 4]);
        assert_eq!(VideoPortDeviceState::parse(&bytes), Ok(state));
    }

    #[test]
    fn snapshots_validate_discriminants_reserved_bytes_and_cross_field_invariants() {
        assert_eq!(
            VideoPortDeviceState::parse(&[0; 16]),
            Ok(VideoPortDeviceState::new())
        );
        for discovery in 0u32..=4 {
            for initialization in 0u32..=4 {
                let mut bytes = [0; 16];
                bytes[..4].copy_from_slice(&discovery.to_le_bytes());
                bytes[4..8].copy_from_slice(&initialization.to_le_bytes());
                let result = VideoPortDeviceState::parse(&bytes);
                if discovery < 4 && initialization < 4 && (initialization == 0 || discovery == 2) {
                    assert_roundtrip(result.unwrap());
                } else {
                    assert_eq!(result, Err(VideoPortLifecycleError::InvalidSnapshot));
                }
            }
        }
        for index in 8..16 {
            let mut bytes = [0; 16];
            bytes[index] = 1;
            assert_eq!(
                VideoPortDeviceState::parse(&bytes),
                Err(VideoPortLifecycleError::InvalidSnapshot)
            );
        }
        let mut short = [0xA5; 15];
        let error = VideoPortLifecycleError::BufferTooSmall { needed: 16 };
        assert_eq!(VideoPortDeviceState::parse(&short), Err(error));
        assert_eq!(VideoPortDeviceState::new().write(&mut short), Err(error));
        assert_eq!(short, [0xA5; 15]);
    }

    #[test]
    fn bypass_opens_never_initialize_or_mutate_any_valid_state() {
        for discovery in 0u32..4 {
            for initialization in 0u32..4 {
                let mut bytes = [0; 16];
                bytes[..4].copy_from_slice(&discovery.to_le_bytes());
                bytes[4..8].copy_from_slice(&initialization.to_le_bytes());
                let Ok(mut state) = VideoPortDeviceState::parse(&bytes) else {
                    continue;
                };
                let before = state;
                assert_eq!(
                    state.begin_open(1, u32::MAX),
                    Ok(VideoOpenAction::Complete {
                        status: 0,
                        information: 0
                    })
                );
                assert_eq!(
                    state.begin_open(0, FILE_READ_ATTRIBUTES),
                    Ok(VideoOpenAction::Complete {
                        status: 0,
                        information: 1
                    })
                );
                assert_eq!(
                    state.begin_open(2, FILE_READ_ATTRIBUTES),
                    Err(VideoPortLifecycleError::InvalidRequestorMode)
                );
                assert_eq!(state, before);
            }
        }
    }

    #[test]
    fn discovery_requires_claim_and_only_failed_discovery_can_retry() {
        let mut state = VideoPortDeviceState::new();
        let config_error = Ok(VideoOpenAction::Complete {
            status: STATUS_DEVICE_CONFIGURATION_ERROR,
            information: 1,
        });
        assert_eq!(state.begin_open(0, 0x81), config_error);
        assert_eq!(
            state.record_find_adapter(true),
            Err(VideoPortLifecycleError::InvalidTransition)
        );
        state.begin_find_adapter().unwrap();
        let running = state;
        assert_eq!(
            state.begin_find_adapter(),
            Err(VideoPortLifecycleError::Busy)
        );
        assert_eq!(state.begin_open(0, 0), Ok(VideoOpenAction::Busy));
        assert_eq!(state, running);
        state.record_find_adapter(false).unwrap();
        assert_eq!(state.begin_open(0, 0), config_error);
        state.begin_find_adapter().unwrap();
        state.record_find_adapter(true).unwrap();
        let succeeded = state;
        assert_eq!(
            state.begin_find_adapter(),
            Err(VideoPortLifecycleError::InvalidTransition)
        );
        assert_eq!(
            state.record_find_adapter(false),
            Err(VideoPortLifecycleError::InvalidTransition)
        );
        assert_eq!(state, succeeded);
    }

    #[test]
    fn eligible_open_invokes_once_and_remembers_success_or_failure() {
        for succeeded in [false, true] {
            let mut state = found();
            assert_eq!(
                state.finish_initialize(succeeded),
                Err(VideoPortLifecycleError::InvalidTransition)
            );
            assert_eq!(state.begin_open(0, 0x81), Ok(VideoOpenAction::Initialize));
            assert_roundtrip(state);
            let running = state;
            assert_eq!(state.begin_open(0, 0), Ok(VideoOpenAction::Busy));
            assert_eq!(
                state.begin_find_adapter(),
                Err(VideoPortLifecycleError::Busy)
            );
            assert_eq!(
                state.record_find_adapter(false),
                Err(VideoPortLifecycleError::InvalidTransition)
            );
            assert_eq!(state, running);
            let completion = state.finish_initialize(succeeded).unwrap();
            let expected = if succeeded {
                0
            } else {
                STATUS_DEVICE_CONFIGURATION_ERROR
            };
            assert_eq!(
                completion,
                VideoOpenCompletion {
                    status: expected,
                    information: 1
                }
            );
            let terminal = state;
            for _ in 0..3 {
                assert_eq!(
                    state.begin_open(0, 0),
                    Ok(VideoOpenAction::Complete {
                        status: expected,
                        information: 1
                    })
                );
                assert_eq!(
                    state.finish_initialize(!succeeded),
                    Err(VideoPortLifecycleError::InvalidTransition)
                );
                assert_eq!(
                    state.begin_find_adapter(),
                    Err(VideoPortLifecycleError::InvalidTransition)
                );
                assert_eq!(
                    state.record_find_adapter(true),
                    Err(VideoPortLifecycleError::InvalidTransition)
                );
                assert_eq!(state, terminal);
            }
            assert_roundtrip(state);
        }
    }

    #[test]
    fn devices_keep_independent_discovery_and_initialization() {
        let mut first = found();
        let mut second = VideoPortDeviceState::new();
        assert_eq!(first.begin_open(0, 0), Ok(VideoOpenAction::Initialize));
        second.begin_find_adapter().unwrap();
        first.finish_initialize(false).unwrap();
        second.record_find_adapter(true).unwrap();
        assert_eq!(second.begin_open(0, 0), Ok(VideoOpenAction::Initialize));
        second.finish_initialize(true).unwrap();
        assert_eq!(
            first.initialization_state(),
            VideoHardwareInitializationState::Failed
        );
        assert_eq!(
            second.initialization_state(),
            VideoHardwareInitializationState::Succeeded
        );
    }

    #[test]
    fn control_admission_distinguishes_kernel_user_brightness_and_invalid_modes() {
        let brightness = [0x0023_0494, 0x0023_0498, 0x0023_049C];
        let other = [
            crate::IOCTL_VIDEO_QUERY_CURRENT_MODE,
            0x8000_2000,
            0,
            u32::MAX,
        ];
        for code in brightness {
            assert_eq!(validate_device_control_requestor(0, code), Ok(()));
            assert_eq!(validate_device_control_requestor(1, code), Ok(()));
            for mode in 2..=u8::MAX {
                assert_eq!(
                    validate_device_control_requestor(mode, code),
                    Err(0xC000_000D)
                );
            }
        }
        for code in other {
            assert_eq!(validate_device_control_requestor(0, code), Ok(()));
            assert_eq!(validate_device_control_requestor(1, code), Err(0xC000_0022));
            for mode in 2..=u8::MAX {
                assert_eq!(
                    validate_device_control_requestor(mode, code),
                    Err(0xC000_000D)
                );
            }
        }
    }

    fn concurrently<T: Send + 'static>(
        cell: &Arc<VideoPortDeviceStateCell>,
        operation: fn(&VideoPortDeviceStateCell) -> T,
    ) -> Vec<T> {
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let cell = Arc::clone(cell);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                operation(&cell)
            }));
        }
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    }

    #[test]
    fn production_cell_grants_one_discovery_and_one_initialization_claim() {
        let cell = Arc::new(VideoPortDeviceStateCell::new());
        assert_eq!(cell.snapshot(), Ok(VideoPortDeviceState::new()));
        let discovery = concurrently(&cell, |cell| {
            cell.update(|state| state.begin_find_adapter())
        });
        assert_eq!(discovery.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            discovery
                .iter()
                .filter(|result| **result == Err(VideoPortLifecycleError::Busy))
                .count(),
            7
        );
        assert_eq!(
            cell.update(|state| state.begin_open(0, 0)),
            Ok(VideoOpenAction::Busy)
        );
        cell.update(|state| state.record_find_adapter(true))
            .unwrap();
        let opens = concurrently(&cell, |cell| cell.update(|state| state.begin_open(0, 0)));
        assert_eq!(
            opens
                .iter()
                .filter(|result| **result == Ok(VideoOpenAction::Initialize))
                .count(),
            1
        );
        assert_eq!(
            opens
                .iter()
                .filter(|result| **result == Ok(VideoOpenAction::Busy))
                .count(),
            7
        );
        let finishes = concurrently(&cell, |cell| {
            cell.update(|state| state.finish_initialize(true))
        });
        assert_eq!(finishes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            finishes
                .iter()
                .filter(|result| **result == Err(VideoPortLifecycleError::InvalidTransition))
                .count(),
            7
        );
        assert_eq!(
            cell.snapshot().unwrap().initialization_state(),
            VideoHardwareInitializationState::Succeeded
        );
        assert_eq!(
            cell.update(|state| state.begin_open(0, 0)),
            Ok(VideoOpenAction::Complete {
                status: 0,
                information: 1
            })
        );
    }

    #[test]
    fn production_cells_are_independent_and_validate_raw_prefix_before_transition() {
        assert_eq!(core::mem::size_of::<VideoPortDeviceStateCell>(), 16);
        assert_eq!(core::mem::align_of::<VideoPortDeviceStateCell>(), 16);
        let first = VideoPortDeviceStateCell::new();
        let second = VideoPortDeviceStateCell::new();
        for cell in [&first, &second] {
            cell.update(|state| state.begin_find_adapter()).unwrap();
            cell.update(|state| state.record_find_adapter(true))
                .unwrap();
            assert_eq!(
                cell.update(|state| state.begin_open(0, 0)),
                Ok(VideoOpenAction::Initialize)
            );
        }
        first
            .update(|state| state.finish_initialize(false))
            .unwrap();
        assert_eq!(
            second.snapshot().unwrap().initialization_state(),
            VideoHardwareInitializationState::Running
        );
        second
            .update(|state| state.finish_initialize(true))
            .unwrap();
        assert_eq!(
            first.snapshot().unwrap().initialization_state(),
            VideoHardwareInitializationState::Failed
        );

        let invalid = VideoPortDeviceStateCell::new();
        invalid.reserved.store(1, Ordering::Release);
        assert_eq!(
            invalid.snapshot(),
            Err(VideoPortLifecycleError::InvalidSnapshot)
        );
        assert_eq!(
            invalid.update(|state| state.begin_find_adapter()),
            Err(VideoPortLifecycleError::InvalidSnapshot)
        );
        assert_eq!(invalid.state.load(Ordering::Acquire), 0);
        invalid.reserved.store(0, Ordering::Release);
        invalid.state.store(u64::MAX, Ordering::Release);
        assert_eq!(
            invalid.update(|state| state.begin_find_adapter()),
            Err(VideoPortLifecycleError::InvalidSnapshot)
        );
        assert_eq!(invalid.state.load(Ordering::Acquire), u64::MAX);
    }
}
