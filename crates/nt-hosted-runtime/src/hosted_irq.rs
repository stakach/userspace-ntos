//! Lane-private hosted interrupt command/result transport.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

pub const HOSTED_IRQ_FRAME_MAGIC: u64 = 0x4849_5251_4C41_4E45;
pub const HOSTED_IRQ_FRAME_VERSION: u16 = 1;

const COMMAND_IDLE: u32 = 0;
const COMMAND_PUBLISHING: u32 = 1;
const COMMAND_PENDING: u32 = 2;
const COMMAND_RUNNING: u32 = 3;
const COMMAND_SHUTDOWN: u32 = 4;
const RESULT_EMPTY: u32 = 0;
const RESULT_COMPLETE: u32 = 1;
const RESULT_FAULTED: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqLaneIdentity {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub lane_generation: u64,
}

impl HostedIrqLaneIdentity {
    pub const fn new(domain_id: u64, domain_cookie: u64, lane_generation: u64) -> Option<Self> {
        if domain_id == 0 || domain_cookie == 0 || lane_generation == 0 {
            None
        } else {
            Some(Self {
                domain_id,
                domain_cookie,
                lane_generation,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqCommand {
    pub interrupt_id: u64,
    pub vector: u32,
    pub irql: u8,
    pub synchronize_irql: u8,
    pub interrupt_object: u64,
    pub service_routine: u64,
    pub service_context: u64,
}

impl HostedIrqCommand {
    fn valid(self) -> bool {
        self.interrupt_id != 0
            && self.vector != 0
            && self.irql != 0
            && self.synchronize_irql >= self.irql
            && self.interrupt_object != 0
            && self.service_routine != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqWork {
    pub sequence: u64,
    pub command: HostedIrqCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqCompletion {
    pub sequence: u64,
    pub status: i32,
    pub claimed: bool,
    pub faulted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedIrqFrameError {
    InvalidIdentity,
    InvalidCommand,
    Busy,
    SequenceExhausted,
    NotPending,
    NotRunning,
    ResultNotReady,
    StaleSequence,
    Shutdown,
}

/// One page-safe command/result frame shared only by root and one interrupt lane.
#[repr(C, align(64))]
pub struct HostedIrqFrame {
    magic: u64,
    version: u16,
    size: u16,
    reserved: u32,
    domain_id: u64,
    domain_cookie: u64,
    lane_generation: u64,
    command_seq: AtomicU64,
    command_state: AtomicU32,
    reserved_command: AtomicU32,
    interrupt_id: AtomicU64,
    vector_irql: AtomicU64,
    interrupt_object: AtomicU64,
    service_routine: AtomicU64,
    service_context: AtomicU64,
    result_seq: AtomicU64,
    result_state: AtomicU32,
    result_status: AtomicI32,
    result_claimed: AtomicU32,
    reserved_result: AtomicU32,
}

impl HostedIrqFrame {
    pub fn new(identity: HostedIrqLaneIdentity) -> Self {
        Self {
            magic: HOSTED_IRQ_FRAME_MAGIC,
            version: HOSTED_IRQ_FRAME_VERSION,
            size: core::mem::size_of::<Self>() as u16,
            reserved: 0,
            domain_id: identity.domain_id,
            domain_cookie: identity.domain_cookie,
            lane_generation: identity.lane_generation,
            command_seq: AtomicU64::new(0),
            command_state: AtomicU32::new(COMMAND_IDLE),
            reserved_command: AtomicU32::new(0),
            interrupt_id: AtomicU64::new(0),
            vector_irql: AtomicU64::new(0),
            interrupt_object: AtomicU64::new(0),
            service_routine: AtomicU64::new(0),
            service_context: AtomicU64::new(0),
            result_seq: AtomicU64::new(0),
            result_state: AtomicU32::new(RESULT_EMPTY),
            result_status: AtomicI32::new(0),
            result_claimed: AtomicU32::new(0),
            reserved_result: AtomicU32::new(0),
        }
    }

    pub fn identity(&self) -> Option<HostedIrqLaneIdentity> {
        if self.magic != HOSTED_IRQ_FRAME_MAGIC
            || self.version != HOSTED_IRQ_FRAME_VERSION
            || self.size as usize != core::mem::size_of::<Self>()
        {
            return None;
        }
        HostedIrqLaneIdentity::new(self.domain_id, self.domain_cookie, self.lane_generation)
    }

    pub fn identity_matches(&self, identity: HostedIrqLaneIdentity) -> bool {
        self.identity() == Some(identity)
    }

    pub fn root_publish(
        &self,
        identity: HostedIrqLaneIdentity,
        command: HostedIrqCommand,
    ) -> Result<u64, HostedIrqFrameError> {
        if !self.identity_matches(identity) {
            return Err(HostedIrqFrameError::InvalidIdentity);
        }
        if !command.valid() {
            return Err(HostedIrqFrameError::InvalidCommand);
        }
        self.command_state
            .compare_exchange(
                COMMAND_IDLE,
                COMMAND_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|state| {
                if state == COMMAND_SHUTDOWN {
                    HostedIrqFrameError::Shutdown
                } else {
                    HostedIrqFrameError::Busy
                }
            })?;
        let sequence = match self
            .command_seq
            .load(Ordering::Relaxed)
            .checked_add(1)
            .filter(|sequence| *sequence != 0)
        {
            Some(sequence) => sequence,
            None => {
                self.command_state.store(COMMAND_IDLE, Ordering::Release);
                return Err(HostedIrqFrameError::SequenceExhausted);
            }
        };
        self.interrupt_id
            .store(command.interrupt_id, Ordering::Relaxed);
        self.vector_irql.store(
            command.vector as u64
                | (command.irql as u64) << 32
                | (command.synchronize_irql as u64) << 40,
            Ordering::Relaxed,
        );
        self.interrupt_object
            .store(command.interrupt_object, Ordering::Relaxed);
        self.service_routine
            .store(command.service_routine, Ordering::Relaxed);
        self.service_context
            .store(command.service_context, Ordering::Relaxed);
        self.result_state.store(RESULT_EMPTY, Ordering::Relaxed);
        self.result_status.store(0, Ordering::Relaxed);
        self.result_claimed.store(0, Ordering::Relaxed);
        self.command_seq.store(sequence, Ordering::Relaxed);
        self.command_state.store(COMMAND_PENDING, Ordering::Release);
        Ok(sequence)
    }

    pub fn worker_begin(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<HostedIrqWork, HostedIrqFrameError> {
        if !self.identity_matches(identity) {
            return Err(HostedIrqFrameError::InvalidIdentity);
        }
        self.command_state
            .compare_exchange(
                COMMAND_PENDING,
                COMMAND_RUNNING,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .map_err(|state| {
                if state == COMMAND_SHUTDOWN {
                    HostedIrqFrameError::Shutdown
                } else {
                    HostedIrqFrameError::NotPending
                }
            })?;
        let sequence = self.command_seq.load(Ordering::Relaxed);
        if sequence == 0 || sequence <= self.result_seq.load(Ordering::Acquire) {
            self.command_state.store(COMMAND_IDLE, Ordering::Release);
            return Err(HostedIrqFrameError::StaleSequence);
        }
        let vector_irql = self.vector_irql.load(Ordering::Relaxed);
        let command = HostedIrqCommand {
            interrupt_id: self.interrupt_id.load(Ordering::Relaxed),
            vector: vector_irql as u32,
            irql: (vector_irql >> 32) as u8,
            synchronize_irql: (vector_irql >> 40) as u8,
            interrupt_object: self.interrupt_object.load(Ordering::Relaxed),
            service_routine: self.service_routine.load(Ordering::Relaxed),
            service_context: self.service_context.load(Ordering::Relaxed),
        };
        if !command.valid() {
            self.command_state.store(COMMAND_IDLE, Ordering::Release);
            return Err(HostedIrqFrameError::InvalidCommand);
        }
        Ok(HostedIrqWork { sequence, command })
    }

    pub fn worker_complete(
        &self,
        sequence: u64,
        status: i32,
        claimed: bool,
        faulted: bool,
    ) -> Result<(), HostedIrqFrameError> {
        if self.command_state.load(Ordering::Acquire) != COMMAND_RUNNING {
            return Err(HostedIrqFrameError::NotRunning);
        }
        if sequence == 0 || self.command_seq.load(Ordering::Relaxed) != sequence {
            return Err(HostedIrqFrameError::StaleSequence);
        }
        self.result_status.store(status, Ordering::Relaxed);
        self.result_claimed.store(claimed as u32, Ordering::Relaxed);
        self.result_seq.store(sequence, Ordering::Relaxed);
        self.result_state.store(
            if faulted {
                RESULT_FAULTED
            } else {
                RESULT_COMPLETE
            },
            Ordering::Release,
        );
        Ok(())
    }

    pub fn root_completion(
        &self,
        identity: HostedIrqLaneIdentity,
        expected_sequence: u64,
    ) -> Result<HostedIrqCompletion, HostedIrqFrameError> {
        if !self.identity_matches(identity) {
            return Err(HostedIrqFrameError::InvalidIdentity);
        }
        let state = self.result_state.load(Ordering::Acquire);
        if !matches!(state, RESULT_COMPLETE | RESULT_FAULTED) {
            return Err(HostedIrqFrameError::ResultNotReady);
        }
        let sequence = self.result_seq.load(Ordering::Relaxed);
        if sequence == 0 || sequence != expected_sequence {
            return Err(HostedIrqFrameError::StaleSequence);
        }
        Ok(HostedIrqCompletion {
            sequence,
            status: self.result_status.load(Ordering::Relaxed),
            claimed: self.result_claimed.load(Ordering::Relaxed) != 0,
            faulted: state == RESULT_FAULTED,
        })
    }

    /// Release a completed command only after root has validated its transport completion.
    pub fn root_ack_completion(&self, sequence: u64) -> Result<(), HostedIrqFrameError> {
        if self.result_seq.load(Ordering::Acquire) != sequence {
            return Err(HostedIrqFrameError::StaleSequence);
        }
        self.command_state
            .compare_exchange(
                COMMAND_RUNNING,
                COMMAND_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqFrameError::NotRunning)?;
        self.result_state.store(RESULT_EMPTY, Ordering::Release);
        Ok(())
    }

    /// Fence teardown against a pending or running command.
    pub fn root_request_shutdown(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<(), HostedIrqFrameError> {
        if !self.identity_matches(identity) {
            return Err(HostedIrqFrameError::InvalidIdentity);
        }
        self.command_state
            .compare_exchange(
                COMMAND_IDLE,
                COMMAND_SHUTDOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|state| {
                if state == COMMAND_SHUTDOWN {
                    HostedIrqFrameError::Shutdown
                } else {
                    HostedIrqFrameError::Busy
                }
            })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    fn identity() -> HostedIrqLaneIdentity {
        HostedIrqLaneIdentity::new(7, 9, 11).unwrap()
    }

    fn command() -> HostedIrqCommand {
        HostedIrqCommand {
            interrupt_id: 13,
            vector: 0x31,
            irql: 5,
            synchronize_irql: 7,
            interrupt_object: 0x1000,
            service_routine: 0x2000,
            service_context: 0x3000,
        }
    }

    #[test]
    fn frame_is_cache_aligned_and_page_safe() {
        assert_eq!(align_of::<HostedIrqFrame>(), 64);
        assert!(size_of::<HostedIrqFrame>() <= crate::PAGE_SIZE as usize);
        assert_eq!(offset_of!(HostedIrqFrame, command_seq), 40);
        assert!(
            offset_of!(HostedIrqFrame, result_seq) > offset_of!(HostedIrqFrame, service_context)
        );
    }

    #[test]
    fn command_completion_roundtrip_is_sequence_bound() {
        let frame = HostedIrqFrame::new(identity());
        let sequence = frame.root_publish(identity(), command()).unwrap();
        let work = frame.worker_begin(identity()).unwrap();
        assert_eq!(
            work,
            HostedIrqWork {
                sequence,
                command: command()
            }
        );
        frame.worker_complete(sequence, 0, true, false).unwrap();
        assert_eq!(
            frame.root_completion(identity(), sequence).unwrap(),
            HostedIrqCompletion {
                sequence,
                status: 0,
                claimed: true,
                faulted: false,
            }
        );
        frame.root_ack_completion(sequence).unwrap();
        assert_eq!(
            frame.root_publish(identity(), command()).unwrap(),
            sequence + 1
        );
    }

    #[test]
    fn busy_and_stale_transitions_fail_closed() {
        let frame = HostedIrqFrame::new(identity());
        let sequence = frame.root_publish(identity(), command()).unwrap();
        assert_eq!(
            frame.root_publish(identity(), command()),
            Err(HostedIrqFrameError::Busy)
        );
        frame.worker_begin(identity()).unwrap();
        assert_eq!(
            frame.worker_complete(sequence + 1, 0, false, false),
            Err(HostedIrqFrameError::StaleSequence)
        );
        assert_eq!(
            frame.root_completion(identity(), sequence),
            Err(HostedIrqFrameError::ResultNotReady)
        );
    }

    #[test]
    fn generation_and_shutdown_fence_reuse() {
        let frame = HostedIrqFrame::new(identity());
        let stale = HostedIrqLaneIdentity::new(7, 9, 12).unwrap();
        assert_eq!(
            frame.root_publish(stale, command()),
            Err(HostedIrqFrameError::InvalidIdentity)
        );
        frame.root_request_shutdown(identity()).unwrap();
        assert_eq!(
            frame.root_publish(identity(), command()),
            Err(HostedIrqFrameError::Shutdown)
        );
    }

    #[test]
    fn fault_completion_is_not_an_unclaimed_success() {
        let frame = HostedIrqFrame::new(identity());
        let sequence = frame.root_publish(identity(), command()).unwrap();
        frame.worker_begin(identity()).unwrap();
        frame.worker_complete(sequence, -1, false, true).unwrap();
        let completion = frame.root_completion(identity(), sequence).unwrap();
        assert!(completion.faulted);
        assert!(!completion.claimed);
        assert_eq!(completion.status, -1);
    }
}
