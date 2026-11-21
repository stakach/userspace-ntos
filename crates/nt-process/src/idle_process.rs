//! `PsIdleProcess` and each processor's idle thread (`KPRCB->IdleThread`).
//!
//! NT builds both before any CID exists: `KiInitializeKernel` initializes every idle thread with
//! `KeInitializeThread` alone, and `PspInitPhase0` adopts the boot processor's process as
//! `PsIdleProcess`, naming it "Idle". Neither passes through `PspCreateProcess` or
//! `PspCreateThread`, so none of them is in `PspCidTable`: the process id is 0 and every idle
//! thread's id is 0. They are therefore kept here, outside the CID-keyed process and thread
//! tables. No CID lookup, handle open, state change, suspend or termination can name them, and
//! they are never deleted. NT's `SystemProcessInformation` lists this process first, as process
//! id 0 with session 0, no handles and its idle threads; that class is not implemented yet, and
//! must enumerate [`ProcessManager::idle_process`] and [`ProcessManager::idle_threads`] first.
use crate::{ProcessId, ProcessManager, ThreadId, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER};
use alloc::vec::Vec;

pub const IDLE_PROCESS_ID: ProcessId = 0;
pub const IDLE_THREAD_ID: ThreadId = 0;
pub const IDLE_PROCESS_IMAGE_FILE_NAME: &str = "Idle";

pub(crate) struct IdleSystem {
    process_body: Option<u64>,
    /// Indexed by processor number.
    thread_bodies: Vec<Option<u64>>,
}

/// A snapshot of the Idle process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleProcess {
    thread_count: u32,
    kernel_object: Option<u64>,
}

impl IdleProcess {
    pub const fn process_id(self) -> ProcessId {
        IDLE_PROCESS_ID
    }

    pub const fn image_file_name(self) -> &'static str {
        IDLE_PROCESS_IMAGE_FILE_NAME
    }

    /// The Idle process always reports session 0.
    pub const fn session_id(self) -> u32 {
        0
    }

    pub const fn thread_count(self) -> u32 {
        self.thread_count
    }

    /// The published EPROCESS body.
    pub const fn kernel_object(self) -> Option<u64> {
        self.kernel_object
    }
}

/// A snapshot of one processor's idle thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleThread {
    processor: u32,
    kernel_object: Option<u64>,
}

impl IdleThread {
    pub const fn processor(self) -> u32 {
        self.processor
    }

    pub const fn process_id(self) -> ProcessId {
        IDLE_PROCESS_ID
    }

    pub const fn thread_id(self) -> ThreadId {
        IDLE_THREAD_ID
    }

    /// Idle threads run only in kernel mode and have no TEB.
    pub const fn teb_base(self) -> u64 {
        0
    }

    /// The published ETHREAD body.
    pub const fn kernel_object(self) -> Option<u64> {
        self.kernel_object
    }
}

impl ProcessManager {
    /// The processors this manager was constructed for; idle thread `i` belongs to processor `i`.
    pub fn active_processor_count(&self) -> u32 {
        self.active_affinity_mask.unwrap_or(1).count_ones()
    }

    /// Create the Idle process and one idle thread per active processor, once.
    pub fn create_idle_process(&mut self) -> Result<IdleProcess, u32> {
        if self.idle.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let count = self.active_processor_count() as usize;
        let mut thread_bodies = Vec::new();
        thread_bodies
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        thread_bodies.resize(count, None);
        self.idle = Some(IdleSystem { process_body: None, thread_bodies });
        Ok(self.idle_process().expect("idle process was just created"))
    }

    pub fn idle_process(&self) -> Option<IdleProcess> {
        self.idle.as_ref().map(|idle| IdleProcess {
            thread_count: idle.thread_bodies.len() as u32,
            kernel_object: idle.process_body,
        })
    }

    /// `KPRCB->IdleThread` of `processor`.
    pub fn idle_thread(&self, processor: u32) -> Option<IdleThread> {
        let idle = self.idle.as_ref()?;
        let &kernel_object = idle.thread_bodies.get(processor as usize)?;
        Some(IdleThread { processor, kernel_object })
    }

    /// The idle threads in processor order.
    pub fn idle_threads(&self) -> impl Iterator<Item = IdleThread> + '_ {
        let count = self.idle.as_ref().map_or(0, |idle| idle.thread_bodies.len() as u32);
        (0..count).filter_map(|processor| self.idle_thread(processor))
    }

    /// Publish the EPROCESS body and every idle thread's ETHREAD body (in processor order)
    /// together. The caller must already own initialized backing for every address. Republishing
    /// the identical set is idempotent; anything else after publication is refused, as is any
    /// zero, duplicate or already owned address. A refusal publishes nothing.
    pub fn publish_idle_kernel_objects(&mut self, eprocess: u64, ethreads: &[u64]) -> bool {
        let Some(idle) = self.idle.as_ref() else {
            return false;
        };
        if ethreads.len() != idle.thread_bodies.len() {
            return false;
        }
        if idle.process_body.is_some() {
            return idle.process_body == Some(eprocess)
                && idle.thread_bodies.iter().zip(ethreads).all(|(body, &new)| *body == Some(new));
        }
        let bodies = || core::iter::once(eprocess).chain(ethreads.iter().copied());
        if bodies().enumerate().any(|(index, body)| {
            body == 0
                || bodies().skip(index + 1).any(|other| other == body)
                || self.kernel_body_is_owned_outside_idle(body)
        }) {
            return false;
        }
        let idle = self.idle.as_mut().unwrap();
        idle.process_body = Some(eprocess);
        for (slot, &body) in idle.thread_bodies.iter_mut().zip(ethreads) {
            *slot = Some(body);
        }
        true
    }

    /// Whether `body` is the published Idle EPROCESS or one of its ETHREADs.
    pub fn is_idle_kernel_object(&self, body: u64) -> bool {
        body != 0
            && self.idle.as_ref().is_some_and(|idle| {
                idle.process_body == Some(body) || idle.thread_bodies.contains(&Some(body))
            })
    }

    fn kernel_body_is_owned_outside_idle(&self, body: u64) -> bool {
        self.retired_kernel_body_is_reserved(body)
            || self.jobs.reserves_kernel_object(body)
            || self.processes.values().any(|process| process.kernel_process_object == Some(body))
            || self.threads.values().any(|thread| thread.kernel_thread_object == Some(body))
    }
}
