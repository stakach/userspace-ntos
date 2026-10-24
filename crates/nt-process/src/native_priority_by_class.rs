//! Process and thread scheduling projection for `PsSetProcessPriorityByClass`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    job::JobId, ProcessId, ProcessManager, ProcessState, ThreadId, ThreadLifetime, ThreadState,
    HIGH_PRIORITY, LOW_REALTIME_PRIORITY, PROCESS_PRIORITY_CLASS_IDLE,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};

const CLASS_BASE_PRIORITIES: [i32; 7] = [8, 4, 8, 13, 24, 6, 10];
const JOB_SCHEDULING_QUANTUMS: [u8; 10] = [6, 12, 18, 24, 30, 36, 42, 48, 54, 60];
const MEMORY_PRIORITY_BACKGROUND: u8 = 0;
const MEMORY_PRIORITY_FOREGROUND: u8 = 2;
static NEXT_MANAGER: AtomicU64 = AtomicU64::new(1);

/// The admitted `PsChangeQuantumTable` selection supplied by the executive scheduler owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessPriorityQuantumPolicy {
    pub foreground_quantums: [u8; 3],
    pub priority_separation: u8,
    pub use_job_scheduling_classes: bool,
}

impl ProcessPriorityQuantumPolicy {
    /// Select the ReactOS quantum table from the admitted
    /// `PriorityControl\Win32PrioritySeparation` DWORD and the memory manager's NT-as-system
    /// classification. This is a pure selection; the executive must supply both live inputs.
    pub fn from_priority_separation(raw: u32, nt_as_system: bool) -> Self {
        let separation = ((raw & 3) as u8).min(2);
        let fixed = match raw & 0x0c {
            0x04 => false,
            0x08 => true,
            _ => nt_as_system,
        };
        let long = match raw & 0x30 {
            0x10 => true,
            0x20 => false,
            _ => nt_as_system,
        };
        let foreground_quantums = match (fixed, long) {
            (false, false) => [6, 12, 18],
            (false, true) => [12, 24, 36],
            (true, false) => [18, 18, 18],
            (true, true) => [36, 36, 36],
        };
        Self {
            foreground_quantums,
            priority_separation: separation,
            use_job_scheduling_classes: fixed && long,
        }
    }

    fn validate(self) -> Result<(), u32> {
        if self.priority_separation > 2
            || self.foreground_quantums.iter().any(|&quantum| quantum == 0 || quantum > i8::MAX as u8)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }
}

/// Ps-owned process scheduler values; class and base priority remain separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessSchedulingState {
    pub priority_class: u8,
    pub base_priority: i32,
    pub quantum_reset: u8,
    pub memory_priority: u8,
}

/// Ps-owned thread scheduler values beneath a live ETHREAD identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSchedulingState {
    pub base_priority: i32,
    pub priority: i32,
    pub quantum_reset: u8,
    pub quantum: i8,
    pub priority_decrement: i8,
    pub saturation: i8,
}

/// One exact ETHREAD activation and its proposed scheduler projection. The executive can use
/// this to apply the physical TCB transition before committing Process Manager state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadPriorityByClassEffect {
    lifetime: ThreadLifetime,
    kernel_object: Option<u64>,
    expected: ThreadSchedulingState,
    next: ThreadSchedulingState,
    state: ThreadState,
}

impl ThreadPriorityByClassEffect {
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
    pub const fn kernel_object(&self) -> Option<u64> {
        self.kernel_object
    }
    pub const fn state(&self) -> ThreadState {
        self.state
    }
    pub const fn expected(&self) -> ThreadSchedulingState {
        self.expected
    }
    pub const fn next(&self) -> ThreadSchedulingState {
        self.next
    }
}

/// Checked scheduler transition. Its private owner and snapshots prevent a stale or foreign
/// plan from partially changing PM after native TCB work has been reserved.
#[must_use = "commit only after the exact native scheduler effects have completed"]
#[derive(Debug)]
pub struct ProcessPriorityByClassPlan {
    manager: u64,
    eprocess: u64,
    pid: ProcessId,
    creation_sequence: u64,
    process_state: ProcessState,
    expected: ProcessSchedulingState,
    next: ProcessSchedulingState,
    threads: Vec<ThreadPriorityByClassEffect>,
    job: Option<JobId>,
    job_scheduling_class: Option<u32>,
}

impl ProcessPriorityByClassPlan {
    pub const fn process_object(&self) -> u64 {
        self.eprocess
    }
    pub const fn next_process_state(&self) -> ProcessSchedulingState {
        self.next
    }
    pub fn thread_effects(&self) -> &[ThreadPriorityByClassEffect] {
        &self.threads
    }
}

impl ProcessManager {
    pub(crate) fn ensure_priority_plan_manager_identity(&mut self) -> Result<u64, u32> {
        if self.priority_plan_manager_identity == 0 {
            self.priority_plan_manager_identity = NEXT_MANAGER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        Ok(self.priority_plan_manager_identity)
    }

    pub fn process_scheduling_state_for_kernel_object(
        &self,
        eprocess: u64,
    ) -> Result<ProcessSchedulingState, u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(ProcessSchedulingState {
            priority_class: process.priority_class,
            base_priority: process.base_priority,
            quantum_reset: process.quantum_reset,
            memory_priority: process.memory_priority,
        })
    }

    pub fn thread_scheduling_state(&self, tid: ThreadId) -> Result<ThreadSchedulingState, u32> {
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(ThreadSchedulingState {
            base_priority: thread.base_priority,
            priority: thread.priority,
            quantum_reset: thread.quantum_reset,
            quantum: thread.quantum,
            priority_decrement: thread.priority_decrement,
            saturation: thread.saturation,
        })
    }

    /// Compute ReactOS's mode and class transition without changing PM state. The caller owns
    /// native effect reservation and TCB updates before checked commit.
    pub fn prepare_process_priority_by_class_for_kernel_object(
        &mut self,
        eprocess: u64,
        mode: u32,
        policy: ProcessPriorityQuantumPolicy,
    ) -> Result<ProcessPriorityByClassPlan, u32> {
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if mode > 2 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        policy.validate()?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let base_priority = *CLASS_BASE_PRIORITIES
            .get(usize::from(process.priority_class))
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let memory_priority = match mode {
            0 => MEMORY_PRIORITY_FOREGROUND,
            1 => MEMORY_PRIORITY_BACKGROUND,
            _ => process.memory_priority,
        };
        let expected = ProcessSchedulingState {
            priority_class: process.priority_class,
            base_priority: process.base_priority,
            quantum_reset: process.quantum_reset,
            memory_priority: process.memory_priority,
        };
        let mut next = expected;
        next.memory_priority = memory_priority;
        let mut threads = Vec::new();
        let job = self.jobs.job_for_process(pid);
        let mut job_scheduling_class = None;

        // PspComputeQuantumAndPriority sets memory priority first. KeSetPriorityAndQuantumProcess
        // returns immediately when the computed base equals the current base, before quantum or
        // thread changes.
        if base_priority != process.base_priority {
            let quantum_reset = if process.priority_class == PROCESS_PRIORITY_CLASS_IDLE {
                6
            } else if policy.use_job_scheduling_classes {
                match job {
                    Some(job) => {
                        let limits = self.jobs.basic_limits(job)?;
                        job_scheduling_class = Some(limits.scheduling_class);
                        *JOB_SCHEDULING_QUANTUMS
                            .get(limits.scheduling_class as usize)
                            .ok_or(STATUS_INVALID_PARAMETER)?
                    }
                    None => {
                        policy.foreground_quantums[if mode == 0 {
                            usize::from(policy.priority_separation)
                        } else {
                            0
                        }]
                    }
                }
            } else {
                policy.foreground_quantums[if mode == 0 {
                    usize::from(policy.priority_separation)
                } else {
                    0
                }]
            };
            next.base_priority = base_priority;
            next.quantum_reset = quantum_reset;
        }

        threads
            .try_reserve_exact(process.threads.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for tid in &process.threads {
            let thread = self.threads.get(tid).ok_or(STATUS_INVALID_HANDLE)?;
            if thread.process_id != pid {
                return Err(STATUS_INVALID_HANDLE);
            }
            let next_base = if base_priority == process.base_priority {
                thread.base_priority
            } else {
                let candidate = thread.base_priority + (base_priority - process.base_priority);
                if base_priority >= LOW_REALTIME_PRIORITY {
                    candidate.clamp(LOW_REALTIME_PRIORITY, HIGH_PRIORITY)
                } else {
                    candidate.clamp(1, LOW_REALTIME_PRIORITY - 1)
                }
            };
            let expected_thread = ThreadSchedulingState {
                base_priority: thread.base_priority,
                priority: thread.priority,
                quantum_reset: thread.quantum_reset,
                quantum: thread.quantum,
                priority_decrement: thread.priority_decrement,
                saturation: thread.saturation,
            };
            // KeSetPriorityAndQuantumProcess changes QuantumReset before checking saturation.
            // Within the same priority range a saturated thread retains its priority, current
            // quantum, and decrement; crossing ranges permits a saturated priority transition.
            let mut next_thread = expected_thread;
            if base_priority != process.base_priority {
                next_thread.quantum_reset = next.quantum_reset;
                let apply_priority = thread.saturation == 0
                    || if base_priority >= LOW_REALTIME_PRIORITY {
                        process.base_priority < LOW_REALTIME_PRIORITY
                    } else {
                        process.base_priority >= LOW_REALTIME_PRIORITY
                    };
                if apply_priority {
                    let selected_base = match thread.saturation.cmp(&0) {
                        core::cmp::Ordering::Greater if base_priority >= LOW_REALTIME_PRIORITY => HIGH_PRIORITY,
                        core::cmp::Ordering::Greater => LOW_REALTIME_PRIORITY - 1,
                        core::cmp::Ordering::Less if base_priority >= LOW_REALTIME_PRIORITY => LOW_REALTIME_PRIORITY,
                        core::cmp::Ordering::Less => 1,
                        core::cmp::Ordering::Equal => next_base,
                    };
                    next_thread.base_priority = selected_base;
                    next_thread.priority = selected_base;
                    next_thread.quantum = next_thread.quantum_reset as i8;
                    next_thread.priority_decrement = 0;
                }
            }
            threads.push(ThreadPriorityByClassEffect {
                lifetime: ThreadLifetime {
                    thread_id: *tid,
                    process_id: pid,
                    generation: thread.activation_generation,
                },
                kernel_object: thread.kernel_thread_object,
                expected: expected_thread,
                next: next_thread,
                state: thread.state,
            });
        }
        let creation_sequence = process.creation_sequence;
        let process_state = process.state;

        let manager = self.ensure_priority_plan_manager_identity()?;
        Ok(ProcessPriorityByClassPlan {
            manager,
            eprocess,
            pid,
            creation_sequence,
            process_state,
            expected,
            next,
            threads,
            job,
            job_scheduling_class,
        })
    }

    /// Revalidate every process/thread input before changing any PM scheduler value.
    pub fn commit_process_priority_by_class(
        &mut self,
        plan: ProcessPriorityByClassPlan,
    ) -> Result<(), u32> {
        self.commit_process_priority_by_class_retained(&plan)
    }

    /// Checked commit that leaves the caller's plan owned across a stale post-effect refusal.
    pub fn commit_process_priority_by_class_retained(
        &mut self,
        plan: &ProcessPriorityByClassPlan,
    ) -> Result<(), u32> {
        if self.priority_plan_manager_identity != plan.manager
            || self.pid_for_kernel_process_object(plan.eprocess) != Some(plan.pid)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let process = self.process(plan.pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.creation_sequence != plan.creation_sequence
            || process.state != plan.process_state
            || matches!(
                process.state,
                ProcessState::Exiting | ProcessState::Terminated
            )
            || process.priority_class != plan.expected.priority_class
            || process.base_priority != plan.expected.base_priority
            || process.quantum_reset != plan.expected.quantum_reset
            || process.memory_priority != plan.expected.memory_priority
            || process.threads.len() != plan.threads.len()
            || self.jobs.job_for_process(plan.pid) != plan.job
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(expected_class) = plan.job_scheduling_class {
            let job = self
                .jobs
                .job_for_process(plan.pid)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            let limits = self.jobs.basic_limits(job)?;
            if limits.scheduling_class != expected_class {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        for (index, effect) in plan.threads.iter().enumerate() {
            if process.threads.get(index) != Some(&effect.lifetime.thread_id()) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let thread = self
                .thread(effect.lifetime.thread_id())
                .ok_or(STATUS_INVALID_HANDLE)?;
            if thread.process_id != plan.pid
                || thread.activation_generation != effect.lifetime.generation()
                || thread.kernel_thread_object != effect.kernel_object
                || thread.state != effect.state
                || thread.base_priority != effect.expected.base_priority
                || thread.priority != effect.expected.priority
                || thread.quantum_reset != effect.expected.quantum_reset
                || thread.quantum != effect.expected.quantum
                || thread.priority_decrement != effect.expected.priority_decrement
                || thread.saturation != effect.expected.saturation
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }

        let process = self.processes.get_mut(&plan.pid).unwrap();
        process.base_priority = plan.next.base_priority;
        process.quantum_reset = plan.next.quantum_reset;
        process.memory_priority = plan.next.memory_priority;
        for effect in &plan.threads {
            let thread = self.threads.get_mut(&effect.lifetime.thread_id()).unwrap();
            thread.base_priority = effect.next.base_priority;
            thread.priority = effect.next.priority;
            thread.quantum_reset = effect.next.quantum_reset;
            thread.quantum = effect.next.quantum;
            thread.priority_decrement = effect.next.priority_decrement;
            thread.saturation = effect.next.saturation;
        }
        Ok(())
    }

    /// Domain-only convenience path for callers with no separate native TCB effects.
    pub fn set_process_priority_by_class_for_kernel_object(
        &mut self,
        eprocess: u64,
        mode: u32,
        policy: ProcessPriorityQuantumPolicy,
    ) -> Result<(), u32> {
        let plan =
            self.prepare_process_priority_by_class_for_kernel_object(eprocess, mode, policy)?;
        self.commit_process_priority_by_class(plan)
    }
}

#[cfg(test)]
mod reactos_scheduler_regressions {
    use super::*;
    use crate::{PROCESS_PRIORITY_CLASS_HIGH, PROCESS_PRIORITY_CLASS_REALTIME};

    fn policy() -> ProcessPriorityQuantumPolicy {
        ProcessPriorityQuantumPolicy {
            foreground_quantums: [12, 18, 24],
            priority_separation: 2,
            use_job_scheduling_classes: false,
        }
    }

    #[test]
    fn changed_base_resets_quantum_and_decrement_after_unboosted_transition() {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("gui.exe", None, None);
        pm.set_process_base_priority(pid, 8).unwrap();
        let tid = pm.create_thread(pid, 0, 0, false).unwrap();
        pm.threads.get_mut(&tid).unwrap().quantum = 3;
        pm.threads.get_mut(&tid).unwrap().priority_decrement = 2;
        assert!(pm.publish_process_kernel_object(pid, 0x1000));
        pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH).unwrap();

        let plan = pm.prepare_process_priority_by_class_for_kernel_object(0x1000, 0, policy()).unwrap();
        let next = plan.thread_effects()[0].next();
        assert_eq!((next.base_priority, next.priority, next.quantum_reset), (13, 13, 24));
        assert_eq!((next.quantum, next.priority_decrement, next.saturation), (24, 0, 0));
        pm.commit_process_priority_by_class(plan).unwrap();
        assert_eq!(pm.thread_scheduling_state(tid).unwrap(), next);
    }

    #[test]
    fn saturation_in_same_priority_range_skips_priority_and_quantum_reset_only() {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("gui.exe", None, None);
        pm.set_process_base_priority(pid, 8).unwrap();
        let tid = pm.create_thread(pid, 0, 0, false).unwrap();
        let thread = pm.threads.get_mut(&tid).unwrap();
        thread.saturation = 1;
        thread.quantum = 3;
        thread.priority_decrement = 2;
        assert!(pm.publish_process_kernel_object(pid, 0x1000));
        pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH).unwrap();

        let plan = pm.prepare_process_priority_by_class_for_kernel_object(0x1000, 0, policy()).unwrap();
        let next = plan.thread_effects()[0].next();
        assert_eq!((next.base_priority, next.priority, next.quantum_reset), (8, 8, 24));
        assert_eq!((next.quantum, next.priority_decrement, next.saturation), (3, 2, 1));
        pm.commit_process_priority_by_class(plan).unwrap();
        assert_eq!(pm.thread_scheduling_state(tid).unwrap(), next);
    }

    #[test]
    fn crossing_into_realtime_applies_positive_saturation_to_realtime_ceiling() {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("gui.exe", None, None);
        pm.set_process_base_priority(pid, 8).unwrap();
        let tid = pm.create_thread(pid, 0, 0, false).unwrap();
        let thread = pm.threads.get_mut(&tid).unwrap();
        thread.saturation = 1;
        thread.quantum = 3;
        thread.priority_decrement = 2;
        assert!(pm.publish_process_kernel_object(pid, 0x1000));
        pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_REALTIME).unwrap();

        let plan = pm.prepare_process_priority_by_class_for_kernel_object(0x1000, 0, policy()).unwrap();
        let next = plan.thread_effects()[0].next();
        assert_eq!((next.base_priority, next.priority, next.quantum_reset), (HIGH_PRIORITY, HIGH_PRIORITY, 24));
        assert_eq!((next.quantum, next.priority_decrement, next.saturation), (24, 0, 1));
        pm.commit_process_priority_by_class(plan).unwrap();
        assert_eq!(pm.thread_scheduling_state(tid).unwrap(), next);
    }

    #[test]
    fn captured_quantum_and_saturation_changes_refuse_stale_commit() {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("gui.exe", None, None);
        pm.set_process_base_priority(pid, 8).unwrap();
        let tid = pm.create_thread(pid, 0, 0, false).unwrap();
        assert!(pm.publish_process_kernel_object(pid, 0x1000));
        pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH).unwrap();
        let plan = pm.prepare_process_priority_by_class_for_kernel_object(0x1000, 0, policy()).unwrap();
        pm.threads.get_mut(&tid).unwrap().saturation = -1;
        let before = pm.thread_scheduling_state(tid).unwrap();
        let process_before = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
        assert_eq!(pm.commit_process_priority_by_class(plan), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(pm.thread_scheduling_state(tid).unwrap(), before);
        assert_eq!(pm.process_scheduling_state_for_kernel_object(0x1000).unwrap(), process_before);
    }
}
