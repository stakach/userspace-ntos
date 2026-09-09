//! Native suspension owns its exact runtime until physical and Ps acknowledgments agree.

use crate::*;
use core::cell::RefCell;
use nt_process::thread_suspend::ThreadSuspendOperation;
use nt_user_host::thread_suspend::{
    ThreadExecutionState, ThreadSuspendAction, ThreadSuspendError, ThreadSuspendInvocation,
    ThreadSuspendOutcome, ThreadSuspendOwner, ThreadSuspendPhase,
};

type Owner = ThreadSuspendOwner<HostedThreadRole>;

pub(crate) struct HostedThreadSuspend {
    owner: RefCell<Option<Owner>>,
}

impl core::fmt::Debug for HostedThreadSuspend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostedThreadSuspend")
            .field("pending", &self.is_pending())
            .finish()
    }
}

impl HostedThreadSuspend {
    pub(crate) const fn new() -> Self {
        Self {
            owner: RefCell::new(None),
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.owner.try_borrow().is_ok_and(|owner| owner.is_none())
    }
    pub(crate) fn is_pending(&self) -> bool {
        self.owner
            .try_borrow()
            .map_or(true, |owner| owner.as_ref().is_some_and(Owner::is_pending))
    }
}

fn status(error: ThreadSuspendError) -> u32 {
    match error {
        ThreadSuspendError::Process(status) => status,
        ThreadSuspendError::Busy | ThreadSuspendError::WrongPhase => nt_process::STATUS_DEVICE_BUSY,
        _ => nt_process::STATUS_UNSUCCESSFUL,
    }
}

fn entry(handler: &ExecNtHandler, tid: u64) -> Option<&HostedThreadRuntimeOwner> {
    unsafe { &*handler.thread_runtime.table }
        .entries
        .iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.tid == tid)
}

/// Construction has retained the exact inactive TCB and has never invoked its first Resume.
pub(crate) unsafe fn publish_dormant(handler: &ExecNtHandler, tid: u64) -> Result<(), u32> {
    let runtime = entry(handler, tid).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let lifetime = handler
        .pm
        .thread_lifetime(tid as nt_process::ThreadId)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let mut slot = runtime
        .suspension
        .owner
        .try_borrow_mut()
        .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    if slot.is_some() {
        return Err(nt_process::STATUS_DEVICE_BUSY);
    }
    *slot = Some(Owner::dormant(runtime.binding(), lifetime).map_err(status)?);
    Ok(())
}

/// Admit the first NtCreateThread against its exact, never-started main TCB. Publish the dormant
/// owner only after count admission succeeds, then retain it through physical and PM ACKs.
pub(crate) unsafe fn create_initial_thread(
    handler: &mut ExecNtHandler,
    tid: nt_process::ThreadId,
    create_suspended: bool,
) -> Result<(), u32> {
    let lifetime = handler
        .pm
        .thread_lifetime(tid)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let binding = handler
        .thread_runtime
        .executable_by_tid(u64::from(tid))
        .ok_or(nt_process::STATUS_DEVICE_BUSY)?
        .binding();
    let invocation = {
        let table = &*handler.thread_runtime.table;
        let runtime = table
            .entries
            .iter()
            .filter_map(|slot| slot.owner())
            .find(|owner| owner.binding() == binding)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let mut slot = runtime
            .suspension
            .owner
            .try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        if handler
            .pm
            .thread(tid)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?
            .suspend_count
            != 0
        {
            return Err(nt_process::STATUS_DEVICE_BUSY);
        }
        let mut fresh = if slot.is_none() {
            Some(Owner::dormant(binding, lifetime).map_err(status)?)
        } else {
            None
        };
        let owner = slot
            .as_mut()
            .or(fresh.as_mut())
            .expect("existing or unpublished dormant owner");
        if owner.execution_state() != ThreadExecutionState::Dormant || owner.is_pending() {
            return Err(nt_process::STATUS_DEVICE_BUSY);
        }
        let phase = if create_suspended {
            owner.prepare(
                &mut handler.pm,
                binding,
                lifetime,
                ThreadSuspendOperation::Suspend,
            )
        } else {
            owner.prepare_initial_start(&mut handler.pm, binding, lifetime)
        }
        .map_err(status)?;
        if let Some(owner) = fresh {
            *slot = Some(owner);
        }
        if phase == ThreadSuspendPhase::Prepared {
            Some(
                slot.as_mut()
                    .expect("admitted startup owner published")
                    .begin()
                    .map_err(status)?,
            )
        } else {
            None
        }
    };
    finish_control(handler, binding, lifetime, invocation).map(|_| ())
}

/// Called only after retirement has acknowledged deletion of this runtime's TCB.
pub(crate) fn tcb_deleted(handler: &ExecNtHandler, tid: u64, tcb: u64) -> bool {
    let Some(runtime) = entry(handler, tid).filter(|runtime| runtime.tcb == tcb) else {
        return false;
    };
    let Ok(mut slot) = runtime.suspension.owner.try_borrow_mut() else {
        return false;
    };
    if slot.as_ref().is_some_and(|owner| !owner.can_retire()) {
        return false;
    }
    *slot = None;
    true
}

pub(crate) unsafe fn control(
    handler: &mut ExecNtHandler,
    tid: nt_process::ThreadId,
    operation: ThreadSuspendOperation,
) -> Result<u32, u32> {
    let lifetime = handler
        .pm
        .thread_lifetime(tid)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let runtime = handler
        .thread_runtime
        .executable_by_tid(u64::from(tid))
        .ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    let binding = runtime.binding();
    // The table is only borrowed within these local scopes. No owner/manager borrow crosses IPC.
    let invocation = {
        let table = &*handler.thread_runtime.table;
        let retained = table
            .entries
            .iter()
            .filter_map(|slot| slot.owner())
            .find(|owner| owner.binding() == binding)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let mut slot = retained
            .suspension
            .owner
            .try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        if slot.is_none() {
            *slot = Some(Owner::running(binding, lifetime).map_err(status)?);
        }
        let owner = slot.as_mut().expect("suspension owner initialized");
        let phase = match owner.prepare(&mut handler.pm, binding, lifetime, operation) {
            Ok(phase) => phase,
            Err(error) => {
                if !owner.is_pending() && owner.execution_state() == ThreadExecutionState::Running {
                    *slot = None;
                }
                return Err(status(error));
            }
        };
        if phase == ThreadSuspendPhase::Prepared {
            Some(owner.begin().map_err(status)?)
        } else {
            None
        }
    };
    finish_control(handler, binding, lifetime, invocation)
}

unsafe fn finish_control(
    handler: &mut ExecNtHandler,
    binding: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    lifetime: nt_process::ThreadLifetime,
    invocation: Option<ThreadSuspendInvocation<HostedThreadRole>>,
) -> Result<u32, u32> {
    let tid = lifetime.thread_id();
    if let Some(invocation) = invocation {
        use sel4_rt::execution_hold::{self, Error};
        let outcome = match invocation.action() {
            ThreadSuspendAction::Acquire { tcb } => match execution_hold::acquire(tcb) {
                Ok(generation) => ThreadSuspendOutcome::Acknowledged {
                    generation: Some(generation),
                },
                Err(Error::Kernel(_)) => ThreadSuspendOutcome::Rejected {
                    status: nt_process::STATUS_UNSUCCESSFUL,
                },
                Err(Error::MalformedReply) => ThreadSuspendOutcome::Indeterminate {
                    status: nt_process::STATUS_UNSUCCESSFUL,
                },
            },
            ThreadSuspendAction::Release { tcb, generation } => {
                match execution_hold::release(tcb, generation) {
                    Ok(()) => ThreadSuspendOutcome::Acknowledged { generation: None },
                    Err(Error::Kernel(_)) => ThreadSuspendOutcome::Rejected {
                        status: nt_process::STATUS_UNSUCCESSFUL,
                    },
                    Err(Error::MalformedReply) => ThreadSuspendOutcome::Indeterminate {
                        status: nt_process::STATUS_UNSUCCESSFUL,
                    },
                }
            }
            ThreadSuspendAction::Start { tcb } => match execution_hold::resume_initial(tcb) {
                Ok(()) => ThreadSuspendOutcome::Acknowledged { generation: None },
                Err(Error::Kernel(_)) => ThreadSuspendOutcome::Rejected {
                    status: nt_process::STATUS_UNSUCCESSFUL,
                },
                Err(Error::MalformedReply) => ThreadSuspendOutcome::Indeterminate {
                    status: nt_process::STATUS_UNSUCCESSFUL,
                },
            },
        };
        let retained = entry(handler, u64::from(tid))
            .filter(|runtime| runtime.binding() == binding)
            .ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        let mut slot = retained
            .suspension
            .owner
            .try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        slot.as_mut()
            .ok_or(nt_process::STATUS_DEVICE_BUSY)?
            .record(invocation, outcome)
            .map_err(|(error, _)| status(error))?;
    }
    let table = &*handler.thread_runtime.table;
    let retained = table
        .entries
        .iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.binding() == binding)
        .ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    let mut slot = retained
        .suspension
        .owner
        .try_borrow_mut()
        .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    let owner = slot.as_mut().ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    let result = owner
        .finish(&mut handler.pm, binding, lifetime)
        .map_err(status)?;
    if owner.execution_state() == ThreadExecutionState::Running {
        *slot = None;
    }
    match result.rejection {
        Some(status) => Err(status),
        None => Ok(result.previous_count),
    }
}
