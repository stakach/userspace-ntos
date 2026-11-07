//! Root-owned, win32k-visible PEJOB bodies and their exact pool receipts.
//!
//! Job identity and restrictions remain in ProcessManager. A body is created
//! only when win32k first asks for that job, since jobs may predate win32k.

use super::*;
use nt_process::kernel_job_body::{JobBodyReceipt, KernelJobBodyOwner};

const BODY_BYTES: u64 = 0x1000;
const RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const NOT_READY: u32 = 0xC000_00A3;

type Allocation = crate::win32k_subsystem::RootProviderPoolAllocation;

impl JobBodyReceipt for Allocation {
    fn address(self) -> u64 { Allocation::address(self) }
}

#[derive(Clone, Copy)]
struct PendingAllocation {
    allocation: Allocation,
    uncertain: bool,
}

#[derive(Clone, Copy)]
struct PendingRetirement {
    destruction: nt_process::job::JobDestruction,
    uncertain: bool,
}

static mut BODIES: KernelJobBodyOwner<Allocation> = KernelJobBodyOwner::new();
static mut UNPUBLISHED: Vec<PendingAllocation> = Vec::new();
static mut RETIREMENTS: Vec<PendingRetirement> = Vec::new();

/// Materialize a shared PEJOB body only after the provider pool is ready.
/// The pool's pinned receipt is retained before PM exposes the pointer.
pub(crate) unsafe fn ensure(
    pm: &mut nt_process::ProcessManager,
    job: nt_process::job::JobId,
) -> Result<u64, u32> {
    redrive();
    if let Some(body) = pm.job_kernel_object(job) {
        return match (&*core::ptr::addr_of!(BODIES)).receipt_for(job) {
            Some(allocation) if allocation.address() == body => Ok(body),
            _ => Err(INVALID),
        };
    }
    if !pm.job_exists(job) {
        return Err(INVALID);
    }
    // An unpublished allocation remains here if PM rejected publication or
    // native cleanup was busy/uncertain. Reserve that owner before allocation.
    (&mut *core::ptr::addr_of_mut!(UNPUBLISHED))
        .try_reserve(1).map_err(|_| RESOURCES)?;
    let allocation = crate::win32k_subsystem::try_allocate_root_provider_pool_allocation(BODY_BYTES)
        .map_err(pool_status)?;
    let body = allocation.address();
    let owner = &mut *core::ptr::addr_of_mut!(BODIES);
    match owner.publish(pm, job, allocation) {
        Ok(()) => Ok(body),
        Err(allocation) => {
            (&mut *core::ptr::addr_of_mut!(UNPUBLISHED)).push(PendingAllocation {
                allocation,
                uncertain: false,
            });
            redrive();
            Err(INVALID)
        }
    }
}

/// Reserve a durable cleanup slot before win32k's termination callout and
/// security rundown take effects. A failed reserve leaves PM destruction live.
pub(crate) unsafe fn prepare_retirement(
    destruction: nt_process::job::JobDestruction,
) -> Result<(), u32> {
    if destruction.kernel_job_object.is_none() { return Ok(()); }
    if (&*core::ptr::addr_of!(BODIES)).retirement_receipt(destruction).is_none() {
        return Err(INVALID);
    }
    (&mut *core::ptr::addr_of_mut!(RETIREMENTS))
        .try_reserve(1).map_err(|_| RESOURCES)
}

/// Called only after the other job teardown effects have completed. There is
/// no rollback/replay of those effects if native pool retirement is delayed.
pub(crate) unsafe fn commit_retirement(destruction: nt_process::job::JobDestruction) {
    if destruction.kernel_job_object.is_none() { return; }
    let pending = &mut *core::ptr::addr_of_mut!(RETIREMENTS);
    debug_assert!(pending.capacity() > pending.len());
    pending.push(PendingRetirement { destruction, uncertain: false });
    redrive();
}

/// Retry only known no-effect refusals. Any uncertain native result keeps its
/// exact receipt and body address quarantined against replay or reuse.
pub(crate) unsafe fn redrive() {
    let unpublished = &mut *core::ptr::addr_of_mut!(UNPUBLISHED);
    let mut index = 0;
    while index < unpublished.len() {
        if unpublished[index].uncertain { index += 1; continue; }
        match crate::win32k_subsystem::try_retire_root_provider_pool_allocation(
            unpublished[index].allocation,
        ) {
            Ok(()) => { unpublished.swap_remove(index); }
            Err(crate::win32k_subsystem::RootPoolError::BusyNoEffect) => index += 1,
            Err(_) => { unpublished[index].uncertain = true; index += 1; }
        }
    }

    let pending = &mut *core::ptr::addr_of_mut!(RETIREMENTS);
    let bodies = &mut *core::ptr::addr_of_mut!(BODIES);
    let mut index = 0;
    while index < pending.len() {
        if pending[index].uncertain { index += 1; continue; }
        let destruction = pending[index].destruction;
        let Some(allocation) = bodies.retirement_receipt(destruction) else {
            pending[index].uncertain = true;
            index += 1;
            continue;
        };
        match crate::win32k_subsystem::try_retire_root_provider_pool_allocation(allocation) {
            Ok(()) => {
                assert!(bodies.acknowledge_retirement(destruction), "PEJOB receipt lost after pool retirement");
                pending.swap_remove(index);
            }
            Err(crate::win32k_subsystem::RootPoolError::BusyNoEffect) => index += 1,
            Err(_) => {
                let body = destruction.kernel_job_object.expect("PEJOB pending without body");
                assert!(bodies.quarantine_retirement(destruction.id, body));
                pending[index].uncertain = true;
                index += 1;
            }
        }
    }
}

fn pool_status(error: crate::win32k_subsystem::RootPoolError) -> u32 {
    match error {
        crate::win32k_subsystem::RootPoolError::InsufficientResources => RESOURCES,
        crate::win32k_subsystem::RootPoolError::BusyNoEffect => NOT_READY,
        crate::win32k_subsystem::RootPoolError::InvalidIdentity
        | crate::win32k_subsystem::RootPoolError::Indeterminate => INVALID,
    }
}
