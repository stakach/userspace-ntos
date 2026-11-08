use super::*;
use nt_user_host::sched_context::{Error, SchedContextConstruction, SchedContextIo};

// Failed attachments own only unbound SCs/empty slots. Never retry binding: the caller may already
// have deleted the failed target TCB. Rows are allocated before any capability is acquired.
static mut CONSTRUCTIONS: Vec<SchedContextConstruction> = Vec::new();

// Workers stay on core zero until concurrent Win32k dispatches have one exact shared-page owner.
pub(crate) const GUEST_SCHED_CONTROL_CORE: u8 = 0;

pub(crate) fn validate_guest_affinity(requested_mask: u64) -> Result<(), u32> {
    nt_user_host::sched_context::validate_hosted_thread_affinity(
        requested_mask,
        SYSTEM_PROCESSOR_COUNT.load(Ordering::Relaxed),
        GUEST_SCHED_CONTROL_CORE,
    )
}

struct Backend {
    core: u8,
}

fn validate_sched_control_core(core: u8) -> Result<(), u64> {
    if !SYSTEM_PROCESSOR_TOPOLOGY_READY.load(Ordering::Acquire) {
        return Err(u64::MAX);
    }
    let online = SYSTEM_PROCESSOR_COUNT.load(Ordering::Relaxed);
    // rust-micro publishes one SchedControl per started CPU in the root CSpace region beginning
    // at SLOT_SCHED_CONTROL. The APIC identity array has the same maximum provisioned capacity.
    let provisioned = SYSTEM_PROCESSOR_APIC_IDS.len() as u64;
    if online == 0 || online > provisioned || u64::from(core) >= online {
        return Err(u64::MAX);
    }
    Ok(())
}

fn checked(status: u64) -> Result<(), u64> {
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

impl SchedContextIo for Backend {
    fn allocate_slot(&mut self) -> Result<u64, u64> {
        try_alloc_slot().ok_or(u64::MAX)
    }
    fn retype(&mut self, slot: u64) -> Result<(), u64> {
        checked(unsafe {
            untyped_retype_r(
                CAP_INIT_UNTYPED,
                OBJ_SCHED_CONTEXT,
                SCHED_CONTEXT_BITS,
                1,
                slot,
            )
        })
    }
    fn configure(&mut self, cap: u64, budget: u64, period: u64) -> Result<(), u64> {
        checked(unsafe { sched_control_configure_r(
            SLOT_SCHED_CONTROL + u64::from(self.core),
            cap,
            budget,
            period,
        ) })
    }
    fn bind(&mut self, cap: u64, tcb: u64) -> Result<(), u64> {
        checked(unsafe { sched_context_bind_r(cap, tcb) })
    }
    fn delete(&mut self, cap: u64) -> Result<(), u64> {
        checked(unsafe { cnode_delete_r(cap) })
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u64> {
        unsafe { root_slot_recycle::publish_empty(slot) }.map_err(|_| u64::MAX)
    }
}

pub(super) unsafe fn attach_sched_context(tcb: u64) -> Result<u64, u64> {
    attach_sched_context_on_core(tcb, GUEST_SCHED_CONTROL_CORE)
}

/// The caller must retain the selected core with the returned SC and publish both together.
/// Refuse an unavailable SchedControl before allocating any capability or construction row.
pub(super) unsafe fn attach_sched_context_on_core(tcb: u64, core: u8) -> Result<u64, u64> {
    validate_sched_control_core(core)?;
    let construction = SchedContextConstruction::new(tcb, 10, 10).ok_or(u64::MAX)?;
    let _durable = allocator::enter_durable();
    let rows = &mut *core::ptr::addr_of_mut!(CONSTRUCTIONS);
    let mut backend = Backend { core };
    rows.retain_mut(|owner| owner.retire(&mut backend).is_err());
    rows.try_reserve(1).map_err(|_| u64::MAX)?;
    rows.push(construction);
    let owner = rows
        .last_mut()
        .expect("SC construction row reserved before allocation");
    match owner.construct(&mut backend) {
        Ok(()) => {
            let cap = owner
                .take_bound()
                .expect("successful SC bind transfers its cap");
            rows.pop();
            Ok(cap)
        }
        Err(Error::Backend { status, .. }) => {
            if owner.retire(&mut backend).is_ok() {
                rows.pop();
            }
            Err(status)
        }
        Err(Error::InvalidState) => unreachable!("new SC construction starts before allocation"),
    }
}
