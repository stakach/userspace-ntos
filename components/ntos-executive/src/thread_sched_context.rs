use super::*;
use nt_user_host::sched_context::{Error, SchedContextConstruction, SchedContextIo};

// Failed attachments own only unbound SCs/empty slots. Never retry binding: the caller may already
// have deleted the failed target TCB. Rows are allocated before any capability is acquired.
static mut CONSTRUCTIONS: Vec<SchedContextConstruction> = Vec::new();

struct Backend;

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
        checked(unsafe { sched_control_configure_r(cap, budget, period) })
    }
    fn bind(&mut self, cap: u64, tcb: u64) -> Result<(), u64> {
        checked(unsafe { sched_context_bind_r(cap, tcb) })
    }
    fn delete(&mut self, cap: u64) -> Result<(), u64> {
        checked(unsafe { cnode_delete_r(cap) })
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u64> {
        // The legacy recycler is infallible only after these checks, under this serialized borrow.
        // In particular, never clear the live bit/accounting before free-list space is available.
        let Some((word, bit)) = root_slot_bit(slot) else {
            return Err(u64::MAX);
        };
        unsafe {
            let live =
                core::ptr::read((core::ptr::addr_of!(ROOT_SLOT_LIVE_BITS) as *const u64).add(word));
            if root_slot_is_pinned(slot)
                || live & bit == 0
                || ROOT_SLOT_RECYCLE_N.load(Ordering::Relaxed) >= ROOT_SLOT_RECYCLE_CAP as u64
            {
                return Err(u64::MAX);
            }
            recycle_deleted_root_slot(slot);
        }
        Ok(())
    }
}

pub(super) unsafe fn attach_sched_context(tcb: u64) -> Result<u64, u64> {
    let construction = SchedContextConstruction::new(tcb, 10, 10).ok_or(u64::MAX)?;
    let _durable = allocator::enter_durable();
    let rows = &mut *core::ptr::addr_of_mut!(CONSTRUCTIONS);
    let mut backend = Backend;
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
