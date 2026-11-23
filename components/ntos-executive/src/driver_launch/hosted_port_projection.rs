//! Physical CNode ownership for hosted port-cap projections.
//!
//! A nonzero native result cannot establish whether a child delete/copy took effect. The row
//! retains the prior published bank, the incoming bank, and the exact attempted step until the
//! physical CNode can be retired with proof. Successful rows keep the prior-bank identity needed
//! to fence its root caps if a later projection fails while clearing the same CNode.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PhysicalOwner {
    Primary {
        instance: usize,
        domain_id: u64,
        cookie: u64,
        tcb: u64,
    },
    Thread {
        construction: usize,
        domain_id: u64,
        cookie: u64,
        tcb: u64,
    },
    Irq {
        instance: usize,
        domain_id: u64,
        cookie: u64,
        generation: u64,
        tcb: u64,
    },
}

impl PhysicalOwner {
    fn domain(self) -> (u64, u64) {
        match self {
            Self::Primary {
                domain_id, cookie, ..
            }
            | Self::Thread {
                domain_id, cookie, ..
            }
            | Self::Irq {
                domain_id, cookie, ..
            } => (domain_id, cookie),
        }
    }
}

#[derive(Clone, Copy)]
struct Bank {
    device_id: u64,
    domain_id: u64,
    cookie: u64,
    pdo_object: u64,
}

impl Bank {
    fn from_state(state: HostedDeviceResourceState) -> Self {
        Self {
            device_id: state.device_id,
            domain_id: state.projection_domain.domain_id.raw(),
            cookie: state.projection_domain.cookie,
            pdo_object: state.pdo_object,
        }
    }

    fn matches_domain(self, domain: HostedDomainIdentity) -> bool {
        self.domain_id == domain.domain_id.raw() && self.cookie == domain.cookie
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeStep {
    Delete,
    Copy,
}

#[derive(Clone, Copy)]
struct Attempt {
    step: NativeStep,
    slot: u64,
    root_cap: u64,
}

struct Projection {
    owner: PhysicalOwner,
    cnode: u64,
    published: Option<Bank>,
    incoming: Option<Bank>,
    attempt: Option<Attempt>,
    active: bool,
}

static mut PROJECTIONS: Vec<Projection> = Vec::new();

/// A failed native call leaves this ticket's row active and the attempted step retained.
pub(super) struct Ticket {
    index: usize,
}

impl Ticket {
    pub(super) unsafe fn begin(
        owner: PhysicalOwner,
        cnode: u64,
        state: Option<HostedDeviceResourceState>,
    ) -> Result<Self, nt_status::NtStatus> {
        // A provider runs in its own physical domain while projecting a dependent device's
        // resource bank under an admitted dependency lease. Keep both domains: a later uncertain
        // native effect fences the bank's canonical caps and the provider's physical CNode.
        if cnode == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let projections = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
        if let Some(index) = projections.iter().position(|row| row.cnode == cnode) {
            let row = &mut projections[index];
            if row.owner != owner || row.active {
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            }
            row.incoming = state.map(Bank::from_state);
            row.active = true;
            return Ok(Self { index });
        }
        let _durable = crate::allocator::enter_durable();
        projections
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let index = projections.len();
        projections.push(Projection {
            owner,
            cnode,
            published: None,
            incoming: state.map(Bank::from_state),
            attempt: None,
            active: true,
        });
        Ok(Self { index })
    }

    unsafe fn row(&self) -> &'static mut Projection {
        &mut (&mut *core::ptr::addr_of_mut!(PROJECTIONS))[self.index]
    }

    unsafe fn record(&self, step: NativeStep, slot: u64, root_cap: u64) {
        self.row().attempt = Some(Attempt {
            step,
            slot,
            root_cap,
        });
    }

    unsafe fn acknowledge(&self) {
        self.row().attempt = None;
    }

    pub(super) unsafe fn delete(&self, slot: u64) -> Result<(), nt_status::NtStatus> {
        self.record(NativeStep::Delete, slot, 0);
        if crate::cnode_delete_in_cnode_r(self.row().cnode, slot) != 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        self.acknowledge();
        Ok(())
    }

    pub(super) unsafe fn copy(&self, slot: u64, cap: u64) -> Result<(), nt_status::NtStatus> {
        self.record(NativeStep::Copy, slot, cap);
        let label = crate::cnode_copy_at_r(self.row().cnode, slot, cap);
        if label != 0 {
            print_str(b"[driver-launch] IOPort cap restore failed label=");
            print_u64(label);
            print_str(b" device_id=");
            print_u64(self.row().incoming.map_or(0, |bank| bank.device_id));
            print_str(b" cnode=");
            print_u64(self.row().cnode);
            print_str(b"\n");
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        self.acknowledge();
        Ok(())
    }

    pub(super) unsafe fn finish(self) -> Result<(), nt_status::NtStatus> {
        let row = self.row();
        if !row.active || row.attempt.is_some() {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        row.published = row.incoming.take();
        row.active = false;
        Ok(())
    }
}

pub(super) unsafe fn quarantines_domain(domain: HostedDomainIdentity) -> bool {
    (&*core::ptr::addr_of!(PROJECTIONS)).iter().any(|row| {
        row.active
            && (row
                .published
                .is_some_and(|bank| bank.matches_domain(domain))
                || row.incoming.is_some_and(|bank| bank.matches_domain(domain))
                || row.owner.domain() == (domain.domain_id.raw(), domain.cookie))
    })
}

pub(super) unsafe fn retirement_allowed(cnode: u64, owner: PhysicalOwner) -> bool {
    (&*core::ptr::addr_of!(PROJECTIONS))
        .iter()
        .find(|row| row.cnode == cnode)
        .is_none_or(|row| row.owner == owner && !row.active)
}

/// Called only after exact physical CNode retirement has acknowledged its root-cap cleanup.
pub(super) unsafe fn retired(cnode: u64, owner: PhysicalOwner) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    let Some(index) = rows.iter().position(|row| row.cnode == cnode) else {
        return true;
    };
    if rows[index].owner != owner || rows[index].active {
        return false;
    }
    rows.remove(index);
    true
}
