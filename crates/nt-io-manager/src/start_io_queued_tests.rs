use super::*;
use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner};
use crate::{HostedDomainId, HostedDomainIdentity};
use alloc::rc::Rc;
use core::cell::Cell;

fn identity(ticket_generation: u64, pool_generation: u64, address: u64) -> SourceIrpForwardIdentity {
    let domain = HostedDomainIdentity { domain_id: HostedDomainId(9), cookie: 17 };
    let ticket = SourceIrpTicket::new(domain, 31, ticket_generation).unwrap();
    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(1), domain, component_address: address,
        bytes: 0xd0, stack_count: 1, pool_generation,
    };
    SourceIrpForwardIdentity::new(ticket, allocation).unwrap()
}

struct Owner(Rc<Cell<usize>>);
impl Drop for Owner {
    fn drop(&mut self) { self.0.set(self.0.get() + 1); }
}

#[test]
fn selected_packet_transfers_only_its_exact_queued_owner() {
    // The WDM queue makes FIFO/keyed selection. This receipt checks only the selected lifetime.
    let drops = Rc::new(Cell::new(0));
    let first = identity(1, 1, 0x1000);
    let second = identity(2, 1, 0x2000);
    let queued = QueuedStartIo::new(first, Owner(drops.clone()));
    let queued = queued.select(second).err().expect("another packet cannot take this owner");
    assert_eq!(drops.get(), 0);
    drop(queued.select(first).ok().expect("actual selected packet owns this receipt"));
    assert_eq!(drops.get(), 1);
}

#[test]
fn reused_address_and_ticket_cannot_complete_old_queued_cancel() {
    let drops = Rc::new(Cell::new(0));
    let first = identity(1, 1, 0x1000);
    let reused = identity(2, 2, 0x1000);
    let mut cancel = QueuedStartIo::new(first, Owner(drops.clone()))
        .begin_cancel(first).ok().unwrap();
    assert!(cancel.observe_terminal(reused).is_err());
    assert!(cancel.callback_returned(reused).is_err());
    assert_eq!(drops.get(), 0);
    assert!(cancel.finish().is_err(), "wrong generation cannot settle ownership");
}

#[test]
fn queued_cancel_retains_owner_until_terminal_and_callback_return_in_either_order() {
    for terminal_first in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let packet = identity(1, 1, 0x1000);
        let mut cancel = QueuedStartIo::new(packet, Owner(drops.clone()))
            .begin_cancel(packet).ok().unwrap();
        if terminal_first {
            cancel.observe_terminal(packet).unwrap();
        } else {
            cancel.callback_returned(packet).unwrap();
        }
        // Refusal returns the still-owned value for the second independent observation.
        let mut cancel = cancel.finish().err().expect("one observation is insufficient");
        if terminal_first {
            cancel.callback_returned(packet).unwrap();
        } else {
            cancel.observe_terminal(packet).unwrap();
        }
        drop(cancel.finish().ok().unwrap());
        assert_eq!(drops.get(), 1);
    }
}
