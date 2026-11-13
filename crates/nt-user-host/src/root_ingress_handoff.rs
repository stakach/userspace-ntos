//! Move-only storage for a selected root Call's held physical parent and pump snapshot.

use nt_component_suspension::{ExternalAdmissionKey, NestedExecutionIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIngressHandoffKey {
    parent: NestedExecutionIdentity,
    child: ExternalAdmissionKey,
    root_reply: u64,
}

impl RootIngressHandoffKey {
    pub fn new(parent: NestedExecutionIdentity, child: ExternalAdmissionKey, root_reply: u64) -> Option<Self> {
        (root_reply != 0 && child.reply() != 0 && child.executor() != 0
            && child.admission_sequence() != 0)
            .then_some(Self { parent, child, root_reply })
    }

    pub const fn parent(self) -> NestedExecutionIdentity { self.parent }
    pub const fn child(self) -> ExternalAdmissionKey { self.child }
    pub const fn root_reply(self) -> u64 { self.root_reply }
}

pub use crate::retained_owner_table::{
    RetainedOwnerError as RootIngressHandoffError,
    RetainedOwnerReservation as RootIngressHandoffReservation,
    RetainedOwnerTransitionError as RootIngressTransitionError,
};

pub type RootIngressHandoffTicket = crate::retained_owner_table::RetainedOwnerTicket<RootIngressHandoffKey>;
pub type RootIngressHandoffTable<B> = crate::retained_owner_table::RetainedOwnerTable<RootIngressHandoffKey, B>;
