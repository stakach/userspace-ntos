//! Distinct caller and target identities retained by a cross-process VM lock.

use crate::process_identity::ProcessIdentity;
use crate::provider_logical_caller::ProviderLogicalCaller;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmLockInvocationOwner {
    caller: ProviderLogicalCaller,
    target_pi: usize,
    target: ProcessIdentity,
    reply: u64,
}

impl VmLockInvocationOwner {
    /// Both identities must be independently captured before the original Reply is parked.
    pub fn capture(
        caller: ProviderLogicalCaller, target_pi: usize, target: ProcessIdentity, reply: u64,
    ) -> Option<Self> {
        if reply == 0 || !target.is_valid() || !caller.process().is_valid() { return None; }
        Some(Self { caller, target_pi, target, reply })
    }

    pub fn matches(
        self, caller: ProviderLogicalCaller, target_pi: usize,
        target: ProcessIdentity, reply: u64,
    ) -> bool {
        self.caller == caller && self.target_pi == target_pi
            && self.target == target && self.reply == reply
    }

    pub const fn caller(self) -> ProviderLogicalCaller { self.caller }
    pub const fn target_pi(self) -> usize { self.target_pi }
    pub const fn target(self) -> ProcessIdentity { self.target }
    pub const fn reply(self) -> u64 { self.reply }
}

#[cfg(test)]
#[path = "vm_lock_owner_tests.rs"]
mod tests;
