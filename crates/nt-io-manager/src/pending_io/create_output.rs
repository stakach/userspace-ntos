//! Retained CREATE handle commitment and user-output settlement.

use super::*;
use nt_io_completion::{file_create_output_plan, FileCreateOutputPlan};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CreateOutputSettlement {
    #[default]
    Pending,
    Published,
    Skipped,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCreateOutputAction {
    CommitHandle,
    Handle,
    Information,
    Status,
    Complete,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCreateOutputObservation {
    Succeeded,
    /// Only an explicit pre-effect refusal permits another attempt at this action.
    RetryNoEffect,
    UserFault(u32),
    Uncertain(u32),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PendingCreateOutput {
    action: Option<PendingCreateOutputAction>,
    table_handle_committed: bool,
    handle: CreateOutputSettlement,
    information: CreateOutputSettlement,
    status: CreateOutputSettlement,
    syscall_fault: Option<u32>,
    uncertain_status: Option<u32>,
}

impl PendingCreateOutput {
    pub(super) fn new(status: u32, iosb_present: bool) -> Self {
        use CreateOutputSettlement::{Pending, Skipped};
        use PendingCreateOutputAction::{CommitHandle, Complete, Information};
        let plan = file_create_output_plan(status);
        let handle_required = plan == FileCreateOutputPlan::HandleAndIoStatus;
        let iosb_required = plan != FileCreateOutputPlan::None && iosb_present;
        Self {
            action: Some(if handle_required {
                CommitHandle
            } else if iosb_required {
                Information
            } else {
                Complete
            }),
            handle: if handle_required { Pending } else { Skipped },
            information: if iosb_required { Pending } else { Skipped },
            status: if iosb_required { Pending } else { Skipped },
            ..Self::default()
        }
    }

    pub fn table_handle_committed(self) -> bool {
        self.table_handle_committed
    }
    pub fn handle_settlement(self) -> CreateOutputSettlement {
        self.handle
    }
    pub fn information_settlement(self) -> CreateOutputSettlement {
        self.information
    }
    pub fn status_settlement(self) -> CreateOutputSettlement {
        self.status
    }
    pub fn syscall_fault(self) -> Option<u32> {
        self.syscall_fault
    }
    pub fn uncertain_status(self) -> Option<u32> {
        self.uncertain_status
    }
    pub fn action(self) -> Option<PendingCreateOutputAction> {
        self.action
    }

    pub(super) fn is_complete(self) -> bool {
        self.action == Some(PendingCreateOutputAction::Complete)
    }

    fn observe(
        &mut self,
        action: PendingCreateOutputAction,
        observation: PendingCreateOutputObservation,
    ) -> Option<()> {
        use CreateOutputSettlement::{Faulted, Pending, Published, Skipped};
        use PendingCreateOutputAction::*;
        if self.action != Some(action) || matches!(action, Complete | Uncertain) {
            return None;
        }
        match observation {
            PendingCreateOutputObservation::RetryNoEffect => {}
            PendingCreateOutputObservation::Uncertain(status) => {
                self.uncertain_status = Some(status);
                self.action = Some(Uncertain);
            }
            PendingCreateOutputObservation::UserFault(status) => {
                if action == CommitHandle || (status as i32) >= 0 {
                    return None;
                }
                self.syscall_fault = Some(status);
                match action {
                    Handle => self.handle = Faulted,
                    Information => self.information = Faulted,
                    Status => self.status = Faulted,
                    _ => return None,
                }
                if self.information == Pending {
                    self.information = Skipped;
                }
                if self.status == Pending {
                    self.status = Skipped;
                }
                self.action = Some(Complete);
            }
            PendingCreateOutputObservation::Succeeded => {
                self.action = Some(match action {
                    CommitHandle => {
                        self.table_handle_committed = true;
                        Handle
                    }
                    Handle => {
                        self.handle = Published;
                        if self.information == Pending {
                            Information
                        } else {
                            Complete
                        }
                    }
                    Information => {
                        self.information = Published;
                        Status
                    }
                    Status => {
                        self.status = Published;
                        Complete
                    }
                    _ => return None,
                });
            }
        }
        Some(())
    }
}

impl PendingFileIoTable {
    pub fn create_output_action_exact(
        &self,
        identity: PendingFileIoIdentity,
        irp_id: u64,
    ) -> Option<PendingCreateOutputAction> {
        let pending = self.get_exact(identity)?;
        let PendingFileIoOperation::Create(create) = pending.operation else {
            return None;
        };
        (pending.irp_id == irp_id && pending.delivery_state & IO_DELIVERY_CREATE_COMMITTED != 0)
            .then(|| create.output.action())
            .flatten()
    }

    pub fn observe_create_output_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        irp_id: u64,
        action: PendingCreateOutputAction,
        observation: PendingCreateOutputObservation,
    ) -> Option<u16> {
        if self.create_output_action_exact(identity, irp_id) != Some(action)
            || self.apc_owned_slot(identity.slot)
        {
            return None;
        }
        let pending = self.slots[identity.slot].as_mut()?;
        if pending.delivery_state & (IO_DELIVERY_BACKEND_ACKED | IO_DELIVERY_REPLY_CLAIMED) != 0 {
            return None;
        }
        let PendingFileIoOperation::Create(mut create) = pending.operation else {
            return None;
        };
        create.output.observe(action, observation)?;
        if create.output.handle_settlement() == CreateOutputSettlement::Published {
            pending.delivery_state |= IO_DELIVERY_HANDLE_PUBLISHED;
        }
        if create.output.status_settlement() == CreateOutputSettlement::Published {
            pending.delivery_state |= IO_DELIVERY_IOSB_PUBLISHED;
        }
        pending.operation = PendingFileIoOperation::Create(create);
        Some(pending.delivery_state)
    }

    pub(super) fn create_output_is_settled(pending: PendingFileIo) -> bool {
        match pending.operation {
            PendingFileIoOperation::Create(create) => create.output.is_complete(),
            _ => true,
        }
    }
}
