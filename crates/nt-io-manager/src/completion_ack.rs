//! Neutral foreign acknowledgement classification and canonical ACK reservation identity.

use crate::IrpId;
use nt_status::NtStatus;

/// Produced by the trusted backend adapter, not inferred from transport Reply success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionAcknowledgement {
    Acknowledged,
    NotEntered { status: NtStatus },
    Rejected { status: NtStatus },
    Indeterminate { transport_status: NtStatus },
}

impl CompletionAcknowledgement {
    pub(crate) fn checked_status(self) -> Result<(), NtStatus> {
        match self {
            Self::Acknowledged => Ok(()),
            Self::NotEntered { status } | Self::Rejected { status } => Err(status),
            Self::Indeterminate { transport_status } => Err(transport_status),
        }
    }

    pub(crate) fn permits_retry(self) -> bool {
        matches!(self, Self::NotEntered { .. } | Self::Rejected { .. })
    }
}

/// Stored in the actual canonical IRP, not in an independent owner table. The manager identity
/// and generation-bearing IrpId identify one reservation; private issuance requires an unreserved
/// actual terminal record. The corresponding non-Copy invocation is its sole external owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompletionAckReservation {
    manager: u64,
    irp: IrpId,
}

impl CompletionAckReservation {
    pub(crate) fn new(manager: u64, irp: IrpId) -> Result<Self, NtStatus> {
        if manager == 0 || irp == IrpId::NULL {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self { manager, irp })
    }

    pub(crate) fn matches(self, manager: u64, irp: IrpId) -> bool {
        self.manager == manager && self.irp == irp
    }
}
