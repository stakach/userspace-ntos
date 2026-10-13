//! Exact, retained ownership for a foreign keyboard or mouse CONNECT IRP.
//!
//! The native adapter owns the source IRP, its METHOD_NEITHER `CONNECT_DATA`, and its
//! reply separately. This contract holds the lower device reference and records whether
//! a real provider dispatch may have occurred. An uncertain result cannot be replayed.

use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget,
    source_irp_ledger::SourceIrpForwardIdentity,
    HostedDevicePointerRegistration, IoManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectControl {
    Keyboard,
    Mouse,
}

impl ConnectControl {
    pub const fn code(self) -> u32 {
        // ReactOS kbdmou.h: CTL_CODE(FILE_DEVICE_*, 0x80, METHOD_NEITHER, FILE_ANY_ACCESS).
        let device_type = match self {
            Self::Keyboard => 0x0b,
            Self::Mouse => 0x0f,
        };
        nt_io_abi::ioctl::ctl_code(device_type, 0x80, nt_io_abi::ioctl::METHOD_NEITHER, 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectForwardIdentity {
    pub source: SourceIrpForwardIdentity,
    pub target: HostedDevicePointerRegistration,
    pub control: ConnectControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectForwardError {
    WrongIdentity,
    Target(NtStatus),
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectDispatchReturn {
    Pending,
    Terminal(NtStatus),
    Indeterminate(NtStatus),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectForwardPhase {
    Prepared,
    Entered,
    Pending,
    Terminal(NtStatus),
    TerminalConsumed,
    Indeterminate(NtStatus),
}

/// Retains the exact lower device until native source completion and provider ACK.
#[must_use = "retain the lower device until the source completion retires"]
#[derive(Debug)]
pub struct RetainedConnectForward {
    identity: ConnectForwardIdentity,
    target: HostedForwardTarget,
    phase: ConnectForwardPhase,
}

impl RetainedConnectForward {
    pub fn new(source: SourceIrpForwardIdentity, target: HostedForwardTarget, control: ConnectControl) -> Self {
        Self {
            identity: ConnectForwardIdentity {
                source,
                target: target.registration(),
                control,
            },
            target,
            phase: ConnectForwardPhase::Prepared,
        }
    }

    pub const fn identity(&self) -> ConnectForwardIdentity { self.identity }
    pub const fn phase(&self) -> ConnectForwardPhase { self.phase }

    /// The caller must first reserve and validate its source IRP and callback authority.
    pub fn enter<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ConnectForwardIdentity,
    ) -> Result<(), ConnectForwardError> {
        if observed != self.identity {
            return Err(ConnectForwardError::WrongIdentity);
        }
        if self.identity.source.allocation().domain != self.identity.target.domain() {
            return Err(ConnectForwardError::WrongIdentity);
        }
        self.target.validate(io).map_err(ConnectForwardError::Target)?;
        if self.phase != ConnectForwardPhase::Prepared {
            return Err(ConnectForwardError::InvalidTransition);
        }
        self.phase = ConnectForwardPhase::Entered;
        Ok(())
    }

    /// Observe the real lower dispatch. PENDING and uncertainty retain all authority.
    pub fn observe_dispatch<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ConnectForwardIdentity,
        result: ConnectDispatchReturn,
    ) -> Result<ConnectForwardPhase, ConnectForwardError> {
        if observed != self.identity {
            return Err(ConnectForwardError::WrongIdentity);
        }
        self.target.validate(io).map_err(ConnectForwardError::Target)?;
        let next = match (self.phase, result) {
            (ConnectForwardPhase::Entered, ConnectDispatchReturn::Pending) => {
                ConnectForwardPhase::Pending
            }
            (
                ConnectForwardPhase::Entered | ConnectForwardPhase::Pending,
                ConnectDispatchReturn::Terminal(status),
            ) if status != NtStatus::PENDING => ConnectForwardPhase::Terminal(status),
            (ConnectForwardPhase::Entered | ConnectForwardPhase::Pending, ConnectDispatchReturn::Indeterminate(status)) => {
                ConnectForwardPhase::Indeterminate(status)
            }
            _ => return Err(ConnectForwardError::InvalidTransition),
        };
        self.phase = next;
        Ok(next)
    }

    /// Consume a terminal exactly once, after the native adapter has completed the source IRP.
    /// The retained target remains held until `retire_after_source_completion` succeeds.
    pub fn consume_terminal<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ConnectForwardIdentity,
    ) -> Result<NtStatus, ConnectForwardError> {
        if observed != self.identity {
            return Err(ConnectForwardError::WrongIdentity);
        }
        self.target.validate(io).map_err(ConnectForwardError::Target)?;
        let ConnectForwardPhase::Terminal(status) = self.phase else {
            return Err(ConnectForwardError::InvalidTransition);
        };
        self.phase = ConnectForwardPhase::TerminalConsumed;
        Ok(status)
    }

    /// Release the lower Device reference only after caller-local terminal work and provider ACK.
    /// A failed release returns the owner intact for reconciliation.
    pub fn retire_after_source_completion<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<(), (ConnectForwardError, Self)> {
        if self.phase != ConnectForwardPhase::TerminalConsumed {
            return Err((ConnectForwardError::InvalidTransition, self));
        }
        if let Err(status) = self.target.release(io) {
            return Err((ConnectForwardError::Target(status), self));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use crate::{DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort};
    use crate::retained_query_path_forward::SourceIrpTicket;
    use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner};
    use nt_types::NtPath;

    fn source(domain: crate::HostedDomainIdentity, generation: u64) -> SourceIrpForwardIdentity {
        let ticket = SourceIrpTicket::new(domain, 17, generation).unwrap();
        SourceIrpForwardIdentity::new(ticket, SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(0),
            domain,
            component_address: 0x7000,
            bytes: 0x100,
            stack_count: 3,
            pool_generation: generation,
        }).unwrap()
    }

    #[test]
    fn pending_connect_retains_exact_owner_and_cannot_reenter() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(
            &NtPath::parse_str(r"\Driver\ConnectForward").unwrap(),
            Box::new(MockDriverBackend::new()),
        ).unwrap();
        let device = io.create_device(
            driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device).unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let mut forward = RetainedConnectForward::new(source(domain, 3), target, ConnectControl::Keyboard);
        let identity = forward.identity();
        assert_eq!(identity.control.code(), 0x000b_0203);
        assert_eq!(forward.enter(&io, identity), Ok(()));
        assert_eq!(
            forward.observe_dispatch(&io, identity, ConnectDispatchReturn::Pending),
            Ok(ConnectForwardPhase::Pending),
        );
        assert_eq!(forward.enter(&io, identity), Err(ConnectForwardError::InvalidTransition));
        let wrong = ConnectForwardIdentity {
            source: source(domain, 4),
            ..identity
        };
        assert_eq!(
            forward.observe_dispatch(&io, wrong, ConnectDispatchReturn::Terminal(NtStatus::SUCCESS)),
            Err(ConnectForwardError::WrongIdentity),
        );
        assert_eq!(forward.phase(), ConnectForwardPhase::Pending);
        assert_eq!(
            forward.observe_dispatch(&io, identity, ConnectDispatchReturn::Terminal(NtStatus::SUCCESS)),
            Ok(ConnectForwardPhase::Terminal(NtStatus::SUCCESS)),
        );
        assert_eq!(forward.consume_terminal(&io, identity), Ok(NtStatus::SUCCESS));
        assert_eq!(forward.consume_terminal(&io, identity), Err(ConnectForwardError::InvalidTransition));
        assert!(forward.retire_after_source_completion(&mut io).is_ok());
    }

    #[test]
    fn wrong_target_and_unknown_effect_never_authorize_replay() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(
            &NtPath::parse_str(r"\Driver\ConnectForwardOther").unwrap(),
            Box::new(MockDriverBackend::new()),
        ).unwrap();
        let first = io.create_device(
            driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ).unwrap();
        let second = io.create_device(
            driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, first).unwrap();
        let wrong_target = io.bind_hosted_device_pointer(domain, 0x6000, second).unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let mut forward = RetainedConnectForward::new(source(domain, 1), target, ConnectControl::Mouse);
        let identity = forward.identity();
        assert_eq!(identity.control.code(), 0x000f_0203);
        assert_eq!(forward.enter(&io, ConnectForwardIdentity { target: wrong_target, ..identity }), Err(ConnectForwardError::WrongIdentity));
        assert_eq!(forward.phase(), ConnectForwardPhase::Prepared);
        assert_eq!(forward.enter(&io, identity), Ok(()));
        assert_eq!(
            forward.observe_dispatch(&io, identity, ConnectDispatchReturn::Indeterminate(NtStatus::DEVICE_NOT_CONNECTED)),
            Ok(ConnectForwardPhase::Indeterminate(NtStatus::DEVICE_NOT_CONNECTED)),
        );
        assert_eq!(forward.enter(&io, identity), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(forward.observe_dispatch(&io, identity, ConnectDispatchReturn::Pending), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(forward.consume_terminal(&io, identity), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(
            forward.observe_dispatch(&io, identity, ConnectDispatchReturn::Terminal(NtStatus::SUCCESS)),
            Err(ConnectForwardError::InvalidTransition),
        );
        assert_eq!(forward.phase(), ConnectForwardPhase::Indeterminate(NtStatus::DEVICE_NOT_CONNECTED));
    }
}
