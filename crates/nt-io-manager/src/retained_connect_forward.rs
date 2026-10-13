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

/// A pool allocation containing the caller's METHOD_NEITHER CONNECT_DATA. The
/// native adapter must prove liveness under the pool lock before capturing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectBufferAllocation {
    pub domain: crate::HostedDomainIdentity,
    pub base: u64,
    pub bytes: u64,
    pub generation: u64,
}

/// An authenticated live provider thread stack range. The native adapter owns
/// the thread/stack lease and must keep it through synchronous completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectStackRange {
    pub domain: crate::HostedDomainIdentity,
    pub thread: u64,
    pub base: u64,
    pub bytes: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectBufferSource {
    Pool(ConnectBufferAllocation),
    Stack(ConnectStackRange),
}

fn contains_range(base: u64, bytes: u64, pointer: u64, length: u64) -> bool {
    base != 0
        && bytes != 0
        && pointer != 0
        && length != 0
        && base.checked_add(bytes).is_some_and(|end| {
            pointer >= base
                && pointer.checked_add(length).is_some_and(|requested_end| requested_end <= end)
        })
}

impl ConnectBufferSource {
    fn contains(self, domain: crate::HostedDomainIdentity, pointer: u64, length: u64) -> bool {
        match self {
            Self::Pool(allocation) => allocation.contains(domain, pointer, length),
            Self::Stack(stack) => {
                stack.domain == domain
                    && stack.thread != 0
                    && stack.generation != 0
                    && contains_range(stack.base, stack.bytes, pointer, length)
            }
        }
    }
}

impl ConnectBufferAllocation {
    fn contains(self, domain: crate::HostedDomainIdentity, pointer: u64, length: u64) -> bool {
        self.domain == domain
            && self.generation != 0
            && contains_range(self.base, self.bytes, pointer, length)
    }
}

/// The exact source buffer and class callback pair observed before forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectPayloadIdentity {
    pub forward: ConnectForwardIdentity,
    pub buffer: ConnectBufferSource,
    pub input_pointer: u64,
    pub input_length: u64,
    /// Owned bytes copied under the source memory lease before provider entry.
    pub snapshot: [u8; 16],
    pub class_device: HostedDevicePointerRegistration,
    pub class_service: u64,
}

impl ConnectPayloadIdentity {
    pub const CONNECT_DATA_BYTES: u64 = 16;

    /// `class_device` is the exact source-domain projection of the callback's
    /// first argument; `expected_class_device` is its canonical device identity.
    pub fn validate<P>(
        self,
        io: &IoManager<P>,
        retained: &RetainedConnectForward,
        expected_class_device: crate::DeviceId,
    ) -> Result<(), ConnectForwardError> {
        let source_domain = self.forward.source.allocation().domain;
        let mut expected_snapshot = [0; 16];
        expected_snapshot[..8].copy_from_slice(&self.class_device.address().to_le_bytes());
        expected_snapshot[8..].copy_from_slice(&self.class_service.to_le_bytes());
        if self.forward != retained.identity()
            || self.forward.target.domain() != source_domain
            || retained.target.validate(io).ok() != Some(self.forward.target.device_id())
            || self.input_length != Self::CONNECT_DATA_BYTES
            || self.input_pointer & 7 != 0
            || !self.buffer.contains(source_domain, self.input_pointer, self.input_length)
            || self.class_device.domain() != source_domain
            || self.class_device.device_id() != expected_class_device
            || io.hosted_device_pointer_registration(source_domain, self.class_device.address()) != Some(self.class_device)
            || self.class_service == 0
            || self.snapshot != expected_snapshot
        {
            return Err(ConnectForwardError::WrongIdentity);
        }
        Ok(())
    }
}

/// The port driver's reverse HOOK request to the attached class device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookPayloadIdentity {
    pub connect: ConnectPayloadIdentity,
    pub source: SourceIrpForwardIdentity,
    pub buffer: HookBufferSource,
    pub input_pointer: u64,
    pub input_length: u64,
    /// Owned bytes captured before forwarding; mouse uses the first 40 bytes.
    pub snapshot: [u8; 48],
    pub class_target: HostedDevicePointerRegistration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookDeviceExtensionRange {
    pub owner: HostedDevicePointerRegistration,
    pub base: u64,
    pub bytes: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookBufferSource {
    Pool(ConnectBufferAllocation),
    DeviceExtension(HookDeviceExtensionRange),
}

impl HookPayloadIdentity {
    pub const fn code(self) -> u32 {
        let device_type = match self.connect.forward.control {
            ConnectControl::Keyboard => 0x0b,
            ConnectControl::Mouse => 0x0f,
        };
        nt_io_abi::ioctl::ctl_code(device_type, 0x0ff0, nt_io_abi::ioctl::METHOD_NEITHER, 0)
    }

    pub fn validate<P>(
        self,
        io: &IoManager<P>,
        retained_connect: &RetainedConnectForward,
        retained_class_target: &HostedForwardTarget,
        expected_source: SourceIrpForwardIdentity,
        expected_source_device: HostedDevicePointerRegistration,
    ) -> Result<(), ConnectForwardError> {
        let class_id = self.connect.class_device.device_id();
        self.connect.validate(io, retained_connect, class_id)?;
        let source_domain = self.source.allocation().domain;
        let required_bytes = match self.connect.forward.control {
            ConnectControl::Keyboard => 48,
            ConnectControl::Mouse => 40,
        };
        let source_live = expected_source_device.domain() == source_domain
            && expected_source_device.device_id() == self.connect.forward.target.device_id()
            && io.hosted_device_pointer_registration(source_domain, expected_source_device.address())
                == Some(expected_source_device);
        let buffer_live = match self.buffer {
            HookBufferSource::Pool(allocation) => {
                allocation.contains(source_domain, self.input_pointer, self.input_length)
            }
            HookBufferSource::DeviceExtension(extension) => {
                extension.owner == expected_source_device
                    && extension.generation != 0
                    && contains_range(extension.base, extension.bytes, self.input_pointer, self.input_length)
            }
        };
        if source_domain == self.connect.forward.source.allocation().domain
            || self.source != expected_source
            || !matches!(retained_connect.phase(), ConnectForwardPhase::Entered | ConnectForwardPhase::Pending)
            || !source_live
            || self.input_length != required_bytes
            || self.input_pointer & 7 != 0
            || !buffer_live
            || self.class_target.domain() != source_domain
            || self.class_target != retained_class_target.registration()
            || retained_class_target.validate(io).ok() != Some(self.class_target.device_id())
            || io.top_of_device_stack(expected_source_device.device_id()).ok()
                != Some(self.class_target.device_id())
        {
            return Err(ConnectForwardError::WrongIdentity);
        }
        Ok(())
    }
}

/// ReactOS i8042prt completes its pending CONNECT only after the reverse HOOK
/// has returned (or its wait has observed completion). This records that order
/// without treating the port's dispatch return as provider completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookForwardPhase {
    AwaitingHook,
    Entered(SourceIrpForwardIdentity),
    Terminal(SourceIrpForwardIdentity, NtStatus),
    ConnectTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I8042ConnectHookSequence {
    connect: ConnectForwardIdentity,
    phase: HookForwardPhase,
}

impl I8042ConnectHookSequence {
    pub const fn new(connect: ConnectForwardIdentity) -> Self {
        Self { connect, phase: HookForwardPhase::AwaitingHook }
    }

    pub const fn phase(&self) -> HookForwardPhase { self.phase }

    pub fn enter_hook<P>(
        &mut self,
        io: &IoManager<P>,
        connect: &RetainedConnectForward,
        hook: HookPayloadIdentity,
        class_target: &HostedForwardTarget,
        source: SourceIrpForwardIdentity,
        source_device: HostedDevicePointerRegistration,
    ) -> Result<(), ConnectForwardError> {
        if self.phase != HookForwardPhase::AwaitingHook || connect.identity() != self.connect {
            return Err(ConnectForwardError::InvalidTransition);
        }
        hook.validate(io, connect, class_target, source, source_device)?;
        self.phase = HookForwardPhase::Entered(source);
        Ok(())
    }

    pub fn observe_hook_terminal(
        &mut self,
        source: SourceIrpForwardIdentity,
        status: NtStatus,
    ) -> Result<(), ConnectForwardError> {
        if self.phase != HookForwardPhase::Entered(source) || status == NtStatus::PENDING {
            return Err(ConnectForwardError::InvalidTransition);
        }
        self.phase = HookForwardPhase::Terminal(source, status);
        Ok(())
    }

    pub fn observe_connect_terminal<P>(
        &mut self,
        io: &IoManager<P>,
        connect: &mut RetainedConnectForward,
        status: NtStatus,
    ) -> Result<ConnectForwardPhase, ConnectForwardError> {
        if !matches!(self.phase, HookForwardPhase::Terminal(_, _))
            || connect.identity() != self.connect
        {
            return Err(ConnectForwardError::InvalidTransition);
        }
        let phase = connect.observe_dispatch(io, self.connect, ConnectDispatchReturn::Terminal(status))?;
        self.phase = HookForwardPhase::ConnectTerminal;
        Ok(phase)
    }
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
    payload: Option<ConnectPayloadIdentity>,
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
            payload: None,
            phase: ConnectForwardPhase::Prepared,
        }
    }

    pub const fn identity(&self) -> ConnectForwardIdentity { self.identity }
    pub const fn phase(&self) -> ConnectForwardPhase { self.phase }

    /// Capture the identity of the separately pinned source pool allocation.
    /// Native must keep that pin until the source CONNECT has completed.
    pub fn capture_payload<P>(
        &mut self,
        io: &IoManager<P>,
        payload: ConnectPayloadIdentity,
        expected_class_device: crate::DeviceId,
    ) -> Result<(), ConnectForwardError> {
        if self.phase != ConnectForwardPhase::Prepared || self.payload.is_some() {
            return Err(ConnectForwardError::InvalidTransition);
        }
        payload.validate(io, self, expected_class_device)?;
        self.payload = Some(payload);
        Ok(())
    }

    /// Cancel only before provider entry. The native adapter must separately release its source
    /// IRP and stack leases after this exact target reference has been retired.
    pub fn abort_before_enter<P>(
        mut self,
        io: &mut IoManager<P>,
        observed: ConnectForwardIdentity,
    ) -> Result<(), (ConnectForwardError, Self)> {
        if self.identity != observed || self.phase != ConnectForwardPhase::Prepared {
            return Err((ConnectForwardError::InvalidTransition, self));
        }
        if let Err(status) = self.target.release(io) {
            return Err((ConnectForwardError::Target(status), self));
        }
        Ok(())
    }

    /// A reused address with a new allocation generation cannot impersonate the
    /// CONNECT_DATA captured before the provider was entered.
    pub fn validate_payload<P>(
        &self,
        io: &IoManager<P>,
        observed: ConnectPayloadIdentity,
    ) -> Result<(), ConnectForwardError> {
        if self.payload != Some(observed) {
            return Err(ConnectForwardError::WrongIdentity);
        }
        observed.validate(io, self, observed.class_device.device_id())
    }

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
        let payload = self.payload.ok_or(ConnectForwardError::InvalidTransition)?;
        payload.validate(io, self, payload.class_device.device_id())?;
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

    fn capture_test_stack_payload(
        io: &mut IoManager<MockObjectPort>,
        forward: &mut RetainedConnectForward,
        domain: crate::HostedDomainIdentity,
        class: crate::DeviceId,
    ) {
        let class_registration = io.bind_hosted_device_pointer(domain, 0x7000, class).unwrap();
        let mut snapshot = [0; 16];
        snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
        snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
        let payload = ConnectPayloadIdentity {
            forward: forward.identity(),
            buffer: ConnectBufferSource::Stack(ConnectStackRange {
                domain, thread: 7, base: 0x7000, bytes: 0x1000, generation: 11,
            }),
            input_pointer: 0x7ff0,
            input_length: 16,
            snapshot,
            class_device: class_registration,
            class_service: 0x9000,
        };
        forward.capture_payload(io, payload, class).unwrap();
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
        let class = io.create_device(driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device).unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let mut forward = RetainedConnectForward::new(source(domain, 3), target, ConnectControl::Keyboard);
        capture_test_stack_payload(&mut io, &mut forward, domain, class);
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
        let class = io.create_device(driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, first).unwrap();
        let wrong_target = io.bind_hosted_device_pointer(domain, 0x6000, second).unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let mut forward = RetainedConnectForward::new(source(domain, 1), target, ConnectControl::Mouse);
        capture_test_stack_payload(&mut io, &mut forward, domain, class);
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

    #[test]
    fn connect_payload_requires_exact_live_buffer_and_class_callback_projection() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(&NtPath::parse_str(r"\Driver\ConnectPayload").unwrap(), Box::new(MockDriverBackend::new())).unwrap();
        let lower = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let class = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let domain = io.register_hosted_domain();
        let other = io.register_hosted_domain();
        let lower_registration = io.bind_hosted_device_pointer(domain, 0x5000, lower).unwrap();
        let class_registration = io.bind_hosted_device_pointer(domain, 0x6000, class).unwrap();
        let wrong_class = io.bind_hosted_device_pointer(other, 0x6000, class).unwrap();
        let mut retained = RetainedConnectForward::new(
            source(domain, 3),
            HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap(),
            ConnectControl::Keyboard,
        );
        let mut snapshot = [0; 16];
        snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
        snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
        let payload = ConnectPayloadIdentity {
            forward: ConnectForwardIdentity { source: source(domain, 3), target: lower_registration, control: ConnectControl::Keyboard },
            buffer: ConnectBufferSource::Pool(ConnectBufferAllocation { domain, base: 0x8000, bytes: 0x20, generation: 9 }),
            input_pointer: 0x8000,
            input_length: ConnectPayloadIdentity::CONNECT_DATA_BYTES,
            snapshot,
            class_device: class_registration,
            class_service: 0x9000,
        };
        assert_eq!(payload.validate(&io, &retained, class), Ok(()));
        assert_eq!(retained.capture_payload(&io, payload, class), Ok(()));
        assert_eq!(retained.validate_payload(&io, payload), Ok(()));
        assert_eq!(
            retained.validate_payload(&io, ConnectPayloadIdentity {
                buffer: ConnectBufferSource::Pool(ConnectBufferAllocation { domain, base: 0x8000, bytes: 0x20, generation: 10 }),
                ..payload
            }),
            Err(ConnectForwardError::WrongIdentity),
        );
        assert_eq!(
            retained.capture_payload(&io, payload, class),
            Err(ConnectForwardError::InvalidTransition),
        );
        for bad in [
            ConnectPayloadIdentity { input_pointer: 0x8018, ..payload },
            ConnectPayloadIdentity { input_length: 8, ..payload },
            ConnectPayloadIdentity { buffer: ConnectBufferSource::Pool(ConnectBufferAllocation { domain, base: 0x8000, bytes: 0x20, generation: 0 }), ..payload },
            ConnectPayloadIdentity { buffer: ConnectBufferSource::Pool(ConnectBufferAllocation { domain: other, base: 0x8000, bytes: 0x20, generation: 9 }), ..payload },
            ConnectPayloadIdentity { class_device: wrong_class, ..payload },
            ConnectPayloadIdentity { class_service: 0, ..payload },
        ] {
            assert_eq!(bad.validate(&io, &retained, class), Err(ConnectForwardError::WrongIdentity));
        }
        assert_eq!(payload.validate(&io, &retained, lower), Err(ConnectForwardError::WrongIdentity));
    }

    #[test]
    fn reverse_hook_keeps_connect_class_pair_and_its_own_source_allocation() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(&NtPath::parse_str(r"\Driver\HookPayload").unwrap(), Box::new(MockDriverBackend::new())).unwrap();
        let lower = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let class = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let main_class = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        io.attach_device_to_stack(class, lower).unwrap();
        let port_domain = io.register_hosted_domain();
        let class_domain = io.register_hosted_domain();
        let lower_registration = io.bind_hosted_device_pointer(class_domain, 0x5000, lower).unwrap();
        let class_registration = io.bind_hosted_device_pointer(class_domain, 0x6000, main_class).unwrap();
        io.bind_hosted_device_pointer(class_domain, 0x6100, class).unwrap();
        let class_in_port = io.bind_hosted_device_pointer(port_domain, 0x7000, class).unwrap();
        let source_in_port = io.bind_hosted_device_pointer(port_domain, 0x8000, lower).unwrap();
        let mut retained_connect = RetainedConnectForward::new(
            source(class_domain, 3),
            HostedForwardTarget::capture(&mut io, class_domain, 0x5000).unwrap(),
            ConnectControl::Keyboard,
        );
        let retained_class_target = HostedForwardTarget::capture(&mut io, port_domain, 0x7000).unwrap();
        let mut snapshot = [0; 16];
        snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
        snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
        let connect = ConnectPayloadIdentity {
            forward: ConnectForwardIdentity { source: source(class_domain, 3), target: lower_registration, control: ConnectControl::Keyboard },
            buffer: ConnectBufferSource::Pool(ConnectBufferAllocation { domain: class_domain, base: 0x8000, bytes: 0x20, generation: 9 }),
            input_pointer: 0x8000,
            input_length: 16,
            snapshot,
            class_device: class_registration,
            class_service: 0x9000,
        };
        retained_connect.capture_payload(&io, connect, main_class).unwrap();
        retained_connect.enter(&io, retained_connect.identity()).unwrap();
        retained_connect.observe_dispatch(&io, retained_connect.identity(), ConnectDispatchReturn::Pending).unwrap();
        let hook_source = source(port_domain, 4);
        let hook = HookPayloadIdentity {
            connect,
            source: hook_source,
            buffer: HookBufferSource::Pool(ConnectBufferAllocation { domain: port_domain, base: 0xa000, bytes: 48, generation: 10 }),
            input_pointer: 0xa000,
            input_length: 48,
            snapshot: [0; 48],
            class_target: class_in_port,
        };
        assert_eq!(hook.code(), 0x000b_3fc3);
        assert_eq!(hook.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Ok(()));
        let mut sequence = I8042ConnectHookSequence::new(retained_connect.identity());
        assert_eq!(
            sequence.observe_connect_terminal(&io, &mut retained_connect, NtStatus::SUCCESS),
            Err(ConnectForwardError::InvalidTransition),
        );
        let wrong_top = io.bind_hosted_device_pointer(port_domain, 0x7100, main_class).unwrap();
        let wrong_top_target = HostedForwardTarget::capture(&mut io, port_domain, 0x7100).unwrap();
        assert_eq!(
            HookPayloadIdentity { class_target: wrong_top, ..hook }.validate(
                &io, &retained_connect, &wrong_top_target, hook_source, source_in_port,
            ),
            Err(ConnectForwardError::WrongIdentity),
        );
        io.detach_device_from_stack(class).unwrap();
        assert_eq!(hook.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Err(ConnectForwardError::WrongIdentity));
        io.attach_device_to_stack(class, lower).unwrap();
        for bad in [
            HookPayloadIdentity { input_pointer: 0xa020, ..hook },
            HookPayloadIdentity { input_length: 40, ..hook },
            HookPayloadIdentity { buffer: HookBufferSource::Pool(ConnectBufferAllocation { domain: port_domain, base: 0xa000, bytes: 48, generation: 0 }), ..hook },
            HookPayloadIdentity { source: source(class_domain, 4), ..hook },
            HookPayloadIdentity { source: source(port_domain, 5), ..hook },
            HookPayloadIdentity { class_target: class_registration, ..hook },
        ] {
            assert_eq!(bad.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Err(ConnectForwardError::WrongIdentity));
        }
        // ReactOS i8042prt sends HOOK from KeyboardHook inside the port FDO extension.
        let extension_hook = HookPayloadIdentity {
            buffer: HookBufferSource::DeviceExtension(HookDeviceExtensionRange {
                owner: source_in_port,
                base: 0xb000,
                bytes: 0x200,
                generation: 12,
            }),
            input_pointer: 0xb080,
            snapshot: [5; 48],
            ..hook
        };
        assert_eq!(extension_hook.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Ok(()));
        for bad in [
            HookPayloadIdentity { buffer: HookBufferSource::DeviceExtension(HookDeviceExtensionRange { owner: class_in_port, base: 0xb000, bytes: 0x200, generation: 12 }), ..extension_hook },
            HookPayloadIdentity { buffer: HookBufferSource::DeviceExtension(HookDeviceExtensionRange { owner: source_in_port, base: 0xb000, bytes: 0x200, generation: 0 }), ..extension_hook },
            HookPayloadIdentity { input_pointer: 0xb1e0, ..extension_hook },
        ] {
            assert_eq!(bad.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Err(ConnectForwardError::WrongIdentity));
        }
        assert_eq!(sequence.enter_hook(&io, &retained_connect, hook, &retained_class_target, hook_source, source_in_port), Ok(()));
        assert_eq!(sequence.enter_hook(&io, &retained_connect, hook, &retained_class_target, hook_source, source_in_port), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(sequence.observe_hook_terminal(source(port_domain, 5), NtStatus::SUCCESS), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(sequence.observe_hook_terminal(hook_source, NtStatus::PENDING), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(sequence.observe_hook_terminal(hook_source, NtStatus::SUCCESS), Ok(()));
        assert_eq!(sequence.observe_connect_terminal(&io, &mut retained_connect, NtStatus::SUCCESS), Ok(ConnectForwardPhase::Terminal(NtStatus::SUCCESS)));
        assert_eq!(sequence.observe_connect_terminal(&io, &mut retained_connect, NtStatus::SUCCESS), Err(ConnectForwardError::InvalidTransition));
        assert_eq!(hook.validate(&io, &retained_connect, &retained_class_target, hook_source, source_in_port), Err(ConnectForwardError::WrongIdentity));
    }

    #[test]
    fn stack_local_connect_data_requires_owned_snapshot_and_exact_stack_generation() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(&NtPath::parse_str(r"\Driver\StackConnect").unwrap(), Box::new(MockDriverBackend::new())).unwrap();
        let lower = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let class = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let domain = io.register_hosted_domain();
        let lower_registration = io.bind_hosted_device_pointer(domain, 0x5000, lower).unwrap();
        let class_registration = io.bind_hosted_device_pointer(domain, 0x6000, class).unwrap();
        let mut retained = RetainedConnectForward::new(
            source(domain, 3),
            HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap(),
            ConnectControl::Keyboard,
        );
        let mut snapshot = [0; 16];
        snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
        snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
        let payload = ConnectPayloadIdentity {
            forward: ConnectForwardIdentity { source: source(domain, 3), target: lower_registration, control: ConnectControl::Keyboard },
            buffer: ConnectBufferSource::Stack(ConnectStackRange { domain, thread: 7, base: 0x7000, bytes: 0x1000, generation: 11 }),
            input_pointer: 0x7ff0,
            input_length: 16,
            snapshot,
            class_device: class_registration,
            class_service: 0x9000,
        };
        assert_eq!(retained.capture_payload(&io, payload, class), Ok(()));
        assert_eq!(retained.validate_payload(&io, payload), Ok(()));
        let reused = ConnectPayloadIdentity {
            buffer: ConnectBufferSource::Stack(ConnectStackRange { domain, thread: 7, base: 0x7000, bytes: 0x1000, generation: 12 }),
            ..payload
        };
        assert_eq!(retained.validate_payload(&io, reused), Err(ConnectForwardError::WrongIdentity));
        for bad in [
            ConnectPayloadIdentity { buffer: ConnectBufferSource::Stack(ConnectStackRange { domain, thread: 0, base: 0x7000, bytes: 0x1000, generation: 11 }), ..payload },
            ConnectPayloadIdentity { buffer: ConnectBufferSource::Stack(ConnectStackRange { domain, thread: 7, base: 0x7000, bytes: 0x1000, generation: 0 }), ..payload },
            ConnectPayloadIdentity { input_pointer: 0x7ff8, ..payload },
        ] {
            assert_eq!(bad.validate(&io, &retained, class), Err(ConnectForwardError::WrongIdentity));
        }
        let mut wrong_snapshot = payload;
        wrong_snapshot.snapshot[8] ^= 1;
        assert_eq!(wrong_snapshot.validate(&io, &retained, class), Err(ConnectForwardError::WrongIdentity));
    }

    #[test]
    fn connect_dispatch_cannot_enter_without_exact_captured_stack_payload() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(&NtPath::parse_str(r"\Driver\CaptureFirst").unwrap(), Box::new(MockDriverBackend::new())).unwrap();
        let lower = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let class = io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, lower).unwrap();
        let class_registration = io.bind_hosted_device_pointer(domain, 0x6000, class).unwrap();
        let mut forward = RetainedConnectForward::new(source(domain, 3),
            HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap(), ConnectControl::Keyboard);
        let identity = forward.identity();
        assert_eq!(forward.enter(&io, identity), Err(ConnectForwardError::InvalidTransition));
        let mut snapshot = [0; 16];
        snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
        snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
        let payload = ConnectPayloadIdentity {
            forward: identity,
            buffer: ConnectBufferSource::Stack(ConnectStackRange {
                domain, thread: 9, base: 0x7000, bytes: 0x1000, generation: 12,
            }),
            input_pointer: 0x7ff0,
            input_length: 16,
            snapshot,
            class_device: class_registration,
            class_service: 0x9000,
        };
        assert_eq!(forward.capture_payload(&io, payload, class), Ok(()));
        assert_eq!(forward.enter(&io, identity), Ok(()));
        assert_eq!(forward.enter(&io, identity), Err(ConnectForwardError::InvalidTransition));
    }
}
