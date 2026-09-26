//! Pointer-free ownership of one hosted, cross-domain WDM FLUSH_BUFFERS forward.
//!
//! FLUSH has a FileObject but no transfer buffer. A source Reply or uncertain provider entry
//! never authorizes replay or target release; only an exact terminal can be retired.

use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    FileId, HostedDevicePointerRegistration, IoManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushForwardIdentity {
    pub source: SourceIrpTicket,
    pub target: HostedDevicePointerRegistration,
    pub file_id: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushForwardError {
    WrongIdentity,
    InvalidFile,
    Target(NtStatus),
    PendingTerminal,
    NonzeroInformation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushCompletion {
    status: u32,
    information: u64,
}

impl FlushCompletion {
    pub const fn new(status: u32, information: u64) -> Self {
        Self {
            status,
            information,
        }
    }

    pub const fn status(&self) -> u32 {
        self.status
    }
    pub const fn information(&self) -> u64 {
        self.information
    }
}

#[derive(Debug)]
struct Owner {
    identity: FlushForwardIdentity,
    target: HostedForwardTarget,
}

impl Owner {
    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: FlushForwardIdentity,
    ) -> Result<(), FlushForwardError> {
        if observed != self.identity {
            return Err(FlushForwardError::WrongIdentity);
        }
        self.target
            .validate(io)
            .map_err(FlushForwardError::Target)?;
        if io
            .file(self.identity.file_id)
            .is_none_or(|file| file.device_id != self.target.device_id())
        {
            return Err(FlushForwardError::InvalidFile);
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "begin or retain this prepared source and target owner"]
pub struct PreparedFlushForward(Owner);

#[derive(Debug)]
#[must_use = "return the exact invocation after provider dispatch"]
pub struct FlushForwardInvocation(Owner);

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct FlushForwardReturn {
    owner: Owner,
    outcome: FlushForwardOutcome,
}

#[derive(Debug)]
#[must_use = "retain until an exact provider terminal is known"]
pub struct RetainedFlushForward {
    owner: Owner,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
    cancel_requested: bool,
}

#[derive(Debug)]
#[must_use = "retire the target after source-local completion"]
pub struct TerminalFlushForward {
    owner: Owner,
    completion: FlushCompletion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushForwardOutcome {
    Pending,
    Indeterminate(NtStatus),
    Returned(FlushCompletion),
}

#[derive(Debug)]
pub enum FlushForwardResult {
    Retained(RetainedFlushForward),
    Terminal(TerminalFlushForward),
    Rejected {
        error: FlushForwardError,
        retained: RetainedFlushForward,
    },
}

impl PreparedFlushForward {
    pub fn new(source: SourceIrpTicket, target: HostedForwardTarget, file_id: FileId) -> Self {
        Self(Owner {
            identity: FlushForwardIdentity {
                source,
                target: target.registration(),
                file_id,
            },
            target,
        })
    }

    pub fn identity(&self) -> FlushForwardIdentity {
        self.0.identity
    }

    /// Only proven pre-entry refusal leaves a retryable owner.
    pub fn not_entered(self, status: NtStatus) -> (NtStatus, Self) {
        (status, self)
    }

    pub fn begin<P>(
        self,
        io: &IoManager<P>,
        observed: FlushForwardIdentity,
    ) -> Result<FlushForwardInvocation, (FlushForwardError, Self)> {
        if let Err(error) = self.0.validate(io, observed) {
            return Err((error, self));
        }
        Ok(FlushForwardInvocation(self.0))
    }
}

impl FlushForwardInvocation {
    pub fn identity(&self) -> FlushForwardIdentity {
        self.0.identity
    }

    pub fn returned(self, outcome: FlushForwardOutcome) -> FlushForwardReturn {
        FlushForwardReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl FlushForwardReturn {
    pub fn finish<P>(
        self,
        io: &IoManager<P>,
        observed: FlushForwardIdentity,
    ) -> FlushForwardResult {
        let Self { owner, outcome } = self;
        if let Err(error) = owner.validate(io, observed) {
            return FlushForwardResult::Rejected {
                error,
                retained: RetainedFlushForward {
                    owner,
                    indeterminate: true,
                    transport_status: None,
                    cancel_requested: false,
                },
            };
        }
        match outcome {
            FlushForwardOutcome::Pending => FlushForwardResult::Retained(RetainedFlushForward {
                owner,
                indeterminate: false,
                transport_status: None,
                cancel_requested: false,
            }),
            FlushForwardOutcome::Indeterminate(status) => {
                FlushForwardResult::Retained(RetainedFlushForward {
                    owner,
                    indeterminate: true,
                    transport_status: Some(status),
                    cancel_requested: false,
                })
            }
            FlushForwardOutcome::Returned(completion) => {
                finish_completion(owner, completion, false)
            }
        }
    }
}

fn finish_completion(
    owner: Owner,
    completion: FlushCompletion,
    cancel_requested: bool,
) -> FlushForwardResult {
    let error = if completion.status == NtStatus::PENDING.raw() as u32 {
        Some(FlushForwardError::PendingTerminal)
    } else if completion.information != 0 {
        Some(FlushForwardError::NonzeroInformation)
    } else {
        None
    };
    if let Some(error) = error {
        return FlushForwardResult::Rejected {
            error,
            retained: RetainedFlushForward {
                owner,
                indeterminate: true,
                transport_status: None,
                cancel_requested,
            },
        };
    }
    FlushForwardResult::Terminal(TerminalFlushForward { owner, completion })
}

impl RetainedFlushForward {
    pub fn identity(&self) -> FlushForwardIdentity {
        self.owner.identity
    }
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }
    pub fn transport_status(&self) -> Option<NtStatus> {
        self.transport_status
    }
    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Cancellation is intent, not a provider terminal or permission to release the target.
    pub fn request_cancel(&mut self) {
        self.cancel_requested = true;
    }

    pub fn complete<P>(
        self,
        io: &IoManager<P>,
        observed: FlushForwardIdentity,
        completion: FlushCompletion,
    ) -> FlushForwardResult {
        if let Err(error) = self.owner.validate(io, observed) {
            return FlushForwardResult::Rejected {
                error,
                retained: self,
            };
        }
        let Self {
            owner,
            cancel_requested,
            ..
        } = self;
        finish_completion(owner, completion, cancel_requested)
    }
}

impl TerminalFlushForward {
    pub fn identity(&self) -> FlushForwardIdentity {
        self.owner.identity
    }
    pub fn completion(&self) -> FlushCompletion {
        self.completion
    }

    /// The source-domain completion routine may free its IRP. Release only after it has run.
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<FlushCompletion, (NtStatus, Self)> {
        if let Err(status) = self.owner.target.release(io) {
            return Err((status, self));
        }
        Ok(self.completion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort,
    };
    use alloc::boxed::Box;
    use nt_types::{AccessMask, ClientId, NtPath, ObjectId};

    fn fixture() -> (IoManager<MockObjectPort>, PreparedFlushForward) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\FlushForward").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\FlushForward").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let file = io.add_file(crate::FileRecord::new(
            ObjectId::NULL,
            ClientId(1),
            device,
            AccessMask::GENERIC_WRITE,
            crate::ShareAccess::READ,
            crate::CreateOptions::empty(),
            NtPath::parse_str(r"\Device\FlushForward\one")
                .unwrap()
                .to_unicode_string(),
        ));
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let source = SourceIrpTicket::new(domain, 17, 3).unwrap();
        (io, PreparedFlushForward::new(source, target, file))
    }

    #[test]
    fn only_exact_source_target_and_file_can_enter() {
        let (mut io, prepared) = fixture();
        let mut wrong = prepared.identity();
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        let prepared = match prepared.begin(&io, wrong) {
            Err((FlushForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong source must not enter"),
        };
        wrong = prepared.identity();
        wrong.file_id = FileId(wrong.file_id.raw() + 1);
        let prepared = match prepared.begin(&io, wrong) {
            Err((FlushForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong File must not enter"),
        };
        wrong = prepared.identity();
        let other_domain = io.register_hosted_domain();
        wrong.target = io
            .bind_hosted_device_pointer(other_domain, 0x7000, wrong.target.device_id())
            .unwrap();
        let prepared = match prepared.begin(&io, wrong) {
            Err((FlushForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong projection must not enter"),
        };
        let identity = prepared.identity();
        io.remove_file(identity.file_id).unwrap();
        assert!(matches!(
            prepared.begin(&io, identity),
            Err((FlushForwardError::InvalidFile, _))
        ));
    }

    #[test]
    fn pre_entry_refusal_retains_exact_target_and_remains_retryable() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let (status, prepared) = prepared.not_entered(NtStatus::DEVICE_BUSY);
        assert_eq!(status, NtStatus::DEVICE_BUSY);
        assert_eq!(io.device_reference_count(device), held);
        let terminal = match prepared
            .begin(&io, identity)
            .unwrap()
            .returned(FlushForwardOutcome::Returned(FlushCompletion::new(0, 0)))
            .finish(&io, identity)
        {
            FlushForwardResult::Terminal(terminal) => terminal,
            _ => panic!("exact retry must enter"),
        };
        assert_eq!(io.device_reference_count(device), held);
        assert_eq!(terminal.retire(&mut io).unwrap().information(), 0);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn pending_cancel_and_late_terminal_keep_target_until_retirement() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let mut retained = match prepared
            .begin(&io, identity)
            .unwrap()
            .returned(FlushForwardOutcome::Pending)
            .finish(&io, identity)
        {
            FlushForwardResult::Retained(retained) => retained,
            _ => panic!("pending must retain"),
        };
        retained.request_cancel();
        let mut wrong = identity;
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        retained = match retained.complete(&io, wrong, FlushCompletion::new(0xc0000120, 0)) {
            FlushForwardResult::Rejected {
                error: FlushForwardError::WrongIdentity,
                retained,
            } => retained,
            _ => panic!("wrong late terminal must retain"),
        };
        assert!(retained.cancel_requested());
        assert_eq!(io.device_reference_count(device), held);
        let terminal = match retained.complete(&io, identity, FlushCompletion::new(0xc0000120, 0)) {
            FlushForwardResult::Terminal(terminal) => terminal,
            _ => panic!("exact cancellation terminal must complete"),
        };
        assert_eq!(io.device_reference_count(device), held);
        assert_eq!(terminal.retire(&mut io).unwrap().status(), 0xc0000120);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn uncertain_entry_never_replays_and_requires_exact_terminal() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let retained = match prepared
            .begin(&io, identity)
            .unwrap()
            .returned(FlushForwardOutcome::Indeterminate(NtStatus::DEVICE_BUSY))
            .finish(&io, identity)
        {
            FlushForwardResult::Retained(retained) => retained,
            _ => panic!("uncertain entry must retain"),
        };
        assert!(retained.is_indeterminate());
        assert_eq!(retained.transport_status(), Some(NtStatus::DEVICE_BUSY));
        assert_eq!(io.device_reference_count(device), held);
        let terminal = match retained.complete(&io, identity, FlushCompletion::new(0, 0)) {
            FlushForwardResult::Terminal(terminal) => terminal,
            _ => panic!("late exact completion must become terminal"),
        };
        assert_eq!(terminal.retire(&mut io).unwrap().status(), 0);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn pending_and_nonzero_information_are_not_flush_terminals() {
        for (completion, error) in [
            (
                FlushCompletion::new(0x103, 0),
                FlushForwardError::PendingTerminal,
            ),
            (
                FlushCompletion::new(0, 1),
                FlushForwardError::NonzeroInformation,
            ),
        ] {
            let (io, prepared) = fixture();
            let identity = prepared.identity();
            let retained = match prepared
                .begin(&io, identity)
                .unwrap()
                .returned(FlushForwardOutcome::Returned(completion))
                .finish(&io, identity)
            {
                FlushForwardResult::Rejected {
                    error: got,
                    retained,
                } => {
                    assert_eq!(got, error);
                    retained
                }
                _ => panic!("invalid terminal must retain"),
            };
            assert!(retained.is_indeterminate());
        }
    }
}
