//! Pointer-free ownership of one cross-domain WDM QUERY_INFORMATION forward.
//!
//! The source IRP, File, output buffer, and completion routine remain in the source domain.
//! Provider output is owned before source-local completion and an uncertain dispatch never
//! authorizes a second provider invocation.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    FileId, HostedDevicePointerRegistration, IoManager, StackFlags,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedQueryInformation {
    information_class: u32,
    length: u32,
    stack_flags: StackFlags,
}

impl CapturedQueryInformation {
    pub const fn new(information_class: u32, length: u32, stack_flags: StackFlags) -> Self {
        Self {
            information_class,
            length,
            stack_flags,
        }
    }

    pub const fn information_class(&self) -> u32 {
        self.information_class
    }
    pub const fn length(&self) -> u32 {
        self.length
    }
    pub const fn stack_flags(&self) -> StackFlags {
        self.stack_flags
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryInformationForwardIdentity {
    pub source: SourceIrpTicket,
    pub target: HostedDevicePointerRegistration,
    pub file_id: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryInformationForwardError {
    WrongIdentity,
    InvalidFile,
    Target(NtStatus),
    PendingTerminal,
    ExcessInformation,
    OutputLengthMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueryInformationCompletion {
    status: u32,
    information: u64,
    bytes: Vec<u8>,
}

impl QueryInformationCompletion {
    pub fn capture(status: u32, information: u64, bytes: &[u8]) -> Result<Self, NtStatus> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        owned.extend_from_slice(bytes);
        Ok(Self::from_owned(status, information, owned))
    }

    /// Adopt provider output without a second allocation after dispatch retires.
    pub fn from_owned(status: u32, information: u64, bytes: Vec<u8>) -> Self {
        Self {
            status,
            information,
            bytes,
        }
    }

    pub fn status(&self) -> u32 {
        self.status
    }
    pub fn information(&self) -> u64 {
        self.information
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
struct Owner {
    identity: QueryInformationForwardIdentity,
    target: HostedForwardTarget,
    query: CapturedQueryInformation,
}

impl Owner {
    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: QueryInformationForwardIdentity,
    ) -> Result<(), QueryInformationForwardError> {
        if observed != self.identity {
            return Err(QueryInformationForwardError::WrongIdentity);
        }
        self.target
            .validate(io)
            .map_err(QueryInformationForwardError::Target)?;
        if io
            .file(self.identity.file_id)
            .is_none_or(|file| file.device_id != self.target.device_id())
        {
            return Err(QueryInformationForwardError::InvalidFile);
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "begin or retain this prepared source and target owner"]
pub struct PreparedQueryInformationForward(Owner);

#[derive(Debug)]
#[must_use = "return the exact invocation after provider dispatch"]
pub struct QueryInformationForwardInvocation(Owner);

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct QueryInformationForwardReturn {
    owner: Owner,
    outcome: QueryInformationForwardOutcome,
}

#[derive(Debug)]
#[must_use = "retain until an exact provider terminal is known"]
pub struct RetainedQueryInformationForward {
    owner: Owner,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
    cancel_requested: bool,
}

#[derive(Debug)]
#[must_use = "retire the target after source-local completion"]
pub struct TerminalQueryInformationForward {
    owner: Owner,
    completion: QueryInformationCompletion,
}

#[derive(Debug)]
pub enum QueryInformationForwardOutcome {
    Pending,
    Indeterminate(NtStatus),
    Returned(QueryInformationCompletion),
}

#[derive(Debug)]
pub enum QueryInformationForwardResult {
    Retained(RetainedQueryInformationForward),
    Terminal(TerminalQueryInformationForward),
    Rejected {
        error: QueryInformationForwardError,
        retained: RetainedQueryInformationForward,
    },
}

impl PreparedQueryInformationForward {
    pub fn new(
        source: SourceIrpTicket,
        target: HostedForwardTarget,
        file_id: FileId,
        query: CapturedQueryInformation,
    ) -> Self {
        Self(Owner {
            identity: QueryInformationForwardIdentity {
                source,
                target: target.registration(),
                file_id,
            },
            target,
            query,
        })
    }

    pub fn identity(&self) -> QueryInformationForwardIdentity {
        self.0.identity
    }
    pub fn query(&self) -> CapturedQueryInformation {
        self.0.query
    }

    /// Only proven pre-entry refusal leaves a retryable owner.
    pub fn not_entered(self, status: NtStatus) -> (NtStatus, Self) {
        (status, self)
    }

    pub fn begin<P>(
        self,
        io: &IoManager<P>,
        observed: QueryInformationForwardIdentity,
    ) -> Result<QueryInformationForwardInvocation, (QueryInformationForwardError, Self)> {
        if let Err(error) = self.0.validate(io, observed) {
            return Err((error, self));
        }
        Ok(QueryInformationForwardInvocation(self.0))
    }
}

impl QueryInformationForwardInvocation {
    pub fn identity(&self) -> QueryInformationForwardIdentity {
        self.0.identity
    }
    pub fn query(&self) -> CapturedQueryInformation {
        self.0.query
    }
    pub fn returned(
        self,
        outcome: QueryInformationForwardOutcome,
    ) -> QueryInformationForwardReturn {
        QueryInformationForwardReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl QueryInformationForwardReturn {
    pub fn finish<P>(
        self,
        io: &IoManager<P>,
        observed: QueryInformationForwardIdentity,
    ) -> QueryInformationForwardResult {
        let Self { owner, outcome } = self;
        if let Err(error) = owner.validate(io, observed) {
            return QueryInformationForwardResult::Rejected {
                error,
                retained: RetainedQueryInformationForward {
                    owner,
                    indeterminate: true,
                    transport_status: None,
                    cancel_requested: false,
                },
            };
        }
        match outcome {
            QueryInformationForwardOutcome::Pending => {
                QueryInformationForwardResult::Retained(RetainedQueryInformationForward {
                    owner,
                    indeterminate: false,
                    transport_status: None,
                    cancel_requested: false,
                })
            }
            QueryInformationForwardOutcome::Indeterminate(status) => {
                QueryInformationForwardResult::Retained(RetainedQueryInformationForward {
                    owner,
                    indeterminate: true,
                    transport_status: Some(status),
                    cancel_requested: false,
                })
            }
            QueryInformationForwardOutcome::Returned(completion) => {
                finish_completion(owner, completion, false)
            }
        }
    }
}

fn finish_completion(
    owner: Owner,
    completion: QueryInformationCompletion,
    cancel_requested: bool,
) -> QueryInformationForwardResult {
    let error = if completion.status == 0x103 {
        Some(QueryInformationForwardError::PendingTerminal)
    } else if completion.information > owner.query.length as u64 {
        Some(QueryInformationForwardError::ExcessInformation)
    } else if completion.bytes.len() as u64 != completion.information {
        Some(QueryInformationForwardError::OutputLengthMismatch)
    } else {
        None
    };
    if let Some(error) = error {
        return QueryInformationForwardResult::Rejected {
            error,
            retained: RetainedQueryInformationForward {
                owner,
                indeterminate: true,
                transport_status: None,
                cancel_requested,
            },
        };
    }
    QueryInformationForwardResult::Terminal(TerminalQueryInformationForward { owner, completion })
}

impl RetainedQueryInformationForward {
    pub fn identity(&self) -> QueryInformationForwardIdentity {
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

    /// Cancellation records intent; it is not a provider terminal or target release.
    pub fn request_cancel(&mut self) {
        self.cancel_requested = true;
    }

    pub fn complete<P>(
        self,
        io: &IoManager<P>,
        observed: QueryInformationForwardIdentity,
        completion: QueryInformationCompletion,
    ) -> QueryInformationForwardResult {
        if let Err(error) = self.owner.validate(io, observed) {
            return QueryInformationForwardResult::Rejected {
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

impl TerminalQueryInformationForward {
    pub fn identity(&self) -> QueryInformationForwardIdentity {
        self.owner.identity
    }
    pub fn completion(&self) -> &QueryInformationCompletion {
        &self.completion
    }

    /// Source completion may free its IRP; release only after it has run or the source stopped.
    pub fn retire<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<QueryInformationCompletion, (NtStatus, Self)> {
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

    fn fixture() -> (IoManager<MockObjectPort>, PreparedQueryInformationForward) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\QueryInformationForward").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\QueryInformationForward").unwrap()),
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
            AccessMask::GENERIC_READ,
            crate::ShareAccess::READ,
            crate::CreateOptions::empty(),
            NtPath::parse_str(r"\Device\QueryInformationForward\one")
                .unwrap()
                .to_unicode_string(),
        ));
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let source = SourceIrpTicket::new(domain, 17, 3).unwrap();
        let query = CapturedQueryInformation::new(5, 24, StackFlags::empty());
        (
            io,
            PreparedQueryInformationForward::new(source, target, file, query),
        )
    }

    fn completion(status: u32, information: u64, bytes: &[u8]) -> QueryInformationCompletion {
        QueryInformationCompletion::capture(status, information, bytes).unwrap()
    }

    #[test]
    fn captures_class_length_flags_and_owned_provider_bytes() {
        let query = CapturedQueryInformation::new(5, 24, StackFlags::empty());
        assert_eq!((query.information_class(), query.length()), (5, 24));
        assert_eq!(query.stack_flags(), StackFlags::empty());
        let mut source = [1, 2, 3];
        let output = completion(0, 3, &source);
        source[0] = 8;
        assert_eq!(source[0], 8);
        assert_eq!(output.bytes(), &[1, 2, 3]);
    }

    #[test]
    fn only_exact_target_and_file_can_enter() {
        let (mut io, prepared) = fixture();
        let mut wrong = prepared.identity();
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        let prepared = match prepared.begin(&io, wrong) {
            Err((QueryInformationForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong source must not enter"),
        };
        let mut wrong = prepared.identity();
        wrong.file_id = FileId(wrong.file_id.raw() + 1);
        let prepared = match prepared.begin(&io, wrong) {
            Err((QueryInformationForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong file must not enter"),
        };
        let identity = prepared.identity();
        io.remove_file(identity.file_id).unwrap();
        assert!(matches!(
            prepared.begin(&io, identity),
            Err((QueryInformationForwardError::InvalidFile, _))
        ));
    }

    #[test]
    fn pending_cancel_retains_target_until_exact_late_terminal_and_retirement() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let invocation = prepared.begin(&io, identity).unwrap();
        let mut retained = match invocation
            .returned(QueryInformationForwardOutcome::Pending)
            .finish(&io, identity)
        {
            QueryInformationForwardResult::Retained(retained) => retained,
            _ => panic!("pending provider must retain"),
        };
        retained.request_cancel();
        let mut wrong = identity;
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        retained = match retained.complete(&io, wrong, completion(0xc0000120, 0, &[])) {
            QueryInformationForwardResult::Rejected {
                error: QueryInformationForwardError::WrongIdentity,
                retained,
            } => retained,
            _ => panic!("wrong terminal must retain"),
        };
        assert!(retained.cancel_requested());
        assert_eq!(io.device_reference_count(device), held);
        let terminal = match retained.complete(&io, identity, completion(0xc0000120, 0, &[])) {
            QueryInformationForwardResult::Terminal(terminal) => terminal,
            _ => panic!("exact late terminal must complete"),
        };
        assert_eq!(terminal.retire(&mut io).unwrap().status(), 0xc0000120);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn uncertain_dispatch_and_invalid_terminals_keep_owner() {
        for (invalid, expected) in [
            (
                completion(0x103, 0, &[]),
                QueryInformationForwardError::PendingTerminal,
            ),
            (
                completion(0, 25, &[0; 25]),
                QueryInformationForwardError::ExcessInformation,
            ),
            (
                completion(0, 3, &[1, 2]),
                QueryInformationForwardError::OutputLengthMismatch,
            ),
        ] {
            let (io, prepared) = fixture();
            let identity = prepared.identity();
            let retained = match prepared
                .begin(&io, identity)
                .unwrap()
                .returned(QueryInformationForwardOutcome::Indeterminate(
                    NtStatus::DEVICE_BUSY,
                ))
                .finish(&io, identity)
            {
                QueryInformationForwardResult::Retained(retained) => retained,
                _ => panic!("uncertain dispatch must retain"),
            };
            assert!(retained.is_indeterminate());
            assert_eq!(retained.transport_status(), Some(NtStatus::DEVICE_BUSY));
            match retained.complete(&io, identity, invalid) {
                QueryInformationForwardResult::Rejected { error, retained } => {
                    assert_eq!(error, expected);
                    assert!(retained.is_indeterminate());
                }
                _ => panic!("invalid terminal must retain"),
            }
        }
    }

    #[test]
    fn immediate_information_is_bounded_and_retired_after_source() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        assert_eq!(prepared.query().information_class(), 5);
        let terminal = match prepared
            .begin(&io, identity)
            .unwrap()
            .returned(QueryInformationForwardOutcome::Returned(completion(
                0,
                4,
                &[3, 4, 5, 6],
            )))
            .finish(&io, identity)
        {
            QueryInformationForwardResult::Terminal(terminal) => terminal,
            _ => panic!("bounded output must complete"),
        };
        assert_eq!(terminal.completion().bytes(), &[3, 4, 5, 6]);
        assert_eq!(terminal.retire(&mut io).unwrap().information(), 4);
    }
}
