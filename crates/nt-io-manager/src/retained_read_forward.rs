//! Pointer-free ownership of one hosted, cross-domain buffered WDM READ forward.
//!
//! The native adapter retains the source IRP and File reference separately. It copies provider
//! output into owned bytes before source-local completion; no component address is transport
//! authority, and an uncertain dispatch or Reply never authorizes provider replay.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    DeviceFlags, FileId, HostedDevicePointerRegistration, IoManager, StackFlags,
};

/// Source stack scalars. The provider produces the bytes; READ has no captured input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedRead {
    length: u32,
    key: u32,
    byte_offset: u64,
    stack_flags: StackFlags,
}

impl CapturedRead {
    pub const fn new(length: u32, key: u32, byte_offset: u64, stack_flags: StackFlags) -> Self {
        Self {
            length,
            key,
            byte_offset,
            stack_flags,
        }
    }

    pub const fn length(&self) -> u32 {
        self.length
    }
    pub const fn key(&self) -> u32 {
        self.key
    }
    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }
    pub const fn stack_flags(&self) -> StackFlags {
        self.stack_flags
    }
}

/// The FileId identifies the provider File represented by the lower IRP FileObject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadForwardIdentity {
    pub source: SourceIrpTicket,
    pub target: HostedDevicePointerRegistration,
    pub file_id: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadForwardError {
    WrongIdentity,
    InvalidFile,
    NonBufferedDevice,
    Target(NtStatus),
    PendingTerminal,
    ExcessInformation,
    OutputLengthMismatch,
}

/// Provider-produced bytes copied while the provider output remains live.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadCompletion {
    status: u32,
    information: u64,
    bytes: Vec<u8>,
}

impl ReadCompletion {
    pub fn capture(status: u32, information: u64, bytes: &[u8]) -> Result<Self, NtStatus> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        owned.extend_from_slice(bytes);
        Ok(Self::from_owned(status, information, owned))
    }

    /// Adopt provider output without a second allocation after its dispatch has retired.
    /// The forward owner validates terminal bounds before publication.
    pub fn from_owned(status: u32, information: u64, bytes: Vec<u8>) -> Self {
        Self { status, information, bytes }
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
    identity: ReadForwardIdentity,
    target: HostedForwardTarget,
    read: CapturedRead,
}

impl Owner {
    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: ReadForwardIdentity,
    ) -> Result<(), ReadForwardError> {
        if observed != self.identity {
            return Err(ReadForwardError::WrongIdentity);
        }
        self.target.validate(io).map_err(ReadForwardError::Target)?;
        let device = io
            .device(self.target.device_id())
            .ok_or(ReadForwardError::Target(NtStatus::INVALID_PARAMETER))?;
        if !device.flags.contains(DeviceFlags::BUFFERED_IO) {
            return Err(ReadForwardError::NonBufferedDevice);
        }
        if io
            .file(self.identity.file_id)
            .is_none_or(|file| file.device_id != self.target.device_id())
        {
            return Err(ReadForwardError::InvalidFile);
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "begin or retain this prepared source and target owner"]
pub struct PreparedReadForward(Owner);

#[derive(Debug)]
#[must_use = "return the exact invocation after provider dispatch"]
pub struct ReadForwardInvocation(Owner);

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct ReadForwardReturn {
    owner: Owner,
    outcome: ReadForwardOutcome,
}

#[derive(Debug)]
#[must_use = "retain until an exact provider terminal is known"]
pub struct RetainedReadForward {
    owner: Owner,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
    cancel_requested: bool,
}

#[derive(Debug)]
#[must_use = "retire the target after source-local completion"]
pub struct TerminalReadForward {
    owner: Owner,
    completion: ReadCompletion,
}

#[derive(Debug)]
pub enum ReadForwardOutcome {
    Pending,
    Indeterminate(NtStatus),
    Returned(ReadCompletion),
}

#[derive(Debug)]
pub enum ReadForwardResult {
    Retained(RetainedReadForward),
    Terminal(TerminalReadForward),
    Rejected {
        error: ReadForwardError,
        retained: RetainedReadForward,
    },
}

impl PreparedReadForward {
    pub fn new(
        source: SourceIrpTicket,
        target: HostedForwardTarget,
        file_id: FileId,
        read: CapturedRead,
    ) -> Self {
        Self(Owner {
            identity: ReadForwardIdentity {
                source,
                target: target.registration(),
                file_id,
            },
            target,
            read,
        })
    }

    pub fn identity(&self) -> ReadForwardIdentity {
        self.0.identity
    }
    pub fn read(&self) -> CapturedRead {
        self.0.read
    }

    /// Only proven pre-entry refusal leaves a retryable owner.
    pub fn not_entered(self, status: NtStatus) -> (NtStatus, Self) {
        (status, self)
    }

    pub fn begin<P>(
        self,
        io: &IoManager<P>,
        observed: ReadForwardIdentity,
    ) -> Result<ReadForwardInvocation, (ReadForwardError, Self)> {
        if let Err(error) = self.0.validate(io, observed) {
            return Err((error, self));
        }
        Ok(ReadForwardInvocation(self.0))
    }
}

impl ReadForwardInvocation {
    pub fn identity(&self) -> ReadForwardIdentity {
        self.0.identity
    }
    pub fn read(&self) -> CapturedRead {
        self.0.read
    }
    pub fn returned(self, outcome: ReadForwardOutcome) -> ReadForwardReturn {
        ReadForwardReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl ReadForwardReturn {
    pub fn finish<P>(self, io: &IoManager<P>, observed: ReadForwardIdentity) -> ReadForwardResult {
        let Self { owner, outcome } = self;
        if let Err(error) = owner.validate(io, observed) {
            return ReadForwardResult::Rejected {
                error,
                retained: RetainedReadForward {
                    owner,
                    indeterminate: true,
                    transport_status: None,
                    cancel_requested: false,
                },
            };
        }
        match outcome {
            ReadForwardOutcome::Pending => ReadForwardResult::Retained(RetainedReadForward {
                owner,
                indeterminate: false,
                transport_status: None,
                cancel_requested: false,
            }),
            ReadForwardOutcome::Indeterminate(status) => {
                ReadForwardResult::Retained(RetainedReadForward {
                    owner,
                    indeterminate: true,
                    transport_status: Some(status),
                    cancel_requested: false,
                })
            }
            ReadForwardOutcome::Returned(completion) => finish_completion(owner, completion, false),
        }
    }
}

fn finish_completion(
    owner: Owner,
    completion: ReadCompletion,
    cancel_requested: bool,
) -> ReadForwardResult {
    let error = if completion.status == 0x103 {
        Some(ReadForwardError::PendingTerminal)
    } else if completion.information > owner.read.length as u64 {
        Some(ReadForwardError::ExcessInformation)
    } else if completion.bytes.len() as u64 != completion.information {
        Some(ReadForwardError::OutputLengthMismatch)
    } else {
        None
    };
    if let Some(error) = error {
        return ReadForwardResult::Rejected {
            error,
            retained: RetainedReadForward {
                owner,
                indeterminate: true,
                transport_status: None,
                cancel_requested,
            },
        };
    }
    ReadForwardResult::Terminal(TerminalReadForward { owner, completion })
}

impl RetainedReadForward {
    pub fn identity(&self) -> ReadForwardIdentity {
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
        observed: ReadForwardIdentity,
        completion: ReadCompletion,
    ) -> ReadForwardResult {
        if let Err(error) = self.owner.validate(io, observed) {
            return ReadForwardResult::Rejected {
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

impl TerminalReadForward {
    pub fn identity(&self) -> ReadForwardIdentity {
        self.owner.identity
    }
    pub fn completion(&self) -> &ReadCompletion {
        &self.completion
    }

    /// The source-domain completion routine may free its IRP. Release only after it has run.
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<ReadCompletion, (NtStatus, Self)> {
        if let Err(status) = self.owner.target.release(io) {
            return Err((status, self));
        }
        Ok(self.completion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceCharacteristics, DeviceType, MockDriverBackend, MockObjectPort};
    use alloc::boxed::Box;
    use nt_types::{AccessMask, ClientId, NtPath, ObjectId};

    fn fixture(flags: DeviceFlags) -> (IoManager<MockObjectPort>, PreparedReadForward) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ReadForward").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\ReadForward").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                flags,
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
            NtPath::parse_str(r"\Device\ReadForward\one")
                .unwrap()
                .to_unicode_string(),
        ));
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let source = SourceIrpTicket::new(domain, 17, 3).unwrap();
        let read = CapturedRead::new(3, 9, 40, StackFlags::empty());
        (io, PreparedReadForward::new(source, target, file, read))
    }

    fn completion(status: u32, information: u64, bytes: &[u8]) -> ReadCompletion {
        ReadCompletion::capture(status, information, bytes).unwrap()
    }

    #[test]
    fn captures_provider_bytes_and_stack_scalars() {
        let read = CapturedRead::new(3, 9, 40, StackFlags::empty());
        assert_eq!((read.length(), read.key(), read.byte_offset()), (3, 9, 40));
        assert_eq!(read.stack_flags(), StackFlags::empty());
        let mut source = [1, 2, 3];
        let output = ReadCompletion::capture(0, 3, &source).unwrap();
        source[0] = 8;
        assert_eq!(source[0], 8);
        assert_eq!(output.bytes(), &[1, 2, 3]);
    }

    #[test]
    fn immediate_completion_adopts_provider_output_without_copying() {
        let output = alloc::vec![4, 5, 6];
        let address = output.as_ptr();
        let completion = ReadCompletion::from_owned(0, 3, output);
        assert_eq!(completion.bytes(), &[4, 5, 6]);
        assert_eq!(completion.bytes().as_ptr(), address);
    }

    #[test]
    fn only_exact_buffered_provider_file_can_enter() {
        let (mut io, prepared) = fixture(DeviceFlags::BUFFERED_IO);
        let mut wrong = prepared.identity();
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        let prepared = prepared.begin(&io, wrong).err().unwrap().1;
        wrong = prepared.identity();
        wrong.file_id = FileId(wrong.file_id.raw() + 1);
        let prepared = prepared.begin(&io, wrong).err().unwrap().1;
        wrong = prepared.identity();
        let other_domain = io.register_hosted_domain();
        wrong.target = io
            .bind_hosted_device_pointer(other_domain, 0x7000, wrong.target.device_id())
            .unwrap();
        let prepared = match prepared.begin(&io, wrong) {
            Err((ReadForwardError::WrongIdentity, prepared)) => prepared,
            _ => panic!("wrong registration must not enter"),
        };
        let identity = prepared.identity();
        io.remove_file(identity.file_id).unwrap();
        assert!(matches!(
            prepared.begin(&io, identity),
            Err((ReadForwardError::InvalidFile, _))
        ));

        let (io, prepared) = fixture(DeviceFlags::DIRECT_IO);
        let identity = prepared.identity();
        assert!(matches!(
            prepared.begin(&io, identity),
            Err((ReadForwardError::NonBufferedDevice, _))
        ));
    }

    #[test]
    fn pending_uncertain_cancel_and_exact_terminal_retain_target() {
        let (mut io, prepared) = fixture(DeviceFlags::BUFFERED_IO);
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let invocation = prepared.begin(&io, identity).unwrap();
        let mut retained = match invocation
            .returned(ReadForwardOutcome::Indeterminate(NtStatus::DEVICE_BUSY))
            .finish(&io, identity)
        {
            ReadForwardResult::Retained(retained) => retained,
            _ => panic!("uncertain entry must retain"),
        };
        assert_eq!(retained.transport_status(), Some(NtStatus::DEVICE_BUSY));
        retained.request_cancel();
        let mut wrong = identity;
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        retained = match retained.complete(&io, wrong, completion(0, 3, &[1, 2, 3])) {
            ReadForwardResult::Rejected {
                error: ReadForwardError::WrongIdentity,
                retained,
            } => retained,
            _ => panic!("wrong terminal must retain"),
        };
        assert!(retained.cancel_requested());
        let terminal = match retained.complete(&io, identity, completion(0, 3, &[1, 2, 3])) {
            ReadForwardResult::Terminal(terminal) => terminal,
            _ => panic!("exact terminal must complete"),
        };
        assert_eq!(terminal.completion().bytes(), &[1, 2, 3]);
        assert_eq!(io.device_reference_count(device), held);
        assert_eq!(terminal.retire(&mut io).unwrap().information(), 3);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn pending_is_not_terminal_and_output_must_match_information_and_request() {
        for (completion, expected) in [
            (completion(0x103, 0, &[]), ReadForwardError::PendingTerminal),
            (
                completion(0, 4, &[1, 2, 3, 4]),
                ReadForwardError::ExcessInformation,
            ),
            (
                completion(0, 3, &[1, 2]),
                ReadForwardError::OutputLengthMismatch,
            ),
        ] {
            let (io, prepared) = fixture(DeviceFlags::BUFFERED_IO);
            let identity = prepared.identity();
            let invocation = prepared.begin(&io, identity).unwrap();
            let retained = match invocation
                .returned(ReadForwardOutcome::Pending)
                .finish(&io, identity)
            {
                ReadForwardResult::Retained(retained) => retained,
                _ => panic!("pending must retain"),
            };
            match retained.complete(&io, identity, completion) {
                ReadForwardResult::Rejected { error, retained } => {
                    assert_eq!(error, expected);
                    assert!(retained.is_indeterminate());
                }
                _ => panic!("invalid terminal must retain"),
            }
        }
        let (mut io, prepared) = fixture(DeviceFlags::BUFFERED_IO);
        let identity = prepared.identity();
        let terminal = match prepared
            .begin(&io, identity)
            .unwrap()
            .returned(ReadForwardOutcome::Returned(completion(0xc0000001, 0, &[])))
            .finish(&io, identity)
        {
            ReadForwardResult::Terminal(terminal) => terminal,
            _ => panic!("zero-byte failure is still a terminal"),
        };
        assert_eq!(terminal.retire(&mut io).unwrap().status(), 0xc0000001);
    }
}
