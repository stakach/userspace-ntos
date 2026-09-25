//! Pointer-free ownership of one hosted, cross-domain WDM WRITE forward.
//!
//! The native adapter captures the source IRP, File pointer reference, and transfer bytes in
//! the source domain. This contract retains only their canonical identities and owned bytes.
//! It never executes a driver or treats a source address as provider authority.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    DeviceFlags, FileId, HostedDevicePointerRegistration, IoManager, StackFlags,
};

/// The address is a source-domain lookup key only. Native code must validate and copy the
/// selected range before constructing `CapturedWrite`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteBufferSource {
    Empty,
    SystemBuffer(u64),
    Mdl(u64),
    UserBuffer(u64),
}

/// Mup chooses the lower IRP's buffer representation from the target device flags. A
/// nonempty WRITE must have the corresponding pointer; an unrelated populated pointer
/// does not authorize reading from it.
pub fn select_write_buffer_source(
    device_flags: DeviceFlags,
    length: u32,
    system_buffer: u64,
    mdl: u64,
    user_buffer: u64,
) -> Result<WriteBufferSource, NtStatus> {
    if length == 0 {
        return Ok(WriteBufferSource::Empty);
    }
    if device_flags.contains(DeviceFlags::BUFFERED_IO) {
        return (system_buffer != 0)
            .then_some(WriteBufferSource::SystemBuffer(system_buffer))
            .ok_or(NtStatus::INVALID_PARAMETER);
    }
    if device_flags.contains(DeviceFlags::DIRECT_IO) {
        return (mdl != 0)
            .then_some(WriteBufferSource::Mdl(mdl))
            .ok_or(NtStatus::INVALID_PARAMETER);
    }
    (user_buffer != 0)
        .then_some(WriteBufferSource::UserBuffer(user_buffer))
        .ok_or(NtStatus::INVALID_PARAMETER)
}

/// The source stack's scalar WRITE parameters and a snapshot of its input bytes.
#[derive(Debug)]
pub struct CapturedWrite {
    bytes: Vec<u8>,
    key: u32,
    byte_offset: u64,
    stack_flags: StackFlags,
}

impl CapturedWrite {
    pub fn capture(
        bytes: &[u8],
        length: u32,
        key: u32,
        byte_offset: u64,
        stack_flags: StackFlags,
    ) -> Result<Self, NtStatus> {
        if bytes.len() != length as usize {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            key,
            byte_offset,
            stack_flags,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn length(&self) -> u32 {
        self.bytes.len() as u32
    }
    pub fn key(&self) -> u32 {
        self.key
    }
    pub fn byte_offset(&self) -> u64 {
        self.byte_offset
    }
    pub fn stack_flags(&self) -> StackFlags {
        self.stack_flags
    }
}

/// The FileId is the provider File represented by Mup's lower IRP FileObject, not the
/// unrelated upper Mup FileObject. The native owner separately pins that File reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteForwardIdentity {
    pub source: SourceIrpTicket,
    pub target: HostedDevicePointerRegistration,
    pub file_id: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteForwardError {
    WrongIdentity,
    InvalidFile,
    Target(NtStatus),
    PendingTerminal,
    ExcessInformation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteCompletion {
    pub status: u32,
    pub information: u64,
}

#[derive(Debug)]
struct Owner {
    identity: WriteForwardIdentity,
    target: HostedForwardTarget,
    write: CapturedWrite,
}

impl Owner {
    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: WriteForwardIdentity,
    ) -> Result<(), WriteForwardError> {
        if observed != self.identity {
            return Err(WriteForwardError::WrongIdentity);
        }
        self.target
            .validate(io)
            .map_err(WriteForwardError::Target)?;
        if io
            .file(self.identity.file_id)
            .is_none_or(|file| file.device_id != self.target.device_id())
        {
            return Err(WriteForwardError::InvalidFile);
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "begin or retain this prepared source and target owner"]
pub struct PreparedWriteForward(Owner);

#[derive(Debug)]
#[must_use = "return the exact invocation after provider dispatch"]
pub struct WriteForwardInvocation(Owner);

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct WriteForwardReturn {
    owner: Owner,
    outcome: WriteForwardOutcome,
}

#[derive(Debug)]
#[must_use = "retain until an exact provider terminal is known"]
pub struct RetainedWriteForward {
    owner: Owner,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
    cancel_requested: bool,
}

#[derive(Debug)]
#[must_use = "retire the target after source-local completion"]
pub struct TerminalWriteForward {
    owner: Owner,
    completion: WriteCompletion,
}

#[derive(Debug)]
pub enum WriteForwardOutcome {
    Pending,
    /// Transport uncertainty is never permission to re-enter the provider.
    Indeterminate(NtStatus),
    Returned(WriteCompletion),
}

#[derive(Debug)]
pub enum WriteForwardResult {
    Retained(RetainedWriteForward),
    Terminal(TerminalWriteForward),
    Rejected {
        error: WriteForwardError,
        retained: RetainedWriteForward,
    },
}

impl PreparedWriteForward {
    pub fn new(
        source: SourceIrpTicket,
        target: HostedForwardTarget,
        file_id: FileId,
        write: CapturedWrite,
    ) -> Self {
        Self(Owner {
            identity: WriteForwardIdentity {
                source,
                target: target.registration(),
                file_id,
            },
            target,
            write,
        })
    }

    pub fn identity(&self) -> WriteForwardIdentity {
        self.0.identity
    }
    pub fn write(&self) -> &CapturedWrite {
        &self.0.write
    }

    /// Only proven pre-entry refusal returns a retryable owner.
    pub fn not_entered(self, status: NtStatus) -> (NtStatus, Self) {
        (status, self)
    }

    pub fn begin<P>(
        self,
        io: &IoManager<P>,
        observed: WriteForwardIdentity,
    ) -> Result<WriteForwardInvocation, (WriteForwardError, Self)> {
        if let Err(error) = self.0.validate(io, observed) {
            return Err((error, self));
        }
        Ok(WriteForwardInvocation(self.0))
    }
}

impl WriteForwardInvocation {
    pub fn identity(&self) -> WriteForwardIdentity {
        self.0.identity
    }
    pub fn write(&self) -> &CapturedWrite {
        &self.0.write
    }
    pub fn returned(self, outcome: WriteForwardOutcome) -> WriteForwardReturn {
        WriteForwardReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl WriteForwardReturn {
    pub fn finish<P>(
        self,
        io: &IoManager<P>,
        observed: WriteForwardIdentity,
    ) -> WriteForwardResult {
        let Self { owner, outcome } = self;
        if let Err(error) = owner.validate(io, observed) {
            return WriteForwardResult::Rejected {
                error,
                retained: RetainedWriteForward {
                    owner,
                    indeterminate: true,
                    transport_status: None,
                    cancel_requested: false,
                },
            };
        }
        match outcome {
            WriteForwardOutcome::Pending => WriteForwardResult::Retained(RetainedWriteForward {
                owner,
                indeterminate: false,
                transport_status: None,
                cancel_requested: false,
            }),
            WriteForwardOutcome::Indeterminate(status) => {
                WriteForwardResult::Retained(RetainedWriteForward {
                    owner,
                    indeterminate: true,
                    transport_status: Some(status),
                    cancel_requested: false,
                })
            }
            WriteForwardOutcome::Returned(completion) => {
                finish_completion(owner, completion, false)
            }
        }
    }
}

fn finish_completion(
    owner: Owner,
    completion: WriteCompletion,
    cancel_requested: bool,
) -> WriteForwardResult {
    let error = if completion.status == 0x103 {
        Some(WriteForwardError::PendingTerminal)
    } else if completion.information > owner.write.length() as u64 {
        Some(WriteForwardError::ExcessInformation)
    } else {
        None
    };
    if let Some(error) = error {
        return WriteForwardResult::Rejected {
            error,
            retained: RetainedWriteForward {
                owner,
                indeterminate: true,
                transport_status: None,
                cancel_requested,
            },
        };
    }
    WriteForwardResult::Terminal(TerminalWriteForward { owner, completion })
}

impl RetainedWriteForward {
    pub fn identity(&self) -> WriteForwardIdentity {
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

    /// The native adapter issues canonical cancellation separately. This records intent without
    /// treating cancellation or a stopped source Call as a provider terminal.
    pub fn request_cancel(&mut self) {
        self.cancel_requested = true;
    }

    pub fn complete<P>(
        self,
        io: &IoManager<P>,
        observed: WriteForwardIdentity,
        completion: WriteCompletion,
    ) -> WriteForwardResult {
        if let Err(error) = self.owner.validate(io, observed) {
            return WriteForwardResult::Rejected {
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

impl TerminalWriteForward {
    pub fn identity(&self) -> WriteForwardIdentity {
        self.owner.identity
    }
    pub fn completion(&self) -> WriteCompletion {
        self.completion
    }

    /// The source-domain completion routine may free its IRP. Call this only after it has run;
    /// failed release retains the exact target for redrive.
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<WriteCompletion, (NtStatus, Self)> {
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

    fn fixture() -> (IoManager<MockObjectPort>, PreparedWriteForward) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\WriteForward").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\WriteForward").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
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
            NtPath::parse_str(r"\Device\WriteForward\one")
                .unwrap()
                .to_unicode_string(),
        ));
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let source = SourceIrpTicket::new(domain, 17, 3).unwrap();
        let write = CapturedWrite::capture(&[1, 2, 3], 3, 9, 40, StackFlags::empty()).unwrap();
        (io, PreparedWriteForward::new(source, target, file, write))
    }

    #[test]
    fn captures_owned_bytes_and_exact_length() {
        let mut bytes = [1, 2, 3];
        let captured = CapturedWrite::capture(&bytes, 3, 9, 40, StackFlags::empty()).unwrap();
        bytes[0] = 8;
        assert_eq!(captured.bytes(), &[1, 2, 3]);
        assert_eq!(captured.key(), 9);
        assert_eq!(captured.byte_offset(), 40);
        assert_eq!(
            CapturedWrite::capture(&bytes, 4, 0, 0, StackFlags::empty()).unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn selects_only_the_target_device_write_buffer() {
        let buffered = DeviceFlags::BUFFERED_IO | DeviceFlags::DIRECT_IO;
        assert_eq!(
            select_write_buffer_source(buffered, 3, 0x1000, 0x2000, 0x3000),
            Ok(WriteBufferSource::SystemBuffer(0x1000))
        );
        assert_eq!(
            select_write_buffer_source(buffered, 3, 0, 0x2000, 0x3000),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            select_write_buffer_source(DeviceFlags::DIRECT_IO, 3, 0x1000, 0x2000, 0x3000),
            Ok(WriteBufferSource::Mdl(0x2000))
        );
        assert_eq!(
            select_write_buffer_source(DeviceFlags::DIRECT_IO, 3, 0x1000, 0, 0x3000),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            select_write_buffer_source(DeviceFlags::empty(), 3, 0x1000, 0x2000, 0x3000),
            Ok(WriteBufferSource::UserBuffer(0x3000))
        );
        assert_eq!(
            select_write_buffer_source(DeviceFlags::empty(), 3, 0x1000, 0x2000, 0),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            select_write_buffer_source(DeviceFlags::DIRECT_IO, 0, 0, 0, 0),
            Ok(WriteBufferSource::Empty)
        );
    }

    #[test]
    fn wrong_ticket_target_or_file_cannot_enter() {
        let (mut io, prepared) = fixture();
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
        assert!(matches!(
            prepared.begin(&io, wrong),
            Err((WriteForwardError::WrongIdentity, _))
        ));
    }

    #[test]
    fn removed_provider_file_cannot_enter() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        io.remove_file(identity.file_id).unwrap();
        assert!(matches!(
            prepared.begin(&io, identity),
            Err((WriteForwardError::InvalidFile, _))
        ));
    }

    #[test]
    fn pending_uncertain_and_cancel_keep_owner_until_exact_terminal() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let invocation = prepared.begin(&io, identity).unwrap();
        let mut retained = match invocation
            .returned(WriteForwardOutcome::Indeterminate(NtStatus::DEVICE_BUSY))
            .finish(&io, identity)
        {
            WriteForwardResult::Retained(retained) => retained,
            _ => panic!("entered uncertainty must retain"),
        };
        assert!(retained.is_indeterminate());
        assert_eq!(retained.transport_status(), Some(NtStatus::DEVICE_BUSY));
        retained.request_cancel();
        let mut wrong = identity;
        wrong.source.generation = core::num::NonZeroU64::new(4).unwrap();
        retained = match retained.complete(
            &io,
            wrong,
            WriteCompletion {
                status: 0,
                information: 3,
            },
        ) {
            WriteForwardResult::Rejected {
                error: WriteForwardError::WrongIdentity,
                retained,
            } => retained,
            _ => panic!("wrong terminal must retain"),
        };
        assert!(retained.cancel_requested());
        let terminal = match retained.complete(
            &io,
            identity,
            WriteCompletion {
                status: 0,
                information: 3,
            },
        ) {
            WriteForwardResult::Terminal(terminal) => terminal,
            _ => panic!("real terminal must retire"),
        };
        assert_eq!(io.device_reference_count(device), held);
        terminal.retire(&mut io).unwrap();
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn pending_is_not_a_terminal_and_information_is_bounded() {
        for completion in [
            WriteCompletion {
                status: 0x103,
                information: 0,
            },
            WriteCompletion {
                status: 0,
                information: 4,
            },
        ] {
            let (io, prepared) = fixture();
            let identity = prepared.identity();
            let invocation = prepared.begin(&io, identity).unwrap();
            let retained = match invocation
                .returned(WriteForwardOutcome::Pending)
                .finish(&io, identity)
            {
                WriteForwardResult::Retained(retained) => retained,
                _ => panic!("pending must retain"),
            };
            assert!(matches!(
                retained.complete(&io, identity, completion),
                WriteForwardResult::Rejected {
                    retained: RetainedWriteForward {
                        indeterminate: true,
                        ..
                    },
                    ..
                }
            ));
        }
    }
}
