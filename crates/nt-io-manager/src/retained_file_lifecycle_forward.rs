//! Exact retained ownership for a source driver's forwarded File lifecycle IRP.
//!
//! The native adapter separately owns the source pin, subsidiary canonical IRP,
//! provider FILE_OBJECT projection, Reply, and completion callback. This owner
//! holds their identity and the File/device references across uncertain effects.

use nt_io_abi::major;
use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, source_irp_ledger::SourceIrpForwardIdentity,
    FileId, FileState, HostedDevicePointerRegistration, IoManager, IoParameters, IrpId,
    IrpProjection, IrpState,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FileLifecycleForwardIdentity {
    /// Native must keep the exact ledger pin; this copied identity is not authority.
    pub source: SourceIrpForwardIdentity,
    pub source_device: HostedDevicePointerRegistration,
    pub lower_device: HostedDevicePointerRegistration,
    pub file: FileId,
    pub outer_irp: IrpId,
    /// Native allocates and owns this distinct canonical IRP before provider entry.
    pub subsidiary_irp: IrpId,
    pub major: u8,
}

/// Read-only observation of a live, manager-authenticated lower File IRP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubsidiaryFileLifecycleIdentity {
    outer_irp: IrpId,
    file_id: FileId,
    major: u8,
}

impl SubsidiaryFileLifecycleIdentity {
    pub const fn outer_irp(self) -> IrpId {
        self.outer_irp
    }
    pub const fn file_id(self) -> FileId {
        self.file_id
    }
    pub const fn major(self) -> u8 {
        self.major
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileLifecycleForwardError {
    WrongIdentity,
    InvalidFile,
    InvalidStack,
    InvalidTransition,
    PendingTerminal,
    Target(NtStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileLifecycleDispatchReturn {
    /// The trusted native executor proves no provider handler was entered.
    NotEntered(NtStatus),
    Pending,
    InlineTerminal {
        status: NtStatus,
        information: u64,
    },
    Indeterminate(NtStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileLifecycleForwardPhase {
    Prepared,
    Entered,
    NotEntered(NtStatus),
    Discarding,
    Pending,
    Indeterminate(NtStatus),
    Terminal { status: NtStatus, information: u64 },
    SourceCompletionHeld { status: NtStatus, information: u64 },
    SourceCompleted,
    SourceStopped,
    AckIndeterminate(NtStatus),
    Acknowledged,
    Retiring,
}

/// Consuming owner: dropping it cannot safely retire the source or lower provider.
#[derive(Debug)]
#[must_use = "retain until source completion and exact provider acknowledgement"]
pub struct RetainedFileLifecycleForward {
    identity: FileLifecycleForwardIdentity,
    target: HostedForwardTarget,
    phase: FileLifecycleForwardPhase,
    terminal: Option<(NtStatus, u64)>,
    target_released: bool,
}

impl RetainedFileLifecycleForward {
    /// The exact entered outer IRP and subsidiary IRP jointly pin the File,
    /// including after CLOSE bars acquisition of a new FileReference.
    pub fn new<P>(
        io: &IoManager<P>,
        identity: FileLifecycleForwardIdentity,
        target: HostedForwardTarget,
    ) -> Result<Self, (FileLifecycleForwardError, HostedForwardTarget)> {
        let owner = Self {
            identity,
            target,
            phase: FileLifecycleForwardPhase::Prepared,
            terminal: None,
            target_released: false,
        };
        if let Err(error) = owner.validate(io, identity, true) {
            return Err((error, owner.target));
        }
        Ok(owner)
    }

    pub const fn identity(&self) -> FileLifecycleForwardIdentity {
        self.identity
    }
    pub const fn phase(&self) -> FileLifecycleForwardPhase {
        self.phase
    }

    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
        check_state: bool,
    ) -> Result<(), FileLifecycleForwardError> {
        let id = self.identity;
        if observed != id
            || self.target.registration() != id.lower_device
            || id.source.allocation().domain != id.source_device.domain()
            || id.lower_device.domain() != id.source_device.domain()
            || id.outer_irp.is_null()
            || id.subsidiary_irp.is_null()
            || id.outer_irp == id.subsidiary_irp
            || !matches!(
                id.major,
                major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE
            )
            || io.hosted_device_pointer_registration(
                id.source_device.domain(),
                id.source_device.address(),
            ) != Some(id.source_device)
        {
            return Err(FileLifecycleForwardError::WrongIdentity);
        }
        self.target
            .validate(io)
            .map_err(FileLifecycleForwardError::Target)?;
        let source = io
            .device(id.source_device.device_id())
            .ok_or(FileLifecycleForwardError::InvalidStack)?;
        if source.attached_to != Some(id.lower_device.device_id()) {
            return Err(FileLifecycleForwardError::InvalidStack);
        }
        let file = io
            .file(id.file)
            .ok_or(FileLifecycleForwardError::InvalidFile)?;
        let outer = io
            .irp(id.outer_irp)
            .ok_or(FileLifecycleForwardError::WrongIdentity)?;
        let subsidiary = io
            .irp(id.subsidiary_irp)
            .ok_or(FileLifecycleForwardError::WrongIdentity)?;
        if outer.file_id != Some(id.file)
            || outer.origin_major != id.major
            || !matches!(
                outer.state,
                IrpState::Dispatched
                    | IrpState::Pending
                    | IrpState::Indeterminate
                    | IrpState::Completed
            )
            || subsidiary.file_id != Some(id.file)
            || subsidiary.origin_device_id != id.lower_device.device_id()
            || subsidiary.origin_major != id.major
            || subsidiary.subsidiary_file_lifecycle != Some(id.outer_irp)
        {
            return Err(FileLifecycleForwardError::WrongIdentity);
        }
        if io.top_of_device_stack(file.device_id).ok() != Some(id.source_device.device_id()) {
            return Err(FileLifecycleForwardError::InvalidFile);
        }
        if check_state
            && !matches!(
                (id.major, file.state),
                (major::IRP_MJ_CREATE, FileState::CreateIrpDispatched)
                    | (major::IRP_MJ_CLEANUP, FileState::CleanupPending)
                    | (major::IRP_MJ_CLOSE, FileState::ClosePending)
            )
        {
            return Err(FileLifecycleForwardError::InvalidFile);
        }
        Ok(())
    }

    /// Record ownership before the native dispatch; this cannot be called twice.
    pub fn enter<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, true)?;
        if self.phase != FileLifecycleForwardPhase::Prepared {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = FileLifecycleForwardPhase::Entered;
        Ok(())
    }

    pub fn dispatch_returned<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
        result: FileLifecycleDispatchReturn,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        if self.phase != FileLifecycleForwardPhase::Entered {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = match result {
            FileLifecycleDispatchReturn::NotEntered(status) if status != NtStatus::PENDING => {
                FileLifecycleForwardPhase::NotEntered(status)
            }
            FileLifecycleDispatchReturn::Pending => FileLifecycleForwardPhase::Pending,
            FileLifecycleDispatchReturn::InlineTerminal {
                status,
                information,
            } if status != NtStatus::PENDING => FileLifecycleForwardPhase::Terminal {
                status,
                information,
            },
            FileLifecycleDispatchReturn::Indeterminate(status) => {
                FileLifecycleForwardPhase::Indeterminate(status)
            }
            _ => return Err(FileLifecycleForwardError::PendingTerminal),
        };
        if let FileLifecycleForwardPhase::Terminal {
            status,
            information,
        } = self.phase
        {
            self.terminal = Some((status, information));
        }
        Ok(())
    }

    /// Only the authenticated native provider callback may report this terminal.
    pub fn provider_terminal<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
        status: NtStatus,
        information: u64,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        if status == NtStatus::PENDING {
            return Err(FileLifecycleForwardError::PendingTerminal);
        }
        if !matches!(
            self.phase,
            FileLifecycleForwardPhase::Pending | FileLifecycleForwardPhase::Indeterminate(_)
        ) {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = FileLifecycleForwardPhase::Terminal {
            status,
            information,
        };
        self.terminal = Some((status, information));
        Ok(())
    }

    /// A source callback that returns MORE_PROCESSING_REQUIRED remains held here.
    pub fn hold_source_completion<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(NtStatus, u64), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        let FileLifecycleForwardPhase::Terminal {
            status,
            information,
        } = self.phase
        else {
            return Err(FileLifecycleForwardError::InvalidTransition);
        };
        self.phase = FileLifecycleForwardPhase::SourceCompletionHeld {
            status,
            information,
        };
        Ok((status, information))
    }

    pub fn source_completion_finished<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        if !matches!(
            self.phase,
            FileLifecycleForwardPhase::SourceCompletionHeld { .. }
        ) {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = FileLifecycleForwardPhase::SourceCompleted;
        Ok(())
    }

    /// The native adapter must prove its exact source service stopped before
    /// entering any callback. The provider terminal is still required.
    pub fn source_stopped<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        if !matches!(self.phase, FileLifecycleForwardPhase::Terminal { .. }) {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = FileLifecycleForwardPhase::SourceStopped;
        Ok(())
    }

    /// Reply acknowledgement is not provider completion. Only an exact native
    /// provider ACK after source completion permits reference retirement.
    /// An indeterminate ACK permanently retains this owner because repeating
    /// the request could acknowledge a different provider operation.
    pub fn acknowledge<P>(
        &mut self,
        io: &IoManager<P>,
        observed: FileLifecycleForwardIdentity,
        acknowledgement: crate::completion_ack::CompletionAcknowledgement,
    ) -> Result<(), FileLifecycleForwardError> {
        self.validate(io, observed, false)?;
        if !matches!(
            self.phase,
            FileLifecycleForwardPhase::SourceCompleted
                | FileLifecycleForwardPhase::SourceStopped
        ) {
            return Err(FileLifecycleForwardError::InvalidTransition);
        }
        self.phase = match acknowledgement {
            crate::completion_ack::CompletionAcknowledgement::Acknowledged => {
                FileLifecycleForwardPhase::Acknowledged
            }
            crate::completion_ack::CompletionAcknowledgement::Indeterminate {
                transport_status,
            } => FileLifecycleForwardPhase::AckIndeterminate(transport_status),
            _ => return Err(FileLifecycleForwardError::InvalidTransition),
        };
        Ok(())
    }

    pub fn retire<P>(
        mut self,
        io: &mut IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(), (FileLifecycleForwardError, Self)> {
        if observed != self.identity {
            return Err((FileLifecycleForwardError::WrongIdentity, self));
        }
        if self.phase != FileLifecycleForwardPhase::Acknowledged
            && self.phase != FileLifecycleForwardPhase::Retiring
        {
            return Err((FileLifecycleForwardError::InvalidTransition, self));
        }
        if self.phase == FileLifecycleForwardPhase::Acknowledged {
            if let Err(error) = self.validate(io, observed, false) {
                return Err((error, self));
            }
            let terminal = self.terminal;
            let completion_matches = io.irp(self.identity.subsidiary_irp).is_some_and(|irp| {
                irp.state == IrpState::Completed
                    && irp.completion_origin == Some(crate::IrpCompletionOrigin::Driver)
                    && terminal == Some((irp.status, irp.information))
            });
            if !completion_matches {
                return Err((FileLifecycleForwardError::InvalidTransition, self));
            }
            self.phase = FileLifecycleForwardPhase::Retiring;
        }
        if !self.target_released {
            if let Err(status) = self.target.release(io) {
                return Err((FileLifecycleForwardError::Target(status), self));
            }
            self.target_released = true;
        }
        // The native provider ACK was authenticated before entering this phase.
        // Reclaim only this subsidiary IRP; the outer File transition belongs to
        // its independently retained lifecycle owner.
        let subsidiary = self.identity.subsidiary_irp;
        if let Some(irp) = io.irp_mut(subsidiary) {
            irp.detached_file_owner = false;
        }
        if io.free_irp(subsidiary).is_none() {
            return Err((FileLifecycleForwardError::InvalidTransition, self));
        }
        Ok(())
    }

    /// Reclaim a preparation or a provider call with proven no-entry. A
    /// transport failure or uncertain result cannot use this path.
    pub fn discard_not_entered<P>(
        mut self,
        io: &mut IoManager<P>,
        observed: FileLifecycleForwardIdentity,
    ) -> Result<(), (FileLifecycleForwardError, Self)> {
        if observed != self.identity {
            return Err((FileLifecycleForwardError::WrongIdentity, self));
        }
        if !matches!(
            self.phase,
            FileLifecycleForwardPhase::Prepared
                | FileLifecycleForwardPhase::NotEntered(_)
                | FileLifecycleForwardPhase::Discarding
        ) {
            return Err((FileLifecycleForwardError::InvalidTransition, self));
        }
        if self.phase != FileLifecycleForwardPhase::Discarding {
            if let Err(error) = self.validate(io, observed, false) {
                return Err((error, self));
            }
            self.phase = FileLifecycleForwardPhase::Discarding;
        }
        if !self.target_released {
            if let Err(status) = self.target.release(io) {
                return Err((FileLifecycleForwardError::Target(status), self));
            }
            self.target_released = true;
        }
        let subsidiary = self.identity.subsidiary_irp;
        if let Some(irp) = io.irp_mut(subsidiary) {
            irp.detached_file_owner = false;
        }
        if io.free_irp(subsidiary).is_none() {
            return Err((FileLifecycleForwardError::InvalidTransition, self));
        }
        Ok(())
    }
}

impl<P> IoManager<P> {
    /// Authenticate the private subsidiary marker against its still-live outer
    /// IRP, exact File, major, and direct lower attachment. A numeric IrpId or
    /// request payload flag alone never grants CLOSE projection authority.
    pub fn subsidiary_file_lifecycle_identity(
        &self,
        subsidiary: IrpId,
    ) -> Option<SubsidiaryFileLifecycleIdentity> {
        let lower = self.irp(subsidiary)?;
        let outer_irp = lower.subsidiary_file_lifecycle?;
        let outer = self.irp(outer_irp)?;
        let file_id = lower.file_id?;
        let source_device = outer.current_stack()?.device_id;
        if outer.file_id != Some(file_id)
            || outer.origin_major != lower.origin_major
            || !matches!(
                lower.origin_major,
                major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE
            )
            || self.device(source_device)?.attached_to != Some(lower.origin_device_id)
            || self
                .top_of_device_stack(self.file(file_id)?.device_id)
                .ok()?
                != source_device
        {
            return None;
        }
        Some(SubsidiaryFileLifecycleIdentity {
            outer_irp,
            file_id,
            major: lower.origin_major,
        })
    }

    /// Checked lower projection includes the canonical File name on CREATE.
    pub fn subsidiary_file_lifecycle_projection(
        &self,
        outer: IrpId,
        subsidiary: IrpId,
    ) -> Result<IrpProjection, NtStatus> {
        let irp = self.irp(subsidiary).ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.subsidiary_file_lifecycle != Some(outer) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.file_irp_projection(subsidiary)
    }

    /// Allocate a distinct lower canonical IRP while the authenticated outer
    /// lifecycle IRP still owns the File. This leaves the outer File state alone.
    pub fn prepare_subsidiary_file_lifecycle(
        &mut self,
        outer: IrpId,
        source: HostedDevicePointerRegistration,
        lower: HostedDevicePointerRegistration,
    ) -> Result<IrpId, NtStatus> {
        if source.domain() != lower.domain()
            || self.hosted_device_pointer_registration(source.domain(), source.address())
                != Some(source)
            || self.hosted_device_pointer_registration(lower.domain(), lower.address())
                != Some(lower)
            || self
                .device(source.device_id())
                .and_then(|device| device.attached_to)
                != Some(lower.device_id())
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let outer_record = self.irp(outer).ok_or(NtStatus::INVALID_PARAMETER)?;
        let major = outer_record.origin_major;
        if !matches!(
            major,
            major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE
        ) || !matches!(
            outer_record.state,
            IrpState::Dispatched | IrpState::Pending | IrpState::Indeterminate
        ) || outer_record.current_stack().map(|stack| stack.device_id)
            != Some(source.device_id())
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file_id = outer_record.file_id.ok_or(NtStatus::INVALID_HANDLE)?;
        if self
            .irps
            .iter()
            .any(|(_, irp)| irp.subsidiary_file_lifecycle == Some(outer))
        {
            return Err(NtStatus::DEVICE_BUSY);
        }
        let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if self.top_of_device_stack(file.device_id)? != source.device_id()
            || !matches!(
                (major, file.state),
                (major::IRP_MJ_CREATE, FileState::CreateIrpDispatched)
                    | (major::IRP_MJ_CLEANUP, FileState::CleanupPending)
                    | (major::IRP_MJ_CLOSE, FileState::ClosePending)
            )
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let client = outer_record.client_id;
        let requestor_tid = outer_record.requestor_tid;
        let parameters = match major {
            major::IRP_MJ_CREATE => outer_record
                .current_stack()
                .map(|stack| stack.parameters.clone())
                .filter(|params| matches!(params, IoParameters::Create(_)))
                .ok_or(NtStatus::INVALID_PARAMETER)?,
            major::IRP_MJ_CLEANUP => IoParameters::Cleanup,
            major::IRP_MJ_CLOSE => IoParameters::Close,
            _ => return Err(NtStatus::INVALID_PARAMETER),
        };
        let mut record = self.build_irp_record_at_device(
            client,
            lower.device_id(),
            Some(file_id),
            major,
            parameters,
        )?;
        record.requestor_tid = requestor_tid;
        record.subsidiary_file_lifecycle = Some(outer);
        record.detached_file_owner = true;
        let subsidiary = self.allocate_irp(record)?;
        self.irp_mut(subsidiary)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .transition(IrpState::Initialized);
        Ok(subsidiary)
    }

    /// Claim provider entry exactly once. An uncertain native result keeps this
    /// canonical IRP and its File reference until genuine completion or teardown.
    pub fn begin_subsidiary_file_lifecycle(
        &mut self,
        outer: IrpId,
        subsidiary: IrpId,
    ) -> Result<(), NtStatus> {
        let irp = self
            .irp_mut(subsidiary)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.subsidiary_file_lifecycle != Some(outer) || !irp.transition(IrpState::Dispatched) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    /// Record the actual outer return without replaying the provider call.
    pub fn record_subsidiary_file_lifecycle_return(
        &mut self,
        outer: IrpId,
        subsidiary: IrpId,
        result: FileLifecycleDispatchReturn,
    ) -> Result<(), NtStatus> {
        let irp = self
            .irp_mut(subsidiary)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.subsidiary_file_lifecycle != Some(outer) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        // IoCompleteRequest may publish a synchronous completion before the
        // native dispatch call returns. A pending/uncertain return leaves that
        // genuine terminal intact; an inline return must match it exactly.
        if irp.state == IrpState::Completed {
            if irp.completion_origin != Some(crate::IrpCompletionOrigin::Driver) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            return match result {
                FileLifecycleDispatchReturn::InlineTerminal {
                    status,
                    information,
                } if irp.status == status && irp.information == information => Ok(()),
                FileLifecycleDispatchReturn::Pending
                | FileLifecycleDispatchReturn::Indeterminate(_) => Ok(()),
                _ => Err(NtStatus::INVALID_PARAMETER),
            };
        }
        if irp.state != IrpState::Dispatched {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        match result {
            FileLifecycleDispatchReturn::NotEntered(status) if status != NtStatus::PENDING => {
                Ok(())
            }
            FileLifecycleDispatchReturn::InlineTerminal { status, .. }
                if status != NtStatus::PENDING =>
            {
                Ok(())
            }
            FileLifecycleDispatchReturn::Pending if irp.transition(IrpState::Pending) => Ok(()),
            FileLifecycleDispatchReturn::Indeterminate(_)
                if irp.transition(IrpState::Indeterminate) =>
            {
                Ok(())
            }
            _ => Err(NtStatus::INVALID_PARAMETER),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        retained_query_path_forward::SourceIrpTicket,
        source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner},
        CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, FileRecord,
        MockDriverBackend, MockObjectPort, ShareAccess,
    };
    use alloc::boxed::Box;
    use nt_types::{AccessMask, ClientId, NtPath, ObjectId};

    fn publish(
        io: &mut IoManager<MockObjectPort>,
        id: FileLifecycleForwardIdentity,
        status: NtStatus,
        information: u64,
    ) {
        let driver = io.device(id.lower_device.device_id()).unwrap().driver_id;
        assert!(io.publish_driver_completion(
            driver,
            crate::DriverCompletion {
                irp_id: id.subsidiary_irp,
                status,
                information,
                file_context: None,
            }
        ));
    }

    fn fixture(
        major: u8,
    ) -> (
        IoManager<MockObjectPort>,
        FileLifecycleForwardIdentity,
        HostedForwardTarget,
    ) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\LifecycleForward").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let lower = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let source = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        io.attach_device_to_stack(source, lower).unwrap();
        let file = io.add_file(FileRecord::new(
            ObjectId::NULL,
            ClientId(1),
            lower,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            NtPath::parse_str(r"\Device\LifecycleForward")
                .unwrap()
                .to_unicode_string(),
        ));
        // CREATE is admitted while Allocated; the outer IRP subsequently owns
        // the transition to CreateIrpDispatched.
        if major != major::IRP_MJ_CREATE {
            io.file_mut(file).unwrap().state = if major == major::IRP_MJ_CLEANUP {
                FileState::CleanupPending
            } else {
                FileState::ClosePending
            };
        }
        let parameters = match major {
            major::IRP_MJ_CREATE => IoParameters::Create(crate::CreateParameters::default()),
            major::IRP_MJ_CLEANUP => IoParameters::Cleanup,
            major::IRP_MJ_CLOSE => IoParameters::Close,
            _ => unreachable!(),
        };
        let outer_record = io
            .build_irp_record(ClientId(1), driver, lower, Some(file), major, parameters)
            .unwrap();
        let outer_irp = io.allocate_irp(outer_record).unwrap();
        assert!(io
            .irp_mut(outer_irp)
            .unwrap()
            .transition(IrpState::Initialized));
        assert!(io
            .irp_mut(outer_irp)
            .unwrap()
            .transition(IrpState::Dispatched));
        io.file_mut(file).unwrap().state = match major {
            major::IRP_MJ_CREATE => FileState::CreateIrpDispatched,
            major::IRP_MJ_CLEANUP => FileState::CleanupPending,
            major::IRP_MJ_CLOSE => FileState::ClosePending,
            _ => unreachable!(),
        };
        let domain = io.register_hosted_domain();
        let source_device = io
            .bind_hosted_device_pointer(domain, 0x5000, source)
            .unwrap();
        let lower_device = io
            .bind_hosted_device_pointer(domain, 0x6000, lower)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x6000).unwrap();
        let subsidiary_irp = io
            .prepare_subsidiary_file_lifecycle(outer_irp, source_device, lower_device)
            .unwrap();
        let allocation = SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(0),
            domain,
            component_address: 0x7000,
            bytes: 0x100,
            stack_count: 2,
            pool_generation: 9,
        };
        let ticket = SourceIrpTicket::new(domain, 5, 9).unwrap();
        let source_irp = SourceIrpForwardIdentity::new(ticket, allocation).unwrap();
        let identity = FileLifecycleForwardIdentity {
            source: source_irp,
            source_device,
            lower_device,
            file,
            outer_irp,
            subsidiary_irp,
            major,
        };
        (io, identity, target)
    }

    #[test]
    fn accepts_each_lifecycle_major_without_completing_outer_file() {
        for major in [
            major::IRP_MJ_CREATE,
            major::IRP_MJ_CLEANUP,
            major::IRP_MJ_CLOSE,
        ] {
            let (mut io, id, target) = fixture(major);
            let before = io.file(id.file).unwrap().state;
            let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
            owner.enter(&io, id).unwrap();
            io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
                .unwrap();
            owner
                .dispatch_returned(
                    &io,
                    id,
                    FileLifecycleDispatchReturn::InlineTerminal {
                        status: NtStatus::SUCCESS,
                        information: 0,
                    },
                )
                .unwrap();
            publish(&mut io, id, NtStatus::SUCCESS, 0);
            assert_eq!(
                owner.hold_source_completion(&io, id),
                Ok((NtStatus::SUCCESS, 0))
            );
            owner.source_completion_finished(&io, id).unwrap();
            owner
                .acknowledge(
                    &io,
                    id,
                    crate::completion_ack::CompletionAcknowledgement::Acknowledged,
                )
                .unwrap();
            owner.retire(&mut io, id).unwrap();
            assert_eq!(io.file(id.file).unwrap().state, before);
            assert_eq!(io.file(id.file).unwrap().outstanding_irp_refs, 1);
        }
    }

    #[test]
    fn exact_source_generation_device_and_subsidiary_identity_are_required() {
        let (io, id, target) = fixture(major::IRP_MJ_CREATE);
        let mut wrong = id;
        wrong.subsidiary_irp = wrong.outer_irp;
        let (error, target) = RetainedFileLifecycleForward::new(&io, wrong, target).unwrap_err();
        assert_eq!(error, FileLifecycleForwardError::WrongIdentity);
        let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
        let allocation = SourceIrpAllocation {
            pool_generation: 10,
            ..id.source.allocation()
        };
        wrong = id;
        wrong.source = SourceIrpForwardIdentity::new(id.source.ticket(), allocation).unwrap();
        assert_eq!(
            owner.enter(&io, wrong),
            Err(FileLifecycleForwardError::WrongIdentity)
        );
        let mut forged = id;
        forged.lower_device = id.source_device;
        assert_eq!(
            owner.enter(&io, forged),
            Err(FileLifecycleForwardError::WrongIdentity)
        );
        owner.enter(&io, id).unwrap();
        assert_eq!(
            owner.enter(&io, id),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
    }

    #[test]
    fn pending_uncertain_and_duplicate_dispatch_never_replay() {
        for outcome in [
            FileLifecycleDispatchReturn::Pending,
            FileLifecycleDispatchReturn::Indeterminate(NtStatus::DEVICE_BUSY),
        ] {
            let (mut io, id, target) = fixture(major::IRP_MJ_CLEANUP);
            let count = io.device_reference_count(id.lower_device.device_id());
            let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
            owner.enter(&io, id).unwrap();
            io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
                .unwrap();
            io.record_subsidiary_file_lifecycle_return(id.outer_irp, id.subsidiary_irp, outcome)
                .unwrap();
            owner.dispatch_returned(&io, id, outcome).unwrap();
            assert_eq!(
                owner.dispatch_returned(&io, id, outcome),
                Err(FileLifecycleForwardError::InvalidTransition)
            );
            assert!(matches!(
                owner.retire(&mut io, id),
                Err((FileLifecycleForwardError::InvalidTransition, _))
            ));
            assert_eq!(
                io.device_reference_count(id.lower_device.device_id()),
                count
            );
        }
    }

    #[test]
    fn source_callback_and_exact_ack_hold_references_until_both_finish() {
        let (mut io, id, target) = fixture(major::IRP_MJ_CREATE);
        let held = io.device_reference_count(id.lower_device.device_id());
        let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
        owner.enter(&io, id).unwrap();
        io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
            .unwrap();
        io.record_subsidiary_file_lifecycle_return(
            id.outer_irp,
            id.subsidiary_irp,
            FileLifecycleDispatchReturn::Pending,
        )
        .unwrap();
        owner
            .dispatch_returned(&io, id, FileLifecycleDispatchReturn::Pending)
            .unwrap();
        assert_eq!(
            owner.hold_source_completion(&io, id),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
        owner
            .provider_terminal(&io, id, NtStatus::SUCCESS, 2)
            .unwrap();
        publish(&mut io, id, NtStatus::SUCCESS, 2);
        assert_eq!(
            owner.hold_source_completion(&io, id),
            Ok((NtStatus::SUCCESS, 2))
        );
        assert_eq!(
            owner.acknowledge(
                &io,
                id,
                crate::completion_ack::CompletionAcknowledgement::Acknowledged
            ),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
        owner.source_completion_finished(&io, id).unwrap();
        let mut forged = id;
        forged.outer_irp = IrpId(0x300);
        assert_eq!(
            owner.acknowledge(
                &io,
                forged,
                crate::completion_ack::CompletionAcknowledgement::Acknowledged
            ),
            Err(FileLifecycleForwardError::WrongIdentity)
        );
        owner
            .acknowledge(
                &io,
                id,
                crate::completion_ack::CompletionAcknowledgement::Indeterminate {
                    transport_status: NtStatus::DEVICE_BUSY,
                },
            )
            .unwrap();
        owner = match owner.retire(&mut io, id) {
            Err((FileLifecycleForwardError::InvalidTransition, owner)) => owner,
            _ => panic!("uncertain ACK must retain"),
        };
        assert_eq!(io.device_reference_count(id.lower_device.device_id()), held);
        assert_eq!(
            owner.acknowledge(
                &io,
                id,
                crate::completion_ack::CompletionAcknowledgement::Acknowledged,
            ),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
        owner = match owner.retire(&mut io, id) {
            Err((FileLifecycleForwardError::InvalidTransition, owner)) => owner,
            _ => panic!("uncertain ACK cannot become retirement authority"),
        };
        assert_eq!(
            owner.phase(),
            FileLifecycleForwardPhase::AckIndeterminate(NtStatus::DEVICE_BUSY)
        );
        assert_eq!(io.device_reference_count(id.lower_device.device_id()), held);
        assert_eq!(io.file(id.file).unwrap().outstanding_irp_refs, 2);
    }

    #[test]
    fn detached_stack_and_wrong_outer_file_state_cannot_enter() {
        let (mut io, id, target) = fixture(major::IRP_MJ_CREATE);
        io.file_mut(id.file).unwrap().state = FileState::Open;
        let (error, target) = RetainedFileLifecycleForward::new(&io, id, target).unwrap_err();
        assert_eq!(error, FileLifecycleForwardError::InvalidFile);
        io.file_mut(id.file).unwrap().state = FileState::CreateIrpDispatched;
        io.device_mut(id.source_device.device_id())
            .unwrap()
            .attached_to = None;
        let (error, _) = RetainedFileLifecycleForward::new(&io, id, target).unwrap_err();
        assert_eq!(error, FileLifecycleForwardError::InvalidStack);
    }

    #[test]
    fn proven_no_entry_discards_only_the_subsidiary_without_file_completion() {
        let (mut io, id, target) = fixture(major::IRP_MJ_CREATE);
        let before = io.file(id.file).unwrap().state;
        let projection = io
            .subsidiary_file_lifecycle_projection(id.outer_irp, id.subsidiary_irp)
            .unwrap();
        assert!(projection.file_name.is_some());
        let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
        owner.enter(&io, id).unwrap();
        io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
            .unwrap();
        let no_entry = FileLifecycleDispatchReturn::NotEntered(NtStatus::INVALID_DEVICE_REQUEST);
        io.record_subsidiary_file_lifecycle_return(id.outer_irp, id.subsidiary_irp, no_entry)
            .unwrap();
        owner.dispatch_returned(&io, id, no_entry).unwrap();
        owner.discard_not_entered(&mut io, id).unwrap();
        assert!(io.irp(id.subsidiary_irp).is_none());
        assert_eq!(io.irp(id.outer_irp).unwrap().state, IrpState::Dispatched);
        assert_eq!(io.file(id.file).unwrap().state, before);
        assert_eq!(io.file(id.file).unwrap().outstanding_irp_refs, 1);
    }

    #[test]
    fn stopped_source_requires_lower_terminal_and_skips_only_its_callback() {
        let (mut io, id, target) = fixture(major::IRP_MJ_CLOSE);
        let mut owner = RetainedFileLifecycleForward::new(&io, id, target).unwrap();
        owner.enter(&io, id).unwrap();
        io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
            .unwrap();
        io.record_subsidiary_file_lifecycle_return(
            id.outer_irp,
            id.subsidiary_irp,
            FileLifecycleDispatchReturn::Pending,
        )
        .unwrap();
        owner
            .dispatch_returned(&io, id, FileLifecycleDispatchReturn::Pending)
            .unwrap();
        assert_eq!(
            owner.source_stopped(&io, id),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
        owner
            .provider_terminal(&io, id, NtStatus::CANCELLED, 0)
            .unwrap();
        publish(&mut io, id, NtStatus::CANCELLED, 0);
        owner.source_stopped(&io, id).unwrap();
        assert_eq!(
            owner.hold_source_completion(&io, id),
            Err(FileLifecycleForwardError::InvalidTransition)
        );
        owner
            .acknowledge(
                &io,
                id,
                crate::completion_ack::CompletionAcknowledgement::Acknowledged,
            )
            .unwrap();
        owner.retire(&mut io, id).unwrap();
        assert_eq!(io.file(id.file).unwrap().state, FileState::ClosePending);
    }

    #[test]
    fn close_marker_requires_exact_live_subsidiary_and_outer_identity() {
        for major in [
            major::IRP_MJ_CREATE,
            major::IRP_MJ_CLEANUP,
            major::IRP_MJ_CLOSE,
        ] {
            let (mut io, id, _) = fixture(major);
            let marker = io
                .subsidiary_file_lifecycle_identity(id.subsidiary_irp)
                .unwrap();
            assert_eq!(
                (marker.outer_irp(), marker.file_id(), marker.major()),
                (id.outer_irp, id.file, major)
            );
            assert_eq!(io.subsidiary_file_lifecycle_identity(id.outer_irp), None);
            io.device_mut(id.source_device.device_id())
                .unwrap()
                .attached_to = None;
            assert_eq!(
                io.subsidiary_file_lifecycle_identity(id.subsidiary_irp),
                None
            );
        }
    }

    #[test]
    fn synchronous_completion_before_dispatch_return_requires_exact_terminal() {
        let (mut io, id, _) = fixture(major::IRP_MJ_CREATE);
        io.begin_subsidiary_file_lifecycle(id.outer_irp, id.subsidiary_irp)
            .unwrap();
        publish(&mut io, id, NtStatus::SUCCESS, 3);
        for result in [
            FileLifecycleDispatchReturn::InlineTerminal {
                status: NtStatus::SUCCESS,
                information: 2,
            },
            FileLifecycleDispatchReturn::InlineTerminal {
                status: NtStatus::ACCESS_DENIED,
                information: 3,
            },
            FileLifecycleDispatchReturn::NotEntered(NtStatus::INVALID_DEVICE_REQUEST),
        ] {
            assert_eq!(
                io.record_subsidiary_file_lifecycle_return(id.outer_irp, id.subsidiary_irp, result),
                Err(NtStatus::INVALID_PARAMETER)
            );
        }
        assert_eq!(
            io.record_subsidiary_file_lifecycle_return(
                id.outer_irp,
                id.subsidiary_irp,
                FileLifecycleDispatchReturn::InlineTerminal {
                    status: NtStatus::SUCCESS,
                    information: 3
                }
            ),
            Ok(())
        );
        assert_eq!(
            io.record_subsidiary_file_lifecycle_return(
                id.outer_irp,
                id.subsidiary_irp,
                FileLifecycleDispatchReturn::Pending
            ),
            Ok(())
        );
        assert_eq!(
            io.record_subsidiary_file_lifecycle_return(
                id.outer_irp,
                id.subsidiary_irp,
                FileLifecycleDispatchReturn::Indeterminate(NtStatus::DEVICE_BUSY)
            ),
            Ok(())
        );
    }
}
