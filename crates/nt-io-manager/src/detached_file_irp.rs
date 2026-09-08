//! Detached DriverPeer dispatch. Native execution and completion ACK run outside the manager.
//!
//! Every owner is consuming and manager-bound. Dropping an owner does not retire its canonical
//! IRP. CLEANUP/CLOSE require the manager's separate lifecycle transaction and are not admitted
//! here. The integration host keeps its real requestor-thread lease beside these owners.

use crate::{
    BufferAccess, CompletedIrp, DeviceId, DriverId, DriverPeerId, FileId, FileState, IoBufferRef,
    IoManager, IoParameters, IrpCompletionOrigin, IrpId, IrpProjection, IrpState,
    ObjectManagerPort, StackFlags,
};
use alloc::vec::Vec;
use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::ClientId;

#[derive(Debug)]
pub struct ExternalFileIrpRequest {
    pub client: ClientId,
    pub device_id: DeviceId,
    pub file_id: Option<FileId>,
    pub user_data: u64,
    pub requestor_tid: u64,
    pub major: u8,
    pub parameters: IoParameters,
    pub stack_flags: StackFlags,
}

/// Separate owned buffers preserve both input and initial output bytes without aliasing slices.
#[derive(Debug)]
pub struct ExternalFileIrpBuffers {
    input: Vec<u8>,
    output: Vec<u8>,
}

pub struct ExternalFileIrpBufferView<'a> {
    input: &'a [u8],
    output: &'a mut [u8],
}
impl<'a> ExternalFileIrpBufferView<'a> {
    pub fn split(self) -> (&'a [u8], &'a mut [u8]) {
        (self.input, self.output)
    }
}

impl ExternalFileIrpBuffers {
    pub fn new(input: Vec<u8>, output: Vec<u8>) -> Self {
        Self { input, output }
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn output_mut(&mut self) -> &mut [u8] {
        &mut self.output
    }
    pub fn split(&mut self) -> (&[u8], &mut [u8]) {
        (&self.input, &mut self.output)
    }
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.input, self.output)
    }
}

/// The canonical DriverPeer table target, never an inferred native provider instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalFileIrpRoute {
    driver_id: DriverId,
    device_id: DeviceId,
    peer: DriverPeerId,
}
impl ExternalFileIrpRoute {
    pub fn driver_id(self) -> DriverId {
        self.driver_id
    }
    pub fn device_id(self) -> DeviceId {
        self.device_id
    }
    pub fn peer(self) -> DriverPeerId {
        self.peer
    }
}

#[derive(Debug)]
struct Owner {
    manager: u64,
    projection: IrpProjection,
    route: ExternalFileIrpRoute,
    client: ClientId,
    origin_driver: DriverId,
    origin_device: DeviceId,
    related: Option<FileId>,
    target: Option<FileId>,
    buffers: ExternalFileIrpBuffers,
}

#[derive(Debug)]
#[must_use = "discard or begin through the issuing I/O Manager"]
/// A preparation cannot authorize two dispatches.
///
/// ```compile_fail
/// use nt_io_manager::detached_file_irp::PreparedExternalFileIrp;
/// fn duplicate(owner: PreparedExternalFileIrp) {
///     let first = owner;
///     let second = owner;
/// }
/// ```
pub struct PreparedExternalFileIrp(Owner);
#[derive(Debug)]
#[must_use = "return the exact invocation; dropping it retains the canonical IRP"]
pub struct ExternalFileIrpInvocation(Owner);
#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct ExternalFileIrpReturn {
    owner: Owner,
    outcome: ExternalFileIrpOutcome,
}
#[derive(Debug)]
#[must_use = "retain until genuine backend completion can be acknowledged"]
pub struct RetainedExternalFileIrp {
    owner: Owner,
    indeterminate: bool,
}
#[derive(Debug)]
#[must_use = "retire through the issuing I/O Manager"]
pub struct ExternalFileIrpTerminal {
    owner: Owner,
    completion: CompletedIrp,
}
#[derive(Debug)]
#[must_use = "acknowledge outside the manager and return the exact invocation"]
/// The same completion invocation cannot be acknowledged twice.
///
/// ```compile_fail
/// use nt_io_manager::detached_file_irp::{ExternalFileIrpCompletionInvocation,
///     ExternalFileIrpAcknowledgement};
/// fn duplicate(owner: ExternalFileIrpCompletionInvocation) {
///     let first = owner.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged);
///     let second = owner.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged);
/// }
/// ```
pub struct ExternalFileIrpCompletionInvocation {
    owner: Owner,
    completion: CompletedIrp,
}
#[derive(Debug)]
#[must_use = "finish acknowledgement through the issuing I/O Manager"]
pub struct ExternalFileIrpCompletionReturn {
    invocation: ExternalFileIrpCompletionInvocation,
    acknowledgement: ExternalFileIrpAcknowledgement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFileIrpAcknowledgement {
    Acknowledged,
    NotEntered { status: NtStatus },
    Rejected { status: NtStatus },
    Indeterminate { transport_status: NtStatus },
}

#[derive(Debug)]
#[must_use = "recover the unchanged owner"]
pub struct ExternalFileIrpRejection<T> {
    status: NtStatus,
    owner: T,
}
impl<T> ExternalFileIrpRejection<T> {
    pub fn status(&self) -> NtStatus {
        self.status
    }
    pub fn owner(&self) -> &T {
        &self.owner
    }
    pub fn into_owner(self) -> T {
        self.owner
    }
    pub fn into_parts(self) -> (NtStatus, T) {
        (self.status, self.owner)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFileIrpOutcome {
    /// The executor proves it did not enter the native dispatch transport at all.
    NotEntered {
        status: NtStatus,
    },
    Returned {
        status: NtStatus,
        information: u64,
        file_context: Option<u64>,
    },
    Pending,
    Indeterminate {
        transport_status: NtStatus,
    },
}

#[derive(Debug)]
pub enum ExternalFileIrpResult {
    NotEntered {
        status: NtStatus,
        prepared: PreparedExternalFileIrp,
    },
    Returned(ExternalFileIrpTerminal),
    Pending(RetainedExternalFileIrp),
    Indeterminate {
        transport_status: NtStatus,
        retained: RetainedExternalFileIrp,
    },
}

/// Only successful canonical retirement can mint this receipt.
#[derive(Debug)]
pub struct ExternalFileIrpTerminalReceipt {
    manager: u64,
    completion: CompletedIrp,
    backend_acknowledged: bool,
}
impl ExternalFileIrpTerminalReceipt {
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion
    }
    pub fn backend_acknowledged(&self) -> bool {
        self.backend_acknowledged
    }
}

macro_rules! owner_accessors {
    ($ty:ty, $field:tt) => {
        impl $ty {
            pub fn irp_id(&self) -> IrpId {
                self.$field.projection.irp_id
            }
            pub fn projection(&self) -> &IrpProjection {
                &self.$field.projection
            }
            pub fn route(&self) -> ExternalFileIrpRoute {
                self.$field.route
            }
            pub fn buffers(&self) -> &ExternalFileIrpBuffers {
                &self.$field.buffers
            }
        }
    };
}
owner_accessors!(PreparedExternalFileIrp, 0);
owner_accessors!(ExternalFileIrpInvocation, 0);
owner_accessors!(RetainedExternalFileIrp, owner);
owner_accessors!(ExternalFileIrpTerminal, owner);
owner_accessors!(ExternalFileIrpCompletionInvocation, owner);

impl ExternalFileIrpInvocation {
    pub fn buffers_mut(&mut self) -> ExternalFileIrpBufferView<'_> {
        ExternalFileIrpBufferView {
            input: &self.0.buffers.input,
            output: &mut self.0.buffers.output,
        }
    }
    pub fn returned(self, outcome: ExternalFileIrpOutcome) -> ExternalFileIrpReturn {
        ExternalFileIrpReturn {
            owner: self.0,
            outcome,
        }
    }
}
impl RetainedExternalFileIrp {
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }
}
impl ExternalFileIrpTerminal {
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion
    }
}
impl ExternalFileIrpCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion
    }
    pub fn buffers_mut(&mut self) -> ExternalFileIrpBufferView<'_> {
        ExternalFileIrpBufferView {
            input: &self.owner.buffers.input,
            output: &mut self.owner.buffers.output,
        }
    }
    pub fn acknowledged(
        self,
        acknowledgement: ExternalFileIrpAcknowledgement,
    ) -> ExternalFileIrpCompletionReturn {
        ExternalFileIrpCompletionReturn {
            invocation: self,
            acknowledgement,
        }
    }
}

impl ExternalFileIrpCompletionReturn {
    /// Only a failed ACK can be executed again. An accepted ACK remains durable for local retry.
    pub fn retry(self) -> Result<ExternalFileIrpCompletionInvocation, Self> {
        if matches!(
            self.acknowledgement,
            ExternalFileIrpAcknowledgement::NotEntered { .. }
                | ExternalFileIrpAcknowledgement::Rejected { .. }
        ) {
            Ok(self.invocation)
        } else {
            Err(self)
        }
    }
    pub fn acknowledgement(&self) -> ExternalFileIrpAcknowledgement {
        self.acknowledgement
    }
}

fn referenced_files(parameters: &IoParameters) -> (Option<FileId>, Option<FileId>) {
    match parameters {
        IoParameters::Create(parameters) => (parameters.related_file, None),
        IoParameters::SetInformation(parameters) => (None, parameters.target_file),
        _ => (None, None),
    }
}

fn validate_buffers(
    request: &ExternalFileIrpRequest,
    buffers: &ExternalFileIrpBuffers,
) -> Result<(u32, u32, u32), NtStatus> {
    let input = u32::try_from(buffers.input.len()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let output = u32::try_from(buffers.output.len()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let valid = match &request.parameters {
        IoParameters::Create(p) => {
            crate::is_create_major(request.major) && output == 0 && input >= p.ea_length
        }
        IoParameters::Read(p) => {
            request.major == major::IRP_MJ_READ && input == 0 && output == p.length
        }
        IoParameters::Write(p) => {
            request.major == major::IRP_MJ_WRITE && input == p.length && output == 0
        }
        IoParameters::DeviceControl(p) => {
            matches!(
                request.major,
                major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_FILE_SYSTEM_CONTROL
            ) && input == p.input_len
                && output == p.output_len
        }
        IoParameters::InternalDeviceControl(p) => {
            request.major == major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                && input == p.input_len
                && output == p.output_len
        }
        IoParameters::QueryInformation(p) => {
            request.major == major::IRP_MJ_QUERY_INFORMATION && input == 0 && output == p.length
        }
        IoParameters::SetInformation(p) => {
            request.major == major::IRP_MJ_SET_INFORMATION && input == p.length && output == 0
        }
        IoParameters::FlushBuffers => {
            request.major == major::IRP_MJ_FLUSH_BUFFERS && input == 0 && output == 0
        }
        IoParameters::QueryEa(_)
        | IoParameters::SetEa(_)
        | IoParameters::QueryQuota(_)
        | IoParameters::SetQuota(_)
        | IoParameters::QueryVolumeInformation(_)
        | IoParameters::SetVolumeInformation(_)
        | IoParameters::LockControl(_)
        | IoParameters::NotifyDirectory(_) => true,
        _ => false,
    };
    if !valid
        || request.file_id.is_none()
            && !matches!(
                request.parameters,
                IoParameters::DeviceControl(_)
                    | IoParameters::InternalDeviceControl(_)
                    | IoParameters::FlushBuffers
            )
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let separate = matches!(
        request.parameters,
        IoParameters::QueryEa(_) | IoParameters::QueryQuota(_)
    ) || matches!(&request.parameters, IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p) if p.ioctl_code & 3 != 0);
    let total = if separate {
        input
            .checked_add(output)
            .ok_or(NtStatus::INVALID_PARAMETER)?
    } else {
        input.max(output)
    };
    crate::external_dispatch::validate_external_parameter_layout(
        request.major,
        &request.parameters,
        request.stack_flags,
        input,
        output,
        total as usize,
    )?;
    Ok((input, output, total))
}

impl<P: ObjectManagerPort> IoManager<P> {
    pub fn prepare_external_file_irp_owned(
        &mut self,
        mut request: ExternalFileIrpRequest,
        buffers: ExternalFileIrpBuffers,
    ) -> Result<PreparedExternalFileIrp, NtStatus> {
        let (input, output, total) = validate_buffers(&request, &buffers)?;
        let device = self
            .device(request.device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if device.delete_pending {
            return Err(NtStatus::DELETE_PENDING);
        }
        let origin_driver = device.driver_id;
        if let Some(file_id) = request.file_id {
            let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
            if file.client_id != request.client || file.device_id != request.device_id {
                return Err(NtStatus::INVALID_HANDLE);
            }
            if let IoParameters::Create(parameters) = &mut request.parameters {
                parameters.related_file = file.related_file;
                request.user_data = 0;
            } else {
                request.user_data = file.driver_context.unwrap_or(0);
            }
        }
        let mut record = self.build_irp_record(
            request.client,
            origin_driver,
            request.device_id,
            request.file_id,
            request.major,
            request.parameters,
        )?;
        for stack in &mut record.stack {
            stack.flags = request.stack_flags;
        }
        record.requestor_tid = request.requestor_tid;
        record.user_data = request.user_data;
        record.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: total,
            input_len: input,
            output_len: output,
            access: BufferAccess::ReadWrite,
        });
        record.set_request_input_fingerprint(&buffers.input);
        let mut projection = IrpProjection::from_record(&record)?;
        let peer = self
            .driver(projection.driver_id)
            .and_then(|driver| driver.dispatch.get(request.major).driver_peer_id())
            .filter(|peer| (peer.0 as usize) < self.backends.len())
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let route = ExternalFileIrpRoute {
            driver_id: projection.driver_id,
            device_id: projection.device_id,
            peer,
        };
        let manager = self.ensure_ownership_identity()?;
        let (related, target) = referenced_files(&projection.parameters);
        let irp_id = self.allocate_irp(record)?;
        projection.irp_id = irp_id;
        let record = self.irp_mut(irp_id).expect("allocated detached IRP");
        assert!(record.transition(IrpState::Initialized));
        record.detached_file_owner = true;
        Ok(PreparedExternalFileIrp(Owner {
            manager,
            projection,
            route,
            client: request.client,
            origin_driver,
            origin_device: request.device_id,
            related,
            target,
            buffers,
        }))
    }

    fn validate_detached_owner(&self, owner: &Owner) -> Result<(), NtStatus> {
        if owner.manager == 0 || owner.manager != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let irp = self
            .irp(owner.projection.irp_id)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let stack = irp.current_stack().ok_or(NtStatus::INVALID_PARAMETER)?;
        let projection = &owner.projection;
        if irp.id != projection.irp_id
            || irp.current_location != projection.stack_location
            || irp.stack.len() != usize::from(projection.stack_count)
            || stack.driver_id != projection.driver_id
            || stack.device_id != projection.device_id
            || stack.file_id != projection.file_id
            || stack.major != projection.major
            || stack.minor != projection.minor
            || stack.flags != projection.flags
            || stack.control != projection.control
            || stack.parameters != projection.parameters
            || irp.buffer != projection.buffer
            || irp.user_data != projection.user_data
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !irp.detached_file_owner
            || irp.client_id != owner.client
            || irp.file_id != owner.projection.file_id
            || irp.origin_driver_id != owner.origin_driver
            || irp.origin_device_id != owner.origin_device
            || irp.origin_major != owner.projection.major
            || irp.origin_minor != owner.projection.minor
            || irp.requestor_tid != owner.projection.requestor_tid
            || referenced_files(
                &irp.current_stack()
                    .ok_or(NtStatus::INVALID_PARAMETER)?
                    .parameters,
            ) != (owner.related, owner.target)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        for file in [owner.projection.file_id, owner.related, owner.target]
            .into_iter()
            .flatten()
        {
            if !self
                .file(file)
                .is_some_and(|file| file.outstanding_irp_refs != 0)
            {
                return Err(NtStatus::INVALID_HANDLE);
            }
        }
        Ok(())
    }

    fn validate_detached_route(&self, owner: &Owner) -> Result<(), NtStatus> {
        let irp = self
            .irp(owner.projection.irp_id)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let stack = irp.current_stack().ok_or(NtStatus::INVALID_PARAMETER)?;
        if stack.driver_id != owner.route.driver_id
            || stack.device_id != owner.route.device_id
            || self
                .driver(stack.driver_id)
                .and_then(|driver| driver.dispatch.get(stack.major).driver_peer_id())
                != Some(owner.route.peer)
            || (owner.route.peer.0 as usize) >= self.backends.len()
        {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        Ok(())
    }

    pub fn begin_prepared_external_file_irp(
        &mut self,
        prepared: PreparedExternalFileIrp,
    ) -> Result<ExternalFileIrpInvocation, ExternalFileIrpRejection<PreparedExternalFileIrp>> {
        let valid = (|| {
            self.validate_detached_owner(&prepared.0)?;
            self.validate_detached_route(&prepared.0)?;
            if self
                .driver(prepared.0.route.driver_id)
                .is_some_and(|driver| driver.flags.contains(crate::DriverFlags::FAULTED))
            {
                return Err(NtStatus::DEVICE_NOT_CONNECTED);
            }
            let record = self
                .irp(prepared.irp_id())
                .ok_or(NtStatus::INVALID_HANDLE)?;
            if record.state != IrpState::Initialized
                || IrpProjection::from_record(record)? != prepared.0.projection
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if crate::is_create_major(record.origin_major)
                && !record
                    .file_id
                    .and_then(|id| self.file(id))
                    .is_some_and(|file| {
                        file.state == FileState::Allocated
                            && file.related_file.is_none()
                            && !file.close_deferred
                    })
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: prepared,
            });
        }
        if crate::is_create_major(prepared.0.projection.major) {
            let file = self
                .file_mut(prepared.0.projection.file_id.unwrap())
                .unwrap();
            assert!(file.transition(FileState::CreateIrpDispatched));
        }
        assert!(self
            .irp_mut(prepared.irp_id())
            .unwrap()
            .transition(IrpState::Dispatched));
        Ok(ExternalFileIrpInvocation(prepared.0))
    }

    pub fn discard_prepared_external_file_irp(
        &mut self,
        prepared: PreparedExternalFileIrp,
    ) -> Result<ExternalFileIrpBuffers, ExternalFileIrpRejection<PreparedExternalFileIrp>> {
        let valid = (|| {
            self.validate_detached_owner(&prepared.0)?;
            if self.irp(prepared.irp_id()).unwrap().state != IrpState::Initialized {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if crate::is_create_major(prepared.0.projection.major) {
                let file = self
                    .file(prepared.0.projection.file_id.unwrap())
                    .ok_or(NtStatus::INVALID_HANDLE)?;
                if file.state != FileState::Allocated || file.related_file.is_some() {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: prepared,
            });
        }
        if crate::is_create_major(prepared.0.projection.major) {
            self.file_mut(prepared.0.projection.file_id.unwrap())
                .unwrap()
                .related_file = prepared.0.related;
        }
        self.irp_mut(prepared.irp_id()).unwrap().detached_file_owner = false;
        self.free_irp(prepared.irp_id())
            .expect("validated prepared retirement");
        if let Some(file) = prepared.0.projection.file_id {
            self.schedule_deferred_file_close(file);
        }
        Ok(prepared.0.buffers)
    }

    pub fn finish_external_file_irp(
        &mut self,
        returned: ExternalFileIrpReturn,
    ) -> Result<ExternalFileIrpResult, ExternalFileIrpRejection<ExternalFileIrpReturn>> {
        let valid = (|| {
            self.validate_detached_owner(&returned.owner)?;
            let record = self.irp(returned.owner.projection.irp_id).unwrap();
            if record.state == IrpState::Indeterminate {
                return Ok(());
            }
            if record.state == IrpState::Completed {
                if !self.completed_irps.contains(&record.id)
                    || record.completion_origin != Some(IrpCompletionOrigin::Driver)
                {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                return Ok(());
            }
            if record.state != IrpState::Dispatched {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.validate_detached_route(&returned.owner)?;
            if matches!(
                returned.outcome,
                ExternalFileIrpOutcome::Returned {
                    status: NtStatus::PENDING,
                    ..
                }
            ) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if matches!(
                returned.outcome,
                ExternalFileIrpOutcome::Returned {
                    file_context: Some(_),
                    ..
                }
            ) && !crate::is_create_major(record.origin_major)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if let ExternalFileIrpOutcome::NotEntered { .. } = returned.outcome {
                if crate::is_create_major(record.origin_major)
                    && !record
                        .file_id
                        .and_then(|id| self.file(id))
                        .is_some_and(|file| {
                            file.state == FileState::CreateIrpDispatched
                                && file.related_file.is_none()
                        })
                {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: returned,
            });
        }
        let ExternalFileIrpReturn { owner, outcome } = returned;
        let id = owner.projection.irp_id;
        if self.irp(id).unwrap().state == IrpState::Indeterminate {
            return Ok(ExternalFileIrpResult::Indeterminate {
                transport_status: self.irp(id).unwrap().status,
                retained: RetainedExternalFileIrp {
                    owner,
                    indeterminate: true,
                },
            });
        }
        if self.irp(id).unwrap().state == IrpState::Completed {
            return Ok(ExternalFileIrpResult::Pending(RetainedExternalFileIrp {
                owner,
                indeterminate: false,
            }));
        }
        Ok(match outcome {
            ExternalFileIrpOutcome::NotEntered { status } => {
                self.irp_mut(id).unwrap().state = IrpState::Initialized;
                if crate::is_create_major(owner.projection.major) {
                    self.file_mut(owner.projection.file_id.unwrap())
                        .unwrap()
                        .state = FileState::Allocated;
                }
                ExternalFileIrpResult::NotEntered {
                    status,
                    prepared: PreparedExternalFileIrp(owner),
                }
            }
            ExternalFileIrpOutcome::Pending => {
                let record = self.irp_mut(id).unwrap();
                record.status = NtStatus::PENDING;
                assert!(record.transition(IrpState::Pending));
                ExternalFileIrpResult::Pending(RetainedExternalFileIrp {
                    owner,
                    indeterminate: false,
                })
            }
            ExternalFileIrpOutcome::Indeterminate { transport_status } => {
                assert!(self
                    .irp_mut(id)
                    .unwrap()
                    .transition(IrpState::Indeterminate));
                ExternalFileIrpResult::Indeterminate {
                    transport_status,
                    retained: RetainedExternalFileIrp {
                        owner,
                        indeterminate: true,
                    },
                }
            }
            ExternalFileIrpOutcome::Returned {
                status,
                information,
                file_context,
            } => {
                let record = self.irp_mut(id).unwrap();
                record.status = status;
                record.information = information;
                record.completion_file_context = file_context;
                record.completion_origin = Some(IrpCompletionOrigin::Driver);
                assert!(record.transition(IrpState::Completing));
                assert!(record.transition(IrpState::Completed));
                if crate::is_create_major(owner.projection.major) {
                    let file = self.file_mut(owner.projection.file_id.unwrap()).unwrap();
                    if status.is_success() {
                        file.driver_context = file_context;
                        if file.state == FileState::CreateIrpDispatched {
                            assert!(file.transition(FileState::Open));
                        }
                    } else if file.state == FileState::CreateIrpDispatched {
                        assert!(file.transition(FileState::Closed));
                    }
                }
                let completion = self
                    .completed_irp_snapshot(id)
                    .expect("terminal detached snapshot");
                ExternalFileIrpResult::Returned(ExternalFileIrpTerminal { owner, completion })
            }
        })
    }

    pub fn retire_external_file_irp_terminal(
        &mut self,
        terminal: ExternalFileIrpTerminal,
    ) -> Result<
        (ExternalFileIrpTerminalReceipt, ExternalFileIrpBuffers),
        ExternalFileIrpRejection<ExternalFileIrpTerminal>,
    > {
        let valid = self.validate_detached_owner(&terminal.owner).and_then(|_| {
            if self.completed_irp_snapshot(terminal.completion.id).as_ref()
                != Some(&terminal.completion)
                || self.completed_irps.contains(&terminal.completion.id)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        });
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: terminal,
            });
        }
        let ExternalFileIrpTerminal { owner, completion } = terminal;
        self.irp_mut(completion.id).unwrap().detached_file_owner = false;
        self.free_irp(completion.id)
            .expect("validated synchronous detached retirement");
        if let Some(file) = completion.file_id {
            self.schedule_deferred_file_close(file);
        }
        Ok((
            ExternalFileIrpTerminalReceipt {
                manager: owner.manager,
                completion,
                backend_acknowledged: false,
            },
            owner.buffers,
        ))
    }

    pub fn prepare_external_file_irp_completion(
        &mut self,
        retained: RetainedExternalFileIrp,
    ) -> Result<
        ExternalFileIrpCompletionInvocation,
        ExternalFileIrpRejection<RetainedExternalFileIrp>,
    > {
        let result = self.validate_detached_owner(&retained.owner).and_then(|_| {
            let completed = self
                .completed_irp_snapshot(retained.irp_id())
                .ok_or(NtStatus::PENDING)?;
            if !self.completed_irps.contains(&completed.id)
                || completed.completion_origin != IrpCompletionOrigin::Driver
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(completed)
        });
        match result {
            Ok(completion) => Ok(ExternalFileIrpCompletionInvocation {
                owner: retained.owner,
                completion,
            }),
            Err(status) => Err(ExternalFileIrpRejection {
                status,
                owner: retained,
            }),
        }
    }

    pub fn finish_external_file_irp_completion(
        &mut self,
        returned: ExternalFileIrpCompletionReturn,
    ) -> Result<
        (ExternalFileIrpTerminalReceipt, ExternalFileIrpBuffers),
        ExternalFileIrpRejection<ExternalFileIrpCompletionReturn>,
    > {
        let invocation = &returned.invocation;
        let valid = self
            .validate_detached_owner(&invocation.owner)
            .and_then(|_| {
                if self
                    .completed_irp_snapshot(invocation.completion.id)
                    .as_ref()
                    != Some(&invocation.completion)
                    || !self.completed_irps.contains(&invocation.completion.id)
                {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                match returned.acknowledgement {
                    ExternalFileIrpAcknowledgement::Acknowledged => Ok(()),
                    ExternalFileIrpAcknowledgement::NotEntered { status }
                    | ExternalFileIrpAcknowledgement::Rejected { status } => Err(status),
                    ExternalFileIrpAcknowledgement::Indeterminate { transport_status } => {
                        Err(transport_status)
                    }
                }
            });
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: returned,
            });
        }
        let invocation = returned.invocation;
        let ExternalFileIrpCompletionInvocation { owner, completion } = invocation;
        let index = self
            .completed_irps
            .iter()
            .position(|id| *id == completion.id)
            .unwrap();
        self.completed_irps.remove(index);
        self.irp_mut(completion.id).unwrap().detached_file_owner = false;
        self.free_irp(completion.id)
            .expect("validated acknowledged detached retirement");
        if let Some(file) = completion.file_id {
            self.schedule_deferred_file_close(file);
        }
        Ok((
            ExternalFileIrpTerminalReceipt {
                manager: owner.manager,
                completion,
                backend_acknowledged: true,
            },
            owner.buffers,
        ))
    }

    pub fn accepts_external_file_irp_receipt(
        &self,
        receipt: &ExternalFileIrpTerminalReceipt,
    ) -> bool {
        receipt.manager != 0 && receipt.manager == self.ownership_identity()
    }
}

#[cfg(test)]
mod tests;
