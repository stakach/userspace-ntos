//! External synchronous dispatch adapters.
//!
//! These helpers let an integration host that already owns object/file lifetime
//! feed a real I/O Manager IRP through the canonical driver/device stores and
//! dispatch backend. They are deliberately narrower than `open`/`read`/`write`:
//! the caller supplies the target id, optional canonical file id, and any
//! transport-local file cookie in `user_data`.

use alloc::vec::Vec;

use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, NtPath, ObjectId};

use crate::dispatch::{DispatchContext, DispatchOutcome, IrpProjection};
use crate::file::{CreateOptions, FileRecord, FileState, ShareAccess};
use crate::irp::{BufferAccess, IoBufferRef, IoParameters, IrpState, PnpParameters};
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

/// Result of dispatching an externally constructed IRP. A pending request stays
/// owned by the I/O Manager until its driver publishes a terminal completion and
/// the integration host acknowledges that completion.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExternalDispatchResult {
    Completed {
        status: NtStatus,
        information: u64,
        file_context: Option<u64>,
    },
    Pending {
        irp_id: IrpId,
    },
}

/// Exclusive ownership of one fully prepared, but not yet dispatched, canonical PnP IRP.
///
/// The payload is copied into this owner so acquiring external PnP lifecycle authority cannot be
/// followed by a buffer allocation or extent failure. The token is deliberately non-`Clone`.
pub struct PreparedExternalPnpIrp {
    irp_id: IrpId,
    payload: Vec<u8>,
}

impl PreparedExternalPnpIrp {
    pub fn irp_id(&self) -> IrpId {
        self.irp_id
    }
}

/// Exact outcome of entering a prepared canonical PnP request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExternalPnpDispatchResult {
    /// The outer device-stack call returned a terminal status.
    Returned { status: NtStatus, information: u64 },
    /// The outer device-stack call returned `STATUS_PENDING`; the canonical IRP remains owned by
    /// the I/O manager until a genuine terminal completion is acknowledged.
    Pending { irp_id: IrpId },
    /// Backend entry did not produce a trustworthy outer return. The canonical IRP is retained as
    /// a teardown barrier and must not be interpreted as a driver veto or completion.
    Indeterminate {
        irp_id: IrpId,
        transport_status: NtStatus,
    },
}

impl<P> IoManager<P> {
    /// Prepare one File-less PnP request against a canonical PDO and snapshot its complete attached
    /// stack. All allocation, payload copying, projection validation, and backend-route validation
    /// happens here, before an external lifecycle manager acquires dispatch authority.
    pub fn prepare_external_pnp_to_device(
        &mut self,
        client: ClientId,
        pdo_device_id: DeviceId,
        requestor_tid: u64,
        parameters: PnpParameters,
        payload: &[u8],
    ) -> Result<PreparedExternalPnpIrp, NtStatus> {
        let expected_len = parameters.input_len() as usize;
        if payload.len() != expected_len {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let origin = self
            .device(pdo_device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if origin.delete_pending {
            return Err(NtStatus::DELETE_PENDING);
        }
        let origin_driver_id = origin.driver_id;

        let mut owned_payload = Vec::new();
        owned_payload
            .try_reserve_exact(payload.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        owned_payload.extend_from_slice(payload);

        let mut irp = self.build_irp_record(
            client,
            origin_driver_id,
            pdo_device_id,
            None,
            nt_io_abi::major::IRP_MJ_PNP,
            IoParameters::Pnp(parameters),
        )?;
        irp.requestor_tid = requestor_tid;
        irp.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: expected_len as u32,
            input_len: expected_len as u32,
            output_len: 0,
            access: BufferAccess::ReadWrite,
        });
        let irp_id = self.allocate_irp(irp)?;
        let prepared = (|| {
            let record = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            IrpProjection::from_record(record)?;
            let current_driver_id = record
                .current_stack()
                .map(|stack| stack.driver_id)
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            let target = self
                .driver(current_driver_id)
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .dispatch
                .get(nt_io_abi::major::IRP_MJ_PNP);
            let backend_index = target
                .mock_id()
                .map(|id| id.0 as usize)
                .or_else(|| target.kernel_id().map(|id| id.0 as usize))
                .or_else(|| target.driver_peer_id().map(|id| id.0 as usize));
            let backend_index = backend_index.ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
            if backend_index >= self.backends.len() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        if let Err(status) = prepared {
            self.free_irp(irp_id);
            return Err(status);
        }
        if !self
            .irp_mut(irp_id)
            .expect("validated prepared PnP IRP disappeared")
            .transition(IrpState::Initialized)
        {
            self.free_irp(irp_id);
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(PreparedExternalPnpIrp {
            irp_id,
            payload: owned_payload,
        })
    }

    /// Discard an exact prepared PnP IRP when external lifecycle authority could not be acquired.
    pub fn discard_prepared_external_pnp(
        &mut self,
        prepared: PreparedExternalPnpIrp,
    ) -> Result<(), NtStatus> {
        let irp = self
            .irp_mut(prepared.irp_id)
            .filter(|irp| {
                irp.origin_major == nt_io_abi::major::IRP_MJ_PNP
                    && irp.state == IrpState::Initialized
            })
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !irp.transition(IrpState::Failed) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.free_irp(prepared.irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        Ok(())
    }

    /// Enter an exact prepared PnP IRP. This consumes the preparation token and performs no payload
    /// allocation. Any violated invariant or backend transport error retains the IRP as
    /// `Indeterminate`; only a genuine synchronous return reclaims it here.
    pub fn dispatch_prepared_external_pnp(
        &mut self,
        mut prepared: PreparedExternalPnpIrp,
    ) -> ExternalPnpDispatchResult {
        let irp_id = prepared.irp_id;
        let valid = self.irp(irp_id).is_some_and(|irp| {
            irp.origin_major == nt_io_abi::major::IRP_MJ_PNP
                && irp.state == IrpState::Initialized
                && irp.file_id.is_none()
                && irp.buffer.is_some_and(|buffer| {
                    buffer.input_len as usize == prepared.payload.len()
                        && buffer.output_len == 0
                        && buffer.len as usize == prepared.payload.len()
                })
        });
        if !valid
            || !self
                .irp_mut(irp_id)
                .is_some_and(|irp| irp.transition(IrpState::Dispatched))
        {
            self.mark_external_pnp_indeterminate(irp_id);
            return ExternalPnpDispatchResult::Indeterminate {
                irp_id,
                transport_status: NtStatus::INVALID_PARAMETER,
            };
        }
        let current_driver_id = match self
            .irp(irp_id)
            .and_then(|irp| irp.current_stack())
            .map(|stack| stack.driver_id)
        {
            Some(driver_id) => driver_id,
            None => {
                self.mark_external_pnp_indeterminate(irp_id);
                return ExternalPnpDispatchResult::Indeterminate {
                    irp_id,
                    transport_status: NtStatus::INVALID_PARAMETER,
                };
            }
        };
        let outcome = self.dispatch_to_driver(current_driver_id, irp_id, &mut prepared.payload);
        if let Err(transport_status) = outcome {
            self.mark_external_pnp_indeterminate(irp_id);
            return ExternalPnpDispatchResult::Indeterminate {
                irp_id,
                transport_status,
            };
        }
        if self
            .irp(irp_id)
            .map(|irp| irp.state != IrpState::Dispatched)
            .unwrap_or(true)
        {
            return ExternalPnpDispatchResult::Pending { irp_id };
        }
        match outcome.expect("transport error handled above") {
            DispatchOutcome::Completed {
                status,
                information,
                ..
            } => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.information = information;
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                }
                self.free_irp(irp_id);
                ExternalPnpDispatchResult::Returned {
                    status,
                    information,
                }
            }
            DispatchOutcome::Failed { status } => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.transition(IrpState::Failed);
                }
                self.free_irp(irp_id);
                ExternalPnpDispatchResult::Returned {
                    status,
                    information: 0,
                }
            }
            DispatchOutcome::Pending => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = NtStatus::PENDING;
                    irp.transition(IrpState::Pending);
                }
                ExternalPnpDispatchResult::Pending { irp_id }
            }
        }
    }

    fn mark_external_pnp_indeterminate(&mut self, irp_id: IrpId) {
        if let Some(irp) = self.irp_mut(irp_id) {
            if irp.state == IrpState::Initialized {
                irp.transition(IrpState::Dispatched);
            }
            if irp.state == IrpState::Dispatched {
                irp.transition(IrpState::Indeterminate);
            }
        }
    }

    /// Allocate a canonical File owned by an integration host whose process
    /// handles live outside the I/O Manager's Object Manager port. The record
    /// exists before CREATE and its `FileId` is the only cross-domain identity.
    pub fn allocate_external_file(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        desired_access: AccessMask,
        share_access: ShareAccess,
        create_options: CreateOptions,
        file_name: Option<NtPath>,
    ) -> Result<FileId, NtStatus> {
        if self.device(device_id).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(self.add_file(FileRecord::new(
            ObjectId::NULL,
            client,
            device_id,
            desired_access,
            share_access,
            create_options,
            file_name,
        )))
    }

    /// Return the mutable driver-owned context attached to a live canonical
    /// File. A null context is valid and remains distinct from File identity.
    pub fn external_file_context(
        &self,
        client: ClientId,
        file_id: FileId,
    ) -> Result<Option<u64>, NtStatus> {
        let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if file.client_id != client || !file.state.is_open() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(file.driver_context)
    }

    /// Build one IRP for `device_id`, route it through the owning driver's
    /// dispatch table, and return either its synchronous result or the canonical
    /// id retained for asynchronous completion.
    ///
    /// This path is for hosts that have not yet moved open/handle lifetime into
    /// this crate but still need canonical driver/device/IRP dispatch. Warning
    /// and error statuses are returned as driver completions rather than being
    /// normalized into host errors.
    pub fn build_and_dispatch_external_to_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        user_data: u64,
        requestor_tid: u64,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        self.build_and_dispatch_external(
            client,
            driver_id,
            device_id,
            file_id,
            user_data,
            requestor_tid,
            major,
            params,
            input_len,
            output_len,
            system_buffer,
        )
    }

    /// Build one IRP for a driver that does not expose a control device yet,
    /// route it through the driver's dispatch table, and complete it
    /// synchronously or retain it under a canonical IRP id.
    pub fn build_and_dispatch_external_to_driver(
        &mut self,
        client: ClientId,
        driver_id: DriverId,
        file_id: Option<FileId>,
        user_data: u64,
        requestor_tid: u64,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.build_and_dispatch_external(
            client,
            driver_id,
            DeviceId::NULL,
            file_id,
            user_data,
            requestor_tid,
            major,
            params,
            input_len,
            output_len,
            system_buffer,
        )
    }

    fn build_and_dispatch_external(
        &mut self,
        client: ClientId,
        driver_id: DriverId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        user_data: u64,
        requestor_tid: u64,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        match &params {
            IoParameters::Pnp(parameters) => {
                let expected_input = parameters.input_len();
                if major != nt_io_abi::major::IRP_MJ_PNP
                    || input_len != expected_input
                    || output_len != 0
                    || system_buffer.len() != expected_input as usize
                {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
            }
            _ if major == nt_io_abi::major::IRP_MJ_PNP => {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            _ => {}
        }
        if self.driver(driver_id).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let user_data = if let Some(file_id) = file_id {
            let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
            if device_id == DeviceId::NULL {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if file.client_id != client
                || (device_id != DeviceId::NULL && file.device_id != device_id)
            {
                return Err(NtStatus::INVALID_HANDLE);
            }
            if crate::is_create_major(major) {
                0
            } else {
                file.driver_context.unwrap_or(0)
            }
        } else {
            user_data
        };
        let mut irp =
            self.build_irp_record(client, driver_id, device_id, file_id, major, params)?;
        irp.user_data = user_data;
        irp.requestor_tid = requestor_tid;
        irp.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: system_buffer.len() as u32,
            input_len: input_len.min(system_buffer.len() as u32),
            output_len: output_len.min(system_buffer.len() as u32),
            access: BufferAccess::ReadWrite,
        });
        let irp_id = self.allocate_irp(irp)?;
        if crate::is_create_major(major) {
            if let Some(file_id) = file_id {
                self.file_mut(file_id)
                    .expect("CREATE File disappeared after IRP allocation")
                    .transition(FileState::CreateIrpDispatched);
            }
        }
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Initialized);
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Dispatched);
        let current_driver_id = self
            .irp(irp_id)
            .and_then(|irp| irp.current_stack())
            .map(|stack| stack.driver_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let outcome = self.dispatch_to_driver(current_driver_id, irp_id, system_buffer);
        Ok(self.complete_external_dispatch(irp_id, outcome))
    }

    pub(crate) fn dispatch_to_driver(
        &mut self,
        driver_id: DriverId,
        irp_id: IrpId,
        system_buffer: &mut [u8],
    ) -> Result<DispatchOutcome, NtStatus> {
        self.dispatch_to_driver_with_transfer_buffers(
            driver_id,
            irp_id,
            system_buffer,
            None,
            None,
            None,
        )
    }

    pub(crate) fn dispatch_to_driver_with_transfer_buffers(
        &mut self,
        driver_id: DriverId,
        irp_id: IrpId,
        system_buffer: &mut [u8],
        direct_buffer: Option<&mut [u8]>,
        type3_input_buffer: Option<&mut [u8]>,
        user_buffer: Option<&mut [u8]>,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (major_fn, client, current_driver_id) = {
            let irp = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            let stack = irp.current_stack().ok_or(NtStatus::INVALID_PARAMETER)?;
            (stack.major, irp.client_id, stack.driver_id)
        };
        if driver_id != current_driver_id {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let target = self
            .driver(driver_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .dispatch
            .get(major_fn);
        let idx = if let Some(id) = target.mock_id() {
            id.0 as usize
        } else if let Some(id) = target.kernel_id() {
            id.0 as usize
        } else if let Some(id) = target.driver_peer_id() {
            id.0 as usize
        } else {
            return Ok(DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST,
            });
        };
        let proj = IrpProjection::from_record(self.irp(irp_id).expect("checked above"))?;
        let backend = self
            .backends
            .get_mut(idx)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        backend.dispatch_irp(
            DispatchContext::with_transfer_buffers(
                driver_id,
                client,
                system_buffer,
                direct_buffer,
                type3_input_buffer,
                user_buffer,
            ),
            &proj,
        )
    }

    fn complete_external_dispatch(
        &mut self,
        irp_id: IrpId,
        outcome: Result<DispatchOutcome, NtStatus>,
    ) -> ExternalDispatchResult {
        let (major, file_id) = self
            .irp(irp_id)
            .map(|irp| (irp.origin_major, irp.file_id))
            .unwrap_or((u8::MAX, None));
        if self
            .irp(irp_id)
            .map(|irp| irp.state != IrpState::Dispatched)
            .unwrap_or(true)
        {
            return ExternalDispatchResult::Pending { irp_id };
        }
        match outcome {
            Ok(DispatchOutcome::Completed {
                status,
                information,
                file_context,
            }) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.information = information;
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                }
                self.free_irp(irp_id);
                if crate::is_create_major(major) {
                    if let Some(file_id) = file_id {
                        if status.is_success() {
                            let file = self.file_mut(file_id).expect("CREATE File disappeared");
                            file.driver_context = file_context;
                            file.transition(FileState::Open);
                        } else if let Some(file) = self.file_mut(file_id) {
                            file.transition(FileState::Closed);
                        }
                    }
                }
                ExternalDispatchResult::Completed {
                    status,
                    information,
                    file_context,
                }
            }
            Ok(DispatchOutcome::Failed { status }) | Err(status) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.transition(IrpState::Failed);
                }
                self.free_irp(irp_id);
                if crate::is_create_major(major) {
                    if let Some(file_id) = file_id {
                        if let Some(file) = self.file_mut(file_id) {
                            file.transition(FileState::Closed);
                        }
                    }
                }
                ExternalDispatchResult::Completed {
                    status,
                    information: 0,
                    file_context: None,
                }
            }
            Ok(DispatchOutcome::Pending) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    if irp.state == IrpState::Dispatched {
                        irp.status = NtStatus::PENDING;
                        irp.transition(IrpState::Pending);
                    }
                }
                ExternalDispatchResult::Pending { irp_id }
            }
        }
    }
}
