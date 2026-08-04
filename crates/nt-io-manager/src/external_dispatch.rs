//! External synchronous dispatch adapters.
//!
//! These helpers let an integration host that already owns object/file lifetime
//! feed a real I/O Manager IRP through the canonical driver/device stores and
//! dispatch backend. They are deliberately narrower than `open`/`read`/`write`:
//! the caller supplies the target id, optional canonical file id, and any
//! transport-local file cookie in `user_data`.

use nt_status::NtStatus;
use nt_types::ClientId;

use crate::dispatch::{DispatchContext, DispatchOutcome, IrpProjection};
use crate::driver::DispatchTarget;
use crate::irp::{BufferAccess, IoBufferRef, IoParameters, IoStackLocation, IrpRecord, IrpState};
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

impl<P> IoManager<P> {
    /// Build one IRP for `device_id`, route it through the owning driver's
    /// dispatch table, complete it synchronously, and return the raw completion
    /// status plus `IoStatus.Information`.
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
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<(NtStatus, u64), NtStatus> {
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
            major,
            params,
            input_len,
            output_len,
            system_buffer,
        )
    }

    /// Build one IRP for a driver that does not expose a control device yet,
    /// route it through the driver's dispatch table, and complete it
    /// synchronously.
    pub fn build_and_dispatch_external_to_driver(
        &mut self,
        client: ClientId,
        driver_id: DriverId,
        file_id: Option<FileId>,
        user_data: u64,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<(NtStatus, u64), NtStatus> {
        self.build_and_dispatch_external(
            client,
            driver_id,
            DeviceId::NULL,
            file_id,
            user_data,
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
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
    ) -> Result<(NtStatus, u64), NtStatus> {
        if self.driver(driver_id).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let mut irp = IrpRecord::new(client, device_id, file_id, major);
        irp.user_data = user_data;
        let mut sl = IoStackLocation::new(major, device_id, file_id);
        sl.parameters = params;
        irp.stack.push(sl);
        irp.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: system_buffer.len() as u32,
            input_len: input_len.min(system_buffer.len() as u32),
            output_len: output_len.min(system_buffer.len() as u32),
            access: BufferAccess::ReadWrite,
        });
        let irp_id = self.allocate_irp(irp);
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Initialized);
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Dispatched);
        let outcome = self.dispatch_to_driver(driver_id, irp_id, system_buffer);
        Ok(self.complete_external_sync(irp_id, outcome))
    }

    pub(crate) fn dispatch_to_driver(
        &mut self,
        driver_id: DriverId,
        irp_id: IrpId,
        system_buffer: &mut [u8],
    ) -> Result<DispatchOutcome, NtStatus> {
        let (major_fn, client) = {
            let irp = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            (irp.major, irp.client_id)
        };
        let target = self
            .driver(driver_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .dispatch
            .get(major_fn);
        let idx = match target {
            DispatchTarget::Mock(id) => id.0 as usize,
            DispatchTarget::DriverPeer(id) => id.0 as usize,
            DispatchTarget::Unsupported => {
                return Ok(DispatchOutcome::Failed {
                    status: NtStatus::INVALID_DEVICE_REQUEST,
                });
            }
        };
        let proj = IrpProjection::from_record(self.irp(irp_id).expect("checked above"));
        let backend = self
            .backends
            .get_mut(idx)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        backend.dispatch_irp(
            DispatchContext::new(driver_id, client, system_buffer),
            &proj,
        )
    }

    fn complete_external_sync(
        &mut self,
        irp_id: IrpId,
        outcome: Result<DispatchOutcome, NtStatus>,
    ) -> (NtStatus, u64) {
        match outcome {
            Ok(DispatchOutcome::Completed {
                status,
                information,
            }) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.information = information;
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                }
                self.free_irp(irp_id);
                (status, information)
            }
            Ok(DispatchOutcome::Failed { status }) | Err(status) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = status;
                    irp.transition(IrpState::Failed);
                }
                self.free_irp(irp_id);
                (status, 0)
            }
            Ok(DispatchOutcome::Pending) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.status = NtStatus::PENDING;
                    irp.transition(IrpState::Pending);
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                }
                self.free_irp(irp_id);
                (NtStatus::PENDING, 0)
            }
        }
    }
}
