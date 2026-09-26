//! Driver-peer dispatch backend (spec §15.3, §16).
//!
//! A [`DriverPeerBackend`] is a [`DriverDispatchBackend`] that marshals IRP
//! projections to an isolated, **untrusted** driver peer (a future Driver Host)
//! over a [`DriverPeerTransport`] — a SURT ring pair on the kernel, or a
//! [`MockDriverPeer`] in tests. The peer completes synchronously (a dispatch
//! response), accepts a request as pending (a later reverse-ring completion), or
//! faults. A faulted peer's requests fail with `STATUS_DEVICE_NOT_CONNECTED`; the
//! I/O Manager's `pump` then fails its in-flight IRPs (see `fault.rs`).

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use nt_io_abi::{
    ioctl, major, valid_create_case_sensitive, valid_directory_notify_parameters,
    valid_ea_parameters, valid_initial_information, valid_lock_control_parameters,
    valid_quota_parameters, valid_read_write_parameters, valid_set_information_control,
    valid_volume_information_parameters, IrpDispatchRequest, IO_ABI_VERSION,
};
use nt_status::NtStatus;

use crate::dispatch::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpProjection,
};
use crate::{FileId, HostedDomainIdentity, HostedProviderIdentity, IrpId};

/// The transport to a driver peer: dispatch/cancel, poll reverse-ring
/// completions, report faults (spec §16.1–16.2).
pub trait DriverPeerTransport {
    /// Send `IODRV_OP_DISPATCH_IRP` with `request` + transfer buffers, returning
    /// the peer's immediate dispatch response.
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome;
    /// Send `IODRV_OP_CANCEL_IRP` for `irp_id`.
    fn cancel(&mut self, irp_id: IrpId);
    /// Poll the reverse ring for a peer's final `IODRV_OP_COMPLETE_IRP`.
    fn poll_completion(&mut self) -> Option<DriverCompletion>;
    /// Whether the peer has faulted / disconnected.
    fn is_faulted(&self) -> bool;
}

/// Transfer buffers passed to a driver peer. `system` is the
/// `AssociatedIrp.SystemBuffer` staging area; the optional buffers model direct
/// I/O and neither I/O without collapsing them into `system`.
pub struct PeerTransferBuffers<'a> {
    pub system: &'a mut [u8],
    pub direct: Option<&'a mut [u8]>,
    pub type3_input: Option<&'a mut [u8]>,
    pub user: Option<&'a mut [u8]>,
}

impl<'a> PeerTransferBuffers<'a> {
    pub fn new(system: &'a mut [u8]) -> Self {
        Self {
            system,
            direct: None,
            type3_input: None,
            user: None,
        }
    }
}

fn segment(cursor: &mut u32, len: usize) -> Result<(u32, u32), NtStatus> {
    let len = u32::try_from(len).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    if len == 0 {
        return Ok((0, 0));
    }
    let offset = *cursor;
    *cursor = cursor.checked_add(len).ok_or(NtStatus::INVALID_PARAMETER)?;
    Ok((offset, len))
}

/// Build the wire dispatch request for a projection (spec §16.4).
fn build_dispatch_request(
    irp: &IrpProjection,
    ctx: &DispatchContext<'_>,
    target: HostedDomainIdentity,
    provider: Option<HostedProviderIdentity>,
) -> Result<IrpDispatchRequest, NtStatus> {
    // A hosted WDM query needs a driver-domain UNICODE_STRING/FileName allocation. The kernel
    // backend owns the captured pattern directly; do not drop it from a peer wire request.
    if matches!(&irp.parameters, crate::irp::IoParameters::QueryDirectory(_)) {
        return Err(NtStatus::NOT_SUPPORTED);
    }
    let mut cursor = u32::try_from(core::mem::size_of::<IrpDispatchRequest>())
        .map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let (buffer_offset, buffer_len) = segment(&mut cursor, ctx.system_buffer.len())?;
    let (direct_buffer_offset, direct_buffer_len) = segment(
        &mut cursor,
        ctx.direct_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
    )?;
    let (type3_input_offset, type3_input_len) = segment(
        &mut cursor,
        ctx.type3_input_buffer
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(0),
    )?;
    let (user_buffer_offset, user_buffer_len) = segment(
        &mut cursor,
        ctx.user_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
    )?;
    let (
        ioctl_code,
        input_len,
        output_len,
        create_desired_access,
        create_share_access,
        create_disposition,
        create_options,
        create_file_attributes,
        create_ea_length,
        quota_sid_list_length,
        quota_start_sid_length,
        parameter_offset,
        parameter_len,
    ) = match &irp.parameters {
        crate::irp::IoParameters::DeviceControl(p)
        | crate::irp::IoParameters::InternalDeviceControl(p) => (
            p.ioctl_code,
            p.input_len,
            p.output_len,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        crate::irp::IoParameters::Create(p) => (
            0,
            u32::try_from(ctx.system_buffer.len()).map_err(|_| NtStatus::INVALID_PARAMETER)?,
            0,
            p.desired_access.bits(),
            p.share_access.bits(),
            p.create_disposition,
            p.create_options.bits(),
            p.file_attributes,
            p.ea_length,
            0,
            0,
            0,
            0,
        ),
        crate::irp::IoParameters::Read(p) => (0, 0, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        crate::irp::IoParameters::Write(p) => (0, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        crate::irp::IoParameters::QueryInformation(p) => {
            (p.info_class, 0, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        }
        crate::irp::IoParameters::SetInformation(p) => {
            (p.info_class, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        }
        crate::irp::IoParameters::QueryEa(p) => {
            (0, p.ea_list_length, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        }
        crate::irp::IoParameters::SetEa(p) => (0, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        crate::irp::IoParameters::QueryQuota(p) => {
            let input_len = p.input_length().ok_or(NtStatus::INVALID_PARAMETER)?;
            (
                0,
                input_len,
                p.length,
                0,
                0,
                0,
                0,
                0,
                0,
                p.sid_list_length,
                p.start_sid_length,
                0,
                0,
            )
        }
        crate::irp::IoParameters::SetQuota(p) => (0, p.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        crate::irp::IoParameters::QueryVolumeInformation(p) => (
            p.information_class,
            0,
            p.length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        crate::irp::IoParameters::SetVolumeInformation(p) => (
            p.information_class,
            p.length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        crate::irp::IoParameters::NotifyDirectory(p) => (
            p.completion_filter,
            0,
            p.length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        crate::irp::IoParameters::Pnp(p) => match p.start_parameters() {
            Some(start) => (
                p.wire_argument().unwrap_or(0),
                p.input_len(),
                p.output_len(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                start.raw_resource_list_len,
                start.translated_resource_list_len,
            ),
            None => (
                p.wire_argument().unwrap_or(0),
                p.input_len(),
                p.output_len(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
        },
        _ => (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    };
    let set_information_control = match &irp.parameters {
        crate::irp::IoParameters::SetInformation(parameters) => {
            if !parameters.control.valid_for_class(parameters.info_class) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            parameters.control.wire_value()
        }
        _ => 0,
    };
    let (ea_list_length, ea_index) = match &irp.parameters {
        crate::irp::IoParameters::QueryEa(parameters) => {
            (parameters.ea_list_length, parameters.ea_index)
        }
        _ => (0, 0),
    };
    let (lock_byte_offset, lock_length, lock_key) = match &irp.parameters {
        crate::irp::IoParameters::LockControl(parameters) => {
            (parameters.byte_offset, parameters.length, parameters.key)
        }
        _ => (0, 0, 0),
    };
    let (read_write_byte_offset, read_write_key) = match &irp.parameters {
        crate::irp::IoParameters::Read(parameters)
        | crate::irp::IoParameters::Write(parameters) => (parameters.offset, parameters.key),
        _ => (0, 0),
    };
    if matches!(&irp.parameters, crate::irp::IoParameters::LockControl(parameters) if parameters.minor != irp.minor)
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let initial_information = if irp.major == major::IRP_MJ_PNP {
        // PnP information can be a peer-local pointer.
        0
    } else {
        irp.information
    };
    if !valid_initial_information(irp.major, initial_information, input_len, output_len) {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let create_case_sensitive = u32::from(irp.create_case_sensitive);
    if !valid_create_case_sensitive(irp.major, create_case_sensitive) {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if !nt_io_abi::valid_file_create_options(irp.major, irp.file_create_options) {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(IrpDispatchRequest {
        abi_version: IO_ABI_VERSION as u16,
        abi_size: core::mem::size_of::<IrpDispatchRequest>() as u16,
        major: irp.major,
        minor: irp.minor,
        _reserved0: 0,
        flags: irp.flags.bits() as u32 | ((irp.control.bits() as u32) << 8),
        set_information_control,
        target_domain_id: target.domain_id.raw(),
        target_domain_cookie: target.cookie,
        provider_domain_id: provider
            .map(|identity| identity.domain_id.raw())
            .unwrap_or(0),
        provider_cookie: provider.map(|identity| identity.cookie).unwrap_or(0),
        irp_id: irp.irp_id.0,
        driver_id: irp.driver_id.0,
        device_id: irp.device_id.0,
        file_id: irp.file_id.map(|f| f.0).unwrap_or(0),
        related_file_id: match &irp.parameters {
            crate::irp::IoParameters::Create(parameters) => {
                parameters.related_file.map(FileId::raw).unwrap_or(0)
            }
            _ => 0,
        },
        target_file_id: match &irp.parameters {
            crate::irp::IoParameters::SetInformation(parameters) => {
                parameters.target_file.map(FileId::raw).unwrap_or(0)
            }
            _ => 0,
        },
        buffer_id: irp.buffer.map(|b| b.buffer_id).unwrap_or(0),
        buffer_offset: buffer_offset as u64,
        buffer_len,
        direct_buffer_offset,
        direct_buffer_len,
        type3_input_offset,
        type3_input_len,
        user_buffer_offset,
        user_buffer_len,
        input_len,
        output_len,
        ioctl_code,
        create_desired_access,
        create_share_access,
        create_disposition,
        create_options,
        create_file_attributes,
        create_ea_length,
        quota_sid_list_length,
        quota_start_sid_length,
        ea_list_length,
        ea_index,
        parameter_offset,
        parameter_len,
        stack_location: irp.stack_location as u32,
        stack_count: irp.stack_count as u32,
        lock_byte_offset,
        lock_length,
        lock_key,
        file_create_options: irp.file_create_options,
        read_write_byte_offset,
        read_write_key,
        create_case_sensitive,
        initial_information,
    })
}

/// A `DriverDispatchBackend` that dispatches to an isolated driver peer over `T`.
pub struct DriverPeerBackend<T> {
    transport: T,
    target: HostedDomainIdentity,
    provider: Option<HostedProviderIdentity>,
}

impl<T: DriverPeerTransport> DriverPeerBackend<T> {
    pub fn new(
        transport: T,
        target: HostedDomainIdentity,
        provider: Option<HostedProviderIdentity>,
    ) -> Result<Self, NtStatus> {
        if target.domain_id.is_null() || target.cookie == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if provider.is_some_and(|identity| identity.domain_id.is_null() || identity.cookie == 0) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            transport,
            target,
            provider,
        })
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: DriverPeerTransport> DriverDispatchBackend for DriverPeerBackend<T> {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        if self.transport.is_faulted() {
            return Ok(DispatchOutcome::Failed {
                status: NtStatus::DEVICE_NOT_CONNECTED,
            });
        }
        let request = build_dispatch_request(irp, &ctx, self.target, self.provider)?;
        Ok(self.transport.dispatch(
            &request,
            PeerTransferBuffers {
                system: ctx.system_buffer,
                direct: ctx.direct_buffer,
                type3_input: ctx.type3_input_buffer,
                user: ctx.user_buffer,
            },
        ))
    }

    fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
        self.transport.cancel(irp_id);
        Ok(())
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.transport.poll_completion()
    }

    fn is_faulted(&self) -> bool {
        self.transport.is_faulted()
    }
}

// ---------------------------------------------------------------------------
// Mock driver peer — an in-memory simulated peer for tests. The state is shared
// (Rc<RefCell>) so a test can control a peer that has already been boxed into the
// I/O Manager's backend registry.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PeerState {
    create_status: NtStatus,
    read_data: Vec<u8>,
    force_pending: bool,
    pending_completion: Option<(NtStatus, u64)>,
    faulted: bool,
    written: Vec<u8>,
    ready: Vec<DriverCompletion>,
    last_request: Option<IrpDispatchRequest>,
}

/// A shared handle to a mock peer's configuration + observed state.
#[derive(Clone, Default)]
pub struct MockPeerControl {
    state: Rc<RefCell<PeerState>>,
}

impl MockPeerControl {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(PeerState {
                create_status: NtStatus::SUCCESS,
                ..Default::default()
            })),
        }
    }

    /// The transport handle to hand to a [`DriverPeerBackend`].
    pub fn transport(&self) -> MockDriverPeer {
        MockDriverPeer {
            state: self.state.clone(),
        }
    }

    pub fn set_read_data(&self, data: &[u8]) {
        self.state.borrow_mut().read_data = data.to_vec();
    }
    pub fn set_create_status(&self, status: NtStatus) {
        self.state.borrow_mut().create_status = status;
    }
    pub fn set_force_pending(&self, pending: bool) {
        self.state.borrow_mut().force_pending = pending;
    }
    pub fn set_pending_completion(&self, status: NtStatus, information: u64) {
        self.state.borrow_mut().pending_completion = Some((status, information));
    }
    /// Simulate the peer faulting / disconnecting.
    pub fn set_faulted(&self, faulted: bool) {
        self.state.borrow_mut().faulted = faulted;
    }
    pub fn written(&self) -> Vec<u8> {
        self.state.borrow().written.clone()
    }
    pub fn last_request(&self) -> Option<IrpDispatchRequest> {
        self.state.borrow().last_request
    }
}

/// A mock driver-peer transport, obtained from [`MockPeerControl::transport`].
pub struct MockDriverPeer {
    state: Rc<RefCell<PeerState>>,
}

impl DriverPeerTransport for MockDriverPeer {
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        mut buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome {
        let mut s = self.state.borrow_mut();
        s.last_request = Some(*request);
        if s.faulted {
            return DispatchOutcome::Failed {
                status: NtStatus::DEVICE_NOT_CONNECTED,
            };
        }
        if request.abi_version != IO_ABI_VERSION as u16
            || request.abi_size as usize != core::mem::size_of::<IrpDispatchRequest>()
            || !request.has_well_formed_domain_route()
            || !valid_initial_information(
                request.major,
                request.initial_information,
                request.input_len,
                request.output_len,
            )
            || (request.major == major::IRP_MJ_QUERY_INFORMATION
                && (request.output_len > request.buffer_len
                    || request.buffer_len as usize > buffers.system.len()))
            || !valid_set_information_control(
                request.major,
                request.ioctl_code,
                request.set_information_control,
            )
            || !valid_create_case_sensitive(
                request.major,
                request.create_case_sensitive,
            )
            || !nt_io_abi::valid_file_create_options(request.major, request.file_create_options)
            || !valid_quota_parameters(
                request.major,
                request.quota_sid_list_length,
                request.quota_start_sid_length,
                request.input_len,
            )
            || !valid_ea_parameters(
                request.major,
                request.ea_list_length,
                request.ea_index,
                request.input_len,
            )
            || !valid_volume_information_parameters(
                request.major,
                request.ioctl_code,
                request.input_len,
                request.output_len,
            )
            || !valid_directory_notify_parameters(
                request.major,
                request.minor,
                request.flags as u8,
                request.ioctl_code,
                request.input_len,
            )
            || !valid_lock_control_parameters(
                request.major,
                request.minor,
                request.flags as u8,
                request.lock_byte_offset,
                request.lock_length,
                request.lock_key,
            )
            || !valid_read_write_parameters(
                request.major,
                request.read_write_byte_offset,
                request.read_write_key,
            )
            || (request.major != major::IRP_MJ_SET_INFORMATION
                && (request.target_file_id != 0 || request.set_information_control != 0))
            || (request.target_file_id != 0 && !matches!(request.ioctl_code, 10 | 11 | 31))
        {
            return DispatchOutcome::Failed {
                status: NtStatus::INVALID_PARAMETER,
            };
        }
        let is_data = matches!(
            request.major,
            major::IRP_MJ_READ
                | major::IRP_MJ_WRITE
                | major::IRP_MJ_QUERY_INFORMATION
                | major::IRP_MJ_QUERY_EA
                | major::IRP_MJ_SET_EA
                | major::IRP_MJ_QUERY_QUOTA
                | major::IRP_MJ_SET_QUOTA
                | major::IRP_MJ_QUERY_VOLUME_INFORMATION
                | major::IRP_MJ_SET_VOLUME_INFORMATION
                | major::IRP_MJ_LOCK_CONTROL
                | major::IRP_MJ_DEVICE_CONTROL
                | major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        );
        if s.force_pending && is_data {
            if let Some((status, information)) = s.pending_completion {
                s.ready.push(DriverCompletion {
                    irp_id: IrpId(request.irp_id),
                    status,
                    information,
                    file_context: None,
                });
            }
            return DispatchOutcome::Pending;
        }
        match request.major {
            major::IRP_MJ_CREATE => DispatchOutcome::from_status(s.create_status, 0),
            major::IRP_MJ_READ => {
                let buffer = &mut buffers.system;
                let n = s.read_data.len().min(buffer.len());
                buffer[..n].copy_from_slice(&s.read_data[..n]);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_WRITE => {
                let n = (request.buffer_len as usize).min(buffers.system.len());
                s.written = buffers.system[..n].to_vec();
                s.read_data = s.written.clone(); // loopback
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                let method = ioctl::method(request.ioctl_code);
                let mut input_copy = Vec::new();
                match method {
                    ioctl::METHOD_NEITHER => {
                        let input = buffers.type3_input.as_deref().unwrap_or(&[]);
                        let input_len = (request.input_len as usize).min(input.len());
                        input_copy.extend_from_slice(&input[..input_len]);
                    }
                    _ => {
                        let input_len = (request.input_len as usize).min(buffers.system.len());
                        input_copy.extend_from_slice(&buffers.system[..input_len]);
                    }
                };
                let output = match method {
                    ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                        buffers.direct.as_deref_mut().unwrap_or(&mut [])
                    }
                    ioctl::METHOD_NEITHER => buffers.user.as_deref_mut().unwrap_or(&mut []),
                    _ => buffers.system,
                };
                let n = input_copy
                    .len()
                    .min(request.output_len as usize)
                    .min(output.len());
                output[..n].copy_from_slice(&input_copy[..n]);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE | major::IRP_MJ_FLUSH_BUFFERS => {
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                }
            }
            major::IRP_MJ_QUERY_INFORMATION => DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: request.initial_information,
                file_context: None,
            },
            major::IRP_MJ_SET_INFORMATION
            | major::IRP_MJ_QUERY_EA
            | major::IRP_MJ_SET_EA
            | major::IRP_MJ_QUERY_QUOTA
            | major::IRP_MJ_SET_QUOTA
            | major::IRP_MJ_QUERY_VOLUME_INFORMATION
            | major::IRP_MJ_SET_VOLUME_INFORMATION
            | major::IRP_MJ_LOCK_CONTROL => DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            },
            _ => DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST,
            },
        }
    }

    fn cancel(&mut self, irp_id: IrpId) {
        let mut state = self.state.borrow_mut();
        if !state
            .ready
            .iter()
            .any(|completion| completion.irp_id == irp_id)
        {
            state.ready.push(DriverCompletion {
                irp_id,
                status: NtStatus::CANCELLED,
                information: 0,
                file_context: None,
            });
        }
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.state.borrow_mut().ready.pop()
    }

    fn is_faulted(&self) -> bool {
        self.state.borrow().faulted
    }
}

#[cfg(test)]
mod initial_information_tests {
    use super::*;
    use crate::{
        DeviceId, DriverId, HostedDomainId, InformationParameters, IoParameters, PnpParameters,
        StackControl, StackFlags,
    };
    use nt_types::ClientId;

    fn projection() -> IrpProjection {
        IrpProjection {
            create_case_sensitive: false,
            file_name: None,
            file_create_options: 0,
            irp_id: IrpId::new(1, 1),
            driver_id: DriverId::new(1, 2),
            device_id: DeviceId::new(1, 3),
            file_id: Some(FileId::new(1, 4)),
            stack_location: 0,
            stack_count: 1,
            major: major::IRP_MJ_QUERY_INFORMATION,
            minor: 0,
            flags: StackFlags::empty(),
            control: StackControl::empty(),
            status: NtStatus::SUCCESS,
            information: 88,
            parameters: IoParameters::QueryInformation(InformationParameters {
                info_class: 18,
                length: 104,
            }),
            buffer: None,
            user_data: 0,
            requestor_tid: 20,
        }
    }

    fn target() -> HostedDomainIdentity {
        HostedDomainIdentity {
            domain_id: HostedDomainId::new(1, 5),
            cookie: 6,
        }
    }

    fn request() -> IrpDispatchRequest {
        let irp = projection();
        let mut bytes = [0; 104];
        let context = DispatchContext::new(irp.driver_id, ClientId(1), &mut bytes);
        build_dispatch_request(&irp, &context, target(), None).unwrap()
    }

    #[test]
    fn hosted_peer_refuses_directory_query_until_pattern_has_a_wire_representation() {
        let mut irp = projection();
        irp.major = major::IRP_MJ_DIRECTORY_CONTROL;
        irp.minor = crate::IRP_MN_QUERY_DIRECTORY;
        irp.parameters = IoParameters::QueryDirectory(crate::DirectoryQueryParameters {
            length: 104,
            information_class: nt_fs::FILE_BOTH_DIRECTORY_INFORMATION,
            file_index: 7,
            pattern: Some(nt_types::UnicodeString::from_str("*.dll")),
        });
        let mut output = [0; 104];
        let context = DispatchContext::new(irp.driver_id, ClientId(1), &mut output);
        assert_eq!(
            build_dispatch_request(&irp, &context, target(), None),
            Err(NtStatus::NOT_SUPPORTED)
        );
    }

    #[test]
    fn initial_information_projection_and_peer_keep_scalar_and_output_seed() {
        let request = request();
        assert_eq!(request.initial_information, 88);
        assert_eq!(request.input_len, 0);
        assert_eq!(request.output_len, 104);
        assert_eq!(request.buffer_offset, 256);
        let mut output = [0x5a; 104];
        let before = output;
        let control = MockPeerControl::new();
        let mut peer = control.transport();
        assert_eq!(
            peer.dispatch(&request, PeerTransferBuffers::new(&mut output)),
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 88,
                file_context: None,
            }
        );
        assert_eq!(output, before);
        assert_eq!(control.last_request(), Some(request));
    }

    #[test]
    fn initial_information_projection_refuses_oversized_query_and_never_exports_pnp_pointer() {
        let mut irp = projection();
        let mut output = [0; 104];
        let context = DispatchContext::new(irp.driver_id, ClientId(1), &mut output);
        irp.information = 105;
        assert_eq!(
            build_dispatch_request(&irp, &context, target(), None),
            Err(NtStatus::INVALID_PARAMETER)
        );
        irp.major = major::IRP_MJ_READ;
        irp.parameters = IoParameters::Read(crate::ReadWriteParameters {
            length: 104,
            key: 0,
            offset: 0,
        });
        irp.information = 1;
        assert_eq!(
            build_dispatch_request(&irp, &context, target(), None),
            Err(NtStatus::INVALID_PARAMETER)
        );
        irp.major = major::IRP_MJ_PNP;
        let parameters = PnpParameters::query_device_relations(0);
        irp.minor = parameters.minor;
        irp.parameters = IoParameters::Pnp(parameters);
        irp.information = 0xffff_9000_1234_5678;
        let wire = build_dispatch_request(&irp, &context, target(), None).unwrap();
        assert_eq!(wire.initial_information, 0);
    }

    #[test]
    fn initial_information_peer_rejects_old_abi_and_malformed_scalar_before_touching_output() {
        let valid = request();
        let invalid = [
            IrpDispatchRequest {
                abi_version: 13,
                ..valid
            },
            IrpDispatchRequest {
                abi_version: 12,
                ..valid
            },
            IrpDispatchRequest {
                abi_size: 248,
                ..valid
            },
            IrpDispatchRequest {
                initial_information: 105,
                ..valid
            },
            IrpDispatchRequest {
                initial_information: u64::MAX,
                ..valid
            },
            IrpDispatchRequest {
                input_len: 1,
                ..valid
            },
            IrpDispatchRequest {
                buffer_len: 103,
                ..valid
            },
            IrpDispatchRequest {
                buffer_len: 105,
                ..valid
            },
            IrpDispatchRequest {
                major: major::IRP_MJ_READ,
                ..valid
            },
            IrpDispatchRequest {
                major: major::IRP_MJ_PNP,
                ..valid
            },
        ];
        let mut peer = MockPeerControl::new().transport();
        for request in invalid {
            let mut output = [0x5a; 104];
            assert_eq!(
                peer.dispatch(&request, PeerTransferBuffers::new(&mut output)),
                DispatchOutcome::Failed {
                    status: NtStatus::INVALID_PARAMETER,
                }
            );
            assert_eq!(output, [0x5a; 104]);
        }
    }

    #[test]
    fn canonical_create_provenance_roundtrips_to_wire_and_wdm_for_each_major() {
        use crate::detached_file_irp::{ExternalFileIrpBuffers, ExternalFileIrpRequest};
        use crate::{
            write_wdm_file_object, CreateOptions, CreateParameters, DeviceCharacteristics,
            DeviceFlags, DeviceType, DispatchTarget, IoManager, MajorFunctionTable,
            MockDriverBackend, MockObjectPort, ShareAccess, WdmFileObjectInit,
            WDM_X64_FILE_OBJECT_SIZE,
        };
        use alloc::{boxed::Box, vec};
        use nt_types::{AccessMask, NtPath, UnicodeString};

        let original = CreateOptions::WRITE_THROUGH | CreateOptions::SYNCHRONOUS_IO_NONALERT;
        for major in [
            major::IRP_MJ_CREATE,
            major::IRP_MJ_CREATE_NAMED_PIPE,
            major::IRP_MJ_CREATE_MAILSLOT,
        ] {
            for sensitive in [false, true] {
                let mut io = IoManager::new(MockObjectPort::new());
                let client = io.register_client();
                let mut majors = MajorFunctionTable::new();
                majors.set_all(DispatchTarget::DriverPeer(crate::DriverPeerId(0)));
                let driver = io
                    .create_driver_peer_with_major_table(
                        &NtPath::parse_str(r"\Driver\CaseProjection").unwrap(),
                        Box::new(MockDriverBackend::new()),
                        majors,
                    )
                    .unwrap();
                let device = io
                    .create_device(
                        driver,
                        None,
                        DeviceType::UNKNOWN,
                        DeviceCharacteristics::empty(),
                        DeviceFlags::BUFFERED_IO,
                        0,
                    )
                    .unwrap();
                let file = io
                    .allocate_external_file(
                        client,
                        device,
                        AccessMask::GENERIC_READ,
                        ShareAccess::READ,
                        original,
                        UnicodeString::from_str("MixedCase"),
                    )
                    .unwrap();
                let parameters = CreateParameters {
                    opened_case_sensitive: sensitive,
                    create_options: original,
                    ..Default::default()
                };
                let prepared = io
                    .prepare_external_file_irp_owned(
                        ExternalFileIrpRequest {
                            client,
                            device_id: device,
                            file_id: Some(file),
                            user_data: 0,
                            requestor_tid: 99,
                            major,
                            stack_flags: parameters.case_sensitive_stack_flags(major),
                            parameters: IoParameters::Create(parameters),
                            initial_information: 0,
                        },
                        ExternalFileIrpBuffers::new(vec![], vec![]),
                    )
                    .unwrap();
                let mut bytes = [];
                let context = DispatchContext::new(driver, client, &mut bytes);
                let request =
                    build_dispatch_request(prepared.projection(), &context, target(), None)
                        .unwrap();
                assert_eq!(request.create_case_sensitive, sensitive as u32);
                assert_eq!(request.file_create_options, original.bits());
                for options in [0x30, 0x0100_0000] {
                    let mut malformed = prepared.projection().clone();
                    malformed.file_create_options = options;
                    assert_eq!(
                        build_dispatch_request(&malformed, &context, target(), None),
                        Err(NtStatus::INVALID_PARAMETER)
                    );
                }
                assert_eq!(
                    request.flags & 0x80 != 0,
                    major == major::IRP_MJ_CREATE && sensitive
                );
                assert!(valid_create_case_sensitive(
                    request.major,
                    request.create_case_sensitive
                ));
                let mut peer = MockPeerControl::new().transport();
                let expected = if major == major::IRP_MJ_CREATE {
                    DispatchOutcome::Completed {
                        status: NtStatus::SUCCESS,
                        information: 0,
                        file_context: None,
                    }
                } else {
                    DispatchOutcome::Failed {
                        status: NtStatus::INVALID_DEVICE_REQUEST,
                    }
                };
                assert_eq!(
                    peer.dispatch(&request, PeerTransferBuffers::new(&mut [])),
                    expected
                );
                let mut wdm = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
                write_wdm_file_object(
                    &mut wdm,
                    WdmFileObjectInit {
                        file_object_address: 0x4000,
                        opened_case_sensitive: request.create_case_sensitive != 0,
                        create_options: request.file_create_options,
                        device_object: 0x1122,
                        fs_context: 0x3344,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert_eq!(
                    u32::from_le_bytes(wdm[0x50..0x54].try_into().unwrap()),
                    0x12 | if sensitive { 0x0002_0000 } else { 0 }
                );
                assert_eq!(u64::from_le_bytes(wdm[8..16].try_into().unwrap()), 0x1122);
                assert_eq!(io.file(file).unwrap().opened_case_sensitive(), sensitive);
                for (flags, value) in [(request.flags, 2)] {
                    let malformed = IrpDispatchRequest {
                        flags,
                        create_case_sensitive: value,
                        ..request
                    };
                    assert_eq!(
                        peer.dispatch(&malformed, PeerTransferBuffers::new(&mut [])),
                        DispatchOutcome::Failed {
                            status: NtStatus::INVALID_PARAMETER
                        }
                    );
                }
                for malformed in [
                    IrpDispatchRequest {
                        abi_version: 14,
                        ..request
                    },
                    IrpDispatchRequest {
                        file_create_options: 0x30,
                        ..request
                    },
                    IrpDispatchRequest {
                        file_create_options: 0x0100_0000,
                        ..request
                    },
                    IrpDispatchRequest {
                        major: major::IRP_MJ_READ,
                        create_case_sensitive: 0,
                        ..request
                    },
                ] {
                    assert_eq!(
                        peer.dispatch(&malformed, PeerTransferBuffers::new(&mut [])),
                        DispatchOutcome::Failed {
                            status: NtStatus::INVALID_PARAMETER
                        }
                    );
                }
                io.discard_prepared_external_file_irp(prepared).unwrap();
                io.release_external_file(client, file).unwrap();
            }
        }
    }

    #[test]
    fn forwarded_create_preserves_file_provenance_while_filter_changes_lower_stack() {
        use crate::{
            write_wdm_file_object, CreateOptions, CreateParameters, DeviceCharacteristics,
            DeviceFlags, DeviceType, IoManager, IoStackLocation, MockDriverBackend, MockObjectPort,
            ShareAccess, WdmFileObjectInit, WDM_X64_FILE_OBJECT_SIZE,
        };
        use alloc::boxed::Box;
        use nt_types::{AccessMask, NtPath, UnicodeString};

        let original = CreateOptions::from_bits_retain(0x181a);
        let lower_options = CreateOptions::SYNCHRONOUS_IO_NONALERT | CreateOptions::SEQUENTIAL_ONLY;
        for sensitive in [false, true] {
            let mut io = IoManager::new(MockObjectPort::new());
            let client = io.register_client();
            let lower_driver = io
                .create_driver(
                    &NtPath::parse_str(r"\Driver\CaseLower").unwrap(),
                    Box::new(MockDriverBackend::new()),
                )
                .unwrap();
            let filter_driver = io
                .create_driver(
                    &NtPath::parse_str(r"\Driver\CaseFilter").unwrap(),
                    Box::new(MockDriverBackend::new()),
                )
                .unwrap();
            let lower = io
                .create_device(
                    lower_driver,
                    None,
                    DeviceType::UNKNOWN,
                    DeviceCharacteristics::empty(),
                    DeviceFlags::BUFFERED_IO,
                    0,
                )
                .unwrap();
            let filter = io
                .create_device(
                    filter_driver,
                    None,
                    DeviceType::UNKNOWN,
                    DeviceCharacteristics::empty(),
                    DeviceFlags::BUFFERED_IO,
                    0,
                )
                .unwrap();
            io.attach_device_to_stack(filter, lower).unwrap();
            let file = io
                .allocate_external_file(
                    client,
                    lower,
                    AccessMask::GENERIC_READ,
                    ShareAccess::READ,
                    original,
                    UnicodeString::from_str("MixedCase"),
                )
                .unwrap();
            let parameters = CreateParameters {
                opened_case_sensitive: sensitive,
                create_options: original,
                ..Default::default()
            };
            let mut rejected = io
                .build_irp_record(
                    client,
                    lower_driver,
                    lower,
                    Some(file),
                    major::IRP_MJ_CREATE,
                    IoParameters::Create(parameters),
                )
                .unwrap();
            rejected.stack[0].flags.toggle(StackFlags::CASE_SENSITIVE);
            assert_eq!(io.allocate_irp(rejected), Err(NtStatus::INVALID_PARAMETER));
            assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
            assert!(!io.file(file).unwrap().opened_case_sensitive());
            for options in [0x30, 0x0100_0000] {
                io.file_mut(file).unwrap().create_options = CreateOptions::from_bits_retain(options);
                let rejected = io
                    .build_irp_record(
                        client,
                        lower_driver,
                        lower,
                        Some(file),
                        major::IRP_MJ_CREATE,
                        IoParameters::Create(parameters),
                    )
                    .unwrap();
                assert_eq!(io.allocate_irp(rejected), Err(NtStatus::INVALID_PARAMETER));
                assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
                assert!(!io.file(file).unwrap().opened_case_sensitive());
                assert_eq!(io.irp_count(), 0);
            }
            io.file_mut(file).unwrap().create_options = original;
            let record = io
                .build_irp_record(
                    client,
                    lower_driver,
                    lower,
                    Some(file),
                    major::IRP_MJ_CREATE,
                    IoParameters::Create(parameters),
                )
                .unwrap();
            let irp = io.allocate_irp(record).unwrap();
            assert_eq!(io.irp(irp).unwrap().create_case_sensitive(), sensitive);
            assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 1);
            let changed = CreateParameters {
                opened_case_sensitive: !sensitive,
                create_options: lower_options,
                ..parameters
            };
            let mut next =
                IoStackLocation::new(lower_driver, major::IRP_MJ_CREATE, lower, Some(file));
            next.flags = changed.case_sensitive_stack_flags(major::IRP_MJ_CREATE);
            next.parameters = IoParameters::Create(changed);
            assert_eq!(
                io.handoff_irp_to_next_stack(irp, lower_driver, next.clone()),
                Err(NtStatus::INVALID_PARAMETER)
            );
            assert_eq!(io.irp(irp).unwrap().current_location, 0);
            assert_eq!(
                io.handoff_irp_to_next_stack(irp, filter_driver, next),
                Ok((lower_driver, lower))
            );
            let projection = IrpProjection::from_record(io.irp(irp).unwrap()).unwrap();
            assert_eq!(projection.create_case_sensitive, sensitive);
            assert_eq!(projection.file_create_options, original.bits());
            assert_eq!(
                projection.flags.contains(StackFlags::CASE_SENSITIVE),
                !sensitive
            );
            let IoParameters::Create(lower_parameters) = &projection.parameters else {
                panic!("CREATE parameters lost");
            };
            assert_eq!(lower_parameters.opened_case_sensitive, !sensitive);
            assert_eq!(lower_parameters.create_options, lower_options);
            let mut bytes = [];
            let context = DispatchContext::new(lower_driver, client, &mut bytes);
            let request = build_dispatch_request(&projection, &context, target(), None).unwrap();
            assert_eq!(request.create_case_sensitive, sensitive as u32);
            assert_eq!(request.file_create_options, original.bits());
            assert_eq!(request.create_options, lower_options.bits());
            assert_eq!(request.flags & 0x80 != 0, !sensitive);
            let mut peer = MockPeerControl::new().transport();
            assert!(matches!(
                peer.dispatch(&request, PeerTransferBuffers::new(&mut [])),
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    ..
                }
            ));
            let mut wdm = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
            write_wdm_file_object(
                &mut wdm,
                WdmFileObjectInit {
                    file_object_address: 0x4000,
                    opened_case_sensitive: request.create_case_sensitive != 0,
                    create_options: request.file_create_options,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(
                u32::from_le_bytes(wdm[0x50..0x54].try_into().unwrap()),
                0x0010_001e | if sensitive { 0x0002_0000 } else { 0 }
            );
            assert_eq!(io.file(file).unwrap().opened_case_sensitive(), sensitive);
            assert_eq!(io.irp(irp).unwrap().create_case_sensitive(), sensitive);
            assert_eq!(io.file(file).unwrap().create_options, original);
            let current = &mut io.irp_mut(irp).unwrap().stack[1];
            current.major = major::IRP_MJ_READ;
            current.parameters = IoParameters::Read(Default::default());
            assert!(
                !IrpProjection::from_record(io.irp(irp).unwrap())
                    .unwrap()
                    .create_case_sensitive
            );
            assert_eq!(io.irp(irp).unwrap().create_case_sensitive(), sensitive);
            assert_eq!(
                IrpProjection::from_record(io.irp(irp).unwrap())
                    .unwrap()
                    .file_create_options,
                0
            );
            assert_eq!(io.irp(irp).unwrap().file_create_options(), original.bits());
            io.free_irp(irp).unwrap();
            assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
            io.release_external_file(client, file).unwrap();
            assert!(io.file(file).is_none());
        }
    }
}
