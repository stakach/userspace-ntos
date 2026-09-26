//! Driver ZwReadFile and ZwQueryInformationFile on an authenticated routed File.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::file_read_query_wire::{self as wire, FileReadQueryRequest, FileReadQueryWireError};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const STATUS_NOT_SUPPORTED_LOCAL: i32 = 0xc000_00bbu32 as i32;
const STATUS_INVALID_INFO_CLASS_LOCAL: i32 = 0xc000_0003u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH_LOCAL: i32 = 0xc000_0004u32 as i32;
const FILE_READ_DATA: u32 = 0x0000_0001;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

const COMPLETED_OFF: u64 = 24;

fn wire_status(error: FileReadQueryWireError) -> u32 {
    match error {
        FileReadQueryWireError::InvalidClass => STATUS_INVALID_INFO_CLASS_LOCAL as u32,
        FileReadQueryWireError::LengthMismatch => STATUS_INFO_LENGTH_MISMATCH_LOCAL as u32,
        FileReadQueryWireError::BufferTooSmall => STATUS_INVALID_BUFFER_SIZE as u32,
        FileReadQueryWireError::Malformed => STATUS_INVALID_PARAMETER as u32,
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Read(ReadWriteParameters),
    Query(u32),
}

impl Operation {
    fn major(self) -> u8 {
        match self {
            Self::Read(_) => major::IRP_MJ_READ,
            Self::Query(_) => major::IRP_MJ_QUERY_INFORMATION,
        }
    }
}

struct Work {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    file: super::hosted_file_capture::Capture,
    instance: DriverInstance,
    domain: nt_io_manager::HostedTransportIdentity,
    packet: u64,
    packet_length: u64,
    operation: Operation,
    output: Vec<u8>,
    entered: bool,
    pending_irp: Option<IrpId>,
    terminal: Option<(u32, u64)>,
    cancel_requested: bool,
    reply_entered: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn capture_packet(
    instance: DriverInstance,
    packet: u64,
    packet_length: u64,
) -> Result<(Operation, Vec<u8>), u32> {
    let total = usize::try_from(packet_length).map_err(|_| STATUS_INVALID_BUFFER_SIZE as u32)?;
    if total < wire::HEADER_BYTES || packet_length >= FSD_POOL_FRAMES * 0x1000 {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let exec =
        unsafe { hosted_instance_pool_allocation_exec_if_live(instance, packet, packet_length) }
            .ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let request = wire::decode_request(unsafe { core::slice::from_raw_parts(exec as *const u8, total) })
        .map_err(wire_status)?;
    let operation = match request {
        FileReadQueryRequest::Read(parameters) => Operation::Read(parameters),
        FileReadQueryRequest::Query { class, .. } => Operation::Query(class),
    };
    let length = request.output_len() as usize;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    output.resize(length, 0);
    Ok((operation, output))
}

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    packet: u64,
    packet_length: u64,
    handle: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    let (_, instance) = match instance_for_pump_channel(channel, active_reply_cap) {
        Some(instance) => instance,
        None => return Some(STATUS_ACCESS_DENIED),
    };
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(status as i32),
    };
    let (operation, output) = match capture_packet(instance, packet, packet_length) {
        Ok(packet) => packet,
        Err(status) => return Some(status as i32),
    };
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let (file_id, device_id, granted, mut actor) =
        match crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)?;
            let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
            let target = pm.inspect_native_close_target(caller, handle)?;
            if target.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
                return Err(STATUS_INVALID_HANDLE as u32);
            }
            let granted = target
                .information()
                .granted_access
                .ok_or(STATUS_INVALID_HANDLE as u32)?;
            if matches!(operation, Operation::Read(_))
                && granted & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) == 0
            {
                return Err(STATUS_ACCESS_DENIED as u32);
            }
            let actor = pm.reference_native_requestor(caller)?;
            Ok((file_id, device_id, granted, actor))
        }) {
            Ok(value) => value,
            Err(status) => return Some(status as i32),
        };
    let file = match super::hosted_file_capture::capture(file_id, device_id, granted) {
        Ok(file) => file,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered hosted File read/query actor");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
        });
    if slot.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err()
    {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered hosted File read/query actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token =
        match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
            Ok(token) => token,
            Err(_) => {
                crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                    .expect("unentered hosted File read/query actor");
                return Some(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
    let work = Work {
        route,
        dispatch,
        reply,
        token,
        caller,
        actor,
        file,
        instance,
        domain: nt_io_manager::HostedTransportIdentity {
            domain: channel
                .physical_domain
                .expect("authenticated hosted File I/O domain"),
            endpoint: channel.fault_ep,
            vspace: channel.pml4,
            shared: channel.shared_va,
        },
        packet,
        packet_length,
        operation,
        output,
        entered: false,
        pending_irp: None,
        terminal: None,
        cancel_requested: false,
        reply_entered: false,
    };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked hosted File read/query");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked hosted File read/query actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    fn checked_terminal(&self, status: u32, information: u64) -> (u32, u64) {
        if matches!(self.operation, Operation::Read(_)) && information > self.output.len() as u64 {
            (nt_fs::STATUS_DATA_ERROR, 0)
        } else {
            (status, information)
        }
    }

    fn cancelled(&self) -> bool {
        unsafe {
            runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
        }
    }

    unsafe fn release(&mut self, handler: *mut ExecNtHandler) {
        self.actor
            .release(&mut (*handler).pm)
            .expect("hosted File read/query actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> bool {
        if let Some(irp) = self.pending_irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if completed_irp_exact(irp.raw()).is_none()
                || acknowledge_completed_irp(irp.raw()).is_err()
            {
                return false;
            }
            self.pending_irp = None;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("hosted File read/query cancellation");
        self.release(handler);
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("hosted File read/query Reply identity");
            if !acked {
                if self.cancelled() {
                    return self.finish_cancelled(handler);
                }
                return false;
            }
            if let Some(irp) = self.pending_irp {
                if acknowledge_completed_irp(irp.raw()).is_err() {
                    return false;
                }
                self.pending_irp = None;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("hosted File read/query Reply retirement");
            self.release(handler);
            return true;
        }
        if !self.entered {
            if self.cancelled() {
                return self.finish_cancelled(handler);
            }
            if let Err(status) = self.actor.validate(&(*handler).pm) {
                self.entered = true;
                self.terminal = Some((status, 0));
            } else {
                (*handler)
                    .file_completion
                    .set_signaled(self.file.file_id(), false)
                    .expect("live hosted File read/query signal");
                self.entered = true;
                let result = match self.operation {
                    Operation::Read(parameters) => {
                        dispatch_hosted_file_read_write_irp_result_exact(
                            self.file.file_id(),
                            major::IRP_MJ_READ,
                            self.caller,
                            parameters,
                            &[],
                            &mut self.output,
                        )
                    }
                    Operation::Query(class) => dispatch_hosted_file_irp_result_exact(
                        self.file.file_id(),
                        major::IRP_MJ_QUERY_INFORMATION as u64,
                        class as u64,
                        self.caller,
                        &[],
                        &mut self.output,
                        0,
                    ),
                };
                match result {
                    Ok((_, _, Some(irp), _)) => self.pending_irp = Some(irp),
                    Ok((status, information, None, _)) => {
                        self.terminal = Some(self.checked_terminal(status as u32, information));
                    }
                    Err(status) => self.terminal = Some((status, 0)),
                }
            }
        }
        if self.terminal.is_none() {
            if self.cancelled() && !self.cancel_requested {
                self.cancel_requested = true;
                if let Some(irp) = self.pending_irp {
                    let _ = cancel_irp_if_pending(irp.raw());
                }
            }
            let Some(irp) = self.pending_irp else {
                return false;
            };
            let Some(completion) = completed_irp_exact(irp.raw()) else {
                return false;
            };
            if completion.file_id != self.file.file_id()
                || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
                || completion.major != self.operation.major()
            {
                panic!("hosted File read/query terminal identity mismatch");
            }
            let (status, information) =
                self.checked_terminal(completion.status, completion.information);
            let transfer = if nt_io_completion::file_io_status_copies_output(completion.status)
                && status == completion.status
                && !self.cancelled()
            {
                nt_io_manager::completion_output_transfer_len(information, self.output.len() as u64)
                    as usize
            } else {
                0
            };
            if transfer != 0 {
                match copy_completed_irp_output_exact(irp.raw(), 0, &mut self.output[..transfer]) {
                    Ok(bytes) if bytes == transfer => {}
                    _ if self.cancelled() => return self.finish_cancelled(handler),
                    _ => return false,
                }
            }
            self.terminal = Some((status, information));
        }
        if self.cancelled() {
            return self.finish_cancelled(handler);
        }
        let (status, information) = self.terminal.expect("hosted File read/query terminal");
        let Some((_, live)) = instance_by_shared_va(self.domain.shared) else {
            return false;
        };
        let Some(live_domain) = instance_domain_identity(live) else {
            return false;
        };
        let live_transport = nt_io_manager::HostedTransportIdentity {
            domain: live_domain,
            endpoint: live.fault_ep,
            vspace: live.pml4,
            shared: live.exec_shared_va,
        };
        if !self.domain.matches_live(live_transport)
            || live.exec_pool_va != self.instance.exec_pool_va
        {
            return false;
        }
        let Some(exec) =
            hosted_instance_pool_allocation_exec_if_live(live, self.packet, self.packet_length)
        else {
            return false;
        };
        let packet = core::slice::from_raw_parts_mut(exec as *mut u8, self.packet_length as usize);
        if wire::publish_completion(packet, &self.output, status, information).is_err() {
            crate::provider_bugcheck::report(0xc4, [self.packet, self.packet_length, self.file.file_id(), status as u64]);
        }
        (*handler)
            .file_completion
            .set_signaled(self.file.file_id(), true)
            .expect("terminal hosted File read/query signal");
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            status as i32,
        );
        false
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 {
        return;
    }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .map(|work| (index, work))
    }) else {
        return;
    };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING))
        .try_reserve(1)
        .is_err()
    {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(),
        Some(index)
    );
}

fn invoke(handle: u64, iosb: u64, output: u64, length: u32, operation: Operation) -> i32 {
    if iosb == 0 || (length != 0 && output == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let total = match wire::packet_len(length) {
        Ok(total) if (total as u64) < FSD_POOL_FRAMES * 0x1000 => total,
        _ => return STATUS_INVALID_BUFFER_SIZE as i32,
    };
    let packet = unsafe { pool_alloc(total as u64) };
    if packet == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let request = match operation {
        Operation::Read(parameters) => FileReadQueryRequest::Read(parameters),
        Operation::Query(class) => FileReadQueryRequest::Query { class, length },
    };
    if let Err(error) = wire::encode_request(
        request,
        unsafe { core::slice::from_raw_parts_mut(packet as *mut u8, total) },
    ) {
        unsafe { pool_free(packet) };
        return wire_status(error) as i32;
    }
    let (label, status, _, _, _) = unsafe {
        call_on4(
            (FSD_SERVICE_ZW_READ_QUERY_FILE_LABEL << 12) | 4,
            packet,
            total as u64,
            handle,
            0,
        )
    };
    if label != 0 {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_ZW_READ_QUERY_FILE_LABEL, packet, label, status],
            );
        }
    }
    let result = if unsafe { read_unaligned((packet + COMPLETED_OFF) as *const u32) } == 1 {
        let (terminal, information, bytes) = match wire::decode_completion(unsafe {
            core::slice::from_raw_parts(packet as *const u8, total)
        }) {
            Ok(completion) => completion,
            Err(_) => unsafe {
                crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_ZW_READ_QUERY_FILE_LABEL, packet, total as u64, status])
            },
        };
        let copied = if nt_io_completion::file_io_status_copies_output(terminal) {
            nt_io_manager::completion_output_transfer_len(information, length as u64) as usize
        } else {
            0
        };
        unsafe {
            if copied != 0 {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    output as *mut u8,
                    copied,
                );
            }
            write_unaligned(iosb as *mut u32, terminal);
            write_unaligned((iosb + 8) as *mut u64, information);
        }
        terminal as i32
    } else {
        status as u32 as i32
    };
    unsafe { pool_free(packet) };
    result
}

pub(super) extern "win64" fn s_zw_query_information_file(
    handle: u64,
    iosb: u64,
    output: u64,
    length: u32,
    class: u32,
) -> i32 {
    let Some(contract) = nt_io_manager::query_information_contract(class) else {
        return STATUS_INVALID_INFO_CLASS_LOCAL;
    };
    if (length as usize) < contract.minimum_length() {
        return STATUS_INFO_LENGTH_MISMATCH_LOCAL;
    }
    invoke(handle, iosb, output, length, Operation::Query(class))
}

pub(super) extern "win64" fn s_zw_read_file(
    handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    iosb: u64,
    output: u64,
    length: u32,
    byte_offset: u64,
    key: u64,
) -> i32 {
    if event != 0 || apc_routine != 0 || apc_context != 0 || byte_offset == 0 {
        return STATUS_NOT_SUPPORTED_LOCAL;
    }
    let offset = unsafe { read_unaligned(byte_offset as *const u64) };
    if (offset as i64) < 0 {
        return STATUS_NOT_SUPPORTED_LOCAL;
    }
    let key = if key == 0 {
        0
    } else {
        unsafe { read_unaligned(key as *const u32) }
    };
    invoke(
        handle,
        iosb,
        output,
        length,
        Operation::Read(ReadWriteParameters {
            length,
            key,
            offset,
        }),
    )
}
