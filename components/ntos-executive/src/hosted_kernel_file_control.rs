//! Hosted ZwFsControlFile and file-handle wait, using canonical RoutedFile ownership.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const HEADER_BYTES: usize = 32;
const STATUS_CANCELLED_LOCAL: u32 = 0xc000_0120;
const STATUS_TIMEOUT_LOCAL: u32 = 0x0000_0102;
const STATUS_NOT_SUPPORTED_LOCAL: u32 = 0xc000_00bb;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

const CODE_OFF: u64 = 0;
const INPUT_LEN_OFF: u64 = 4;
const OUTPUT_LEN_OFF: u64 = 8;
const COMPLETED_OFF: u64 = 12;
const STATUS_OFF: u64 = 16;
const COPIED_OFF: u64 = 20;
const INFORMATION_OFF: u64 = 24;

struct FileWork {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    file: super::hosted_file_capture::Capture,
    instance: DriverInstance,
    domain: nt_io_manager::HostedTransportIdentity,
    component_packet: u64,
    packet_length: u64,
    control_code: u32,
    input: Vec<u8>,
    output: Vec<u8>,
    entered: bool,
    pending_irp: Option<IrpId>,
    terminal: Option<(u32, u64)>,
    copied: usize,
    cancelled_after_entry: bool,
    reply_entered: bool,
}

static mut WORK: Vec<Option<FileWork>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn control_access(granted: u32, code: u32) -> bool {
    let required = nt_io_abi::ioctl::access(code);
    (required & nt_io_abi::ioctl::FILE_READ_ACCESS == 0
        || granted & (0x0000_0001 | 0x8000_0000 | 0x1000_0000) != 0)
        && (required & nt_io_abi::ioctl::FILE_WRITE_ACCESS == 0
            || granted & (0x0000_0002 | 0x0000_0004 | 0x4000_0000 | 0x1000_0000) != 0)
}

fn lookup_file(
    caller: NativeHandleCaller,
    handle: u64,
    code: Option<u32>,
) -> Result<(u64, u64, u32, NativeThreadProcessReference), u32> {
    unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let (file, device) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
        let target = pm.inspect_native_close_target(caller, handle)?;
        if target.object() != (nt_process::HandleObject::RoutedFile {
            file_id: file, device_id: device,
        }) {
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        let granted = target.information().granted_access.ok_or(STATUS_INVALID_HANDLE as u32)?;
        if code.is_some_and(|code| !control_access(granted, code)) {
            return Err(STATUS_ACCESS_DENIED as u32);
        }
        if code.is_none() && granted & (SYNCHRONIZE_ACCESS | 0x1000_0000) == 0 {
            return Err(STATUS_ACCESS_DENIED as u32);
        }
        let actor = pm.reference_native_requestor(caller)?;
        Ok((file, device, granted, actor))
    }) }
}

fn capture_packet(
    instance: DriverInstance,
    component_packet: u64,
    packet_length: u64,
) -> Result<(u32, Vec<u8>, Vec<u8>), u32> {
    let total = usize::try_from(packet_length).map_err(|_| STATUS_INVALID_BUFFER_SIZE as u32)?;
    if total < HEADER_BYTES || packet_length >= FSD_POOL_FRAMES * 0x1000 {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let exec = unsafe {
        hosted_instance_pool_allocation_exec_if_live(instance, component_packet, packet_length)
    }.ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let code = unsafe { read_unaligned((exec + CODE_OFF) as *const u32) };
    let input_len = unsafe { read_unaligned((exec + INPUT_LEN_OFF) as *const u32) } as usize;
    let output_len = unsafe { read_unaligned((exec + OUTPUT_LEN_OFF) as *const u32) } as usize;
    if HEADER_BYTES.checked_add(input_len).and_then(|n| n.checked_add(output_len)) != Some(total) {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let mut input = Vec::new();
    input.try_reserve_exact(input_len).map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    unsafe {
        input.extend_from_slice(core::slice::from_raw_parts((exec + HEADER_BYTES as u64) as *const u8, input_len));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    output.resize(output_len, 0);
    Ok((code, input, output))
}

/// A provider's pointers are copied only from its exact live pool allocation. The root resolves
/// the handle in the authenticated actor's table and retains that File before dispatch.
pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    component_packet: u64,
    packet_length: u64,
    handle: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    let (_instance_index, instance) = match instance_for_pump_channel(channel, active_reply_cap) {
        Some(instance) => instance,
        None => return Some(STATUS_ACCESS_DENIED),
    };
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(status as i32),
    };
    let (code, input, output) = match capture_packet(instance, component_packet, packet_length) {
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
    let (file_id, device_id, grant, mut actor) = match lookup_file(caller, handle, Some(code)) {
        Ok(file) => file,
        Err(status) => return Some(status as i32),
    };
    let file = match super::hosted_file_capture::capture(file_id, device_id, grant) {
        Ok(file) => file,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unadmitted hosted FSCTL actor");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(i, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&i)).then_some(i)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unadmitted hosted FSCTL actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
        Ok(token) => token,
        Err(_) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unadmitted hosted FSCTL actor");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let work = FileWork {
        route, dispatch, reply, token, caller, actor, file, instance,
        domain: nt_io_manager::HostedTransportIdentity {
            domain: channel.physical_domain.expect("authenticated hosted FSCTL domain"),
            endpoint: channel.fault_ep, vspace: channel.pml4, shared: channel.shared_va,
        },
        component_packet, packet_length, control_code: code, input, output,
        entered: false, pending_irp: None, terminal: None, copied: 0,
        cancelled_after_entry: false, reply_entered: false,
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
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().expect("unparked FSCTL work");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked FSCTL actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

impl FileWork {
    fn cancelled(&self) -> bool {
        unsafe { runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) }
    }

    unsafe fn release(&mut self, handler: &mut ExecNtHandler) {
        self.actor.release(&mut handler.pm).expect("hosted FSCTL actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: &mut ExecNtHandler) -> bool {
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("sealed hosted FSCTL cancellation");
        if let Some(irp) = self.pending_irp {
            acknowledge_completed_irp(irp.raw()).expect("cancelled terminal FSCTL ACK");
        }
        self.release(handler);
        true
    }

    unsafe fn advance(&mut self, handler: &mut ExecNtHandler) -> bool {
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("hosted FSCTL Reply identity");
            if !acked {
                if self.cancelled() { return self.finish_cancelled(handler); }
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("hosted FSCTL Reply retirement");
            if let Some(irp) = self.pending_irp {
                acknowledge_completed_irp(irp.raw()).expect("hosted FSCTL backend ACK");
            }
            self.release(handler);
            return true;
        }
        if !self.entered {
            if self.cancelled() { return self.finish_cancelled(handler); }
            if let Err(status) = self.actor.validate(&handler.pm) {
                self.entered = true;
                self.terminal = Some((status, 0));
            } else {
                handler.file_completion.set_signaled(self.file.file_id(), false)
                    .expect("live hosted FSCTL File signal");
                self.entered = true;
                match dispatch_hosted_file_irp_result_exact(
                    self.file.file_id(), major::IRP_MJ_FILE_SYSTEM_CONTROL as u64,
                    self.control_code as u64, self.caller, &self.input, &mut self.output, 0,
                ) {
                    Ok((_, _, Some(irp), _)) => self.pending_irp = Some(irp),
                    Ok((status, info, None, _)) => {
                        self.copied = if nt_io_completion::file_io_status_copies_output(status as u32) {
                            nt_io_manager::completion_output_transfer_len(info, self.output.len() as u64) as usize
                        } else { 0 };
                        self.terminal = Some((status as u32, info));
                    }
                    Err(status) => self.terminal = Some((status, 0)),
                }
            }
            return false;
        }
        if self.terminal.is_none() {
            if self.cancelled() && !self.cancelled_after_entry {
                self.cancelled_after_entry = true;
                if let Some(irp) = self.pending_irp { let _ = cancel_irp_if_pending(irp.raw()); }
            }
            let Some(irp) = self.pending_irp else { return false; };
            let Some(completion) = completed_irp_exact(irp.raw()) else { return false; };
            if completion.file_id != self.file.file_id()
                || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
                || completion.major != major::IRP_MJ_FILE_SYSTEM_CONTROL
            {
                panic!("hosted FSCTL terminal identity mismatch");
            }
            let transfer = if nt_io_completion::file_io_status_copies_output(completion.status)
                && !self.cancelled()
            {
                nt_io_manager::completion_output_transfer_len(
                    completion.information, self.output.len() as u64,
                ) as usize
            } else { 0 };
            if transfer != 0 {
                match copy_completed_irp_output_exact(irp.raw(), 0, &mut self.output[..transfer]) {
                    Ok(bytes) if bytes == transfer => self.copied = bytes,
                    _ => return false,
                }
            }
            self.terminal = Some((completion.status, completion.information));
        }
        if self.cancelled() { return self.finish_cancelled(handler); }
        let (status, information) = self.terminal.expect("hosted FSCTL terminal");
        let Some((_, live)) = instance_by_shared_va(self.domain.shared) else { return false; };
        let Some(live_domain) = instance_domain_identity(live) else { return false; };
        let live_transport = nt_io_manager::HostedTransportIdentity {
            domain: live_domain, endpoint: live.fault_ep,
            vspace: live.pml4, shared: live.exec_shared_va,
        };
        if !self.domain.matches_live(live_transport) || live.exec_pool_va != self.instance.exec_pool_va {
            return false;
        }
        let Some(exec) = hosted_instance_pool_allocation_exec_if_live(
            live, self.component_packet, self.packet_length,
        ) else { return false; };
        let out_offset = HEADER_BYTES + self.input.len();
        core::ptr::copy_nonoverlapping(
            self.output.as_ptr(), (exec + out_offset as u64) as *mut u8, self.output.len(),
        );
        write_unaligned((exec + STATUS_OFF) as *mut u32, status);
        write_unaligned((exec + COPIED_OFF) as *mut u32, self.copied as u32);
        write_unaligned((exec + INFORMATION_OFF) as *mut u64, information);
        write_unaligned((exec + COMPLETED_OFF) as *mut u32, 1);
        handler.file_completion.set_signaled(self.file.file_id(), true)
            .expect("terminal hosted FSCTL File signal");
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return; };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
}

pub(super) extern "win64" fn s_zw_fs_control_file(
    file_handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    io_status_block: u64,
    control_code: u32,
    input_buffer: u64,
    input_length: u32,
    output_buffer: u64,
    output_length: u32,
) -> i32 {
    if io_status_block == 0 || event != 0 || apc_routine != 0 || apc_context != 0 {
        return STATUS_NOT_SUPPORTED_LOCAL as i32;
    }
    if (input_length != 0 && input_buffer == 0) || (output_length != 0 && output_buffer == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let total = match HEADER_BYTES.checked_add(input_length as usize)
        .and_then(|n| n.checked_add(output_length as usize)) {
        Some(total) if (total as u64) < FSD_POOL_FRAMES * 0x1000 => total,
        _ => return STATUS_INVALID_BUFFER_SIZE as i32,
    };
    let packet = unsafe { pool_alloc(total as u64) };
    if packet == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
    unsafe {
        write_unaligned((packet + CODE_OFF) as *mut u32, control_code);
        write_unaligned((packet + INPUT_LEN_OFF) as *mut u32, input_length);
        write_unaligned((packet + OUTPUT_LEN_OFF) as *mut u32, output_length);
        write_unaligned((packet + COMPLETED_OFF) as *mut u32, 0);
        write_unaligned((packet + COPIED_OFF) as *mut u32, 0);
        if input_length != 0 {
            core::ptr::copy_nonoverlapping(
                input_buffer as *const u8, (packet + HEADER_BYTES as u64) as *mut u8,
                input_length as usize,
            );
        }
    }
    let (label, status, _, _, _) = unsafe { call_on4(
        (FSD_SERVICE_ZW_FS_CONTROL_FILE_LABEL << 12) | 4,
        packet, total as u64, file_handle, 0,
    ) };
    let final_status = if label == 0 {
        let complete = unsafe { read_unaligned((packet + COMPLETED_OFF) as *const u32) };
        if complete == 1 {
            let status = unsafe { read_unaligned((packet + STATUS_OFF) as *const u32) };
            let copied = unsafe { read_unaligned((packet + COPIED_OFF) as *const u32) };
            let info = unsafe { read_unaligned((packet + INFORMATION_OFF) as *const u64) };
            if copied > output_length {
                STATUS_INVALID_BUFFER_SIZE as i32
            } else {
                unsafe {
                    if copied != 0 {
                        core::ptr::copy_nonoverlapping(
                            (packet + HEADER_BYTES as u64 + input_length as u64) as *const u8,
                            output_buffer as *mut u8, copied as usize,
                        );
                    }
                    write_unaligned(io_status_block as *mut u32, status);
                    write_unaligned((io_status_block + 8) as *mut u64, info);
                }
                status as i32
            }
        } else { status as u32 as i32 }
    } else { STATUS_INVALID_PARAMETER };
    unsafe { pool_free(packet) };
    final_status
}

struct WaitWork {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    actor: NativeThreadProcessReference,
    file: super::hosted_file_capture::Capture,
    deadline: nt_kernel_exec::Deadline,
    reply_entered: bool,
}

static mut WAITS: Vec<Option<WaitWork>> = Vec::new();
static mut WAIT_EXECUTING: Vec<usize> = Vec::new();
static WAIT_NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static WAIT_CURSOR: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit_wait(
    channel: &crate::spawn_hosts::PumpChannel,
    handle: u64,
    timeout_code: u64,
    timeout_arg: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    if instance_for_pump_channel(channel, active_reply_cap).is_none() {
        return Some(STATUS_ACCESS_DENIED);
    }
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
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
    let (file_id, device_id, grant, mut actor) = match lookup_file(caller, handle, None) {
        Ok(file) => file,
        Err(status) => return Some(status as i32),
    };
    let file = match super::hosted_file_capture::capture(file_id, device_id, grant) {
        Ok(file) => file,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unadmitted hosted File wait actor");
            return Some(status as i32);
        }
    };
    let deadline = match timeout_code {
        0 => nt_kernel_exec::Deadline::Infinite,
        1 => nt_kernel_exec::Deadline::from_nt_timeout(Some(0), crate::nt_time_snapshot()),
        2 => nt_kernel_exec::Deadline::from_nt_timeout(Some(timeout_arg as i64), crate::nt_time_snapshot()),
        _ => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("invalid hosted File wait actor");
            return Some(STATUS_INVALID_PARAMETER);
        }
    };
    let slot = (&*core::ptr::addr_of!(WAITS)).iter().enumerate().find_map(|(i, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(WAIT_EXECUTING)).contains(&i)).then_some(i)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WAITS)).try_reserve(1).is_err() {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unadmitted hosted File wait actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token = match WAIT_NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
        Ok(token) => token,
        Err(_) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unadmitted hosted File wait actor");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let work = WaitWork { route, dispatch, reply, token, actor, file, deadline, reply_entered: false };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WAITS))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WAITS);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WAITS))[index].take().expect("unparked File wait");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked File wait actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

impl WaitWork {
    unsafe fn advance(&mut self, handler: &mut ExecNtHandler) -> bool {
        let cancelled = runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        );
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("hosted File wait Reply identity");
            if !acked {
                if !cancelled { return false; }
                runtime::acknowledge_retained_service_cancellation(
                    self.route, self.dispatch, self.reply, self.token,
                ).expect("sealed hosted File wait cancellation");
            } else {
                runtime::retire_stopped_acknowledged_retained_service(
                    self.route, self.dispatch, self.reply, self.token,
                ).expect("hosted File wait Reply retirement");
            }
            self.actor.release(&mut handler.pm).expect("hosted File wait actor identity");
            return true;
        }
        if cancelled {
            runtime::acknowledge_retained_service_cancellation(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("sealed hosted File wait cancellation");
            self.actor.release(&mut handler.pm).expect("hosted File wait actor identity");
            return true;
        }
        let status = match handler.file_completion.is_signaled(self.file.file_id()) {
            Ok(true) => Some(STATUS_SUCCESS),
            Ok(false) if self.deadline.is_due(crate::nt_time_snapshot()) => Some(STATUS_TIMEOUT_LOCAL as i32),
            Ok(false) => None,
            Err(status) => Some(status as i32),
        };
        let Some(status) = status else { return false; };
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status,
        );
        false
    }
}

pub(crate) unsafe fn redrive_waits(handler: &mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WAITS)).len();
    if count == 0 { return; }
    let start = WAIT_CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(WAIT_EXECUTING)).contains(&index) { return None; }
        (&mut *core::ptr::addr_of_mut!(WAITS))[index].take().map(|work| (index, work))
    }) else { return; };
    if (&mut *core::ptr::addr_of_mut!(WAIT_EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WAITS))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(WAIT_EXECUTING)).push(index);
    WAIT_CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done { (&mut *core::ptr::addr_of_mut!(WAITS))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(WAIT_EXECUTING)).pop(), Some(index));
}

pub(super) extern "win64" fn s_zw_wait_for_single_object(
    handle: u64,
    alertable: u8,
    timeout: u64,
) -> i32 {
    if alertable != 0 { return STATUS_NOT_SUPPORTED_LOCAL as i32; }
    let (timeout_code, timeout_arg) = unsafe { hosted_wait_timeout_payload(timeout) };
    let (label, status, _, _, _) = unsafe { call_on4(
        (FSD_SERVICE_ZW_WAIT_FILE_LABEL << 12) | 4,
        handle, timeout_code, timeout_arg, 0,
    ) };
    if label == 0 { status as u32 as i32 } else { STATUS_INVALID_PARAMETER }
}
