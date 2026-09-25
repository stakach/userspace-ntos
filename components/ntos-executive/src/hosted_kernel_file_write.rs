//! Kernel-driver ZwWriteFile for an authenticated routed File handle.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const HEADER_BYTES: usize = 32;
const STATUS_NOT_SUPPORTED_LOCAL: i32 = 0xc000_00bbu32 as i32;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

// The component owns this exact pool allocation until the retained Call replies.
const LENGTH_OFF: u64 = 0;
const KEY_OFF: u64 = 4;
const OFFSET_OFF: u64 = 8;
const COMPLETED_OFF: u64 = 16;
const STATUS_OFF: u64 = 20;
const INFORMATION_OFF: u64 = 24;

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
    parameters: ReadWriteParameters,
    input: Vec<u8>,
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

fn capture_packet(instance: DriverInstance, packet: u64, length: u64)
    -> Result<(ReadWriteParameters, Vec<u8>), u32>
{
    let total = usize::try_from(length).map_err(|_| STATUS_INVALID_BUFFER_SIZE as u32)?;
    if total < HEADER_BYTES || length >= FSD_POOL_FRAMES * 0x1000 {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let exec = unsafe { hosted_instance_pool_allocation_exec_if_live(instance, packet, length) }
        .ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let bytes = unsafe { read_unaligned((exec + LENGTH_OFF) as *const u32) } as usize;
    if HEADER_BYTES.checked_add(bytes) != Some(total) {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let parameters = ReadWriteParameters {
        length: bytes as u32,
        key: unsafe { read_unaligned((exec + KEY_OFF) as *const u32) },
        offset: unsafe { read_unaligned((exec + OFFSET_OFF) as *const u64) },
    };
    let mut input = Vec::new();
    input.try_reserve_exact(bytes).map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    unsafe {
        input.extend_from_slice(core::slice::from_raw_parts(
            (exec + HEADER_BYTES as u64) as *const u8, bytes,
        ));
    }
    Ok((parameters, input))
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
    let (parameters, input) = match capture_packet(instance, packet, packet_length) {
        Ok(value) => value,
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
    let (file_id, device_id, granted, mut actor) = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
        let target = pm.inspect_native_close_target(caller, handle)?;
        if target.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        let granted = target.information().granted_access.ok_or(STATUS_INVALID_HANDLE as u32)?;
        if granted & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED as u32);
        }
        let actor = pm.reference_native_requestor(caller)?;
        Ok((file_id, device_id, granted, actor))
    }) {
        Ok(value) => value,
        Err(status) => return Some(status as i32),
    };
    let offset_value = parameters.offset as i64;
    let valid_offset = io_manager_mut().file(FileId(file_id)).is_some_and(|file| {
        if file.device_id.raw() != device_id { return false; }
        let synchronous = file.mode_state().io_mode()
            .is_ok_and(|mode| mode.is_synchronous());
        (offset_value >= nt_io_manager::FILE_USE_FILE_POINTER_POSITION)
            && (offset_value != nt_io_manager::FILE_USE_FILE_POINTER_POSITION || synchronous)
            && (granted & (FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) != 0
                || offset_value == nt_io_manager::FILE_WRITE_TO_END_OF_FILE)
    });
    if !valid_offset {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered hosted WRITE actor");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let file = match super::hosted_file_capture::capture(file_id, device_id, granted) {
        Ok(file) => file,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered hosted WRITE actor");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered hosted WRITE actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
        Ok(token) => token,
        Err(_) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered hosted WRITE actor");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let work = Work {
        route, dispatch, reply, token, caller, actor, file, instance,
        domain: nt_io_manager::HostedTransportIdentity {
            domain: channel.physical_domain.expect("authenticated hosted WRITE domain"),
            endpoint: channel.fault_ep, vspace: channel.pml4, shared: channel.shared_va,
        },
        packet, packet_length, parameters, input, entered: false, pending_irp: None,
        terminal: None, cancel_requested: false, reply_entered: false,
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
            .take().expect("unparked hosted WRITE");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked hosted WRITE actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    fn cancelled(&self) -> bool {
        unsafe { runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) }
    }

    unsafe fn release(&mut self, handler: *mut ExecNtHandler) {
        self.actor.release(&mut (*handler).pm).expect("hosted WRITE actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> bool {
        if let Some(irp) = self.pending_irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if completed_irp_exact(irp.raw()).is_none() {
                return false;
            }
            if acknowledge_completed_irp(irp.raw()).is_err() {
                return false;
            }
            self.pending_irp = None;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("hosted WRITE cancellation");
        self.release(handler);
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("hosted WRITE Reply identity");
            if !acked {
                if self.cancelled() { return self.finish_cancelled(handler); }
                return false;
            }
            if let Some(irp) = self.pending_irp {
                if acknowledge_completed_irp(irp.raw()).is_err() {
                    return false;
                }
                self.pending_irp = None;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("hosted WRITE Reply retirement");
            self.release(handler);
            return true;
        }
        if !self.entered {
            if self.cancelled() { return self.finish_cancelled(handler); }
            if let Err(status) = self.actor.validate(&(*handler).pm) {
                self.entered = true;
                self.terminal = Some((status, 0));
            } else {
                (*handler).file_completion.set_signaled(self.file.file_id(), false)
                    .expect("live hosted WRITE File signal");
                self.entered = true;
                match dispatch_hosted_file_read_write_irp_result_exact(
                    self.file.file_id(), major::IRP_MJ_WRITE, self.caller,
                    self.parameters, &self.input, &mut [],
                ) {
                    Ok((_, _, Some(irp), _)) => self.pending_irp = Some(irp),
                    Ok((status, info, None, _)) => self.terminal = Some((status as u32, info)),
                    Err(status) => self.terminal = Some((status, 0)),
                }
            }
        }
        if self.terminal.is_none() {
            if self.cancelled() && !self.cancel_requested {
                self.cancel_requested = true;
                if let Some(irp) = self.pending_irp { let _ = cancel_irp_if_pending(irp.raw()); }
            }
            let Some(irp) = self.pending_irp else { return false; };
            let Some(completion) = completed_irp_exact(irp.raw()) else { return false; };
            if completion.file_id != self.file.file_id()
                || completion.requestor_tid != u64::from(self.caller.original_thread().thread_id())
                || completion.major != major::IRP_MJ_WRITE
            {
                panic!("hosted WRITE terminal identity mismatch");
            }
            self.terminal = Some((completion.status, completion.information));
        }
        if self.cancelled() { return self.finish_cancelled(handler); }
        let (status, information) = self.terminal.expect("hosted WRITE terminal");
        if information > self.parameters.length as u64 {
            panic!("hosted WRITE terminal exceeds submitted byte count");
        }
        let Some((_, live)) = instance_by_shared_va(self.domain.shared) else { return false; };
        let Some(live_domain) = instance_domain_identity(live) else { return false; };
        let live_transport = nt_io_manager::HostedTransportIdentity {
            domain: live_domain, endpoint: live.fault_ep,
            vspace: live.pml4, shared: live.exec_shared_va,
        };
        if !self.domain.matches_live(live_transport)
            || live.exec_pool_va != self.instance.exec_pool_va
        { return false; }
        let Some(exec) = hosted_instance_pool_allocation_exec_if_live(
            live, self.packet, self.packet_length,
        ) else { return false; };
        write_unaligned((exec + STATUS_OFF) as *mut u32, status);
        write_unaligned((exec + INFORMATION_OFF) as *mut u64, information);
        write_unaligned((exec + COMPLETED_OFF) as *mut u32, 1);
        (*handler).file_completion.set_signaled(self.file.file_id(), true)
            .expect("terminal hosted WRITE File signal");
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
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

pub(super) extern "win64" fn s_zw_write_file(
    file_handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    io_status_block: u64,
    buffer: u64,
    length: u32,
    byte_offset: u64,
    key: u64,
) -> i32 {
    if io_status_block == 0 || event != 0 || apc_routine != 0 || apc_context != 0 {
        return STATUS_NOT_SUPPORTED_LOCAL;
    }
    if length != 0 && buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let offset = if byte_offset == 0 {
        nt_io_manager::FILE_USE_FILE_POINTER_POSITION as u64
    } else {
        unsafe { read_unaligned(byte_offset as *const u64) }
    };
    let key = if key == 0 { 0 } else { unsafe { read_unaligned(key as *const u32) } };
    let total = match HEADER_BYTES.checked_add(length as usize) {
        Some(total) if (total as u64) < FSD_POOL_FRAMES * 0x1000 => total,
        _ => return STATUS_INVALID_BUFFER_SIZE as i32,
    };
    let packet = unsafe { pool_alloc(total as u64) };
    if packet == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
    unsafe {
        write_unaligned((packet + LENGTH_OFF) as *mut u32, length);
        write_unaligned((packet + KEY_OFF) as *mut u32, key);
        write_unaligned((packet + OFFSET_OFF) as *mut u64, offset);
        write_unaligned((packet + COMPLETED_OFF) as *mut u32, 0);
        if length != 0 {
            core::ptr::copy_nonoverlapping(
                buffer as *const u8, (packet + HEADER_BYTES as u64) as *mut u8,
                length as usize,
            );
        }
    }
    let (label, status, _, _, _) = unsafe { call_on4(
        (FSD_SERVICE_ZW_WRITE_FILE_LABEL << 12) | 4,
        packet, total as u64, file_handle, 0,
    ) };
    let result = if label == 0 {
        let completed = unsafe { read_unaligned((packet + COMPLETED_OFF) as *const u32) };
        if completed == 1 {
            let terminal = unsafe { read_unaligned((packet + STATUS_OFF) as *const u32) };
            let information = unsafe { read_unaligned((packet + INFORMATION_OFF) as *const u64) };
            unsafe {
                write_unaligned(io_status_block as *mut u32, terminal);
                write_unaligned((io_status_block + 8) as *mut u64, information);
            }
            terminal as i32
        } else { status as u32 as i32 }
    } else { STATUS_INVALID_PARAMETER };
    unsafe { pool_free(packet) };
    result
}
