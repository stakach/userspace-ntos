//! Independent ordinary dispatch for a class PortDO reached by i8042's HOOK work item.
//!
//! The class primary thread can be parked in AddDevice waiting for CONNECT. Its shared request
//! bank and Reply are still owned by that AddDevice. This lane retains a different physical TCB,
//! Reply, route and bank before admitting the nested class IRP.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::peer_registry::PeerRoute;

const LABEL: u64 = 0x7bd;
pub(super) const FSD_DISPATCH_DYNAMIC_DELETE: u64 = u64::MAX - 0x7bd;
const BANK_OFFSET: u64 = FSD_WORKER_KPCR_OFFSET + 0x1000;
const ARG_OFFSET: u64 = BANK_OFFSET + 0x1000;
const REQUEST_OFFSET: u64 = 0x800;
const JUMP_OFFSET: u64 = align_up_u64(
    REQUEST_OFFSET + core::mem::size_of::<IrpDispatchRequest>() as u64, 16,
);
const SCRATCH_BANK_OFFSET: u64 = 0xff0;
const ORDINAL_BIT: u64 = 1 << 63;
const _: () = assert!(REQUEST_OFFSET + core::mem::size_of::<IrpDispatchRequest>() as u64 <= JUMP_OFFSET);
const _: () = assert!(JUMP_OFFSET + 3 * 8 <= SCRATCH_BANK_OFFSET);
const _: () = assert!(BANK_OFFSET + 0x1000 <= FSD_WORKER_STRIDE);
const _: () = assert!(ARG_OFFSET + FSD_ARG_FRAMES * 0x1000 <= FSD_WORKER_STRIDE);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Preparing, Ready, Entered, Uncertain, Retiring, Retired }

struct Lane {
    instance: usize,
    domain: HostedDomainIdentity,
    pml4: u64,
    ordinal: u64,
    handle: u64,
    route: Option<PeerRoute>,
    component_shared: u64,
    executive_shared: u64,
    phase: Phase,
    current_irp: Option<u64>,
    startup_dispatch: Option<nt_component_suspension::LaneDispatchIdentity>,
}

static mut LANES: Vec<Lane> = Vec::new();

pub(super) struct Selection {
    pub route: PeerRoute,
    pub shared: u64,
    pub tcb: u64,
    pub request: u64,
    pub label: u64,
    purpose: SelectionPurpose,
}

impl Selection {
    pub(super) fn newly_retains(&self, irp: u64) -> Option<u64> {
        matches!(self.purpose, SelectionPurpose::New).then_some(irp)
    }
}

#[derive(Clone, Copy)]
enum SelectionPurpose { New, Control(u64), Callback }

unsafe fn index_for(instance_index: usize) -> Option<usize> {
    let inst = instance(instance_index)?;
    let domain = instance_domain_identity(inst)?;
    (&*core::ptr::addr_of!(LANES)).iter().position(|row| {
        row.instance == instance_index && row.domain == domain && row.pml4 == inst.pml4
            && row.phase != Phase::Retired
    })
}

pub(super) unsafe fn worker(instance_index: usize, ordinal: u64) -> Option<HostedDriverThreadRuntime> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.instance == instance_index && row.ordinal == ordinal && row.phase != Phase::Retired
    })?;
    let inst = instance(instance_index)?;
    if instance_domain_identity(inst) != Some(row.domain) || inst.pml4 != row.pml4 { return None; }
    (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES)).as_ref()?.iter().copied().find(|runtime| {
        runtime.instance == instance_index && runtime.domain == row.domain
            && runtime.pml4 == row.pml4 && runtime.handle == row.handle
    })
}

pub(super) unsafe fn instance_for_shared(shared: u64) -> Option<(usize, DriverInstance)> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.executive_shared == shared && row.phase != Phase::Retired
    })?;
    let inst = instance(row.instance)?;
    (instance_domain_identity(inst) == Some(row.domain) && inst.pml4 == row.pml4)
        .then_some((row.instance, inst))
}

pub(super) unsafe fn matches_channel(
    instance_index: usize, inst: DriverInstance, ch: &crate::spawn_hosts::PumpChannel,
) -> bool {
    let Some(domain) = instance_domain_identity(inst) else { return false; };
    let Some(row) = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.instance == instance_index && row.domain == domain && row.pml4 == inst.pml4
            && row.executive_shared == ch.shared_va && row.route == ch.ingress_route
    }) else { return false; };
    let Some(worker) = worker(instance_index, row.ordinal) else { return false; };
    row.phase != Phase::Retired && ch.physical_domain == Some(domain)
        && ch.pml4 == row.pml4 && ch.tcb == worker.tcb
        && ch.shared_va == row.executive_shared && ch.ingress_route == row.route
        && row.route.is_some_and(|route| ch.fault_ep == route.endpoint())
}

pub(crate) unsafe fn is_channel(ch: &crate::spawn_hosts::PumpChannel) -> bool {
    instance_for_shared(ch.shared_va)
        .is_some_and(|(index, inst)| matches_channel(index, inst, ch))
}

pub(super) unsafe fn prepare(instance_index: usize) -> Result<(), nt_status::NtStatus> {
    if let Some(index) = index_for(instance_index) {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        return if row.phase == Phase::Ready && row.route.is_some_and(|route|
            matches!(runtime::ready_for_admission(route), Ok(true))) { Ok(()) }
            else { Err(nt_status::NtStatus::DEVICE_BUSY) };
    }
    let inst = instance(instance_index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if !inst.ready || inst.faulted { return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED); }
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let _durable = crate::allocator::enter_durable();
    let index = {
        let rows = &mut *core::ptr::addr_of_mut!(LANES);
        rows.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let ordinal = ORDINAL_BIT | (rows.len() as u64).checked_add(1)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        rows.push(Lane { instance: instance_index, domain, pml4: inst.pml4, ordinal, handle: 0,
            route: None, component_shared: 0, executive_shared: 0, phase: Phase::Preparing,
            current_irp: None, startup_dispatch: None });
        rows.len() - 1
    };
    let result = construct(index, inst);
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    row.phase = if result.is_ok() { Phase::Ready } else { Phase::Uncertain };
    trace_startup_return(row, result.as_ref().err().copied().unwrap_or(0));
    result.map_err(|status| nt_status::NtStatus(status as i32))
}

fn trace_startup_return(row: &Lane, status: u32) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    print_str(b"[class-startup-return] instance/ordinal/phase/status=");
    print_u64(row.instance as u64); print_str(b"/");
    print_u64(row.ordinal); print_str(b"/");
    print_u64(match row.phase { Phase::Ready => 1, Phase::Uncertain => 2, _ => 0 });
    print_str(b"/"); print_hex(status); print_str(b"\n");
}

unsafe fn construct(index: usize, inst: DriverInstance) -> Result<(), u32> {
    let (instance_index, domain, ordinal) = {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        (row.instance, row.domain, row.ordinal)
    };
    hosted_driver_thread_runtimes_mut().try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let slot = allocate_hosted_driver_component_slot(instance_index)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let shared = hosted_worker_component_base_for_slot(slot)
        .and_then(|base| base.checked_add(BANK_OFFSET))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let handle = hosted_driver_thread_table_mut(instance_index)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?
        .create(entry as *const () as u64, shared)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].handle = handle;
    let spawn = spawn_hosted_driver_worker_thread_with_shared_bank(
        instance_index, inst, handle, slot, entry as *const () as u64, shared,
        Some(HostedWorkerSharedBankSpec { offset: BANK_OFFSET, frames: 1,
            arg_offset: Some(ARG_OFFSET) }),
    ).ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let bank = spawn.shared_bank.ok_or(STATUS_INVALID_HANDLE as u32)?;
    if bank.component != shared || bank.arg_component
        != hosted_worker_component_base_for_slot(slot).and_then(|base| base.checked_add(ARG_OFFSET))
        || bank.arg_executive.is_none() { return Err(STATUS_INVALID_HANDLE as u32); }
    hosted_driver_thread_table_mut(instance_index)
        .ok_or(STATUS_INVALID_HANDLE as u32)?
        .attach_tcb(handle, spawn.tcb)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    let worker = HostedDriverThreadRuntime {
        instance: instance_index, domain, handle, tcb: spawn.tcb, pml4: inst.pml4,
        reply_cap: spawn.reply_cap, ingress_route: None, construction: spawn.construction,
        component_slot: spawn.component_slot, exec_alias_slot: spawn.exec_alias_slot,
        component_scratch_va: spawn.component_scratch_va, exec_scratch_va: spawn.exec_scratch_va,
        raw_cnode: spawn.raw_cnode, cnode: spawn.cnode, sched_context: spawn.sched_context,
    };
    hosted_driver_thread_runtimes_mut().push(worker);
    {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        row.component_shared = shared;
        row.executive_shared = bank.executive;
    }
    hosted_thread_resources::enter_shared(spawn.construction, spawn.reply_cap);
    let route = hosted_ingress_sources::enroll_completion(instance_index, ordinal, spawn.reply_cap)
        .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].route = Some(route);
    hosted_driver_thread_runtimes_mut().iter_mut()
        .find(|runtime| runtime.instance == instance_index && runtime.handle == handle)
        .unwrap().ingress_route = Some(route);
    write_volatile((spawn.exec_scratch_va + SCRATCH_BANK_OFFSET) as *mut u64, shared);
    for (offset, value) in [(0x80, ordinal), (0x88, domain.domain_id.raw()),
        (0x90, domain.cookie), (0x98, handle)] {
        write_volatile((bank.executive + offset) as *mut u64, value);
    }
    write_volatile((bank.executive + SH_SEH_FOREIGN_CALL2_VA) as *mut u64,
        read_volatile((inst.exec_shared_va + SH_SEH_FOREIGN_CALL2_VA) as *const u64));
    let startup = runtime::start_bootstrap(route, spawn.cnode, spawn.sched_context)
        .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    (&mut *core::ptr::addr_of_mut!(LANES))[index].startup_dispatch = Some(startup);
    let caller = hosted_thread_resources::registry_caller(worker)?;
    let ch = channel(index, worker, crate::spawn_hosts::InitialAction::RecvFirst)?;
    let pump = component_scheduler::hosted_component_pump_with_caller(&ch, caller);
    if !pump.completed || pump.status != STATUS_SUCCESS
        || pump.startup_stack_receipt != Some([ordinal, domain.domain_id.raw(),
            domain.cookie, shared, handle]) {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    Ok(())
}

unsafe fn channel(index: usize, worker: HostedDriverThreadRuntime,
    initial: crate::spawn_hosts::InitialAction) -> Result<crate::spawn_hosts::PumpChannel, u32> {
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    let route = row.route.ok_or(STATUS_INVALID_HANDLE as u32)?;
    let inst = instance(row.instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let window = ExecVaWindow::try_for_instance(row.instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    Ok(crate::spawn_hosts::PumpChannel {
        fault_ep: route.endpoint(), pml4: row.pml4, physical_domain: Some(row.domain),
        ingress_route: Some(route), code_va: 0, image_frames: 0, exec_code_va: window.code_va,
        root_image_rights: 3, root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: row.executive_shared, dispatch_label: LABEL, demand_cap: 256,
        trace_faults: false, initial, tcb: worker.tcb,
        reply_cap: runtime::current_reply(route).map_err(|_| STATUS_INVALID_HANDLE as u32)?,
        client_pi: 0, client_generation: 0, logical_caller: None, kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps { dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp, ..crate::spawn_hosts::HostCaps::default() },
    })
}

pub(crate) unsafe fn startup_expected(ch: &crate::spawn_hosts::PumpChannel) -> Option<[u64; 5]> {
    if ch.initial != crate::spawn_hosts::InitialAction::RecvFirst
        || ch.caps.kind != crate::spawn_hosts::ReqKind::Irp || ch.dispatch_label != LABEL { return None; }
    let route = runtime::channel_route(ch).ok()??;
    let source = runtime::physical_source(route).ok()?;
    let runtime::PhysicalSourceKind::DispatchWorker { ordinal } = source.kind else { return None; };
    let runtime::PhysicalDomain::Hosted(domain) = source.domain else { return None; };
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.phase == Phase::Preparing && row.route == Some(route) && row.domain == domain
            && row.pml4 == source.pml4 && row.ordinal == ordinal
            && row.executive_shared == ch.shared_va
    })?;
    let worker = worker(row.instance, ordinal)?;
    let enrollment = hosted_ingress_sources::enrollment(source)?;
    if worker.tcb != ch.tcb || source.tcb != ch.tcb || ch.physical_domain != Some(domain)
        || worker.handle != row.handle || enrollment.cnode != worker.cnode
        || enrollment.route != Some(route)
        || !matches!(runtime::dispatch(route), Ok(current) if Some(current) == row.startup_dispatch)
    { return None; }
    Some([ordinal, domain.domain_id.raw(), domain.cookie, row.component_shared, row.handle])
}

pub(crate) unsafe fn validate_startup_ready(ch: &crate::spawn_hosts::PumpChannel,
    words: [u64; 5]) -> bool {
    if startup_expected(ch) != Some(words) { return false; }
    let Ok(Some(route)) = runtime::channel_route(ch) else { return false; };
    let Ok(current) = runtime::current_reply(route) else { return false; };
    let Ok(Some((incoming, message))) = runtime::next_message(route) else { return false; };
    current != 0 && incoming != 0 && current != incoming && message.badge() == route.badge()
        && message.info() == (LABEL << 12) | 5
        && words.iter().enumerate().all(|(index, word)| message.word(index) == Some(*word))
        && matches!(crate::spawn_hosts::query_component_reply_binding(ch.tcb, current),
            Ok(nt_component_suspension::ReplyBindingObservation::Free))
        && matches!(crate::spawn_hosts::query_component_reply_binding(ch.tcb, incoming),
            Ok(nt_component_suspension::ReplyBindingObservation::BoundToTarget))
}

unsafe fn select(instance_index: usize, purpose: SelectionPurpose) -> Option<Selection> {
    let index = index_for(instance_index)?;
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    if row.phase != Phase::Ready { return None; }
    match purpose {
        SelectionPurpose::New if row.current_irp.is_some() => return None,
        SelectionPurpose::Control(irp) if row.current_irp != Some(irp) => return None,
        SelectionPurpose::Callback if row.current_irp.is_some() => return None,
        _ => {}
    }
    let route = row.route?;
    if !matches!(runtime::ready_for_admission(route), Ok(true)) { return None; }
    let worker = worker(instance_index, row.ordinal)?;
    Some(Selection { route, shared: row.executive_shared, tcb: worker.tcb,
        request: row.executive_shared + REQUEST_OFFSET, label: LABEL, purpose })
}

pub(super) unsafe fn select_new(instance_index: usize) -> Option<Selection> {
    select(instance_index, SelectionPurpose::New)
}

pub(super) unsafe fn select_callback(instance_index: usize) -> Option<Selection> {
    select(instance_index, SelectionPurpose::Callback)
}

/// Execute one PASSIVE_LEVEL callback on the worker's independent TCB, Reply, and bank. The
/// caller must retain its exact callback ticket before entering this uncertain native effect.
pub(super) unsafe fn dispatch_callback(
    instance_index: usize, selection: &Selection, callback: u64, object: u64,
) -> bool {
    let Some(index) = index_for(instance_index) else { return false; };
    let Some(worker) = worker(instance_index, (&*core::ptr::addr_of!(LANES))[index].ordinal)
    else { return false; };
    let Some(inst) = instance(instance_index) else { return false; };
    if selection.shared != (&*core::ptr::addr_of!(LANES))[index].executive_shared
        || callback == 0 || object == 0
    { return false; }
    let Some(caller) = hosted_thread_resources::registry_caller(worker).ok() else {
        return false;
    };
    let Ok(ch) = channel(index, worker, crate::spawn_hosts::InitialAction::ReplyRequest)
    else { return false; };
    write_volatile((selection.shared + SH_DRVOBJ) as *mut u64, selection.shared);
    write_volatile((selection.shared + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_DYNAMIC_DELETE);
    write_volatile((selection.shared + SH_REQ_MINOR) as *mut u64, callback);
    write_volatile((selection.shared + SH_REQ_FILEID) as *mut u64, object);
    write_volatile((selection.shared + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((selection.shared + SH_REQ_INFO) as *mut u64, 0);
    if instance_domain_identity(inst) != Some((&*core::ptr::addr_of!(LANES))[index].domain)
        || !mark_entered(instance_index, selection, None)
    { return false; }
    let result = component_scheduler::hosted_component_pump_with_caller(&ch, caller);
    finish(instance_index, selection, result.completed);
    result.completed && result.status == STATUS_SUCCESS
}

pub(super) unsafe fn select_control(instance_index: usize, irp: u64) -> Option<Selection> {
    select(instance_index, SelectionPurpose::Control(irp))
}

/// A canonical completed CONNECT first enters this worker for its ACK. A refused ACK leaves
/// the same IRP reserved here, so only its exact retry can use the lane thereafter.
pub(super) unsafe fn select_completion_control(instance_index: usize, irp: u64) -> Option<Selection> {
    if owns_irp(instance_index, irp) {
        select_control(instance_index, irp)
    } else {
        select_new(instance_index)
    }
}

pub(super) unsafe fn owns_irp(instance_index: usize, irp: u64) -> bool {
    index_for(instance_index).is_some_and(|index| {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        row.current_irp == Some(irp) && row.phase != Phase::Retired
    })
}

pub(super) unsafe fn mark_entered(instance_index: usize, selection: &Selection,
    irp: Option<u64>) -> bool {
    let Some(index) = index_for(instance_index) else { return false; };
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    if row.phase != Phase::Ready || row.route != Some(selection.route)
        || row.executive_shared != selection.shared { return false; }
    match selection.purpose {
        SelectionPurpose::New if irp.is_none() || row.current_irp.is_some() => return false,
        SelectionPurpose::Control(expected) if irp.is_some()
            || row.current_irp != Some(expected) => return false,
        SelectionPurpose::Callback if irp.is_some() || row.current_irp.is_some() => return false,
        _ => {}
    }
    row.phase = Phase::Entered;
    if let Some(irp) = irp { row.current_irp = Some(irp); }
    true
}

pub(super) unsafe fn finish(instance_index: usize, selection: &Selection, completed: bool) {
    let Some(index) = index_for(instance_index) else { return; };
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
    if row.phase == Phase::Entered && row.route == Some(selection.route)
        && row.executive_shared == selection.shared {
        row.phase = if completed { Phase::Ready } else { Phase::Uncertain };
    }
}

pub(super) unsafe fn acknowledged(instance_index: usize, irp: u64) {
    if let Some(index) = index_for(instance_index) {
        let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[index];
        if row.phase == Phase::Ready && row.current_irp == Some(irp) {
            row.current_irp = None;
        }
    }
}

pub(super) unsafe fn begin_worker_retirement(instance_index: usize, handle: u64) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES)).iter_mut()
        .find(|row| row.instance == instance_index && row.handle == handle)
    else { return true; };
    if !matches!(row.phase, Phase::Ready | Phase::Retiring) || row.current_irp.is_some() {
        return false;
    }
    row.phase = Phase::Retiring;
    true
}

pub(super) unsafe fn finish_worker_retirement(instance_index: usize, handle: u64) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES)).iter_mut()
        .find(|row| row.instance == instance_index && row.handle == handle) {
        if row.phase == Phase::Retiring { row.phase = Phase::Retired; }
    }
}

/// Only the dedicated class worker has this bank. Every ordinary worker has the scratch page,
/// so a zero marker on unrelated workers is safe to read. The parent primary has no worker stack.
pub(super) fn current_component_bank() -> Option<u64> {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags)); }
    let base = hosted_worker_component_base_from_rsp(rsp)?;
    let marker = unsafe { read_volatile((base + FSD_WORKER_SCRATCH_OFFSET + SCRATCH_BANK_OFFSET) as *const u64) };
    (marker == base + BANK_OFFSET).then_some(marker)
}

pub(super) fn current_jump_buffer() -> Option<*mut u64> {
    current_component_bank().map(|shared| (shared + JUMP_OFFSET) as *mut u64)
}

pub(super) fn current_component_arg() -> Option<u64> {
    current_component_bank().map(|shared| shared + (ARG_OFFSET - BANK_OFFSET))
}

pub(super) unsafe fn executive_arg_for_shared(shared: u64) -> Option<u64> {
    (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.executive_shared == shared && row.phase != Phase::Retired
    }).map(|row| row.executive_shared + (ARG_OFFSET - BANK_OFFSET))
}

unsafe extern "win64" fn entry(shared: u64) {
    let ready = [read_volatile((shared + 0x80) as *const u64),
        read_volatile((shared + 0x88) as *const u64),
        read_volatile((shared + 0x90) as *const u64), shared,
        read_volatile((shared + 0x98) as *const u64)];
    crate::spawn_hosts::component_dispatch_loop_with_ready(
        shared, shared, SH_REQ_STATUS, LABEL, execute, Some(ready))
}

unsafe fn execute(request: &crate::spawn_hosts::DispatchReq) -> (i32, u64) {
    let shared = request.drv;
    if current_component_bank() != Some(shared) { return (STATUS_INVALID_PARAMETER, 0); }
    if request.sel == FSD_DISPATCH_DYNAMIC_DELETE {
        let callback = read_volatile((shared + SH_REQ_MINOR) as *const u64);
        let object = read_volatile((shared + SH_REQ_FILEID) as *const u64);
        if callback == 0 || object == 0 { return (STATUS_INVALID_PARAMETER, 0); }
        let Some(jb) = current_jump_buffer() else { return (STATUS_INVALID_HANDLE, 0); };
        let boundary = read_volatile((FSD_SHARED_VADDR + SH_SEH_FOREIGN_CALL16_VA) as *const u64);
        if boundary == 0 { return (STATUS_INVALID_DEVICE_REQUEST, 0); }
        write_volatile(jb, 0);
        write_volatile(jb.add(1), 0);
        write_volatile(jb.add(2), 0);
        let args = [object, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        fsd_guarded_call_vector(callback, args.as_ptr(), 12, jb, boundary);
        if read_volatile(jb.add(2)) != 0 { return (STATUS_UNSUCCESSFUL, 0); }
        return (STATUS_SUCCESS, 0);
    }
    let irp = read_volatile((shared + SH_REQ_CONTROL_ID) as *const u64);
    if matches!(request.sel, FSD_DISPATCH_COPY_MUTABLE_INPUT | FSD_DISPATCH_COPY_COMPLETION
        | FSD_DISPATCH_ACK_COMPLETION | FSD_DISPATCH_CANCEL_IRP) {
        if irp == 0 { return (STATUS_INVALID_PARAMETER, 0); }
        let offset = read_volatile((shared + SH_REQ_FSCTL) as *const u64);
        let capacity = read_volatile((shared + SH_REQ_OUTLEN) as *const u64);
        return match request.sel {
            FSD_DISPATCH_COPY_MUTABLE_INPUT =>
                hosted_mutable_input_completion::copy(irp, offset, capacity),
            FSD_DISPATCH_COPY_COMPLETION => copy_pending_irp_completion(irp, offset, capacity),
            FSD_DISPATCH_CANCEL_IRP => {
                let cancelled = cancel_pending_irp(irp);
                (if cancelled { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER },
                    u64::from(cancelled))
            }
            FSD_DISPATCH_ACK_COMPLETION => {
                let acknowledged = if let Some(graph_released) =
                    hosted_mutable_input_completion::graph_released(irp) {
                    (graph_released || acknowledge_pending_irp_completion(irp))
                        && hosted_mutable_input_completion::acknowledge(irp)
                } else { acknowledge_pending_irp_completion(irp) };
                (if acknowledged { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }, 0)
            }
            _ => unreachable!(),
        };
    }
    if request.sel != major::IRP_MJ_INTERNAL_DEVICE_CONTROL as u64
        && request.sel != major::IRP_MJ_CREATE as u64 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let driver = read_volatile((shared + SH_DRVOBJ) as *const u64);
    if driver == 0 || component_pool_allocation_capacity(driver)
        .is_none_or(|bytes| bytes < WDM_X64_DRIVER_OBJECT_SIZE as u64) {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let handler = read_unaligned((driver + WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET as u64
        + request.sel * 8) as *const u64);
    if handler == 0 { return (STATUS_INVALID_DEVICE_REQUEST as i32, 0); }
    run_irp_with_bank(request.sel, handler, shared, shared + REQUEST_OFFSET)
}
