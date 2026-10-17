//! Independent ordinary worker for a provider export called while its primary dispatch is parked.
//! The worker has its own TCB, Reply, admitted route, request bank, and guarded-call jump buffer.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::peer_registry::PeerRoute;

// This lane's completion must use the ordinary dispatch label: the nested export may call
// GOP and display-ownership services before it returns.
const LABEL: u64 = FSD_DISPATCH_LABEL;
const _: () = assert!(LABEL == FSD_DISPATCH_LABEL);
const _: () = assert!(LABEL != FSD_SERVICE_GOP_QUERY_LABEL);
const _: () = assert!(LABEL != FSD_SERVICE_DISPLAY_OWNERSHIP_LABEL);
const BANK_OFFSET: u64 = FSD_WORKER_KPCR_OFFSET + 0x6000;
const ARG_OFFSET: u64 = BANK_OFFSET + FSD_SHARED_FRAMES * 0x1000;
const JUMP_OFFSET: u64 = 0x900;
const SCRATCH_BANK_OFFSET: u64 = 0xff0;
const ORDINAL_BIT: u64 = 1 << 62;
const _: () = assert!(BANK_OFFSET + FSD_SHARED_FRAMES * 0x1000 <= FSD_WORKER_STRIDE);
const _: () = assert!(ARG_OFFSET + FSD_ARG_FRAMES * 0x1000 <= FSD_WORKER_STRIDE);
const _: () = assert!(JUMP_OFFSET + 3 * 8 <= 0x1000);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Preparing, Ready, Entered, Uncertain, Retiring, Retired }

struct Lane {
    provider: usize,
    domain: HostedDomainIdentity,
    pml4: u64,
    owner: HostedProviderObjectOwner,
    publication: u64,
    ordinal: u64,
    handle: u64,
    route: Option<PeerRoute>,
    component_shared: u64,
    executive_shared: u64,
    phase: Phase,
    startup_dispatch: Option<nt_component_suspension::LaneDispatchIdentity>,
}

static mut LANES: Vec<Lane> = Vec::new();

#[derive(Clone, Copy)]
pub(super) struct Selection {
    index: usize,
    route: PeerRoute,
    pub component_shared: u64,
    pub executive_shared: u64,
    pub provider: usize,
    pub owner: HostedProviderObjectOwner,
    pub publication: u64,
}

unsafe fn index_for(provider: usize, owner: HostedProviderObjectOwner, publication: u64) -> Option<usize> {
    let inst = instance(provider)?;
    let domain = instance_domain_identity(inst)?;
    (&*core::ptr::addr_of!(LANES)).iter().position(|row| {
        row.provider == provider && row.domain == domain && row.pml4 == inst.pml4
            && row.owner == owner && row.publication == publication && row.phase != Phase::Retired
    })
}

pub(super) unsafe fn worker(provider: usize, ordinal: u64) -> Option<HostedDriverThreadRuntime> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.provider == provider && row.ordinal == ordinal && row.phase != Phase::Retired
    })?;
    let inst = instance(provider)?;
    if instance_domain_identity(inst) != Some(row.domain) || inst.pml4 != row.pml4 { return None; }
    (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES)).as_ref()?.iter().copied().find(|runtime| {
        runtime.instance == provider && runtime.domain == row.domain && runtime.pml4 == row.pml4
            && runtime.handle == row.handle
    })
}

pub(super) unsafe fn instance_for_shared(shared: u64) -> Option<(usize, DriverInstance)> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.executive_shared == shared && row.phase != Phase::Retired
    })?;
    let inst = instance(row.provider)?;
    (instance_domain_identity(inst) == Some(row.domain) && inst.pml4 == row.pml4)
        .then_some((row.provider, inst))
}

pub(super) unsafe fn matches_channel(
    provider: usize, inst: DriverInstance, ch: &crate::spawn_hosts::PumpChannel,
) -> bool {
    let Some(domain) = instance_domain_identity(inst) else { return false; };
    let Some(row) = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.provider == provider && row.domain == domain && row.pml4 == inst.pml4
            && row.executive_shared == ch.shared_va && row.route == ch.ingress_route
    }) else { return false; };
    let Some(worker) = worker(provider, row.ordinal) else { return false; };
    row.phase != Phase::Retired && ch.physical_domain == Some(domain)
        && ch.pml4 == row.pml4 && ch.tcb == worker.tcb
        && ch.shared_va == row.executive_shared && ch.ingress_route == row.route
        && row.route.is_some_and(|route| ch.fault_ep == route.endpoint())
}

pub(crate) unsafe fn is_channel(ch: &crate::spawn_hosts::PumpChannel) -> bool {
    instance_for_shared(ch.shared_va)
        .is_some_and(|(index, inst)| matches_channel(index, inst, ch))
}

pub(super) unsafe fn prepare(
    provider: usize, dependent: usize, owner: HostedProviderObjectOwner, publication: u64,
) -> Result<(), nt_status::NtStatus> {
    if publication == 0 || !hosted_provider_object_owner_is_live(owner, provider, dependent) {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    if let Some(index) = index_for(provider, owner, publication) {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        return if row.phase == Phase::Ready && row.route.is_some_and(|route|
            matches!(runtime::ready_for_admission(route), Ok(true))) { Ok(()) }
            else { Err(nt_status::NtStatus::DEVICE_BUSY) };
    }
    let inst = instance(provider).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if !inst.ready || inst.faulted { return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED); }
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let _durable = crate::allocator::enter_durable();
    let index = {
        let rows = &mut *core::ptr::addr_of_mut!(LANES);
        rows.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let ordinal = ORDINAL_BIT | (rows.len() as u64).checked_add(1)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        rows.push(Lane { provider, domain, pml4: inst.pml4, owner, publication, ordinal,
            handle: 0, route: None, component_shared: 0, executive_shared: 0,
            phase: Phase::Preparing, startup_dispatch: None });
        rows.len() - 1
    };
    let result = construct(index, inst);
    (&mut *core::ptr::addr_of_mut!(LANES))[index].phase =
        if result.is_ok() { Phase::Ready } else { Phase::Uncertain };
    result.map_err(|status| nt_status::NtStatus(status as i32))
}

unsafe fn construct(index: usize, inst: DriverInstance) -> Result<(), u32> {
    print_str(b"[dxg-worker] construct\n");
    let (provider, domain, ordinal) = {
        let row = &(&*core::ptr::addr_of!(LANES))[index];
        (row.provider, row.domain, row.ordinal)
    };
    hosted_driver_thread_runtimes_mut().try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let slot = allocate_hosted_driver_component_slot(provider)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    print_str(b"[dxg-worker] slot\n");
    let shared = hosted_worker_component_base_for_slot(slot)
        .and_then(|base| base.checked_add(BANK_OFFSET))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    let handle = hosted_driver_thread_table_mut(provider)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?
        .create(entry as *const () as u64, shared)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    print_str(b"[dxg-worker] handle\n");
    (&mut *core::ptr::addr_of_mut!(LANES))[index].handle = handle;
    let spawn = spawn_hosted_driver_worker_thread_with_shared_bank(
        provider, inst, handle, slot, entry as *const () as u64, shared,
        Some(HostedWorkerSharedBankSpec { offset: BANK_OFFSET, frames: FSD_SHARED_FRAMES,
            arg_offset: Some(ARG_OFFSET) }),
    ).ok_or(STATUS_INSUFFICIENT_RESOURCES as u32)?;
    print_str(b"[dxg-worker] spawn\n");
    let bank = spawn.shared_bank.ok_or(STATUS_INVALID_HANDLE as u32)?;
    if bank.component != shared || bank.arg_component
        != hosted_worker_component_base_for_slot(slot).and_then(|base| base.checked_add(ARG_OFFSET))
        || bank.arg_executive.is_none() { return Err(STATUS_INVALID_HANDLE as u32); }
    print_str(b"[dxg-worker] bank\n");
    hosted_driver_thread_table_mut(provider)
        .ok_or(STATUS_INVALID_HANDLE as u32)?
        .attach_tcb(handle, spawn.tcb)
        .map_err(|error| hosted_driver_thread_error_status(error) as u32)?;
    print_str(b"[dxg-worker] attach\n");
    let worker = HostedDriverThreadRuntime {
        instance: provider, domain, handle, tcb: spawn.tcb, pml4: inst.pml4,
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
    let route = hosted_ingress_sources::enroll_completion(provider, ordinal, spawn.reply_cap)
        .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    print_str(b"[dxg-worker] enroll\n");
    (&mut *core::ptr::addr_of_mut!(LANES))[index].route = Some(route);
    hosted_driver_thread_runtimes_mut().iter_mut()
        .find(|runtime| runtime.instance == provider && runtime.handle == handle)
        .unwrap().ingress_route = Some(route);
    write_volatile((spawn.exec_scratch_va + SCRATCH_BANK_OFFSET) as *mut u64, shared);
    for (offset, value) in [(0x80, ordinal), (0x88, domain.domain_id.raw()),
        (0x90, domain.cookie), (0x98, handle)] {
        write_volatile((bank.executive + offset) as *mut u64, value);
    }
    for offset in [SH_SEH_FOREIGN_CALL2_VA, SH_SEH_FOREIGN_CALL16_VA] {
        write_volatile((bank.executive + offset) as *mut u64,
            read_volatile((inst.exec_shared_va + offset) as *const u64));
    }
    let initial_irql = read_volatile((inst.exec_shared_va + SH_HOSTED_CURRENT_IRQL) as *const u8);
    if initial_irql > 15 { return Err(STATUS_INVALID_HANDLE as u32); }
    write_volatile((bank.executive + SH_HOSTED_CURRENT_IRQL) as *mut u8, initial_irql);
    // Bootstrap, like ordinary nested dispatch, needs exclusive control of the scheduler's
    // running lane. Retain the dependent's live Call and physical hold before resuming this
    // worker, then restore that exact parent even if startup has an uncertain result.
    let mut parent = runtime::nested::park_current().map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    let startup_result = (|| -> Result<(), u32> {
        let startup = runtime::start_bootstrap(route, spawn.cnode, spawn.sched_context)
            .map_err(|_| STATUS_INVALID_HANDLE as u32)?;
        print_str(b"[dxg-worker] bootstrap\n");
        (&mut *core::ptr::addr_of_mut!(LANES))[index].startup_dispatch = Some(startup);
        let caller = hosted_thread_resources::registry_caller(worker)?;
        print_str(b"[dxg-worker] caller\n");
        let ch = channel(index, worker, crate::spawn_hosts::InitialAction::RecvFirst)?;
        print_str(b"[dxg-worker] channel\n");
        let pump = component_scheduler::hosted_component_pump_with_caller(&ch, caller);
        print_str(b"[dxg-worker] startup-pump\n");
        if !pump.completed || pump.status != STATUS_SUCCESS
            || pump.startup_stack_receipt != Some([ordinal, domain.domain_id.raw(),
                domain.cookie, shared, handle]) {
            print_str(b"[dxg-worker] startup-reject completed=");
            print_u64(u64::from(pump.completed));
            print_str(b" status=0x");
            print_hex(pump.status as u32);
            print_str(b" receipt=");
            print_u64(u64::from(pump.startup_stack_receipt.is_some()));
            print_str(b"\n");
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        Ok(())
    })();
    runtime::nested::restore(&mut parent).map_err(|_| STATUS_INVALID_HANDLE as u32)?;
    startup_result
}

unsafe fn channel(index: usize, worker: HostedDriverThreadRuntime,
    initial: crate::spawn_hosts::InitialAction) -> Result<crate::spawn_hosts::PumpChannel, u32> {
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    let route = row.route.ok_or(STATUS_INVALID_HANDLE as u32)?;
    let inst = instance(row.provider).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let window = ExecVaWindow::try_for_instance(row.provider).ok_or(STATUS_INVALID_HANDLE as u32)?;
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
    let worker = worker(row.provider, ordinal)?;
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

pub(super) unsafe fn select(provider: usize, owner: HostedProviderObjectOwner,
    publication: u64) -> Option<Selection> {
    let Some(index) = index_for(provider, owner, publication) else {
        print_str(b"[dxg-worker] select reject=index\n");
        return None;
    };
    let row = &(&*core::ptr::addr_of!(LANES))[index];
    if row.phase != Phase::Ready {
        print_str(b"[dxg-worker] select reject=phase\n");
        return None;
    }
    let Some(route) = row.route else { print_str(b"[dxg-worker] select reject=route\n"); return None; };
    if !matches!(runtime::ready_for_admission(route), Ok(true)) {
        print_str(b"[dxg-worker] select reject=admission\n");
        return None;
    }
    let Some(worker) = worker(provider, row.ordinal) else {
        print_str(b"[dxg-worker] select reject=worker\n");
        return None;
    };
    let Some(primary_route) = hosted_ingress_sources::primary_route(provider) else {
        print_str(b"[dxg-worker] select reject=primary-route\n");
        return None;
    };
    let primary = nt_hosted_runtime::HostedProviderWorkerIdentity::new(
        instance(provider)?.tcb, instance(provider)?.reply_cap,
        instance(provider)?.exec_shared_va, primary_route.endpoint(), primary_route.badge(),
        primary_route.identity().lane.generation)?;
    let candidate = nt_hosted_runtime::HostedProviderWorkerIdentity::new(
        worker.tcb, worker.reply_cap, row.executive_shared, route.endpoint(), route.badge(),
        route.identity().lane.generation)?;
    if nt_hosted_runtime::select_hosted_provider_export_worker(
        owner, publication, row.owner, row.publication, primary, candidate, true).is_none() {
        print_str(b"[dxg-worker] select reject=physical primary-route-badge=");
        print_u64(primary.route_badge);
        print_str(b" worker-route-badge=");
        print_u64(candidate.route_badge);
        print_str(b" primary-route-gen=");
        print_u64(primary.route_generation);
        print_str(b" worker-route-gen=");
        print_u64(candidate.route_generation);
        print_str(b"\n");
        return None;
    }
    Some(Selection { index, route, component_shared: row.component_shared,
        executive_shared: row.executive_shared, provider, owner, publication })
}

pub(super) unsafe fn dispatch(selection: Selection, export_rva: u64,
    args: &[u64; HOSTED_PROVIDER_EXPORT_ARG_CAP], caller_rsp: u64,
    caller: nt_process::native_handle::NativeHandleCaller) -> Result<u64, i32> {
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[selection.index];
    if row.phase != Phase::Ready || row.route != Some(selection.route)
        || row.owner != selection.owner || row.publication != selection.publication
        || row.executive_shared != selection.executive_shared { return Err(STATUS_INVALID_HANDLE); }
    let worker = worker(selection.provider, row.ordinal).ok_or(STATUS_INVALID_HANDLE)?;
    let ch = channel(selection.index, worker, crate::spawn_hosts::InitialAction::ReplyRequest)
        .map_err(|status| status as i32)?;
    let shared = selection.executive_shared;
    write_volatile((shared + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_PROVIDER_EXPORT);
    write_volatile((shared + SH_REQ_MINOR) as *mut u64, export_rva);
    for (offset, value) in [(SH_REQ_FSCTL, args[0]), (SH_REQ_INLEN, args[1]),
        (SH_REQ_OUTLEN, args[2]), (SH_REQ_FILEID, args[3]),
        (SH_PROVIDER_EXPORT_CALLER_RSP, caller_rsp)] {
        write_volatile((shared + offset) as *mut u64, value);
    }
    for index in 0..SH_PROVIDER_EXPORT_STACK_QWORDS {
        write_volatile((shared + SH_PROVIDER_EXPORT_STACK_BASE + index * 8) as *mut u64,
            args[4 + index as usize]);
    }
    for offset in [SH_ACTIVE_IRP, SH_ACTIVE_IOSL, SH_ACTIVE_DATA, SH_ACTIVE_DATA_CAP,
        SH_ACTIVE_FILE_OBJECT] {
        write_volatile((shared + offset) as *mut u64, 0);
    }
    write_volatile((shared + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((shared + SH_REQ_INFO) as *mut u64, 0);
    row.phase = Phase::Entered;
    let pump = component_scheduler::hosted_component_pump_with_caller(&ch, caller);
    let row = &mut (&mut *core::ptr::addr_of_mut!(LANES))[selection.index];
    let completion = nt_hosted_runtime::classify_hosted_provider_export_completion(
        pump.completed, pump.status);
    if row.phase == Phase::Entered && row.route == Some(selection.route) {
        row.phase = if completion == nt_hosted_runtime::HostedProviderExportCompletion::Reusable {
            Phase::Ready
        } else { Phase::Uncertain };
    }
    match completion {
        nt_hosted_runtime::HostedProviderExportCompletion::Reusable =>
            Ok(read_volatile((shared + SH_REQ_INFO) as *const u64)),
        nt_hosted_runtime::HostedProviderExportCompletion::Retain(status) => Err(status),
    }
}

pub(super) unsafe fn begin_worker_retirement(provider: usize, handle: u64) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES)).iter_mut()
        .find(|row| row.provider == provider && row.handle == handle) else { return true; };
    if !matches!(row.phase, Phase::Ready | Phase::Retiring) { return false; }
    row.phase = Phase::Retiring;
    true
}

pub(super) unsafe fn finish_worker_retirement(provider: usize, handle: u64) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(LANES)).iter_mut()
        .find(|row| row.provider == provider && row.handle == handle) {
        if row.phase == Phase::Retiring { row.phase = Phase::Retired; }
    }
}

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

/// Authority for a nested provider import while its independent export worker is executing.
/// The caller separately authenticates the pump's current Reply and badge before using this.
pub(super) unsafe fn authority_for_channel(
    channel: &crate::spawn_hosts::PumpChannel,
) -> Option<(usize, HostedProviderObjectOwner, u64)> {
    let row = (&*core::ptr::addr_of!(LANES)).iter().find(|row| {
        row.executive_shared == channel.shared_va && row.phase == Phase::Entered
            && channel.physical_domain == Some(row.domain)
            && instance(row.provider).is_some_and(|inst| inst.pml4 == row.pml4)
    })?;
    let route = runtime::channel_route(channel).ok()??;
    let source = runtime::physical_source(route).ok()?;
    let worker = worker(row.provider, row.ordinal)?;
    let enrollment = hosted_ingress_sources::enrollment(source)?;
    if row.route != Some(route) || worker.tcb != channel.tcb
        || enrollment.route != Some(route) || source.tcb != worker.tcb
        || source.pml4 != row.pml4
        || !matches!(source.kind, runtime::PhysicalSourceKind::DispatchWorker { ordinal }
            if ordinal == row.ordinal)
        || !row.owner.provider_matches(row.domain.domain_id.raw(), row.domain.cookie)
    { return None; }
    Some((row.provider, row.owner, row.publication))
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
    if current_component_bank() != Some(shared) || request.sel != FSD_DISPATCH_PROVIDER_EXPORT {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(jb) = current_jump_buffer() else { return (STATUS_INVALID_HANDLE, 0); };
    component_dispatch_provider_export_with_bank(shared, jb)
}
