//! Retained GDI system-image acquisition after the installed mount has a native provider.
//!
//! The provider's original Call owns its Reply until each mounted File read and native
//! completion ACK has settled. PE mapping begins only after the dependency snapshots are
//! complete, so a missing forwarder cannot cause a second mapping effect on retry.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_pe_loader::{
    module_namespace::{self, ExportTarget, ImageExports, Symbol},
    system_image_load_plan::{LoadAction, LoadPlanError, SystemImageLoadPlan},
    ImportRef, PeFile,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

use crate::{
    allocator, mounted_system_image_read::{MountedSystemImageRead, SnapshotStep},
    spawn_hosts, win32k_glue, win32k_seh_image, win32k_subsystem, ExecNtHandler,
};
use spawn_hosts::shared_ingress::owner::runtime::{self, PhysicalDomain, PhysicalSource};

const INVALID: u32 = 0xc000_000d;
const RESOURCES: u32 = 0xc000_009a;
const CANCELLED: u32 = 0xc000_0120;
const RETRY_100NS: u64 = 1_000_000;

fn plan_error_status(error: LoadPlanError) -> u32 {
    match error {
        LoadPlanError::NoCapacity => RESOURCES,
        LoadPlanError::InvalidName | LoadPlanError::WrongCompletion | LoadPlanError::Cycle => {
            0xc000_007bu32
        }
    }
}

pub(crate) enum SubmitResult {
    Ready((i32, u64)),
    Deferred,
}

enum Phase {
    WaitNative,
    Plan,
    Read { name: String, read: MountedSystemImageRead },
    ReadyReply,
    ReplyEntered,
}

struct Work {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    caller: NativeHandleCaller,
    reference: Option<NativeThreadProcessReference>,
    source: PhysicalSource,
    packet: win32k_subsystem::ProviderPoolPacketLease,
    root: String,
    plan: SystemImageLoadPlan,
    catalog: Vec<win32k_glue::image_loader::ImageSnapshot>,
    phase: Phase,
    status: i32,
    module: u64,
    mapped_effect: bool,
    indeterminate: bool,
}

static mut WORK: Vec<Work> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit_routed_gdi_image(
    route: PeerRoute, dispatch: LaneDispatchIdentity, reply: u64,
    caller: NativeHandleCaller, source: PhysicalSource, packet: u64, length: u64,
) -> SubmitResult {
    use nt_pe_loader::system_image_request::{self, Request};
    let _durable = allocator::enter_durable();
    if length != system_image_request::PACKET_BYTES as u64 {
        return SubmitResult::Ready((INVALID as i32, 0));
    }
    let Ok((lease, bytes)) = win32k_subsystem::capture_provider_pool_packet(packet, length as usize)
    else { return SubmitResult::Ready((INVALID as i32, 0)); };
    let root = match system_image_request::decode(&bytes) {
        Some(Request::Load(root)) => root,
        Some(Request::Unload(_)) => return SubmitResult::Ready(
            win32k_glue::image_loader::service_request(packet, length, source),
        ),
        None => return SubmitResult::Ready((INVALID as i32, 0)),
    };
    if !win32k_subsystem::provider_pool_packet_lease_live(lease) {
        return SubmitResult::Ready((INVALID as i32, 0));
    }
    let Ok(plan) = SystemImageLoadPlan::new(&root)
    else { return SubmitResult::Ready((INVALID as i32, 0)); };
    let Ok(token) = runtime::next_service_wait_token()
    else { return SubmitResult::Ready((RESOURCES as i32, 0)); };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    if rows.try_reserve(1).is_err() {
        return SubmitResult::Ready((RESOURCES as i32, 0));
    }
    rows.push(Work {
        route, dispatch, reply, token, caller, reference: None, source, packet: lease,
        root, plan, catalog: Vec::new(), phase: Phase::WaitNative, status: 0, module: 0,
        mapped_effect: false, indeterminate: false,
    });
    if runtime::park_retained_service(route, token).is_err() {
        rows.pop().expect("unparked GDI image owner");
        return SubmitResult::Ready((RESOURCES as i32, 0));
    }
    NEXT_RETRY.store(crate::monotonic_time_100ns(), Ordering::Release);
    SubmitResult::Deferred
}

pub(crate) fn next_deadline() -> Option<u64> {
    // An uncertain native effect must keep its owner, but cannot make autonomous progress.
    // Other queued requests remain eligible while an indeterminate owner is retained.
    unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(|work| !work.indeterminate) }
        .then(|| NEXT_RETRY.load(Ordering::Acquire))
}

pub(crate) fn has_outstanding() -> bool {
    ACTIVE.load(Ordering::Acquire)
        || unsafe { !(&*core::ptr::addr_of!(WORK)).is_empty() }
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

fn snapshot<'a>(catalog: &'a [win32k_glue::image_loader::ImageSnapshot], name: &str)
    -> Option<&'a win32k_glue::image_loader::ImageSnapshot>
{
    catalog.iter().find(|snapshot| snapshot.name == name)
}

fn dependencies(bytes: &[u8]) -> Result<Vec<String>, u32> {
    let pe = PeFile::parse(bytes).map_err(|_| 0xc000_007bu32)?;
    pe.imports().map_err(|_| 0xc000_007bu32)?.into_iter().map(|dll| {
        module_namespace::module_leaf(&dll.name).map_err(|_| 0xc000_007bu32)
    }).collect()
}

unsafe fn exports_for(
    name: &str, pml4: u64,
) -> Result<Option<ImageExports>, u32> {
    if name == "win32k.sys" {
        return win32k_seh_image::win32k_exports(pml4)
            .map(Some).ok_or(0xc000_00a3u32);
    }
    Ok(win32k_glue::image_loader::loaded_exports(name, pml4))
}

/// Inspect the exact imported symbol's forwarder chain before any native map effect. An
/// unacquired target becomes another `SystemImageLoadPlan` read/map action.
unsafe fn missing_forwarder(
    module: &str, symbol: Symbol, pml4: u64,
    seen: &mut Vec<(String, Symbol)>,
) -> Result<Option<String>, u32> {
    let module = module_namespace::module_leaf(module).map_err(|_| 0xc000_007bu32)?;
    if seen.len() >= 64 || seen.iter().any(|pair| pair.0 == module && pair.1 == symbol) {
        return Err(0xc000_007bu32);
    }
    seen.push((module.clone(), symbol.clone()));
    if module_namespace::core_role(&module).is_some() { return Ok(None); }
    let Some(exports) = exports_for(&module, pml4)?
    else { return Ok(Some(module)); };
    let export = exports.exports.iter().find(|export| match &symbol {
        Symbol::Name(name) => export.name == *name,
        Symbol::Ordinal(ordinal) => export.ordinal == *ordinal,
    }).ok_or(0xc000_0139u32)?;
    let ExportTarget::Forwarder(target) = &export.target else { return Ok(None); };
    let (module, name) = target.rsplit_once('.').ok_or(0xc000_007bu32)?;
    let module = module_namespace::forwarder_module(module).map_err(|_| 0xc000_007bu32)?;
    if !win32k_glue::image_loader::loaded_image(&module, pml4) && module != "win32k.sys"
        && module_namespace::core_role(&module).is_none()
    {
        return Ok(Some(module));
    }
    let symbol = if let Some(ordinal) = name.strip_prefix('#') {
        Symbol::Ordinal(ordinal.parse().map_err(|_| 0xc000_007bu32)?)
    } else {
        Symbol::Name(String::from(name))
    };
    missing_forwarder(&module, symbol, pml4, seen)
}

unsafe fn preflight_map(
    name: &str, pml4: u64, catalog: &[win32k_glue::image_loader::ImageSnapshot],
) -> Result<Option<String>, u32> {
    let Some(source) = snapshot(catalog, name) else { return Err(0xc000_0034u32); };
    let pe = PeFile::parse(&source.bytes).map_err(|_| 0xc000_007bu32)?;
    for dll in pe.imports().map_err(|_| 0xc000_007bu32)? {
        for function in dll.functions {
            let symbol = match function {
                ImportRef::ByName { name, .. } => Symbol::Name(name),
                ImportRef::ByOrdinal { ordinal, .. } => Symbol::Ordinal(ordinal),
            };
            if let Some(missing) = missing_forwarder(&dll.name, symbol, pml4, &mut Vec::new())? {
                return Ok(Some(missing));
            }
        }
    }
    Ok(None)
}

enum Step { Progress, Wait, Finished }

impl Work {
    unsafe fn finish_cancelled(&mut self, handler: &mut ExecNtHandler) -> Step {
        if runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).is_err() {
            self.indeterminate = true;
            return Step::Wait;
        }
        if let Some(mut reference) = self.reference.take() {
            reference.release(&mut handler.pm)
                .expect("cancelled GDI provider requestor retirement");
        }
        // The native mapping and load reference have no teardown operation yet. Keep their
        // exact provider/image owner after the Call is cancelled, without arming a retry timer.
        if self.mapped_effect || self.module != 0 {
            self.indeterminate = true;
            return Step::Wait;
        }
        Step::Finished
    }

    unsafe fn advance(&mut self, handler: &mut ExecNtHandler) -> Step {
        if self.indeterminate { return Step::Wait; }
        let cancelled = runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        );
        if cancelled {
            match self.phase {
                Phase::WaitNative | Phase::Plan => {
                    self.status = CANCELLED as i32;
                    self.phase = Phase::ReadyReply;
                    return Step::Progress;
                }
                Phase::ReadyReply | Phase::ReplyEntered => {
                    return self.finish_cancelled(handler);
                }
                Phase::Read { .. } => {} // The mounted File owner must drain its exact I/O first.
            }
        }
        if self.reference.is_none()
            && matches!(self.phase, Phase::WaitNative | Phase::Plan | Phase::Read { .. })
        {
            match handler.pm.reference_native_requestor(self.caller) {
                Ok(reference) => self.reference = Some(reference),
                Err(status) => {
                    self.status = status as i32;
                    self.phase = Phase::ReadyReply;
                    return Step::Progress;
                }
            }
        }
        if !cancelled && (!win32k_subsystem::provider_pool_packet_lease_live(self.packet)
            || runtime::physical_source(self.route).ok() != Some(self.source)
            || !matches!(self.source.domain, PhysicalDomain::Provider { domain, .. }
                if crate::win32k_provider_domain_is_current(domain))) {
            self.indeterminate = true;
            return Step::Wait;
        }
        match &mut self.phase {
            Phase::WaitNative => {
                if cancelled {
                    self.status = CANCELLED as i32;
                    self.phase = Phase::ReadyReply;
                    return Step::Progress;
                }
                let route = crate::fs_loader::exec_fs_mount_identity().and_then(
                    crate::fs_loader::exec_block_route_kind,
                );
                if route == Some(nt_fs::BlockSourceKind::Native) {
                    self.phase = Phase::Plan;
                    Step::Progress
                } else {
                    Step::Wait
                }
            }
            Phase::Plan => {
                if cancelled {
                    self.status = CANCELLED as i32;
                    self.phase = Phase::ReadyReply;
                    return Step::Progress;
                }
                match self.plan.next() {
                    Some(LoadAction::ReadMountedFile(name)) => {
                        if win32k_glue::image_loader::loaded_image(&name, self.source.pml4) {
                            if self.plan.skip_loaded(&name).is_err() {
                                self.indeterminate = true;
                                return Step::Wait;
                            }
                            return Step::Progress;
                        }
                        if let Some(snapshot) = snapshot(&self.catalog, &name) {
                            let dependencies = match dependencies(&snapshot.bytes) {
                                Ok(dependencies) => dependencies,
                                Err(status) => {
                                    self.status = status as i32;
                                    self.phase = Phase::ReadyReply;
                                    return Step::Progress;
                                }
                            };
                            let names: Vec<&str> = dependencies.iter().map(String::as_str).collect();
                            if let Err(error) = self.plan.file_ready(&name, &names) {
                                self.status = plan_error_status(error) as i32;
                                self.phase = Phase::ReadyReply;
                                return Step::Progress;
                            }
                            return Step::Progress;
                        }
                        match MountedSystemImageRead::new(&name) {
                            Ok(read) => self.phase = Phase::Read { name, read },
                            Err(status) => {
                                self.status = status as i32;
                                self.phase = Phase::ReadyReply;
                            }
                        }
                        Step::Progress
                    }
                    Some(LoadAction::Map(name)) => {
                        match preflight_map(&name, self.source.pml4, &self.catalog) {
                            Ok(Some(missing)) => {
                                if self.plan.require_dependency(&name, &missing).is_err() {
                                    self.status = 0xc000_007bu32 as i32;
                                    self.phase = Phase::ReadyReply;
                                }
                            }
                            Ok(None) => {
                                match win32k_glue::image_loader::load_installed_from_catalog(
                                    &name, self.source.pml4, &self.catalog,
                                ) {
                                    Err(error) => {
                                        self.status = error.ntstatus();
                                        self.phase = Phase::ReadyReply;
                                    }
                                    Ok(_) => {
                                        self.mapped_effect = true;
                                        if self.plan.mapped(&name).is_err() {
                                            self.indeterminate = true;
                                            return Step::Wait;
                                        }
                                    }
                                }
                            }
                            Err(status) => {
                                self.status = status as i32;
                                self.phase = Phase::ReadyReply;
                            }
                        }
                        Step::Progress
                    }
                    None => {
                        let (status, module) = win32k_glue::image_loader::load_catalog_and_publish(
                            &self.root, self.source.pml4, &self.catalog,
                        );
                        self.status = status;
                        self.module = module;
                        self.phase = Phase::ReadyReply;
                        Step::Progress
                    }
                }
            }
            Phase::Read { name, read } => {
                if cancelled { read.request_cancel(); }
                match read.advance() {
                    SnapshotStep::Progress => Step::Progress,
                    SnapshotStep::Wait => Step::Wait,
                    SnapshotStep::Indeterminate => {
                        self.indeterminate = true;
                        Step::Wait
                    }
                    SnapshotStep::Ready(result) => {
                        match result {
                            Ok(snapshot) => {
                                let dependencies = match dependencies(&snapshot.bytes) {
                                    Ok(dependencies) => dependencies,
                                    Err(status) => {
                                        self.status = status as i32;
                                        self.phase = Phase::ReadyReply;
                                        return Step::Progress;
                                    }
                                };
                                let names: Vec<&str> = dependencies.iter().map(String::as_str).collect();
                                if let Err(error) = self.plan.file_ready(name, &names) {
                                    self.status = plan_error_status(error) as i32;
                                    self.phase = Phase::ReadyReply;
                                    return Step::Progress;
                                }
                                let mut source = win32k_glue::image_loader::ImageSnapshot {
                                    name: name.clone(), path: snapshot.path, bytes: snapshot.bytes,
                                };
                                if self.catalog.try_reserve(1).is_err() {
                                    source.bytes.clear();
                                    self.status = RESOURCES as i32;
                                    self.phase = Phase::ReadyReply;
                                    return Step::Progress;
                                }
                                self.catalog.push(source);
                                self.phase = Phase::Plan;
                            }
                            Err(status) => {
                                self.status = status as i32;
                                self.phase = Phase::ReadyReply;
                            }
                        }
                        Step::Progress
                    }
                }
            }
            Phase::ReadyReply => {
                if runtime::retained_service_cancelled(
                    self.route, self.dispatch, self.reply, self.token,
                ) {
                    return self.finish_cancelled(handler);
                }
                if self.reference.as_ref().is_some_and(|reference|
                    reference.validate(&handler.pm).is_err())
                {
                    self.status = CANCELLED as i32;
                    self.module = 0;
                }
                self.phase = Phase::ReplyEntered;
                if runtime::wake_gdi_image_service(
                    self.route, self.dispatch, self.reply, self.token,
                    self.status, self.module,
                ).is_err() && matches!(runtime::retained_service_reply_not_entered(
                    self.route, self.dispatch, self.reply, self.token,
                ), Ok(true)) {
                    self.phase = Phase::ReadyReply;
                    return Step::Wait;
                }
                Step::Progress
            }
            Phase::ReplyEntered => {
                if !matches!(runtime::reconcile_retained_service_reply(
                    self.route, self.dispatch, self.reply, self.token,
                ), Ok(true)) {
                    if runtime::retained_service_cancelled(
                        self.route, self.dispatch, self.reply, self.token,
                    ) {
                        return self.finish_cancelled(handler);
                    }
                    return Step::Wait;
                }
                runtime::retire_stopped_acknowledged_retained_service(
                    self.route, self.dispatch, self.reply, self.token,
                ).expect("acknowledged GDI provider Reply retirement");
                if let Some(reference) = self.reference.as_mut() {
                    reference.release(&mut handler.pm)
                        .expect("acknowledged GDI provider requestor retirement");
                }
                Step::Finished
            }
        }
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) -> bool {
    if ACTIVE.swap(true, Ordering::AcqRel) { return false; }
    let _durable = allocator::enter_durable();
    let mut work = {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        if rows.is_empty() {
            ACTIVE.store(false, Ordering::Release);
            return false;
        }
        rows.remove(0)
    };
    let mut progressed = false;
    let mut finished = false;
    for _ in 0..8 {
        match work.advance(handler) {
            Step::Progress => progressed = true,
            Step::Finished => { progressed = true; finished = true; break; }
            Step::Wait => break,
        }
    }
    if !finished { (&mut *core::ptr::addr_of_mut!(WORK)).push(work); }
    NEXT_RETRY.store(crate::monotonic_time_100ns().saturating_add(RETRY_100NS), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
    progressed
}
