//! Original Reply and exact process references for an entered hosted spawn with uncertain effects.
//!
//! No second spawn or synthetic failure is permitted once VSpace construction has entered.
//! These rows are deliberately retained until an exact reconciliation path can prove the
//! child's physical state. They also fence teardown of both creator and child mechanisms.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use nt_process::native_handle::NativeThreadProcessReference;

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

pub(crate) struct Prepared {
    park: root_reply_park::RootReplyPark,
    reply: u64,
    creator_pi: usize,
    creator_tid: u64,
    child_pi: usize,
    child_tid: u64,
    request: nt_exe_image::SpawnRequest,
    creator: NativeThreadProcessReference,
    child_identity: nt_types::ProcessIdentity,
    child_lifetime: nt_process::ThreadLifetime,
}

struct Uncertain {
    _reply: u64,
    creator_pi: usize,
    creator_tid: u64,
    child_pi: usize,
    child_tid: u64,
    _request: nt_exe_image::SpawnRequest,
    _creator: NativeThreadProcessReference,
    _child_identity: nt_types::ProcessIdentity,
    _child_lifetime: nt_process::ThreadLifetime,
    _status: u32,
}

static mut WORK: Vec<Uncertain> = Vec::new();
static TRANSFERRED: AtomicBool = AtomicBool::new(false);

/// Reserve every owner before the first child VSpace effect. The creator has an exact native
/// requestor reference; the child has exact identity and wait references while it is pre-spawn.
pub(crate) unsafe fn prepare(
    handler: &mut ExecNtHandler,
    request: nt_exe_image::SpawnRequest,
) -> Result<Prepared, u32> {
    let _durable = allocator::enter_durable();
    let target = request.target.ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
    let child_identity = handler.capture_process_identity(target.pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if child_identity.generation != nt_types::ProcessGeneration::Hosted(target.generation) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let child_tid = u64::from(handler.pm_main_tid_for_pi(target.pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?);
    let creator_tid = handler.current_tid;
    let creator_tid_id = nt_process::ThreadId::try_from(creator_tid)
        .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
    let creator_lifetime = handler.pm.thread_lifetime(creator_tid_id)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let child_lifetime = handler.pm.thread_lifetime(child_tid as nt_process::ThreadId)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if child_lifetime.process_id() != child_identity.pid
        || handler.pm_pid_for_pi(request.creator_pi) != Some(creator_lifetime.process_id())
    { return Err(nt_process::STATUS_INVALID_HANDLE); }
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    rows.try_reserve(1).map_err(|_| RESOURCES)?;
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let creator_caller = handler.pm.capture_native_handle_caller(
        creator_lifetime, nt_types::AccessMode::KernelMode)?;
    let mut creator = handler.pm.reference_native_requestor(creator_caller)?;
    if let Err(status) = handler.pm.retain_process_wait_reference(child_identity.pid) {
        creator.release(&mut handler.pm).expect("unentered creator reference");
        return Err(status);
    }
    if let Err(status) = handler.pm.retain_thread_wait_reference(child_lifetime.thread_id()) {
        handler.pm.release_process_wait_reference(child_identity.pid)
            .expect("unentered child process wait reference");
        creator.release(&mut handler.pm).expect("unentered creator reference");
        return Err(status);
    }
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    Ok(Prepared { park, reply, creator_pi: request.creator_pi, creator_tid,
        child_pi: target.pi, child_tid, request, creator, child_identity, child_lifetime })
}

pub(crate) fn release_unentered(handler: &mut ExecNtHandler, mut prepared: Prepared) {
    handler.pm.release_thread_wait_reference(prepared.child_lifetime.thread_id())
        .expect("unentered child thread wait reference");
    handler.pm.release_process_wait_reference(prepared.child_identity.pid)
        .expect("unentered child process wait reference");
    prepared.creator.release(&mut handler.pm).expect("unentered creator reference");
}

/// The physical spawn was entered exactly once. Keep the original Reply and both process
/// references; a later event must reconcile this exact target before either can be retired.
pub(crate) unsafe fn retain_entered(prepared: Prepared, status: u32) {
    let Prepared { park, reply, creator_pi, creator_tid, child_pi, child_tid,
        request, creator, child_identity, child_lifetime } = prepared;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    assert!(rows.len() < rows.capacity(), "spawn uncertainty owner lost reserved storage");
    rows.push(Uncertain { _reply: reply, creator_pi, creator_tid, child_pi, child_tid,
        _request: request, _creator: creator, _child_identity: child_identity,
        _child_lifetime: child_lifetime, _status: status });
    park.commit();
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
}

pub(crate) fn take_transferred() -> bool { TRANSFERRED.swap(false, Ordering::AcqRel) }

pub(crate) fn has_thread(tid: u64) -> bool { unsafe {
    (&*core::ptr::addr_of!(WORK)).iter().any(|work|
        work.creator_tid == tid || work.child_tid == tid)
} }

pub(crate) fn has_process(pi: usize, _preserve_tid: Option<u64>) -> bool { unsafe {
    (&*core::ptr::addr_of!(WORK)).iter().any(|work|
        work.creator_pi == pi || work.child_pi == pi)
} }
