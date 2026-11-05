//! Retained NtRead/WriteVirtualMemory copy. The original syscall Reply owns every page wait.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_address_space::copy::{VmCopyContinuation, VmCopyCountProbe, STATUS_PARTIAL_COPY};
use nt_address_space::{FaultAccess, PAGE_SIZE};
use nt_user_host::process_identity::ProcessIdentity;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

use crate::exec_handler::CopyPageAdmission;
use crate::routed_pagein_source::RoutedPageInSource;

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
const INVALID: u32 = nt_fs::STATUS_INVALID_HANDLE;
const RETRY_DELAY: u64 = 1_000_000;

type Progress =
    VmCopyContinuation<ProviderLogicalCaller, Option<ProcessIdentity>, RoutedPageInSource, u64>;
type CountProbe = VmCopyCountProbe<ProviderLogicalCaller, RoutedPageInSource, u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    CountCapture,
    CountWrite,
    Resolve,
    Stage,
    ProbeRead,
    ProbeWrite,
    CopyWrite,
    Output,
    Waiting,
    ReplyReady(u32),
    ReplyEntered,
    ReplySent,
    Cancel,
    RetypeReply,
    Done,
    Indeterminate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingPurpose {
    CountCapture,
    CountWrite,
    Stage,
    ProbeRead,
    ProbeWrite,
    CopyWrite,
    Output,
}

impl PendingPurpose {
    const fn resume(self) -> Phase {
        match self {
            Self::CountCapture => Phase::CountCapture,
            Self::CountWrite => Phase::CountWrite,
            Self::Stage => Phase::Stage,
            Self::ProbeRead => Phase::ProbeRead,
            Self::ProbeWrite => Phase::ProbeWrite,
            Self::CopyWrite => Phase::CopyWrite,
            Self::Output => Phase::Output,
        }
    }

    const fn copy_offset(self) -> bool {
        matches!(
            self,
            Self::Stage | Self::ProbeRead | Self::ProbeWrite | Self::CopyWrite
        )
    }
}

#[derive(Clone, Copy)]
struct Pending {
    purpose: PendingPurpose,
    target_pi: usize,
    page: u64,
    source: RoutedPageInSource,
    token: u64,
    offset: u64,
}

struct Work {
    caller: ProviderLogicalCaller,
    reply: u64,
    args: [u64; 5],
    read: bool,
    target: Option<(usize, ProcessIdentity)>,
    source_pi: usize,
    destination_pi: usize,
    progress: Option<Progress>,
    count: Option<CountProbe>,
    pending: Option<Pending>,
    probe_byte: u8,
    phase: Phase,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_CALLER: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_TARGET: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT: AtomicU64 = AtomicU64::new(0);
static NEXT_PAGE_TOKEN: AtomicU64 = AtomicU64::new(1);

fn fresh_page_token() -> Option<u64> {
    NEXT_PAGE_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .ok()
        .filter(|value| *value != 0)
}

/// Capture call arguments and park the original Reply before any count probe or page effect.
pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler,
    args: &[u64],
    read: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let args: [u64; 5] = args
        .get(..5)
        .and_then(|args| args.try_into().ok())
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let length = args[3];
    for base in [args[1], args[2]] {
        if base
            .checked_add(length)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT)
        {
            return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
        }
    }
    if args[4] != 0
        && args[4]
            .checked_add(8)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT)
    {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let pi = handler.pi;
    let tid = handler.current_tid;
    let badge = handler.current_badge;
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller = handler
        .capture_provider_logical_caller(pi, tid, badge, tcb)
        .ok_or(INVALID)?;
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64).then_some(index)
    });
    if index.is_none() && rows.try_reserve(1).is_err() {
        return Err(RESOURCES);
    }
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let work = Work {
        caller,
        reply,
        args,
        read,
        target: None,
        source_pi: pi,
        destination_pi: pi,
        progress: None,
        count: (args[4] != 0).then(|| CountProbe::new(caller, args[4])),
        pending: None,
        probe_byte: 0,
        phase: if args[4] == 0 {
            Phase::Resolve
        } else {
            Phase::CountCapture
        },
        resume_ip,
        sp,
        flags,
        native_call_transport,
    };
    match index {
        Some(index) => rows[index] = Some(work),
        None => rows.push(Some(work)),
    }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe {
            (&*core::ptr::addr_of!(WORK))
                .iter()
                .flatten()
                .any(|work| u64::from(work.caller.thread().thread_id()) == tid)
        }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    ((EXECUTING_CALLER.load(Ordering::Acquire) == pi as u64
        || EXECUTING_TARGET.load(Ordering::Acquire) == pi as u64)
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe {
            (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work| {
                (work.caller.pi() == pi
                    || work.target.is_some_and(|(target_pi, _)| target_pi == pi))
                    && preserve_tid != Some(u64::from(work.caller.thread().thread_id()))
            })
        }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (ACTIVE.load(Ordering::Acquire)
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some) })
    .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

fn valid(handler: &ExecNtHandler, work: &Work) -> bool {
    handler.validate_provider_logical_caller(work.caller)
        && work
            .target
            .is_none_or(|(pi, process)| handler.capture_process_identity(pi) == Some(process))
}

/// Page workers call after exact terminal copy and strict ACK, or proven no-entry cancellation.
pub(crate) unsafe fn page_completed(
    token: u64,
    target_pi: usize,
    page: u64,
    source: RoutedPageInSource,
    status: u32,
) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let mut found = None;
    for (index, row) in rows.iter().enumerate() {
        if row
            .as_ref()
            .is_some_and(|row| row.pending.is_some_and(|pending| pending.token == token))
        {
            if found.replace(index).is_some() {
                return false;
            }
        }
    }
    let Some(index) = found else {
        return false;
    };
    let work = rows[index].as_mut().unwrap();
    let Some(pending) = work.pending else {
        return false;
    };
    if work.phase != Phase::Waiting
        || pending.target_pi != target_pi
        || pending.page != page
        || pending.source != source
        || pending.token != token
    {
        return false;
    }
    let caller = work.caller;
    let exact = if pending.purpose == PendingPurpose::CountCapture {
        let Some(count) = work.count.as_mut() else {
            return false;
        };
        count.acknowledge_pending(caller, pending.offset, source, token)
            && if status == 0 {
                count.resume_pending(caller, pending.offset, source, token)
            } else {
                count.fail_pending(caller, pending.offset, source, token, status)
            }
    } else if pending.purpose.copy_offset() {
        let Some(progress) = work.progress.as_mut() else {
            return false;
        };
        let target = work.target.map(|(_, process)| process);
        progress.acknowledge_pending(caller, target, pending.offset, source, token)
            && if status == 0 {
                progress.resume_pending(caller, target, pending.offset, source, token)
            } else {
                let reported = match pending.purpose {
                    PendingPurpose::Stage | PendingPurpose::CopyWrite => STATUS_PARTIAL_COPY,
                    _ => status,
                };
                progress.fail_pending(caller, target, pending.offset, source, token, reported)
            }
    } else {
        true
    };
    if !exact {
        work.phase = Phase::Indeterminate;
        return false;
    }
    work.pending = None;
    work.phase = if status == 0 {
        pending.purpose.resume()
    } else {
        match pending.purpose {
            PendingPurpose::CountCapture => Phase::ReplyReady(status),
            PendingPurpose::CountWrite => {
                if work
                    .count
                    .as_mut()
                    .is_some_and(|count| count.fail_before_write(caller, status))
                {
                    Phase::ReplyReady(status)
                } else {
                    Phase::Indeterminate
                }
            }
            PendingPurpose::Output => {
                let target = work.target.map(|(_, process)| process);
                if work
                    .progress
                    .as_mut()
                    .is_some_and(|progress| progress.output_failed(caller, target))
                {
                    Phase::ReplyReady(0)
                } else {
                    Phase::Indeterminate
                }
            }
            _ => Phase::Output,
        }
    };
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    true
}

enum Admission {
    Ready,
    Waiting,
    Failed(u32),
}

/// A missing routed page is transferred to a worker; no synchronous provider read occurs here.
unsafe fn admit(
    handler: &mut ExecNtHandler,
    work: &mut Work,
    pi: usize,
    address: u64,
    access: FaultAccess,
    purpose: PendingPurpose,
) -> Admission {
    // Reject a coordinator phase mismatch before installing a worker that could enter I/O.
    if purpose == PendingPurpose::CountCapture {
        if work
            .count
            .as_ref()
            .and_then(|count| count.next_capture(work.caller))
            .map(|(next, _)| next)
            != Some(address)
        {
            return Admission::Failed(INVALID);
        }
    } else if purpose.copy_offset()
        && work
            .progress
            .as_ref()
            .and_then(|progress| {
                progress.next_offset(work.caller, work.target.map(|(_, identity)| identity))
            })
            .is_none()
    {
        return Admission::Failed(INVALID);
    }
    match handler.copy_page_admission(pi, address, access) {
        Ok(CopyPageAdmission::Resident) => return Admission::Ready,
        Err(status) => return Admission::Failed(status),
        Ok(CopyPageAdmission::NeedsRoutedPageIn) => {}
    }
    let page = address & !(PAGE_SIZE - 1);
    let Some(token) = fresh_page_token() else {
        return Admission::Failed(RESOURCES);
    };
    let info = match handler.query_memory_basic_information(pi, page) {
        Ok(info) => info,
        Err(status) => return Admission::Failed(status),
    };
    let result = match info.type_ {
        nt_address_space::MEM_MAPPED => crate::section_pagein_work::submit_for_vm_copy(
            handler,
            work.caller.pi(),
            pi,
            page,
            access,
            work.reply,
            token,
        )
        .map(Some),
        nt_address_space::MEM_IMAGE => crate::native_image_pagein_work::submit_for_vm_copy(
            handler,
            work.caller.pi(),
            pi,
            page,
            access,
            work.reply,
            token,
        ),
        _ => Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES),
    };
    let source = match result {
        Ok(Some(source)) => source,
        Ok(None) => return Admission::Failed(INVALID),
        Err(status) => return Admission::Failed(status),
    };
    let offset = if purpose == PendingPurpose::CountCapture {
        address
    } else {
        work.progress
            .as_ref()
            .and_then(|progress| {
                progress.next_offset(work.caller, work.target.map(|(_, identity)| identity))
            })
            .unwrap_or(0)
    };
    let registered = if purpose == PendingPurpose::CountCapture {
        work.count
            .as_mut()
            .is_some_and(|count| count.begin_pending(work.caller, address, source, token))
    } else if purpose.copy_offset() {
        work.progress.as_mut().is_some_and(|progress| {
            progress.begin_pending(
                work.caller,
                work.target.map(|(_, identity)| identity),
                offset,
                source,
                token,
            )
        })
    } else {
        true
    };
    work.pending = Some(Pending {
        purpose,
        target_pi: pi,
        page,
        source,
        token,
        offset,
    });
    work.phase = if registered {
        Phase::Waiting
    } else {
        Phase::Indeterminate
    };
    Admission::Waiting
}

unsafe fn advance(handler: &mut ExecNtHandler, work: &mut Work) {
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
        || handler
            .pm
            .thread(work.caller.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler
            .pm
            .process(work.caller.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !valid(handler, work);
    if cancelled
        && work.pending.is_none()
        && !matches!(
            work.phase,
            Phase::ReplyEntered
                | Phase::ReplySent
                | Phase::RetypeReply
                | Phase::Done
                | Phase::Indeterminate
        )
    {
        work.phase = Phase::Cancel;
    }
    match work.phase {
        Phase::CountCapture => {
            let Some(count) = work.count.as_ref() else {
                work.phase = Phase::Indeterminate;
                return;
            };
            let Some((address, length)) = count.next_capture(work.caller) else {
                work.phase = if count.published(work.caller) {
                    Phase::Resolve
                } else {
                    Phase::CountWrite
                };
                return;
            };
            let pi = work.caller.pi();
            match admit(
                handler,
                work,
                pi,
                address,
                FaultAccess::Read,
                PendingPurpose::CountCapture,
            ) {
                Admission::Waiting => return,
                Admission::Failed(status) => {
                    work.phase = if work.count.as_mut().unwrap().fail(work.caller, status) {
                        Phase::ReplyReady(status)
                    } else {
                        Phase::Indeterminate
                    };
                    return;
                }
                Admission::Ready => {}
            }
            let mut bytes = [0u8; 8];
            if let Err(status) = handler.copy_read_resident_page(
                work.caller.pi(),
                work.caller.process(),
                address,
                &mut bytes[..length],
            ) {
                work.phase = if work.count.as_mut().unwrap().fail(work.caller, status) {
                    Phase::ReplyReady(status)
                } else {
                    Phase::Indeterminate
                };
                return;
            }
            if !work
                .count
                .as_mut()
                .unwrap()
                .capture_bytes(work.caller, address, &bytes[..length])
            {
                work.phase = Phase::Indeterminate;
            }
        }
        Phase::CountWrite => {
            let Some(count) = work.count.as_ref() else {
                work.phase = Phase::Indeterminate;
                return;
            };
            if count.published(work.caller) {
                work.phase = Phase::Resolve;
                return;
            }
            let Some((expected_address, expected_length)) = count.next_write(work.caller) else {
                work.phase = Phase::Indeterminate;
                return;
            };
            let pi = work.caller.pi();
            match admit(
                handler,
                work,
                pi,
                expected_address,
                FaultAccess::Write,
                PendingPurpose::CountWrite,
            ) {
                Admission::Waiting => return,
                Admission::Failed(status) => {
                    work.phase = if work
                        .count
                        .as_mut()
                        .unwrap()
                        .fail_before_write(work.caller, status)
                    {
                        Phase::ReplyReady(status)
                    } else {
                        Phase::Indeterminate
                    };
                    return;
                }
                Admission::Ready => {}
            }
            let mut bytes = [0u8; 8];
            let Some((address, input)) = work.count.as_mut().unwrap().enter_write(work.caller)
            else {
                work.phase = Phase::Indeterminate;
                return;
            };
            if address != expected_address || input.len() != expected_length {
                work.phase = Phase::Indeterminate;
                return;
            }
            bytes[..input.len()].copy_from_slice(input);
            work.phase = Phase::Indeterminate;
            let length = input.len();
            if handler
                .copy_write_resident_page(
                    work.caller.pi(),
                    work.caller.process(),
                    address,
                    &bytes[..length],
                )
                .is_ok()
                && work
                    .count
                    .as_mut()
                    .unwrap()
                    .write_completed(work.caller, address)
            {
                work.phase = Phase::CountWrite;
            }
        }
        Phase::Resolve => {
            let count_ptr = work.args[4];
            if work.args[3] == 0 {
                let mut progress = Progress::new(work.caller, None, 0, 0, 0, count_ptr);
                if !progress.finish(work.caller, None, 0) {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                work.progress = Some(progress);
                work.phase = Phase::Output;
                return;
            }
            let access = if work.read { 0x0010 } else { 0x0020 };
            let (target_pid, target_pi) =
                match handler.resolve_process_for_access(work.args[0], access) {
                    Ok(target) => target,
                    Err(status) => {
                        let mut progress = Progress::new(work.caller, None, 0, 0, 0, count_ptr);
                        if !progress.fail(work.caller, None, status) {
                            work.phase = Phase::Indeterminate;
                            return;
                        }
                        work.progress = Some(progress);
                        work.phase = Phase::Output;
                        return;
                    }
                };
            if handler.pm.process(target_pid).is_some_and(|process| {
                matches!(
                    process.state,
                    nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
                )
            }) {
                let mut progress = Progress::new(work.caller, None, 0, 0, 0, count_ptr);
                if !progress.fail(work.caller, None, nt_process::STATUS_PROCESS_IS_TERMINATING) {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                work.progress = Some(progress);
                work.phase = Phase::Output;
                return;
            }
            let Some(target) = handler.capture_process_identity(target_pi) else {
                let mut progress = Progress::new(work.caller, None, 0, 0, 0, count_ptr);
                if !progress.fail(work.caller, None, INVALID) {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                work.progress = Some(progress);
                work.phase = Phase::Output;
                return;
            };
            work.target = Some((target_pi, target));
            let (source_pi, source, destination_pi, destination) = if work.read {
                (target_pi, work.args[1], work.caller.pi(), work.args[2])
            } else {
                (work.caller.pi(), work.args[2], target_pi, work.args[1])
            };
            work.source_pi = source_pi;
            work.destination_pi = destination_pi;
            work.progress = Some(Progress::new(
                work.caller,
                Some(target),
                source,
                destination,
                work.args[3],
                count_ptr,
            ));
            work.phase = Phase::Stage;
        }
        Phase::Stage => {
            let target = work.target.map(|(_, identity)| identity);
            let Some((source, destination, remaining)) = work
                .progress
                .as_ref()
                .and_then(|progress| progress.next_addresses(work.caller, target))
            else {
                if work
                    .progress
                    .as_mut()
                    .is_some_and(|progress| progress.finish(work.caller, target, 0))
                {
                    work.phase = Phase::Output;
                } else {
                    work.phase = Phase::Indeterminate;
                }
                return;
            };
            let chunk = remaining
                .min(256)
                .min(PAGE_SIZE - source % PAGE_SIZE)
                .min(PAGE_SIZE - destination % PAGE_SIZE) as usize;
            let source_pi = work.source_pi;
            match admit(
                handler,
                work,
                source_pi,
                source,
                FaultAccess::Read,
                PendingPurpose::Stage,
            ) {
                Admission::Waiting => return,
                Admission::Failed(_) => {
                    if work.progress.as_mut().unwrap().fail(
                        work.caller,
                        target,
                        STATUS_PARTIAL_COPY,
                    ) {
                        work.phase = Phase::Output;
                    } else {
                        work.phase = Phase::Indeterminate;
                    }
                    return;
                }
                Admission::Ready => {}
            }
            let process = if work.source_pi == work.caller.pi() {
                work.caller.process()
            } else {
                work.target.unwrap().1
            };
            let mut bytes = [0u8; 256];
            if handler
                .copy_read_resident_page(work.source_pi, process, source, &mut bytes[..chunk])
                .is_err()
            {
                if work
                    .progress
                    .as_mut()
                    .unwrap()
                    .fail(work.caller, target, STATUS_PARTIAL_COPY)
                {
                    work.phase = Phase::Output;
                } else {
                    work.phase = Phase::Indeterminate;
                }
                return;
            }
            let progress = work.progress.as_mut().unwrap();
            let offset = progress.next_offset(work.caller, target).unwrap();
            if !progress.stage_source(work.caller, target, offset, &bytes[..chunk]) {
                work.phase = Phase::Indeterminate;
            } else {
                work.phase = if progress.next_probe_address(work.caller, target).is_some() {
                    Phase::ProbeRead
                } else {
                    Phase::CopyWrite
                };
            }
        }
        Phase::ProbeRead => {
            let target = work.target.map(|(_, identity)| identity);
            let Some(address) = work
                .progress
                .as_ref()
                .and_then(|progress| progress.next_probe_address(work.caller, target))
            else {
                work.phase = Phase::CopyWrite;
                return;
            };
            let destination_pi = work.destination_pi;
            match admit(
                handler,
                work,
                destination_pi,
                address,
                FaultAccess::Read,
                PendingPurpose::ProbeRead,
            ) {
                Admission::Waiting => return,
                Admission::Failed(status) => {
                    if work
                        .progress
                        .as_mut()
                        .unwrap()
                        .fail(work.caller, target, status)
                    {
                        work.phase = Phase::Output;
                    } else {
                        work.phase = Phase::Indeterminate;
                    }
                    return;
                }
                Admission::Ready => {}
            }
            let process = if work.destination_pi == work.caller.pi() {
                work.caller.process()
            } else {
                work.target.unwrap().1
            };
            let mut byte = [0u8; 1];
            if let Err(status) =
                handler.copy_read_resident_page(work.destination_pi, process, address, &mut byte)
            {
                if work
                    .progress
                    .as_mut()
                    .unwrap()
                    .fail(work.caller, target, status)
                {
                    work.phase = Phase::Output;
                } else {
                    work.phase = Phase::Indeterminate;
                }
                return;
            }
            work.probe_byte = byte[0];
            work.phase = Phase::ProbeWrite;
        }
        Phase::ProbeWrite => {
            let target = work.target.map(|(_, identity)| identity);
            let Some(address) = work
                .progress
                .as_ref()
                .and_then(|progress| progress.next_probe_address(work.caller, target))
            else {
                work.phase = Phase::Indeterminate;
                return;
            };
            let destination_pi = work.destination_pi;
            match admit(
                handler,
                work,
                destination_pi,
                address,
                FaultAccess::Write,
                PendingPurpose::ProbeWrite,
            ) {
                Admission::Waiting => return,
                Admission::Failed(status) => {
                    if work
                        .progress
                        .as_mut()
                        .unwrap()
                        .fail(work.caller, target, status)
                    {
                        work.phase = Phase::Output;
                    } else {
                        work.phase = Phase::Indeterminate;
                    }
                    return;
                }
                Admission::Ready => {}
            }
            let process = if work.destination_pi == work.caller.pi() {
                work.caller.process()
            } else {
                work.target.unwrap().1
            };
            if !work
                .progress
                .as_mut()
                .unwrap()
                .enter_probe_page(work.caller, target, address)
            {
                work.phase = Phase::Indeterminate;
                return;
            }
            work.phase = Phase::Indeterminate;
            if handler
                .copy_write_resident_page(work.destination_pi, process, address, &[work.probe_byte])
                .is_ok()
                && work.progress.as_mut().unwrap().probe_page_completed(
                    work.caller,
                    target,
                    address,
                )
            {
                work.phase = if work
                    .progress
                    .as_ref()
                    .unwrap()
                    .next_probe_address(work.caller, target)
                    .is_some()
                {
                    Phase::ProbeRead
                } else {
                    Phase::CopyWrite
                };
            }
        }
        Phase::CopyWrite => {
            let target = work.target.map(|(_, identity)| identity);
            let Some((_, address, _)) = work
                .progress
                .as_ref()
                .and_then(|progress| progress.next_addresses(work.caller, target))
            else {
                work.phase = Phase::Indeterminate;
                return;
            };
            let destination_pi = work.destination_pi;
            match admit(
                handler,
                work,
                destination_pi,
                address,
                FaultAccess::Write,
                PendingPurpose::CopyWrite,
            ) {
                Admission::Waiting => return,
                Admission::Failed(_) => {
                    if work.progress.as_mut().unwrap().fail(
                        work.caller,
                        target,
                        STATUS_PARTIAL_COPY,
                    ) {
                        work.phase = Phase::Output;
                    } else {
                        work.phase = Phase::Indeterminate;
                    }
                    return;
                }
                Admission::Ready => {}
            }
            let process = if work.destination_pi == work.caller.pi() {
                work.caller.process()
            } else {
                work.target.unwrap().1
            };
            let progress = work.progress.as_mut().unwrap();
            let offset = progress.next_offset(work.caller, target).unwrap();
            let Some(input) = progress.staged_source(work.caller, target, offset) else {
                work.phase = Phase::Indeterminate;
                return;
            };
            let mut bytes = [0u8; 256];
            let length = input.len();
            bytes[..length].copy_from_slice(input);
            if !progress.enter_copy_write(work.caller, target, offset) {
                work.phase = Phase::Indeterminate;
                return;
            }
            work.phase = Phase::Indeterminate;
            if handler
                .copy_write_resident_page(work.destination_pi, process, address, &bytes[..length])
                .is_ok()
                && progress.commit_copied(work.caller, target, offset, length as u64)
            {
                work.phase = Phase::Stage;
            }
        }
        Phase::Output => {
            let target = work.target.map(|(_, identity)| identity);
            let Some(progress) = work.progress.as_ref() else {
                work.phase = Phase::Indeterminate;
                return;
            };
            if work.args[4] == 0 {
                if work
                    .progress
                    .as_mut()
                    .unwrap()
                    .skip_null_output(work.caller, target)
                {
                    work.phase = Phase::ReplyReady(0);
                } else {
                    work.phase = Phase::Indeterminate;
                }
                return;
            }
            let Some((address, input)) = progress.next_output_chunk(work.caller, target) else {
                if work
                    .progress
                    .as_mut()
                    .unwrap()
                    .output_published(work.caller, target)
                {
                    work.phase = Phase::ReplyReady(0);
                } else {
                    work.phase = Phase::Indeterminate;
                }
                return;
            };
            let mut bytes = [0u8; 8];
            let length = input.len();
            bytes[..length].copy_from_slice(input);
            let pi = work.caller.pi();
            match admit(
                handler,
                work,
                pi,
                address,
                FaultAccess::Write,
                PendingPurpose::Output,
            ) {
                Admission::Waiting => return,
                Admission::Failed(_) => {
                    if work
                        .progress
                        .as_mut()
                        .unwrap()
                        .output_failed(work.caller, target)
                    {
                        work.phase = Phase::ReplyReady(0);
                    } else {
                        work.phase = Phase::Indeterminate;
                    }
                    return;
                }
                Admission::Ready => {}
            }
            if !work
                .progress
                .as_mut()
                .unwrap()
                .enter_output_page(work.caller, target, address)
            {
                work.phase = Phase::Indeterminate;
                return;
            }
            work.phase = Phase::Indeterminate;
            if handler
                .copy_write_resident_page(
                    work.caller.pi(),
                    work.caller.process(),
                    address,
                    &bytes[..length],
                )
                .is_ok()
                && work.progress.as_mut().unwrap().output_page_completed(
                    work.caller,
                    target,
                    address,
                )
            {
                work.phase = Phase::Output;
            }
        }
        Phase::Waiting => {}
        Phase::ReplyReady(status) => {
            if parked_reply::validate_saved(work.reply).is_err() {
                return;
            }
            let status = if let Some(progress) = work.progress.as_mut() {
                let target = work.target.map(|(_, identity)| identity);
                let Some((caller, result)) = progress.enter_reply(work.caller, target) else {
                    work.phase = Phase::Indeterminate;
                    return;
                };
                if caller != work.caller {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                result.status
            } else {
                status
            };
            work.phase = Phase::ReplyEntered;
            if reply_parked_syscall(work.reply, u64::from(status)) {
                work.phase = Phase::ReplySent;
            }
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply,
            ) {
                Ok(true) => work.phase = Phase::ReplySent,
                _ if cancelled => work.phase = Phase::Indeterminate,
                _ => {}
            }
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(work.reply).is_ok() {
                thread_wait_state_clear_badge_ready(handler, work.caller.badge());
                work.phase = Phase::Done;
            }
        }
        Phase::Cancel => {
            if work.pending.is_some() {
                return;
            }
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(
                        work.reply,
                    )
                    .is_err()
                {
                    return;
                }
            } else if parked_reply::revoke(work.reply).is_err() {
                return;
            }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            if parked_reply::retype(work.reply).is_ok() {
                work.phase = Phase::Done;
            }
        }
        Phase::Done | Phase::Indeterminate => {}
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else {
            continue;
        };
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(
            u64::from(work.caller.thread().thread_id()),
            Ordering::Release,
        );
        EXECUTING_CALLER.store(work.caller.pi() as u64, Ordering::Release);
        EXECUTING_TARGET.store(
            work.target.map_or(u64::MAX, |(pi, _)| pi as u64),
            Ordering::Release,
        );
        let target_pi = work.target.map_or(work.caller.pi(), |(pi, _)| pi);
        let service = if work.read {
            SSN_NT_READ_VM
        } else {
            SSN_NT_WRITE_VM
        };
        let done = crate::service_sec_image::with_pagein_caller_target_context(
            handler,
            work.caller.pi(),
            target_pi,
            u64::from(work.caller.thread().thread_id()),
            work.caller.badge(),
            work.resume_ip,
            work.sp,
            work.flags,
            work.native_call_transport,
            service as u32,
            |handler| {
                // Inline pages make progress within this turn; provider Pending stops here.
                for _ in 0..32 {
                    let before = (
                        work.phase,
                        work.count
                            .as_ref()
                            .and_then(|count| count.next_write(work.caller)),
                        work.count
                            .as_ref()
                            .and_then(|count| count.next_capture(work.caller)),
                        work.progress.as_ref().and_then(|progress| {
                            progress
                                .next_offset(work.caller, work.target.map(|(_, process)| process))
                        }),
                        work.progress.as_ref().and_then(|progress| {
                            progress
                                .next_output_chunk(
                                    work.caller,
                                    work.target.map(|(_, process)| process),
                                )
                                .map(|(address, _)| address)
                        }),
                    );
                    advance(handler, &mut work);
                    let after = (
                        work.phase,
                        work.count
                            .as_ref()
                            .and_then(|count| count.next_write(work.caller)),
                        work.count
                            .as_ref()
                            .and_then(|count| count.next_capture(work.caller)),
                        work.progress.as_ref().and_then(|progress| {
                            progress
                                .next_offset(work.caller, work.target.map(|(_, process)| process))
                        }),
                        work.progress.as_ref().and_then(|progress| {
                            progress
                                .next_output_chunk(
                                    work.caller,
                                    work.target.map(|(_, process)| process),
                                )
                                .map(|(address, _)| address)
                        }),
                    );
                    if before == after
                        || matches!(
                            work.phase,
                            Phase::Waiting | Phase::Done | Phase::Indeterminate
                        )
                    {
                        break;
                    }
                }
            },
        );
        if done.is_none() {
            work.phase = Phase::Indeterminate;
        }
        if work.phase != Phase::Done {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_CALLER.store(u64::MAX, Ordering::Release);
        EXECUTING_TARGET.store(u64::MAX, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    NEXT.store(
        monotonic_time_100ns().saturating_add(RETRY_DELAY),
        Ordering::Release,
    );
    ACTIVE.store(false, Ordering::Release);
}
