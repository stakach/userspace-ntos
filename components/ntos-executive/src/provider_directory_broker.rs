//! Inline win32k directory-object transport over the canonical executive namespace.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_object_manager::directory::{plan_directory_entries, DirectoryPackPlan};
use nt_process::native_handle::NativeHandleCaller;
use nt_process::native_handle::NativeThreadProcessReference;
use nt_types::UnicodeString;
use nt_user_host::provider_directory_name::{
    DirectoryNameMetadata, DirectoryNameUploads, DirectoryUploadError, DirectoryUploadOwner,
    DirectoryUploadPhase,
};
use nt_user_host::provider_directory_query::{
    DirectoryQueryError, DirectoryQueryOwner, DirectoryQuerySnapshots,
};
use nt_user_host::canonical_directory_backing::{BackingError, Publication};

use crate::exec_handler::directory_object::{DirectoryPublishProgress, ReservedProviderDirectoryObject};
use crate::ExecNtHandler;
use crate::spawn_hosts::shared_ingress::owner::runtime;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_CANCELLED: u32 = 0xC000_0120;
const MAX_NAME_UNITS: usize = 1024;
const RETRY_DELAY_100NS: u64 = 1_000_000;
const MAX_DEFINITE_CLOSE_RETRIES: u8 = 8;
static REDRIVE_ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static NEXT_SCAN: AtomicU64 = AtomicU64::new(0);
static EFFECT_NEXT_SCAN: AtomicU64 = AtomicU64::new(0);

pub(crate) enum SubmitResult {
    Ready((i32, u64, u64, u64)),
    Deferred,
}

type Owner = DirectoryUploadOwner<PeerRoute, (LaneDispatchIdentity, u64), NativeHandleCaller>;

struct Pending {
    owner: Owner,
    staged: ReservedProviderDirectoryObject,
    phase: PendingPhase,
    publish: Option<PublishWork>,
}

struct PublishWork {
    reply: u64,
    token: u64,
    reference: NativeThreadProcessReference,
    phase: PublishPhase,
    status: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectKind { Close, MakeTemporary }

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectPhase { CanonicalStart, CanonicalPending, ReadyReply, ReplyEntered, Indeterminate }

struct EffectWork {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    reference: NativeThreadProcessReference,
    kind: EffectKind,
    phase: EffectPhase,
    identity: u64,
    status: u32,
    definite_close_retries: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishPhase { Start, CanonicalPending, CanonicalRollback, ReadyReply, ReplyEntered }

struct QuerySnapshot {
    entries: Vec<(UnicodeString, UnicodeString)>,
    plan: DirectoryPackPlan,
    next_offset: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingPhase {
    Reserved,
    Publishing,
    Aborted,
    PublishedUnacknowledged,
    Acknowledged,
    EffectUncertain,
}

struct Broker {
    uploads: DirectoryNameUploads<PeerRoute, (LaneDispatchIdentity, u64), NativeHandleCaller>,
    kinds: Vec<(PeerRoute, LaneDispatchIdentity, u64, bool)>,
    pending: Vec<Pending>,
    effects: Vec<EffectWork>,
    queries:
        DirectoryQuerySnapshots<PeerRoute, LaneDispatchIdentity, NativeHandleCaller, QuerySnapshot>,
    failed_commits: Vec<Owner>,
    next_token: u64,
}

impl Broker {
    const fn new() -> Self {
        Self {
            uploads: DirectoryNameUploads::new(),
            kinds: Vec::new(),
            pending: Vec::new(),
            effects: Vec::new(),
            queries: DirectoryQuerySnapshots::new(),
            failed_commits: Vec::new(),
            next_token: 1,
        }
    }

    fn owner(
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        caller: NativeHandleCaller,
        token: u64,
    ) -> Owner {
        DirectoryUploadOwner {
            route,
            dispatch: (dispatch, token),
            caller,
        }
    }

    fn next_token(&mut self) -> Result<u64, u32> {
        let token = self.next_token;
        self.next_token = token.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(token)
    }

    unsafe fn submit_publish(
        &mut self,
        handler: &mut ExecNtHandler,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        caller: NativeHandleCaller,
        reply: u64,
        token: u64,
        value: u64,
        reserved: u64,
    ) -> SubmitResult {
        if reserved != 0 {
            return SubmitResult::Ready((STATUS_INVALID_PARAMETER as i32, 0, 0, 0));
        }
        let owner = Self::owner(route, dispatch, caller, token);
        let Some(index) = self.pending.iter().position(|entry| {
            entry.owner == owner && entry.staged.value() == value
                && entry.phase == PendingPhase::Reserved && entry.publish.is_none()
        }) else {
            return SubmitResult::Ready((STATUS_INVALID_HANDLE as i32, 0, 0, 0));
        };
        if !matches!(runtime::current_reply(route), Ok(current) if current == reply) {
            return SubmitResult::Ready((STATUS_INVALID_HANDLE as i32, 0, 0, 0));
        }
        let mut reference = match handler.pm.reference_native_requestor(caller) {
            Ok(reference) => reference,
            Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
        };
        let wait_token = match runtime::next_service_wait_token() {
            Ok(token) => token,
            Err(_) => {
                reference.release(&mut handler.pm)
                    .expect("unsubmitted directory requestor reference");
                return SubmitResult::Ready((STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0));
            }
        };
        if runtime::park_retained_service(route, wait_token).is_err() {
            reference.release(&mut handler.pm)
                .expect("unsubmitted directory requestor reference");
            return SubmitResult::Ready((STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0));
        }
        self.pending[index].publish = Some(PublishWork {
            reply,
            token: wait_token,
            reference,
            phase: PublishPhase::Start,
            status: 0,
        });
        self.pending[index].phase = PendingPhase::Publishing;
        NEXT_RETRY.store(crate::monotonic_time_100ns(), Ordering::Release);
        SubmitResult::Deferred
    }

    unsafe fn submit_effect(
        &mut self,
        handler: &mut ExecNtHandler,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        caller: NativeHandleCaller,
        reply: u64,
        op: u64,
        handle: u64,
        m2: u64,
        m3: u64,
    ) -> SubmitResult {
        if m2 != 0 || m3 != 0 {
            return SubmitResult::Ready((STATUS_INVALID_PARAMETER as i32, 0, 0, 0));
        }
        if !matches!(runtime::current_reply(route), Ok(current) if current == reply) {
            return SubmitResult::Ready((STATUS_INVALID_HANDLE as i32, 0, 0, 0));
        }
        let kind = if op == 7 { EffectKind::Close } else { EffectKind::MakeTemporary };
        let access = if kind == EffectKind::MakeTemporary { 0x0001_0000 } else { 0 };
        let identity = match handler.provider_directory_effect_identity(caller, handle, access) {
            Ok(identity) => identity,
            Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
        };
        if self.effects.iter().any(|work| work.identity == identity) {
            return SubmitResult::Ready((STATUS_INVALID_HANDLE as i32, 0, 0, 0));
        }
        if self.effects.try_reserve(1).is_err() {
            return SubmitResult::Ready((STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0));
        }
        let mut reference = match handler.pm.reference_native_requestor(caller) {
            Ok(reference) => reference,
            Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
        };
        let token = match runtime::next_service_wait_token() {
            Ok(token) => token,
            Err(_) => {
                reference.release(&mut handler.pm)
                    .expect("unsubmitted directory effect requestor reference");
                return SubmitResult::Ready((STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0));
            }
        };
        if runtime::park_retained_service(route, token).is_err() {
            reference.release(&mut handler.pm)
                .expect("unsubmitted directory effect requestor reference");
            return SubmitResult::Ready((STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0));
        }
        self.effects.push(EffectWork { route, dispatch, reply, token, reference,
            kind, phase: EffectPhase::CanonicalStart, identity, status: 0,
            definite_close_retries: 0 });
        if kind == EffectKind::Close {
            // The row and Reply already own the detached identity. Consume the exact native
            // handle in this same serialized dispatch, before another thread can reuse its
            // numeric slot while the asynchronous canonical close waits.
            let work = self.effects.last_mut().expect("reserved directory close work");
            match handler.close_provider_directory_native_handle(caller, handle, identity) {
                Ok(()) => work.phase = EffectPhase::CanonicalStart,
                Err(status) => {
                    work.status = status;
                    work.phase = EffectPhase::ReadyReply;
                }
            }
        } else {
            // DELETE was admitted against this exact visible handle above. Begin the owned
            // canonical effect before another thread can close/reuse the numeric handle.
            let work = self.effects.last_mut().expect("reserved directory permanence work");
            match handler.make_temporary_provider_directory_canonical(identity) {
                Ok(Publication::Ready) => {
                    work.phase = if handler.finish_provider_directory_make_temporary(identity).is_ok() {
                        EffectPhase::ReadyReply
                    } else { EffectPhase::Indeterminate };
                }
                Ok(Publication::Pending) => work.phase = EffectPhase::CanonicalPending,
                Err(BackingError::NoEffect(status) | BackingError::Terminal(status)) => {
                    work.status = status;
                    work.phase = EffectPhase::ReadyReply;
                }
                Err(_) => work.phase = EffectPhase::Indeterminate,
            }
        }
        NEXT_RETRY.store(crate::monotonic_time_100ns(), Ordering::Release);
        SubmitResult::Deferred
    }

    fn query_owner(
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        caller: NativeHandleCaller,
        token: u64,
    ) -> DirectoryQueryOwner<PeerRoute, LaneDispatchIdentity, NativeHandleCaller> {
        DirectoryQueryOwner {
            route,
            dispatch,
            caller,
            token,
        }
    }

    fn dispatch(
        &mut self,
        handler: &mut ExecNtHandler,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        caller: NativeHandleCaller,
        op: u64,
        m1: u64,
        m2: u64,
        m3: u64,
    ) -> Result<(u32, u64, u64, u64), u32> {
        match op {
            1 | 2 => {
                let total = usize::try_from(m3).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
                if total == 0 || total > MAX_NAME_UNITS {
                    return Err(STATUS_OBJECT_NAME_INVALID);
                }
                self.kinds
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                let token = self.next_token()?;
                self.uploads
                    .begin(
                        Self::owner(route, dispatch, caller, token),
                        DirectoryNameMetadata {
                            root_directory: m1,
                            attributes: (m2 >> 32) as u32,
                            desired_access: m2 as u32,
                            total_units: total,
                        },
                    )
                    .map_err(upload_status)?;
                // The operation kind is retained separately from the upload metadata.
                self.kinds.push((route, dispatch, token, op == 1));
                Ok((0, token, 0, 0))
            }
            3 => {
                let token = m1;
                let offset = (m2 >> 32) as usize;
                let count = m2 as u32 as usize;
                if count == 0 || count > 4 || token == 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let mut chunk = [0u16; 4];
                for (i, slot) in chunk.iter_mut().take(count).enumerate() {
                    *slot = (m3 >> (i * 16)) as u16;
                    if *slot == 0 || *slot > 0x7f {
                        return Err(STATUS_OBJECT_NAME_INVALID);
                    }
                }
                if count < 4 && m3 >> (count * 16) != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.uploads
                    .append(
                        Self::owner(route, dispatch, caller, token),
                        offset,
                        &chunk[..count],
                    )
                    .map_err(upload_status)?;
                Ok((0, 0, 0, 0))
            }
            4 => {
                let token = m1;
                if m2 != 0 || m3 != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let position = self
                    .kinds
                    .iter()
                    .position(|&(r, d, t, _)| r == route && d == dispatch && t == token)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                self.pending
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                self.failed_commits
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                let owner = Self::owner(route, dispatch, caller, token);
                let capture = self.uploads.commit(owner).map_err(upload_status)?;
                let create = self.kinds.swap_remove(position).3;
                let staged = handler.reserve_provider_directory_object(
                    capture.root_directory,
                    capture.attributes,
                    &capture.name,
                    caller,
                    capture.desired_access,
                    create,
                );
                let staged = match staged {
                    Ok(staged) => staged,
                    Err(status) => {
                        self.failed_commits.push(owner);
                        return Err(status);
                    }
                };
                let value = staged.value();
                self.pending.push(Pending {
                    owner,
                    staged,
                    phase: PendingPhase::Reserved,
                    publish: None,
                });
                Ok((0, value, 0, 0))
            }
            6 | 8 => {
                if m3 != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let owner = Self::owner(route, dispatch, caller, m1);
                if op == 6 && m2 == 0 && !self.pending.iter().any(|entry| entry.owner == owner) {
                    match self.uploads.phase(owner) {
                        Some(DirectoryUploadPhase::Uploading) => {
                            self.uploads.abort(owner).map_err(upload_status)?;
                            self.kinds
                                .retain(|&(r, d, t, _)| r != route || d != dispatch || t != m1);
                            return Ok((0, 0, 0, 0));
                        }
                        Some(DirectoryUploadPhase::Committed) => {
                            let index = self
                                .failed_commits
                                .iter()
                                .position(|&failed| failed == owner)
                                .ok_or(STATUS_INVALID_HANDLE)?;
                            self.failed_commits.swap_remove(index);
                            self.uploads.retire_definite(owner).map_err(upload_status)?;
                            return Ok((0, 0, 0, 0));
                        }
                        _ => return Err(STATUS_INVALID_HANDLE),
                    }
                }
                let position = self
                    .pending
                    .iter()
                    .position(|entry| entry.owner == owner && entry.staged.value() == m2)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                if op == 8 {
                    if self.pending[position].phase != PendingPhase::PublishedUnacknowledged {
                        return Err(STATUS_INVALID_HANDLE);
                    }
                    self.uploads
                        .retire_definite(owner)
                        .expect("acknowledged directory upload remains committed");
                    self.pending[position].phase = PendingPhase::Acknowledged;
                    Ok((0, 0, 0, 0))
                } else {
                    if !matches!(
                        self.pending[position].phase,
                        PendingPhase::Reserved | PendingPhase::Aborted
                    ) {
                        return Err(STATUS_INVALID_HANDLE);
                    }
                    if self.pending[position].phase == PendingPhase::Reserved
                        && !handler.abort_reserved_provider_directory_object(
                            &mut self.pending[position].staged)
                    {
                        return Err(STATUS_INVALID_HANDLE);
                    }
                    let _entry = self.pending.swap_remove(position);
                    self.uploads
                        .retire_definite(owner)
                        .expect("aborted directory upload remains committed");
                    Ok((0, 0, 0, 0))
                }
            }
            9..=12 => {
                let length = m3 as u32 as usize;
                let context = (m3 >> 32) as u32;
                let restart = op == 10 || op == 12;
                let single = op == 11 || op == 12;
                let entries = handler.snapshot_provider_directory_entries(caller, m1)?;
                let plan = plan_directory_entries(&entries, context, restart, single, m2, length)
                    .map_err(|status| status.raw() as u32)?;
                let query = plan.query();
                let token = if query.written != 0 {
                    let token = self.next_token()?;
                    self.queries
                        .begin(
                            Self::query_owner(route, dispatch, caller, token),
                            QuerySnapshot {
                                entries,
                                plan,
                                next_offset: 0,
                            },
                        )
                        .map_err(query_status)?;
                    token
                } else {
                    0
                };
                let lengths = (u64::from(query.return_length) << 32) | u64::from(query.written);
                Ok((
                    query.status.raw() as u32,
                    token,
                    lengths,
                    u64::from(query.context),
                ))
            }
            13 => {
                let offset = usize::try_from(m2).map_err(|_| STATUS_INVALID_PARAMETER)?;
                let count = usize::try_from(m3).map_err(|_| STATUS_INVALID_PARAMETER)?;
                if m1 == 0 || !(1..=24).contains(&count) {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let owner = Self::query_owner(route, dispatch, caller, m1);
                let snapshot = self.queries.get_mut(owner).map_err(query_status)?;
                let end = offset.checked_add(count).ok_or(STATUS_INVALID_PARAMETER)?;
                if offset != snapshot.next_offset || end > snapshot.plan.query().written as usize {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let mut bytes = [0u8; 24];
                snapshot
                    .plan
                    .read_range(&snapshot.entries, offset, &mut bytes[..count])
                    .map_err(|status| status.raw() as u32)?;
                snapshot.next_offset = end;
                Ok((
                    0,
                    u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
                    u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                    u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                ))
            }
            14 => {
                if m1 == 0 || m2 != 0 || m3 != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let owner = Self::query_owner(route, dispatch, caller, m1);
                let snapshot = self.queries.get(owner).map_err(query_status)?;
                if snapshot.next_offset != snapshot.plan.query().written as usize {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.queries.ack(owner).map_err(query_status)?;
                Ok((0, 0, 0, 0))
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    fn retire_completed(
        &mut self,
        handler: &mut ExecNtHandler,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
    ) {
        for index in (0..self.pending.len()).rev() {
            if self.pending[index].owner.route == route
                && self.pending[index].owner.dispatch.0 == dispatch
            {
                match self.pending[index].phase {
                    PendingPhase::PublishedUnacknowledged => {
                        let owner = self.pending[index].owner;
                        self.uploads
                            .mark_effect_uncertain(owner)
                            .expect("unacknowledged directory publication retains its upload");
                        self.pending[index].phase = PendingPhase::EffectUncertain;
                    }
                    PendingPhase::Publishing | PendingPhase::EffectUncertain => {}
                    phase => {
                        if phase == PendingPhase::Reserved
                            && !handler.abort_reserved_provider_directory_object(
                                &mut self.pending[index].staged)
                        {
                            self.pending[index].phase = PendingPhase::EffectUncertain;
                            continue;
                        }
                        let _entry = self.pending.swap_remove(index);
                    }
                }
            }
        }
        self.kinds
            .retain(|&(r, d, _, _)| r != route || d != dispatch);
        self.failed_commits
            .retain(|owner| owner.route != route || owner.dispatch.0 != dispatch);
        self.queries
            .retire_matching(|owner| owner.route == route && owner.dispatch == dispatch);
        self.uploads.retire_matching(|owner| {
            owner.route == route && owner.dispatch.0 == dispatch
                && !self.pending.iter().any(|entry| entry.owner == owner
                    && matches!(entry.phase, PendingPhase::Publishing | PendingPhase::EffectUncertain))
        });
    }
}

/// Poll one retained provider publication. The shared-ingress Reply is owned
/// by the exact service-wait token until transport ACK, independently of the
/// provider's later directory-upload ACK (op 8).
unsafe fn redrive_one(handler: &mut ExecNtHandler) -> bool {
    let broker = &mut *core::ptr::addr_of_mut!(BROKER);
    let len = broker.pending.len();
    if len == 0 { return false; }
    let start = (NEXT_SCAN.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len).find(|&index| {
        broker.pending[index].phase == PendingPhase::Publishing
            && broker.pending[index].publish.is_some()
    }) else { return false; };
    let entry = &mut broker.pending[index];
    let work = entry.publish.as_mut().expect("publishing directory owns Reply");
    let owner = entry.owner;
    if work.phase == PublishPhase::Start {
        if runtime::retained_service_cancelled(owner.route, owner.dispatch.0,
            work.reply, work.token)
        {
            if !handler.abort_reserved_provider_directory_object(&mut entry.staged) {
                return false;
            }
            runtime::acknowledge_retained_service_cancellation(owner.route,
                owner.dispatch.0, work.reply, work.token)
                .expect("cancelled pre-effect directory Reply retirement");
            work.reference.release(&mut handler.pm)
                .expect("cancelled directory requestor reference");
            entry.publish = None;
            entry.phase = PendingPhase::Aborted;
            return true;
        }
        if let Err(status) = work.reference.validate(&handler.pm) {
            if !handler.abort_reserved_provider_directory_object(&mut entry.staged) {
                return false;
            }
            work.status = status;
        } else {
            match handler.publish_provider_directory_object(&mut entry.staged, owner.caller) {
                DirectoryPublishProgress::Ready(status) | DirectoryPublishProgress::Failed(status) => {
                    work.status = status;
                }
                DirectoryPublishProgress::Pending => {
                    work.phase = PublishPhase::CanonicalPending;
                    return true;
                }
            }
        }
        work.phase = PublishPhase::ReadyReply;
        return true;
    }
    let cancelled = runtime::retained_service_cancelled(owner.route, owner.dispatch.0,
        work.reply, work.token);
    if work.phase == PublishPhase::CanonicalPending && cancelled {
        match handler.canonical_poll_directory_object(&mut entry.staged) {
            DirectoryPublishProgress::Ready(_) => {
                match handler.rollback_unpublished_directory_open(
                    &mut entry.staged, STATUS_CANCELLED) {
                    DirectoryPublishProgress::Failed(_) => {}
                    DirectoryPublishProgress::Pending => {
                        work.phase = PublishPhase::CanonicalRollback;
                        return true;
                    }
                    DirectoryPublishProgress::Ready(_) => return false,
                }
            }
            DirectoryPublishProgress::Failed(_) => {}
            DirectoryPublishProgress::Pending => return false,
        }
        runtime::acknowledge_retained_service_cancellation(owner.route,
            owner.dispatch.0, work.reply, work.token)
            .expect("cancelled directory Reply after canonical cleanup");
        work.reference.release(&mut handler.pm)
            .expect("cancelled directory requestor reference");
        entry.publish = None;
        entry.phase = PendingPhase::Aborted;
        return true;
    }
    if work.phase == PublishPhase::CanonicalRollback {
        if !cancelled { return false; }
        match handler.canonical_poll_directory_object(&mut entry.staged) {
            DirectoryPublishProgress::Failed(_) => {
                runtime::acknowledge_retained_service_cancellation(owner.route,
                    owner.dispatch.0, work.reply, work.token)
                    .expect("cancelled directory Reply after rollback");
                work.reference.release(&mut handler.pm)
                    .expect("cancelled directory requestor reference");
                entry.publish = None;
                entry.phase = PendingPhase::Aborted;
                return true;
            }
            DirectoryPublishProgress::Pending | DirectoryPublishProgress::Ready(_) => return false,
        }
    }
    if work.phase == PublishPhase::CanonicalPending {
        match handler.poll_provider_directory_object(&mut entry.staged) {
            DirectoryPublishProgress::Ready(status) | DirectoryPublishProgress::Failed(status) => {
                work.status = status;
                work.phase = PublishPhase::ReadyReply;
                return true;
            }
            DirectoryPublishProgress::Pending => return false,
        }
    }
    if cancelled {
        runtime::acknowledge_retained_service_cancellation(owner.route,
            owner.dispatch.0, work.reply, work.token)
            .expect("cancelled directory Reply retirement");
        work.reference.release(&mut handler.pm)
            .expect("cancelled directory requestor reference");
        if work.status == 0 || work.status == 0x4000_0000 {
            broker.uploads.mark_effect_uncertain(owner)
                .expect("published directory retains upload after cancelled Reply");
            entry.phase = PendingPhase::EffectUncertain;
        } else {
            entry.phase = PendingPhase::Aborted;
        }
        entry.publish = None;
        return true;
    }
    if work.phase == PublishPhase::ReadyReply {
        if runtime::wake_directory_service(owner.route, owner.dispatch.0,
            work.reply, work.token, work.status as i32).is_err()
            && matches!(runtime::retained_service_reply_not_entered(owner.route,
                owner.dispatch.0, work.reply, work.token), Ok(true))
        {
            return false;
        }
        work.phase = PublishPhase::ReplyEntered;
        return true;
    }
    if matches!(runtime::reconcile_retained_service_reply(owner.route,
        owner.dispatch.0, work.reply, work.token), Ok(true))
    {
        runtime::retire_stopped_acknowledged_retained_service(owner.route,
            owner.dispatch.0, work.reply, work.token)
            .expect("acknowledged directory service Reply retirement");
        work.reference.release(&mut handler.pm)
            .expect("acknowledged directory requestor reference");
        entry.phase = if work.status == 0 || work.status == 0x4000_0000 {
            PendingPhase::PublishedUnacknowledged
        } else {
            PendingPhase::Aborted
        };
        entry.publish = None;
        return true;
    }
    false
}

/// The native close is consumed at most once. Its detached directory identity remains in this
/// row while an Object Manager close is pending, so no name or lease is reused early.
fn retry_definite_close(work: &mut EffectWork) -> bool {
    if work.definite_close_retries >= MAX_DEFINITE_CLOSE_RETRIES {
        work.phase = EffectPhase::Indeterminate;
        return false;
    }
    work.definite_close_retries += 1;
    work.phase = EffectPhase::CanonicalStart;
    true
}

unsafe fn redrive_effect_one(handler: &mut ExecNtHandler) -> bool {
    let broker = &mut *core::ptr::addr_of_mut!(BROKER);
    let len = broker.effects.len();
    if len == 0 { return false; }
    let start = (EFFECT_NEXT_SCAN.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len).find(|&index|
        broker.effects[index].phase != EffectPhase::Indeterminate) else { return false; };
    let work = &mut broker.effects[index];
    let cancelled = runtime::retained_service_cancelled(work.route, work.dispatch,
        work.reply, work.token);
    if work.phase == EffectPhase::CanonicalStart {
        if cancelled && work.kind == EffectKind::MakeTemporary {
            runtime::acknowledge_retained_service_cancellation(work.route, work.dispatch,
                work.reply, work.token).expect("cancelled pre-effect make-temporary Reply");
            let mut work = broker.effects.swap_remove(index);
            work.reference.release(&mut handler.pm)
                .expect("cancelled make-temporary requestor reference");
            return true;
        }
        let result = if work.kind == EffectKind::Close {
            handler.release_provider_directory_canonical(work.identity)
        } else {
            handler.make_temporary_provider_directory_canonical(work.identity)
        };
        match result {
            Ok(Publication::Ready) => {
                let local = if work.kind == EffectKind::Close {
                    handler.finish_provider_directory_close(work.identity)
                } else {
                    handler.finish_provider_directory_make_temporary(work.identity)
                };
                if local.is_err() {
                    work.phase = EffectPhase::Indeterminate;
                    return false;
                }
                work.phase = EffectPhase::ReadyReply;
                return true;
            }
            Ok(Publication::Pending) => {
                work.phase = EffectPhase::CanonicalPending;
                return true;
            }
            Err(BackingError::NoEffect(status)) => {
                if work.kind == EffectKind::Close {
                    work.status = status;
                    return retry_definite_close(work);
                }
                work.status = status;
                work.phase = EffectPhase::ReadyReply;
                return true;
            }
            Err(BackingError::Terminal(status)) => {
                if work.kind == EffectKind::Close {
                    work.status = status;
                    return retry_definite_close(work);
                }
                work.status = status;
                work.phase = EffectPhase::ReadyReply;
                return true;
            }
            Err(_) => {
                work.phase = EffectPhase::Indeterminate;
                return false;
            }
        }
    }
    if work.phase == EffectPhase::CanonicalPending {
        let result = if work.kind == EffectKind::Close {
            handler.poll_provider_directory_canonical_close(work.identity)
        } else {
            handler.poll_provider_directory_make_temporary(work.identity)
        };
        match result {
            Ok(Some(Publication::Ready)) => {
                let local = if work.kind == EffectKind::Close {
                    handler.finish_provider_directory_close(work.identity)
                } else {
                    handler.finish_provider_directory_make_temporary(work.identity)
                };
                if local.is_err() {
                    work.phase = EffectPhase::Indeterminate;
                    return false;
                }
                work.phase = EffectPhase::ReadyReply;
                return true;
            }
            Ok(None) | Ok(Some(Publication::Pending)) => return false,
            Err(BackingError::NoEffect(status)) => {
                if work.kind == EffectKind::Close {
                    work.status = status;
                    return retry_definite_close(work);
                } else {
                    work.status = status;
                    work.phase = EffectPhase::ReadyReply;
                }
                return true;
            }
            Err(BackingError::Terminal(status)) => {
                if work.kind == EffectKind::Close {
                    work.status = status;
                    return retry_definite_close(work);
                }
                work.status = status;
                work.phase = EffectPhase::ReadyReply;
                return true;
            }
            Err(_) => {
                work.phase = EffectPhase::Indeterminate;
                return false;
            }
        }
    }
    if cancelled {
        runtime::acknowledge_retained_service_cancellation(work.route, work.dispatch,
            work.reply, work.token).expect("cancelled terminal directory effect Reply");
        let mut work = broker.effects.swap_remove(index);
        work.reference.release(&mut handler.pm)
            .expect("cancelled terminal directory effect requestor reference");
        return true;
    }
    if work.phase == EffectPhase::ReadyReply {
        if runtime::wake_directory_service(work.route, work.dispatch, work.reply,
            work.token, work.status as i32).is_err()
            && matches!(runtime::retained_service_reply_not_entered(work.route,
                work.dispatch, work.reply, work.token), Ok(true))
        {
            return false;
        }
        work.phase = EffectPhase::ReplyEntered;
        return true;
    }
    if matches!(runtime::reconcile_retained_service_reply(work.route, work.dispatch,
        work.reply, work.token), Ok(true)) {
        runtime::retire_stopped_acknowledged_retained_service(work.route, work.dispatch,
            work.reply, work.token).expect("acknowledged directory effect Reply");
        let mut work = broker.effects.swap_remove(index);
        work.reference.release(&mut handler.pm)
            .expect("acknowledged directory effect requestor reference");
        return true;
    }
    false
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) -> bool {
    if handler.is_null() || crate::monotonic_time_100ns() < NEXT_RETRY.load(Ordering::Acquire) {
        return false;
    }
    redrive_nested_ready(handler)
}

pub(crate) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    if handler.is_null() || REDRIVE_ACTIVE.swap(true, Ordering::AcqRel) { return false; }
    let progressed = redrive_one(&mut *handler) | redrive_effect_one(&mut *handler);
    NEXT_RETRY.store(crate::monotonic_time_100ns().saturating_add(RETRY_DELAY_100NS), Ordering::Release);
    REDRIVE_ACTIVE.store(false, Ordering::Release);
    progressed
}

pub(crate) fn next_deadline() -> Option<u64> {
    (unsafe { (&*core::ptr::addr_of!(BROKER)).pending.iter().any(|entry|
        entry.phase == PendingPhase::Publishing)
        || (&*core::ptr::addr_of!(BROKER)).effects.iter().any(|effect|
            effect.phase != EffectPhase::Indeterminate) })
        .then(|| NEXT_RETRY.load(Ordering::Acquire))
}

/// Includes quarantined owners that have no retry timer. A dormant timer is not proof that
/// a native Reply, requestor pin, or canonical directory lease has been retired.
pub(crate) fn has_outstanding() -> bool {
    unsafe {
        let broker = &*core::ptr::addr_of!(BROKER);
        broker.pending.iter().any(|entry| !matches!(entry.phase,
            PendingPhase::Aborted | PendingPhase::Acknowledged))
            || !broker.effects.is_empty()
    }
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

pub(crate) fn nested_work_ready() -> bool {
    wake_due(crate::monotonic_time_100ns()) != 0
}

fn upload_status(error: DirectoryUploadError) -> u32 {
    match error {
        DirectoryUploadError::InvalidLength
        | DirectoryUploadError::InvalidChunk
        | DirectoryUploadError::WrongOffset
        | DirectoryUploadError::Overflow
        | DirectoryUploadError::Incomplete
        | DirectoryUploadError::InvalidPhase => STATUS_INVALID_PARAMETER,
        DirectoryUploadError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        DirectoryUploadError::RouteOccupied | DirectoryUploadError::WrongOwner => {
            STATUS_INVALID_HANDLE
        }
    }
}

fn query_status(error: DirectoryQueryError) -> u32 {
    match error {
        DirectoryQueryError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        DirectoryQueryError::RouteOccupied
        | DirectoryQueryError::WrongOwner
        | DirectoryQueryError::AlreadyAcknowledged => STATUS_INVALID_HANDLE,
    }
}

static mut BROKER: Broker = Broker::new();

pub(crate) unsafe fn dispatch(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    identity: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    reply_cap: u64,
    op: u64,
    m1: u64,
    m2: u64,
    m3: u64,
) -> SubmitResult {
    let _durable = crate::allocator::enter_durable();
    let broker = &mut *core::ptr::addr_of_mut!(BROKER);
    if op == 5 {
        return broker.submit_publish(handler, route, identity, caller,
            reply_cap, m1, m2, m3);
    }
    if op == 7 || op == 15 {
        return broker.submit_effect(handler, route, identity, caller,
            reply_cap, op, m1, m2, m3);
    }
    match broker.dispatch(handler, route, identity, caller, op, m1, m2, m3) {
        Ok((status, out1, out2, out3)) => SubmitResult::Ready((status as i32, out1, out2, out3)),
        Err(status) => SubmitResult::Ready((status as i32, 0, 0, 0)),
    }
}

pub(crate) unsafe fn retire_completed(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    identity: LaneDispatchIdentity,
) {
    let _durable = crate::allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(BROKER)).retire_completed(handler, route, identity);
}
