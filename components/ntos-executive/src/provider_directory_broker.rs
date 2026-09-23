//! Inline win32k directory-object transport over the canonical executive namespace.

use alloc::vec::Vec;
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_object_manager::directory::{plan_directory_entries, DirectoryPackPlan};
use nt_process::native_handle::NativeHandleCaller;
use nt_types::UnicodeString;
use nt_user_host::provider_directory_name::{
    DirectoryNameMetadata, DirectoryNameUploads, DirectoryUploadError, DirectoryUploadOwner,
    DirectoryUploadPhase,
};
use nt_user_host::provider_directory_query::{
    DirectoryQueryError, DirectoryQueryOwner, DirectoryQuerySnapshots,
};

use crate::exec_handler::directory_object::ReservedProviderDirectoryObject;
use crate::ExecNtHandler;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const MAX_NAME_UNITS: usize = 1024;

type Owner = DirectoryUploadOwner<PeerRoute, (LaneDispatchIdentity, u64), NativeHandleCaller>;

struct Pending {
    owner: Owner,
    staged: ReservedProviderDirectoryObject,
    phase: PendingPhase,
}

struct QuerySnapshot {
    entries: Vec<(UnicodeString, UnicodeString)>,
    plan: DirectoryPackPlan,
    next_offset: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingPhase {
    Reserved,
    Aborted,
    PublishedUnacknowledged,
    Acknowledged,
    EffectUncertain,
}

struct Broker {
    uploads: DirectoryNameUploads<PeerRoute, (LaneDispatchIdentity, u64), NativeHandleCaller>,
    kinds: Vec<(PeerRoute, LaneDispatchIdentity, u64, bool)>,
    pending: Vec<Pending>,
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
                });
                Ok((0, value, 0, 0))
            }
            5 | 6 | 8 => {
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
                if op == 5 {
                    if self.pending[position].phase != PendingPhase::Reserved {
                        return Err(STATUS_INVALID_HANDLE);
                    }
                    match handler.publish_provider_directory_object(
                        &mut self.pending[position].staged,
                        caller,
                    ) {
                        Ok(status) => {
                            self.pending[position].phase = PendingPhase::PublishedUnacknowledged;
                            Ok((status, 0, 0, 0))
                        }
                        Err(status) => {
                            self.pending[position].phase = PendingPhase::Aborted;
                            Err(status)
                        }
                    }
                } else if op == 8 {
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
                    let mut entry = self.pending.swap_remove(position);
                    if entry.phase == PendingPhase::Reserved {
                        handler.abort_reserved_provider_directory_object(&mut entry.staged);
                    }
                    self.uploads
                        .retire_definite(owner)
                        .expect("aborted directory upload remains committed");
                    Ok((0, 0, 0, 0))
                }
            }
            7 => {
                if m2 != 0 || m3 != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                handler.close_provider_directory_object(caller, m1)?;
                Ok((0, 0, 0, 0))
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
                    PendingPhase::EffectUncertain => {}
                    phase => {
                        let mut entry = self.pending.swap_remove(index);
                        if phase == PendingPhase::Reserved {
                            handler.abort_reserved_provider_directory_object(&mut entry.staged);
                        }
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
        let uncertain = self
            .pending
            .iter()
            .find(|entry| {
                entry.owner.route == route
                    && entry.owner.dispatch.0 == dispatch
                    && entry.phase == PendingPhase::EffectUncertain
            })
            .map(|entry| entry.owner);
        self.uploads.retire_matching(|owner| {
            owner.route == route && owner.dispatch.0 == dispatch && Some(owner) != uncertain
        });
    }
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
    op: u64,
    m1: u64,
    m2: u64,
    m3: u64,
) -> (i32, u64, u64, u64) {
    let _durable = crate::allocator::enter_durable();
    let broker = &mut *core::ptr::addr_of_mut!(BROKER);
    match broker.dispatch(handler, route, identity, caller, op, m1, m2, m3) {
        Ok((status, out1, out2, out3)) => (status as i32, out1, out2, out3),
        Err(status) => (status as i32, 0, 0, 0),
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
