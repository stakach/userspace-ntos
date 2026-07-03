//! Per-client handle tables and the client registry.
//!
//! A handle is a per-client, generation-protected name for an object. Each open
//! handle holds a strong [`ObjectRef`] — so it contributes to the object's
//! `pointer_count` (keeping it alive) and increments its `handle_count`. Closing
//! a handle decrements `handle_count` and drops the reference. Handle values are
//! meaningful only in the issuing client's table; a value from another client (or
//! a reused/closed slot) fails to resolve with `STATUS_INVALID_HANDLE`.

use alloc::vec::Vec;

use nt_status::NtStatus;
use nt_types::{AccessMask, AccessMode, ClientId, Generation, HandleValue, ObjAttrFlags};

use crate::store::ObjectRef;

/// The kind of a connected client (governs default access-check policy).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ClientKind {
    ExecutiveService,
    DriverHost,
    NativeUser,
    Test,
}

/// One entry in a handle table.
struct HandleEntry {
    /// Strong reference — contributes to the object's `pointer_count`.
    object: ObjectRef,
    /// Access granted when the handle was opened.
    granted_access: AccessMask,
    /// `OBJ_*` handle attributes (e.g. `INHERIT`); consulted by handle
    /// duplication/inheritance in a later milestone.
    #[allow(dead_code)]
    attributes: ObjAttrFlags,
}

struct HandleSlot {
    generation: Generation,
    entry: Option<HandleEntry>,
}

/// A per-client table mapping [`HandleValue`]s to objects.
#[derive(Default)]
pub struct HandleTable {
    slots: Vec<HandleSlot>,
}

impl HandleTable {
    fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Number of open handles.
    pub fn open_count(&self) -> usize {
        self.slots.iter().filter(|s| s.entry.is_some()).count()
    }

    /// Insert an object reference, returning a fresh handle. Increments the
    /// object's handle count. `object` must already be a clone the table takes
    /// ownership of.
    fn insert(
        &mut self,
        object: ObjectRef,
        granted_access: AccessMask,
        attributes: ObjAttrFlags,
    ) -> HandleValue {
        object.inc_handle_count();
        let idx = self.find_free_slot();
        let generation = if idx < self.slots.len() {
            self.slots[idx].generation.next()
        } else {
            Generation(1)
        };
        let slot = HandleSlot {
            generation,
            entry: Some(HandleEntry {
                object,
                granted_access,
                attributes,
            }),
        };
        if idx < self.slots.len() {
            self.slots[idx] = slot;
        } else {
            self.slots.push(slot);
        }
        HandleValue::new(generation, idx as u64)
    }

    /// Resolve a handle to its entry, validating slot + generation + occupancy.
    fn get(&self, handle: HandleValue) -> Result<&HandleEntry, NtStatus> {
        let idx = handle.slot() as usize;
        let slot = self.slots.get(idx).ok_or(NtStatus::INVALID_HANDLE)?;
        if slot.generation != handle.generation() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        slot.entry.as_ref().ok_or(NtStatus::INVALID_HANDLE)
    }

    /// Close a handle: decrement the object's handle count and return the
    /// reference so the caller can run namespace reaping before it drops (which
    /// may take `pointer_count` to zero and delete the object).
    fn close(&mut self, handle: HandleValue) -> Result<ObjectRef, NtStatus> {
        let idx = handle.slot() as usize;
        let slot = self.slots.get_mut(idx).ok_or(NtStatus::INVALID_HANDLE)?;
        if slot.generation != handle.generation() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let entry = slot.entry.take().ok_or(NtStatus::INVALID_HANDLE)?;
        entry.object.dec_handle_count();
        Ok(entry.object)
    }

    /// Close every handle (client death), returning the closed references so the
    /// caller can reap. Decrements each object's handle count.
    fn close_all(&mut self) -> Vec<ObjectRef> {
        let mut closed = Vec::new();
        for slot in &mut self.slots {
            if let Some(entry) = slot.entry.take() {
                entry.object.dec_handle_count();
                closed.push(entry.object);
            }
        }
        closed
    }

    fn find_free_slot(&self) -> usize {
        self.slots
            .iter()
            .position(|s| s.entry.is_none())
            .unwrap_or(self.slots.len())
    }
}

/// Per-client state (spec §16).
struct ClientRecord {
    #[allow(dead_code)]
    kind: ClientKind,
    #[allow(dead_code)]
    access_mode: AccessMode,
    handle_table: HandleTable,
}

/// Registry of connected clients. `ClientId` is the registration index; slots are
/// not reused in v0.1, so a closed client's id never aliases a new one.
#[derive(Default)]
pub struct ClientRegistry {
    clients: Vec<Option<ClientRecord>>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
        }
    }

    pub fn register(&mut self, kind: ClientKind, access_mode: AccessMode) -> ClientId {
        let id = ClientId(self.clients.len() as u64);
        self.clients.push(Some(ClientRecord {
            kind,
            access_mode,
            handle_table: HandleTable::new(),
        }));
        id
    }

    fn record(&self, client: ClientId) -> Result<&ClientRecord, NtStatus> {
        self.clients
            .get(client.0 as usize)
            .and_then(|o| o.as_ref())
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn record_mut(&mut self, client: ClientId) -> Result<&mut ClientRecord, NtStatus> {
        self.clients
            .get_mut(client.0 as usize)
            .and_then(|o| o.as_mut())
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    /// Close a client: close all its handles (returning the closed references for
    /// the caller to reap), then drop its record.
    pub fn close(&mut self, client: ClientId) -> Result<Vec<ObjectRef>, NtStatus> {
        let closed = self.record_mut(client)?.handle_table.close_all();
        self.clients[client.0 as usize] = None;
        Ok(closed)
    }

    /// Open a handle to `object` for `client`.
    pub fn open_handle(
        &mut self,
        client: ClientId,
        object: ObjectRef,
        granted_access: AccessMask,
        attributes: ObjAttrFlags,
    ) -> Result<HandleValue, NtStatus> {
        let rec = self.record_mut(client)?;
        Ok(rec.handle_table.insert(object, granted_access, attributes))
    }

    /// Resolve a handle in `client`'s table to a new counted reference,
    /// enforcing the expected type and requested access.
    pub fn reference_by_handle(
        &self,
        client: ClientId,
        handle: HandleValue,
        expected_type: Option<nt_types::ObjectTypeId>,
        desired_access: AccessMask,
    ) -> Result<ObjectRef, NtStatus> {
        let rec = self.record(client)?;
        let entry = rec.handle_table.get(handle)?;
        if let Some(ty) = expected_type {
            if entry.object.type_id() != ty {
                return Err(NtStatus::OBJECT_TYPE_MISMATCH);
            }
        }
        if !entry.granted_access.contains(desired_access) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        Ok(entry.object.clone())
    }

    /// Close a handle in `client`'s table, returning the closed reference.
    pub fn close_handle(
        &mut self,
        client: ClientId,
        handle: HandleValue,
    ) -> Result<ObjectRef, NtStatus> {
        self.record_mut(client)?.handle_table.close(handle)
    }

    /// Number of open handles held by `client` (debug/tests).
    pub fn open_handle_count(&self, client: ClientId) -> Result<usize, NtStatus> {
        Ok(self.record(client)?.handle_table.open_count())
    }
}
