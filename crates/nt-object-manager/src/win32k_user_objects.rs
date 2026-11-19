//! The win32k provider's USER object bodies (WindowStation, Desktop and any other type win32k
//! creates through `ObCreateObject`).
//!
//! The store owns only what an NT object header owns: the body identity and its generation, the
//! pointer and handle counts, the name and the security descriptor, plus the created-but-not-yet-
//! inserted state that `ObInsertObject` consumes. Handles are not minted here: every handle lives
//! in its process's ProcessManager table and names the body by
//! `(object_type, body, generation)`. A body address recycled by the pool therefore never
//! inherits an earlier object's handles.
//!
//! Counts follow `references/nt5/base/ntos/ob`: each handle owns one pointer reference, a
//! handle count of zero removes the name (ObpDeleteNameCheck), and a pointer count of zero
//! transfers the body to the caller for its type's delete procedure ([`UserObjectRelease::Final`]).
//!
//! Like the rest of the win32k Ob layer this is allocation-free: the provider keeps it in a
//! `static`, and allocates and frees bodies from its own pool.

use crate::win32k_ob::ObKind;
use nt_status::NtStatus;

/// How a successful Desktop parse result becomes the caller's handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DesktopParseAdmission {
    /// The parse status the caller sees (`STATUS_OBJECT_NAME_EXISTS` for an OBJ_OPENIF open).
    pub status: NtStatus,
    pub identity: UserObjectIdentity,
}

/// Live and created-but-not-inserted objects the provider can own at once.
pub const USER_OBJECT_CAPACITY: usize = 64;
/// Maximum self-relative security descriptor bytes stored for one USER object.
pub const OB_SECURITY_DESCRIPTOR_MAX: usize = 1024;
/// Generations travel in 32 bits on the provider broker wire.
pub const USER_OBJECT_GENERATION_MAX: u64 = u32::MAX as u64;

/// The names this provider resolves without a namespace directory. A name is visible only
/// while its object is inserted and has at least one handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserObjectName {
    Unnamed,
    /// The interactive window station (`WinSta0`).
    InteractiveWindowStation,
    /// A noninteractive service window station, one per logon session.
    ServiceWindowStation { authentication_id: u64 },
}

/// The exact body a handle names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserObjectIdentity {
    pub kind: ObKind,
    /// The `OBJECT_TYPE` pointer the body was created with.
    pub object_type: u64,
    pub body: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserObjectRelease {
    Retained { pointers: u32, handles: u32 },
    /// The last reference is gone and the entry has been removed. The caller owns the body and
    /// must run its type's delete procedure and free it.
    Final(UserObjectIdentity),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserObjectError {
    /// No live entry for this body.
    Unknown,
    /// The body is live, but under a different generation or type than the caller named.
    Stale,
    /// The operation needs an inserted object (or, for insert, a created one).
    WrongState,
    /// The release would cross the pointer references the handles own.
    Underflow,
    Overflow,
    /// No free entry, an oversized descriptor or an exhausted generation counter.
    Exhausted,
    InvalidParameter,
}

#[derive(Clone, Copy)]
struct Entry {
    identity: UserObjectIdentity,
    pointer_count: u32,
    handle_count: u32,
    inserted: bool,
    name: UserObjectName,
    /// OBJ_INHERIT / OBJ_KERNEL_HANDLE captured by ObCreateObject for ObInsertObject.
    handle_attributes: u32,
    security_len: usize,
    security: [u8; OB_SECURITY_DESCRIPTOR_MAX],
}

impl Entry {
    fn security_descriptor(&self) -> Option<&[u8]> {
        (self.security_len != 0).then_some(&self.security[..self.security_len])
    }

    fn set_security_descriptor(&mut self, descriptor: &[u8]) -> bool {
        if descriptor.len() > self.security.len() {
            return false;
        }
        self.security[..descriptor.len()].copy_from_slice(descriptor);
        self.security_len = descriptor.len();
        true
    }

    fn named(&self, name: UserObjectName) -> bool {
        name != UserObjectName::Unnamed
            && self.name == name
            && self.inserted
            && self.handle_count != 0
    }
}

/// The provider's USER object bodies. The provider synchronizes access; a borrow must not be
/// held across a callback or broker call.
pub struct UserObjectStore {
    entries: [Option<Entry>; USER_OBJECT_CAPACITY],
    next_generation: u64,
}

impl Default for UserObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UserObjectStore {
    pub const fn new() -> Self {
        Self {
            entries: [None; USER_OBJECT_CAPACITY],
            next_generation: 1,
        }
    }

    fn index(&self, body: u64) -> Option<usize> {
        if body == 0 {
            return None;
        }
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.identity.body == body))
    }

    fn entry(&self, body: u64) -> Option<&Entry> {
        self.entries[self.index(body)?].as_ref()
    }

    fn exact_mut(&mut self, body: u64, generation: u64) -> Result<&mut Entry, UserObjectError> {
        let index = self.index(body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        if entry.identity.generation != generation {
            return Err(UserObjectError::Stale);
        }
        Ok(entry)
    }

    /// `ObCreateObject`: one creator pointer reference, no handle, invisible to names until
    /// `ObInsertObject`. Returns the body's generation.
    pub fn create(
        &mut self,
        kind: ObKind,
        object_type: u64,
        body: u64,
        descriptor: Option<&[u8]>,
        name: UserObjectName,
        handle_attributes: u32,
    ) -> Result<u64, UserObjectError> {
        if body == 0 || object_type == 0 {
            return Err(UserObjectError::InvalidParameter);
        }
        if self.index(body).is_some() {
            return Err(UserObjectError::WrongState);
        }
        if descriptor.is_some_and(|descriptor| descriptor.len() > OB_SECURITY_DESCRIPTOR_MAX)
            || self.next_generation > USER_OBJECT_GENERATION_MAX
        {
            return Err(UserObjectError::Exhausted);
        }
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(UserObjectError::Exhausted)?;
        let generation = self.next_generation;
        let mut entry = Entry {
            identity: UserObjectIdentity {
                kind,
                object_type,
                body,
                generation,
            },
            pointer_count: 1,
            handle_count: 0,
            inserted: false,
            name,
            handle_attributes,
            security_len: 0,
            security: [0; OB_SECURITY_DESCRIPTOR_MAX],
        };
        if let Some(descriptor) = descriptor {
            entry.set_security_descriptor(descriptor);
        }
        self.next_generation += 1;
        self.entries[slot] = Some(entry);
        Ok(generation)
    }

    /// `ObInsertObject`: the creator reference becomes the first handle's reference. Returns the
    /// identity and the handle attributes captured at create. A newer holder of the same name
    /// takes it over.
    pub fn insert(&mut self, body: u64) -> Result<(UserObjectIdentity, u32), UserObjectError> {
        let index = self.index(body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_ref().ok_or(UserObjectError::Unknown)?;
        if entry.inserted || entry.handle_count != 0 || entry.pointer_count == 0 {
            return Err(UserObjectError::WrongState);
        }
        let name = entry.name;
        if name != UserObjectName::Unnamed {
            for other in self.entries.iter_mut().flatten() {
                if other.identity.body != body && other.name == name {
                    other.name = UserObjectName::Unnamed;
                }
            }
        }
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        entry.inserted = true;
        entry.handle_count = 1;
        Ok((entry.identity, entry.handle_attributes))
    }

    /// A new handle to an inserted object that also takes its own pointer reference
    /// (`ObOpenObjectByPointer`, an open by name).
    pub fn open_handle(
        &mut self,
        body: u64,
        generation: u64,
    ) -> Result<UserObjectIdentity, UserObjectError> {
        let entry = self.exact_mut(body, generation)?;
        if !entry.inserted {
            return Err(UserObjectError::WrongState);
        }
        let pointers = entry.pointer_count.checked_add(1).ok_or(UserObjectError::Overflow)?;
        let handles = entry.handle_count.checked_add(1).ok_or(UserObjectError::Overflow)?;
        entry.pointer_count = pointers;
        entry.handle_count = handles;
        Ok(entry.identity)
    }

    /// Turn a pointer reference the caller already owns into a handle reference.
    pub fn transfer_reference_to_handle(
        &mut self,
        body: u64,
    ) -> Result<UserObjectIdentity, UserObjectError> {
        let index = self.index(body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        if !entry.inserted {
            return Err(UserObjectError::WrongState);
        }
        if entry.pointer_count <= entry.handle_count {
            return Err(UserObjectError::Underflow);
        }
        entry.handle_count = entry.handle_count.checked_add(1).ok_or(UserObjectError::Overflow)?;
        Ok(entry.identity)
    }

    /// Handles copied by ProcessManager (inheritance, duplication) each own a reference.
    pub fn apply_acquired_handles(
        &mut self,
        identity: UserObjectIdentity,
        count: u32,
    ) -> Result<(), UserObjectError> {
        let entry = self.exact_mut(identity.body, identity.generation)?;
        if entry.identity != identity {
            return Err(UserObjectError::Stale);
        }
        if !entry.inserted || entry.handle_count == 0 {
            return Err(UserObjectError::WrongState);
        }
        let pointers = entry.pointer_count.checked_add(count).ok_or(UserObjectError::Overflow)?;
        let handles = entry.handle_count.checked_add(count).ok_or(UserObjectError::Overflow)?;
        entry.pointer_count = pointers;
        entry.handle_count = handles;
        Ok(())
    }

    /// Release `count` closed handles and the pointer references they owned.
    pub fn apply_released_handles(
        &mut self,
        identity: UserObjectIdentity,
        count: u32,
    ) -> Result<UserObjectRelease, UserObjectError> {
        let index = self.index(identity.body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        if entry.identity != identity {
            return Err(UserObjectError::Stale);
        }
        if count == 0 || !entry.inserted {
            return Err(UserObjectError::WrongState);
        }
        if entry.handle_count < count || entry.pointer_count < entry.handle_count {
            return Err(UserObjectError::Underflow);
        }
        entry.handle_count -= count;
        entry.pointer_count -= count;
        if entry.handle_count == 0 {
            entry.name = UserObjectName::Unnamed;
        }
        Ok(self.settle(index))
    }

    /// Close one handle this provider created but could not publish.
    pub fn close_handle(
        &mut self,
        identity: UserObjectIdentity,
    ) -> Result<UserObjectRelease, UserObjectError> {
        self.apply_released_handles(identity, 1)
    }

    fn settle(&mut self, index: usize) -> UserObjectRelease {
        let entry = self.entries[index].expect("settled entry is live");
        if entry.pointer_count == 0 {
            self.entries[index] = None;
            return UserObjectRelease::Final(entry.identity);
        }
        UserObjectRelease::Retained {
            pointers: entry.pointer_count,
            handles: entry.handle_count,
        }
    }

    /// `ObReferenceObject`.
    pub fn reference(&mut self, body: u64) -> Result<u32, UserObjectError> {
        let index = self.index(body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        entry.pointer_count = entry.pointer_count.checked_add(1).ok_or(UserObjectError::Overflow)?;
        Ok(entry.pointer_count)
    }

    /// `ObDereferenceObject`: releases one pointer reference that no handle owns.
    pub fn dereference(&mut self, body: u64) -> Result<UserObjectRelease, UserObjectError> {
        let index = self.index(body).ok_or(UserObjectError::Unknown)?;
        let entry = self.entries[index].as_mut().ok_or(UserObjectError::Unknown)?;
        if entry.pointer_count <= entry.handle_count {
            return Err(UserObjectError::Underflow);
        }
        entry.pointer_count -= 1;
        Ok(self.settle(index))
    }

    pub fn identity(&self, body: u64) -> Option<UserObjectIdentity> {
        self.entry(body).map(|entry| entry.identity)
    }

    /// The identity of a body that is inserted, under exactly this generation.
    pub fn inserted_identity(&self, body: u64, generation: u64) -> Option<UserObjectIdentity> {
        self.entry(body)
            .filter(|entry| entry.inserted && entry.identity.generation == generation)
            .map(|entry| entry.identity)
    }

    pub fn kind_by_body(&self, body: u64) -> Option<ObKind> {
        self.entry(body).map(|entry| entry.identity.kind)
    }

    /// `(pointer_count, handle_count)`.
    pub fn counts(&self, body: u64) -> Option<(u32, u32)> {
        self.entry(body)
            .map(|entry| (entry.pointer_count, entry.handle_count))
    }

    pub fn is_inserted(&self, body: u64) -> bool {
        self.entry(body).is_some_and(|entry| entry.inserted)
    }

    /// `ObGetObjectType`. An object created with a type this layer did not recognize has no
    /// provable registered type identity and returns `None`.
    pub fn object_type_addr_by_body(&self, body: u64) -> Option<u64> {
        let entry = self.entry(body)?;
        (entry.identity.kind != ObKind::Other).then_some(entry.identity.object_type)
    }

    /// `ObOpenObjectByName` after the WindowStation parse procedure returned a Desktop. Win32k's
    /// `IntDesktopObjectParse` either created the body (`ObCreateObject`, Context = TRUE), whose
    /// creator reference becomes the first handle's, or found it on `DesktopListHead` and took
    /// one `ObReferenceObject` reference, which the new handle consumes. Each count is counted
    /// here; on an error the caller still owns the reference the parse returned.
    pub fn admit_desktop_parse_result(
        &mut self,
        status: NtStatus,
        object: u64,
        created: bool,
    ) -> Result<DesktopParseAdmission, NtStatus> {
        if status.is_error() {
            return Err(status);
        }
        if object == 0
            || (created && status != NtStatus::SUCCESS)
            || (!created && status != NtStatus::SUCCESS && status != NtStatus::OBJECT_NAME_EXISTS)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let entry = self.entry(object).ok_or(NtStatus::INVALID_HANDLE)?;
        if entry.identity.kind != ObKind::Desktop {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        if created {
            if entry.inserted {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            // The handle takes the opener's attributes, not those of win32k's ObCreateObject.
            let (identity, _) = self.insert(object).map_err(|_| NtStatus::INVALID_PARAMETER)?;
            Ok(DesktopParseAdmission { status, identity })
        } else {
            let identity = self.transfer_reference_to_handle(object).map_err(|error| match error {
                UserObjectError::Overflow => NtStatus::INSUFFICIENT_RESOURCES,
                _ => NtStatus::INVALID_PARAMETER,
            })?;
            Ok(DesktopParseAdmission { status, identity })
        }
    }

    /// The inserted object that currently holds `name`.
    pub fn named(&self, name: UserObjectName) -> Option<UserObjectIdentity> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.named(name))
            .map(|entry| entry.identity)
    }

    /// The outer `None` rejects an unknown body; the inner `None` is a valid null descriptor.
    pub fn security_descriptor_by_body(&self, body: u64) -> Option<(ObKind, Option<&[u8]>)> {
        let entry = self.entry(body)?;
        Some((entry.identity.kind, entry.security_descriptor()))
    }

    /// The descriptor of exactly this body generation (a handle's target).
    pub fn security_descriptor_for(&self, body: u64, generation: u64) -> Option<Option<&[u8]>> {
        let entry = self.entry(body)?;
        (entry.identity.generation == generation).then(|| entry.security_descriptor())
    }

    pub fn set_security_descriptor_by_body(
        &mut self,
        body: u64,
        kind: ObKind,
        descriptor: &[u8],
    ) -> bool {
        let Some(index) = self.index(body) else {
            return false;
        };
        self.entries[index]
            .as_mut()
            .is_some_and(|entry| entry.identity.kind == kind && entry.set_security_descriptor(descriptor))
    }

    pub fn set_security_descriptor_for(
        &mut self,
        body: u64,
        generation: u64,
        descriptor: &[u8],
    ) -> bool {
        self.exact_mut(body, generation)
            .is_ok_and(|entry| entry.set_security_descriptor(descriptor))
    }
}

#[cfg(test)]
mod tests;
