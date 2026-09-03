//! win32k DESKTOP / WINDOWSTATION object layer as a raw-memory primitive.
//!
//! win32k.sys creates and opens real `DESKTOP` and `WINDOWSTATION_OBJECT` bodies through the
//! ntoskrnl `Ob*` API — `ObOpenObjectByName` / `ObCreateObject` / `ObInsertObject` /
//! `ObReferenceObjectByHandle`. When those fall to a no-op stub (return `STATUS_SUCCESS` but write
//! no handle/object), `IntCreateDesktop` sees `Context == FALSE` and returns early *without*
//! building the desktop window graph. To drive win32k past that early-return it needs a real object
//! layer: allocate object bodies, mint handles for them, and resolve those handles back to their
//! bodies with type awareness (`IntGetAndReferenceClass(WC_DESKTOP)` etc.).
//!
//! Like [`session_section`](../../nt_kernel_exec/session_section) this is a raw-pointer,
//! allocation-free primitive: the win32k host component's bump heap is spent by the time win32k
//! runs, so the state lives in a caller-owned [`ObHandleTable`] (a `static`), and body allocation is
//! done by the caller against win32k's own pool. The object-manager *semantics* — dense handle
//! minting, the handle→(type, body) registry, the create→insert latch, and the
//! single-instance window-station cache — live here, host-tested, reused by every hosted binary
//! that drives the win32k Ob path. The type-object VAs win32k passes (`ExDesktopObjectType` /
//! `ExWindowStationObjectType`) are classified by the caller into an [`ObKind`]; this module never
//! sees a host VA. Real Ob semantics reference: `references/nt5/base/ntos/ob/` (ObpCreateHandle,
//! OBJECT_HEADER/OBJECT_TYPE); DESKTOP layout: `references/reactos/win32ss/user/ntuser/desktop.c`.

use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ExternalObjectReference {
    object: u64,
    pointer_count: u32,
}

/// Provider-backed object references projected into win32k as opaque object pointers. The table
/// owns local pointer-count semantics over one retained provider reference; its final row is removed
/// only after the provider confirms release, so a failed external teardown remains retryable.
#[derive(Default)]
pub struct ExternalObjectReferenceTable {
    entries: Vec<ExternalObjectReference>,
}

impl ExternalObjectReferenceTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn reserve(&mut self) -> bool {
        self.entries.try_reserve(1).is_ok()
    }

    pub fn insert_reserved(&mut self, object: u64) -> bool {
        if object == 0 || self.entries.iter().any(|entry| entry.object == object) {
            return false;
        }
        self.entries.push(ExternalObjectReference {
            object,
            pointer_count: 1,
        });
        true
    }

    pub fn contains(&self, object: u64) -> bool {
        self.entries.iter().any(|entry| entry.object == object)
    }

    pub fn reference(&mut self, object: u64) -> Option<u32> {
        let entry = self.entries.iter_mut().find(|entry| entry.object == object)?;
        entry.pointer_count = entry.pointer_count.checked_add(1)?;
        Some(entry.pointer_count)
    }

    /// Decrement a non-final reference. `None` means the exact row is at its final reference and
    /// remains unchanged until [`complete_final_release`](Self::complete_final_release).
    pub fn dereference_nonfinal(&mut self, object: u64) -> Result<Option<u32>, ()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.object == object)
            .ok_or(())?;
        if entry.pointer_count == 1 {
            return Ok(None);
        }
        entry.pointer_count -= 1;
        Ok(Some(entry.pointer_count))
    }

    pub fn complete_final_release(&mut self, object: u64) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.object == object && entry.pointer_count == 1)
        else {
            return false;
        };
        self.entries.remove(index);
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The win32k object types this layer models — the `DESKTOP` and `WINDOWSTATION_OBJECT`
/// `OBJECT_TYPE`s (`ExDesktopObjectType` / `ExWindowStationObjectType`), plus `Other` for an object
/// win32k creates through `ObCreateObject` whose type the caller did not recognize (still tracked so
/// its handle resolves).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObKind {
    /// A `DESKTOP` object (`ExDesktopObjectType`).
    Desktop,
    /// A `WINDOWSTATION_OBJECT` (`ExWindowStationObjectType`).
    WindowStation,
    /// An object of some other (unrecognized) win32k type.
    Other,
}

/// Classify the `OBJECT_TYPE` pointer win32k passed into an [`ObKind`], keying off the **real**
/// [`object_type`](crate::object_type) statics (`ExDesktopObjectType` / `ExWindowStationObjectType`).
///
/// win32k reads these type pointers out of its imported data-export cells and hands them to the
/// `Ob*` trampolines purely as identity tokens (the win32k.sys machine code only ever *writes* the
/// desktop/window-station `->TypeInfo.*` fields and passes the pointer by identity — it never reads a
/// field back). The executive points those cells at the real `OBJECT_TYPE` statics and resolves the
/// win32k object type by comparing the pointer against their addresses; a pointer that matches
/// neither is an unrecognized type ([`None`]).
pub fn classify(type_ptr: u64) -> Option<ObKind> {
    if type_ptr == crate::object_type::desktop_object_type_addr() {
        Some(ObKind::Desktop)
    } else if type_ptr == crate::object_type::window_station_object_type_addr() {
        Some(ObKind::WindowStation)
    } else {
        None
    }
}

/// Enforce an `ObReferenceObjectByHandle` **ExpectedType** against an object of `kind`.
///
/// NT semantics (`references/nt5/base/ntos/ob/obref.c` `ObpReferenceObjectByHandle`): if the caller
/// passes a non-NULL `ObjectType` and the referenced object's type does not match, the reference
/// fails with `STATUS_OBJECT_TYPE_MISMATCH`. A NULL `ObjectType` (`expected_type_ptr == 0`) is the
/// polymorphic case (e.g. `NtClose` / `NtQueryObject`) — any type is allowed.
///
/// `expected_type_ptr` is the `POBJECT_TYPE` the caller supplied — the address of one of the real
/// [`object_type`](crate::object_type) statics. A `Desktop` / `WindowStation` object matches only its
/// own type static. [`ObKind::Other`] (an object created through `ObCreateObject` with a type this
/// layer did not recognize) cannot be verified, so it stays permissive.
pub fn object_type_matches(kind: ObKind, expected_type_ptr: u64) -> bool {
    if expected_type_ptr == 0 {
        return true; // NULL ExpectedType: polymorphic, any type allowed.
    }
    match kind {
        ObKind::Desktop => expected_type_ptr == crate::object_type::desktop_object_type_addr(),
        ObKind::WindowStation => {
            expected_type_ptr == crate::object_type::window_station_object_type_addr()
        }
        // Unrecognized create-time type: we have no type identity to check against — stay permissive
        // rather than reject (preserves the pre-enforcement behaviour for these objects).
        ObKind::Other => true,
    }
}

/// DESKTOP body field offsets (`references/reactos/win32ss/user/ntuser/desktop.h` `struct _DESKTOP`).
pub mod desktop {
    /// `PDESKTOPINFO pDeskInfo` — the desktop-info block hung off the DESKTOP body.
    pub const P_DESK_INFO: usize = 0x08;
    /// `LIST_ENTRY PtiList` — the desktop's thread-info list head (desktop.h). Offset from the
    /// DESKTOP layout: dwSessionId@0, pDeskInfo@8, ListEntry@0x10, rpwinstaParent@0x20, dwDTFlags@0x28,
    /// dwDesktopId@0x30, spmenu{Sys,DialogSys,HScroll,VScroll}@0x38..0x58, spwnd*@0x58..0x78,
    /// hsectionDesktop@0x78, pheapDesktop@0x80, ulHeapSize@0x88, PtiList@0x90.
    pub const PTI_LIST: usize = 0x90;
    /// `LIST_ENTRY ShellHookWindows` — the desktop's shell-hook window list head. Continuing:
    /// dwConsoleThreadId@0xA0, spwndTrack@0xA8, htEx@0xB0, rcMouseHover@0xB4, dwMouseHoverTime@0xC4,
    /// ActiveMessageQueue@0xC8, DesktopWindow@0xD0, BlockInputThread@0xD8, ShellHookWindows@0xE0.
    /// `UserBuildShellHookHwndList` (desktop.c) walks this on every window activation (SWP_SHOWWINDOW
    /// → co_IntShellHookNotify) — an uninitialized head null-derefs.
    pub const SHELL_HOOK_WINDOWS: usize = 0xE0;
}

/// THREADINFO field offsets used by the desktop membership invariant.
pub mod thread_info {
    /// `LIST_ENTRY PtiLink` — membership in `THREADINFO.rpdesk->PtiList`.
    pub const PTI_LINK: usize = 0x148;
}

/// Body size to allocate for a `DESKTOP` (real `sizeof(DESKTOP)` is ~0x100; headroom, zeroed).
pub const DESKTOP_BODY_SIZE: u64 = 0x200;
/// Body size to allocate for a `DESKTOPINFO` (+ `szDesktopName` tail, zeroed).
pub const DESKTOPINFO_SIZE: u64 = 0x120;

/// Number of live win32k objects the table can hold. Slot 0 is reserved (handle 0 == `NULL`).
pub const OB_TABLE_LEN: usize = 32;

/// Number of externally visible aliases created by `NtDuplicateObject` for USER objects.
pub const OB_ALIASES_LEN: usize = 32;
/// Number of named desktop links tracked under window-station directories.
pub const OB_NAMED_DESKTOPS_LEN: usize = 32;
/// Maximum ASCII desktop leaf name retained for open-by-name lookups.
pub const OB_NAMED_DESKTOP_NAME_MAX: usize = 48;
/// Keep duplicate aliases disjoint from both native EPROCESS handles and win32k's dense Ob handles.
pub const OB_ALIAS_HANDLE_BASE: u64 = 0x7FF0_0000;
/// Maximum self-relative security descriptor bytes stored for one modeled USER object.
pub const OB_SECURITY_DESCRIPTOR_MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ObjectEntry {
    kind: ObKind,
    body: u64,
    pointer_count: u32,
    handle_count: u32,
    security_len: usize,
    security: [u8; OB_SECURITY_DESCRIPTOR_MAX],
}

impl ObjectEntry {
    const fn new(kind: ObKind, body: u64) -> Self {
        Self {
            kind,
            body,
            // A published USER object starts with one handle. ObInsertObject consumes the creator
            // reference while establishing that handle, so the initial pointer and handle counts
            // are both one.
            pointer_count: 1,
            handle_count: 1,
            security_len: 0,
            security: [0; OB_SECURITY_DESCRIPTOR_MAX],
        }
    }

    fn with_security(kind: ObKind, body: u64, descriptor: Option<&[u8]>) -> Option<Self> {
        let mut entry = Self::new(kind, body);
        if let Some(descriptor) = descriptor {
            if !entry.set_security_descriptor(descriptor) {
                return None;
            }
        }
        Some(entry)
    }

    fn pair(self) -> (ObKind, u64) {
        (self.kind, self.body)
    }

    fn set_body(&mut self, body: u64) {
        self.body = body;
    }

    fn reference(&mut self) -> Option<u32> {
        self.pointer_count = self.pointer_count.checked_add(1)?;
        Some(self.pointer_count)
    }

    fn dereference(&mut self) -> Option<u32> {
        if self.pointer_count <= self.handle_count {
            return None;
        }
        self.pointer_count -= 1;
        Some(self.pointer_count)
    }

    fn open_handle(&mut self) -> bool {
        let Some(pointer_count) = self.pointer_count.checked_add(1) else {
            return false;
        };
        let Some(handle_count) = self.handle_count.checked_add(1) else {
            return false;
        };
        self.pointer_count = pointer_count;
        self.handle_count = handle_count;
        true
    }

    fn close_handle(&mut self) -> bool {
        if self.handle_count <= 1 || self.pointer_count < self.handle_count {
            return false;
        }
        self.handle_count -= 1;
        self.pointer_count -= 1;
        true
    }

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
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct NamedDesktopEntry {
    root_body: u64,
    leaf_len: u8,
    leaf: [u8; OB_NAMED_DESKTOP_NAME_MAX],
    handle: u64,
}

impl NamedDesktopEntry {
    fn new(root_body: u64, leaf: &[u8], handle: u64) -> Option<Self> {
        if root_body == 0
            || leaf.is_empty()
            || leaf.len() > OB_NAMED_DESKTOP_NAME_MAX
            || handle == 0
        {
            return None;
        }
        let mut entry = Self {
            root_body,
            leaf_len: leaf.len() as u8,
            leaf: [0; OB_NAMED_DESKTOP_NAME_MAX],
            handle,
        };
        entry.leaf[..leaf.len()].copy_from_slice(leaf);
        Some(entry)
    }

    fn matches(self, root_body: u64, leaf: &[u8]) -> bool {
        self.root_body == root_body
            && self.leaf_len as usize == leaf.len()
            && self.leaf[..leaf.len()].eq_ignore_ascii_case(leaf)
    }
}

/// A fixed-size handle → (type, body) registry for win32k's DESKTOP / WINDOWSTATION objects.
///
/// Handles are minted densely from 1; the client-visible `HANDLE` is `idx << 2` (a real Ob handle
/// carries tag bits in the low two bits, so shifting keeps them clear), always non-null and
/// distinguishable from any handle *not* in the table (e.g. win32k's process-connect handle, which
/// the caller resolves via an `EPROCESS` fallback). Single-threaded host: a plain struct suffices.
pub struct ObHandleTable {
    slots: [Option<ObjectEntry>; OB_TABLE_LEN],
    next: usize,
    /// Latches `ObCreateObject`'s body, type, and captured security descriptor so the following
    /// `ObInsertObject` can register it under a fresh handle.
    pending: Option<ObjectEntry>,
    /// The one input window station once created; a later `ObOpenObjectByName(WINSTA)` OPENs it
    /// (returns this handle) instead of reporting NOT_FOUND (which would create a duplicate).
    winsta_handle: u64,
    winsta_body: u64,
    /// USER-object aliases minted for `NtDuplicateObject`, indexed by a high-range external handle.
    aliases: [Option<(ObKind, u64)>; OB_ALIASES_LEN],
    /// Named DESKTOP objects under WINDOWSTATION directories. Real Ob lookup uses the root directory
    /// handle and leaf name; this compact table preserves that semantic without allocating.
    named_desktops: [Option<NamedDesktopEntry>; OB_NAMED_DESKTOPS_LEN],
}

impl Default for ObHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ObHandleTable {
    /// An empty table (usable as a `static` initializer).
    pub const fn new() -> Self {
        Self {
            slots: [None; OB_TABLE_LEN],
            next: 1,
            pending: None,
            winsta_handle: 0,
            winsta_body: 0,
            aliases: [None; OB_ALIASES_LEN],
            named_desktops: [None; OB_NAMED_DESKTOPS_LEN],
        }
    }

    fn register_entry(&mut self, entry: ObjectEntry, cache_window_station: bool) -> u64 {
        let idx = (1..self.next)
            .find(|&idx| self.slots[idx].is_none())
            .unwrap_or(self.next);
        if idx >= OB_TABLE_LEN {
            return 0;
        }
        if idx == self.next {
            self.next = idx + 1;
        }
        let kind = entry.kind;
        let body = entry.body;
        self.slots[idx] = Some(entry);
        let handle = (idx as u64) << 2;
        if cache_window_station && kind == ObKind::WindowStation {
            self.winsta_handle = handle;
            self.winsta_body = body;
        }
        handle
    }

    fn register_inner(
        &mut self,
        kind: ObKind,
        body: u64,
        cache_window_station: bool,
        descriptor: Option<&[u8]>,
    ) -> u64 {
        let Some(entry) = ObjectEntry::with_security(kind, body, descriptor) else {
            return 0;
        };
        self.register_entry(entry, cache_window_station)
    }

    /// Register `body` under `kind` at a fresh slot and return its client-visible `HANDLE`
    /// (`idx << 2`), or 0 if the table is full. A `WindowStation` registration is also cached as
    /// the single input window station.
    pub fn register(&mut self, kind: ObKind, body: u64) -> u64 {
        self.register_inner(kind, body, true, None)
    }

    /// Register `body` with an initial self-relative security descriptor captured from the caller's
    /// `OBJECT_ATTRIBUTES`.
    pub fn register_with_security(
        &mut self,
        kind: ObKind,
        body: u64,
        descriptor: Option<&[u8]>,
    ) -> u64 {
        self.register_inner(kind, body, true, descriptor)
    }

    /// Register `body` under `kind` without changing the cached input window station. Noninteractive
    /// service window stations are real `WindowStation` objects, but they must not replace WinSta0
    /// as the interactive station later host code uses for GUI-client inheritance.
    pub fn register_uncached(&mut self, kind: ObKind, body: u64) -> u64 {
        self.register_inner(kind, body, false, None)
    }

    /// Register `body` with an initial security descriptor without replacing the cached input window
    /// station.
    pub fn register_uncached_with_security(
        &mut self,
        kind: ObKind,
        body: u64,
        descriptor: Option<&[u8]>,
    ) -> u64 {
        self.register_inner(kind, body, false, descriptor)
    }

    /// Find a canonical handle for an object body of the expected kind.
    pub fn handle_for_body(&self, kind: ObKind, body: u64) -> Option<u64> {
        if body == 0 {
            return None;
        }
        for (idx, slot) in self.slots.iter().enumerate().skip(1) {
            if slot.is_some_and(|entry| entry.kind == kind && entry.body == body) {
                return Some((idx as u64) << 2);
            }
        }
        None
    }

    /// Create a closeable alias for an object body of the expected kind.
    pub fn duplicate_by_body(&mut self, kind: ObKind, body: u64) -> Option<u64> {
        let handle = self.handle_for_body(kind, body)?;
        self.duplicate(handle)
    }

    /// Create a distinct high-range handle alias for an existing win32k object. Keeping aliases out
    /// of the dense range prevents a USER handle from colliding with an EPROCESS-native handle.
    pub fn duplicate(&mut self, handle: u64) -> Option<u64> {
        let (kind, body) = self.lookup(handle)?;
        let index = self.aliases.iter().position(Option::is_none)?;
        let canonical = self
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.kind == kind && entry.body == body)?;
        if !canonical.open_handle() {
            return None;
        }
        self.aliases[index] = Some((kind, body));
        Some(OB_ALIAS_HANDLE_BASE + (index as u64) * 4)
    }

    /// Close an alias created by [`duplicate`](Self::duplicate). Object bodies come from win32k's
    /// session-lifetime pool, so closing removes only this alias; the original remains valid.
    pub fn close(&mut self, handle: u64) -> bool {
        if handle < OB_ALIAS_HANDLE_BASE || handle & 0b11 != 0 {
            return false;
        }
        let index = ((handle - OB_ALIAS_HANDLE_BASE) >> 2) as usize;
        let Some((kind, body)) = self.aliases.get(index).copied().flatten() else {
            return false;
        };
        let Some(canonical) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.kind == kind && entry.body == body)
        else {
            return false;
        };
        if !canonical.close_handle() {
            return false;
        }
        self.aliases[index] = None;
        true
    }

    /// Resolve a handle to its `(kind, body)`, or `None` if it is not a registered win32k object
    /// handle. Checks the dense `idx << 2` object slots (Desktop/WindowStation/Other), then the
    /// externally minted aliases.
    pub fn lookup(&self, handle: u64) -> Option<(ObKind, u64)> {
        if handle >= OB_ALIAS_HANDLE_BASE && handle & 0b11 == 0 {
            let index = ((handle - OB_ALIAS_HANDLE_BASE) >> 2) as usize;
            if let Some(entry) = self.aliases.get(index).copied().flatten() {
                return Some(entry);
            }
        }
        let idx = (handle >> 2) as usize;
        if idx != 0 && idx < self.next {
            if let Some(entry) = self.slots.get(idx).copied().flatten() {
                return Some(entry.pair());
            }
        }
        None
    }

    /// Resolve a handle to its body, or 0 if it is not a registered win32k object handle.
    pub fn lookup_body(&self, handle: u64) -> u64 {
        self.lookup(handle).map(|(_, body)| body).unwrap_or(0)
    }

    /// Return `(pointer_count, handle_count)` for the canonical object containing `body`.
    pub fn counts_by_body(&self, body: u64) -> Option<(u32, u32)> {
        self.slots
            .iter()
            .flatten()
            .find(|entry| entry.body == body)
            .map(|entry| (entry.pointer_count, entry.handle_count))
    }

    /// Acquire one pointer reference by object body, as `ObReferenceObject` does.
    pub fn reference_by_body(&mut self, body: u64) -> Option<u32> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.body == body)?
            .reference()
    }

    /// Release one non-handle pointer reference by object body. The handle-owned floor cannot be
    /// crossed; final handle teardown remains a separate operation with an explicit finalizer.
    pub fn dereference_by_body(&mut self, body: u64) -> Option<u32> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.body == body)?
            .dereference()
    }

    fn window_station_body_for_handle(&self, root_handle: u64) -> Option<u64> {
        match self.lookup(root_handle) {
            Some((ObKind::WindowStation, body)) if body != 0 => Some(body),
            _ => None,
        }
    }

    /// Resolve a named desktop under a window-station root handle.
    pub fn desktop_handle_for_name(&self, root_handle: u64, leaf: &[u8]) -> Option<u64> {
        let root_body = self.window_station_body_for_handle(root_handle)?;
        let entry = self
            .named_desktops
            .iter()
            .flatten()
            .find(|entry| entry.matches(root_body, leaf))?;
        matches!(self.lookup(entry.handle), Some((ObKind::Desktop, _))).then_some(entry.handle)
    }

    /// Record the name of a desktop created under a window-station root handle.
    pub fn remember_desktop_name(&mut self, root_handle: u64, leaf: &[u8], handle: u64) -> bool {
        if !matches!(self.lookup(handle), Some((ObKind::Desktop, _))) {
            return false;
        }
        let Some(root_body) = self.window_station_body_for_handle(root_handle) else {
            return false;
        };
        let Some(entry) = NamedDesktopEntry::new(root_body, leaf, handle) else {
            return false;
        };
        for slot in self.named_desktops.iter_mut() {
            if slot.is_some_and(|existing| existing.matches(root_body, leaf)) {
                *slot = Some(entry);
                return true;
            }
        }
        if let Some(slot) = self.named_desktops.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(entry);
            true
        } else {
            false
        }
    }

    fn canonical_slot_index(&self, handle: u64) -> Option<usize> {
        if handle >= OB_ALIAS_HANDLE_BASE && handle & 0b11 == 0 {
            let index = ((handle - OB_ALIAS_HANDLE_BASE) >> 2) as usize;
            let (kind, body) = self.aliases.get(index).copied().flatten()?;
            return self
                .slots
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, slot)| {
                    slot.is_some_and(|entry| entry.kind == kind && entry.body == body)
                })
                .map(|(idx, _)| idx);
        }
        let idx = (handle >> 2) as usize;
        if idx != 0 && idx < self.next && self.slots.get(idx)?.is_some() {
            Some(idx)
        } else {
            None
        }
    }

    /// Return the USER-object handle grant that win32k's Ob layer assigned at create/open time.
    pub fn granted_access(&self, handle: u64) -> Option<u32> {
        self.lookup(handle).map(|(kind, _)| match kind {
            // winuser.h: WINSTA_ALL_ACCESS / DESKTOP_ALL_ACCESS.
            ObKind::WindowStation => 0x000f_037f,
            ObKind::Desktop => 0x000f_01ff,
            ObKind::Other => u32::MAX,
        })
    }

    /// Stored self-relative security descriptor for a modeled Desktop/WindowStation object.
    pub fn security_descriptor(&self, handle: u64) -> Option<&[u8]> {
        let idx = self.canonical_slot_index(handle)?;
        self.slots[idx]
            .as_ref()
            .and_then(ObjectEntry::security_descriptor)
    }

    /// Replace the object's self-relative security descriptor.
    pub fn set_security_descriptor(&mut self, handle: u64, descriptor: &[u8]) -> bool {
        let Some(idx) = self.canonical_slot_index(handle) else {
            return false;
        };
        self.slots[idx]
            .as_mut()
            .is_some_and(|entry| entry.set_security_descriptor(descriptor))
    }

    /// Latch a (kind, body) from `ObCreateObject` for the following `ObInsertObject`.
    pub fn latch_pending(&mut self, kind: ObKind, body: u64) {
        self.pending = Some(ObjectEntry::new(kind, body));
    }

    /// Latch a (kind, body, security descriptor) from `ObCreateObject` for the following
    /// `ObInsertObject`. Returns `false` if the descriptor is too large for the modeled object header.
    pub fn latch_pending_with_security(
        &mut self,
        kind: ObKind,
        body: u64,
        descriptor: Option<&[u8]>,
    ) -> bool {
        let Some(entry) = ObjectEntry::with_security(kind, body, descriptor) else {
            return false;
        };
        self.pending = Some(entry);
        true
    }

    fn insert_pending_inner(&mut self, object: u64, cache_window_station: bool) -> u64 {
        let entry = match self.pending.take() {
            Some(mut entry) => {
                entry.set_body(object);
                entry
            }
            None => ObjectEntry::new(ObKind::Other, object),
        };
        self.register_entry(entry, cache_window_station)
    }

    /// Register the latched object under a fresh handle (`ObInsertObject`). Uses the kind latched by
    /// [`latch_pending`](Self::latch_pending), defaulting to [`ObKind::Other`] if none was latched,
    /// clears the latch, and returns the new handle.
    pub fn insert_pending(&mut self, object: u64) -> u64 {
        self.insert_pending_inner(object, true)
    }

    /// Register the latched object without replacing the cached input window station.
    pub fn insert_pending_uncached(&mut self, object: u64) -> u64 {
        self.insert_pending_inner(object, false)
    }

    /// The cached input window-station handle (0 if none has been created yet).
    pub fn cached_winsta_handle(&self) -> u64 {
        self.winsta_handle
    }

    /// The cached input window-station body (0 if none has been created yet).
    pub fn cached_winsta_body(&self) -> u64 {
        self.winsta_body
    }
}

/// Wire a freshly-allocated, zeroed DESKTOP body to its DESKTOPINFO block (`DESKTOP.pDeskInfo`).
/// Mirrors the effect of win32k's desktop allocation; kept here so the body layout lives with the
/// object-type definition rather than in host glue.
///
/// # Safety
/// `desktop_body` must point to at least [`DESKTOP_BODY_SIZE`] writable bytes.
pub unsafe fn init_desktop_body(desktop_body: *mut u8, desktop_info: u64) {
    core::ptr::write_unaligned(
        desktop_body.add(desktop::P_DESK_INFO) as *mut u64,
        desktop_info,
    );
    // InitializeListHead the DESKTOP's list heads (Flink=Blink=&head), as real IntCreateDesktop does.
    // The window-manager/paint path walks these (PtiList, ShellHookWindows); a zeroed (NULL Flink) head
    // null-derefs on the first traversal.
    for off in [desktop::PTI_LIST, desktop::SHELL_HOOK_WINDOWS] {
        let head = desktop_body.add(off) as u64;
        core::ptr::write_unaligned(desktop_body.add(off) as *mut u64, head); // Flink = &head
        core::ptr::write_unaligned(desktop_body.add(off + 8) as *mut u64, head);
        // Blink = &head
    }
}

/// Insert a THREADINFO into a DESKTOP's `PtiList`, matching `InsertTailList` in
/// `IntSetThreadDesktop`. Returns `false` when the desktop list head was not initialized or the
/// thread entry is already linked elsewhere.
///
/// # Safety
/// `desktop_body` and `thread_body` must point to writable DESKTOP/THREADINFO bodies containing
/// the fields described by [`desktop::PTI_LIST`] and [`thread_info::PTI_LINK`].
pub unsafe fn link_thread_to_desktop(desktop_body: *mut u8, thread_body: *mut u8) -> bool {
    let head = desktop_body.add(desktop::PTI_LIST);
    let entry = thread_body.add(thread_info::PTI_LINK);
    let tail = core::ptr::read_unaligned(head.add(8) as *const u64) as *mut u8;
    if tail.is_null() {
        return false;
    }
    let entry_flink = core::ptr::read_unaligned(entry as *const u64);
    let entry_blink = core::ptr::read_unaligned(entry.add(8) as *const u64);
    if (entry_flink != 0 || entry_blink != 0)
        && (entry_flink != entry as u64 || entry_blink != entry as u64)
    {
        return false;
    }

    core::ptr::write_unaligned(entry as *mut u64, head as u64);
    core::ptr::write_unaligned(entry.add(8) as *mut u64, tail as u64);
    core::ptr::write_unaligned(tail as *mut u64, entry as u64);
    core::ptr::write_unaligned(head.add(8) as *mut u64, entry as u64);
    true
}

/// Remove `THREADINFO.PtiLink` from its current desktop list, matching `RemoveEntryList`, then
/// reset the entry to a self-referential empty list head. Returns `false` if the entry's backlinks
/// are not a valid linked-list membership.
///
/// # Safety
/// `thread_body` must point to a writable THREADINFO body containing [`thread_info::PTI_LINK`].
pub unsafe fn unlink_thread_from_desktop(thread_body: *mut u8) -> bool {
    let entry = thread_body.add(thread_info::PTI_LINK);
    let flink = core::ptr::read_unaligned(entry as *const u64) as *mut u8;
    let blink = core::ptr::read_unaligned(entry.add(8) as *const u64) as *mut u8;
    if flink.is_null() || blink.is_null() {
        return false;
    }
    if flink == entry && blink == entry {
        return true;
    }
    let flink_blink = core::ptr::read_unaligned(flink.add(8) as *const u64);
    let blink_flink = core::ptr::read_unaligned(blink as *const u64);
    if flink_blink != entry as u64 || blink_flink != entry as u64 {
        return false;
    }
    core::ptr::write_unaligned(flink.add(8) as *mut u64, blink as u64);
    core::ptr::write_unaligned(blink as *mut u64, flink as u64);
    core::ptr::write_unaligned(entry as *mut u64, entry as u64);
    core::ptr::write_unaligned(entry.add(8) as *mut u64, entry as u64);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_keys_off_real_object_type_statics() {
        use crate::object_type::{desktop_object_type_addr, window_station_object_type_addr};
        // The real OBJECT_TYPE static addresses discriminate DESKTOP vs WINDOWSTATION.
        assert_eq!(classify(desktop_object_type_addr()), Some(ObKind::Desktop));
        assert_eq!(
            classify(window_station_object_type_addr()),
            Some(ObKind::WindowStation)
        );
        // Any other pointer (an unrecognized type, or a stale placeholder value) does not resolve.
        assert_eq!(classify(0), None);
        assert_eq!(classify(0xDEAD_BEEF), None);
        assert_eq!(
            classify(desktop_object_type_addr() ^ 0x1000),
            None,
            "a nearby-but-wrong pointer must not classify"
        );
    }

    #[test]
    fn object_type_matches_enforces_expected_type() {
        use crate::object_type::{
            desktop_object_type_addr, process_object_type_addr, window_station_object_type_addr,
        };
        // Matching type resolves.
        assert!(object_type_matches(
            ObKind::Desktop,
            desktop_object_type_addr()
        ));
        assert!(object_type_matches(
            ObKind::WindowStation,
            window_station_object_type_addr()
        ));
        // NULL ExpectedType is polymorphic: any kind resolves.
        assert!(object_type_matches(ObKind::Desktop, 0));
        assert!(object_type_matches(ObKind::WindowStation, 0));
        assert!(object_type_matches(ObKind::Other, 0));
        // Mismatched type is rejected (would be STATUS_OBJECT_TYPE_MISMATCH).
        assert!(!object_type_matches(
            ObKind::Desktop,
            window_station_object_type_addr()
        ));
        assert!(!object_type_matches(
            ObKind::WindowStation,
            desktop_object_type_addr()
        ));
        // A desktop referenced as a Process (wrong type) is rejected.
        assert!(!object_type_matches(
            ObKind::Desktop,
            process_object_type_addr()
        ));
        // Unrecognized create-time type stays permissive (no identity to verify).
        assert!(object_type_matches(
            ObKind::Other,
            desktop_object_type_addr()
        ));
    }

    #[test]
    fn registers_and_resolves_typed_objects() {
        let mut t = ObHandleTable::new();
        let desk = t.register(ObKind::Desktop, 0xD00D_0000);
        let winsta = t.register(ObKind::WindowStation, 0x5700_0000);
        assert_eq!(desk, 1 << 2);
        assert_eq!(winsta, 2 << 2);
        assert_eq!(t.lookup(desk), Some((ObKind::Desktop, 0xD00D_0000)));
        assert_eq!(t.lookup(winsta), Some((ObKind::WindowStation, 0x5700_0000)));
        assert_eq!(t.lookup_body(desk), 0xD00D_0000);
    }

    #[test]
    fn handles_are_dense_and_unique_with_clear_tag_bits() {
        let mut t = ObHandleTable::new();
        let a = t.register(ObKind::Desktop, 0x1000);
        let b = t.register(ObKind::Desktop, 0x2000);
        let c = t.register(ObKind::Desktop, 0x3000);
        assert_eq!((a, b, c), (4, 8, 12));
        assert_ne!(a, b);
        assert_ne!(b, c);
        for h in [a, b, c] {
            assert_eq!(h & 0b11, 0, "low tag bits must be clear");
        }
        assert_eq!(t.lookup_body(b), 0x2000);
    }

    #[test]
    fn duplicate_aliases_the_typed_object_and_closes_independently() {
        let mut t = ObHandleTable::new();
        let original = t.register(ObKind::Desktop, 0xD00D_0000);
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((1, 1)));
        let duplicate = t.duplicate(original).unwrap();
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((2, 2)));
        assert_ne!(duplicate, original);
        assert_eq!(t.lookup(duplicate), t.lookup(original));
        assert!(t.close(duplicate));
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((1, 1)));
        assert_eq!(t.lookup(duplicate), None);
        assert_eq!(t.lookup(original), Some((ObKind::Desktop, 0xD00D_0000)));
        assert!(!t.close(duplicate));
        assert_eq!(t.duplicate(original), Some(duplicate));
    }

    #[test]
    fn user_pointer_references_cannot_cross_the_handle_owned_floor() {
        let mut t = ObHandleTable::new();
        let handle = t.register(ObKind::WindowStation, 0x5700_0000);

        assert_eq!(t.counts_by_body(0x5700_0000), Some((1, 1)));
        assert_eq!(t.reference_by_body(0x5700_0000), Some(2));
        assert_eq!(t.counts_by_body(0x5700_0000), Some((2, 1)));
        assert_eq!(t.dereference_by_body(0x5700_0000), Some(1));
        assert_eq!(t.dereference_by_body(0x5700_0000), None);
        assert_eq!(t.lookup(handle), Some((ObKind::WindowStation, 0x5700_0000)));
        assert_eq!(t.counts_by_body(0x5700_0000), Some((1, 1)));
    }

    #[test]
    fn duplicate_handle_and_pointer_references_balance_independently() {
        let mut t = ObHandleTable::new();
        let handle = t.register(ObKind::Desktop, 0xD00D_0000);
        let alias = t.duplicate(handle).unwrap();

        assert_eq!(t.reference_by_body(0xD00D_0000), Some(3));
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((3, 2)));
        assert!(t.close(alias));
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((2, 1)));
        assert_eq!(t.dereference_by_body(0xD00D_0000), Some(1));
        assert_eq!(t.counts_by_body(0xD00D_0000), Some((1, 1)));
    }

    #[test]
    fn user_object_security_is_shared_by_aliases() {
        let mut t = ObHandleTable::new();
        let original = t.register(ObKind::WindowStation, 0x5700_0000);
        let alias = t.duplicate(original).unwrap();
        let descriptor = [0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00];

        assert_eq!(t.security_descriptor(original), None);
        assert!(t.set_security_descriptor(alias, &descriptor));
        assert_eq!(t.security_descriptor(original), Some(descriptor.as_slice()));
        assert_eq!(t.security_descriptor(alias), Some(descriptor.as_slice()));

        assert!(t.close(alias));
        assert_eq!(t.security_descriptor(original), Some(descriptor.as_slice()));
        assert_eq!(t.security_descriptor(alias), None);
    }

    #[test]
    fn user_object_security_rejects_oversized_descriptors() {
        let mut t = ObHandleTable::new();
        let handle = t.register(ObKind::Desktop, 0xD00D_0000);
        let oversized = [0xAA; OB_SECURITY_DESCRIPTOR_MAX + 1];

        assert!(!t.set_security_descriptor(handle, &oversized));
        assert_eq!(t.security_descriptor(handle), None);
    }

    #[test]
    fn user_object_granted_access_tracks_kind() {
        let mut t = ObHandleTable::new();
        let desk = t.register(ObKind::Desktop, 0xD00D_0000);
        let winsta = t.register(ObKind::WindowStation, 0x5700_0000);

        assert_eq!(t.granted_access(desk), Some(0x000f_01ff));
        assert_eq!(t.granted_access(winsta), Some(0x000f_037f));
        assert_eq!(t.granted_access(0), None);
    }

    #[test]
    fn unknown_and_null_handles_do_not_resolve() {
        let mut t = ObHandleTable::new();
        let h = t.register(ObKind::Desktop, 0x1000);
        assert_eq!(t.lookup(0), None);
        assert_eq!(t.lookup_body(0), 0);
        assert_eq!(t.lookup(h + 4), None); // never minted
        assert_eq!(t.lookup(0x5A5A_0100), None); // an unrelated handle (EPROCESS fallback territory)
    }

    #[test]
    fn create_then_insert_latches_the_type() {
        let mut t = ObHandleTable::new();
        // ObCreateObject(WINDOWSTATION) → latch, then ObInsertObject(body) → register.
        t.latch_pending(ObKind::WindowStation, 0x7700_0000);
        let h = t.insert_pending(0x7700_0000);
        assert_eq!(t.lookup(h), Some((ObKind::WindowStation, 0x7700_0000)));
        // The latch is consumed; a bare insert with no latch defaults to Other.
        let h2 = t.insert_pending(0x8800_0000);
        assert_eq!(t.lookup(h2), Some((ObKind::Other, 0x8800_0000)));
    }

    #[test]
    fn create_then_insert_preserves_initial_security() {
        let mut t = ObHandleTable::new();
        let descriptor = [0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00];

        assert!(t.latch_pending_with_security(
            ObKind::WindowStation,
            0x7700_0000,
            Some(&descriptor)
        ));
        let h = t.insert_pending(0x7700_0000);

        assert_eq!(t.lookup(h), Some((ObKind::WindowStation, 0x7700_0000)));
        assert_eq!(t.security_descriptor(h), Some(descriptor.as_slice()));
    }

    #[test]
    fn window_station_is_cached_as_single_instance() {
        let mut t = ObHandleTable::new();
        assert_eq!(t.cached_winsta_handle(), 0);
        t.latch_pending(ObKind::WindowStation, 0x7700_0000);
        let h = t.insert_pending(0x7700_0000);
        assert_eq!(t.cached_winsta_handle(), h);
        assert_eq!(t.cached_winsta_body(), 0x7700_0000);
        // A registered Desktop must not disturb the cached window station.
        t.register(ObKind::Desktop, 0xD000);
        assert_eq!(t.cached_winsta_handle(), h);
    }

    #[test]
    fn uncached_window_station_does_not_replace_input_station() {
        let mut t = ObHandleTable::new();
        let input = t.register(ObKind::WindowStation, 0x7700_0000);
        let service = t.register_uncached(ObKind::WindowStation, 0x8800_0000);
        assert_ne!(service, 0);
        assert_eq!(t.cached_winsta_handle(), input);
        assert_eq!(t.cached_winsta_body(), 0x7700_0000);
        assert_eq!(
            t.lookup(service),
            Some((ObKind::WindowStation, 0x8800_0000))
        );
    }

    #[test]
    fn body_pointer_open_uses_a_closeable_alias() {
        let mut t = ObHandleTable::new();
        let original = t.register(ObKind::Desktop, 0xD00D_0000);
        assert_eq!(
            t.handle_for_body(ObKind::Desktop, 0xD00D_0000),
            Some(original)
        );
        let alias = t
            .duplicate_by_body(ObKind::Desktop, 0xD00D_0000)
            .expect("alias");
        assert_ne!(alias, original);
        assert_eq!(t.lookup(alias), Some((ObKind::Desktop, 0xD00D_0000)));
        assert!(t.close(alias));
        assert_eq!(t.lookup(original), Some((ObKind::Desktop, 0xD00D_0000)));
    }

    #[test]
    fn named_desktop_lookup_is_scoped_to_window_station_body() {
        let mut t = ObHandleTable::new();
        let interactive_winsta = t.register(ObKind::WindowStation, 0x5700_0000);
        let service_winsta = t.register_uncached(ObKind::WindowStation, 0x5700_1000);
        let interactive_default = t.register(ObKind::Desktop, 0xD00D_0000);
        let service_default = t.register(ObKind::Desktop, 0xD00D_1000);

        assert!(t.remember_desktop_name(interactive_winsta, b"Default", interactive_default));
        assert!(t.remember_desktop_name(service_winsta, b"default", service_default));

        assert_eq!(
            t.desktop_handle_for_name(interactive_winsta, b"default"),
            Some(interactive_default)
        );
        assert_eq!(
            t.desktop_handle_for_name(service_winsta, b"Default"),
            Some(service_default)
        );
    }

    #[test]
    fn named_desktop_lookup_accepts_root_aliases() {
        let mut t = ObHandleTable::new();
        let winsta = t.register(ObKind::WindowStation, 0x5700_0000);
        let winsta_alias = t.duplicate(winsta).unwrap();
        let desktop = t.register(ObKind::Desktop, 0xD00D_0000);

        assert!(t.remember_desktop_name(winsta, b"Default", desktop));
        assert_eq!(
            t.desktop_handle_for_name(winsta_alias, b"Default"),
            Some(desktop)
        );
    }

    #[test]
    fn table_full_returns_null_handle() {
        let mut t = ObHandleTable::new();
        for i in 1..OB_TABLE_LEN {
            assert_ne!(t.register(ObKind::Desktop, i as u64 * 0x1000), 0);
        }
        assert_eq!(t.register(ObKind::Desktop, 0xDEAD), 0); // full
    }

    #[test]
    fn desktop_body_wires_desk_info() {
        let mut body = [0u8; DESKTOP_BODY_SIZE as usize];
        unsafe {
            init_desktop_body(body.as_mut_ptr(), 0xDEC0_0000);
            let p =
                core::ptr::read_unaligned(body.as_ptr().add(desktop::P_DESK_INFO) as *const u64);
            assert_eq!(p, 0xDEC0_0000);
        }
    }

    #[test]
    fn desktop_body_initializes_list_heads() {
        // ShellHookWindows + PtiList must be self-referential empty list heads (Flink=Blink=&head),
        // so win32k's list traversals (UserBuildShellHookHwndList) terminate immediately.
        let mut body = [0u8; DESKTOP_BODY_SIZE as usize];
        let base = body.as_mut_ptr() as u64;
        unsafe {
            init_desktop_body(body.as_mut_ptr(), 0x1000);
            for off in [desktop::PTI_LIST, desktop::SHELL_HOOK_WINDOWS] {
                let flink = core::ptr::read_unaligned(body.as_ptr().add(off) as *const u64);
                let blink = core::ptr::read_unaligned(body.as_ptr().add(off + 8) as *const u64);
                assert_eq!(flink, base + off as u64);
                assert_eq!(blink, base + off as u64);
            }
        }
    }

    #[test]
    fn desktop_thread_link_has_all_insert_tail_backlinks() {
        let mut body = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut thread = [0u8; 0x300];
        let head = unsafe { body.as_mut_ptr().add(desktop::PTI_LIST) } as u64;
        let entry = unsafe { thread.as_mut_ptr().add(thread_info::PTI_LINK) } as u64;
        unsafe {
            init_desktop_body(body.as_mut_ptr(), 0x1000);
            assert!(link_thread_to_desktop(
                body.as_mut_ptr(),
                thread.as_mut_ptr()
            ));
            assert_eq!(core::ptr::read_unaligned(head as *const u64), entry);
            assert_eq!(core::ptr::read_unaligned((head + 8) as *const u64), entry);
            assert_eq!(core::ptr::read_unaligned(entry as *const u64), head);
            assert_eq!(core::ptr::read_unaligned((entry + 8) as *const u64), head);
        }
    }

    #[test]
    fn desktop_thread_unlink_restores_empty_membership() {
        let mut body = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut thread = [0u8; 0x300];
        let head = unsafe { body.as_mut_ptr().add(desktop::PTI_LIST) } as u64;
        let entry = unsafe { thread.as_mut_ptr().add(thread_info::PTI_LINK) } as u64;
        unsafe {
            init_desktop_body(body.as_mut_ptr(), 0x1000);
            assert!(link_thread_to_desktop(
                body.as_mut_ptr(),
                thread.as_mut_ptr()
            ));
            assert!(unlink_thread_from_desktop(thread.as_mut_ptr()));
            assert_eq!(core::ptr::read_unaligned(head as *const u64), head);
            assert_eq!(core::ptr::read_unaligned((head + 8) as *const u64), head);
            assert_eq!(core::ptr::read_unaligned(entry as *const u64), entry);
            assert_eq!(core::ptr::read_unaligned((entry + 8) as *const u64), entry);
        }
    }

    #[test]
    fn desktop_thread_link_rejects_live_membership() {
        let mut first = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut second = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut thread = [0u8; 0x300];
        unsafe {
            init_desktop_body(first.as_mut_ptr(), 0x1000);
            init_desktop_body(second.as_mut_ptr(), 0x2000);
            assert!(link_thread_to_desktop(
                first.as_mut_ptr(),
                thread.as_mut_ptr()
            ));
            assert!(!link_thread_to_desktop(
                second.as_mut_ptr(),
                thread.as_mut_ptr()
            ));
            assert!(unlink_thread_from_desktop(thread.as_mut_ptr()));
            assert!(link_thread_to_desktop(
                second.as_mut_ptr(),
                thread.as_mut_ptr()
            ));
        }
    }

    #[test]
    fn desktop_thread_unlink_rejects_corrupt_membership() {
        let mut thread = [0u8; 0x300];
        let mut scratch = [0u8; 0x20];
        let entry = unsafe { thread.as_mut_ptr().add(thread_info::PTI_LINK) } as u64;
        let flink = scratch.as_mut_ptr() as u64;
        let blink = unsafe { scratch.as_mut_ptr().add(0x10) } as u64;
        unsafe {
            core::ptr::write_unaligned(entry as *mut u64, flink);
            core::ptr::write_unaligned((entry + 8) as *mut u64, blink);
            core::ptr::write_unaligned((flink + 8) as *mut u64, 0);
            core::ptr::write_unaligned(blink as *mut u64, 0);
            assert!(!unlink_thread_from_desktop(thread.as_mut_ptr()));
        }
    }

    #[test]
    fn desktop_thread_link_rejects_uninitialized_head() {
        let mut body = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut thread = [0u8; 0x300];
        assert!(!unsafe { link_thread_to_desktop(body.as_mut_ptr(), thread.as_mut_ptr()) });
    }

    #[test]
    fn external_reference_table_releases_only_after_provider_confirmation() {
        let mut table = ExternalObjectReferenceTable::new();
        assert!(table.reserve());
        assert!(table.insert_reserved(0x9100));
        assert_eq!(table.reference(0x9100), Some(2));
        assert_eq!(table.dereference_nonfinal(0x9100), Ok(Some(1)));
        assert_eq!(table.dereference_nonfinal(0x9100), Ok(None));
        assert!(table.contains(0x9100));
        assert!(table.complete_final_release(0x9100));
        assert!(table.is_empty());
    }

    #[test]
    fn external_reference_table_rejects_stale_duplicate_and_underflow() {
        let mut table = ExternalObjectReferenceTable::new();
        assert!(table.reserve());
        assert!(!table.insert_reserved(0));
        assert!(table.insert_reserved(0x9200));
        assert!(!table.insert_reserved(0x9200));
        assert_eq!(table.dereference_nonfinal(0x9300), Err(()));
        assert!(!table.complete_final_release(0x9300));
        assert!(table.complete_final_release(0x9200));
        assert_eq!(table.reference(0x9200), None);
        assert_eq!(table.len(), 0);
    }
}
