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
//! Bodies, counts, names and security live in the provider's
//! [`UserObjectStore`](crate::win32k_user_objects::UserObjectStore); handles live in each
//! process's ProcessManager table. The type-object VAs win32k passes (`ExDesktopObjectType` /
//! `ExWindowStationObjectType`) are classified by the caller into an [`ObKind`]. Real Ob
//! semantics reference: `references/nt5/base/ntos/ob/` (ObpCreateHandle,
//! OBJECT_HEADER/OBJECT_TYPE); DESKTOP layout: `references/reactos/win32ss/user/ntuser/desktop.c`.

use alloc::vec::Vec;

/// Pointer and handle counts for a provider-owned object projection. The provider retains one
/// owner reference for the lifetime of the projection; every published handle owns one additional
/// pointer reference, and transient kernel references may not cross that combined floor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnedObjectReferenceCounts {
    pointer_count: u32,
    handle_count: u32,
}

impl OwnedObjectReferenceCounts {
    pub const fn new() -> Self {
        Self {
            pointer_count: 1,
            handle_count: 0,
        }
    }

    pub const fn pointer_count(self) -> u32 {
        self.pointer_count
    }

    pub const fn handle_count(self) -> u32 {
        self.handle_count
    }

    pub const fn can_finalize(self) -> bool {
        self.pointer_count == 1 && self.handle_count == 0
    }

    pub fn reference(&mut self) -> Option<u32> {
        self.pointer_count = self.pointer_count.checked_add(1)?;
        Some(self.pointer_count)
    }

    pub fn dereference(&mut self) -> Option<u32> {
        if self.pointer_count <= self.handle_count.saturating_add(1) {
            return None;
        }
        self.pointer_count -= 1;
        Some(self.pointer_count)
    }

    pub fn open_handle(&mut self) -> Option<(u32, u32)> {
        let pointer_count = self.pointer_count.checked_add(1)?;
        let handle_count = self.handle_count.checked_add(1)?;
        self.pointer_count = pointer_count;
        self.handle_count = handle_count;
        Some((pointer_count, handle_count))
    }

    pub fn close_handle(&mut self) -> Option<(u32, u32)> {
        if self.handle_count == 0 || self.pointer_count <= self.handle_count {
            return None;
        }
        self.pointer_count -= 1;
        self.handle_count -= 1;
        Some((self.pointer_count, self.handle_count))
    }
}

impl Default for OwnedObjectReferenceCounts {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ExternalReferenceToken {
    object: u64,
    token: u64,
}

/// Local projection references paired with opaque canonical-owner tokens. Releasing a reference is
/// a two-phase operation: the token remains recorded until the external owner confirms release.
#[derive(Default)]
pub struct ExternalReferenceTokenLedger {
    entries: Vec<ExternalReferenceToken>,
}

impl ExternalReferenceTokenLedger {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn reserve(&mut self) -> bool {
        self.entries.try_reserve(1).is_ok()
    }

    pub fn insert_reserved(&mut self, object: u64, token: u64) -> Option<u32> {
        if object == 0 || token == 0 || self.entries.iter().any(|entry| entry.token == token) {
            return None;
        }
        let count = self
            .entries
            .iter()
            .filter(|entry| entry.object == object)
            .count()
            .checked_add(1)
            .and_then(|count| u32::try_from(count).ok())?;
        self.entries.push(ExternalReferenceToken { object, token });
        Some(count)
    }

    pub fn release_token(&self, object: u64) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.object == object)
            .map(|entry| entry.token)
    }

    pub fn complete_release(&mut self, object: u64, token: u64) -> Option<u32> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.object == object && entry.token == token)?;
        let remaining = self
            .entries
            .iter()
            .filter(|entry| entry.object == object)
            .count()
            .checked_sub(1)
            .and_then(|count| u32::try_from(count).ok())?;
        self.entries.remove(index);
        Some(remaining)
    }

    pub fn count(&self, object: u64) -> u32 {
        u32::try_from(self.entries.iter().filter(|entry| entry.object == object).count())
            .unwrap_or(u32::MAX)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

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
    /// `DESKTOP.dwSessionId`; the parent `WINSTATION_OBJECT.dwSessionId` is also its first field.
    pub const SESSION_ID: usize = 0;
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

/// Bind a newly allocated desktop to its creator's session only when its exact parent station
/// belongs to that same session. The native desktop parse callback makes this assignment before
/// publishing the object; our hosted parse adapter must do likewise.
///
/// # Safety
/// Both pointers must refer to live, readable bodies of the indicated types. `desktop_body`
/// must be writable and must not yet be published.
pub unsafe fn bind_desktop_session(
    desktop_body: *mut u8,
    parent_station_body: *const u8,
    current_session_id: u32,
) -> bool {
    if desktop_body.is_null() || parent_station_body.is_null() {
        return false;
    }
    let parent_session_id = core::ptr::read_unaligned(parent_station_body as *const u32);
    if parent_session_id != current_session_id {
        return false;
    }
    core::ptr::write_unaligned(desktop_body.add(desktop::SESSION_ID) as *mut u32, current_session_id);
    true
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
    fn desktop_session_uses_current_process_only_for_its_exact_parent_station() {
        let mut desktop = [0u8; DESKTOP_BODY_SIZE as usize];
        let mut station = [0u8; 0x100];
        station[..4].copy_from_slice(&1u32.to_le_bytes());
        unsafe {
            assert!(!bind_desktop_session(
                desktop.as_mut_ptr(), station.as_ptr(), 0,
            ));
            assert_eq!(u32::from_le_bytes(desktop[..4].try_into().unwrap()), 0,
                "a foreign session must not publish or mutate the desktop");
            assert!(bind_desktop_session(
                desktop.as_mut_ptr(), station.as_ptr(), 1,
            ));
            assert_eq!(u32::from_le_bytes(desktop[..4].try_into().unwrap()), 1);
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
    fn owned_object_counts_keep_handle_and_owner_pointer_floors() {
        let mut counts = OwnedObjectReferenceCounts::new();
        assert!(counts.can_finalize());
        assert_eq!(counts.open_handle(), Some((2, 1)));
        assert_eq!(counts.reference(), Some(3));
        assert_eq!(counts.dereference(), Some(2));
        assert_eq!(counts.dereference(), None);
        assert_eq!(counts.close_handle(), Some((1, 0)));
        assert!(counts.can_finalize());
        assert_eq!(counts.close_handle(), None);
        assert_eq!(counts.dereference(), None);
    }

    #[test]
    fn owned_object_counts_balance_multiple_handles_and_pointers() {
        let mut counts = OwnedObjectReferenceCounts::new();
        assert_eq!(counts.open_handle(), Some((2, 1)));
        assert_eq!(counts.open_handle(), Some((3, 2)));
        assert_eq!(counts.reference(), Some(4));
        assert_eq!(counts.close_handle(), Some((3, 1)));
        assert_eq!(counts.dereference(), Some(2));
        assert_eq!(counts.close_handle(), Some((1, 0)));
        assert!(counts.can_finalize());
    }

    #[test]
    fn owned_object_counts_reject_overflow_without_partial_mutation() {
        let mut counts = OwnedObjectReferenceCounts {
            pointer_count: u32::MAX,
            handle_count: 7,
        };
        assert_eq!(counts.reference(), None);
        assert_eq!(counts.open_handle(), None);
        assert_eq!(counts.pointer_count(), u32::MAX);
        assert_eq!(counts.handle_count(), 7);

        counts = OwnedObjectReferenceCounts {
            pointer_count: u32::MAX - 1,
            handle_count: u32::MAX,
        };
        assert_eq!(counts.open_handle(), None);
        assert_eq!(counts.pointer_count(), u32::MAX - 1);
        assert_eq!(counts.handle_count(), u32::MAX);
        assert_eq!(counts.close_handle(), None);
        assert_eq!(counts.pointer_count(), u32::MAX - 1);
        assert_eq!(counts.handle_count(), u32::MAX);
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

    #[test]
    fn external_token_ledger_keeps_release_retryable_until_confirmation() {
        let mut ledger = ExternalReferenceTokenLedger::new();
        assert!(ledger.reserve());
        assert_eq!(ledger.insert_reserved(0xA100, 11), Some(1));
        assert!(ledger.reserve());
        assert_eq!(ledger.insert_reserved(0xA100, 12), Some(2));
        assert!(ledger.reserve());
        assert_eq!(ledger.insert_reserved(0xA200, 13), Some(1));

        assert_eq!(ledger.release_token(0xA100), Some(12));
        assert_eq!(ledger.release_token(0xA100), Some(12));
        assert_eq!(ledger.complete_release(0xA100, 12), Some(1));
        assert_eq!(ledger.release_token(0xA100), Some(11));
        assert_eq!(ledger.count(0xA100), 1);
        assert_eq!(ledger.count(0xA200), 1);
        assert!(!ledger.is_empty());
    }

    #[test]
    fn external_token_ledger_rejects_invalid_and_duplicate_tokens() {
        let mut ledger = ExternalReferenceTokenLedger::new();
        assert!(ledger.reserve());
        assert_eq!(ledger.insert_reserved(0, 1), None);
        assert_eq!(ledger.insert_reserved(1, 0), None);
        assert_eq!(ledger.insert_reserved(1, 20), Some(1));
        assert_eq!(ledger.insert_reserved(2, 20), None);
        assert_eq!(ledger.complete_release(1, 21), None);
        assert_eq!(ledger.count(1), 1);
        assert_eq!(ledger.complete_release(1, 20), Some(0));
        assert!(ledger.is_empty());
    }
}
