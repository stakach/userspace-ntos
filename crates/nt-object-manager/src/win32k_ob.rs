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

/// DESKTOP body field offsets (`references/reactos/win32ss/user/ntuser/desktop.h` `struct _DESKTOP`).
pub mod desktop {
    /// `PDESKTOPINFO pDeskInfo` — the desktop-info block hung off the DESKTOP body.
    pub const P_DESK_INFO: usize = 0x08;
}

/// Body size to allocate for a `DESKTOP` (real `sizeof(DESKTOP)` is ~0x100; headroom, zeroed).
pub const DESKTOP_BODY_SIZE: u64 = 0x200;
/// Body size to allocate for a `DESKTOPINFO` (+ `szDesktopName` tail, zeroed).
pub const DESKTOPINFO_SIZE: u64 = 0x120;

/// Number of live win32k objects the table can hold. Slot 0 is reserved (handle 0 == `NULL`).
pub const OB_TABLE_LEN: usize = 16;

/// A fixed-size handle → (type, body) registry for win32k's DESKTOP / WINDOWSTATION objects.
///
/// Handles are minted densely from 1; the client-visible `HANDLE` is `idx << 2` (a real Ob handle
/// carries tag bits in the low two bits, so shifting keeps them clear), always non-null and
/// distinguishable from any handle *not* in the table (e.g. win32k's process-connect handle, which
/// the caller resolves via an `EPROCESS` fallback). Single-threaded host: a plain struct suffices.
pub struct ObHandleTable {
    slots: [Option<(ObKind, u64)>; OB_TABLE_LEN],
    next: usize,
    /// Latches `ObCreateObject`'s (kind, body) so the following `ObInsertObject` — which receives
    /// only the object pointer, not its type — can register it under a fresh handle.
    pending: Option<(ObKind, u64)>,
    /// The one input window station once created; a later `ObOpenObjectByName(WINSTA)` OPENs it
    /// (returns this handle) instead of reporting NOT_FOUND (which would create a duplicate).
    winsta_handle: u64,
    winsta_body: u64,
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
        }
    }

    /// Register `body` under `kind` at a fresh slot and return its client-visible `HANDLE`
    /// (`idx << 2`), or 0 if the table is full. A `WindowStation` registration is also cached as
    /// the single input window station.
    pub fn register(&mut self, kind: ObKind, body: u64) -> u64 {
        let idx = self.next;
        if idx >= OB_TABLE_LEN {
            return 0;
        }
        self.next = idx + 1;
        self.slots[idx] = Some((kind, body));
        let handle = (idx as u64) << 2;
        if kind == ObKind::WindowStation {
            self.winsta_handle = handle;
            self.winsta_body = body;
        }
        handle
    }

    /// Resolve a handle to its `(kind, body)`, or `None` if it is not a registered win32k object
    /// handle.
    pub fn lookup(&self, handle: u64) -> Option<(ObKind, u64)> {
        let idx = (handle >> 2) as usize;
        if idx == 0 || idx >= self.next {
            return None;
        }
        self.slots.get(idx).copied().flatten()
    }

    /// Resolve a handle to its body, or 0 if it is not a registered win32k object handle.
    pub fn lookup_body(&self, handle: u64) -> u64 {
        self.lookup(handle).map(|(_, body)| body).unwrap_or(0)
    }

    /// Latch a (kind, body) from `ObCreateObject` for the following `ObInsertObject`.
    pub fn latch_pending(&mut self, kind: ObKind, body: u64) {
        self.pending = Some((kind, body));
    }

    /// Register the latched object under a fresh handle (`ObInsertObject`). Uses the kind latched by
    /// [`latch_pending`](Self::latch_pending), defaulting to [`ObKind::Other`] if none was latched,
    /// clears the latch, and returns the new handle.
    pub fn insert_pending(&mut self, object: u64) -> u64 {
        let kind = self.pending.map(|(k, _)| k).unwrap_or(ObKind::Other);
        self.pending = None;
        self.register(kind, object)
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
/// `desktop_body` must point to at least [`desktop::P_DESK_INFO`] + 8 writable bytes.
pub unsafe fn init_desktop_body(desktop_body: *mut u8, desktop_info: u64) {
    core::ptr::write_unaligned(desktop_body.add(desktop::P_DESK_INFO) as *mut u64, desktop_info);
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn table_full_returns_null_handle() {
        let mut t = ObHandleTable::new();
        for i in 1..OB_TABLE_LEN {
            assert_ne!(t.register(ObKind::Desktop, i as u64 * 0x1000), 0);
        }
        assert_eq!(t.register(ObKind::Desktop, 0xDEAD), 0); // full
    }

    #[test]
    fn desktop_body_wires_desk_info() {
        let mut body = [0u8; 0x40];
        unsafe {
            init_desktop_body(body.as_mut_ptr(), 0xDEC0_0000);
            let p = core::ptr::read_unaligned(body.as_ptr().add(desktop::P_DESK_INFO) as *const u64);
            assert_eq!(p, 0xDEC0_0000);
        }
    }
}
