const WIN32K_STOCK_OBJECT_COUNT: u32 = 22;

type CursorLookupKey = nt_kernel_exec::user_cursor::CursorLookupKey;
type BuiltinClassKey = nt_kernel_exec::user_class::BuiltinClassKey;

#[derive(Clone, Copy)]
struct CursorCatalogEntry {
    key: Option<CursorLookupKey>,
    handle: u32,
}

impl CursorCatalogEntry {
    const EMPTY: Self = Self {
        key: None,
        handle: 0,
    };
}

/// Session-owned view of real cursor handles published by win32k.
///
/// A handle becomes visible to another client only after the real win32k path has both observed the
/// cursor identity and promoted that handle through `NtUserSetSystemCursor`.
struct SessionGlobalCursorCatalog<const ENTRIES: usize, const PROMOTED: usize> {
    entries: [CursorCatalogEntry; ENTRIES],
    promoted: [u32; PROMOTED],
    next_entry: usize,
    next_promoted: usize,
}

impl<const ENTRIES: usize, const PROMOTED: usize> SessionGlobalCursorCatalog<ENTRIES, PROMOTED> {
    const fn new() -> Self {
        Self {
            entries: [CursorCatalogEntry::EMPTY; ENTRIES],
            promoted: [0; PROMOTED],
            next_entry: 0,
            next_promoted: 0,
        }
    }

    fn clear(&mut self) {
        self.entries.fill(CursorCatalogEntry::EMPTY);
        self.promoted.fill(0);
        self.next_entry = 0;
        self.next_promoted = 0;
    }

    fn observe_identity(&mut self, key: &CursorLookupKey, handle: u32) {
        if handle == 0 || ENTRIES == 0 {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry
                .key
                .is_some_and(|existing| existing.same_identity(key))
        }) {
            entry.handle = handle;
            return;
        }
        self.entries[self.next_entry] = CursorCatalogEntry {
            key: Some(*key),
            handle,
        };
        self.next_entry = (self.next_entry + 1) % ENTRIES;
    }

    fn promote(&mut self, handle: u32) {
        if handle == 0 || PROMOTED == 0 || self.promoted.contains(&handle) {
            return;
        }
        self.promoted[self.next_promoted] = handle;
        self.next_promoted = (self.next_promoted + 1) % PROMOTED;
    }

    fn lookup(&self, key: &CursorLookupKey) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| {
                entry
                    .key
                    .is_some_and(|existing| existing.same_identity(key))
                    && self.promoted.contains(&entry.handle)
            })
            .map(|entry| entry.handle)
    }
}

#[derive(Clone, Copy)]
struct BuiltinClassCatalogEntry {
    key: Option<BuiltinClassKey>,
    atom: u16,
}

impl BuiltinClassCatalogEntry {
    const EMPTY: Self = Self { key: None, atom: 0 };
}

struct SessionBuiltinClassCatalog<const N: usize> {
    entries: [BuiltinClassCatalogEntry; N],
    next: usize,
}

impl<const N: usize> SessionBuiltinClassCatalog<N> {
    const fn new() -> Self {
        Self {
            entries: [BuiltinClassCatalogEntry::EMPTY; N],
            next: 0,
        }
    }

    fn clear(&mut self) {
        self.entries.fill(BuiltinClassCatalogEntry::EMPTY);
        self.next = 0;
    }

    fn observe(&mut self, key: &BuiltinClassKey, atom: u16) {
        if N == 0 || atom == 0 {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry
                .key
                .is_some_and(|existing| existing.same_identity(key))
        }) {
            entry.atom = atom;
            return;
        }
        self.entries[self.next] = BuiltinClassCatalogEntry {
            key: Some(*key),
            atom,
        };
        self.next = (self.next + 1) % N;
    }

    fn lookup(&self, key: &BuiltinClassKey) -> Option<u16> {
        self.entries
            .iter()
            .find(|entry| {
                entry
                    .key
                    .is_some_and(|existing| existing.same_identity(key))
            })
            .map(|entry| entry.atom)
    }
}

#[derive(Clone, Copy)]
struct ClassAtomNameCatalogEntry {
    atom: u16,
    len: u16,
    units: [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
}

impl ClassAtomNameCatalogEntry {
    const EMPTY: Self = Self {
        atom: 0,
        len: 0,
        units: [0; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
    };
}

/// Session-owned class-atom names learned from real successful win32k registrations.
struct SessionClassAtomNameCatalog<const N: usize> {
    entries: [ClassAtomNameCatalogEntry; N],
    next: usize,
}

impl<const N: usize> SessionClassAtomNameCatalog<N> {
    const fn new() -> Self {
        Self {
            entries: [ClassAtomNameCatalogEntry::EMPTY; N],
            next: 0,
        }
    }

    fn clear(&mut self) {
        self.entries.fill(ClassAtomNameCatalogEntry::EMPTY);
        self.next = 0;
    }

    fn observe(&mut self, atom: u16, units: &[u16]) -> bool {
        if N == 0
            || atom == 0
            || units.is_empty()
            || units.len() > nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP
        {
            return false;
        }
        let entry = if let Some(existing) = self.entries.iter_mut().find(|entry| entry.atom == atom)
        {
            existing
        } else {
            let entry = &mut self.entries[self.next];
            self.next = (self.next + 1) % N;
            entry
        };
        entry.atom = atom;
        entry.len = units.len() as u16;
        entry.units.fill(0);
        entry.units[..units.len()].copy_from_slice(units);
        true
    }

    fn copy_name(&self, atom: u16, out: &mut [u16]) -> Option<usize> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.atom == atom && entry.len != 0)?;
        let len = entry.len as usize;
        if out.len() < len {
            return None;
        }
        out[..len].copy_from_slice(&entry.units[..len]);
        Some(len)
    }
}

struct Win32kSessionRuntimeState {
    stock_object_observed_mask: u32,
    cursor_catalog: SessionGlobalCursorCatalog<32, 16>,
    builtin_class_catalog: SessionBuiltinClassCatalog<16>,
    class_atom_name_catalog: SessionClassAtomNameCatalog<128>,
    stock_objects_observed: u64,
    cursor_identities_observed: u64,
    cursor_promotions: u64,
    userinit_cursor_hits: u64,
    userinit_cursor_handle: u64,
    builtin_classes_observed: u64,
    userinit_builtin_class_hits: u64,
    userinit_builtin_class_misses: u64,
    userinit_builtin_class_mask: u64,
    userinit_dialog_class_atom: u64,
    class_atom_names_observed: u64,
    class_atom_name_serves: u64,
    class_atom_name_failures: u64,
    userinit_scrollbar_queries: u64,
    userinit_scrollbar_copyouts: u64,
    userinit_scrollbar_errors: u64,
    userinit_scrollbar_atom: u64,
    userinit_scrollbar_style: u64,
    userinit_scrollbar_extra: u64,
    userinit_scrollbar_proc: u64,
}

impl Win32kSessionRuntimeState {
    const fn new() -> Self {
        Self {
            stock_object_observed_mask: 0,
            cursor_catalog: SessionGlobalCursorCatalog::new(),
            builtin_class_catalog: SessionBuiltinClassCatalog::new(),
            class_atom_name_catalog: SessionClassAtomNameCatalog::new(),
            stock_objects_observed: 0,
            cursor_identities_observed: 0,
            cursor_promotions: 0,
            userinit_cursor_hits: 0,
            userinit_cursor_handle: 0,
            builtin_classes_observed: 0,
            userinit_builtin_class_hits: 0,
            userinit_builtin_class_misses: 0,
            userinit_builtin_class_mask: 0,
            userinit_dialog_class_atom: 0,
            class_atom_names_observed: 0,
            class_atom_name_serves: 0,
            class_atom_name_failures: 0,
            userinit_scrollbar_queries: 0,
            userinit_scrollbar_copyouts: 0,
            userinit_scrollbar_errors: 0,
            userinit_scrollbar_atom: 0,
            userinit_scrollbar_style: 0,
            userinit_scrollbar_extra: 0,
            userinit_scrollbar_proc: 0,
        }
    }

    #[inline(never)]
    fn clear(&mut self) {
        self.stock_object_observed_mask = 0;
        self.cursor_catalog.clear();
        self.builtin_class_catalog.clear();
        self.class_atom_name_catalog.clear();
        self.stock_objects_observed = 0;
        self.cursor_identities_observed = 0;
        self.cursor_promotions = 0;
        self.userinit_cursor_hits = 0;
        self.userinit_cursor_handle = 0;
        self.builtin_classes_observed = 0;
        self.userinit_builtin_class_hits = 0;
        self.userinit_builtin_class_misses = 0;
        self.userinit_builtin_class_mask = 0;
        self.userinit_dialog_class_atom = 0;
        self.class_atom_names_observed = 0;
        self.class_atom_name_serves = 0;
        self.class_atom_name_failures = 0;
        self.userinit_scrollbar_queries = 0;
        self.userinit_scrollbar_copyouts = 0;
        self.userinit_scrollbar_errors = 0;
        self.userinit_scrollbar_atom = 0;
        self.userinit_scrollbar_style = 0;
        self.userinit_scrollbar_extra = 0;
        self.userinit_scrollbar_proc = 0;
    }

    fn observe_stock_object(&mut self, object_id: u32, handle: u32) -> bool {
        if handle == 0 || object_id >= WIN32K_STOCK_OBJECT_COUNT {
            return false;
        }
        let bit = 1u32 << object_id;
        if self.stock_object_observed_mask & bit != 0 {
            return false;
        }
        self.stock_object_observed_mask |= bit;
        self.stock_objects_observed = self.stock_objects_observed.saturating_add(1);
        true
    }

    fn observe_cursor_identity(
        &mut self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
        handle: u32,
    ) {
        self.cursor_catalog.observe_identity(key, handle);
        if handle != 0 {
            self.cursor_identities_observed = self.cursor_identities_observed.saturating_add(1);
        }
    }

    fn promote_cursor(&mut self, handle: u32) {
        self.cursor_catalog.promote(handle);
        if handle != 0 {
            self.cursor_promotions = self.cursor_promotions.saturating_add(1);
        }
    }

    fn lookup_cursor(&self, key: &nt_kernel_exec::user_cursor::CursorLookupKey) -> Option<u32> {
        self.cursor_catalog.lookup(key)
    }

    fn record_userinit_cursor_hit(&mut self, handle: u32) {
        self.userinit_cursor_hits = self.userinit_cursor_hits.saturating_add(1);
        self.userinit_cursor_handle = handle as u64;
    }

    fn observe_builtin_class(
        &mut self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
        atom: u16,
    ) {
        self.builtin_class_catalog.observe(key, atom);
        if atom != 0 {
            self.builtin_classes_observed = self.builtin_classes_observed.saturating_add(1);
        }
    }

    fn lookup_builtin_class(
        &self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
    ) -> Option<u16> {
        self.builtin_class_catalog.lookup(key)
    }

    fn record_userinit_builtin_class_hit(&mut self, fn_id: u32, atom: u16) {
        self.userinit_builtin_class_hits = self.userinit_builtin_class_hits.saturating_add(1);
        if (0x02a1..=0x02aa).contains(&fn_id) {
            self.userinit_builtin_class_mask |= 1u64 << (fn_id - 0x02a1);
        }
        if fn_id == 0x02a4 {
            self.userinit_dialog_class_atom = atom as u64;
        }
    }

    fn record_userinit_builtin_class_miss(&mut self) {
        self.userinit_builtin_class_misses = self.userinit_builtin_class_misses.saturating_add(1);
    }

    fn observe_class_atom_name(&mut self, atom: u16, units: &[u16]) -> bool {
        let observed = self.class_atom_name_catalog.observe(atom, units);
        if observed {
            self.class_atom_names_observed = self.class_atom_names_observed.saturating_add(1);
        }
        observed
    }

    fn copy_class_atom_name(&self, atom: u16, out: &mut [u16]) -> Option<usize> {
        self.class_atom_name_catalog.copy_name(atom, out)
    }

    fn record_class_atom_name_serve(&mut self) {
        self.class_atom_name_serves = self.class_atom_name_serves.saturating_add(1);
    }

    fn record_class_atom_name_failure(&mut self) {
        self.class_atom_name_failures = self.class_atom_name_failures.saturating_add(1);
    }

    fn record_userinit_scrollbar_query(&mut self) {
        self.userinit_scrollbar_queries = self.userinit_scrollbar_queries.saturating_add(1);
    }

    fn record_userinit_scrollbar_classinfo(
        &mut self,
        atom: u16,
        style: u32,
        cb_wnd_extra: u32,
        has_proc: bool,
        copyout_ok: bool,
    ) {
        self.userinit_scrollbar_atom = atom as u64;
        self.userinit_scrollbar_style = style as u64;
        self.userinit_scrollbar_extra = cb_wnd_extra as u64;
        self.userinit_scrollbar_proc = has_proc as u64;
        if copyout_ok {
            self.userinit_scrollbar_copyouts = self.userinit_scrollbar_copyouts.saturating_add(1);
        } else {
            self.userinit_scrollbar_errors = self.userinit_scrollbar_errors.saturating_add(1);
        }
    }

    fn record_userinit_scrollbar_error(&mut self) {
        self.userinit_scrollbar_errors = self.userinit_scrollbar_errors.saturating_add(1);
    }
}

static mut WIN32K_SESSION_RUNTIME_WORK: Win32kSessionRuntimeState =
    Win32kSessionRuntimeState::new();

pub(crate) struct Win32kSessionRuntime {
    state: *mut Win32kSessionRuntimeState,
}

pub(crate) struct Win32kSessionCursorClassCounters {
    pub(crate) cursor_identities_observed: u64,
    pub(crate) cursor_promotions: u64,
    pub(crate) userinit_cursor_hits: u64,
    pub(crate) userinit_cursor_handle: u64,
    pub(crate) builtin_classes_observed: u64,
    pub(crate) userinit_builtin_class_hits: u64,
    pub(crate) userinit_builtin_class_misses: u64,
    pub(crate) userinit_builtin_class_mask: u64,
    pub(crate) userinit_dialog_class_atom: u64,
}

pub(crate) struct Win32kSessionAtomScrollbarCounters {
    pub(crate) class_atom_names_observed: u64,
    pub(crate) class_atom_name_serves: u64,
    pub(crate) class_atom_name_failures: u64,
    pub(crate) userinit_scrollbar_queries: u64,
    pub(crate) userinit_scrollbar_copyouts: u64,
    pub(crate) userinit_scrollbar_errors: u64,
    pub(crate) userinit_scrollbar_atom: u64,
    pub(crate) userinit_scrollbar_style: u64,
    pub(crate) userinit_scrollbar_extra: u64,
    pub(crate) userinit_scrollbar_proc: u64,
}

impl Win32kSessionRuntime {
    #[inline(never)]
    pub(crate) fn reset() -> Self {
        let state = core::ptr::addr_of_mut!(WIN32K_SESSION_RUNTIME_WORK);
        // SAFETY: `service_sec_image` is serialized and the live handler is the sole owner.
        unsafe { (&mut *state).clear() };
        Self { state }
    }

    pub(crate) fn observe_stock_object(&mut self, object_id: u32, handle: u32) -> bool {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).observe_stock_object(object_id, handle) }
    }

    pub(crate) fn observe_cursor_identity(
        &mut self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
        handle: u32,
    ) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).observe_cursor_identity(key, handle) };
    }

    pub(crate) fn promote_cursor(&mut self, handle: u32) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).promote_cursor(handle) };
    }

    pub(crate) fn lookup_cursor(
        &self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
    ) -> Option<u32> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.state).lookup_cursor(key) }
    }

    pub(crate) fn record_userinit_cursor_hit(&mut self, handle: u32) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_userinit_cursor_hit(handle) };
    }

    pub(crate) fn observe_builtin_class(
        &mut self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
        atom: u16,
    ) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).observe_builtin_class(key, atom) };
    }

    pub(crate) fn lookup_builtin_class(
        &self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
    ) -> Option<u16> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.state).lookup_builtin_class(key) }
    }

    pub(crate) fn record_userinit_builtin_class_hit(&mut self, fn_id: u32, atom: u16) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_userinit_builtin_class_hit(fn_id, atom) };
    }

    pub(crate) fn record_userinit_builtin_class_miss(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_userinit_builtin_class_miss() };
    }

    pub(crate) fn observe_class_atom_name(&mut self, atom: u16, units: &[u16]) -> bool {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).observe_class_atom_name(atom, units) }
    }

    pub(crate) fn copy_class_atom_name(&self, atom: u16, out: &mut [u16]) -> Option<usize> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.state).copy_class_atom_name(atom, out) }
    }

    pub(crate) fn record_class_atom_name_serve(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_class_atom_name_serve() };
    }

    pub(crate) fn record_class_atom_name_failure(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_class_atom_name_failure() };
    }

    pub(crate) fn record_userinit_scrollbar_query(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_userinit_scrollbar_query() };
    }

    pub(crate) fn record_userinit_scrollbar_classinfo(
        &mut self,
        atom: u16,
        style: u32,
        cb_wnd_extra: u32,
        has_proc: bool,
        copyout_ok: bool,
    ) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe {
            (&mut *self.state).record_userinit_scrollbar_classinfo(
                atom,
                style,
                cb_wnd_extra,
                has_proc,
                copyout_ok,
            )
        };
    }

    pub(crate) fn record_userinit_scrollbar_error(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_userinit_scrollbar_error() };
    }
}

pub(crate) fn win32k_session_stock_counters() -> u64 {
    let state = core::ptr::addr_of!(WIN32K_SESSION_RUNTIME_WORK);
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    let state = unsafe { &*state };
    state.stock_objects_observed
}

pub(crate) fn win32k_session_cursor_class_counters() -> Win32kSessionCursorClassCounters {
    let state = core::ptr::addr_of!(WIN32K_SESSION_RUNTIME_WORK);
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    let state = unsafe { &*state };
    Win32kSessionCursorClassCounters {
        cursor_identities_observed: state.cursor_identities_observed,
        cursor_promotions: state.cursor_promotions,
        userinit_cursor_hits: state.userinit_cursor_hits,
        userinit_cursor_handle: state.userinit_cursor_handle,
        builtin_classes_observed: state.builtin_classes_observed,
        userinit_builtin_class_hits: state.userinit_builtin_class_hits,
        userinit_builtin_class_misses: state.userinit_builtin_class_misses,
        userinit_builtin_class_mask: state.userinit_builtin_class_mask,
        userinit_dialog_class_atom: state.userinit_dialog_class_atom,
    }
}

pub(crate) fn win32k_session_atom_scrollbar_counters() -> Win32kSessionAtomScrollbarCounters {
    let state = core::ptr::addr_of!(WIN32K_SESSION_RUNTIME_WORK);
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    let state = unsafe { &*state };
    Win32kSessionAtomScrollbarCounters {
        class_atom_names_observed: state.class_atom_names_observed,
        class_atom_name_serves: state.class_atom_name_serves,
        class_atom_name_failures: state.class_atom_name_failures,
        userinit_scrollbar_queries: state.userinit_scrollbar_queries,
        userinit_scrollbar_copyouts: state.userinit_scrollbar_copyouts,
        userinit_scrollbar_errors: state.userinit_scrollbar_errors,
        userinit_scrollbar_atom: state.userinit_scrollbar_atom,
        userinit_scrollbar_style: state.userinit_scrollbar_style,
        userinit_scrollbar_extra: state.userinit_scrollbar_extra,
        userinit_scrollbar_proc: state.userinit_scrollbar_proc,
    }
}
