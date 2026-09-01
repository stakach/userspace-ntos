use alloc::vec::Vec;

const WIN32K_STOCK_OBJECT_COUNT: u32 = 22;

#[derive(Clone, Copy)]
struct SessionCursorRecord {
    key: nt_kernel_exec::user_cursor::CursorLookupKey,
    handle: u32,
    promoted: bool,
}

#[derive(Clone, Copy)]
struct SessionBuiltinClassRecord {
    key: nt_kernel_exec::user_class::BuiltinClassKey,
    atom: u16,
}

#[derive(Clone, Copy)]
struct SessionAtomNameRecord {
    atom: u16,
    len: u16,
    units: [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
}

struct Win32kSessionRuntimeState {
    stock_object_observed_mask: u32,
    stock_objects_observed: u64,
    cursor_records: Vec<SessionCursorRecord>,
    promoted_cursor_handles: Vec<u32>,
    cursor_identities_observed: u64,
    cursor_promotions: u64,
    userinit_cursor_hits: u64,
    userinit_cursor_handle: u64,
    builtin_class_records: Vec<SessionBuiltinClassRecord>,
    builtin_classes_observed: u64,
    userinit_builtin_class_hits: u64,
    userinit_builtin_class_misses: u64,
    userinit_builtin_class_mask: u64,
    userinit_dialog_class_atom: u64,
    class_atom_name_records: Vec<SessionAtomNameRecord>,
    class_atom_names_observed: u64,
    class_atom_name_serves: u64,
    class_atom_name_failures: u64,
}

impl Win32kSessionRuntimeState {
    fn new() -> Self {
        Self {
            stock_object_observed_mask: 0,
            stock_objects_observed: 0,
            cursor_records: Vec::new(),
            promoted_cursor_handles: Vec::new(),
            cursor_identities_observed: 0,
            cursor_promotions: 0,
            userinit_cursor_hits: 0,
            userinit_cursor_handle: 0,
            builtin_class_records: Vec::new(),
            builtin_classes_observed: 0,
            userinit_builtin_class_hits: 0,
            userinit_builtin_class_misses: 0,
            userinit_builtin_class_mask: 0,
            userinit_dialog_class_atom: 0,
            class_atom_name_records: Vec::new(),
            class_atom_names_observed: 0,
            class_atom_name_serves: 0,
            class_atom_name_failures: 0,
        }
    }

    #[inline(never)]
    fn clear(&mut self) {
        self.stock_object_observed_mask = 0;
        self.stock_objects_observed = 0;
        self.cursor_records.clear();
        self.promoted_cursor_handles.clear();
        self.cursor_identities_observed = 0;
        self.cursor_promotions = 0;
        self.userinit_cursor_hits = 0;
        self.userinit_cursor_handle = 0;
        self.builtin_class_records.clear();
        self.builtin_classes_observed = 0;
        self.userinit_builtin_class_hits = 0;
        self.userinit_builtin_class_misses = 0;
        self.userinit_builtin_class_mask = 0;
        self.userinit_dialog_class_atom = 0;
        self.class_atom_name_records.clear();
        self.class_atom_names_observed = 0;
        self.class_atom_name_serves = 0;
        self.class_atom_name_failures = 0;
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
        if handle == 0 {
            return;
        }
        self.cursor_identities_observed = self.cursor_identities_observed.saturating_add(1);
        let promoted = self.promoted_cursor_handles.contains(&handle);
        for record in self.cursor_records.iter_mut() {
            if record.key.same_identity(key) {
                if !record.promoted || record.handle == handle {
                    record.handle = handle;
                    record.promoted |= promoted;
                }
                return;
            }
        }
        if self.cursor_records.try_reserve_exact(1).is_err() {
            return;
        }
        self.cursor_records.push(SessionCursorRecord {
            key: *key,
            handle,
            promoted,
        });
    }

    fn promote_cursor(&mut self, handle: u32) {
        if handle == 0 {
            return;
        }
        self.cursor_promotions = self.cursor_promotions.saturating_add(1);
        let mut found = false;
        for record in self.cursor_records.iter_mut() {
            if record.handle == handle {
                record.promoted = true;
                found = true;
            }
        }
        if !found && !self.promoted_cursor_handles.contains(&handle) {
            if self.promoted_cursor_handles.try_reserve_exact(1).is_ok() {
                self.promoted_cursor_handles.push(handle);
            }
        }
    }

    fn lookup_cursor(&self, key: &nt_kernel_exec::user_cursor::CursorLookupKey) -> Option<u32> {
        self.cursor_records
            .iter()
            .find(|record| record.promoted && record.handle != 0 && record.key.same_identity(key))
            .map(|record| record.handle)
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
        if atom == 0 {
            return;
        }
        self.builtin_classes_observed = self.builtin_classes_observed.saturating_add(1);
        for record in self.builtin_class_records.iter_mut() {
            if record.key.same_identity(key) {
                record.atom = atom;
                return;
            }
        }
        if self.builtin_class_records.try_reserve_exact(1).is_ok() {
            self.builtin_class_records
                .push(SessionBuiltinClassRecord { key: *key, atom });
        }
    }

    fn lookup_builtin_class(
        &self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
    ) -> Option<u16> {
        self.builtin_class_records
            .iter()
            .find(|record| record.atom != 0 && record.key.same_identity(key))
            .map(|record| record.atom)
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
        let observed = atom != 0
            && !units.is_empty()
            && units.len() <= nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP;
        if observed {
            self.class_atom_names_observed = self.class_atom_names_observed.saturating_add(1);
            let mut stored = SessionAtomNameRecord {
                atom,
                len: units.len() as u16,
                units: [0; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
            };
            stored.units[..units.len()].copy_from_slice(units);
            for record in self.class_atom_name_records.iter_mut() {
                if record.atom == atom {
                    *record = stored;
                    return true;
                }
            }
            if self.class_atom_name_records.try_reserve_exact(1).is_err() {
                return false;
            }
            self.class_atom_name_records.push(stored);
        }
        observed
    }

    fn lookup_class_atom_name(
        &self,
        atom: u16,
        out: &mut [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
    ) -> Option<usize> {
        if atom == 0 {
            return None;
        }
        if let Some(record) = self
            .class_atom_name_records
            .iter()
            .find(|record| record.atom == atom)
        {
            let len = record.len as usize;
            out[..len].copy_from_slice(&record.units[..len]);
            return Some(len);
        }
        nt_kernel_exec::user_class::integer_atom_name(atom, out)
    }

    fn record_class_atom_name_serve(&mut self, success: bool) {
        if success {
            self.class_atom_name_serves = self.class_atom_name_serves.saturating_add(1);
        } else {
            self.class_atom_name_failures = self.class_atom_name_failures.saturating_add(1);
        }
    }
}

static mut WIN32K_SESSION_RUNTIME_WORK: Option<Win32kSessionRuntimeState> = None;

unsafe fn win32k_session_runtime_mut() -> &'static mut Win32kSessionRuntimeState {
    let slot = &mut *core::ptr::addr_of_mut!(WIN32K_SESSION_RUNTIME_WORK);
    if slot.is_none() {
        *slot = Some(Win32kSessionRuntimeState::new());
    }
    slot.as_mut().unwrap_unchecked()
}

unsafe fn win32k_session_runtime_ref() -> Option<&'static Win32kSessionRuntimeState> {
    (&*core::ptr::addr_of!(WIN32K_SESSION_RUNTIME_WORK)).as_ref()
}

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

pub(crate) struct Win32kSessionAtomNameCounters {
    pub(crate) class_atom_names_observed: u64,
    pub(crate) class_atom_name_serves: u64,
    pub(crate) class_atom_name_failures: u64,
}

impl Win32kSessionRuntime {
    #[inline(never)]
    pub(crate) fn reset() -> Self {
        // SAFETY: `service_sec_image` is serialized and the live handler is the sole owner.
        let state = unsafe { win32k_session_runtime_mut() };
        state.clear();
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

    pub(crate) fn lookup_cursor(
        &mut self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
    ) -> Option<u32> {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).lookup_cursor(key) }
    }

    pub(crate) fn promote_cursor(&mut self, handle: u32) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).promote_cursor(handle) };
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
        &mut self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
    ) -> Option<u16> {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).lookup_builtin_class(key) }
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

    pub(crate) fn lookup_class_atom_name(
        &mut self,
        atom: u16,
        out: &mut [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
    ) -> Option<usize> {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).lookup_class_atom_name(atom, out) }
    }

    pub(crate) fn record_class_atom_name_serve(&mut self, success: bool) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_class_atom_name_serve(success) };
    }
}

pub(crate) fn win32k_session_stock_counters() -> u64 {
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    unsafe {
        win32k_session_runtime_ref()
            .map(|state| state.stock_objects_observed)
            .unwrap_or(0)
    }
}

pub(crate) fn win32k_session_cursor_class_counters() -> Win32kSessionCursorClassCounters {
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    unsafe {
        let Some(state) = win32k_session_runtime_ref() else {
            return Win32kSessionCursorClassCounters {
                cursor_identities_observed: 0,
                cursor_promotions: 0,
                userinit_cursor_hits: 0,
                userinit_cursor_handle: 0,
                builtin_classes_observed: 0,
                userinit_builtin_class_hits: 0,
                userinit_builtin_class_misses: 0,
                userinit_builtin_class_mask: 0,
                userinit_dialog_class_atom: 0,
            };
        };
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
}

pub(crate) fn win32k_session_atom_name_counters() -> Win32kSessionAtomNameCounters {
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    unsafe {
        let Some(state) = win32k_session_runtime_ref() else {
            return Win32kSessionAtomNameCounters {
                class_atom_names_observed: 0,
                class_atom_name_serves: 0,
                class_atom_name_failures: 0,
            };
        };
        Win32kSessionAtomNameCounters {
            class_atom_names_observed: state.class_atom_names_observed,
            class_atom_name_serves: state.class_atom_name_serves,
            class_atom_name_failures: state.class_atom_name_failures,
        }
    }
}
