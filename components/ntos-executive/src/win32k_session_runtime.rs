const WIN32K_STOCK_OBJECT_COUNT: u32 = 22;

struct Win32kSessionRuntimeState {
    stock_object_observed_mask: u32,
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
        _key: &nt_kernel_exec::user_cursor::CursorLookupKey,
        handle: u32,
    ) {
        if handle != 0 {
            self.cursor_identities_observed = self.cursor_identities_observed.saturating_add(1);
        }
    }

    fn promote_cursor(&mut self, handle: u32) {
        if handle != 0 {
            self.cursor_promotions = self.cursor_promotions.saturating_add(1);
        }
    }

    fn record_userinit_cursor_hit(&mut self, handle: u32) {
        self.userinit_cursor_hits = self.userinit_cursor_hits.saturating_add(1);
        self.userinit_cursor_handle = handle as u64;
    }

    fn observe_builtin_class(
        &mut self,
        _key: &nt_kernel_exec::user_class::BuiltinClassKey,
        atom: u16,
    ) {
        if atom != 0 {
            self.builtin_classes_observed = self.builtin_classes_observed.saturating_add(1);
        }
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
        }
        observed
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
