struct Win32kSessionRuntimeState {
    stock_objects: nt_kernel_exec::user_gdi::StockObjectMirror,
    cursor_mirror: nt_kernel_exec::user_cursor::GlobalCursorMirror<32, 16>,
    builtin_class_mirror: nt_kernel_exec::user_class::BuiltinClassMirror<16>,
    stock_objects_observed: u64,
    service_stock_hits: u64,
    service_stock_misses: u64,
    cursor_identities_observed: u64,
    cursor_promotions: u64,
    userinit_cursor_hits: u64,
    userinit_cursor_handle: u64,
    builtin_classes_observed: u64,
    userinit_builtin_class_hits: u64,
    userinit_builtin_class_misses: u64,
    userinit_builtin_class_mask: u64,
    userinit_dialog_class_atom: u64,
}

impl Win32kSessionRuntimeState {
    const fn new() -> Self {
        Self {
            stock_objects: nt_kernel_exec::user_gdi::StockObjectMirror::new(),
            cursor_mirror: nt_kernel_exec::user_cursor::GlobalCursorMirror::new(),
            builtin_class_mirror: nt_kernel_exec::user_class::BuiltinClassMirror::new(),
            stock_objects_observed: 0,
            service_stock_hits: 0,
            service_stock_misses: 0,
            cursor_identities_observed: 0,
            cursor_promotions: 0,
            userinit_cursor_hits: 0,
            userinit_cursor_handle: 0,
            builtin_classes_observed: 0,
            userinit_builtin_class_hits: 0,
            userinit_builtin_class_misses: 0,
            userinit_builtin_class_mask: 0,
            userinit_dialog_class_atom: 0,
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn observe_stock_object(&mut self, object_id: u32, handle: u32) -> bool {
        let observed = self.stock_objects.observe(object_id, handle);
        if observed {
            self.stock_objects_observed = self.stock_objects_observed.saturating_add(1);
        }
        observed
    }

    fn lookup_stock_object(&self, object_id: u32) -> Option<u32> {
        self.stock_objects.lookup(object_id)
    }

    fn record_service_stock_hit(&mut self) {
        self.service_stock_hits = self.service_stock_hits.saturating_add(1);
    }

    fn record_service_stock_miss(&mut self) {
        self.service_stock_misses = self.service_stock_misses.saturating_add(1);
    }

    fn observe_cursor_identity(
        &mut self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
        handle: u32,
    ) {
        self.cursor_mirror.observe_identity(key, handle);
        if handle != 0 {
            self.cursor_identities_observed = self.cursor_identities_observed.saturating_add(1);
        }
    }

    fn promote_cursor(&mut self, handle: u32) {
        self.cursor_mirror.promote(handle);
        if handle != 0 {
            self.cursor_promotions = self.cursor_promotions.saturating_add(1);
        }
    }

    fn lookup_cursor(&self, key: &nt_kernel_exec::user_cursor::CursorLookupKey) -> Option<u32> {
        self.cursor_mirror.lookup_global(key)
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
        self.builtin_class_mirror.observe(key, atom);
        if atom != 0 {
            self.builtin_classes_observed = self.builtin_classes_observed.saturating_add(1);
        }
    }

    fn lookup_builtin_class(
        &self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
    ) -> Option<u16> {
        self.builtin_class_mirror.lookup(key)
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

impl Win32kSessionRuntime {
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

    pub(crate) fn lookup_stock_object(&self, object_id: u32) -> Option<u32> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.state).lookup_stock_object(object_id) }
    }

    pub(crate) fn record_service_stock_hit(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_service_stock_hit() };
    }

    pub(crate) fn record_service_stock_miss(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.state).record_service_stock_miss() };
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
}

pub(crate) fn win32k_session_stock_counters() -> (u64, u64, u64) {
    let state = core::ptr::addr_of!(WIN32K_SESSION_RUNTIME_WORK);
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    let state = unsafe { &*state };
    (
        state.stock_objects_observed,
        state.service_stock_hits,
        state.service_stock_misses,
    )
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
