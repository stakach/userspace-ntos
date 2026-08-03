struct Win32kSessionRuntimeState {
    stock_objects: nt_kernel_exec::user_gdi::StockObjectMirror,
    stock_objects_observed: u64,
    service_stock_hits: u64,
    service_stock_misses: u64,
}

impl Win32kSessionRuntimeState {
    const fn new() -> Self {
        Self {
            stock_objects: nt_kernel_exec::user_gdi::StockObjectMirror::new(),
            stock_objects_observed: 0,
            service_stock_hits: 0,
            service_stock_misses: 0,
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
}

static mut WIN32K_SESSION_RUNTIME_WORK: Win32kSessionRuntimeState =
    Win32kSessionRuntimeState::new();

pub(crate) struct Win32kSessionRuntime {
    state: *mut Win32kSessionRuntimeState,
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
