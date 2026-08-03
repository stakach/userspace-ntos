use crate::MAX_PI;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServiceGuiClientRuntime {
    pid: nt_process::ProcessId,
    pi: usize,
    pfn_client_a_scrollbar: u64,
    pfn_client_w_scrollbar: u64,
    hmod_user32: u64,
    scrollbar_atom: u16,
}

impl ServiceGuiClientRuntime {
    const fn empty() -> Self {
        Self {
            pid: 0,
            pi: 0,
            pfn_client_a_scrollbar: 0,
            pfn_client_w_scrollbar: 0,
            hmod_user32: 0,
            scrollbar_atom: 0,
        }
    }

    const fn for_process(pid: nt_process::ProcessId, pi: usize) -> Self {
        Self {
            pid,
            pi,
            pfn_client_a_scrollbar: 0,
            pfn_client_w_scrollbar: 0,
            hmod_user32: 0,
            scrollbar_atom: 0,
        }
    }

    const fn is_live(self) -> bool {
        self.pid != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceGuiClientDebug {
    pub(crate) scrollbar_atom: u16,
    pub(crate) has_pfn_a: bool,
    pub(crate) has_pfn_w: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServiceGuiClientRuntimeTable<const N: usize> {
    entries: [ServiceGuiClientRuntime; N],
    pfn_arrays_captured: u64,
    classinfo_hits: u64,
    classinfo_misses: u64,
    classinfo_copyout_errors: u64,
}

impl<const N: usize> ServiceGuiClientRuntimeTable<N> {
    const fn new() -> Self {
        Self {
            entries: [ServiceGuiClientRuntime::empty(); N],
            pfn_arrays_captured: 0,
            classinfo_hits: 0,
            classinfo_misses: 0,
            classinfo_copyout_errors: 0,
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn entry_mut(
        &mut self,
        pid: nt_process::ProcessId,
        pi: usize,
    ) -> Option<&mut ServiceGuiClientRuntime> {
        if pid == 0 {
            return None;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.is_live() && entry.pid == pid)
        {
            self.entries[index].pi = pi;
            return Some(&mut self.entries[index]);
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.is_live() && entry.pi == pi)
        {
            self.entries[index] = ServiceGuiClientRuntime::for_process(pid, pi);
            return Some(&mut self.entries[index]);
        }
        let index = self.entries.iter().position(|entry| !entry.is_live())?;
        self.entries[index] = ServiceGuiClientRuntime::for_process(pid, pi);
        Some(&mut self.entries[index])
    }

    fn get_by_pid(&self, pid: nt_process::ProcessId) -> Option<ServiceGuiClientRuntime> {
        (pid != 0).then_some(())?;
        self.entries
            .iter()
            .copied()
            .find(|entry| entry.is_live() && entry.pid == pid)
    }

    fn record_client_pfns(
        &mut self,
        pid: nt_process::ProcessId,
        pi: usize,
        pfn_client_a_scrollbar: u64,
        pfn_client_w_scrollbar: u64,
        hmod_user32: u64,
    ) -> Option<bool> {
        let entry = self.entry_mut(pid, pi)?;
        let mut captured = false;
        if pfn_client_a_scrollbar != 0 {
            entry.pfn_client_a_scrollbar = pfn_client_a_scrollbar;
            captured = true;
        }
        if pfn_client_w_scrollbar != 0 {
            entry.pfn_client_w_scrollbar = pfn_client_w_scrollbar;
            captured = true;
        }
        if hmod_user32 != 0 {
            entry.hmod_user32 = hmod_user32;
        }
        if captured {
            self.pfn_arrays_captured = self.pfn_arrays_captured.saturating_add(1);
        }
        Some(captured)
    }

    fn record_scrollbar_atom(&mut self, pid: nt_process::ProcessId, pi: usize, atom: u16) -> bool {
        if atom == 0 {
            return false;
        }
        let Some(entry) = self.entry_mut(pid, pi) else {
            return false;
        };
        entry.scrollbar_atom = atom;
        true
    }

    fn scrollbar_proc(&self, pid: nt_process::ProcessId, ansi: bool) -> Option<u64> {
        let entry = self.get_by_pid(pid)?;
        let proc = if ansi {
            entry.pfn_client_a_scrollbar
        } else {
            entry.pfn_client_w_scrollbar
        };
        (proc != 0).then_some(proc)
    }

    fn scrollbar_atom(&self, pid: nt_process::ProcessId) -> Option<u16> {
        let atom = self.get_by_pid(pid)?.scrollbar_atom;
        (atom != 0).then_some(atom)
    }

    fn debug(&self, pid: nt_process::ProcessId) -> ServiceGuiClientDebug {
        let Some(entry) = self.get_by_pid(pid) else {
            return ServiceGuiClientDebug {
                scrollbar_atom: 0,
                has_pfn_a: false,
                has_pfn_w: false,
            };
        };
        ServiceGuiClientDebug {
            scrollbar_atom: entry.scrollbar_atom,
            has_pfn_a: entry.pfn_client_a_scrollbar != 0,
            has_pfn_w: entry.pfn_client_w_scrollbar != 0,
        }
    }
}

const SERVICE_GUI_CLIENT_RUNTIME_CAP: usize = MAX_PI;

static mut SERVICE_GUI_CLIENT_RUNTIME_WORK: ServiceGuiClientRuntimeTable<
    SERVICE_GUI_CLIENT_RUNTIME_CAP,
> = ServiceGuiClientRuntimeTable::new();

pub(crate) struct ServiceGuiClientRuntimes {
    table: *mut ServiceGuiClientRuntimeTable<SERVICE_GUI_CLIENT_RUNTIME_CAP>,
}

impl ServiceGuiClientRuntimes {
    pub(crate) fn reset() -> Self {
        let table = core::ptr::addr_of_mut!(SERVICE_GUI_CLIENT_RUNTIME_WORK);
        // SAFETY: `service_sec_image` is serialized and the live handler is the sole owner.
        unsafe { (&mut *table).clear() };
        Self { table }
    }

    pub(crate) fn record_client_pfns(
        &mut self,
        pid: nt_process::ProcessId,
        pi: usize,
        pfn_client_a_scrollbar: u64,
        pfn_client_w_scrollbar: u64,
        hmod_user32: u64,
    ) -> Option<bool> {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe {
            (&mut *self.table).record_client_pfns(
                pid,
                pi,
                pfn_client_a_scrollbar,
                pfn_client_w_scrollbar,
                hmod_user32,
            )
        }
    }

    pub(crate) fn record_scrollbar_atom(
        &mut self,
        pid: nt_process::ProcessId,
        pi: usize,
        atom: u16,
    ) -> bool {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        unsafe { (&mut *self.table).record_scrollbar_atom(pid, pi, atom) }
    }

    pub(crate) fn scrollbar_proc(&self, pid: nt_process::ProcessId, ansi: bool) -> Option<u64> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).scrollbar_proc(pid, ansi) }
    }

    pub(crate) fn scrollbar_atom(&self, pid: nt_process::ProcessId) -> Option<u16> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).scrollbar_atom(pid) }
    }

    pub(crate) fn debug(&self, pid: nt_process::ProcessId) -> ServiceGuiClientDebug {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).debug(pid) }
    }

    pub(crate) fn record_classinfo_hit(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        let table = unsafe { &mut *self.table };
        table.classinfo_hits = table.classinfo_hits.saturating_add(1);
    }

    pub(crate) fn record_classinfo_miss(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        let table = unsafe { &mut *self.table };
        table.classinfo_misses = table.classinfo_misses.saturating_add(1);
    }

    pub(crate) fn record_classinfo_copyout_error(&mut self) {
        // SAFETY: this wrapper is the sole mutable owner while its handler is live.
        let table = unsafe { &mut *self.table };
        table.classinfo_copyout_errors = table.classinfo_copyout_errors.saturating_add(1);
    }
}

pub(crate) fn service_gui_runtime_counters() -> (u64, u64, u64, u64) {
    let table = core::ptr::addr_of!(SERVICE_GUI_CLIENT_RUNTIME_WORK);
    // SAFETY: post-loop gates run after `service_sec_image` quiesces; there is no concurrent writer.
    let table = unsafe { &*table };
    (
        table.pfn_arrays_captured,
        table.classinfo_hits,
        table.classinfo_misses,
        table.classinfo_copyout_errors,
    )
}
