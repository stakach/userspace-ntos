//! `ExecNtHandler` inherent methods + its `NativeSyscallHandler` (`dispatch`) impl.
//! The NT syscall service surface (NtXxx handlers). Extracted verbatim from `main.rs`
//! (pure reorg; no logic change). The `ExecNtHandler`/`ExecLoopCtx`/`LpcConnRecord`
//! struct definitions stay in `main.rs`; a child module reaches an ancestor's private
//! fields, and `impl` blocks auto-attach to the type crate-wide.
#![allow(clippy::all)]
use crate::*;

impl ExecNtHandler {
    pub(crate) fn new() -> Self {
        // SAFETY: HIVEBUF is a fixed, executive-lifetime mapping the storage host filled from
        // ::ROSSYS.HIV; REAL_HIVE_SIZE is its reported byte length (0 if unstaged → None).
        let hive = unsafe {
            let n = REAL_HIVE_SIZE.load(Ordering::Relaxed) as usize;
            if n == 0 {
                None
            } else {
                let bytes: &'static [u8] =
                    core::slice::from_raw_parts(HIVEBUF_VADDR as *const u8, n);
                RegfHive::new(bytes)
            }
        };
        ExecNtHandler {
            hive,
            // Reserve up front so the backing buffer is allocated BELOW the heap
            // mark taken in service_sec_image and never reallocates during the
            // smss loop — its address stays stable across the per-syscall bump
            // reset. Opens are deduped (below), so a bounded set of distinct keys
            // never exceeds this.
            key_handles: alloc::vec::Vec::with_capacity(256),
            obj_ns: {
                let mut v = alloc::vec::Vec::with_capacity(48);
                v.push(ObjEntry::dir(b"", 0xFF)); // 0 = root "\"
                // The standard top-level directories the object manager pre-creates. SmpInit opens
                // \?? (DosDevices) + creates drive-letter symlinks in it; the rest exist so later
                // opens (\KnownDlls, \Device, \BaseNamedObjects, …) resolve rather than miss.
                // Names are stored folded (lowercase), matching obj lookups.
                for d in [
                    b"??".as_slice(),
                    b"device",
                    b"global??",
                    b"knowndlls",
                    b"basenamedobjects",
                    b"sessions",
                    b"dosdevices",
                    b"windows",
                    b"objecttypes",
                    b"driver",
                    b"filesystem",
                    b"security",
                ] {
                    v.push(ObjEntry::dir(d, 0));
                }
                v
            },
            pi: 0,
            stop: false,
            next_handle: FAKE_HANDLE,
            out_writes: [(0, 0); 8],
            out_writes_n: 0,
            loop_ctx: None,
            spawn_request: false,
            winlogon_spawn_request: false,
            sm_spawn_request: false,
            wl_spawn_request: false,
            lpc_rendezvous_conn: 0,
            lpc_rendezvous_out: 0,
            csr_spawn_request: false,
            csr_rendezvous_conn: 0,
            csr_rendezvous_out: 0,
            csrss_event_handles: [0; 2],
            csrss_event_n: 0,
            fs: {
                // MemFs::with_fixture() gives the \Windows\System32\Config\* tree (so
                // \Windows\System32 exists as a directory). Seed the full boot-path binary set
                // (SYSTEM32_FILES) under System32 so nt-fs is the single authority for System32 file
                // existence. FILE_CREATE allocates a handle below the heap mark (persistent) — the
                // query path (`&self` query_attributes) never allocates one.
                let mut fs = FileSystem::new(MemFs::with_fixture());
                for name in SYSTEM32_FILES {
                    let path = alloc::format!(r"\SystemRoot\System32\{name}");
                    let r = fs.zw_create_file(&path, 0, 0, 0, nt_fs::FILE_CREATE, 0);
                    let _ = fs.zw_close(r.handle);
                }
                fs
            },
            // Reserve up front (below the per-syscall heap mark) so pushes never reallocate: a
            // bounded set of LPC connections (csrss→\SmApiPort + smss's ports) never exceeds this.
            lpc_connections: alloc::vec::Vec::with_capacity(16),
            winlogon_csr_view: 0,
            csr_view_mask: 0,
            // The real Process Manager. Pre-create an EPROCESS for each hosted process (identity is
            // fixed + known ahead of the actual seL4 spawn — real NT likewise has PspCreateProcess
            // build the EPROCESS before its threads run). Creating all three here (before the
            // service_sec_image heap mark) keeps every EPROCESS allocation persistent + avoids any
            // runtime realloc under the per-syscall bump reset. `PM_PIDS[pi]` records the badge↔pid
            // link (pi 0=smss / 1=csrss / 2=winlogon); the specs verify the objects back the badges.
            pm: {
                let mut pm = nt_process::ProcessManager::new();
                // Path 1b: append-only handle values. The executive hands each hosted process its
                // OWN dense per-process handle VALUES (real NT), then indexes external state (the
                // per-pi DLL registry, EXE section scalars) by those values. NT-style slot reuse
                // would recycle a value while stale bindings to the old value still exist →
                // mis-routing the next open; append-only keeps every value monotonic for the run.
                pm.set_handle_no_reuse(true);
                let smss_pid = pm.create_process("smss.exe", None, None);
                let csrss_pid = pm.create_process("csrss.exe", Some(smss_pid), None);
                let winlogon_pid = pm.create_process("winlogon.exe", Some(smss_pid), None);
                // The 4th hosted process — services.exe, spawned by winlogon's Win32 CreateProcessW
                // (StartServicesManager), so its EPROCESS parent is winlogon.
                let services_pid = pm.create_process("services.exe", Some(winlogon_pid), None);
                PM_PIDS[0].store(smss_pid as u64, Ordering::Relaxed);
                PM_PIDS[1].store(csrss_pid as u64, Ordering::Relaxed);
                PM_PIDS[2].store(winlogon_pid as u64, Ordering::Relaxed);
                PM_PIDS[3].store(services_pid as u64, Ordering::Relaxed);
                PM_PROC_COUNT.store(pm.process_count() as u64, Ordering::Relaxed);
                // Identity check: each EPROCESS exists, names its hosted binary, and has a distinct pid.
                let mut ok = 0u64;
                let expect: [(usize, u32, &str); 4] = [
                    (0, smss_pid, "smss.exe"),
                    (1, csrss_pid, "csrss.exe"),
                    (2, winlogon_pid, "winlogon.exe"),
                    (3, services_pid, "services.exe"),
                ];
                for (i, pid, name) in expect {
                    let distinct = expect.iter().filter(|e| e.1 == pid).count() == 1;
                    if distinct
                        && pm
                            .process(pid)
                            .is_some_and(|p| p.image_file_name.eq_ignore_ascii_case(name))
                    {
                        ok |= 1 << i;
                    }
                }
                PM_IDENTITY_OK.store(ok, Ordering::Relaxed);
                // Path 2 — create each hosted process's MAIN THREAD as a real ETHREAD (identity)
                // NOW, at boot, below the service_sec_image heap mark: pm.create_thread's BTreeMap/
                // BTreeSet inserts are durable but happen before the mark, so the per-syscall bump
                // reset never rewinds them (same non-leaking pattern as the EPROCESSes). This moves
                // each EPROCESS Created→Running + sets its main_thread. The real image ENTRY is bound
                // later, alloc-free, at the actual seL4 spawn (set_thread_start_address). Entry starts
                // 0 = "not yet bound".
                let mut mt_ok = 0u64;
                let pids = [smss_pid, csrss_pid, winlogon_pid, services_pid];
                for (i, &pid) in pids.iter().enumerate() {
                    if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                        PM_TIDS[i].store(tid as u64, Ordering::Relaxed);
                        let running = pm
                            .process(pid)
                            .is_some_and(|p| p.state == nt_process::ProcessState::Running);
                        let cid_ok = pm.client_id(tid) == Some(nt_process::ClientId {
                            unique_process: pid,
                            unique_thread: tid,
                        });
                        if pm.main_thread(pid) == Some(tid) && running && cid_ok {
                            mt_ok |= 1 << i;
                        }
                    }
                }
                PM_MAIN_THREADS_OK.store(mt_ok, Ordering::Relaxed);
                // General NtCreateThread — pre-create a POOL of extra ETHREADs NOW (at boot, below the
                // service_sec_image heap mark) so a RUNTIME NtCreateThread can hand one out WITHOUT a
                // BTreeMap insert (which, made during a serviced call above the mark, the per-syscall
                // bump reset would rewind → corrupt). Runtime create then only pops a pool tid + binds
                // its start routine/TEB (both alloc-free field writes) → reset-safe. One pool ETHREAD
                // per process is enough for the current boot (only winlogon creates a runtime thread —
                // its RPC listener); the array generalizes to any pi. Pool threads are NOT the main
                // thread (main was created first above), so main_thread() is unchanged.
                for (i, &pid) in pids.iter().enumerate() {
                    if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                        PM_POOL_TID[i].store(tid as u64, Ordering::Relaxed);
                    }
                }
                // Pre-reserve each EPROCESS's handle table NOW (below the service_sec_image heap
                // mark) so per-syscall `insert_handle` writes into pre-allocated storage and NEVER
                // reallocates under the per-call bump reset — the NON-LEAKING heap-reset solution.
                // Measured peak is < ~100 handles per process over a full boot; 256 is ~3× headroom.
                for pid in [smss_pid, csrss_pid, winlogon_pid, services_pid] {
                    pm.reserve_handles(pid, PM_HANDLE_RESERVE);
                }
                // Record the reserved capacity (min across the 4) so the run can prove it never
                // grows — i.e. `insert_handle` never reallocates under the per-syscall reset.
                let cap = pm
                    .handle_capacity(smss_pid)
                    .min(pm.handle_capacity(csrss_pid))
                    .min(pm.handle_capacity(winlogon_pid))
                    .min(pm.handle_capacity(services_pid));
                PM_HANDLE_CAP_BOOT.store(cap as u64, Ordering::Relaxed);
                pm
            },
            // The CM write plane. Pre-reserve the key vector up front (below the service_sec_image
            // heap mark) so it never reallocates; the per-key `String`/value `Vec` growth happens at
            // runtime and is retained past the per-syscall bump reset because the loop pins the heap
            // high-water mark past each mutation (see `overlay_dirty`). 64 keys is ample for the
            // SCM's volatile-key creation (the boot creates only a handful).
            overlay: nt_hive_core::RegistryOverlay::with_capacity(64),
            overlay_dirty: false,
        }
    }
    /// Intern a `KeyRef` into `key_handles` (deduped) and return the 4-aligned key handle. Handles
    /// are 4-aligned because advapi32's `MapDefaultKey` clears HKEY bit 0. Dedup keeps the table
    /// from growing unboundedly (a reallocation past the heap mark would be clobbered by the reset).
    pub(crate) fn intern_key_handle(&mut self, kr: KeyRef) -> u64 {
        let slot = match self.key_handles.iter().position(|&c| c == kr) {
            Some(i) => i,
            None => {
                self.key_handles.push(kr);
                self.key_handles.len() - 1
            }
        };
        KEY_HANDLE_BASE + (slot as u64) * 4
    }
    /// Canonical overlay path for a full NT key path (CurrentControlSet alias applied), matching
    /// `resolve_key`'s view so an overlay write and a later base-hive read agree on one key.
    pub(crate) fn overlay_canon(&self, full: &str) -> alloc::string::String {
        nt_hive_core::canon_path(&apply_ccs_alias(full))
    }
    /// Resolve a fault BADGE's process index (pi) to its EPROCESS pid (the badge↔pid convergence
    /// link). Returns `None` before the ProcessManager has created that hosted process.
    pub(crate) fn pm_pid_for_pi(&self, pi: usize) -> Option<nt_process::ProcessId> {
        let pid = PM_PIDS.get(pi)?.load(Ordering::Relaxed);
        (pid != 0).then_some(pid as nt_process::ProcessId)
    }
    /// Mint an executive handle for the CURRENT process (`self.pi`) and record it in that process's
    /// real EPROCESS handle table (path 1 of the nt-process convergence). Behaviour-preserving: the
    /// returned VALUE is still the global monotonic `next_handle` (so the reg/LPC/win32k consumers
    /// that match on handle values are unchanged), but the durable per-process table now OWNS the
    /// handle — tagged with the value in a `HandleObject::Opaque` so `NtClose` can free it. The
    /// pre-reserved capacity guarantees the `insert_handle` never reallocates under the reset.
    pub(crate) fn mint_handle(&mut self) -> u64 {
        // Path 1b: return the process-LOCAL dense value the EPROCESS handle table allocates
        // (real NT `(slot+1)*4`), not a global monotonic value. Two processes each get their own
        // 0x4, 0x8, … namespace; cross-process collisions are resolved by the per-pi-keyed
        // consumers (DLL registry) + pi-scoped scalar comparisons. Append-only (no_reuse) keeps
        // each value monotonic for the run so external bindings never see a recycled value.
        if let Some(pid) = self.pm_pid_for_pi(self.pi) {
            if let Ok(h) = self.pm.insert_handle(pid, nt_process::HandleObject::Opaque(0), 0) {
                let c = self.pm.handle_count(pid) as u64;
                if c > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
                    PM_HANDLE_PEAK.store(c, Ordering::Relaxed);
                }
                PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                return h as u64;
            }
        }
        // Fallback (no EPROCESS for this pi — not the 3 hosted processes): global monotonic value.
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
    /// General NtCreateThread: hand out a real pool ETHREAD for the caller (`self.pi`) — bind the
    /// caller-supplied start routine + parameter + TEB base (all alloc-free field writes, reset-safe),
    /// and mint a TYPED `Thread(tid)` handle in the caller's EPROCESS handle table (dense value, so
    /// `NtQueryInformationThread` resolves the handle VALUE → the real ETHREAD). Returns `(tid, handle)`
    /// or `None` if the caller has no free pool ETHREAD. The seL4 TCB is spawned separately by the loop.
    pub(crate) fn nt_create_thread_handle(&mut self, entry: u64, param: u64, teb_base: u64) -> Option<(u64, u64)> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let tid = PM_POOL_TID.get(self.pi)?.load(Ordering::Relaxed);
        if tid == 0 {
            return None;
        }
        let _ = param; // passed to the thread via the trampoline (RCX); ETHREAD bookkeeping unchanged
        let t = tid as nt_process::ThreadId;
        self.pm.set_thread_start_address(t, entry);
        self.pm.set_thread_teb(t, teb_base);
        let _ = self.pm.set_thread_state(t, nt_process::ThreadState::Running);
        let h = self.pm.insert_handle(pid, nt_process::HandleObject::Thread(t), 0).ok()?;
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        PM_GENERAL_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
        Some((tid, h as u64))
    }
    /// Resolve a ThreadHandle VALUE (in the caller's EPROCESS handle table) → the real ETHREAD tid.
    /// `NtCurrentThread()` (`-2`) → the caller's main ETHREAD. Used by `NtQueryInformationThread`.
    pub(crate) fn resolve_thread_handle(&self, handle: u64) -> Option<u64> {
        let caller = self.pm_pid_for_pi(self.pi)?;
        if handle == 0xFFFF_FFFF_FFFF_FFFE {
            return self.pm.main_thread(caller).map(|t| t as u64); // NtCurrentThread()
        }
        match self.pm.lookup_handle(caller, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Thread(t)) => Some(t as u64),
            _ => None,
        }
    }
    /// Bind a hosted process's MAIN THREAD to its real image entry at the actual seL4 spawn — the
    /// "route NtCreateThread through pm at real spawn time" step (the thread object was pre-created
    /// at boot for the non-leaking heap solution; this alloc-free field write completes it).
    pub(crate) fn bind_main_thread_entry(&mut self, pi: usize, entry: u64) {
        if let Some(tid) = PM_TIDS.get(pi).map(|t| t.load(Ordering::Relaxed)) {
            if tid != 0 && self.pm.set_thread_start_address(tid as nt_process::ThreadId, entry) {
                PM_THREAD_BINDS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    /// `NtOpenProcess` (spec §9): open a handle to the process identified by `target_pid` in the
    /// CURRENT process's (`self.pi`) EPROCESS handle table, returning the handle VALUE (the global
    /// scheme, like every other mint) or `None` if the target/opener is unknown. The table entry is
    /// a typed `Process(target_pid)` so a later lookup/terminate resolves the real EPROCESS.
    pub(crate) fn nt_open_process(&mut self, target_pid: nt_process::ProcessId) -> Option<u64> {
        let opener = self.pm_pid_for_pi(self.pi)?;
        self.pm.process(target_pid)?; // target must exist
        // Path 1b: the returned VALUE is the opener's process-local dense handle for the typed
        // Process(target_pid) object — so a later value→object lookup resolves the real EPROCESS.
        let h = self
            .pm
            .insert_handle(opener, nt_process::HandleObject::Process(target_pid), 0)
            .ok()?;
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(h as u64)
    }
    /// Resolve a `NtTerminateProcess`/`NtOpenProcess`-style ProcessHandle to the target EPROCESS pid.
    /// `NtCurrentProcess()` (`-1`) → the caller (self-terminate). A real child ProcessHandle is now
    /// resolved via path 1b's value→object index: process handles are dense typed `Process(pid)`
    /// entries in the CALLER's EPROCESS handle table, so `lookup_handle(caller, handle)` returns the
    /// target pid. Returns `None` for an unknown/untyped handle (→ the caller falls back to a benign
    /// no-op, never terminating the wrong process).
    pub(crate) fn resolve_process_handle(&self, handle: u64) -> Option<nt_process::ProcessId> {
        let caller = self.pm_pid_for_pi(self.pi)?;
        if handle == 0xFFFF_FFFF_FFFF_FFFF {
            return Some(caller); // NtCurrentProcess()
        }
        // Path 1b: dense process-local handle VALUE → typed Process(pid) object in the caller's table.
        match self.pm.lookup_handle(caller, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Process(pid)) => Some(pid),
            _ => None,
        }
    }
    /// Queue an 8-byte out-param write for the loop to perform after dispatch (group B2). Silently
    /// drops if the fixed queue is full (bounded per-syscall — no handler queues more than 6).
    pub(crate) fn queue_write(&mut self, ptr: u64, val: u64) {
        if self.out_writes_n < self.out_writes.len() {
            self.out_writes[self.out_writes_n] = (ptr, val);
            self.out_writes_n += 1;
        }
    }
    /// Read a UNICODE_STRING's UTF-16 buffer from the faulting process for an LPC syscall, handling
    /// a buffer that lives OUTSIDE the stack/heap/image mirrors — e.g. csrss's `NtConnectPort`
    /// PortName `L"\\SmApiPort"` is a static string in csrsrv's `.rdata` (~0x8000_xxxx). The
    /// UNICODE_STRING struct itself is a stack local (mirror-readable); its Buffer is read via the
    /// per-fault scratch alias of the already-demand-faulted `.rdata` page (`scratch_for`). Empty on
    /// failure (→ the caller's connect misses by name, a clean error, not a crash).
    /// Read an OBJECT_ATTRIBUTES.ObjectName (OA+0x10 → PUNICODE_STRING) with the SAME .rdata-capable
    /// fallback as `read_lpc_name`. The free `smss_read_objattr_name` is mirror-only, so csrss's
    /// `NtCreatePort(\Windows\ApiPort)` (name in csrsrv .rdata) registered under an EMPTY name → the
    /// broker couldn't match winlogon's connect. Use this so the port registers under its real name.
    pub(crate) unsafe fn read_objattr_name(&self, oa_va: u64) -> alloc::vec::Vec<u16> {
        let mut p = [0u8; 8];
        if !smss_copyin(oa_va + 0x10, &mut p) {
            return alloc::vec::Vec::new();
        }
        let objname = u64::from_le_bytes(p);
        if objname == 0 {
            return alloc::vec::Vec::new();
        }
        self.read_lpc_name(objname)
    }
    pub(crate) unsafe fn read_lpc_name(&self, ustr_va: u64) -> alloc::vec::Vec<u16> {
        if ustr_va == 0 {
            return alloc::vec::Vec::new();
        }
        let mut lm = [0u8; 2];
        let mut bp = [0u8; 8];
        if !smss_copyin(ustr_va, &mut lm) || !smss_copyin(ustr_va + 8, &mut bp) {
            return alloc::vec::Vec::new();
        }
        let buffer_va = u64::from_le_bytes(bp);
        let n = ((u16::from_le_bytes(lm) as usize) / 2).min(1024);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let va = buffer_va + (i as u64) * 2;
            let mut w = [0u8; 2];
            if smss_copyin(va, &mut w) {
                out.push(u16::from_le_bytes(w));
                continue;
            }
            // Not in a mirror → try the scratch alias of an already-faulted page (csrsrv .rdata).
            if let Some(ctx) = self.loop_ctx.as_ref() {
                let fp = &*ctx.filled_pages;
                let nf = *ctx.faults as usize;
                if let Some(m) = scratch_for(va, fp, nf, ctx.scratch_base) {
                    let p = m as *const u8;
                    w[0] = *p;
                    w[1] = *p.add(1);
                    out.push(u16::from_le_bytes(w));
                    continue;
                }
            }
            break;
        }
        out
    }
    /// Read `dst.len()` bytes from the current process's VA `va`, resolving a page OUTSIDE the
    /// stack/heap/image mirrors by reading the STATIC content straight from the backing PE image
    /// (main image / ntdll / a registered DLL). The general cross-AS reader for services' registry
    /// key-name strings: those are `RTL_CONSTANT_STRING` literals in a DLL `.rdata` page services
    /// NEVER dereferences (the executive is the first reader), so the page is not demand-faulted and
    /// not in any mirror or frame table — but its bytes are exactly the (relocation-free) `.rdata`
    /// file content, which we read via the loaded PE. Handles a read that spans a page boundary.
    pub(crate) unsafe fn xas_read(&self, va: u64, dst: &mut [u8]) -> bool {
        if smss_copyin(va, dst) {
            return true;
        }
        let ctx = match self.loop_ctx.as_ref() {
            Some(c) => c,
            None => return false,
        };
        let reg = &*ctx.reg;
        let dll_pes = &*ctx.dll_pes;
        let mut done = 0usize;
        while done < dst.len() {
            let cur = va + done as u64;
            let (pe, byte_rva): (&nt_pe_loader::PeFile, u32) =
                if cur >= PE_LOAD_BASE && cur < ctx.img_end {
                    (&*ctx.pe, (cur - PE_LOAD_BASE) as u32)
                } else if !ctx.ntdll_pe.is_null() && cur >= ctx.nt_base && cur < ctx.nt_end {
                    (&*ctx.ntdll_pe, (cur - ctx.nt_base) as u32)
                } else if let Some((i, rva)) = reg.dll_for_page(cur) {
                    match dll_pes[i].as_ref() {
                        Some(pe) => (pe, rva),
                        None => return false,
                    }
                } else {
                    return false;
                };
            let off = (cur & 0xFFF) as usize;
            let n = (0x1000 - off).min(dst.len() - done);
            for j in 0..n {
                match pe_byte_at_rva(pe, byte_rva + j as u32) {
                    Some(b) => dst[done + j] = b,
                    None => return false,
                }
            }
            done += n;
        }
        true
    }
    /// Cross-AS 8-byte out-param write to the current process's VA `va` — handles a target that lives
    /// in a DLL `.data` global (e.g. advapi32's `DefaultHandleTable[]`, where MapDefaultKey stores the
    /// predefined-root handle) that the stack/heap/image mirror can't reach. Delegates to
    /// [`csrss_out_write`] (mirror → already-faulted page's scratch alias → demand-fill from the DLL
    /// PE). No-op if there is no loop context. Used for services (pi 3) NtOpenKey handle copyout.
    pub(crate) unsafe fn xas_write_u64(&self, va: u64, val: u64) {
        if let Some(ctx) = self.loop_ctx {
            let filled_pages = &mut *ctx.filled_pages;
            let faults = &mut *ctx.faults;
            let reg = &*ctx.reg;
            let dll_pes = &*ctx.dll_pes;
            csrss_out_write(va, val, filled_pages, faults, ctx.scratch_base, reg, dll_pes, ctx.pml4);
        } else {
            smss_copyout(va, &val.to_le_bytes());
        }
    }
    /// Cross-AS byte-buffer write to the current process's VA `va` — mirror first, else 8-byte chunks
    /// via [`xas_write_u64`] (each demand-fills a not-yet-faulted DLL/heap page as needed). The last
    /// partial word is read-modify-written so trailing bytes past `src` in that word are preserved.
    /// Used for services (pi 3) registry info-structure copyout (KEY_*_INFORMATION into a heap buffer).
    pub(crate) unsafe fn xas_write_buf(&self, va: u64, src: &[u8]) {
        if smss_copyout(va, src) {
            return;
        }
        let mut i = 0usize;
        while i < src.len() {
            let n = (src.len() - i).min(8);
            let mut w = [0u8; 8];
            if n < 8 {
                let _ = self.xas_read(va + i as u64, &mut w); // preserve bytes n..8
            }
            w[..n].copy_from_slice(&src[i..i + n]);
            self.xas_write_u64(va + i as u64, u64::from_le_bytes(w));
            i += 8;
        }
    }
    /// Cross-AS UNICODE_STRING read (x64 {u16 Length, u16 Max, u32 pad, u64 Buffer}) via [`xas_read`],
    /// so a Buffer in a not-yet-faulted DLL `.rdata` page resolves from the backing PE. Used for
    /// services (pi 3) registry name strings (key names + value names).
    pub(crate) unsafe fn read_ustr_pe(&self, ustr_va: u64) -> alloc::vec::Vec<u16> {
        if ustr_va == 0 {
            return alloc::vec::Vec::new();
        }
        let mut lm = [0u8; 2];
        let mut bp = [0u8; 8];
        if !self.xas_read(ustr_va, &mut lm) || !self.xas_read(ustr_va + 8, &mut bp) {
            return alloc::vec::Vec::new();
        }
        let byte_len = u16::from_le_bytes(lm) as usize;
        let buffer_va = u64::from_le_bytes(bp);
        let n = (byte_len / 2).min(1024);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let mut w = [0u8; 2];
            if !self.xas_read(buffer_va + (i as u64) * 2, &mut w) {
                break;
            }
            out.push(u16::from_le_bytes(w));
        }
        out
    }
    /// Cross-AS OBJECT_ATTRIBUTES.ObjectName read (OA+0x10 → PUNICODE_STRING) via [`read_ustr_pe`],
    /// so a name Buffer in a not-yet-faulted DLL `.rdata` page resolves from the PE. Used for services
    /// (pi 3) registry key opens (see `read_objattr_name`, whose scratch-alias fallback only reaches
    /// already-faulted pages).
    pub(crate) unsafe fn read_objattr_name_pe(&self, oa_va: u64) -> alloc::vec::Vec<u16> {
        let mut p = [0u8; 8];
        if !self.xas_read(oa_va + 0x10, &mut p) {
            return alloc::vec::Vec::new();
        }
        let objname = u64::from_le_bytes(p);
        if objname == 0 {
            return alloc::vec::Vec::new();
        }
        self.read_ustr_pe(objname)
    }
    /// Cache an established LPC connection (the data-plane record). Bounded by the pre-reserved
    /// capacity so the push never reallocates across the per-syscall bump reset. `connector_pi` =
    /// the current process (0=smss, 1=csrss).
    pub(crate) fn cache_lpc_connection(&mut self, connection_id: u64, client_handle: u64, name: &[u16]) {
        if self.lpc_connections.len() >= self.lpc_connections.capacity() {
            return;
        }
        let mut buf = [0u16; 32];
        let n = name.len().min(32);
        buf[..n].copy_from_slice(&name[..n]);
        self.lpc_connections.push(LpcConnRecord {
            connection_id,
            client_handle,
            connector_pi: self.pi as u8,
            name: buf,
            name_len: n as u8,
        });
    }
    /// Service winlogon's kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort).
    ///
    /// csrss owns \Windows\ApiPort but its real CsrApiRequestThread doesn't run yet, so the executive
    /// MODELS the CSR acceptor (interim, mirroring SM path A): auto-accept through the broker + fill the
    /// reply the client reads back. kernel32's BaseDllInitialize is FATAL on a failed connect and then
    /// dereferences the shared static server data (`Peb->ReadOnlyStaticServerData[BASESRV]->
    /// WindowsDirectory`), so this must hand back real, mapped memory:
    ///  - `ClientView` (PORT_VIEW LpcWrite) ViewBase = a 64 KiB RW region kernel32 RtlCreateHeaps over.
    ///  - `ConnectionInfo` (CSR_API_CONNECTINFO) SharedSectionBase/Heap, SharedStaticServerData (→ an
    ///    array whose [BASESRV=1] slot points at a BASE_STATIC_SERVER_DATA with valid Windows dirs),
    ///    and ServerProcessId.
    /// All out-params are winlogon STACK locals (ConnectionInfo/LpcWrite) reached via the mirror; the
    /// backing regions are mapped into winlogon's own VSpace (lazily, once). Returns STATUS_SUCCESS.
    pub(crate) unsafe fn csr_client_connect(
        &mut self,
        name16: &[u16],
        porthandle_ptr: u64,
        clientview_ptr: u64,
        conninfo_ptr: u64,
    ) -> u32 {
        let ctx = match self.loop_ctx {
            Some(c) => c,
            None => return 0xC000_0001,
        };
        let pml4 = ctx.pml4;
        // (1) Connect through the broker (Pending under Manual). ★ AUTHENTIC accept (mirrors SM path
        // B): rather than modeling the acceptor here, RECORD the pending connection id + the caller's
        // *PortHandle so the LOOP drives `csr_rendezvous` — csrss's REAL CsrApiRequestThread issues the
        // NtReplyWaitReceivePort → CsrApiHandleConnectionRequest → NtAcceptConnectPort →
        // NtCompleteConnectPort. The loop overrides the client handle + writes *PortHandle after the
        // rendezvous. Only if the broker connect is NOT pending (no live named port) do we fall back to
        // a modeled handle + write it here. IMAGE_SUBSYSTEM_WINDOWS_GUI(2) = a Win32 GUI client.
        let mut client_handle = 0u64;
        let mut pending = false;
        if let Some(c) = lpc_client() {
            if let Ok(r) = c.connect_port(name16, 2, &[]) {
                if r.pending && r.connection_id != 0 {
                    self.csr_rendezvous_conn = r.connection_id;
                    self.csr_rendezvous_out = porthandle_ptr;
                    pending = true;
                } else if r.handle != 0 {
                    client_handle = r.handle;
                    self.cache_lpc_connection(r.connection_id, r.handle, name16);
                }
            }
        }
        if !pending && client_handle == 0 {
            client_handle = self.mint_handle();
        }
        // (2) Map THIS process's CSR regions once (heap view + static server data) — per-pi. GENERAL
        // per-process plane: winlogon (pi 2), services (pi 3), and every later Win32 process each get
        // their OWN copy of the CSR heap-view + static-server-data at the shared CSR VAs, in their OWN
        // VSpace (`pml4`). The regions are IDENTICAL content-wise across processes (like the DLL bases),
        // so the same VAs are reused per-VSpace; only the guard is per-pi.
        let pibit = 1u32 << self.pi;
        if self.csr_view_mask & pibit == 0 {
            // One 2 MiB PT in THIS process covers both regions.
            let wpt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
            let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, WINLOGON_CSR_HEAP_VA, pml4);
            // The exec-side fill-scratch alias PT is mapped ONCE (shared across all processes — the
            // executive services one syscall at a time, so its frames are filled-then-copied-then-
            // unmapped within THIS call, leaving the scratch VAs free for the next process).
            if CSR_FILL_SCRATCH_PT.swap(1, Ordering::Relaxed) == 0 {
                let spt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
                let _ = paging_struct_map(
                    spt,
                    LBL_X86_PAGE_TABLE_MAP,
                    WINLOGON_CSR_FILL_SCRATCH,
                    CAP_INIT_THREAD_VSPACE,
                );
            }
            // LpcWrite heap view: 16 committed RW frames (kernel32 RtlCreateHeaps over ViewBase).
            for i in 0..16u64 {
                let f = alloc_frame();
                let _ = page_map(copy_cap(f), WINLOGON_CSR_HEAP_VA + i * 0x1000, RW_NX, pml4);
            }
            // Static server data (4 frames): fill via the exec scratch alias, then map into THIS
            // process, then UNMAP the scratch alias so the next process reuses the same scratch VAs.
            //   page0 +0x0000: ReadOnlyStaticServerData[4]; [1] -> BASE_STATIC_SERVER_DATA
            //   page0 +0x0100: BASE_STATIC_SERVER_DATA (WindowsDirectory@0, WindowsSystemDirectory@0x10,
            //                  NamedObjectDirectory@0x20 — all x64 UNICODE_STRINGs)
            //   page3 (+0x3000 in-region): the WCHAR name buffers
            for i in 0..4u64 {
                let f = alloc_frame();
                let sc = WINLOGON_CSR_FILL_SCRATCH + i * 0x1000;
                let _ = page_map(f, sc, RW_NX, CAP_INIT_THREAD_VSPACE);
                if i == 0 {
                    core::ptr::write_volatile((sc + 0x08) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x0100);
                    let bssd = sc + 0x0100;
                    // WindowsDirectory = L"C:\Windows" (9 wchars)
                    core::ptr::write_volatile((bssd + 0x00) as *mut u16, 9 * 2);
                    core::ptr::write_volatile((bssd + 0x02) as *mut u16, 10 * 2);
                    core::ptr::write_volatile((bssd + 0x08) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3000);
                    // WindowsSystemDirectory = L"C:\Windows\System32" (18 wchars)
                    core::ptr::write_volatile((bssd + 0x10) as *mut u16, 18 * 2);
                    core::ptr::write_volatile((bssd + 0x12) as *mut u16, 19 * 2);
                    core::ptr::write_volatile((bssd + 0x18) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3020);
                    // NamedObjectDirectory = L"\BaseNamedObjects" (17 wchars)
                    core::ptr::write_volatile((bssd + 0x20) as *mut u16, 17 * 2);
                    core::ptr::write_volatile((bssd + 0x22) as *mut u16, 18 * 2);
                    core::ptr::write_volatile((bssd + 0x28) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3060);
                } else if i == 3 {
                    write_wstr(sc + 0x000, "C:\\Windows");
                    write_wstr(sc + 0x020, "C:\\Windows\\System32");
                    write_wstr(sc + 0x060, "\\BaseNamedObjects");
                }
                let _ = page_map(copy_cap(f), WINLOGON_CSR_STATIC_VA + i * 0x1000, RW_NX, pml4);
                // Release the scratch alias mapping of `f` (the target copy_cap is a distinct cap →
                // unaffected) so the next process's fill can remap the same scratch VA.
                let _ = page_unmap(f);
            }
            self.csr_view_mask |= pibit;
            self.winlogon_csr_view = WINLOGON_CSR_HEAP_VA;
        }
        // (3) Fill the client PORT_VIEW (LpcWrite): ViewBase/ViewRemoteBase (delta 0 → capture pointers
        // are client pointers, which the direct message plane reads via the mirror) + ViewSize.
        if clientview_ptr != 0 {
            smss_stack_write(clientview_ptr + 0x18, 0x1_0000); // ViewSize = 64 KiB
            smss_stack_write(clientview_ptr + 0x20, WINLOGON_CSR_HEAP_VA); // ViewBase
            smss_stack_write(clientview_ptr + 0x28, WINLOGON_CSR_HEAP_VA); // ViewRemoteBase
        }
        // (4) Fill CSR_API_CONNECTINFO: kernel32 copies these into the PEB (ReadOnlySharedMemoryBase/
        // Heap, ReadOnlyStaticServerData) + records ServerProcessId.
        if conninfo_ptr != 0 {
            smss_stack_write(conninfo_ptr + 0x08, WINLOGON_CSR_HEAP_VA); // SharedSectionBase
            smss_stack_write(conninfo_ptr + 0x10, WINLOGON_CSR_STATIC_VA); // SharedStaticServerData
            smss_stack_write(conninfo_ptr + 0x18, WINLOGON_CSR_HEAP_VA); // SharedSectionHeap
            smss_stack_write(conninfo_ptr + 0x30, 8); // ServerProcessId (csrss — plausible)
        }
        // (5) *PortHandle = &CsrApiPort (an ntdll .data global) — best-effort. On the AUTHENTIC path
        // the loop writes it after `csr_rendezvous` produces the real client comm-port handle; here we
        // write only the fallback (non-pending) handle. (The modeled message plane doesn't dispatch by
        // this handle, so a silent miss is harmless.)
        if !pending && porthandle_ptr != 0 {
            csrss_out_write(
                porthandle_ptr,
                client_handle,
                &mut *ctx.filled_pages,
                &mut *ctx.faults,
                ctx.scratch_base,
                &*ctx.reg,
                &*ctx.dll_pes,
                pml4,
            );
        }
        WINLOGON_CSR_CONNECTED.store(1, Ordering::Relaxed);
        CSR_CONNECTED_MASK.fetch_or(1u64 << self.pi, Ordering::Relaxed);
        print_str(b"[csr] pi=");
        print_u64(self.pi as u64);
        print_str(if pending {
            b" NtSecureConnectPort(\\Windows\\ApiPort) -> driving REAL CsrApiRequestThread accept; client(fallback)=0x".as_slice()
        } else {
            b" NtSecureConnectPort(\\Windows\\ApiPort) -> modeled accept; client=0x".as_slice()
        });
        print_hex((client_handle >> 32) as u32);
        print_hex(client_handle as u32);
        print_str(b" ViewBase=0x");
        print_hex((WINLOGON_CSR_HEAP_VA >> 32) as u32);
        print_hex(WINLOGON_CSR_HEAP_VA as u32);
        print_str(b" StaticData=0x");
        print_hex((WINLOGON_CSR_STATIC_VA >> 32) as u32);
        print_hex(WINLOGON_CSR_STATIC_VA as u32);
        print_str(b"\n");
        0
    }
    /// Lowercase-ASCII a UTF-16 name into a fixed buffer (object names are case-insensitive);
    /// returns the filled length. Non-ASCII code units are truncated to their low byte.
    pub(crate) fn fold_name(name16: &[u16], out: &mut [u8]) -> usize {
        let mut n = 0;
        for &w in name16 {
            if n >= out.len() {
                break;
            }
            out[n] = (w as u8).to_ascii_lowercase();
            n += 1;
        }
        n
    }
    /// Resolve an object path to an `obj_ns` index. A path starting with `\` walks from the root;
    /// otherwise it is relative to `root_idx` (an already-open directory, e.g. an OA RootDirectory).
    /// Empty leading components (from the leading `\`) are skipped.
    pub(crate) fn obj_resolve(&self, path: &[u8], root_idx: usize) -> Option<usize> {
        let mut cur = if path.first() == Some(&b'\\') {
            0
        } else {
            root_idx
        };
        for comp in path.split(|&c| c == b'\\') {
            if comp.is_empty() {
                continue;
            }
            cur = self.obj_child(cur, comp)?;
        }
        Some(cur)
    }
    /// Find a direct child of directory `parent` whose (folded) name matches `leaf`.
    pub(crate) fn obj_child(&self, parent: usize, leaf: &[u8]) -> Option<usize> {
        self.obj_ns
            .iter()
            .position(|e| e.parent as usize == parent && e.name() == leaf)
    }
    /// Insert a child (dir or symlink) under `parent`, or return the existing one (OPENIF/name
    /// collision → reuse). Returns the index, or None if the table is at capacity.
    pub(crate) fn obj_insert(&mut self, parent: usize, leaf: &[u8], kind: u8, target: &[u8]) -> Option<usize> {
        if let Some(i) = self.obj_child(parent, leaf) {
            return Some(i);
        }
        if self.obj_ns.len() >= self.obj_ns.capacity() {
            return None;
        }
        let mut e = ObjEntry::dir(leaf, parent as u8);
        e.kind = kind;
        if kind == 1 {
            let t = target.len().min(40);
            e.target[..t].copy_from_slice(&target[..t]);
            e.target_len = t as u8;
        }
        self.obj_ns.push(e);
        Some(self.obj_ns.len() - 1)
    }
    /// Create a dir/symlink named by `path` (which may be `\`-qualified or relative to `root_idx`):
    /// resolve the parent from all but the last component, then insert the leaf. Existing → reused.
    pub(crate) fn obj_create(&mut self, path: &[u8], root_idx: usize, kind: u8, target: &[u8]) -> Option<usize> {
        let (parent_path, leaf) = match path.iter().rposition(|&c| c == b'\\') {
            Some(p) => (&path[..p], &path[p + 1..]),
            None => (&[][..], path),
        };
        let parent = if parent_path.iter().all(|&c| c == b'\\') {
            // No real parent component: root if the path was absolute, else the supplied root.
            if path.first() == Some(&b'\\') {
                0
            } else {
                root_idx
            }
        } else {
            self.obj_resolve(parent_path, root_idx)?
        };
        if leaf.is_empty() {
            return Some(parent);
        }
        self.obj_insert(parent, leaf, kind, target)
    }
    /// Resolve a full NT key path (`\Registry\Machine\System\…`) to a key node in the SYSTEM hive:
    /// apply the CurrentControlSet alias (the hive has ControlSet001, not the kernel-synthesized
    /// CurrentControlSet symlink) + strip the hive's mount prefix.
    pub(crate) fn resolve_key(&self, full_path: &str) -> Option<KeyRef> {
        let aliased = apply_ccs_alias(full_path);
        let comps: alloc::vec::Vec<&str> =
            aliased.split('\\').filter(|c| !c.is_empty()).collect();
        if comps.len() < 3
            || !comps[0].eq_ignore_ascii_case("Registry")
            || !comps[1].eq_ignore_ascii_case("Machine")
        {
            return None;
        }
        if comps[2].eq_ignore_ascii_case("System") {
            return self.hive.as_ref()?.open_key(&comps[3..].join("\\"));
        }
        // The kernel's volatile HARDWARE hive isn't on disk. Synthesize the one key smss's SmpInit
        // reads: \Registry\Machine\Hardware\Description\System\CentralProcessor\0 (CPU identifier).
        let ci = |i: usize, s: &str| comps.get(i).map_or(false, |c| c.eq_ignore_ascii_case(s));
        if comps.len() == 7
            && ci(2, "Hardware")
            && ci(3, "Description")
            && ci(4, "System")
            && ci(5, "CentralProcessor")
            && ci(6, "0")
        {
            return Some(SYNTH_CPU_KEY);
        }
        None
    }
    /// Does a `\SystemRoot\System32` file with this probe's leaf name exist in the real nt-fs
    /// namespace? Extracts the leaf (last `\`-component) of the folded probe path and looks it up
    /// under System32 — path-form independent (the loader probes many directory prefixes for the
    /// same DLL). nt-fs is the single existence authority; nt-dll-registry keeps SEC_IMAGE geometry.
    pub(crate) fn fs_system32_has(&self, folded: &[u8]) -> bool {
        let leaf = match folded.iter().rposition(|&c| c == b'\\') {
            Some(p) => &folded[p + 1..],
            None => folded,
        };
        if leaf.is_empty() {
            return false;
        }
        let Ok(leaf_str) = core::str::from_utf8(leaf) else {
            return false;
        };
        let mut path = alloc::string::String::from(r"\SystemRoot\System32\");
        path.push_str(leaf_str);
        self.fs.query_attributes(&path).is_some()
    }
}
impl NativeSyscallHandler for ExecNtHandler {
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], _out: &mut alloc::vec::Vec<u8>) -> u32 {
        match ctx.service {
            // NtClose(Handle[R10]=args[0]): free the handle in the caller's REAL EPROCESS handle
            // table by its SLOT (path 1b — the value IS the dense per-process table handle now, so
            // close by value directly; no value-tag scan). Append-only allocation means the freed
            // slot is NOT recycled, so a later open never reuses a closed value (keeping external
            // bindings — the per-pi DLL registry — consistent). We still return SUCCESS
            // unconditionally (matching the prior no-op) so a close of a handle the executive
            // doesn't own — a win32k/Ob handle, a pseudo-handle, or a fallback global value — stays
            // benign. Purely additive: the returned status is unchanged.
            NativeService::NtClose => {
                if let Some(pid) = self.pm_pid_for_pi(self.pi) {
                    if self.pm.close_handle(pid, args[0] as nt_process::Handle).is_ok() {
                        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                0 // STATUS_SUCCESS
            }
            // NtOpenKey(*KeyHandle[0], DesiredAccess[1], ObjectAttributes[2]). Copy in the object
            // name from smss, resolve it in the SYSTEM hive, hand back a handle (copyout to arg0).
            NativeService::NtOpenKey => unsafe {
                // OBJECT_ATTRIBUTES: RootDirectory @+8, ObjectName @+0x10. RtlQueryRegistryValues
                // opens subkeys RELATIVE to an already-open key (RootDirectory = its handle,
                // ObjectName = a leaf like "Environment"), so honour RootDirectory.
                let oa = args[2];
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                // services (pi 3): its RegOpenKeyExW key-name strings are RTL_CONSTANT_STRING literals
                // in a DLL `.rdata` page (advapi32 ~0x88000000) that services NEVER dereferences (the
                // executive is the first reader), so the page is not demand-faulted → unreachable by
                // the mirror/frame table. Read the static content straight from the backing PE image
                // (`read_objattr_name_pe`). Scoped to pi==3 so winlogon/csrss paint-time OA-name reads
                // stay mirror-only (byte-identical).
                let name16 = if self.pi == 3 {
                    self.read_objattr_name_pe(oa)
                } else {
                    smss_read_objattr_name(oa)
                };
                let mut path = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        path.push(c);
                    }
                }
                // services (pi 3): resolve HKLM predefined roots + machine-relative subkeys against
                // the real SYSTEM hive (::ROSSYS.HIV). A predefined `\Registry\Machine` open → the
                // sentinel machine-root handle; a subkey relative to it (RootDirectory ==
                // MACHINE_ROOT_HANDLE) or an absolute `\Registry\Machine\...` path → `resolve_key`;
                // a subkey relative to a real hive handle → `open_key_from`. Self-contained + returns,
                // so the winlogon/csrss paint-time key hacks below are untouched (byte-identical).
                if self.pi == 3 {
                    // Compute the FULL NT path being opened (predefined-root + overlay-relative
                    // cases). `None` = a hive-handle-relative open (path unknown, resolved below).
                    // NOTE: MACHINE_ROOT_HANDLE (0x9_..) is numerically >= KEY_HANDLE_BASE (0x1_..),
                    // so it MUST be matched BEFORE the generic real-handle branch.
                    let full_opt: Option<alloc::string::String> = if root_dir == MACHINE_ROOT_HANDLE {
                        let mut full = alloc::string::String::from(r"\Registry\Machine\");
                        full.push_str(&path);
                        Some(full)
                    } else if let Some(oidx) = (root_dir >= KEY_HANDLE_BASE)
                        .then(|| ((root_dir - KEY_HANDLE_BASE) / 4) as usize)
                        .and_then(|i| self.key_handles.get(i).copied())
                        .and_then(overlay_key_idx)
                    {
                        // Subkey relative to an OVERLAY (created) key → parent path + \ + name.
                        self.overlay.path(oidx).map(|p| {
                            let mut full = alloc::string::String::from(p);
                            if !path.is_empty() {
                                full.push('\\');
                                full.push_str(&path);
                            }
                            full
                        })
                    } else if root_dir >= KEY_HANDLE_BASE {
                        None // relative to a real hive handle — resolved via open_key_from below
                    } else {
                        // Absolute open (root_dir == 0). The predefined `\Registry\Machine` open
                        // itself → the sentinel machine-root handle.
                        let comps: alloc::vec::Vec<&str> =
                            path.split('\\').filter(|c| !c.is_empty()).collect();
                        if comps.len() == 2
                            && comps[0].eq_ignore_ascii_case("Registry")
                            && comps[1].eq_ignore_ascii_case("Machine")
                        {
                            self.xas_write_u64(args[0], MACHINE_ROOT_HANDLE);
                            return 0; // predefined HKLM root → sentinel machine-root handle
                        }
                        Some(path.clone())
                    };
                    // Overlay-FIRST: a created key shadows the base hive. Before services creates
                    // anything the overlay is empty, so this is byte-identical to the prior path.
                    if let Some(ref full) = full_opt {
                        let canon = self.overlay_canon(full);
                        if let Some(oidx) = self.overlay.find(&canon) {
                            let h = self.intern_key_handle(OVERLAY_KEY_TAG | (oidx as u32));
                            self.xas_write_u64(args[0], h);
                            return 0; // STATUS_SUCCESS
                        }
                    }
                    // Base-hive resolution (unchanged from the read-only seam).
                    let cell: Option<KeyRef> = if let Some(ref full) = full_opt {
                        self.resolve_key(full)
                    } else {
                        let idx = ((root_dir - KEY_HANDLE_BASE) / 4) as usize;
                        match (self.hive.as_ref(), self.key_handles.get(idx).copied()) {
                            (Some(h), Some(parent)) => h.open_key_from(parent, &path),
                            _ => None,
                        }
                    };
                    return match cell {
                        Some(cell) => {
                            let h = self.intern_key_handle(cell);
                            self.xas_write_u64(args[0], h);
                            0 // STATUS_SUCCESS
                        }
                        None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                    };
                }
                // P5 PAINT-SAFE keyboard-layout fix (see MACHINE_ROOT_HANDLE). Match the layout key
                // by NAME (its RootDirectory arrives as 0 — advapi32's MapDefaultKey HKLM handle
                // doesn't round-trip into the subkey OA — so the sentinel-relative test isn't hit).
                // This is the ONLY key resolved specially, so every other HKLM/HKCU subkey outcome is
                // identical to pre-fix and win32k's paint-time client reads are unchanged (a broad
                // DLL-.rdata read regressed the paint by letting ALL HKLM reads succeed).
                if is_keyboard_layout_key(&path) {
                    smss_copyout(args[0], &SYNTH_KBD_HANDLE.to_le_bytes());
                    KBD_LAYOUT_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                    return 0; // STATUS_SUCCESS
                }
                // A subkey open relative to the predefined-root sentinel that is NOT the keyboard key:
                // NOT_FOUND (preserves the pre-fix outcome for all non-keyboard predefined subkeys).
                if root_dir == MACHINE_ROOT_HANDLE {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                // An absolute open whose name is an unreadable DLL `.rdata` static (empty path) is a
                // predefined-root open (HKLM/HKCU/HKCR); hand back the sentinel so MapDefaultKey
                // succeeds (else the keyboard subkey open never fires). Non-keyboard subkeys stay
                // not-found via the match above.
                if root_dir < KEY_HANDLE_BASE
                    && path.is_empty()
                    && SERVICES_CREATE_STARTED.load(Ordering::Relaxed) == 0
                {
                    smss_copyout(args[0], &MACHINE_ROOT_HANDLE.to_le_bytes());
                    return 0; // STATUS_SUCCESS
                }
                // Once winlogon's Win32 create for services.exe has begun, an empty-name absolute open
                // is BasepIsProcessAllowed's AppCertDlls key (its .rdata static reads empty in the
                // mirror). Return NOT_FOUND so BasepIsProcessAllowed skips RtlQueryRegistryValues and
                // returns SUCCESS (else that query fails c0000002 → "Process not allowed to launch").
                // The keyboard-layout path that needs MACHINE_ROOT_HANDLE runs long before this.
                if root_dir < KEY_HANDLE_BASE && path.is_empty() {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                let cell = if root_dir >= KEY_HANDLE_BASE {
                    let idx = ((root_dir - KEY_HANDLE_BASE) / 4) as usize;
                    match (self.hive.as_ref(), self.key_handles.get(idx).copied()) {
                        (Some(h), Some(parent)) => h.open_key_from(parent, &path),
                        _ => None,
                    }
                } else {
                    self.resolve_key(&path)
                };
                match cell {
                    Some(cell) => {
                        // Dedup: smss reopens the same keys in a loop and NtClose is a no-op, so
                        // return the existing handle for a known cell instead of growing the table
                        // unboundedly (which would reallocate its buffer above the heap mark and
                        // get clobbered by the per-syscall bump reset).
                        let idx = match self.key_handles.iter().position(|&c| c == cell) {
                            Some(i) => i,
                            None => {
                                self.key_handles.push(cell);
                                self.key_handles.len() - 1
                            }
                        };
                        let h = KEY_HANDLE_BASE + (idx as u64) * 4; // 4-aligned: advapi32 clears HKEY bit0
                        smss_copyout(args[0], &h.to_le_bytes());
                        0 // STATUS_SUCCESS
                    }
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtCreateKey(*KeyHandle[0], DesiredAccess[1], *ObjectAttributes[2], TitleIndex, *Class,
            // CreateOptions, *Disposition[sp+0x38]). The CM WRITE plane: create-or-open a key in the
            // in-memory overlay ([`RegistryOverlay`]) that shadows the read-only base hive. services'
            // (pi 3) ScmCreateServiceDatabase creates volatile keys (Control\ServiceCurrent, group
            // list) here. Scoped to pi==3; pi 0-2 keep the prior behaviour (NtCreateKey was
            // unregistered → the loop stopped on the SSN) so their boot is byte-identical.
            NativeService::NtCreateKey => unsafe {
                if self.pi != 3 {
                    self.stop = true;
                    return 0xC000_0002; // record the SSN + stop (matches the prior unregistered wall)
                }
                let oa = args[2];
                let mut rd = [0u8; 8];
                let _ = self.xas_read(oa + 8, &mut rd); // OBJECT_ATTRIBUTES.RootDirectory @+8
                let root_dir = u64::from_le_bytes(rd);
                let name16 = self.read_objattr_name_pe(oa);
                let mut name = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        name.push(c);
                    }
                }
                // Resolve the full NT path: predefined HKLM root, absolute, or overlay-relative.
                let full: Option<alloc::string::String> = if root_dir == MACHINE_ROOT_HANDLE {
                    let mut f = alloc::string::String::from(r"\Registry\Machine\");
                    f.push_str(&name);
                    Some(f)
                } else if root_dir == 0 {
                    Some(name.clone())
                } else if let Some(oidx) = ((root_dir - KEY_HANDLE_BASE) / 4)
                    .try_into()
                    .ok()
                    .filter(|_| root_dir >= KEY_HANDLE_BASE)
                    .and_then(|i: usize| self.key_handles.get(i).copied())
                    .and_then(overlay_key_idx)
                {
                    self.overlay.path(oidx).map(|p| {
                        let mut f = alloc::string::String::from(p);
                        if !name.is_empty() {
                            f.push('\\');
                            f.push_str(&name);
                        }
                        f
                    })
                } else {
                    // Create relative to a real HIVE handle: the parent path isn't tracked (the SCM
                    // doesn't take this path). Fall through to NOT_FOUND rather than mis-create.
                    None
                };
                let full = match full {
                    Some(f) => f,
                    None => return 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                };
                let canon = self.overlay_canon(&full);
                // Disposition: CREATED unless the key already exists in the overlay OR the base hive.
                let existed =
                    self.overlay.find(&canon).is_some() || self.resolve_key(&full).is_some();
                let (oidx, _) = self.overlay.create(&canon);
                self.overlay_dirty = true;
                let h = self.intern_key_handle(OVERLAY_KEY_TAG | (oidx as u32));
                self.xas_write_u64(args[0], h); // *KeyHandle
                // *Disposition (optional): arg6 at [sp+0x38].
                let disp_ptr = smss_stack_read(get_recv_mr(16) + 0x38);
                if disp_ptr != 0 {
                    let disp = if existed { REG_OPENED_EXISTING_KEY } else { REG_CREATED_NEW_KEY };
                    self.xas_write_buf(disp_ptr, &disp.to_le_bytes());
                }
                0 // STATUS_SUCCESS
            },
            // NtSetValueKey(KeyHandle[0], *ValueName[1], TitleIndex, Type[3], Data[sp+0x28],
            // DataSize[sp+0x30]). The CM WRITE plane: write a value into an overlay (created) key.
            // Scoped to pi==3; pi 0-2 stay a no-op success (byte-identical — smss's SmpInit writes
            // are still discarded). A write to a base-hive handle (not an overlay key) is a no-op
            // success too (we don't shadow arbitrary base keys for writes yet).
            NativeService::NtSetValueKey => unsafe {
                if self.pi != 3 {
                    return 0; // STATUS_SUCCESS (byte-identical no-op for smss/csrss/winlogon)
                }
                let key = match self
                    .key_handles
                    .get((args[0].wrapping_sub(KEY_HANDLE_BASE) / 4) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0, // unknown handle → benign success (prior no-op)
                };
                let oidx = match overlay_key_idx(key) {
                    Some(i) => i,
                    None => return 0, // base-hive handle → no-op success (not shadowed for writes)
                };
                let name16 = self.read_ustr_pe(args[1]);
                let mut name = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        name.push(c);
                    }
                }
                let ty = args[3] as u32; // R9 = Type
                let sp = get_recv_mr(16);
                let data_ptr = smss_stack_read(sp + 0x28); // [sp+0x28] = Data
                let data_size = (smss_stack_read(sp + 0x30) as usize).min(4096); // [sp+0x30] = DataSize
                let mut data = alloc::vec![0u8; data_size];
                if data_ptr != 0 && data_size != 0 && !self.xas_read(data_ptr, &mut data) {
                    data.clear(); // unreadable → store an empty value rather than garbage
                }
                self.overlay.set_value(oidx, &name, ty, &data);
                self.overlay_dirty = true;
                0 // STATUS_SUCCESS
            },
            // NtEnumerateValueKey(KeyHandle[0], Index[1], InfoClass[2], KeyValueInfo[3], Length[4],
            // *ResultLength[5]). Enumerate the value at Index from the real hive + copy the
            // KEY_VALUE_*_INFORMATION out; SmpInit reads the Environment/DOS-Devices/etc. values.
            NativeService::NtEnumerateValueKey => unsafe {
                let hive = match self.hive.as_ref() {
                    Some(h) => h,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let key = match self
                    .key_handles
                    .get((args[0].wrapping_sub(KEY_HANDLE_BASE) / 4) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let byname: Option<(alloc::string::String, u32, alloc::vec::Vec<u8>)> =
                    if key == SYNTH_CPU_KEY {
                        // The synthetic CPU key has 2 values (Identifier, VendorIdentifier).
                        let entry = match args[1] {
                            0 => Some(("Identifier", "identifier")),
                            1 => Some(("VendorIdentifier", "vendoridentifier")),
                            _ => None,
                        };
                        entry.and_then(|(nm, lc)| {
                            synth_cpu_value(lc)
                                .map(|(ty, d16)| (alloc::string::String::from(nm), ty, utf16_bytes(&d16)))
                        })
                    } else if let Some(oidx) = overlay_key_idx(key) {
                        // Overlay (created) key: enumerate its own set values.
                        self.overlay
                            .value_by_index(oidx, args[1] as usize)
                            .map(|(nm, ty, d)| (alloc::string::String::from(nm), ty, d.to_vec()))
                    } else {
                        hive.value_by_index(key, args[1] as usize)
                    };
                match byname {
                    None => 0x8000_001A, // STATUS_NO_MORE_ENTRIES
                    Some((name, ty, data)) => {
                        let info = build_key_value_info(args[2], &name, ty, &data);
                        smss_copyout(args[5], &(info.len() as u32).to_le_bytes()); // *ResultLength
                        if info.len() > args[4] as usize {
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            smss_copyout(args[3], &info);
                            0 // STATUS_SUCCESS
                        }
                    }
                }
            },
            // NtEnumerateKey(KeyHandle[0], Index[1], KeyInformationClass[2], KeyInformation[3],
            // Length[4], *ResultLength[5]). For services (pi 3) this enumerates the REAL subkeys of a
            // hive key (ScmCreateServiceDatabase walks HKLM\SYSTEM\CurrentControlSet\Services). For
            // winlogon/csrss (pi 0-2) it stays the empty-set stub (STATUS_NO_MORE_ENTRIES) — the RPC
            // bring-up needs no subkeys and this keeps their paths byte-identical.
            NativeService::NtEnumerateKey => unsafe {
                NT_ENUMERATE_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
                if self.pi != 3 {
                    return 0x8000_001A; // STATUS_NO_MORE_ENTRIES (byte-identical stub for pi 0-2)
                }
                let hive = match self.hive.as_ref() {
                    Some(h) => h,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let key = match self
                    .key_handles
                    .get((args[0].wrapping_sub(KEY_HANDLE_BASE) / 4) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008,
                };
                // Overlay (created) keys track no enumerated subkeys here (the SCM creates leaf
                // volatile keys); report the empty set rather than mis-reading the tag as an offset.
                if overlay_key_idx(key).is_some() {
                    return 0x8000_001A; // STATUS_NO_MORE_ENTRIES
                }
                let subs = hive.subkeys(key);
                let idx = args[1] as usize;
                if idx >= subs.len() {
                    return 0x8000_001A; // STATUS_NO_MORE_ENTRIES
                }
                let name16: alloc::vec::Vec<u16> = subs[idx].0.encode_utf16().collect();
                let name_bytes = name16.len() * 2;
                // class 0 = KeyBasicInformation {LastWriteTime@0(8), TitleIndex@8(4), NameLength@0xc(4),
                // Name@0x10}; class 1 = KeyNodeInformation {…, ClassOffset@0xc, ClassLength@0x10,
                // NameLength@0x14, Name@0x18}. RegEnumKeyExW(lpClass=NULL) → basic; ScmCreateService-
                // Database uses that. Build both; other classes → basic.
                let node = args[2] == 1;
                let hdr = if node { 0x18usize } else { 0x10 };
                let mut info = alloc::vec::Vec::with_capacity(hdr + name_bytes);
                info.resize(hdr, 0); // LastWriteTime/TitleIndex/(ClassOffset/ClassLength) all 0
                let nl_off = if node { 0x14 } else { 0x0c };
                info[nl_off..nl_off + 4].copy_from_slice(&(name_bytes as u32).to_le_bytes());
                if node {
                    // ClassOffset = header + name (no class stored) — points past the name.
                    let class_off = (hdr + name_bytes) as u32;
                    info[0x0c..0x10].copy_from_slice(&class_off.to_le_bytes());
                }
                for w in &name16 {
                    info.extend_from_slice(&w.to_le_bytes());
                }
                let total = info.len() as u32;
                smss_copyout(args[5], &total.to_le_bytes()); // *ResultLength (stack local)
                if (args[4] as usize) < info.len() {
                    return 0x8000_0005; // STATUS_BUFFER_OVERFLOW
                }
                self.xas_write_buf(args[3], &info); // KeyInformation (heap buffer)
                0 // STATUS_SUCCESS
            },
            // NtQueryKey(KeyHandle[0], KeyInformationClass[1], KeyInformation[2], Length[3],
            // *ResultLength[4]). services' RegQueryInfoKeyW (KeyFullInformation) reads the subkey/value
            // counts + max name lengths of a hive key to size its RegEnumKeyExW buffers. Scoped to
            // pi==3 (services); other processes have no real NtQueryKey path today → stop as before.
            NativeService::NtQueryKey => unsafe {
                if self.pi != 3 {
                    self.stop = true;
                    return 0xC000_0002; // STATUS_NOT_IMPLEMENTED (record the SSN for pi 0-2)
                }
                let hive = match self.hive.as_ref() {
                    Some(h) => h,
                    None => return 0xC000_0008,
                };
                let key = match self
                    .key_handles
                    .get((args[0].wrapping_sub(KEY_HANDLE_BASE) / 4) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008,
                };
                // Overlay (created) key: report its own value count (no subkeys tracked here).
                if let Some(oidx) = overlay_key_idx(key) {
                    if args[1] != 2 {
                        return 0xC000_0003; // STATUS_INVALID_INFO_CLASS
                    }
                    let vlen = self.overlay.values_len(oidx);
                    let max_vname = (0..vlen)
                        .filter_map(|i| self.overlay.value_by_index(oidx, i))
                        .map(|(n, _, _)| n.len())
                        .max()
                        .unwrap_or(0) as u32
                        * 2;
                    let struct_size = 0x2cu32;
                    let mut info = [0u8; 0x2c];
                    info[0x0c..0x10].copy_from_slice(&struct_size.to_le_bytes()); // ClassOffset
                    info[0x20..0x24].copy_from_slice(&(vlen as u32).to_le_bytes()); // Values
                    info[0x24..0x28].copy_from_slice(&max_vname.to_le_bytes()); // MaxValueNameLen
                    smss_copyout(args[4], &struct_size.to_le_bytes()); // *ResultLength
                    if (args[3] as usize) < struct_size as usize {
                        return 0x8000_0005; // STATUS_BUFFER_OVERFLOW
                    }
                    self.xas_write_buf(args[2], &info);
                    return 0; // STATUS_SUCCESS
                }
                let subs = hive.subkeys(key);
                let vals = hive.values(key);
                let subkeys = subs.len() as u32;
                let max_name = subs.iter().map(|(n, _)| n.len()).max().unwrap_or(0) as u32 * 2;
                let values = vals.len() as u32;
                let max_vname = vals.iter().map(|(n, _)| n.len()).max().unwrap_or(0) as u32 * 2;
                // class 2 = KeyFullInformation {LastWriteTime@0(8), TitleIndex@8, ClassOffset@0xc,
                // ClassLength@0x10, SubKeys@0x14, MaxNameLen@0x18, MaxClassLen@0x1c, Values@0x20,
                // MaxValueNameLen@0x24, MaxValueDataLen@0x28, Class@0x2c}. We report no Class.
                if args[1] != 2 {
                    // KeyBasic/Node/Name classes on THIS key aren't needed by the SCM path; report a
                    // clean empty full-info-sized answer is wrong for them, so signal invalid-info.
                    return 0xC000_0003; // STATUS_INVALID_INFO_CLASS
                }
                let struct_size = 0x2cu32;
                let mut info = [0u8; 0x2c];
                info[0x0c..0x10].copy_from_slice(&struct_size.to_le_bytes()); // ClassOffset
                // ClassLength@0x10 = 0
                info[0x14..0x18].copy_from_slice(&subkeys.to_le_bytes());
                info[0x18..0x1c].copy_from_slice(&max_name.to_le_bytes());
                // MaxClassLen@0x1c = 0
                info[0x20..0x24].copy_from_slice(&values.to_le_bytes());
                info[0x24..0x28].copy_from_slice(&max_vname.to_le_bytes());
                // MaxValueDataLen@0x28 = 0 (callers re-query per value; unused for sizing here)
                smss_copyout(args[4], &struct_size.to_le_bytes()); // *ResultLength (stack local)
                if (args[3] as usize) < struct_size as usize {
                    return 0x8000_0005; // STATUS_BUFFER_OVERFLOW
                }
                self.xas_write_buf(args[2], &info);
                0 // STATUS_SUCCESS
            },
            // NtCreateNamedPipeFile(FileHandle[R10], DesiredAccess[RDX], ObjectAttributes[R8],
            // IoStatusBlock[R9], ...). winlogon's StartRpcServer → rpcrt4 ncacn_np creates
            // \Device\NamedPipe\winreg. Model the pipe: mint a handle + report FILE_CREATED so
            // RpcServerUseProtseqEpW/RpcServerListen see RPC_S_OK and StartRpcServer returns TRUE
            // (it is FATAL otherwise). No real transport — nothing connects to \pipe\winreg in the
            // bring-up; the RPC listener thread (NtCreateThread is a no-op) never runs.
            NativeService::NtCreateNamedPipeFile => unsafe {
                let h = self.mint_handle();
                smss_stack_write(get_recv_mr(9), h); // *FileHandle (R10)
                let iosb = get_recv_mr(8); // R9 = *IO_STATUS_BLOCK
                if iosb != 0 {
                    smss_stack_write32(iosb, 0); // Status = STATUS_SUCCESS
                    smss_stack_write(iosb + 8, 2); // Information = FILE_CREATED
                }
                NAMED_PIPE_CREATED.fetch_add(1, Ordering::Relaxed);
                0 // STATUS_SUCCESS
            },
            // NtFsControlFile(FileHandle[R10], Event[RDX], ApcRoutine[R8], ApcContext[R9],
            // IoStatusBlock[sp+0x28], FsControlCode[sp+0x30], ...). rpcrt4's pipe listen/connect
            // FSCTLs. Report success with a zeroed IoStatusBlock so the listener setup proceeds; no
            // client ever connects, so the actual pipe-listen semantics are irrelevant to bring-up.
            NativeService::NtFsControlFile => unsafe {
                let iosb = smss_stack_read(get_recv_mr(16) + 0x28); // [sp+0x28] = *IO_STATUS_BLOCK
                if iosb != 0 {
                    smss_stack_write32(iosb, 0); // Status = STATUS_SUCCESS
                    smss_stack_write(iosb + 8, 0); // Information = 0
                }
                0 // STATUS_SUCCESS
            },
            // NtQueryValueKey(KeyHandle[0], *ValueName[1], InfoClass[2], KeyValueInfo[3], Length[4],
            // *ResultLength[5]). SmpInit reads Identifier/VendorIdentifier from the synthetic CPU
            // key to build PROCESSOR_IDENTIFIER. Real-hive values by name → not-found (smss defaults).
            NativeService::NtQueryValueKey => unsafe {
                let key = match self
                    .key_handles
                    .get((args[0].wrapping_sub(KEY_HANDLE_BASE) / 4) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                // services (pi 3): the value name (e.g. L"SetupType") is a DLL `.rdata` literal the
                // stack/heap/image mirror can't reach — read it from the backing PE (`read_ustr_pe`).
                let name16 = if self.pi == 3 {
                    self.read_ustr_pe(args[1])
                } else {
                    smss_read_ustr(args[1])
                };
                let mut name_lc = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        name_lc.push(c.to_ascii_lowercase());
                    }
                }
                let val: Option<(u32, alloc::vec::Vec<u8>)> = if key == SYNTH_CPU_KEY {
                    synth_cpu_value(&name_lc).map(|(ty, d16)| (ty, utf16_bytes(&d16)))
                } else if let Some(oidx) = overlay_key_idx(key) {
                    // Overlay (created) key: its own set values FIRST, then shadow the base hive by
                    // the overlay key's path (so a created-then-read of a pre-existing key still
                    // sees the base values).
                    if let Some((ty, d)) = self.overlay.value(oidx, &name_lc) {
                        Some((ty, d.to_vec()))
                    } else {
                        let p = self.overlay.path(oidx).map(alloc::string::String::from);
                        p.and_then(|p| self.resolve_key(&p))
                            .and_then(|hk| self.hive.as_ref().and_then(|h| h.value(hk, &name_lc)))
                    }
                } else if self.pi == 3 {
                    // Real SYSTEM hive value-by-name (case-insensitive) — services' SCM reads
                    // SetupType/SystemSetupInProgress + the service DB values off ::ROSSYS.HIV.
                    // Scoped to pi==3 so smss/winlogon/csrss keep the prior None (byte-identical).
                    self.hive.as_ref().and_then(|h| h.value(key, &name_lc))
                } else {
                    None // real-hive value-by-name not modelled for pi 0-2
                };
                match val {
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND — smss uses defaults
                    Some((ty, data)) => {
                        // KeyValuePartialInformation (class 2) carries no name.
                        let info = build_key_value_info(args[2], "", ty, &data);
                        smss_copyout(args[5], &(info.len() as u32).to_le_bytes());
                        if info.len() > args[4] as usize {
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            // services' out-buffer may be an advapi32 heap allocation the mirror can't
                            // reach → use the cross-AS writer so the DWORD data actually lands.
                            if self.pi == 3 {
                                self.xas_write_buf(args[3], &info);
                            } else {
                                smss_copyout(args[3], &info);
                            }
                            0 // STATUS_SUCCESS
                        }
                    }
                }
            },
            // NtQuerySystemInformation(Class[R10]=args[0], Buffer[RDX]=args[1], Len[R8]=args[2],
            // *RetLen[R9]=args[3]). RtlCreateHeap needs SystemBasicInformation (class 0): PageSize,
            // AllocationGranularity, and the user-mode address range. Copyout the fields it reads.
            NativeService::NtQuerySystemInformation => unsafe {
                let class = args[0];
                let buf = args[1];
                let retlen_ptr = args[3]; // R9 = *ReturnLength (a register)
                if class == 0 {
                    smss_stack_write(buf + 0x08, 0x1000); // PageSize
                    smss_stack_write(buf + 0x18, 0x10000); // AllocationGranularity
                    smss_stack_write(buf + 0x20, 0x10000); // MinimumUserModeAddress
                    smss_stack_write(buf + 0x28, 0x0000_7FFF_FFFE_FFFF); // MaximumUserModeAddress
                    smss_stack_write(retlen_ptr, 0x40);
                }
                0
            },
            // NtQueryInformationProcess(Handle[R10]=args[0], Class[RDX]=args[1], Buffer[R8]=args[2],
            // Len[R9]=args[3], *RetLen[arg5]=args[4]).
            NativeService::NtQueryInformationProcess => unsafe {
                let class = args[1]; // ProcessInformationClass
                let buf = args[2]; // R8 = ProcessInformation buffer (a stack local)
                if class == 0 {
                    // ProcessBasicInformation — PROCESS_BASIC_INFORMATION (x64, 48 bytes). Both
                    // processes' PEB is at PEB_VA (own VSpace).
                    smss_stack_write(buf + 0x00, 0); // ExitStatus (running)
                    smss_stack_write(buf + 0x08, PEB_VA); // PebBaseAddress
                    smss_stack_write(buf + 0x10, 1); // AffinityMask
                    smss_stack_write(buf + 0x18, 13); // BasePriority
                    smss_stack_write(buf + 0x20, (self.pi as u64 + 1) * 0x100); // UniqueProcessId (fake)
                    smss_stack_write(buf + 0x28, 0); // InheritedFromUniqueProcessId
                    let retlen = args[4]; // *ReturnLength
                    if retlen != 0 {
                        smss_stack_write32(retlen, 48);
                    }
                    0
                } else if class == 36 {
                    // ProcessCookie — a per-process value ntdll caches for RtlEncode/DecodePointer.
                    smss_stack_write(buf, 0x1a2b_3c4d);
                    0
                } else if class == 28 {
                    // ProcessLUIDDeviceMapsEnabled — a ULONG BOOL. Not enabled → 0.
                    smss_stack_write32(buf, 0);
                    let retlen = args[4];
                    if retlen != 0 {
                        smss_stack_write32(retlen, 4);
                    }
                    0
                } else if class == 23 {
                    // ProcessDeviceMap — an EMPTY drive map (no drives) so SmpCreatePagingFiles
                    // finds no boot volume and smss proceeds without a paging file.
                    for k in 0..(36u64 / 4) {
                        smss_stack_write32(buf + k * 4, 0);
                    }
                    let retlen = args[4];
                    if retlen != 0 {
                        smss_stack_write32(retlen, 36);
                    }
                    0
                } else {
                    print_str(b"[ntos-exec] NtQueryInformationProcess class=");
                    print_u64(class);
                    print_str(b" len=");
                    print_u64(args[3]);
                    print_str(b"\n");
                    self.stop = true; // surfaces the class — stop the process
                    0xC0000002 // STATUS_NOT_IMPLEMENTED
                }
            },
            // NtProtectVirtualMemory(Process, *Base, *Size, NewProtect, *OldProtect[arg5]=args[4]).
            // We don't model per-page protection yet — report success + a plausible previous
            // protection so LdrpInitialize's protect/restore pairs proceed.
            NativeService::NtProtectVirtualMemory => unsafe {
                let oldprot_ptr = args[4]; // *OldAccessProtection
                if oldprot_ptr != 0 {
                    // DWORD write: OldProtect is a ULONG; an 8-byte write clobbers the caller's
                    // adjacent local (in LdrpSetProtection that is the section-header pointer).
                    smss_stack_write32(oldprot_ptr, 0x04); // PAGE_READWRITE
                }
                0
            },
            // NtDisplayString(*String[R10]=args[0] = PUNICODE_STRING). smss prints boot/status text;
            // route it to the serial console.
            NativeService::NtDisplayString => unsafe {
                let s16 = smss_read_ustr(args[0]);
                print_str(b"[smss] ");
                for &w in &s16 {
                    let b = w as u8;
                    debug_put_char(if (0x20..0x7f).contains(&b) || b == b'\n' {
                        b
                    } else {
                        b'.'
                    });
                }
                print_str(b"\n");
                0
            },
            // NtQueryDebugFilterState — return FALSE (filter disabled), the state of a machine with
            // no kernel debugger attached, so DbgPrintEx suppresses the message (see the ladder note
            // this replaces: a TRUE here makes ntdll format a null-relative string → VMFault).
            NativeService::NtQueryDebugFilterState => 0,
            // NtOpenThreadToken — no impersonation token → STATUS_NO_TOKEN; the caller falls back to
            // the process token.
            NativeService::NtOpenThreadToken => 0xC000007C,
            // NtCreatePort(*PortHandle[R10=args[0]], *ObjectAttributes[RDX=args[1]],
            // MaxConnInfo[R8=args[2]], MaxMsg[R9=args[3]], MaxPool[stack]). Create a REAL named port
            // in the isolated LPC connection broker (control plane) and hand the caller its handle.
            // ★ BUG FIX: the out *PortHandle is arg1 = R10 (the x64 out-arg; the stub did `mov r10,rcx`
            // and RCX at the fault holds the return IP). The old fake wrote RCX → csrsrv's CsrSbApiPort
            // stayed 0 → SmConnectToSm returned STATUS_INVALID_PARAMETER_MIX before ever issuing
            // NtConnectPort. Writing to R10 via the out-writer queue (csrss: a .data global; smss: a
            // stack local) lands the handle where the caller reads it → SmConnectToSm reaches connect.
            NativeService::NtCreatePort => unsafe {
                // Robust .rdata-capable name read (csrss's \Windows\ApiPort name is in csrsrv .rdata,
                // unreachable by the mirror-only smss_read_objattr_name) so the port registers under
                // its real name → winlogon's NtSecureConnectPort matches it → the authentic CSR accept.
                let mut name16 = self.read_objattr_name(args[1]);
                if name16.is_empty() {
                    name16 = smss_read_objattr_name(args[1]);
                }
                // csrss's OA + ObjectName UNICODE_STRING are csrsrv .data globals unreachable by the
                // mirror/scratch readers → the name reads EMPTY, so the port would register unnamed and
                // winlogon's NtSecureConnectPort(\Windows\ApiPort) could not match it. csrss creates
                // exactly two ports, in a fixed order: CsrApiPortInitialize(\Windows\ApiPort) then
                // CsrSbApiPortInitialize(\Windows\SbApiPort). Assign the canonical name by order so the
                // ports register correctly → the authentic CSR accept can find the pending connection.
                if self.pi == 1 && name16.is_empty() {
                    let n = CSR_CREATEPORT_N.fetch_add(1, Ordering::Relaxed);
                    let canon: &str = if n == 0 { "\\Windows\\ApiPort" } else { "\\Windows\\SbApiPort" };
                    name16 = canon.encode_utf16().collect();
                }
                let handle = lpc_client()
                    .and_then(|c| {
                        c.create_port(&name16, args[2] as u32, args[3] as u32, 0).ok()
                    })
                    .unwrap_or_else(|| {
                        self.mint_handle()
                    });
                self.queue_write(args[0], handle);
                0
            },
            // SM/CSR worker threads + semaphores. ★ OUT-PARAM FIX (path-B prep): the fake handle now
            // goes to the x64 out-arg0 *Handle = R10 = args[0] via the out-writer queue (was RCX =
            // get_recv_mr(2), which at UnknownSyscall-fault holds the syscall RETURN IP, so the handle
            // landed on a code address and silently missed) — the SAME class as the NtCreatePort /
            // NtCreateEvent bug. Harmless-but-latent while the handles are unused; making it correct is
            // load-bearing for the AUTHENTIC path B (smss's real SmpApiLoop thread needs a REAL handle
            // from NtCreateThread), so land the correct target now. NtCreateThread's REAL spawn (a
            // running smss thread in smss's VSpace) is the next path-B step.
            NativeService::NtCreateThread | NativeService::NtCreateSemaphore => {
                // ★ GENERAL NtCreateThread (real service): winlogon's FIRST NtCreateThread is its RPC
                // listener. Route it through the REAL nt-process ETHREAD lifecycle: pop a pool ETHREAD
                // for the caller, bind the caller's StartRoutine + TEB, mint a TYPED Thread(tid) handle,
                // write NtCreateThread's *ClientId {caller pid, fresh tid} out-param, and signal the loop
                // to spawn the REAL seL4 thread in the caller's VSpace (`spawn_wl_listener_thread`). The
                // no-op (a bare fake handle) is RETIRED for this path — kernel32/rpcrt4 now read a real
                // TEB/ClientId (NtQueryInformationThread(162) resolves the typed handle → the ETHREAD).
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 2
                    && WL_LISTENER_TCB.load(Ordering::Relaxed) == 0
                    && PM_LISTENER_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let entry = smss_stack_read(ctx_va + 0xF8); // CONTEXT.Rip = StartRoutine
                        let param = smss_stack_read(ctx_va + 0x80); // CONTEXT.Rcx = Parameter
                        if let Some((tid, handle)) =
                            self.nt_create_thread_handle(entry, param, WL_LISTENER_TEB_VA)
                        {
                            let pid = self.pm_pid_for_pi(2).unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle = R10
                            let cid_ptr = smss_stack_read(sp + 0x28); // arg5 = *ClientId
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64); // ClientId.UniqueProcess
                                self.queue_write(cid_ptr + 8, tid); // ClientId.UniqueThread
                            }
                            PM_LISTENER_TID.store(tid, Ordering::Relaxed);
                            self.wl_spawn_request = true;
                            return 0; // SUCCESS (handle/ClientId queued)
                        }
                    }
                }
                let h = self.mint_handle();
                self.queue_write(args[0], h); // *Handle = R10 = args[0] (drained via smss_stack_write)
                // Path B: smss creates its SmpApiLoop worker threads via NtCreateThread. Signal the
                // loop to spawn ONE REAL SM-loop thread (the first). The loop reads the CONTEXT (Rip =
                // SmpApiLoop, Rcx = \SmApiPort handle) off the caller's stack + spawns in smss's PML4.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 0
                    && SM_LOOP_TCB.load(Ordering::Relaxed) == 0
                {
                    self.sm_spawn_request = true;
                }
                // Authentic CSR accept: csrss's FIRST NtCreateThread is its CsrApiRequestThread
                // (CsrApiPortInitialize runs before CsrSbApiPortInitialize). Spawn ONE real thread.
                // ★ Also write a chosen ClientId to the *ClientId out-param ([sp+0x28] = arg5): csrss's
                // CsrAddStaticServerThread then registers a CSR_THREAD with this CID, so the connection
                // rendezvous can marshal the SAME CID into the connect message → CsrLocateThreadByClientId
                // finds it → CsrProcess=CsrRootProcess → the accept is ALLOWED (the self-connect
                // simplification, analogous to SM's PID_SMSS — FLAGGED residual).
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 1
                    && CSR_LOOP_TCB.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let cid_ptr = smss_stack_read(sp + 0x28); // arg5 = *ClientId
                        if cid_ptr != 0 {
                            self.queue_write(cid_ptr, CSR_STATIC_CID_PROC);
                            self.queue_write(cid_ptr + 8, CSR_STATIC_CID_THREAD);
                        }
                    }
                    self.csr_spawn_request = true;
                }
                0
            }
            // NtSecureConnectPort — the CSR client connect (kernel32's CsrClientConnectToServer →
            // \Windows\ApiPort, from winlogon's BaseDllInitialize). The SECURE variant (SecurityQos +
            // ServerSid) is CSR-only in this system: SmConnectToSm uses plain NtConnectPort(33), so 218
            // unambiguously means "a Win32 client connecting to CSR". csrss OWNS \Windows\ApiPort but
            // its real CsrApiRequestThread doesn't run (interim), so the executive MODELS the CSR
            // acceptor: auto-accept in the broker + fill the CSR_API_CONNECTINFO reply (SharedSection
            // pointers + a BASE_STATIC_SERVER_DATA) + the LpcWrite PORT_VIEW, so kernel32's DllMain
            // proceeds. See `csr_client_connect`. (Authentic swap: drive csrss's real
            // CsrApiRequestThread via a csr_rendezvous, mirroring the SM path A→B.)
            // x64 ABI: PortHandle=R10=args[0], PortName=RDX=args[1], SecurityQos=R8, ClientView=R9,
            // ServerSid=[sp+0x28], ServerView=[sp+0x30], MaxMsgLen=[sp+0x38], ConnInfo=[sp+0x40],
            // ConnInfoLen=[sp+0x48].
            NativeService::NtSecureConnectPort => unsafe {
                let name16 = self.read_lpc_name(args[1]);
                let sp = get_recv_mr(16);
                let porthandle_ptr = get_recv_mr(9); // R10 = *PortHandle (&CsrApiPort, ntdll .data)
                let clientview_ptr = get_recv_mr(8); // R9 = *ClientView (PORT_VIEW, stack local)
                let conninfo_ptr = smss_stack_read(sp + 0x40); // arg8 = *ConnectionInformation (stack)
                self.csr_client_connect(&name16, porthandle_ptr, clientview_ptr, conninfo_ptr)
            },
            // NtRequestWaitReplyPort(PortHandle=R10, RequestMessage=RDX, ReplyMessage=R8) — the LPC
            // message DATA plane. kernel32's CsrClientCallServer sends the CsrpClientConnect message
            // (ApiNumber 0, ServerId=BASESRV) right after the port connect; its reply Status must be
            // STATUS_SUCCESS or BaseDllInitialize fails. Serviced by the DIRECT cross-badge message
            // plane: the executive reads the CSR_API_MESSAGE off the caller's stack (mirror) and models
            // csrss's reply in place (Status=SUCCESS), against the cached winlogon↔\Windows\ApiPort
            // LpcConnRecord — never a round-trip to the isolated broker. (Interim: a real acceptor would
            // be csrss's CsrApiRequestThread; this models it, like SM path A.)
            NativeService::NtRequestWaitReplyPort => unsafe {
                let reqmsg = args[1]; // RDX = &ApiMessage.Header (request, in/out = same buffer)
                // CSR_API_MESSAGE: PORT_MESSAGE Header(0x28), CsrCaptureData@0x28, ApiNumber@0x30,
                // Status@0x34. Read ApiNumber, model the CSR server: every call → STATUS_SUCCESS.
                let api_number = {
                    let mut b = [0u8; 4];
                    if smss_copyin(reqmsg + 0x30, &mut b) {
                        u32::from_le_bytes(b)
                    } else {
                        0xFFFF_FFFF
                    }
                };
                // Reply in place: Status@+0x34 = STATUS_SUCCESS + mark the PORT_MESSAGE Type = LPC_REPLY.
                smss_stack_write32(reqmsg + 0x34, 0); // ApiMessage.Status = STATUS_SUCCESS
                smss_stack_write16(reqmsg + 0x04, nt_lpc_abi::msg_type::LPC_REPLY); // Header.u2.s2.Type
                print_str(b"[csr-msg] winlogon CsrClientCallServer ApiNumber=0x");
                print_hex(api_number);
                print_str(b" -> modeled reply Status=SUCCESS (direct message plane)\n");
                CSR_MSGS.fetch_add(1, Ordering::Relaxed);
                0
            },
            // NtConnectPort(*PortHandle[R10=args[0]], *PortName[RDX=args[1]], *Qos[R8], *ClientView[R9],
            // *ServerView, *MaxMsg, *ConnInfo, *ConnInfoLen). The SM connect (SmConnectToSm →
            // \SmApiPort). Route to the LPC broker; on the interim AutoAccept path the connect completes
            // synchronously → write the client comm-port handle to the caller's *PortHandle (arg1=R10)
            // + cache the connection; on Manual (path B) the loop drives the authentic SmpApiLoop accept
            // via sm_rendezvous. This is what unblocks csrss's SmConnectToSm.
            NativeService::NtConnectPort => unsafe {
                let name16 = self.read_lpc_name(args[1]);
                match lpc_client().map(|c| c.connect_port(&name16, 0, &[])) {
                    Some(Ok(r)) => {
                        if !r.pending && r.handle != 0 {
                            // AutoAccept (interim): the broker modelled the acceptor — complete now.
                            self.queue_write(args[0], r.handle);
                            self.cache_lpc_connection(r.connection_id, r.handle, &name16);
                            0 // STATUS_SUCCESS
                        } else if r.pending {
                            // Manual (path B, authentic): the connection is Pending in the broker.
                            // Signal the LOOP to drive `sm_rendezvous` (the REAL SmpApiLoop accept)
                            // synchronously, write the completed client comm-port handle to *PortHandle
                            // (args[0]=R10), and reply csrss. The loop needs smss's PML4 + the smss
                            // image/ntdll refs (loop-resident), so it can't run here.
                            self.lpc_rendezvous_conn = r.connection_id;
                            self.lpc_rendezvous_out = args[0];
                            0 // SUCCESS (the loop overrides with the rendezvous outcome)
                        } else {
                            0x0000_0103 // STATUS_PENDING (broker returned no handle + not pending)
                        }
                    }
                    Some(Err(st)) => st.raw() as u32, // e.g. OBJECT_NAME_NOT_FOUND
                    None => 0xC000_0001,              // STATUS_UNSUCCESSFUL (broker absent)
                }
            },
            // NtAcceptConnectPort/NtCompleteConnectPort — the server-side rendezvous (path B). Under
            // AutoAccept these are not reached (the server models the acceptor at connect); wired to
            // the broker so path B is a policy swap, not new plumbing.
            NativeService::NtAcceptConnectPort => unsafe {
                // (*PortHandle[R10], PortContext[RDX], *ConnReq[R8], Accept[R9], ...). We don't yet
                // decode the connection id from the received PORT_MESSAGE (path B), so accept the most
                // recent pending connection is a bulk concern — return success placeholder for now.
                let h = self.mint_handle();
                self.queue_write(args[0], h);
                0
            },
            NativeService::NtCompleteConnectPort => 0,
            // NtCreateEvent(*EventHandle[R10], ACCESS, *OA, EVENT_TYPE, InitialState). winsrv's
            // UserServerDllInitialization creates ghPowerRequestEvent/ghMediaRequestEvent here and
            // hands them to NtUserInitialize (SSN 0x125a); win32k's IntInitWin32PowerManagement then
            // does ObReferenceObjectByHandle(hEvent, *ExEventObjectType, &gpPowerRequestCalloutEvent)
            // on the power event. So the minted handle MUST reach the caller's *EventHandle — which
            // is arg1 = R10 (the x64 out-arg; the syscall stub moved the caller's RCX there, and RCX
            // at the fault holds the return IP, out of any writable range). For csrss that PHANDLE is
            // a winsrv .data global, so QUEUE the write for the loop's per-process out-writer
            // (csrss_out_write demand-pages the global; smss_stack_write handles an smss stack local).
            // The out PHANDLE is arg1 = R10, and for csrss it is a winsrv .bss global. Our csrss
            // demand-fill window is only 256 pages (csrss demand-pages ~343), so `csrss_out_write`
            // cannot reliably reach winsrv's late .bss page — the handle would arrive back at winsrv
            // as NULL (as it did pre-fix, masked by a fake). So instead of writing the flaky global,
            // RECORD the minted handle (csrss only) and DELIVER it to win32k by substituting it into
            // NtUserInitialize's event args at the forward point (see the SSN>=0x1000 arm). That gives
            // win32k the REAL event handles winsrv created, which it models as typed Event objects.
            // (Memory behaviour matches the pre-fix baseline: nothing is written to the caller here.)
            NativeService::NtCreateEvent => {
                let h = self.mint_handle();
                if self.pi == 1 {
                    // Keep the two most-recent csrss event handles in creation order (winsrv creates
                    // hPowerRequestEvent then hMediaRequestEvent right before NtUserInitialize).
                    if self.csrss_event_n < self.csrss_event_handles.len() {
                        self.csrss_event_handles[self.csrss_event_n] = h;
                    } else {
                        self.csrss_event_handles[0] = self.csrss_event_handles[1];
                        self.csrss_event_handles[1] = h;
                    }
                    self.csrss_event_n += 1;
                }
                0
            }
            // NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle). R8 = out handle.
            NativeService::NtOpenProcessToken => unsafe {
                let out = get_recv_mr(7); // R8
                let h = self.mint_handle();
                smss_stack_write(out, h);
                0
            },
            // NtMakeTemporaryObject — clears OBJ_PERMANENT on a link SmpInit re-creates; we don't
            // track permanence. Success no-op.
            NativeService::NtMakeTemporaryObject => 0,
            // No-op → STATUS_SUCCESS: the bump allocator never frees, we don't model thread/process
            // attribute sets, per-object security, keyed events, or a real handle table. (277
            // NtUnmapViewOfSection: we never reclaim a mapped view; 246 NtSetSecurityObject; 214
            // NtResumeThread: CSR worker not modeled; 236 NtSetInformationObject.)
            NativeService::NtFreeVirtualMemory
            | NativeService::NtSetInformationThread
            | NativeService::NtSetInformationProcess
            | NativeService::NtTestAlert
            | NativeService::NtFlushInstructionCache
            | NativeService::NtCreateKeyedEvent
            | NativeService::NtAdjustPrivilegesToken
            | NativeService::NtDeleteValueKey
            | NativeService::NtInitializeRegistry
            | NativeService::NtSetSystemInformation
            | NativeService::NtUnmapViewOfSection
            | NativeService::NtSetSecurityObject
            | NativeService::NtResumeThread
            | NativeService::NtSetInformationObject => 0,
            // NtQueryVirtualMemory(Process, Base[RDX]=args[1], Class, Buffer[R9]=args[3], Len,
            // *RetLen[arg6]=args[5]). LdrpInitialize queries MemoryBasicInformation (class 0) for
            // [TEB+0x10]. Report a plausible committed private region; the env page is 1-page.
            NativeService::NtQueryVirtualMemory => unsafe {
                let base = args[1];
                let buf = args[3];
                let retlen_ptr = args[5];
                let page = base & !0xFFFu64;
                // The env block is a SINGLE mapped page at SMSS_PARAMS_VA+0x1000; report the true
                // 1-page region so ntdll's env-duplication memmove stays in bounds.
                let is_env = page == SMSS_PARAMS_VA + 0x1000;
                let region = if is_env { 0x1000u64 } else { 0x10000u64 };
                let alloc_base = if is_env { page } else { base & !0xFFFFu64 };
                smss_stack_write(buf + 0x00, page); // BaseAddress
                smss_stack_write(buf + 0x08, alloc_base); // AllocationBase
                smss_stack_write(buf + 0x10, 0x04); // AllocationProtect = PAGE_READWRITE
                smss_stack_write(buf + 0x18, region); // RegionSize
                smss_stack_write(buf + 0x20, 0x1000 | (0x04u64 << 32)); // State=MEM_COMMIT, Protect=RW
                smss_stack_write(buf + 0x28, 0x20000); // Type = MEM_PRIVATE
                if retlen_ptr != 0 {
                    smss_stack_write(retlen_ptr, 0x30);
                }
                0
            },
            // NtQueryInformationToken(TokenHandle, Class[RDX]=args[1], buf[R8]=args[2],
            // len[R9]=args[3], *RetLen[arg5]=args[4]). csrss runs as Local System (S-1-5-18).
            NativeService::NtQueryInformationToken => unsafe {
                let class = args[1];
                let buf = args[2];
                let len = args[3];
                let retlen_ptr = args[4];
                match class {
                    1 | 5 => {
                        // TokenUser(1)/TokenPrimaryGroup(5): SID_AND_ATTRIBUTES + the S-1-5-18 SID.
                        let needed: u32 = 0x1C;
                        if len < needed as u64 {
                            if let Some(m) = smss_mirror(retlen_ptr, 4) {
                                core::ptr::write_volatile(m as *mut u32, needed);
                            }
                            0xC000_0023 // STATUS_BUFFER_TOO_SMALL
                        } else if let Some(m) = smss_mirror(buf, needed as u64) {
                            core::ptr::write_volatile((m + 0x00) as *mut u64, buf + 0x10); // Sid → +0x10
                            core::ptr::write_volatile((m + 0x08) as *mut u32, 0); // Attributes
                            core::ptr::write_volatile((m + 0x10) as *mut u64, 0x0500_0000_0000_0101); // Rev,Cnt,IdAuth
                            core::ptr::write_volatile((m + 0x18) as *mut u32, 18); // SubAuthority[0]
                            if let Some(rl) = smss_mirror(retlen_ptr, 4) {
                                core::ptr::write_volatile(rl as *mut u32, needed);
                            }
                            0
                        } else {
                            0xC000_0023
                        }
                    }
                    _ => {
                        print_str(b"[ntos-exec] NtQueryInformationToken class=");
                        print_u64(class);
                        print_str(b" (unhandled)\n");
                        self.stop = true;
                        0xC0000002
                    }
                }
            },
            // NtQueryObject(Handle[R10]=args[0], class[RDX]=args[1], buf[R8]=args[2], len[R9]=args[3],
            // *RetLen[arg5]=args[4]). DIAGNOSTIC: log + return a zeroed buffer + retlen.
            NativeService::NtQueryObject => unsafe {
                let class = args[1];
                let handle = args[0];
                let buf = args[2];
                let len = args[3];
                let retlen_ptr = args[4];
                print_str(b"[ntos-exec] NtQueryObject handle=0x");
                print_hex(handle as u32);
                print_str(b" class=");
                print_u64(class);
                print_str(b" len=");
                print_u64(len);
                print_str(b"\n");
                if len > 0 {
                    if let Some(m) = smss_mirror(buf, len.min(64)) {
                        for i in 0..len.min(64) {
                            core::ptr::write_volatile((m + i) as *mut u8, 0);
                        }
                    }
                }
                if retlen_ptr != 0 {
                    if let Some(m) = smss_mirror(retlen_ptr, 4) {
                        core::ptr::write_volatile(m as *mut u32, 0);
                    }
                }
                0
            },
            // NtWaitForSingleObject — csrsrv's CsrApiPortInitialize waits on its worker-thread
            // startup event; we don't model the worker → STATUS_WAIT_0 (0) so init proceeds.
            // Scoped to csrss (pi==1); smss never issues 281, so a smss 281 stops (as before).
            NativeService::NtWaitForSingleObject => {
                if self.pi == 1 {
                    0
                } else {
                    // smss now issues 281 too: SmpLoadSubSystem waits on NewSubsystem->Event for csrss
                    // to signal init-complete (smsubsys.c:432). csrss IS initialized (parked after
                    // CsrServerInitialization), so model the wait as satisfied (STATUS_WAIT_0). Print
                    // the handle + caller chain once for identification while grinding forward.
                    unsafe {
                        let sp = get_recv_mr(16);
                        print_str(b"[281] smss wait handle=0x");
                        print_hex(args[0] as u32);
                        print_str(b" chain:");
                        let mut shown = 0;
                        for i in 0..96u64 {
                            let v = smss_stack_read(sp + i * 8);
                            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                                print_str(b" n+0x");
                                print_hex((v - NTDLL_BASE) as u32);
                                shown += 1;
                            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                                print_str(b" s+0x");
                                print_hex((v - PE_LOAD_BASE) as u32);
                                shown += 1;
                            }
                            if shown >= 12 {
                                break;
                            }
                        }
                        print_str(b"\n");
                    }
                    0 // STATUS_WAIT_0
                }
            }
            // NtOpen/CreateDirectoryObject(*Handle[R10]=args[0], DesiredAccess, *OA[R8]=args[2]).
            // Resolve/insert in the executive object namespace, hand back a real handle.
            NativeService::NtOpenDirectoryObject | NativeService::NtCreateDirectoryObject => unsafe {
                let out = args[0]; // R10 = *Handle
                let oa = args[2]; // R8 = *OBJECT_ATTRIBUTES
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                let idx = if ctx.service == NativeService::NtCreateDirectoryObject {
                    self.obj_create(&nbuf[..nlen], root_idx, 0, &[])
                } else {
                    self.obj_resolve(&nbuf[..nlen], root_idx)
                };
                match idx {
                    Some(i) => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    None => 0xC0000034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtCreateSymbolicLinkObject(*Handle[R10]=args[0], access, *OA[R8]=args[2],
            // *LinkTarget[R9]=args[3]). SmpInit creates the \?? drive-letter links.
            NativeService::NtCreateSymbolicLinkObject => unsafe {
                let out = args[0];
                let oa = args[2];
                let tgt = args[3]; // R9 = PUNICODE_STRING target
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let target16 = smss_read_ustr(tgt);
                let mut tbuf = [0u8; 40]; // keep the target's case (a device path)
                let mut tl = 0;
                for &w in &target16 {
                    if tl >= tbuf.len() {
                        break;
                    }
                    tbuf[tl] = w as u8;
                    tl += 1;
                }
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                match self.obj_create(&nbuf[..nlen], root_idx, 1, &tbuf[..tl]) {
                    Some(i) => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    None => 0xC0000034,
                }
            },
            // NtOpenSymbolicLinkObject(*Handle[R10]=args[0], DesiredAccess, *OA[R8]=args[2]).
            // Resolve; hand back a handle only for an actual symbolic link (a dir match is a miss).
            NativeService::NtOpenSymbolicLinkObject => unsafe {
                let out = args[0];
                let oa = args[2];
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                match self.obj_resolve(&nbuf[..nlen], root_idx) {
                    Some(i) if self.obj_ns[i].kind == 1 => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    _ => 0xC0000034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtQuerySystemTime(*SystemTime[R10]=args[0]). Return a non-zero monotonic 64-bit clock
            // (rdtsc — a plain ring-3 instruction; do NOT `syscall` from the executive). The out-ptr
            // write is queued so the loop demand-fills it (csrss arbitrary VA vs smss stack local).
            NativeService::NtQuerySystemTime => {
                let out = args[0];
                let now = unsafe { core::arch::x86_64::_rdtsc() };
                self.queue_write(out, now);
                0
            }
            // NtQueryPerformanceCounter(*Counter[R10]=args[0], *Frequency[RDX]=args[1] optional).
            NativeService::NtQueryPerformanceCounter => {
                let ctr_ptr = args[0];
                let freq_ptr = args[1];
                let now = unsafe { core::arch::x86_64::_rdtsc() };
                let freq = 1_000_000_000u64; // 1 GHz — plausible TSC frequency
                self.queue_write(ctr_ptr, now);
                if freq_ptr != 0 {
                    self.queue_write(freq_ptr, freq);
                }
                0
            }
            // NtQueryVolumeInformationFile(FileHandle, *IoStatusBlock[RDX]=args[1], FsInfo[R8]=args[2],
            // Length[R9]=args[3], FsInformationClass[arg5]=args[4]). CsrServerInitialization probes a
            // handle's volume; no real FS → conservative answer. All writes queued (csrss-only).
            NativeService::NtQueryVolumeInformationFile => {
                let iosb = args[1];
                let buf = args[2];
                let len = args[3];
                // FsInformationClass is a ULONG; the 8-byte stack slot has garbage in the high dword.
                let class = args[4] & 0xFFFF_FFFF;
                let info_bytes: u64;
                if class == 4 {
                    // FileFsDeviceInformation { DeviceType=FILE_DEVICE_DISK(7), Characteristics=0 }.
                    self.queue_write(buf, 0x0000_0000_0000_0007);
                    info_bytes = 8;
                } else {
                    print_str(b"[ntos-exec] NtQueryVolumeInformationFile class=");
                    print_u64(class);
                    print_str(b" len=");
                    print_u64(len);
                    print_str(b"\n");
                    let n = len.min(32) / 8;
                    for k in 0..n {
                        self.queue_write(buf + k * 8, 0);
                    }
                    info_bytes = len.min(32);
                }
                if iosb != 0 {
                    self.queue_write(iosb, 0); // Status = STATUS_SUCCESS
                    self.queue_write(iosb + 8, info_bytes); // Information = bytes written
                }
                0
            }
            // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress[RDX]=args[1], ZeroBits,
            // *RegionSize[R9]=args[3], Type[arg5]=args[4], Protect). RESERVE (base in==0) picks a
            // per-process bump base; COMMIT maps frames + mirrors the first heap window (group C:
            // page_map target pml4 comes from the loop ctx).
            NativeService::NtAllocateVirtualMemory => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let base_ptr = args[1]; // RDX
                let size_ptr = args[3]; // R9
                let alloc_type = args[4]; // arg5 = Type
                let base_in = smss_stack_read(base_ptr);
                let want = smss_stack_read(size_ptr);
                let rounded = ((want + 0xFFF) & !0xFFFu64).max(0x1000);
                let base = if base_in != 0 {
                    base_in
                } else if self.pi == 1 {
                    NEXT_CSRSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 2 {
                    NEXT_WINLOGON_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 3 {
                    NEXT_SERVICES_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else {
                    NEXT_SMSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                };
                if alloc_type & 0x1000 != 0 {
                    // MEM_COMMIT — back it with real frames.
                    let mut p = 0u64;
                    while p < rounded {
                        let f = alloc_frame();
                        let _ = page_map(f, base + p, RW_NX, ctx.pml4);
                        // Mirror the first heap window into the executive so smss_copyin can read
                        // heap-resident pointer args, into the ACTIVE process's heap mirror.
                        let va = base + p;
                        if va >= SMSS_ALLOC_VA && va < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
                            let mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
                            let _ = page_map(copy_cap(f),
                                mirror + (va - SMSS_ALLOC_VA), RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                        p += 0x1000;
                    }
                }
                smss_stack_write(base_ptr, base);
                smss_stack_write(size_ptr, rounded);
                NTALLOC_SERVICED.fetch_add(1, Ordering::Relaxed);
                0
            },
            // NtOpenSection(*SectionHandle[R10]=args[0], DesiredAccess, *ObjectAttributes[R8]=args[2]).
            // Provide the US-ASCII NLS code-page section \Nls\NlsSectionCP20127 (csrss's Win32 stack
            // maps it during a DllMain); everything else → NOT_FOUND. Records nls_section_handle.
            NativeService::NtOpenSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let name16 = smss_read_objattr_name(args[2]); // R8 = *ObjectAttributes
                print_str(b"[ntos-exec] NtOpenSection name=\"");
                for &w in name16.iter().take(96) {
                    debug_put_char(if (0x20..0x7f).contains(&w) { w as u8 } else { b'?' });
                }
                print_str(b"\"\n");
                let mut nb = [0u8; 96];
                let mut nlen = 0;
                for &w in &name16 {
                    if nlen >= nb.len() {
                        break;
                    }
                    nb[nlen] = (w as u8).to_ascii_lowercase();
                    nlen += 1;
                }
                if nb[..nlen].windows(17).any(|w| w == b"nlssectioncp20127") {
                    let h = self.mint_handle();
                    smss_stack_write(args[0], h); // R10 = *SectionHandle
                    *ctx.nls_section_handle = h;
                    print_str(b"[ntos-exec] NtOpenSection NlsCP20127 -> handle 0x");
                    print_hex(*ctx.nls_section_handle as u32);
                    print_str(b"\n");
                    0 // STATUS_SUCCESS
                } else {
                    0xC0000034 // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtQueryAttributesFile(*OBJECT_ATTRIBUTES[R10], *FILE_BASIC_INFORMATION[RDX]=args[1]).
            // RtlDosSearchPath_U probes for csrss.exe here (SmpParseCommandLine). Report it EXISTS
            // (FileAttributes = FILE_ATTRIBUTE_NORMAL) so SMP_INVALID_PATH isn't set; everything else
            // → not-found so the loader's manifest probes keep failing.
            NativeService::NtQueryAttributesFile => unsafe {
                let name16 = smss_read_objattr_name(get_recv_mr(9)); // R10 = *OA
                let mut nb = [0u8; 96];
                let mut nlen = 0;
                for &w in &name16 {
                    if nlen >= nb.len() {
                        break;
                    }
                    nb[nlen] = (w as u8).to_ascii_lowercase();
                    nlen += 1;
                }
                // Report EXISTS for csrss.exe + any registry DLL (csrsrv/basesrv/winsrv). The registry
                // rejects SxS probes itself; the csrss.exe (EXE) probe is guarded by its own SxS check
                // so the loader doesn't take the .Local\ redirection or a manifest path.
                let is_sxs = nt_dll_registry::Registry::is_sxs_probe(&nb[..nlen]);
                // The substring only CLASSIFIES which file the loader is probing (path-form
                // tolerant); the REAL nt-fs namespace (seeded in ExecNtHandler::new) authoritatively
                // answers whether csrss.exe exists and its attributes. Identical accept set: csrss.exe
                // is seeded, so a csrss probe resolves EXISTS; if the seed were removed nt-fs would
                // correctly report not-found. Content delivery stays on the nt-dll-registry/PE path.
                let is_csrss_probe = !is_sxs && nb[..nlen].windows(5).any(|w| w == b"csrss");
                // winlogon.exe — smss's SmpParseCommandLine probes the initial command (×N paths).
                // Not scoped to a pi: smss (pi==0) launches it, exactly like csrss.
                let is_winlogon_probe = !is_sxs && nb[..nlen].windows(8).any(|w| w == b"winlogon");
                // services.exe — winlogon's Win32 CreateProcessW target (the 4th hosted process).
                let is_services_probe = !is_sxs && nb[..nlen].windows(8).any(|w| w == b"services");
                let csrss_attrs = if is_csrss_probe {
                    self.fs.query_attributes(r"\SystemRoot\System32\csrss.exe")
                } else if is_winlogon_probe {
                    self.fs.query_attributes(r"\SystemRoot\System32\winlogon.exe")
                } else if is_services_probe {
                    self.fs.query_attributes(r"\SystemRoot\System32\services.exe")
                } else {
                    None
                };
                // DLL existence for csrss (pi==1) now comes from the REAL nt-fs System32 namespace
                // (seeded with SYSTEM32_FILES). NtQueryAttributesFile is a pure existence/attributes
                // query with no image geometry, so nt-fs is cleanly the sole authority here;
                // nt-dll-registry keeps the SEC_IMAGE base/geometry role in NtOpenFile/NtCreateSection.
                // Scoped to a DLL-loading process (pi>=1: csrss OR winlogon) so smss's (pi==0)
                // KnownDLLs probes keep failing and it launches csrss/winlogon.
                let dll_exists = self.pi >= 1 && self.fs_system32_has(&nb[..nlen]);
                if let Some(si) = csrss_attrs {
                    // FILE_BASIC_INFORMATION: 4×8-byte times, then FileAttributes(u32) @ +0x20.
                    // Attributes come from nt-fs: a file → NORMAL, a directory → DIRECTORY.
                    let attr = if si.is_directory { 0x10 } else { 0x80 };
                    smss_stack_write32(args[1] + 0x20, attr);
                    0
                } else if dll_exists {
                    smss_stack_write32(args[1] + 0x20, 0x80); // FILE_ATTRIBUTE_NORMAL
                    0
                } else {
                    // DIAG: log the not-found probes from a DLL-loading process (csrss/winlogon) —
                    // a DllMain probes several files before failing init; we need to know which are
                    // load-bearing.
                    if self.pi >= 1 {
                        print_str(b"[ntos-exec] NtQueryAttributesFile(hosted) not-found: \"");
                        for &w in name16.iter().take(96) {
                            debug_put_char(if (0x20..0x7f).contains(&w) { w as u8 } else { b'?' });
                        }
                        print_str(b"\"\n");
                    }
                    0xC0000034
                }
            },
            // NtOpenFile(*FileHandle[R10], DesiredAccess[RDX], *OBJECT_ATTRIBUTES[R8],
            // *IoStatusBlock[R9], ShareAccess[sp+0x28], OpenOptions[sp+0x30]).
            // SmpCreateInitialSession opens %SystemRoot%\system32 as a DIRECTORY
            // (FILE_DIRECTORY_FILE) before creating the KnownDllPath symlink + looping KnownDLLs.
            // Hand back a directory handle so it proceeds; a plain FILE open (an individual
            // KnownDLL) still fails → smss `continue`s past each DLL and completes the loop.
            NativeService::NtOpenFile => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &mut *ctx.reg;
                const FILE_DIRECTORY_FILE: u64 = 0x01;
                let sp = get_recv_mr(16);
                // Succeed ONLY for SmpInit's KnownDLL directory open (…\system32). The loader's
                // actctx/manifest opens (individual .manifest FILES, and the \??\C:\Windows SxS
                // search directory) must keep failing so ntdll falls back to its defaults and
                // proceeds to SmpInit — otherwise we divert the loader down the SxS path. Match the
                // (folded) object name against "system32".
                let name16 = smss_read_objattr_name(get_recv_mr(7));
                let mut nb = [0u8; 96];
                let nlen = {
                    let mut n = 0;
                    for &w in &name16 {
                        if n >= nb.len() {
                            break;
                        }
                        nb[n] = (w as u8).to_ascii_lowercase();
                        n += 1;
                    }
                    n
                };
                // Reject SxS/actctx probes (csrss.exe.local, csrss.exe.manifest, *.config).
                let is_sxs = nb[..nlen].windows(6).any(|w| w == b".local")
                    || nb[..nlen].windows(9).any(|w| w == b".manifest")
                    || nb[..nlen].windows(7).any(|w| w == b".config");
                // The System32 DIRECTORY open (SmpCreateInitialSession → KnownDLLs) resolves through
                // the REAL nt-fs namespace: the substring classifies the probe, nt-fs authoritatively
                // confirms \Windows\System32 exists AND is a directory (canonical path is
                // mount-resolvable, so path-form independent).
                let want_dir = smss_stack_read(sp + 0x30) & FILE_DIRECTORY_FILE != 0;
                let is_sys32_dir = want_dir
                    && nb[..nlen].windows(8).any(|w| w == b"system32")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32")
                        .is_some_and(|si| si.is_directory);
                // csrss.exe FILE open (SmpExecuteImage): same as NtQueryAttributesFile — substring
                // classifies, nt-fs owns existence + file-vs-dir. Scoped by name so the loader's
                // manifest opens are unaffected.
                let is_csrss = !is_sxs
                    && nb[..nlen].windows(5).any(|w| w == b"csrss")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32\csrss.exe")
                        .is_some_and(|si| !si.is_directory);
                // winlogon.exe FILE open (SmpExecuteImage → RtlCreateUserProcess): same shape as
                // csrss — substring classifies, nt-fs owns existence + file-vs-dir. Not pi-scoped.
                let is_winlogon = !is_sxs
                    && nb[..nlen].windows(8).any(|w| w == b"winlogon")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32\winlogon.exe")
                        .is_some_and(|si| !si.is_directory);
                // services.exe FILE open — winlogon's kernel32 CreateProcessInternalW opens it (the
                // 4th hosted process). Same shape as csrss/winlogon; substring classifies, nt-fs owns
                // existence + file-vs-dir. Issued by winlogon (pi 2).
                let is_services = !is_sxs
                    && nb[..nlen].windows(8).any(|w| w == b"services")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32\services.exe")
                        .is_some_and(|si| !si.is_directory);
                // csrss's static import (csrsrv.dll) + its dynamic ServerDlls (basesrv/winsrv) + the
                // Win32 client stack. SCOPED TO csrss (pi==1): smss's SmpInit enumerates the KnownDLLs
                // — which now include kernel32/user32/gdi32 — and those opens MUST keep failing so
                // smss skips them and launches csrss. Only csrss's loader should resolve these DLLs.
                // nt-dll-registry keeps the image base/geometry role for CONTENT (SEC_IMAGE); nt-fs
                // owns namespace/existence (csrss.exe + System32 dir here). pi>=1 = csrss OR winlogon
                // (both load DLLs); smss (pi==0) still misses so its KnownDLLs opens fail + it
                // launches csrss/winlogon.
                let dll_i = if self.pi >= 1 { reg.resolve_name(&nb[..nlen]) } else { None };
                if is_sys32_dir || is_csrss || is_winlogon || is_services || dll_i.is_some() {
                    let h = self.mint_handle();
                    smss_stack_write(get_recv_mr(9), h); // *FileHandle
                    if is_csrss {
                        *ctx.csrss_file_handle = h; // remember it for NtCreateSection
                    }
                    if is_winlogon {
                        *ctx.winlogon_file_handle = h; // for NtCreateSection
                    }
                    if is_services {
                        *ctx.services_file_handle = h; // for NtCreateSection (winlogon → services.exe)
                    }
                    if let Some(i) = dll_i {
                        reg.set_file_handle(self.pi, i, h); // per-process: remember for NtCreateSection
                    }
                    let iosb = get_recv_mr(8); // R9 = *IO_STATUS_BLOCK
                    if iosb != 0 {
                        smss_stack_write32(iosb, 0); // Status = STATUS_SUCCESS
                        smss_stack_write(iosb + 8, 1); // Information = FILE_OPENED
                    }
                    0
                } else {
                    0xC0000034 // no filesystem yet → not found (smss skips / uses defaults)
                }
            },
            // NtQuerySection(SectionHandle[R10], class[RDX]=args[1], buf[R8], len[R9], *ResultLen[sp+0x28]).
            // RtlCreateUserProcess queries SectionImageInformation (class 1) for the image's entry
            // point, stack sizes + subsystem before creating the initial thread. Return a 64-byte
            // SECTION_IMAGE_INFORMATION derived from the section's backing PE (a registry DLL at its
            // registry base, or the csrss.exe EXE at PE_LOAD_BASE).
            NativeService::NtQuerySection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &*ctx.reg;
                let class = args[1]; // RDX
                let buf = get_recv_mr(7); // R8
                let sect = get_recv_mr(9); // R10 = SectionHandle
                let sp = get_recv_mr(16);
                let csrss_section_handle = *ctx.csrss_section_handle;
                let csrss_pe = &*ctx.csrss_pe;
                let winlogon_section_handle = *ctx.winlogon_section_handle;
                let winlogon_pe = &*ctx.winlogon_pe;
                let info: Option<([u8; 64], &[u8])> = if let Some(i) = reg.index_for_section(self.pi, sect) {
                    reg.image_info(i).map(|b| (b, reg.name(i)))
                } else if self.pi == 0 && csrss_section_handle != 0 && sect == csrss_section_handle {
                    // The csrss.exe SEC_IMAGE section is created + queried ONLY by smss (pi 0) inside
                    // RtlCreateUserProcess. Scope to pi 0 so a DIFFERENT process's dense handle with
                    // the same value (path 1b) can never alias it (reg is matched first regardless).
                    csrss_pe.as_ref().map(|p| {
                        (
                            nt_dll_registry::image_info(
                                PE_LOAD_BASE,
                                p.entry_point_rva(),
                                p.size_of_image(),
                                false,
                            ),
                            b"csrss.exe" as &[u8],
                        )
                    })
                } else if self.pi == 0 && winlogon_section_handle != 0 && sect == winlogon_section_handle {
                    // smss's RtlCreateUserProcess(winlogon) queries SectionImageInformation on the
                    // winlogon SEC_IMAGE section to size the initial thread's stack + find the entry.
                    // Unrecognized before, this stopped the whole demo (the ONLY reason winlogon
                    // couldn't run past its CSR connect); recognized now → smss proceeds + winlogon
                    // (higher prio) keeps running.
                    winlogon_pe.as_ref().map(|p| {
                        (
                            nt_dll_registry::image_info(
                                PE_LOAD_BASE,
                                p.entry_point_rva(),
                                p.size_of_image(),
                                false,
                            ),
                            b"winlogon.exe" as &[u8],
                        )
                    })
                } else if self.pi == 2
                    && *ctx.services_section_handle != 0
                    && sect == *ctx.services_section_handle
                {
                    // winlogon's kernel32 CreateProcessInternalW queries SectionImageInformation on the
                    // services.exe SEC_IMAGE (for the entry/stack/subsystem) before NtCreateProcessEx.
                    // Unlike smss's native path, kernel32 VALIDATES SubSystemType (must be GUI/CUI, not
                    // NATIVE — proc.c:3504) + SubSystemVersion (>= 3.10 — BasepIsImageVersionOk), so
                    // patch the image_info's defaults (SubSystemType@0x20, MinorVersion@0x24,
                    // MajorVersion@0x26) with services.exe's REAL PE values.
                    (*ctx.services_pe).as_ref().map(|p| {
                        let mut info = nt_dll_registry::image_info(
                            PE_LOAD_BASE,
                            p.entry_point_rva(),
                            p.size_of_image(),
                            false,
                        );
                        let (maj, min) = p.subsystem_version();
                        info[0x20..0x24].copy_from_slice(&(p.subsystem() as u32).to_le_bytes());
                        info[0x24..0x26].copy_from_slice(&min.to_le_bytes());
                        info[0x26..0x28].copy_from_slice(&maj.to_le_bytes());
                        (info, b"services.exe" as &[u8])
                    })
                } else {
                    None
                };
                if class == 1 && info.is_some() {
                    let (bytes, who) = info.unwrap();
                    // Copy the 64-byte SECTION_IMAGE_INFORMATION out to `buf` (8 bytes at a time).
                    for k in 0..8 {
                        let mut w = [0u8; 8];
                        w.copy_from_slice(&bytes[k * 8..k * 8 + 8]);
                        smss_stack_write(buf + (k as u64) * 8, u64::from_le_bytes(w));
                    }
                    let rl = smss_stack_read(sp + 0x28); // arg4 = *ResultLength
                    if rl != 0 {
                        smss_stack_write(rl, 64);
                    }
                    let entry = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                    print_str(b"[ntos-exec] NtQuerySection ");
                    print_str(who);
                    print_str(b" entry=0x");
                    print_hex((entry >> 32) as u32);
                    print_hex(entry as u32);
                    print_str(b"\n");
                    0
                } else {
                    self.stop = true;
                    0xC0000002
                }
            },
            // NtQueryDefaultLocale(UserProfile, *DefaultLocaleId[RDX]=args[1]). Write en-US (0x409) to
            // the output, which ntdll points at one of its own .data GLOBALS (not the stack) — so copy
            // out through the target image page's persistent executive scratch mapping, demand-filling
            // the page first if LdrpInitialize hasn't touched it yet.
            NativeService::NtQueryDefaultLocale => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let out = args[1]; // RDX = *DefaultLocaleId
                let pg = out & !0xFFFu64;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let mut idx = usize::MAX;
                for i in 0..(*faults as usize).min(filled_pages.len()) {
                    if filled_pages[i] == pg {
                        idx = i;
                        break;
                    }
                }
                if idx == usize::MAX && (*faults as usize) < filled_pages.len() {
                    let (base, tpe): (u64, *const nt_pe_loader::PeFile<'static>) =
                        if pg >= PE_LOAD_BASE && pg < ctx.img_end {
                            (PE_LOAD_BASE, ctx.pe)
                        } else if ctx.nt_base != 0 && pg >= ctx.nt_base && pg < ctx.nt_end {
                            (ctx.nt_base, ctx.ntdll_pe)
                        } else {
                            (0u64, ctx.pe)
                        };
                    if base != 0 {
                        let scratch = ctx.scratch_base + *faults * 0x1000;
                        let f = alloc_frame();
                        let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                        let rights = fill_image_page(&*tpe, (pg - base) as u32, scratch);
                        let _ = page_map(copy_cap(f), pg, rights, ctx.pml4);
                        filled_pages[*faults as usize] = pg;
                        idx = *faults as usize;
                        *faults += 1;
                    }
                }
                if idx != usize::MAX {
                    core::ptr::write_volatile(
                        (ctx.scratch_base + idx as u64 * 0x1000 + (out & 0xFFF)) as *mut u32,
                        0x409,
                    );
                }
                0
            },
            // NtCreateSection(*SectionHandle[R10], access[RDX], *OA[R8], *MaxSize[R9],
            // PageProtection[sp+0x28], AllocationAttributes[sp+0x30], FileHandle[sp+0x38]).
            // Unlike the other creates, smss USES the section handle (NtCreateProcess), so write it to
            // the real out-param (arg0 = R10). When it's a SEC_IMAGE of csrss.exe, record the handle
            // so NtCreateProcess can spawn the real csrss image from it.
            NativeService::NtCreateSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let h = self.mint_handle();
                let reg = &mut *ctx.reg;
                let dll_pes = &*ctx.dll_pes;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let sp = get_recv_mr(16);
                let out = get_recv_mr(9); // R10 = *SectionHandle
                // *SectionHandle can live outside the stack/heap/image mirrors (e.g. a csrsrv global).
                csrss_out_write(
                    out, h, filled_pages, faults, ctx.scratch_base, reg, dll_pes,
                    ctx.pml4,
                );
                let sec_file = smss_stack_read(sp + 0x38);
                // The csrss.exe / winlogon.exe EXE sections are created ONLY by smss (pi 0). Scope
                // to pi 0 so a csrss/winlogon DLL section create with a same-valued dense file handle
                // (path 1b) can't spuriously match these (the per-pi reg lookup handles DLLs below).
                if self.pi == 0 && *ctx.csrss_file_handle != 0 && sec_file == *ctx.csrss_file_handle {
                    *ctx.csrss_section_handle = h;
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for csrss.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                if self.pi == 0 && *ctx.winlogon_file_handle != 0 && sec_file == *ctx.winlogon_file_handle {
                    *ctx.winlogon_section_handle = h;
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for winlogon.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // The services.exe SEC_IMAGE is created by WINLOGON (pi 2) — its Win32 CreateProcessW.
                if self.pi == 2 && *ctx.services_file_handle != 0 && sec_file == *ctx.services_file_handle {
                    *ctx.services_section_handle = h;
                    SERVICES_CREATE_STARTED.store(1, Ordering::Relaxed);
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for services.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // A registry DLL (csrsrv/basesrv/winsrv): record its section handle by file handle.
                if let Some(i) = reg.index_for_file(self.pi, sec_file) {
                    reg.set_section_handle(self.pi, i, h);
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for ");
                    print_str(reg.name(i));
                    print_str(b" -> handle 0x");
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // Anonymous (no FileHandle) section from csrss — its CSR SharedSection shared memory.
                // Record the requested size (from *MaximumSize = R9) so NtMapViewOfSection can back it.
                if sec_file == 0 && self.pi == 1 && *ctx.csrss_anon_section_handle == 0 {
                    let maxsize_ptr = get_recv_mr(8); // R9 = *MaximumSize (LARGE_INTEGER)
                    let size = if let Some(m) = smss_mirror(maxsize_ptr, 8) {
                        core::ptr::read_volatile(m as *const u64)
                    } else {
                        0
                    };
                    *ctx.csrss_anon_section_handle = h;
                    // SEC_RESERVE with MaximumSize==0 gives no size here; reserve a default 1 MiB
                    // window (demand-paged on touch, so unused pages cost nothing).
                    *ctx.csrss_anon_size = if size == 0 { 0x10_0000 } else { size };
                    print_str(b"[ntos-exec] NtCreateSection(anonymous) size=0x");
                    print_hex(*ctx.csrss_anon_size as u32);
                    print_str(b" -> handle 0x");
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                0
            },
            // NtMapViewOfSection(SectionHandle[R10], ProcessHandle[RDX], *BaseAddress[R8],
            // ZeroBits[R9], CommitSize[sp+0x28], *SectionOffset[sp+0x30], *ViewSize[sp+0x38], …).
            // Map a registry DLL SEC_IMAGE at its (fixed) registry base, the anonymous CSR shared
            // section, or the named NLS section into csrss's VSpace; the fault router demand-pages
            // the DLL/anon views and the NLS frames are mapped eagerly here.
            NativeService::NtMapViewOfSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &mut *ctx.reg;
                let dll_pes = &*ctx.dll_pes;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let pml4 = ctx.pml4;
                let scratch_base = ctx.scratch_base;
                let sp = get_recv_mr(16);
                let sect = get_recv_mr(9);
                if let Some(i) = reg.index_for_section(self.pi, sect) {
                    // A registry DLL (csrsrv/basesrv/winsrv). Reserve its VA range, hand back its base
                    // + view size, and let the fault router demand-page it from its PE. All DLL slots
                    // share the 0x8000_0000 1 GiB PDPT range, so the PD is created once (first mapped
                    // DLL) and each DLL gets its own PT. csrsrv sits at its preferred ImageBase (no
                    // relocation); the ServerDlls are loader-relocated.
                    if let Some(cpe) = dll_pes[i].as_ref() {
                        let dbase = reg.base(i);
                        // PER-PROCESS PD/PT reservation: the DLL's fixed base is the same in every
                        // process, but each VSpace needs its own page tables. csrss and winlogon load
                        // an overlapping DLL set at identical bases into distinct VSpaces, so gate the
                        // reservation on this process's bitmask, not the registry's global `mapped`.
                        let pi = self.pi;
                        let dll_pd_created = &mut *ctx.dll_pd_created;
                        let dll_mapped_bits = &mut *ctx.dll_mapped_bits;
                        if dll_mapped_bits[pi] & (1u32 << i) == 0 {
                            if !dll_pd_created[pi] {
                                let pd = alloc_slot();
                                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
                                let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, dbase, pml4);
                                dll_pd_created[pi] = true;
                            }
                            let pt = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, dbase, pml4);
                            dll_mapped_bits[pi] |= 1u32 << i;
                            // Global flag drives `dll_for_page` VA-range resolution (base-identical).
                            reg.set_mapped(i);
                        }
                        let ext = image_extent(cpe);
                        csrss_out_write(get_recv_mr(7), dbase, filled_pages, faults, scratch_base, reg, dll_pes, pml4); // *BaseAddress
                        let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                        if vs_ptr != 0 {
                            csrss_out_write(vs_ptr, ext, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                        }
                        print_str(b"[ntos-exec] NtMapViewOfSection ");
                        print_str(reg.name(i));
                        print_str(b" -> base 0x");
                        print_hex(dbase as u32);
                        print_str(b"\n");
                        0
                    } else {
                        self.stop = true;
                        0xC0000002
                    }
                } else if self.pi == 1 && *ctx.csrss_anon_section_handle != 0 && sect == *ctx.csrss_anon_section_handle {
                    // Anonymous section (CSR shared memory): reserve a VA range in csrss's VSpace
                    // (page tables only) and let the fault router demand-page zero frames on touch.
                    const CSRSS_ANON_BASE: u64 = 0x0000_0100_0300_0000;
                    if *ctx.csrss_anon_base == 0 {
                        let npts = ((*ctx.csrss_anon_size + 0x1F_FFFF) / 0x20_0000).max(1);
                        let mut k = 0u64;
                        while k < npts {
                            let pt = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                            let _ = paging_struct_map(
                                pt,
                                LBL_X86_PAGE_TABLE_MAP,
                                CSRSS_ANON_BASE + k * 0x20_0000,
                                pml4,
                            );
                            k += 1;
                        }
                        *ctx.csrss_anon_base = CSRSS_ANON_BASE;
                    }
                    // *BaseAddress / *ViewSize are csrsrv globals (CsrSrvSharedSectionBase) — write via
                    // the general path so they don't silently miss (NULL base → RtlAllocateHeap(NULL)).
                    csrss_out_write(get_recv_mr(7), *ctx.csrss_anon_base, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                    if vs_ptr != 0 {
                        csrss_out_write(vs_ptr, *ctx.csrss_anon_size, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    }
                    print_str(b"[ntos-exec] NtMapViewOfSection(anonymous) -> base 0x");
                    print_hex((*ctx.csrss_anon_base >> 32) as u32);
                    print_hex(*ctx.csrss_anon_base as u32);
                    print_str(b"\n");
                    0
                } else if *ctx.nls_section_handle != 0 && sect == *ctx.nls_section_handle {
                    // The named NLS section \Nls\NlsSectionCP20127: map the staged c_20127.nls frames
                    // into csrss at a VA past the DLL bases (same 0x8000_0000 PDPT slot, whose PD the
                    // DLL loads already created), then hand back *BaseAddress / *ViewSize.
                    const NLS_SECTION_CSRSS_VA: u64 = 0x0000_0000_A000_0000;
                    let nls_start = NLS_20127_START.load(Ordering::Relaxed);
                    let nls_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x74) as *const u32) as u64;
                    let npages = (nls_size + 0xFFF) / 0x1000;
                    // Reserve one PT (the DLL PD already covers this 1 GiB PDPT slot).
                    let pt = alloc_slot();
                    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, NLS_SECTION_CSRSS_VA, pml4);
                    for i in 0..npages {
                        let _ = page_map(copy_cap(nls_start + i), NLS_SECTION_CSRSS_VA + i * 0x1000, RW_NX, pml4);
                    }
                    csrss_out_write(get_recv_mr(7), NLS_SECTION_CSRSS_VA, filled_pages, faults, scratch_base, reg, dll_pes, pml4); // *BaseAddress
                    let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                    if vs_ptr != 0 {
                        csrss_out_write(vs_ptr, nls_size, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    }
                    print_str(b"[ntos-exec] NtMapViewOfSection NlsCP20127 -> base 0xA0000000\n");
                    0
                } else {
                    self.stop = true; // other sections not modeled
                    0xC0000002
                }
            },
            // NtCreateProcess(*ProcessHandle[R10], access[RDX], *OA[R8], ParentProcess[R9],
            // InheritHandles[sp+0x28], SectionHandle[sp+0x30], …). Control-flow case: validate the
            // SectionHandle names the tracked csrss.exe SEC_IMAGE, then hand the actual spawn to the
            // loop (it needs fault_ep + the per-badge process arrays) via `spawn_request`.
            NativeService::NtCreateProcess => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let sp = get_recv_mr(16);
                let sect = smss_stack_read(sp + 0x30); // SectionHandle
                // NtCreateProcess(csrss/winlogon) is issued ONLY by smss (pi 0); scope so a dense
                // section handle of the same value in another process can't trigger a spawn (1b).
                if self.pi == 0
                    && *ctx.csrss_section_handle != 0
                    && sect == *ctx.csrss_section_handle
                    && (*ctx.csrss_pe).is_some()
                {
                    self.spawn_request = true; // the loop performs the spawn + writes *ProcessHandle
                    0
                } else if self.pi == 0
                    && *ctx.winlogon_section_handle != 0
                    && sect == *ctx.winlogon_section_handle
                    && (*ctx.winlogon_pe).is_some()
                {
                    self.winlogon_spawn_request = true; // loop spawns winlogon (3rd process)
                    0
                } else {
                    self.stop = true; // not a known section / not staged -> clean stop
                    0xC0000002
                }
            },
            // NtTerminateProcess(ProcessHandle[R10]=args[0], ExitStatus[RDX]=args[1]). Route the
            // POLICY teardown through pm: mark the target EPROCESS Terminated (signalled), terminate
            // its threads, release its image-section map ref. NOT reached during a normal boot (no
            // hosted process self-terminates); additive + proven by the post-loop self-test. FLAG:
            // the seL4 MECHANISM teardown (reclaim the VSpace/CSpace/TCB caps + the mirror/scratch
            // frames) is NOT done here — that needs the trusted-root-task cap reclamation and is the
            // next path-2 follow-up; today the process simply stops faulting and its frames persist.
            NativeService::NtTerminateProcess => {
                PM_TERMINATE_CALLS.fetch_add(1, Ordering::Relaxed);
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                if let Some(pid) = self.resolve_process_handle(handle) {
                    let _ = self.pm.terminate_process(pid, status);
                }
                0 // STATUS_SUCCESS (matches the prior broker fallback for an unresolved handle)
            }
            // NtTerminateThread(ThreadHandle, ExitStatus[RDX]) for NtCurrentThread()==-2 → the
            // caller's main thread. Uses `exit_thread` (NO process cascade — a hosted process's other
            // threads keep it alive), matching the live broker-arm routing (item 2a). This arm is NOT
            // table-registered (267 stays in the broker arm to preserve park_caller); it exists so the
            // policy is exercisable and args-defensive should a future flow register it.
            NativeService::NtTerminateThread => {
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                if handle == 0xFFFF_FFFF_FFFF_FFFE {
                    if let Some(tid) = PM_TIDS.get(self.pi).map(|t| t.load(Ordering::Relaxed)) {
                        if tid != 0 {
                            let _ = self.pm.exit_thread(tid as nt_process::ThreadId, status);
                        }
                    }
                }
                0
            }
            _ => 0xC000_0002, // STATUS_NOT_IMPLEMENTED — never silently succeed
        }
    }
}
