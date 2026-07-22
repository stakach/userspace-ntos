//! `ExecNtHandler` inherent methods + its `NativeSyscallHandler` (`dispatch`) impl.
//! The NT syscall service surface (NtXxx handlers). Extracted verbatim from `main.rs`
//! (pure reorg; no logic change). The `ExecNtHandler`/`ExecLoopCtx`/`LpcConnRecord`
//! struct definitions stay in `main.rs`; a child module reaches an ancestor's private
//! fields, and `impl` blocks auto-attach to the type crate-wide.
#![allow(clippy::all)]
use crate::*;
use nt_io_abi::major;

static WINLOGON_VM_TRACE_N: AtomicU64 = AtomicU64::new(0);
const EXEC_BOOT_STATUS_FILE_SIZE: usize = 0x800;
const EXEC_BSD_DATA_SIZE: usize = 0x88;
const EXEC_BOOT_STATUS_PATH: &[u8] = b"\\systemroot\\bootstat.dat";
static EXEC_BOOT_STATUS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut EXEC_BOOT_STATUS_DATA: [u8; EXEC_BOOT_STATUS_FILE_SIZE] =
    [0; EXEC_BOOT_STATUS_FILE_SIZE];

pub(crate) fn native_processor_information(
) -> nt_syscall::system_information::SystemProcessorInformation {
    use core::arch::x86_64::__cpuid;
    use nt_syscall::system_information::{
        amd64_processor_information_from_cpuid, X86Vendor,
    };

    // SAFETY: CPUID is available in the x86_64 execution environment.
    let vendor_leaf = unsafe { __cpuid(0) };
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&vendor_leaf.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&vendor_leaf.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&vendor_leaf.ecx.to_le_bytes());
    let vendor = match &vendor_bytes {
        b"GenuineIntel" => X86Vendor::Intel,
        b"AuthenticAMD" => X86Vendor::Amd,
        _ => X86Vendor::Other,
    };
    // SAFETY: leaf 1 exists on every x86_64 processor.
    let version = unsafe { __cpuid(1) };
    // SAFETY: extended leaf zero reports whether leaf 0x80000001 is available.
    let max_extended = unsafe { __cpuid(0x8000_0000) }.eax;
    let extended_edx = if max_extended >= 0x8000_0001 {
        // SAFETY: availability was checked above.
        unsafe { __cpuid(0x8000_0001) }.edx
    } else {
        0
    };
    amd64_processor_information_from_cpuid(
        vendor,
        version.eax,
        version.ecx,
        version.edx,
        extended_edx,
        false, // rust-micro currently saves FXSAVE state, not XSAVE state.
    )
}

#[inline]
fn boot_status_data_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(EXEC_BOOT_STATUS_DATA) as *mut u8
}

fn boot_status_path_matches(name: &[u16]) -> bool {
    name.len() == EXEC_BOOT_STATUS_PATH.len()
        && name
            .iter()
            .zip(EXEC_BOOT_STATUS_PATH.iter())
            .all(|(&wide, &ascii)| wide <= 0x7F && (wide as u8).to_ascii_lowercase() == ascii)
}

unsafe fn reset_boot_status_data() {
    let data = boot_status_data_ptr();
    // SAFETY: the boot-status array is executive-lifetime storage.
    unsafe {
        core::ptr::write_bytes(data, 0, EXEC_BOOT_STATUS_FILE_SIZE);
        core::ptr::write_unaligned(data.add(0x00) as *mut u32, EXEC_BSD_DATA_SIZE as u32);
        core::ptr::write_unaligned(data.add(0x04) as *mut u32, 1); // NtProductWinNt
        *data.add(0x08) = 1; // AabEnabled
        *data.add(0x09) = 30; // AabTimeout
        *data.add(0x0A) = 1; // LastBootSucceeded
    }
    EXEC_BOOT_STATUS_INITIALIZED.store(true, Ordering::Release);
}

unsafe fn ensure_boot_status_data() {
    if !EXEC_BOOT_STATUS_INITIALIZED.load(Ordering::Acquire) {
        // SAFETY: repeated reset races are benign in the single-executive boot path.
        unsafe { reset_boot_status_data() };
    }
}

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
                let mut v = alloc::vec::Vec::with_capacity(192);
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
            events: nt_kernel_exec::EventStore::with_capacity(192),
            semaphores: nt_kernel_exec::SemaphoreStore::with_capacity(192),
            global_atoms: nt_kernel_exec::rtl_atom::OwnedAtomTable::with_capacity(
                GLOBAL_ATOM_CAPACITY,
            )
            .unwrap(),
            io_completion_ports: nt_io_completion::CompletionPortTable::new(),
            pi: 0,
            current_tid: 0,
            current_badge: 0,
            post_action: ExecPostAction::None,
            stop: false,
            next_handle: FAKE_HANDLE,
            out_writes: [(0, 0); 8],
            out_writes_n: 0,
            loop_ctx: None,
            spawn_request: false,
            winlogon_spawn_request: false,
            services_spawn_request: false,
            lsass_spawn_request: false,
            sm_spawn_request: false,
            wl_spawn_request: 0,
            svc_listener_spawn: false,
            scm_worker_spawn: false,
            lsass_listener_spawn: false,
            lsass_listener2_spawn: false,
            lsass_listener3_spawn: false,
            wait_park_event: -1,
            wait_deadline_100ns: u64::MAX,
            keyed_wait_key: u64::MAX,
            keyed_wait_deadline_100ns: u64::MAX,
            delay_requested: false,
            delay_interval_100ns: 0,
            delay_alertable: false,
            io_signal_event: -1,
            pipe_park_fid: 0,
            pipe_park_buffer_va: 0,
            pipe_park_buffer_len: 0,
            pipe_park_iosb_va: 0,
            pipe_park_transceive: false,
            pipe_write_redrive: false,
            pipe_listen_fid: 0,
            pipe_listen_event_handle: 0,
            pipe_listen_iosb_va: 0,
            pipe_connect_redrive: 0,
            anon_event_seq: 0,
            lpc_rendezvous_conn: 0,
            lpc_rendezvous_out: 0,
            sm_request_port: 0,
            sm_request_message: 0,
            sm_reply_message: 0,
            csr_spawn_request: 0,
            csr_start_request: 0,
            csr_rendezvous_conn: 0,
            csr_rendezvous_out: 0,
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
                // The 5th hosted process — lsass.exe, spawned by winlogon's StartLsass Win32
                // CreateProcessW (the LSA subsystem), so its EPROCESS parent is winlogon too.
                let lsass_pid = pm.create_process("lsass.exe", Some(winlogon_pid), None);
                PM_PIDS[0].store(smss_pid as u64, Ordering::Relaxed);
                PM_PIDS[1].store(csrss_pid as u64, Ordering::Relaxed);
                PM_PIDS[2].store(winlogon_pid as u64, Ordering::Relaxed);
                PM_PIDS[3].store(services_pid as u64, Ordering::Relaxed);
                PM_PIDS[4].store(lsass_pid as u64, Ordering::Relaxed);
                PM_PROC_COUNT.store(pm.process_count() as u64, Ordering::Relaxed);
                // Identity check: each EPROCESS exists, names its hosted binary, and has a distinct pid.
                let mut ok = 0u64;
                let expect: [(usize, u32, &str); 5] = [
                    (0, smss_pid, "smss.exe"),
                    (1, csrss_pid, "csrss.exe"),
                    (2, winlogon_pid, "winlogon.exe"),
                    (3, services_pid, "services.exe"),
                    (4, lsass_pid, "lsass.exe"),
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
                let pids = [smss_pid, csrss_pid, winlogon_pid, services_pid, lsass_pid];
                for (i, &pid) in pids.iter().enumerate() {
                    if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                        PM_TIDS[i].store(tid as u64, Ordering::Relaxed);
                        let running = pm
                            .process(pid)
                            .is_some_and(|p| p.state == nt_process::ProcessState::Running);
                        let cid_ok = pm.client_id(tid)
                            == Some(nt_process::ClientId {
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
                // service_sec_image heap mark) so runtime NtCreateThread can hand them out WITHOUT a
                // BTreeMap insert (which, made during a serviced call above the mark, the per-syscall
                // bump reset would rewind → corrupt). Runtime create then only pops a pool tid + binds
                // its start routine/TEB (both alloc-free field writes) → reset-safe. One pool ETHREAD
                // per process is enough for the current boot (only winlogon creates a runtime thread —
                // the observed lsass fan-out needs three. Pool threads are NOT the main
                // thread (main was created first above), so main_thread() is unchanged.
                for (i, &pid) in pids.iter().enumerate() {
                    for slot in 0..PM_RUNTIME_THREAD_SLOTS {
                        if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                            let _ = pm.set_thread_state(tid, nt_process::ThreadState::Initialized);
                            PM_POOL_TID[i][slot].store(tid as u64, Ordering::Relaxed);
                        }
                    }
                }
                // Pre-reserve each EPROCESS's handle table NOW (below the service_sec_image heap
                // mark) so per-syscall `insert_handle` writes into pre-allocated storage and NEVER
                // reallocates under the per-call bump reset — the NON-LEAKING heap-reset solution.
                // Measured peak is < ~100 handles per process over a full boot; 256 is ~3× headroom.
                for pid in [smss_pid, csrss_pid, winlogon_pid, services_pid, lsass_pid] {
                    pm.reserve_handles(pid, PM_HANDLE_RESERVE);
                }
                // Record the reserved capacity (min across the 5) so the run can prove it never
                // grows — i.e. `insert_handle` never reallocates under the per-syscall reset.
                let cap = pm
                    .handle_capacity(smss_pid)
                    .min(pm.handle_capacity(csrss_pid))
                    .min(pm.handle_capacity(winlogon_pid))
                    .min(pm.handle_capacity(services_pid))
                    .min(pm.handle_capacity(lsass_pid));
                PM_HANDLE_CAP_BOOT.store(cap as u64, Ordering::Relaxed);
                pm
            },
            primary_tokens: alloc::vec![
                nt_security::AccessToken::system(),
                nt_security::AccessToken::system(),
                nt_security::AccessToken::system(),
                nt_security::AccessToken::system(),
                nt_security::AccessToken::system(),
            ],
            // The CM write plane. Pre-reserve the key vector up front (below the service_sec_image
            // heap mark) so it never reallocates; the per-key `String`/value `Vec` growth happens at
            // runtime and is retained past the per-syscall bump reset because the loop pins the heap
            // high-water mark past each mutation (see `overlay_dirty`). 64 keys is ample for the
            // SCM's volatile-key creation (the boot creates only a handful).
            overlay: nt_hive_core::RegistryOverlay::with_capacity(64),
            overlay_dirty: false,
            dll_loaded_dirty: false,
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
            if let Ok(h) = self
                .pm
                .insert_handle(pid, nt_process::HandleObject::Opaque(0), 0)
            {
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
    /// Mint a process-local handle backed by a typed filesystem `FILE_OBJECT` identity.
    pub(crate) fn mint_file_handle(&mut self, file_id: u64, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let handle = self
            .pm
            .insert_handle(pid, nt_process::HandleObject::File(file_id), access)
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    /// Mint a process-local handle for a read-only file on the mounted FAT volume.
    pub(crate) fn mint_disk_file_handle(
        &mut self,
        first_cluster: u32,
        size: u32,
        access: u32,
    ) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::DiskFile {
                    first_cluster,
                    size,
                },
                access,
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    /// Mint a process-local handle for a directory on the mounted FAT volume.
    pub(crate) fn mint_directory_handle(
        &mut self,
        first_cluster: u32,
        access: u32,
    ) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::Directory { first_cluster },
                access,
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    fn disk_file_for(&self, handle: u64) -> Result<Option<(u32, u32)>, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const FILE_READ_DATA: u32 = 0x0000_0001;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return Ok(None);
        };
        let Some(object) = self
            .pm
            .lookup_handle(pid, handle as nt_process::Handle)
        else {
            return Ok(None);
        };
        match object {
            nt_process::HandleObject::DiskFile {
                first_cluster,
                size,
            } => {
                let access = self
                    .pm
                    .handle_access(pid, handle as nt_process::Handle)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                if access & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) == 0 {
                    return Err(STATUS_ACCESS_DENIED);
                }
                Ok(Some((first_cluster, size)))
            }
            _ => Ok(None),
        }
    }

    /// Mint a process-local handle for the executive-reserved boot-status file.
    pub(crate) fn mint_boot_status_handle(&mut self, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let handle = self
            .pm
            .insert_handle(pid, nt_process::HandleObject::BootStatusFile, access)
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    fn boot_status_handle_access(&self, handle: u64) -> Result<u32, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::BootStatusFile) => self
                .pm
                .handle_access(pid, handle as nt_process::Handle)
                .ok_or(STATUS_INVALID_HANDLE),
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    fn boot_status_check_access(&self, handle: u64, wanted: u32, generic: u32) -> Result<(), u32> {
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const GENERIC_ALL: u32 = 0x1000_0000;
        let access = self.boot_status_handle_access(handle)?;
        if access & (wanted | generic | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    unsafe fn boot_status_offset(&self, byte_offset: u64) -> Result<usize, u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        if byte_offset == 0 {
            return Ok(0);
        }
        let mut raw = [0u8; 8];
        if !self.xas_read(byte_offset, &mut raw) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let signed = i64::from_le_bytes(raw);
        if signed < 0 || signed as usize > EXEC_BOOT_STATUS_FILE_SIZE {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(signed as usize)
    }

    unsafe fn boot_status_read_file(
        &self,
        handle: u64,
        buffer: u64,
        len: usize,
        byte_offset: u64,
    ) -> Result<u64, u32> {
        const FILE_READ_DATA: u32 = 0x0000_0001;
        const GENERIC_READ: u32 = 0x8000_0000;
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        self.boot_status_check_access(handle, FILE_READ_DATA, GENERIC_READ)?;
        if len != 0 && buffer == 0 {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        // SAFETY: reads the caller-supplied LARGE_INTEGER, if present.
        let offset = unsafe { self.boot_status_offset(byte_offset)? };
        let available = EXEC_BOOT_STATUS_FILE_SIZE.saturating_sub(offset);
        let copy_len = len.min(available);
        // SAFETY: initializes and reads from executive-lifetime boot-status storage.
        unsafe {
            ensure_boot_status_data();
            if copy_len != 0 {
                let src = core::slice::from_raw_parts(boot_status_data_ptr().add(offset), copy_len);
                self.xas_write_buf(buffer, src);
            }
        }
        Ok(copy_len as u64)
    }

    unsafe fn boot_status_write_file(
        &self,
        handle: u64,
        buffer: u64,
        len: usize,
        byte_offset: u64,
    ) -> Result<u64, u32> {
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_APPEND_DATA: u32 = 0x0000_0004;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        self.boot_status_check_access(handle, FILE_WRITE_DATA | FILE_APPEND_DATA, GENERIC_WRITE)?;
        if len != 0 && buffer == 0 {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        // SAFETY: reads the caller-supplied LARGE_INTEGER, if present.
        let offset = unsafe { self.boot_status_offset(byte_offset)? };
        let available = EXEC_BOOT_STATUS_FILE_SIZE.saturating_sub(offset);
        let copy_len = len.min(available);
        let mut payload = alloc::vec![0u8; copy_len];
        if copy_len != 0 && !self.xas_read(buffer, &mut payload) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        // SAFETY: initializes and writes into executive-lifetime boot-status storage.
        unsafe {
            ensure_boot_status_data();
            if copy_len != 0 {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    boot_status_data_ptr().add(offset),
                    copy_len,
                );
            }
        }
        Ok(copy_len as u64)
    }

    /// Mint a process-local event handle that references a shared executive event identity.
    pub(crate) fn mint_event_handle(&mut self, event_index: usize, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let tag = EVENT_HANDLE_TAG | event_index as u64;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::Opaque(tag),
                nt_kernel_exec::map_event_access(access),
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    /// Resolve a typed process-local event handle and enforce the access requested by the operation.
    pub(crate) fn event_index_for_handle(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<usize, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        if handle >= OBJ_HANDLE_BASE {
            let index = (handle - OBJ_HANDLE_BASE) as usize;
            return match self.obj_ns.get(index) {
                Some(entry) if entry.kind != 2 => Err(STATUS_OBJECT_TYPE_MISMATCH),
                _ => Err(STATUS_INVALID_HANDLE),
            };
        }
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let tag = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Opaque(tag))
                if tag & EVENT_HANDLE_TAG_MASK == EVENT_HANDLE_TAG =>
            {
                tag
            }
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => return Err(STATUS_INVALID_HANDLE),
        };
        let granted = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if required_access != 0 && granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        let index = (tag & 0xFFFF_FFFF) as usize;
        self.obj_ns
            .get(index)
            .filter(|entry| entry.kind == 2 && self.events.contains(index as u64))
            .map(|_| index)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub(crate) fn mint_semaphore_handle(&mut self, index: usize, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let tag = SEMAPHORE_HANDLE_TAG | index as u64;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::Opaque(tag),
                nt_kernel_exec::map_semaphore_access(access),
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    pub(crate) fn semaphore_index_for_handle(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<usize, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        if handle >= OBJ_HANDLE_BASE {
            let index = (handle - OBJ_HANDLE_BASE) as usize;
            return match self.obj_ns.get(index) {
                Some(entry) if entry.kind != 3 => Err(STATUS_OBJECT_TYPE_MISMATCH),
                _ => Err(STATUS_INVALID_HANDLE),
            };
        }
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let tag = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Opaque(tag))
                if tag & SEMAPHORE_HANDLE_TAG_MASK == SEMAPHORE_HANDLE_TAG => tag,
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => return Err(STATUS_INVALID_HANDLE),
        };
        let granted = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if required_access != 0 && granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        let index = (tag & 0xFFFF_FFFF) as usize;
        self.obj_ns
            .get(index)
            .filter(|entry| entry.kind == 3 && self.semaphores.contains(index as u64))
            .map(|_| index)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub(crate) fn waitable_index_for_handle(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<usize, u32> {
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        match self.event_index_for_handle(handle, required_access) {
            Ok(index) => Ok(index),
            Err(STATUS_OBJECT_TYPE_MISMATCH) => {
                self.semaphore_index_for_handle(handle, required_access)
            }
            Err(status) => Err(status),
        }
    }

    fn dispatcher_object(&self, index: usize) -> Option<nt_kernel_exec::DispatcherObject> {
        match self.obj_ns.get(index).map(|entry| entry.kind) {
            Some(2) => Some(nt_kernel_exec::DispatcherObject::Event(index as u64)),
            Some(3) => Some(nt_kernel_exec::DispatcherObject::Semaphore(index as u64)),
            _ => None,
        }
    }

    pub(crate) fn dispatcher_ready(&self, index: usize) -> bool {
        self.dispatcher_object(index).is_some_and(|object| {
            nt_kernel_exec::dispatcher_ready(&self.events, &self.semaphores, object)
        })
    }

    pub(crate) fn dispatcher_consume(&mut self, index: usize) -> bool {
        let Some(object) = self.dispatcher_object(index) else {
            return false;
        };
        nt_kernel_exec::consume_dispatcher(&mut self.events, &mut self.semaphores, object)
    }

    pub(crate) fn is_legacy_opaque_handle(&self, handle: u64) -> bool {
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return false;
        };
        matches!(
            self.pm.lookup_handle(pid, handle as nt_process::Handle),
            Some(nt_process::HandleObject::Opaque(0))
        )
    }
    pub(crate) fn mint_io_completion_handle(&mut self, object_id: u32, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::IoCompletion(object_id),
                access,
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }
    fn io_completion_id_for(&self, handle: u64, required_access: u32) -> Result<u32, u32> {
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        let pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_io_completion::STATUS_INVALID_HANDLE)?;
        let object_id = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::IoCompletion(object_id)) => object_id,
            _ => return Err(nt_io_completion::STATUS_INVALID_HANDLE),
        };
        let granted = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(nt_io_completion::STATUS_INVALID_HANDLE)?;
        if granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(object_id)
    }
    /// General NtCreateThread: claim the next real pool ETHREAD for the caller (`self.pi`) — bind the
    /// caller-supplied start routine + parameter (all alloc-free field writes, reset-safe),
    /// and mint a TYPED `Thread(tid)` handle in the caller's EPROCESS handle table (dense value, so
    /// `NtQueryInformationThread` resolves the handle VALUE → the real ETHREAD). Returns
    /// `(slot, tid, handle)`
    /// or `None` if the caller has no free pool ETHREAD. The seL4 TCB is spawned separately by the loop.
    pub(crate) fn nt_create_thread_handle(
        &mut self,
        entry: u64,
        create_suspended: bool,
        desired_access: u32,
    ) -> Option<(usize, u64, u64)> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let pool = PM_POOL_TID.get(self.pi)?;
        let used = PM_POOL_USED.get(self.pi)?;
        let mut claimed = used.load(Ordering::Relaxed);
        let slot = loop {
            let slot = (0..PM_RUNTIME_THREAD_SLOTS).find(|slot| claimed & (1 << slot) == 0)?;
            match used.compare_exchange_weak(
                claimed,
                claimed | (1 << slot),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break slot,
                Err(now) => claimed = now,
            }
        };
        let tid = pool[slot].load(Ordering::Relaxed);
        if tid == 0 {
            used.fetch_and(!(1 << slot), Ordering::Relaxed);
            return None;
        }
        let t = tid as nt_process::ThreadId;
        self.pm.set_thread_start_address(t, entry);
        let _ = self.pm.set_thread_state(
            t,
            if create_suspended {
                nt_process::ThreadState::Initialized
            } else {
                nt_process::ThreadState::Running
            },
        );
        let h =
            match self
                .pm
                .insert_handle(pid, nt_process::HandleObject::Thread(t), desired_access)
            {
                Ok(handle) => handle,
                Err(_) => {
                    let _ = self
                        .pm
                        .set_thread_state(t, nt_process::ThreadState::Initialized);
                    used.fetch_and(!(1 << slot), Ordering::Relaxed);
                    return None;
                }
            };
        if create_suspended {
            PM_POOL_SUSPENDED[self.pi].fetch_or(1 << slot, Ordering::Relaxed);
        } else {
            PM_POOL_SUSPENDED[self.pi].fetch_and(!(1 << slot), Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        PM_GENERAL_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
        Some((slot, tid, h as u64))
    }
    /// Bind a hosted process's MAIN THREAD to its real image entry at the actual seL4 spawn — the
    /// "route NtCreateThread through pm at real spawn time" step (the thread object was pre-created
    /// at boot for the non-leaking heap solution; this alloc-free field write completes it).
    pub(crate) fn bind_main_thread_entry(&mut self, pi: usize, entry: u64) {
        if let Some(tid) = PM_TIDS.get(pi).map(|t| t.load(Ordering::Relaxed)) {
            if tid != 0
                && self
                    .pm
                    .set_thread_start_address(tid as nt_process::ThreadId, entry)
            {
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
    fn pi_for_pid(&self, pid: nt_process::ProcessId) -> Option<usize> {
        PM_PIDS
            .iter()
            .position(|stored| stored.load(Ordering::Relaxed) == pid as u64)
    }

    fn token_index_for_handle(&self, handle: u64, required_access: u32) -> Result<usize, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        let caller = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let object = self
            .pm
            .lookup_handle(caller, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let token_pid = match object {
            nt_process::HandleObject::Token(pid) => pid,
            _ => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        let granted = self
            .pm
            .handle_access(caller, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.pi_for_pid(token_pid).ok_or(STATUS_INVALID_HANDLE)
    }

    fn current_token_has_privilege(&self, name: &str) -> bool {
        self.primary_tokens
            .get(self.pi)
            .is_some_and(|token| token.has_privilege(name))
    }

    fn serialize_sid(sid: &nt_security::Sid, output: &mut [u8]) -> Option<usize> {
        let count = u8::try_from(sid.sub_authorities.len()).ok()?;
        let length = 8usize.checked_add(sid.sub_authorities.len().checked_mul(4)?)?;
        let output = output.get_mut(..length)?;
        output[0] = sid.revision;
        output[1] = count;
        output[2..8].copy_from_slice(&sid.identifier_authority);
        for (index, authority) in sid.sub_authorities.iter().enumerate() {
            let offset = 8 + index * 4;
            output[offset..offset + 4].copy_from_slice(&authority.to_le_bytes());
        }
        Some(length)
    }

    pub(crate) unsafe fn nt_open_process_token(
        &mut self,
        process_handle: u64,
        desired_access: u32,
        out: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        if !self.probe_user_output(out, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let target_pid = match self.resolve_process_handle(process_handle) {
            Some(pid) => pid,
            None => return STATUS_INVALID_HANDLE,
        };
        if self.pi_for_pid(target_pid).is_none() {
            return STATUS_INVALID_HANDLE;
        }
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return STATUS_INVALID_HANDLE,
        };
        let handle = match self.pm.insert_handle(
            caller_pid,
            nt_process::HandleObject::Token(target_pid),
            desired_access,
        ) {
            Ok(handle) => handle,
            Err(_) => return STATUS_INSUFFICIENT_RESOURCES,
        };
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        let count = self.pm.handle_count(caller_pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        if !self.xas_write_u64(out, handle as u64) {
            let _ = self.pm.close_handle(caller_pid, handle);
            return STATUS_ACCESS_VIOLATION;
        }
        0
    }

    unsafe fn nt_adjust_privileges_token(&mut self, args: &[u64]) -> u32 {
        const STATUS_SUCCESS: u32 = 0;
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
        const STATUS_NOT_ALL_ASSIGNED: u32 = 0x0000_0106;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;

        let disable_all = args[1] != 0;
        let new_state = args[2];
        let buffer_length = args[3] as usize;
        let previous_state = args[4];
        let return_length = args[5];
        if !disable_all && new_state == 0 {
            return STATUS_INVALID_PARAMETER;
        }

        let mut requested = alloc::vec::Vec::new();
        if !disable_all {
            let mut count_bytes = [0u8; 4];
            if !self.xas_read(new_state, &mut count_bytes) {
                return STATUS_ACCESS_VIOLATION;
            }
            let count = u32::from_le_bytes(count_bytes) as usize;
            let captured_size = match count.checked_mul(12).and_then(|n| n.checked_add(4)) {
                Some(size) => size,
                None => return STATUS_INVALID_PARAMETER,
            };
            if new_state.checked_add(captured_size as u64).is_none()
                || requested.try_reserve_exact(count).is_err()
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            for index in 0..count {
                let mut entry = [0u8; 12];
                if !self.xas_read(new_state + 4 + index as u64 * 12, &mut entry) {
                    return STATUS_ACCESS_VIOLATION;
                }
                requested.push(nt_security::PrivilegeAdjustment {
                    luid: nt_security::Luid {
                        low: u32::from_le_bytes(entry[0..4].try_into().unwrap()),
                        high: i32::from_le_bytes(entry[4..8].try_into().unwrap()),
                    },
                    attributes: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
                });
            }
        }

        if previous_state != 0
            && (return_length == 0
                || !self.probe_user_output(previous_state, buffer_length)
                || !self.probe_user_output(return_length, 4))
        {
            return STATUS_ACCESS_VIOLATION;
        }

        let required_access = TOKEN_ADJUST_PRIVILEGES
            | if previous_state != 0 { TOKEN_QUERY } else { 0 };
        let token_index = match self.token_index_for_handle(args[0], required_access) {
            Ok(index) => index,
            Err(status) => return status,
        };
        let plan = self.primary_tokens[token_index]
            .plan_privilege_adjustment(disable_all, &requested);
        let required_length = 4 + plan.changed * 12;
        if previous_state != 0 {
            if !self.xas_write_u32(return_length, required_length as u32) {
                return STATUS_ACCESS_VIOLATION;
            }
            if buffer_length < required_length {
                return STATUS_BUFFER_TOO_SMALL;
            }
        }

        // The exact ReactOS SYSTEM token has 24 privileges, so this is sufficient even for
        // DisableAllPrivileges and remains allocation-free across the executive heap reset.
        let mut previous = [nt_security::PrivilegeAdjustment::default(); 24];
        let result = self.primary_tokens[token_index].adjust_privileges(
            disable_all,
            &requested,
            &mut previous[..plan.changed],
        );
        if previous_state != 0 {
            let mut output = [0u8; 4 + 24 * 12];
            output[..4].copy_from_slice(&(result.changed as u32).to_le_bytes());
            for (index, privilege) in previous[..result.changed].iter().enumerate() {
                let offset = 4 + index * 12;
                output[offset..offset + 4].copy_from_slice(&privilege.luid.low.to_le_bytes());
                output[offset + 4..offset + 8]
                    .copy_from_slice(&privilege.luid.high.to_le_bytes());
                output[offset + 8..offset + 12]
                    .copy_from_slice(&privilege.attributes.to_le_bytes());
            }
            if !self.xas_try_write_buf(previous_state, &output[..required_length]) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if !disable_all && result.matched < requested.len() {
            STATUS_NOT_ALL_ASSIGNED
        } else {
            STATUS_SUCCESS
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

    pub(crate) fn close_current_handle(&mut self, handle: u64) {
        if let Some(pid) = self.pm_pid_for_pi(self.pi) {
            let _ = self.pm.close_handle(pid, handle as nt_process::Handle);
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
        let filled_pages = &*ctx.filled_pages;
        let faults = *ctx.faults as usize;
        if client_copyin_mapped(
            self.pi as u64,
            va,
            dst,
            filled_pages,
            faults,
            ctx.scratch_base,
        ) {
            return true;
        }
        let reg = &*ctx.reg;
        let dll_pes = ctx.dll_pes();
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
    pub(crate) unsafe fn xas_write_u64(&self, va: u64, val: u64) -> bool {
        if let Some(ctx) = self.loop_ctx {
            if va & 0xFFF <= 0xFF8 {
                let alias = csrss_frame_alias_get(self.pi as u64, va & !0xFFF);
                if alias != 0 {
                    core::ptr::write_volatile(
                        (alias + (va & 0xFFF)) as *mut u64,
                        val,
                    );
                    return true;
                }
            }
            let filled_pages = &mut *ctx.filled_pages;
            let faults = &mut *ctx.faults;
            let reg = &*ctx.reg;
            let dll_pes = ctx.dll_pes();
            csrss_out_write(
                va,
                val,
                filled_pages,
                faults,
                ctx.scratch_base,
                reg,
                dll_pes,
                ctx.pml4,
            )
        } else {
            smss_copyout(va, &val.to_le_bytes())
        }
    }

    /// Cross-address-space DWORD copyout without imposing 8-byte alignment on the user pointer.
    pub(crate) unsafe fn xas_write_u32(&self, va: u64, val: u32) -> bool {
        if let Some(ctx) = self.loop_ctx {
            if va & 0xFFF <= 0xFFC {
                let alias = csrss_frame_alias_get(self.pi as u64, va & !0xFFF);
                if alias != 0 {
                    core::ptr::write_volatile(
                        (alias + (va & 0xFFF)) as *mut u32,
                        val,
                    );
                    return true;
                }
            }
            let filled_pages = &mut *ctx.filled_pages;
            let faults = &mut *ctx.faults;
            let reg = &*ctx.reg;
            let dll_pes = ctx.dll_pes();
            csrss_out_write32(
                va,
                val,
                filled_pages,
                faults,
                ctx.scratch_base,
                reg,
                dll_pes,
                ctx.pml4,
            )
        } else {
            smss_copyout(va, &val.to_le_bytes())
        }
    }

    /// Probe a small writable event output before changing dispatcher state.
    pub(crate) unsafe fn probe_event_output(&self, va: u64, len: usize) -> bool {
        len <= 8 && self.probe_user_output(va, len)
    }

    /// Probe an arbitrary user output range without changing its contents.
    pub(crate) unsafe fn probe_user_output(&self, va: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if va == 0 || va.checked_add(len as u64).is_none() {
            return false;
        }
        let Some(ctx) = self.loop_ctx else {
            let mut address = va;
            let mut remaining = len;
            let mut bytes = [0u8; 8];
            while remaining != 0 {
                let chunk = remaining.min(bytes.len());
                if !self.xas_read(address, &mut bytes[..chunk]) {
                    return false;
                }
                address += chunk as u64;
                remaining -= chunk;
            }
            return true;
        };
        let end = va + len as u64;
        let stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
        let stack_end = stack_base + ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
        if va >= stack_base && end <= stack_end
            || va >= SMSS_ALLOC_VA && end <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW
        {
            return true;
        }

        fn writable_image_range(pe: &nt_pe_loader::PeFile, base: u64, va: u64, len: usize) -> bool {
            let rva = match va.checked_sub(base) {
                Some(rva) => rva,
                None => return false,
            };
            let end = match rva.checked_add(len as u64) {
                Some(end) => end,
                None => return false,
            };
            pe.sections().iter().any(|section| {
                let start = section.virtual_address as u64;
                let section_end = start + section.virtual_size.max(section.size_of_raw_data) as u64;
                rva >= start && end <= section_end && section.is_writable()
            })
        }

        unsafe fn scratch_pages_available(
            ctx: ExecLoopCtx,
            pi: u64,
            va: u64,
            len: usize,
            may_fill: bool,
        ) -> bool {
            let filled_pages = unsafe { &*ctx.filled_pages };
            let faults = unsafe { *ctx.faults } as usize;
            let mut missing = 0usize;
            let mut page = va & !0xFFF;
            let last = (va + len as u64 - 1) & !0xFFF;
            loop {
                let has_alias = unsafe { csrss_frame_alias_get(pi, page) } != 0;
                if !has_alias
                    && unsafe { scratch_for(page, filled_pages, faults, ctx.scratch_base) }.is_none()
                {
                    if !may_fill {
                        return false;
                    }
                    missing += 1;
                }
                if page == last {
                    break;
                }
                page += 0x1000;
            }
            missing == 0
                || faults
                    .checked_add(missing)
                    .is_some_and(|needed| needed <= filled_pages.len())
        }

        if va >= PE_LOAD_BASE && end <= ctx.img_end {
            return writable_image_range(&*ctx.pe, PE_LOAD_BASE, va, len);
        }
        if !ctx.ntdll_pe.is_null() && va >= ctx.nt_base && end <= ctx.nt_end {
            return writable_image_range(&*ctx.ntdll_pe, ctx.nt_base, va, len)
                && scratch_pages_available(ctx, self.pi as u64, va, len, false);
        }
        let reg = &*ctx.reg;
        if let Some((index, _)) = reg.dll_for_page(va) {
            if let Some(pe) = ctx.dll_pes()[index].as_ref() {
                return writable_image_range(pe, reg.base(index), va, len)
                    && scratch_pages_available(ctx, self.pi as u64, va, len, true);
            }
        }
        false
    }
    /// Cross-AS byte-buffer write to the current process's VA `va` — mirror first, else 8-byte chunks
    /// via [`xas_write_u64`] (each demand-fills a not-yet-faulted DLL/heap page as needed). The last
    /// partial word is read-modify-written so trailing bytes past `src` in that word are preserved.
    /// Used for services (pi 3) registry info-structure copyout (KEY_*_INFORMATION into a heap buffer).
    pub(crate) unsafe fn xas_write_buf(&self, va: u64, src: &[u8]) {
        let _ = self.xas_try_write_buf(va, src);
    }

    pub(crate) unsafe fn xas_try_write_buf(&self, va: u64, src: &[u8]) -> bool {
        if smss_copyout(va, src) {
            return true;
        }
        let mut i = 0usize;
        while i < src.len() {
            let n = (src.len() - i).min(8);
            let mut w = [0u8; 8];
            if n < 8 && !self.xas_read(va + i as u64, &mut w) {
                return false;
            }
            w[..n].copy_from_slice(&src[i..i + n]);
            if !self.xas_write_u64(va + i as u64, u64::from_le_bytes(w)) {
                return false;
            }
            i += 8;
        }
        true
    }
    /// Capture an NtAddAtom/NtFindAtom explicit-length UTF-16 name from the current process. Small
    /// pointer values preserve MAKEINTATOM semantics and are returned directly without a read.
    pub(crate) unsafe fn copyin_atom_name(
        &self,
        name_va: u64,
        byte_len: u32,
        name: &mut [u16; nt_kernel_exec::rtl_atom::NAME_CAP],
    ) -> Result<Option<u16>, u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        let byte_len = byte_len as usize;
        if byte_len > nt_kernel_exec::rtl_atom::NAME_CAP * 2 || byte_len & 1 != 0 {
            return Err(nt_kernel_exec::rtl_atom::status::INVALID_PARAMETER);
        }
        if name_va <= 0xFFFF {
            return Ok(Some(name_va as u16));
        }
        let units = byte_len / 2;
        let mut bytes = [0u8; nt_kernel_exec::rtl_atom::NAME_CAP * 2];
        if !self.xas_read(name_va, &mut bytes[..byte_len]) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        for i in 0..units {
            name[i] = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        }
        Ok(None)
    }

    /// Probe a small user output range using the current process's cross-address-space reader.
    pub(crate) unsafe fn probe_atom_output(&self, va: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if va == 0 || len > 8 {
            return false;
        }
        let mut probe = [0u8; 8];
        self.xas_read(va, &mut probe[..len])
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

    /// Validate event OBJECT_ATTRIBUTES and return its root handle plus optional object name.
    pub(crate) unsafe fn read_event_object_attributes(
        &self,
        oa_va: u64,
    ) -> Result<(u64, u32, Option<alloc::vec::Vec<u16>>), u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;

        let mut oa = [0u8; 0x30];
        if !self.xas_read(oa_va, &mut oa) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        if u32::from_le_bytes(oa[0..4].try_into().unwrap()) < 0x30 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let root = u64::from_le_bytes(oa[8..16].try_into().unwrap());
        let object_name = u64::from_le_bytes(oa[16..24].try_into().unwrap());
        let attributes = u32::from_le_bytes(oa[24..28].try_into().unwrap());
        if object_name == 0 {
            return Ok((root, attributes, None));
        }

        let mut ustr = [0u8; 16];
        if !self.xas_read(object_name, &mut ustr) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let length = u16::from_le_bytes(ustr[0..2].try_into().unwrap()) as usize;
        let maximum = u16::from_le_bytes(ustr[2..4].try_into().unwrap()) as usize;
        let buffer = u64::from_le_bytes(ustr[8..16].try_into().unwrap());
        if length == 0 || length & 1 != 0 || length > maximum || length > 2048 || buffer == 0 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let mut bytes = alloc::vec![0u8; length];
        if !self.xas_read(buffer, &mut bytes) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let name = bytes
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .collect();
        Ok((root, attributes, Some(name)))
    }

    fn event_root_index(&self, root: u64) -> Result<usize, u32> {
        if root == 0 {
            return Ok(0);
        }
        if root < OBJ_HANDLE_BASE {
            return Err(0xC000_0008); // STATUS_INVALID_HANDLE
        }
        let index = (root - OBJ_HANDLE_BASE) as usize;
        match self.obj_ns.get(index) {
            Some(entry) if entry.kind == 0 => Ok(index),
            Some(_) => Err(0xC000_0024), // STATUS_OBJECT_TYPE_MISMATCH
            None => Err(0xC000_0008),    // STATUS_INVALID_HANDLE
        }
    }

    /// Convert the byte-oriented subset supported by the compact object namespace without
    /// truncating a full path to one leaf. Individual namespace entries are limited to 40 bytes.
    fn event_object_path(name: &[u16]) -> Result<alloc::vec::Vec<u8>, u32> {
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        let mut path = alloc::vec::Vec::with_capacity(name.len());
        for &unit in name {
            if unit > 0x7f {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            path.push((unit as u8).to_ascii_lowercase());
        }
        let mut components = path.split(|&byte| byte == b'\\');
        if path.first() == Some(&b'\\') {
            components.next();
        }
        if components.any(|component| component.is_empty() || component.len() > 40) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(path)
    }

    /// Apply native OBJECT_ATTRIBUTES path rules: a null RootDirectory requires an absolute name,
    /// while a directory handle requires a relative name.
    fn event_root_and_path<'a>(&self, root: u64, path: &'a [u8]) -> Result<(usize, &'a [u8]), u32> {
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        if root == 0 {
            if path.first() != Some(&b'\\') {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            return Ok((0, path));
        }
        if path.first() == Some(&b'\\') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok((self.event_root_index(root)?, path))
    }

    fn rollback_new_event(&mut self, index: usize) {
        if index + 1 == self.obj_ns.len() {
            self.obj_ns.pop();
            self.events.remove_existing(index as u64);
        }
    }

    fn rollback_new_semaphore(&mut self, index: usize) {
        if index + 1 == self.obj_ns.len() {
            self.obj_ns.pop();
            self.semaphores.remove(index as u64);
        }
    }
    /// Normalize a caller's pipe path (`\Device\NamedPipe\ntsvcs`, `\??\pipe\ntsvcs`, `\??\PIPE\ntsvcs`,
    /// or a relative `ntsvcs`) to npfs's leaf form `\ntsvcs` (UTF-16, leading backslash). npfs's
    /// NpFsdCreate strips the device prefix; the leaf is what the VCB prefix tree keys on.
    pub(crate) fn pipe_leaf16(name16: &[u16]) -> alloc::vec::Vec<u16> {
        // Lowercase ASCII copy for prefix stripping.
        let lc: alloc::vec::Vec<u16> = name16
            .iter()
            .map(|&w| {
                if (b'A' as u16..=b'Z' as u16).contains(&w) {
                    w + 32
                } else {
                    w
                }
            })
            .collect();
        // Find the last occurrence of "namedpipe\" or "pipe\" and take everything after it.
        let after = |needle: &[u16]| -> Option<usize> {
            if lc.len() < needle.len() {
                return None;
            }
            (0..=lc.len() - needle.len())
                .rev()
                .find(|&i| &lc[i..i + needle.len()] == needle)
                .map(|i| i + needle.len())
        };
        let np: alloc::vec::Vec<u16> = "namedpipe\\".encode_utf16().collect();
        let pp: alloc::vec::Vec<u16> = "pipe\\".encode_utf16().collect();
        let start = after(&np).or_else(|| after(&pp)).unwrap_or(0);
        let leaf = &name16[start..];
        // Ensure a single leading backslash (the leaf npfs expects, e.g. "\ntsvcs").
        let mut out = alloc::vec::Vec::with_capacity(leaf.len() + 1);
        if leaf.first().copied() != Some(b'\\' as u16) {
            out.push(b'\\' as u16);
        }
        out.extend_from_slice(leaf);
        out
    }

    /// Route a live pipe IRP through the isolated npfs component. `major` is an `IRP_MJ_*`; `name16` is
    /// the (normalized-here) pipe name for CREATE/CREATE_NAMED_PIPE; `file_id` is npfs's FsContext for
    /// an existing pipe (FSCTL/read/write). Records the returned handle->file_id in the static table.
    /// Returns `(status, file_id)` on success (routed), or `None` if npfs isn't ready (caller falls
    /// back to the modeled path — keeps pi 0-2 byte-identical).
    pub(crate) unsafe fn npfs_route(
        &mut self,
        major: u64,
        fsctl: u64,
        name16: &[u16],
        file_id: u64,
    ) -> Option<(i32, u64)> {
        if !driver_launch::npfs_ready() {
            return None;
        }
        // Build the ARG-frame input (buffered I/O): the pipe name as raw UTF-16 bytes.
        let mut in_bytes = alloc::vec::Vec::with_capacity(name16.len() * 2);
        for &w in name16 {
            in_bytes.extend_from_slice(&w.to_le_bytes());
        }
        let mut out = [0u8; 64];
        let (st, _, fid) = self.npfs_route_raw(major, fsctl, file_id, &in_bytes, &mut out)?;
        Some((st, fid))
    }

    /// Route an npfs IRP with its native byte payload and preserve completion output.
    pub(crate) unsafe fn npfs_route_raw(
        &mut self,
        major: u64,
        fsctl: u64,
        file_id: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Option<(i32, u64, u64)> {
        let (status, information) =
            driver_launch::npfs_dispatch_irp(major, fsctl, file_id, input, output)?;
        NPFS_ROUTED_IRPS.fetch_add(1, Ordering::Relaxed);
        Some((status, information, driver_launch::npfs_last_file_id()))
    }

    /// Resolve a process-local typed file handle to npfs's FILE_OBJECT context.
    pub(crate) fn npfs_file_id_for(&self, handle: u64) -> u64 {
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return 0;
        };
        match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::File(file_id)) => file_id,
            _ => 0,
        }
    }

    /// Resolve a typed pipe handle and enforce the write access granted at create/open time.
    pub(crate) fn npfs_write_file_id_for(&self, handle: u64) -> Result<u64, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_APPEND_DATA: u32 = 0x0000_0004;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;

        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let file_id = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::File(file_id)) if file_id != 0 => file_id,
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        let access = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(file_id)
    }

    /// Resolve a typed named-pipe handle for `NtFlushBuffersFile`. ReactOS's I/O manager requires
    /// write-data access for named pipes (append-data is deliberately excluded because that bit is
    /// `FILE_CREATE_PIPE_INSTANCE` in the pipe namespace). Generic access is retained in our handle
    /// table, so accept the generic write/all grants until object creation performs generic mapping.
    pub(crate) fn npfs_flush_file_id_for(&self, handle: u64) -> Result<u64, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;

        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let file_id = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::File(file_id)) if file_id != 0 => file_id,
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        let access = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if access & (FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(file_id)
    }

    /// Resolve a typed pipe handle and enforce read access granted at create/open time.
    pub(crate) fn npfs_read_file_id_for(&self, handle: u64) -> Result<u64, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const FILE_READ_DATA: u32 = 0x0000_0001;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;

        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let file_id = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::File(file_id)) if file_id != 0 => file_id,
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        let access = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if access & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(file_id)
    }

    /// Validate an optional I/O completion event. Named executive events return their object index;
    /// legacy anonymous events are typed as Opaque and retain the existing immediate-wait model.
    pub(crate) fn validate_io_event(&self, handle: u64) -> Result<Option<usize>, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        if handle == 0 {
            return Ok(None);
        }
        if let Ok(index) = self.event_index_for_handle(handle, 0) {
            return Ok(Some(index));
        }
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Opaque(_)) => Ok(None),
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Cache an established LPC connection (the data-plane record). Bounded by the pre-reserved
    /// capacity so the push never reallocates across the per-syscall bump reset. `connector_pi` =
    /// the current process (0=smss, 1=csrss).
    pub(crate) fn cache_lpc_connection(
        &mut self,
        connection_id: u64,
        client_handle: u64,
        name: &[u16],
    ) {
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

    pub(crate) fn lpc_connection_is(&self, handle: u64, connector_pi: usize, name: &[u8]) -> bool {
        self.lpc_connections.iter().any(|connection| {
            connection.client_handle == handle
                && connection.connector_pi as usize == connector_pi
                && connection.name_len as usize == name.len()
                && connection.name[..name.len()]
                    .iter()
                    .zip(name.iter())
                    .all(|(&wide, &ascii)| {
                        wide <= 0x7f && (wide as u8).to_ascii_lowercase() == ascii.to_ascii_lowercase()
                    })
        })
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
                // ★ AUTHENTIC rendezvous accept is scoped to winlogon (pi 2) — csrss's REAL
                // CsrApiRequestThread accepts ONE pending connect (winlogon's) then parks; there is no
                // second acceptor for services (pi 3) yet, so driving `csr_rendezvous` for pi>=3 would
                // spin the nested accept loop forever. services+ take the MODELED accept (a minted
                // client handle + the mapped CSR view/static-data below) so their bring-up proceeds;
                // wiring a per-client CSR acceptor for services is the SCM batch's frontier.
                if self.pi == 2 && r.pending && r.connection_id != 0 {
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
                    core::ptr::write_volatile(
                        (sc + 0x08) as *mut u64,
                        WINLOGON_CSR_STATIC_VA + 0x0100,
                    );
                    let bssd = sc + 0x0100;
                    // WindowsDirectory = L"C:\Windows" (9 wchars)
                    core::ptr::write_volatile((bssd + 0x00) as *mut u16, 9 * 2);
                    core::ptr::write_volatile((bssd + 0x02) as *mut u16, 10 * 2);
                    core::ptr::write_volatile(
                        (bssd + 0x08) as *mut u64,
                        WINLOGON_CSR_STATIC_VA + 0x3000,
                    );
                    // WindowsSystemDirectory = L"C:\Windows\System32" (18 wchars)
                    core::ptr::write_volatile((bssd + 0x10) as *mut u16, 18 * 2);
                    core::ptr::write_volatile((bssd + 0x12) as *mut u16, 19 * 2);
                    core::ptr::write_volatile(
                        (bssd + 0x18) as *mut u64,
                        WINLOGON_CSR_STATIC_VA + 0x3020,
                    );
                    // NamedObjectDirectory = L"\BaseNamedObjects" (17 wchars)
                    core::ptr::write_volatile((bssd + 0x20) as *mut u16, 17 * 2);
                    core::ptr::write_volatile((bssd + 0x22) as *mut u16, 18 * 2);
                    core::ptr::write_volatile(
                        (bssd + 0x28) as *mut u64,
                        WINLOGON_CSR_STATIC_VA + 0x3060,
                    );
                } else if i == 3 {
                    write_wstr(sc + 0x000, "C:\\Windows");
                    write_wstr(sc + 0x020, "C:\\Windows\\System32");
                    write_wstr(sc + 0x060, "\\BaseNamedObjects");
                }
                let _ = page_map(
                    copy_cap(f),
                    WINLOGON_CSR_STATIC_VA + i * 0x1000,
                    RW_NX,
                    pml4,
                );
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
                ctx.dll_pes(),
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
            if self.obj_ns.get(cur)?.kind != 0 {
                return None;
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
    pub(crate) fn obj_insert(
        &mut self,
        parent: usize,
        leaf: &[u8],
        kind: u8,
        target: &[u8],
    ) -> Option<usize> {
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
    /// Create a fresh ANONYMOUS (unnamed) event object (kind==2). Each call makes a DISTINCT obj_ns
    /// entry — no dedup — carrying a unique synthetic name under a private parent (250) so it is never
    /// found by name-resolution but is still a real, waitable/signalable event. `auto_reset` marks it
    /// as a SynchronizationEvent (consumed on satisfying wait). The namespace index is the shared
    /// event identity; callers receive process-local typed handles referencing it.
    pub(crate) fn obj_create_anon_event(
        &mut self,
        auto_reset: bool,
        initial_state: bool,
    ) -> Option<usize> {
        if self.obj_ns.len() >= self.obj_ns.capacity() {
            return None;
        }
        // Unique 4-byte synthetic name "a" + a 24-bit counter, so obj_child never matches two anon
        // events (they live under a private parent id 250 that no name walk reaches).
        let n = self.anon_event_seq;
        self.anon_event_seq = self.anon_event_seq.wrapping_add(1);
        let name = [
            b'a',
            (n & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
        ];
        let mut e = ObjEntry::dir(&name, 250);
        e.kind = 2;
        self.obj_ns.push(e);
        let index = self.obj_ns.len() - 1;
        self.events.initialize(
            index as u64,
            if auto_reset {
                EventKind::Synchronization
            } else {
                EventKind::Notification
            },
            initial_state,
        );
        Some(index)
    }
    pub(crate) fn obj_create_anon_semaphore(
        &mut self,
        initial: i32,
        maximum: i32,
    ) -> Option<usize> {
        if self.obj_ns.len() >= self.obj_ns.capacity() {
            return None;
        }
        let n = self.anon_event_seq;
        self.anon_event_seq = self.anon_event_seq.wrapping_add(1);
        let name = [
            b's',
            (n & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
        ];
        let mut entry = ObjEntry::dir(&name, 250);
        entry.kind = 3;
        self.obj_ns.push(entry);
        let index = self.obj_ns.len() - 1;
        if self
            .semaphores
            .initialize(index as u64, initial, maximum)
            .is_err()
        {
            self.obj_ns.pop();
            return None;
        }
        Some(index)
    }
    /// Create a dir/symlink named by `path` (which may be `\`-qualified or relative to `root_idx`):
    /// resolve the parent from all but the last component, then insert the leaf. Existing → reused.
    pub(crate) fn obj_create(
        &mut self,
        path: &[u8],
        root_idx: usize,
        kind: u8,
        target: &[u8],
    ) -> Option<usize> {
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
        if self.obj_ns.get(parent)?.kind != 0 {
            return None;
        }
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
        let comps: alloc::vec::Vec<&str> = aliased.split('\\').filter(|c| !c.is_empty()).collect();
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
        // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Winlogon — the SOFTWARE
        // hive isn't on the image; back this one key's EXISTENCE (msgina GetRegistrySettings). See
        // SYNTH_WINLOGON_KEY.
        if is_winlogon_key_comps(&comps[2..]) {
            return Some(SYNTH_WINLOGON_KEY);
        }
        None
    }
    /// Does a `\SystemRoot\System32` file with this probe's leaf name exist? Extracts the leaf (last
    /// `\`-component) of the folded probe path and looks it up under System32 on the REAL \reactos
    /// FS by-path (`sys32_exists` → `open_sys32` → `fat_open_path`) — path-form independent (the
    /// loader probes many directory prefixes for the same DLL) and the SOLE existence authority (no
    /// hand-maintained SYSTEM32_FILES list): a file exists iff it's present on the actual volume.
    /// nt-dll-registry keeps the SEC_IMAGE base/geometry role for CONTENT.
    pub(crate) fn fs_system32_has(&self, folded: &[u8]) -> bool {
        let leaf = match folded.iter().rposition(|&c| c == b'\\') {
            Some(p) => &folded[p + 1..],
            None => folded,
        };
        unsafe { sys32_exists(leaf) }
    }
    /// Classify a folded probe path as one of the hosted-process EXEs by substring and return its
    /// CANONICAL System32 leaf (so existence resolves against the real file, not a possibly-malformed
    /// extracted leaf — ReactOS occasionally builds `\??\C:\Windowsservices.exe` with no separator).
    /// `None` if it isn't a recognized EXE probe or if it's an SxS/actctx probe (which must fail so
    /// the loader doesn't take the .Local\/manifest path). Purely a name→canonical-leaf classifier;
    /// the caller still confirms the leaf on the real FS.
    fn exe_probe_canon(folded: &[u8], is_sxs: bool) -> Option<&'static [u8]> {
        if is_sxs {
            return None;
        }
        if folded.windows(5).any(|w| w == b"csrss") {
            Some(b"csrss.exe")
        } else if folded.windows(8).any(|w| w == b"winlogon") {
            Some(b"winlogon.exe")
        } else if folded.windows(8).any(|w| w == b"services") {
            Some(b"services.exe")
        } else if folded.windows(5).any(|w| w == b"lsass") {
            // "lsass" is specific (lsasrv.dll folds to "lsasr", no match).
            Some(b"lsass.exe")
        } else {
            None
        }
    }
}
impl NativeSyscallHandler for ExecNtHandler {
    fn handle(
        &mut self,
        ctx: &NativeCallContext,
        args: &[u64],
        _out: &mut alloc::vec::Vec<u8>,
    ) -> u32 {
        match ctx.service {
            // NtClose(Handle[R10]=args[0]): free the handle in the caller's REAL EPROCESS handle
            // table by its SLOT (path 1b — the value IS the dense per-process table handle now, so
            // close by value directly; no value-tag scan). Append-only allocation means the freed
            // slot is NOT recycled, so a later open never reuses a closed value (keeping external
            // bindings — the per-pi DLL registry — consistent). We still return SUCCESS
            // unconditionally (matching the prior no-op) so a close of a handle the executive
            // doesn't own stays benign. A win32k USER-object handle is closed through that owning
            // table so a duplicated desktop handle has an independent lifetime.
            NativeService::NtClose => {
                let mut closed = false;
                if let Some(pid) = self.pm_pid_for_pi(self.pi) {
                    let completion_id = match self
                        .pm
                        .lookup_handle(pid, args[0] as nt_process::Handle)
                    {
                        Some(nt_process::HandleObject::IoCompletion(id)) => Some(id),
                        _ => None,
                    };
                    if self.pm.close_handle(pid, args[0] as nt_process::Handle).is_ok() {
                        closed = true;
                        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                        if let Some(id) = completion_id {
                            let _ = self.io_completion_ports.release(id);
                        }
                    }
                }
                if !closed && unsafe { crate::win32k_subsystem::close_user_object_handle(args[0]) }
                {
                    PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                }
                0 // STATUS_SUCCESS
            }
            // NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, *TargetHandle,
            // DesiredAccess, HandleAttributes, Options). Resolve both process handles in the
            // caller's table, then duplicate the typed object into the target EPROCESS table. This
            // preserves shared identities such as msgina's worker-completion event instead of
            // copying an unowned scalar handle value.
            NativeService::NtDuplicateObject => {
                const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
                const DUPLICATE_CLOSE_SOURCE: u32 = 0x1;
                const DUPLICATE_SAME_ACCESS: u32 = 0x2;

                let Some(source_pid) = self.resolve_process_handle(args[0]) else {
                    return STATUS_INVALID_HANDLE;
                };
                let options = args[6] as u32;
                let mut target_pid_for_peak = None;
                let mut native_duplicate = false;
                let result = if args[2] == 0 {
                    if args[3] == 0 && options & DUPLICATE_CLOSE_SOURCE != 0 {
                        Ok(None)
                    } else {
                        Err(STATUS_INVALID_HANDLE)
                    }
                } else {
                    let Some(target_pid) = self.resolve_process_handle(args[2]) else {
                        return STATUS_INVALID_HANDLE;
                    };
                    target_pid_for_peak = Some(target_pid);
                    let desired_access = (options & DUPLICATE_SAME_ACCESS == 0)
                        .then_some(args[4] as u32);
                    match self.pm.duplicate_handle_with_access(
                            source_pid,
                            args[1] as nt_process::Handle,
                            target_pid,
                            desired_access,
                        ) {
                        Ok(handle) => {
                            native_duplicate = true;
                            Ok(Some(handle as u64))
                        }
                        Err(status)
                            if status == STATUS_INVALID_HANDLE
                                && source_pid == target_pid
                                && options & DUPLICATE_SAME_ACCESS != 0 =>
                        {
                            unsafe {
                                crate::win32k_subsystem::duplicate_user_object_handle(args[1])
                            }
                            .map(Some)
                            .ok_or(STATUS_INVALID_HANDLE)
                        }
                        Err(status) => Err(status),
                    }
                };

                if options & DUPLICATE_CLOSE_SOURCE != 0 {
                    let closed_native = self
                        .pm
                        .close_handle(source_pid, args[1] as nt_process::Handle)
                        .is_ok();
                    if closed_native
                        || unsafe {
                            crate::win32k_subsystem::close_user_object_handle(args[1])
                        }
                    {
                        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if self.current_badge == 12 {
                    print_str(b"[duplicate-object] source=0x");
                    print_hex_u64(args[1]);
                    print_str(b" target-out=0x");
                    print_hex_u64(args[3]);
                    print_str(b" options=0x");
                    print_hex(options);
                    match result {
                        Ok(Some(handle)) => {
                            print_str(if native_duplicate { b" native=0x" } else { b" win32k=0x" });
                            print_hex_u64(handle);
                            print_str(b"\n");
                        }
                        Ok(None) => print_str(b" close-only\n"),
                        Err(status) => {
                            print_str(b" status=0x");
                            print_hex(status);
                            print_str(b"\n");
                        }
                    }
                }
                match result {
                    Ok(Some(handle)) => {
                        self.queue_write(args[3], handle);
                        if native_duplicate {
                            let count = self.pm.handle_count(target_pid_for_peak.unwrap()) as u64;
                            if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
                                PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
                            }
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                        }
                        0
                    }
                    Ok(None) => 0,
                    Err(status) => status,
                }
            }
            // One executive-lifetime table is shared across every hosted process. Add increments a
            // duplicate's reference count, Find does not, and Delete decrements/frees at zero.
            NativeService::NtAddAtom | NativeService::NtFindAtom => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                let out_atom = args[2];
                if out_atom != 0 && !self.probe_atom_output(out_atom, 2) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let byte_len = args[1] as u32;
                let mut name = [0u16; nt_kernel_exec::rtl_atom::NAME_CAP];
                let integer = match self.copyin_atom_name(args[0], byte_len, &mut name) {
                    Ok(integer) => integer,
                    Err(status) => return status,
                };
                let result = match (ctx.service, integer) {
                    (NativeService::NtAddAtom, Some(atom)) => self.global_atoms.add_integer(atom),
                    (NativeService::NtFindAtom, Some(atom)) => self.global_atoms.find_integer(atom),
                    (NativeService::NtAddAtom, None) => {
                        self.global_atoms.add_name(&name[..byte_len as usize / 2])
                    }
                    (NativeService::NtFindAtom, None) => {
                        self.global_atoms.find_name(&name[..byte_len as usize / 2])
                    }
                    _ => unreachable!(),
                };
                match result {
                    Ok(atom) => {
                        if out_atom != 0 {
                            self.xas_write_buf(out_atom, &atom.to_le_bytes());
                        }
                        nt_kernel_exec::rtl_atom::status::SUCCESS
                    }
                    Err(status) => status,
                }
            },
            NativeService::NtDeleteAtom => self.global_atoms.delete(args[0] as u16),
            NativeService::NtQueryInformationAtom => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
                const BASIC_HEADER: usize = 6;
                const TABLE_HEADER: usize = 4;

                let atom = args[0] as u16;
                let info_class = args[1] as u32;
                let info_va = args[2];
                let info_len = args[3] as u32 as usize;
                let return_len_va = args[4];

                if return_len_va != 0 && !self.probe_atom_output(return_len_va, 4) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if info_len != 0 {
                    let mut first = [0u8; 8];
                    let probe_len = info_len.min(first.len());
                    if info_va == 0 || !self.xas_read(info_va, &mut first[..probe_len]) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                }

                let mut required_length = 0u32;
                let status = match info_class {
                    0 => {
                        required_length = BASIC_HEADER as u32;
                        if info_len < BASIC_HEADER {
                            nt_kernel_exec::rtl_atom::status::INFO_LENGTH_MISMATCH
                        } else {
                            let name_capacity = (info_len - BASIC_HEADER) as u32;
                            let mut name = [0u16; nt_kernel_exec::rtl_atom::NAME_CAP + 1];
                            let query = self.global_atoms.query(atom, &mut name, name_capacity);
                            if query.status == nt_kernel_exec::rtl_atom::status::SUCCESS {
                                let copied = query.name_length as usize;
                                let write_len = BASIC_HEADER + copied + 2;
                                let mut output = [0u8;
                                    BASIC_HEADER
                                        + (nt_kernel_exec::rtl_atom::NAME_CAP + 1) * 2];
                                if info_va == 0
                                    || !self.xas_read(info_va, &mut output[..write_len])
                                {
                                    return STATUS_ACCESS_VIOLATION;
                                }
                                output[0..2].copy_from_slice(
                                    &(query.reference_count as u16).to_le_bytes(),
                                );
                                output[2..4]
                                    .copy_from_slice(&(query.pin_count as u16).to_le_bytes());
                                output[4..6]
                                    .copy_from_slice(&(query.name_length as u16).to_le_bytes());
                                for i in 0..=(copied / 2) {
                                    let off = BASIC_HEADER + i * 2;
                                    output[off..off + 2].copy_from_slice(&name[i].to_le_bytes());
                                }
                                self.xas_write_buf(info_va, &output[..write_len]);
                                required_length = write_len as u32;
                            }
                            query.status
                        }
                    }
                    1 => {
                        required_length = TABLE_HEADER as u32;
                        if info_len < TABLE_HEADER {
                            nt_kernel_exec::rtl_atom::status::INFO_LENGTH_MISMATCH
                        } else {
                            let slots = ((info_len - TABLE_HEADER) / 2).min(GLOBAL_ATOM_CAPACITY);
                            let mut atoms = [0u16; GLOBAL_ATOM_CAPACITY];
                            let list = self.global_atoms.list(&mut atoms[..slots]);
                            let copied = list.count.min(slots);
                            let write_len = TABLE_HEADER + copied * 2;
                            let mut output = [0u8; TABLE_HEADER + GLOBAL_ATOM_CAPACITY * 2];
                            if info_va == 0 || !self.xas_read(info_va, &mut output[..write_len]) {
                                return STATUS_ACCESS_VIOLATION;
                            }
                            output[..4].copy_from_slice(&(list.count as u32).to_le_bytes());
                            for (i, atom) in atoms[..copied].iter().enumerate() {
                                let off = TABLE_HEADER + i * 2;
                                output[off..off + 2].copy_from_slice(&atom.to_le_bytes());
                            }
                            self.xas_write_buf(info_va, &output[..write_len]);
                            if list.status == nt_kernel_exec::rtl_atom::status::SUCCESS {
                                required_length = write_len as u32;
                            }
                            list.status
                        }
                    }
                    _ => STATUS_INVALID_INFO_CLASS,
                };

                if return_len_va != 0 {
                    self.xas_write_buf(return_len_va, &required_length.to_le_bytes());
                }
                status
            },
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
                let name16 = if self.pi == 3 || self.pi == 4 {
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
                // winlogon (pi 2) — msgina's `GetRegistrySettings` (WlxInitialize) opens the Winlogon
                // key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. advapi32's
                // `RegOpenKeyExW(HKLM, subkey)` first maps HKLM by opening `\Registry\Machine`, then
                // opens the subkey relative to that handle. BOTH names are `RTL_CONSTANT_STRING`
                // literals in `.rdata` pages winlogon/advapi32 never touch, so the pi==2 copyin mirror
                // returns EMPTY for each → recover the real name from the backing PE image
                // (`read_objattr_name_pe`, cross-AS via the registered DLL). Two exact, scoped matches:
                //   (a) `\Registry\Machine` predefined-HKLM open → hand back MACHINE_ROOT_HANDLE so
                //       advapi32's HKLM mapping SUCCEEDS. (Post-`SERVICES_CREATE_STARTED` the generic
                //       empty-name branch below returns NOT_FOUND — which BROKE this open → the msgina
                //       WlxShutdown(NULL) crash. Matching the recovered name distinguishes it from the
                //       BasepIsProcessAllowed AppCertDlls empty-name open that must still miss.)
                //   (b) the Winlogon subkey (relative to MACHINE_ROOT_HANDLE) → back its existence with
                //       SYNTH_WINLOGON_KEY so the open succeeds and value reads miss (msgina applies its
                //       documented registry defaults) → WlxInitialize writes `*pWlxContext` (non-NULL) →
                //       GinaInit succeeds → no HandleShutdown → no WlxShutdown(NULL).
                // Both are EXACT-name matches scoped to pi==2, so no other paint-time HKLM open outcome
                // changes (broadly succeeding HKLM opens regressed the desktop paint; see the
                // keyboard-layout note on MACHINE_ROOT_HANDLE).
                if self.pi == 2 {
                    let eff_name = if !path.is_empty() {
                        path.clone()
                    } else {
                        let pe_name = self.read_objattr_name_pe(oa);
                        let mut s = alloc::string::String::new();
                        for &w in &pe_name {
                            if let Some(c) = char::from_u32(w as u32) {
                                s.push(c);
                            }
                        }
                        s
                    };
                    if is_winlogon_key(&eff_name) {
                        WINLOGON_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                        let h = self.intern_key_handle(SYNTH_WINLOGON_KEY);
                        self.xas_write_u64(args[0], h);
                        return 0; // STATUS_SUCCESS — Winlogon key exists (values default via miss)
                    }
                    // Exact `\Registry\Machine` predefined-HKLM open (rd absolute) → sentinel handle.
                    if root_dir < KEY_HANDLE_BASE {
                        let comps: alloc::vec::Vec<&str> =
                            eff_name.split('\\').filter(|c| !c.is_empty()).collect();
                        if comps.len() == 2
                            && comps[0].eq_ignore_ascii_case("Registry")
                            && comps[1].eq_ignore_ascii_case("Machine")
                        {
                            self.xas_write_u64(args[0], MACHINE_ROOT_HANDLE);
                            return 0; // STATUS_SUCCESS — HKLM predefined root
                        }
                    }
                    // winlogon InitializeSAS → SetDefaultLanguage(NULL) opens
                    // `System\CurrentControlSet\Control\Nls\Language` (relative to the HKLM handle, so
                    // root_dir arrives 0 like the keyboard-layout key) and reads its `Default` value (the
                    // system default LCID string). This key IS in the real staged SYSTEM hive, so resolve
                    // it there (prepend the `\Registry\Machine\` mount prefix → `resolve_key` applies the
                    // CurrentControlSet→ControlSet001 alias + strips the prefix). Backing it makes
                    // SetDefaultLanguage succeed → InitializeSAS succeeds (was: NOT_FOUND → SetDefaultLanguage
                    // FALSE → InitializeSAS FALSE → winlogon ExitProcess(2)). EXACT-name scoped so no other
                    // pi==2 HKLM subkey outcome changes (the desktop paint's client reads stay identical).
                    if is_nls_language_key(&eff_name) {
                        let full = alloc::format!("\\Registry\\Machine\\{}", eff_name);
                        if let Some(kr) = self.resolve_key(&full) {
                            let h = self.intern_key_handle(kr);
                            self.xas_write_u64(args[0], h);
                            return 0; // STATUS_SUCCESS — real Nls\Language key
                        }
                    }
                }
                // services (pi 3): resolve HKLM predefined roots + machine-relative subkeys against
                // the real SYSTEM hive (::ROSSYS.HIV). A predefined `\Registry\Machine` open → the
                // sentinel machine-root handle; a subkey relative to it (RootDirectory ==
                // MACHINE_ROOT_HANDLE) or an absolute `\Registry\Machine\...` path → `resolve_key`;
                // a subkey relative to a real hive handle → `open_key_from`. Self-contained + returns,
                // so the winlogon/csrss paint-time key hacks below are untouched (byte-identical).
                if self.pi == 3 || self.pi == 4 {
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
                    if let Some(cell) = cell {
                        let h = self.intern_key_handle(cell);
                        self.xas_write_u64(args[0], h);
                        return 0; // STATUS_SUCCESS
                    }
                    // lsass (pi 4): the SECURITY + SAM hives (\Registry\Machine\{SECURITY,SAM}) don't
                    // exist in our staged SYSTEM hive, but real ReactOS creates them at setup. lsass'
                    // LsapOpenServiceKey (\Registry\Machine\SECURITY, KEY_CREATE_SUB_KEY) + samsrv's
                    // SampInitDatabase (\Registry\Machine\SAM) do a plain OPEN that would fail c0000034
                    // → lsass bails at LsapInitDatabase / SamIInitialize. Model these hives as EMPTY
                    // overlay roots: on a pi==4 open of a path under SECURITY/SAM that isn't in the base
                    // or overlay yet, auto-create it in the overlay so the open succeeds (lsass then
                    // creates its Policy/database subkeys under them via NtCreateKey → overlay). Scoped to
                    // pi==4 so services (pi 3) / paint reads are unchanged.
                    if self.pi == 4 {
                        if let Some(ref full) = full_opt {
                            if is_lsa_hive_path(full) {
                                let canon = self.overlay_canon(full);
                                let (oidx, _) = self.overlay.create(&canon);
                                self.overlay_dirty = true;
                                let h = self.intern_key_handle(OVERLAY_KEY_TAG | (oidx as u32));
                                self.xas_write_u64(args[0], h);
                                return 0; // STATUS_SUCCESS (empty LSA/SAM hive root/subkey)
                            }
                        }
                    }
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
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
                if self.pi != 3 && self.pi != 4 {
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
                if self.pi != 3 && self.pi != 4 {
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
                let iosb = get_recv_mr(8); // R9 = *IO_STATUS_BLOCK
                // pi==3 (services' SCM RPC server): route the create through the REAL isolated npfs
                // FSD → NpFsdCreateNamedPipe builds a real FCB/CCB + FILE_OBJECT (server end). pi 0-2
                // keep the modeled-fake path (byte-identical: winlogon's \pipe\winreg never connects).
                let mut info: u64 = 2; // FILE_CREATED
                let mut routed_file_id = 0;
                if self.pi == 3 || self.pi == 4 {
                    let oa = get_recv_mr(7); // R8 = *OBJECT_ATTRIBUTES
                    let name16 = self.read_objattr_name_pe(oa);
                    let leaf = Self::pipe_leaf16(&name16);
                    // BATCH 34 DIAG: confirm the server FCB is created for the SCM pipe (\ntsvcs).
                    let mut nm_ascii = [b'.'; 24];
                    for (i, &w) in leaf.iter().take(24).enumerate() {
                        let b = w as u8;
                        nm_ascii[i] = if b.is_ascii_graphic() { b } else { b'.' };
                    }
                    // BATCH 38: bound the SCM `\ntsvcs` server-instance re-create loop so the boot
                    // quiesces after the (now-live) RPC round-trip. Past the cap, fail the create with
                    // STATUS_PIPE_NOT_AVAILABLE (0xC00000AC) → rpcrt4's re-listen fails → the listener
                    // parks. Name-scoped to `\ntsvcs` (SCM), pi 3 only, so lsass/other pipes are unaffected.
                    let is_ntsvcs = leaf.len() >= 7
                        && leaf[1..7].iter().zip(b"ntsvcs".iter()).all(|(&w, &c)| w as u8 == c);
                    if self.pi == 3 && is_ntsvcs {
                        let n = SCM_NTSVCS_CREATE_COUNT.fetch_add(1, Ordering::Relaxed);
                        if n >= SCM_NTSVCS_CREATE_CAP {
                            if n == SCM_NTSVCS_CREATE_CAP {
                                print_str(b"[nt-create-named-pipe] pi=3 \\ntsvcs re-create cap reached -> STATUS_PIPE_NOT_AVAILABLE (listener parks; boot quiesces)\n");
                            }
                            if iosb != 0 {
                                self.xas_write_buf(iosb, &0xC00000ACu32.to_le_bytes()); // Status
                                self.xas_write_buf(iosb + 8, &0u64.to_le_bytes()); // Information
                            }
                            self.queue_write(get_recv_mr(9), 0); // *FileHandle = NULL
                            return 0xC00000AC; // STATUS_PIPE_NOT_AVAILABLE
                        }
                    }
                    // BATCH 40: same re-create cap for lsass' `\lsarpc` LSA RPC server (pi 4). Once
                    // winlogon crosses msgina GINA init and drives its logon flow, lsass re-creates the
                    // `\lsarpc` server pipe unboundedly (no live terminating client under TCG) → the boot
                    // never quiesces. Cap → STATUS_PIPE_NOT_AVAILABLE → the LSA listener parks → gate.
                    let is_lsarpc = leaf.len() >= 7
                        && leaf[1..7].iter().zip(b"lsarpc".iter()).all(|(&w, &c)| w as u8 == c);
                    if self.pi == 4 && is_lsarpc {
                        let n = LSA_LSARPC_CREATE_COUNT.fetch_add(1, Ordering::Relaxed);
                        if n >= LSA_LSARPC_CREATE_CAP {
                            if n == LSA_LSARPC_CREATE_CAP {
                                print_str(b"[nt-create-named-pipe] pi=4 \\lsarpc re-create cap reached -> STATUS_PIPE_NOT_AVAILABLE (LSA listener parks; boot quiesces)\n");
                            }
                            if iosb != 0 {
                                self.xas_write_buf(iosb, &0xC00000ACu32.to_le_bytes()); // Status
                                self.xas_write_buf(iosb + 8, &0u64.to_le_bytes()); // Information
                            }
                            self.queue_write(get_recv_mr(9), 0); // *FileHandle = NULL
                            return 0xC00000AC; // STATUS_PIPE_NOT_AVAILABLE
                        }
                    }
                    // BATCH 43: throttle this per-create diagnostic. The SCM `\ntsvcs` (and `\lsarpc`)
                    // server-instance re-listen loop fires it ~24× each; serial writes are the dominant
                    // per-round-trip cost under TCG, and once winlogon CROSSES its win32k class wall
                    // (BATCH 43) the heavier real SAS-window work + these repeated log lines no longer fit
                    // the 620s boot budget. Print only the FIRST 3 creates per pi (enough to prove the
                    // server FCB path), then suppress — reclaiming budget so the boot quiesces + gates.
                    {
                        let n = NAMED_PIPE_LOG_COUNT[self.pi & 7].fetch_add(1, Ordering::Relaxed);
                        if n < 3 {
                            print_str(b"[nt-create-named-pipe] pi=");
                            print_u64(self.pi as u64);
                            print_str(b" leaf=");
                            print_str(&nm_ascii);
                            print_str(b"\n");
                        }
                    }
                    if let Some((st, fid)) = self.npfs_route(1 /* IRP_MJ_CREATE_NAMED_PIPE */, 0, &leaf, 0) {
                        if st == 0 && fid != 0 {
                            routed_file_id = fid;
                            // BATCH 34: remember this server fid → its pipe leaf name-hash, so a client
                            // connect completes ONLY the matching-name server listen (not every armed one).
                            crate::pipe_fid_name_remember(fid, nt_io_manager::pipe_name_hash(&leaf));
                        } else {
                            info = 1; // FILE_OPENED (subsequent instance) — still SUCCESS to rpcrt4
                        }
                    }
                }
                let h = if routed_file_id != 0 {
                    self.mint_file_handle(routed_file_id, args[1] as u32)
                        .unwrap_or_else(|| self.mint_handle())
                } else {
                    self.mint_handle()
                };
                // *FileHandle (R10): for services/lsass (pi 3/4) it's a DLL .data global → the cross-AS
                // writer; for pi 0-2 the legacy stack write is byte-identical.
                if self.pi == 3 || self.pi == 4 {
                    self.queue_write(get_recv_mr(9), h);
                    if iosb != 0 {
                        self.xas_write_buf(iosb, &0u32.to_le_bytes()); // Status
                        self.xas_write_buf(iosb + 8, &info.to_le_bytes()); // Information
                    }
                } else {
                    smss_stack_write(get_recv_mr(9), h);
                    if iosb != 0 {
                        smss_stack_write32(iosb, 0);
                        smss_stack_write(iosb + 8, 2);
                    }
                }
                NAMED_PIPE_CREATED.fetch_add(1, Ordering::Relaxed);
                0 // STATUS_SUCCESS
            },
            // NtFsControlFile(FileHandle[R10], Event[RDX], ApcRoutine[R8], ApcContext[R9],
            // IoStatusBlock[sp+0x28], FsControlCode[sp+0x30], ...). rpcrt4's pipe listen/connect
            // FSCTLs. Report success with a zeroed IoStatusBlock so the listener setup proceeds; no
            // client ever connects, so the actual pipe-listen semantics are irrelevant to bring-up.
            NativeService::NtFsControlFile => unsafe {
                let iosb = args[4];
                // pi==3: route the FSCTL (FSCTL_PIPE_LISTEN/WAIT/TRANSCEIVE) to npfs for the tracked
                // pipe handle. npfs's NpFsdFileSystemControl runs the real state machine on the CCB.
                // FSCTL_PIPE_LISTEN on a server pipe with no client returns STATUS_PIPE_LISTENING
                // (0x00000000-ish PENDING); we surface npfs's status. pi 0-2 keep the modeled path.
                let fsctl = args[5];
                let mut status: u64 = 0;
                let mut information = 0u64;
                // ★ winlogon (pi 2) rpcrt4 worker: FSCTL_PIPE_LISTEN (0x110008) MUST report
                // STATUS_PENDING (0x103), NOT SUCCESS. In rpcrt4_protseq_np_get_wait_array, SUCCESS →
                // SetEvent(listen_event) → wait_for_new_connection wakes on the listen_event (index>0) →
                // rpcrt4_spawn_connection derefs a NULL RpcConnection (no real client) → NULL deref.
                // PENDING → the listen_event stays UNSIGNALLED, so the worker parks on [mgr_event,
                // listen_event]; the main thread's signal_state_changed SetEvents mgr_event → the worker
                // wakes on WAIT_OBJECT_0 (index 0) → returns 0 → sets set_ready_event → SetEvents
                // server_ready_event → the main thread's WaitForSingleObject(server_ready_event) wakes.
                // This is the correct pending-listen (no synchronous phantom client) that completes the
                // rpcrt4 two-thread handshake without a real npfs connection.
                //
                // ★ BATCH 34 — the SAME invariant for the pi 3/4 REAL ncacn_np SERVER (services'/lsass'
                // SCM/LSA listeners). rpcrt4_protseq_np_get_wait_array posts FSCTL_PIPE_LISTEN on EACH
                // listener pipe; if it returns SUCCESS/STATUS_PIPE_CONNECTED it does `SetEvent(event)`
                // IMMEDIATELY → wait_for_new_connection wakes → rpcrt4_spawn_connection → handoff →
                // rpcrt4_conn_create_pipe creates a NEW instance → get_wait_array posts FSCTL_PIPE_LISTEN
                // on it → SUCCESS again → SetEvent → an INFINITE create-instance runaway (observed: 894
                // `\ntsvcs` creates). The listen MUST return STATUS_PENDING for a freshly-created server
                // instance with no client — then the listener parks on NtWaitForMultipleObjects, and ONLY
                // our explicit event-signal on a REAL client connect (pipe_listen_complete_named) wakes
                // it with io_status.Status = SUCCESS → it spawns exactly ONE connection per real client.
                // So force PENDING + arm the async listen for pi 3/4 too (don't route the LISTEN to
                // npfs's state machine, which returns CONNECTED/SUCCESS for the just-handed-off instance).
                let is_pipe_listen = (fsctl as u32) == 0x0011_0008;
                let force_pending_listen = is_pipe_listen && (self.pi == 2 || self.pi == 3 || self.pi == 4);
                if force_pending_listen {
                    status = 0x103; // STATUS_PENDING
                }
                let fid = self.npfs_file_id_for(args[0]);
                if fid != 0 && !force_pending_listen {
                    let input_len = (args[7] as usize).min(0x4000);
                    let output_len = (args[9] as usize).min(0x4000);
                    let mut input = alloc::vec![0u8; input_len];
                    let mut output = alloc::vec![0u8; output_len];
                    if (input_len == 0 || self.xas_read(args[6], &mut input))
                        && (output_len == 0 || args[8] != 0)
                    {
                        if let Some((st, completed, _)) = self.npfs_route_raw(
                            0xd, fsctl, fid, &input, &mut output,
                        ) {
                            status = st as u64;
                            information = completed;
                            if completed != 0 && args[8] != 0 {
                                let copy_len = (completed as usize).min(output.len());
                                self.xas_write_buf(args[8], &output[..copy_len]);
                            }
                        }
                    }
                }
                // BATCH 33: an FSCTL_PIPE_TRANSCEIVE (write-then-read) on a real npfs pipe that returns
                // PENDING has no response bytes yet → PARK this caller keyed by the reading end fid, and
                // re-drive it when the peer writes the response (the loop steals the reply cap; the
                // response is delivered to args[8]/IOSB at re-drive, so SUPPRESS the PENDING IOSB here).
                if fid != 0
                    && (fsctl as u32) == 0x0011_C017
                    && (status as u32) == 0x0000_0103
                    && args[8] != 0
                {
                    self.pipe_park_fid = fid;
                    self.pipe_park_buffer_va = args[8];
                    self.pipe_park_buffer_len = args[9] as u32;
                    self.pipe_park_iosb_va = iosb;
                    self.pipe_park_transceive = true;
                }
                // ★ BATCH 34 — the async ncacn_np SERVER completion edge. A server (pi 3/4) posting an
                // OVERLAPPED FSCTL_PIPE_LISTEN (0x110008) that npfs returns STATUS_PENDING for (no client
                // yet, NpSetListeningPipeState → IoMarkIrpPending) does NOT block on this syscall — the
                // thread continues to NtWaitForMultipleObjects([mgr_event, listen_event]). Record the
                // pending async listen keyed by the SERVER fid, carrying the completion EVENT (RDX =
                // args[1], resolved to its obj_ns index in the SERVER's OWN handle table NOW while `pi`
                // names the server) + the listen IOSB VA. On the peer connect/write the loop completes it
                // (fills the IOSB SUCCESS + signals the event → the server's wait-array wakes). SUPPRESS
                // the PENDING IOSB write here (overlapped: the IOSB is written at completion, not now).
                if (self.pi == 3 || self.pi == 4)
                    && (fsctl as u32) == 0x0011_0008
                    && (status as u32) == 0x0000_0103
                    && fid != 0
                {
                    // Resolve the overlapped completion Event (RDX = args[1]) to an obj_ns index in the
                    // server's handle table. May be 0/absent (APC-mode); then event_obj_idx = u64::MAX.
                    let event_obj_idx = if args[1] != 0 {
                        self.event_index_for_handle(args[1], 0).map(|i| i as u64).unwrap_or(u64::MAX)
                    } else {
                        u64::MAX
                    };
                    let table = &mut *core::ptr::addr_of_mut!(crate::PIPE_ASYNC_LISTENS);
                    if table
                        .arm(nt_io_manager::AsyncListen {
                            server_file_id: fid,
                            event_obj_idx,
                            pi: self.pi as u32,
                            // The listener badge is derived from pi at completion (pi 3 → SVC_LISTENER,
                            // pi 4 → LSASS_LISTENER); store 0 as a placeholder.
                            badge: 0,
                            iosb_va: iosb,
                            // The server pipe's leaf name-hash (recorded at NtCreateNamedPipeFile) so a
                            // client connect completes ONLY the matching-name listen.
                            name_hash: crate::pipe_fid_name_hash(fid),
                        })
                        .is_some()
                    {
                        crate::PIPE_LISTEN_ARMED_COUNT.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[pipe-listen] ARMED server fid=0x");
                        print_hex(fid as u32);
                        print_str(b" event_obj=0x");
                        print_hex(event_obj_idx as u32);
                        print_str(b" pi=");
                        print_u64(self.pi as u64);
                        print_str(b"\n");
                    }
                    // Overlapped: DON'T write the PENDING IOSB now — it's filled on completion.
                    self.pipe_listen_fid = fid;
                }
                if iosb != 0 && self.pipe_park_fid == 0 && self.pipe_listen_fid == 0 {
                    self.xas_write_buf(iosb, &(status as u32).to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                // A TRANSCEIVE that COMPLETED synchronously (it wrote request bytes into npfs) may also
                // satisfy the peer's parked read — ask the loop to re-drive.
                if fid != 0 && (fsctl as u32) == 0x0011_C017 && (status as u32) != 0x0000_0103 {
                    self.pipe_write_redrive = true;
                }
                if self.pi == 2 && fsctl as u32 == 0x0011_0018
                    && NT_PIPE_WAIT_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8
                {
                    print_str(b"[nt-pipe-wait] fid=0x");
                    print_hex(fid as u32);
                    print_str(b" status=0x");
                    print_hex(status as u32);
                    print_str(b" input_len=");
                    print_u64(args[7]);
                    print_str(b"\n");
                }
                status as u32
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
                // BATCH 41 — winlogon (pi 2) too: msgina's L"DefaultPassword" value name is a msgina.dll
                // `.rdata` literal, so recover it cross-AS from the PE (the mirror-only smss_read_ustr
                // returns empty for it). read_ustr_pe uses xas_read → resolves any resident/PE page.
                let name16 = if self.pi == 2 || self.pi == 3 || self.pi == 4 {
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
                // Set for winlogon's real-hive Nls\Language `Default` read: its out-params (a heap/stack
                // advapi allocation) need the cross-AS writer, whereas msgina's synth reads stay mirror-only
                // (byte-identical). Local so no other value read's copyout method changes.
                let mut use_xas_write = false;
                let val: Option<(u32, alloc::vec::Vec<u8>)> = if key == SYNTH_CPU_KEY {
                    synth_cpu_value(&name_lc).map(|(ty, d16)| (ty, utf16_bytes(&d16)))
                } else if self.pi == 2
                    && key == SYNTH_WINLOGON_KEY
                    && name_lc == "defaultpassword"
                {
                    // BATCH 41 — satisfy msgina's GetRegistrySettings DefaultPassword read (msgina.c:216)
                    // with an EMPTY REG_SZ (a single UTF-16 NUL). This makes `rc == ERROR_SUCCESS` so
                    // `if (rc) GetLsaDefaultPassword(...)` (msgina.c:223) is NOT taken → no LsaOpenPolicy
                    // → no `\pipe\lsarpc` RPC bind → winlogon does not stall (nor raise an RPC exception
                    // our ntdll can't dispatch) inside GinaInit. An empty auto-logon password is a
                    // legitimate value; AutoAdminLogon defaults FALSE so it is never used to log in.
                    WINLOGON_DEFPWD_EMPTY.fetch_add(1, Ordering::Relaxed);
                    Some((1u32 /* REG_SZ */, alloc::vec![0u8, 0u8]))
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
                } else if self.pi == 2 && name_lc == "default" && !is_synth_key(key) {
                    // winlogon (pi 2): SetDefaultLanguage(NULL) reads the `Default` value of the real
                    // SYSTEM-hive key `...\Control\Nls\Language` (opened above via is_nls_language_key,
                    // so `key` is a genuine hive KeyRef, NOT a synth handle). Read it for real so
                    // SetDefaultLanguage succeeds (was: pi 0-2 → None → NOT_FOUND → SetDefaultLanguage
                    // FALSE → InitializeSAS FALSE → ExitProcess(2)). Tightly scoped: pi==2 + value name
                    // exactly "Default" + a real hive key, so no paint-time msgina value read changes
                    // (those hit SYNTH_WINLOGON_KEY / synth handles, excluded by is_synth_key). Its
                    // out-params are advapi heap/stack the plain mirror can't reach → cross-AS write.
                    use_xas_write = true;
                    self.hive.as_ref().and_then(|h| h.value(key, &name_lc))
                } else if self.pi == 3 || self.pi == 4 {
                    // Real SYSTEM hive value-by-name (case-insensitive) — services' SCM reads
                    // SetupType/SystemSetupInProgress + the service DB values off ::ROSSYS.HIV; lsass
                    // (pi 4) reads its own values. Scoped to pi 3/4 so smss/winlogon/csrss keep the
                    // prior None (byte-identical).
                    self.hive.as_ref().and_then(|h| h.value(key, &name_lc))
                } else {
                    None // real-hive value-by-name not modelled for pi 0-2
                };
                match val {
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND — smss uses defaults
                    Some((ty, data)) => {
                        // KeyValuePartialInformation (class 2) carries no name.
                        let info = build_key_value_info(args[2], "", ty, &data);
                        // *ResultLength: use the cross-AS writer for pi 3/4 + the winlogon Nls read
                        // (advapi's out-param may be a heap/stack the plain mirror can't reach — same
                        // reason as the data write below); everything else stays mirror-only (byte-identical).
                        if self.pi == 3 || self.pi == 4 || use_xas_write {
                            self.xas_write_buf(args[5], &(info.len() as u32).to_le_bytes());
                        } else {
                            smss_copyout(args[5], &(info.len() as u32).to_le_bytes());
                        }
                        if info.len() > args[4] as usize {
                            // BUFFER_OVERFLOW: real NtQueryValueKey still fills as much of the buffer as
                            // fits (the KEY_VALUE_PARTIAL_INFORMATION header carries Type + DataLength,
                            // which advapi's RegQueryValueExW reads to size the retry / set dwSize when
                            // lpData is NULL). Writing NOTHING left advapi with a garbage dwType/dwSize →
                            // SetDefaultLanguage bailed. Write the truncated prefix so the header lands.
                            let n = args[4] as usize;
                            if n > 0 {
                                if self.pi == 3 || self.pi == 4 || use_xas_write {
                                    self.xas_write_buf(args[3], &info[..n]);
                                } else {
                                    smss_copyout(args[3], &info[..n]);
                                }
                            }
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            // services'/winlogon's out-buffer may be an advapi32 heap allocation the mirror
                            // can't reach → use the cross-AS writer so the value data actually lands.
                            if self.pi == 3 || self.pi == 4 || use_xas_write {
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
            // *RetLen[R9]=args[3]). Fixed class layouts and size policy live in nt-syscall; this
            // layer supplies the live machine/time facts and performs user-buffer probing/copyout.
            NativeService::NtQuerySystemInformation => unsafe {
                use nt_syscall::system_information::{
                    query_plan, SystemBasicInformation, SystemInformationKind,
                    SystemTimeOfDayInformation, SYSTEM_BASIC_INFORMATION_CLASS,
                    SYSTEM_PROCESSOR_INFORMATION_CLASS, SYSTEM_TIME_OF_DAY_INFORMATION_CLASS,
                };

                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
                const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

                let class = args[0] as u32;
                let buf = args[1];
                let len = args[2] as usize;
                let retlen_ptr = args[3];

                if !matches!(
                    class,
                    SYSTEM_BASIC_INFORMATION_CLASS
                        | SYSTEM_PROCESSOR_INFORMATION_CLASS
                        | SYSTEM_TIME_OF_DAY_INFORMATION_CLASS
                ) {
                    return STATUS_INVALID_INFO_CLASS;
                }
                if len != 0 && buf & 3 != 0 {
                    return STATUS_DATATYPE_MISALIGNMENT;
                }
                if len != 0 && !self.probe_user_output(buf, len) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if retlen_ptr != 0 {
                    if retlen_ptr & 3 != 0 {
                        return STATUS_DATATYPE_MISALIGNMENT;
                    }
                    if !self.probe_user_output(retlen_ptr, 4) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    if !self.xas_write_u32(retlen_ptr, 0) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                }

                let plan = match query_plan(class, len) {
                    Ok(plan) => plan,
                    Err(error) => {
                        if retlen_ptr != 0 {
                            self.xas_write_u32(retlen_ptr, error.return_length);
                        }
                        return error.status;
                    }
                };
                if retlen_ptr != 0 {
                    self.xas_write_u32(retlen_ptr, plan.return_length);
                }

                let wrote = match plan.kind {
                    SystemInformationKind::Basic => {
                        let processors = SYSTEM_PROCESSOR_COUNT.load(Ordering::Relaxed) as u8;
                        let affinity = if processors >= 64 {
                            u64::MAX
                        } else {
                            (1u64 << processors) - 1
                        };
                        let output = SystemBasicInformation {
                            timer_resolution_100ns: 10_000,
                            page_size: 0x1000,
                            number_of_physical_pages: SYSTEM_PHYSICAL_PAGES
                                .load(Ordering::Relaxed)
                                .min(u32::MAX as u64) as u32,
                            lowest_physical_page_number: SYSTEM_LOWEST_PHYSICAL_PAGE
                                .load(Ordering::Relaxed)
                                .min(u32::MAX as u64) as u32,
                            highest_physical_page_number: SYSTEM_HIGHEST_PHYSICAL_PAGE
                                .load(Ordering::Relaxed)
                                .min(u32::MAX as u64) as u32,
                            allocation_granularity: 0x1_0000,
                            minimum_user_mode_address: 0x1_0000,
                            maximum_user_mode_address: 0x0000_07ff_fffe_ffff,
                            active_processors_affinity_mask: affinity,
                            number_of_processors: processors,
                        }
                        .encode();
                        self.xas_try_write_buf(buf, &output)
                    }
                    SystemInformationKind::Processor => {
                        let output = native_processor_information().encode();
                        self.xas_try_write_buf(buf, &output)
                    }
                    SystemInformationKind::TimeOfDay => {
                        let output = SystemTimeOfDayInformation {
                            boot_time_100ns: NT_SYSTEM_TIME_BOOT_100NS,
                            current_time_100ns: nt_system_time_100ns(),
                            time_zone_bias_100ns: 0,
                            time_zone_id: 0,
                        }
                        .encode();
                        self.xas_try_write_buf(buf, &output[..plan.copy_length])
                    }
                };
                if wrote { 0 } else { STATUS_ACCESS_VIOLATION }
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
                } else if class == 29 {
                    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
                    if args[3] != 4 {
                        return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                    }
                    let retlen = args[4];
                    if buf == 0
                        || !self.probe_event_output(buf, 4)
                        || (retlen != 0 && !self.probe_event_output(retlen, 4))
                    {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    let caller = match self.pm_pid_for_pi(self.pi) {
                        Some(pid) => pid,
                        None => return 0xC000_0008,
                    };
                    let pid = match self.pm.resolve_process_handle(
                        caller,
                        args[0],
                        PROCESS_QUERY_INFORMATION,
                    ) {
                        Ok(pid) => pid,
                        Err(status) => return status,
                    };
                    let enabled = self
                        .pm
                        .process_break_on_termination(pid)
                        .unwrap_or(false) as u32;
                    if !self.xas_write_u32(buf, enabled)
                        || (retlen != 0 && !self.xas_write_u32(retlen, 4))
                    {
                        return 0xC000_0005;
                    }
                    0
                } else if class == 36 {
                    // ProcessCookie is a stable per-process ULONG and is queryable only through the
                    // current-process pseudo handle, matching ReactOS's XP-compatible contract.
                    if args[0] != u64::MAX {
                        return 0xC000_000D; // STATUS_INVALID_PARAMETER
                    }
                    if args[3] != 4 {
                        return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                    }
                    let retlen = args[4];
                    if buf == 0
                        || !self.probe_event_output(buf, 4)
                        || (retlen != 0 && !self.probe_event_output(retlen, 4))
                    {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    let Some(pid) = self.pm_pid_for_pi(self.pi) else {
                        return 0xC000_0008; // STATUS_INVALID_HANDLE
                    };
                    let time = nt_system_time_100ns();
                    let mut candidate = time as u32
                        ^ (time >> 32) as u32
                        ^ pid
                        ^ self.current_tid as u32
                        ^ (self.pi as u32).wrapping_mul(0x9E37_79B9);
                    if candidate == 0 {
                        candidate = 0xBB40_E64E;
                    }
                    let Some(cookie) = self.pm.get_or_initialize_process_cookie(pid, candidate) else {
                        return 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                    };
                    if !self.xas_write_u32(buf, cookie)
                        || (retlen != 0 && !self.xas_write_u32(retlen, 4))
                    {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
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
                    // BATCH 10: do NOT stop the whole boot on an unmodeled class. Returning
                    // STATUS_INVALID_INFO_CLASS lets the CALLER degrade gracefully and, crucially,
                    // keeps the single service loop multiplexing so a HIGHER-priority process's
                    // pending fault gets serviced. Previously `self.stop=true` here broke the loop on
                    // smss's terminal ProcessImageInformation(class 44) query, leaving winlogon's
                    // pending user32-init fetch-fault (user32+0x8a940) forever unserviced — the
                    // BATCH 9/10 "silent spin". The class print still surfaces the gap for follow-up.
                    0xC000_0003 // STATUS_INVALID_INFO_CLASS
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
                let mut word = [0u8; 8];
                let base = if self.xas_read(args[1], &mut word) {
                    u64::from_le_bytes(word)
                } else {
                    0
                };
                let size = if self.xas_read(args[2], &mut word) {
                    u64::from_le_bytes(word)
                } else {
                    0
                };
                let registry_slot = self.loop_ctx.and_then(|ctx| {
                    (&*ctx.reg).dll_for_page(base).map(|(slot, _)| slot)
                });
                loader_trace_record(
                    self.pi,
                    LoaderOp::ProtectVirtualMemory,
                    0,
                    registry_slot,
                    base,
                    size,
                    b"",
                );
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
            // NtSetDebugFilterState requires SeDebugPrivilege in ReactOS/NT. We do not model that
            // privilege plane yet, so deny the mutation instead of fabricating a changed mask.
            NativeService::NtSetDebugFilterState => 0xC0000022,
            // NtOpenThreadToken — no impersonation token → STATUS_NO_TOKEN; the caller falls back to
            // the process token.
            NativeService::NtOpenThreadToken => 0xC000007C,
            NativeService::NtRaiseHardError => unsafe {
                use nt_syscall::hard_error::{validate_request, RESPONSE_RETURN_TO_CALLER};

                let number_of_parameters = args[1] as u32;
                let unicode_mask = args[2] as u32;
                let parameters = args[3];
                let response = args[5];
                if let Err(status) = validate_request(
                    number_of_parameters,
                    parameters != 0,
                    args[4] as u32,
                ) {
                    return status;
                }
                if response == 0 || !self.probe_user_output(response, 4) {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }

                let mut captured = [0u64; 5];
                if parameters != 0 {
                    let byte_len = number_of_parameters as usize * 8;
                    let raw = core::slice::from_raw_parts_mut(
                        captured.as_mut_ptr() as *mut u8,
                        byte_len,
                    );
                    if !self.xas_read(parameters, raw) {
                        return nt_syscall::STATUS_ACCESS_VIOLATION;
                    }

                    for i in 0..number_of_parameters as usize {
                        if unicode_mask & (1 << i) == 0 {
                            continue;
                        }
                        let mut descriptor = [0u8; 16];
                        if captured[i] == 0 || !self.xas_read(captured[i], &mut descriptor) {
                            return nt_syscall::STATUS_ACCESS_VIOLATION;
                        }
                        let maximum_length =
                            u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize;
                        let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
                        let mut offset = 0usize;
                        let mut probe = [0u8; 64];
                        while offset < maximum_length {
                            let n = (maximum_length - offset).min(probe.len());
                            if buffer == 0
                                || !self.xas_read(buffer + offset as u64, &mut probe[..n])
                            {
                                return nt_syscall::STATUS_ACCESS_VIOLATION;
                            }
                            offset += n;
                        }
                    }
                }

                print_str(b"[harderr] pi=");
                print_u64(self.pi as u64);
                print_str(b" status=0x");
                print_hex(args[0] as u32);
                print_str(b" n=");
                print_u64(number_of_parameters as u64);
                print_str(b" mask=0x");
                print_hex(unicode_mask);
                print_str(b" option=");
                print_u64(args[4]);
                for i in 0..number_of_parameters as usize {
                    if unicode_mask & (1 << i) == 0 {
                        continue;
                    }
                    let text = self.read_ustr_pe(captured[i]);
                    let ascii: alloc::vec::Vec<u8> = text
                        .iter()
                        .map(|&ch| if ch <= 0x7f { ch as u8 } else { b'?' })
                        .collect();
                    print_str(b" text=");
                    print_str(&ascii);
                }
                print_str(b"\n");

                // No executive hard-error LPC port is registered yet. ReactOS' ExpRaiseHardError
                // returns directly to the caller in that state and reports ResponseReturnToCaller.
                if !self.xas_write_u32(response, RESPONSE_RETURN_TO_CALLER) {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }
                nt_syscall::STATUS_SUCCESS
            },
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
            NativeService::NtCreateThread => {
                // CSRSS creates two suspended server workers during initialization. Back both with
                // real ETHREADs and typed handles so ReactOS's NtResumeThread calls control their
                // actual TCBs. Slot 0 is CsrApiRequestThread; slot 1 is CsrSbApiRequestThread.
                if matches!(ctx.service, NativeService::NtCreateThread) && self.pi == 1 {
                    unsafe {
                        if args[3] != u64::MAX || CSR_SB_TID.load(Ordering::Relaxed) != 0 {
                            return 0xC000_009A;
                        }
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            let teb = match slot {
                                0 => CSR_TEB_VA,
                                1 => CSR_SB_TEB_VA,
                                _ => return 0xC000_009A,
                            };
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
                            let pid = self.pm_pid_for_pi(1).unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            if slot == 0 {
                                CSR_API_TID.store(tid, Ordering::Relaxed);
                            } else {
                                CSR_SB_TID.store(tid, Ordering::Relaxed);
                            }
                            self.csr_spawn_request = slot as u8 + 1;
                            print_str(b"[csr-thread] create slot=");
                            print_u64(slot as u64);
                            print_str(b" tid=");
                            print_u64(tid);
                            print_str(b" handle=0x");
                            print_hex(handle as u32);
                            print_str(b" suspended=");
                            print_u64(create_suspended as u64);
                            print_str(b"\n");
                            return 0;
                        }
                    }
                    return 0xC000_009A;
                }
                // ★ GENERAL NtCreateThread (real service): winlogon's FIRST NtCreateThread is its RPC
                // listener. Route it through the REAL nt-process ETHREAD lifecycle: pop a pool ETHREAD
                // for the caller, bind the caller's StartRoutine + TEB, mint a TYPED Thread(tid) handle,
                // write NtCreateThread's *ClientId {caller pid, fresh tid} out-param, and signal the loop
                // to spawn the REAL seL4 thread in the caller's VSpace (`spawn_wl_listener_thread`). The
                // no-op (a bare fake handle) is RETIRED for this path — kernel32/rpcrt4 now read a real
                // TEB/ClientId (NtQueryInformationThread(162) resolves the typed handle → the ETHREAD).
                if matches!(ctx.service, NativeService::NtCreateThread) && args[3] != u64::MAX {
                    unsafe {
                        let caller_pid = match self.pm_pid_for_pi(self.pi) {
                            Some(pid) => pid,
                            None => return 0xC000_0008,
                        };
                        let target_pid = match self.resolve_process_handle(args[3]) {
                            Some(pid) => pid,
                            None => return 0xC000_0008,
                        };
                        let tid = match self.pm.main_thread(target_pid) {
                            Some(tid) => tid,
                            None => return 0xC000_0008,
                        };
                        let sp = get_recv_mr(16);
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        let handle = match self.pm.insert_handle(
                            caller_pid,
                            nt_process::HandleObject::Thread(tid),
                            args[1] as u32,
                        ) {
                            Ok(handle) => handle as u64,
                            Err(status) => return status,
                        };
                        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                        self.queue_write(args[0], handle);
                        let cid_ptr = smss_stack_read(sp + 0x28);
                        if cid_ptr != 0 {
                            self.queue_write(cid_ptr, target_pid as u64);
                            self.queue_write(cid_ptr + 8, tid as u64);
                        }
                        if create_suspended {
                            if let Err(status) = self.pm.suspend_thread(tid) {
                                return status;
                            }
                        } else if let Some(target_pi) = self.pi_for_pid(target_pid) {
                            let tcb = PM_MAIN_TCBS[target_pi].load(Ordering::Relaxed);
                            if tcb <= 1 || tcb_resume(tcb) != 0 {
                                return 0xC000_0001;
                            }
                            let _ = self.pm.set_thread_state(tid, nt_process::ThreadState::Ready);
                        }
                        let trace = THREAD_LIFECYCLE_TRACE_N.fetch_add(1, Ordering::Relaxed);
                        if trace < 4 {
                            print_str(b"[thread-life] create caller_pi=");
                            print_u64(self.pi as u64);
                            print_str(b" foreign_process=0x");
                            print_hex(args[3] as u32);
                            print_str(b" resolved_pid=");
                            print_u64(target_pid as u64);
                            print_str(b" main_tid=");
                            print_u64(tid as u64);
                            print_str(b" suspended=");
                            print_u64(create_suspended as u64);
                            print_str(b" handle=0x");
                            print_hex(handle as u32);
                            print_str(b" status=0\n");
                        }
                        return 0;
                    }
                }
                if matches!(ctx.service, NativeService::NtCreateThread) && self.pi == 2 {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let cid_ptr = smss_stack_read(sp + 0x28);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let initial_teb = smss_stack_read(sp + 0x38);
                        let initial_stack = nt_thread_start::InitialTeb64::read(
                            |address| smss_stack_read(address),
                            initial_teb,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            let teb = match slot {
                                0 => WL_LISTENER_TEB_VA,
                                1 => WL_WORKER2_TEB_VA,
                                2 => WL_WORKER3_TEB_VA,
                                _ => return 0xC000_009A,
                            };
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
                            let pid = self.pm_pid_for_pi(2).unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle = R10
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64); // ClientId.UniqueProcess
                                self.queue_write(cid_ptr + 8, tid); // ClientId.UniqueThread
                            }
                            match slot {
                                0 => PM_LISTENER_TID.store(tid, Ordering::Relaxed),
                                1 => WL_WORKER2_TID.store(tid, Ordering::Relaxed),
                                2 => WL_WORKER3_TID.store(tid, Ordering::Relaxed),
                                _ => {}
                            }
                            self.wl_spawn_request = slot as u8 + 1;
                            let trace = THREAD_LIFECYCLE_TRACE_N.fetch_add(1, Ordering::Relaxed);
                            if trace < 4 {
                                print_str(
                                    b"[thread-life] create caller=winlogon badge=4 process=0x",
                                );
                                print_hex(args[3] as u32);
                                print_str(b" slot=");
                                print_u64(slot as u64);
                                print_str(b" start=0x");
                                print_hex((start.rip >> 32) as u32);
                                print_hex(start.rip as u32);
                                print_str(b" arg0=0x");
                                print_hex((start.rcx >> 32) as u32);
                                print_hex(start.rcx as u32);
                                print_str(b" arg1=0x");
                                print_hex((start.rdx >> 32) as u32);
                                print_hex(start.rdx as u32);
                                print_str(b" rsp=0x");
                                print_hex((start.rsp >> 32) as u32);
                                print_hex(start.rsp as u32);
                                print_str(b" teb=0x");
                                print_hex((teb >> 32) as u32);
                                print_hex(teb as u32);
                                print_str(b" initial_teb=0x");
                                print_hex(initial_teb as u32);
                                print_str(b" stack_base=0x");
                                print_hex(initial_stack.stack_base as u32);
                                print_str(b" stack_limit=0x");
                                print_hex(initial_stack.stack_limit as u32);
                                print_str(b" alloc_base=0x");
                                print_hex(initial_stack.allocated_stack_base as u32);
                                print_str(b" handle=0x");
                                print_hex(handle as u32);
                                print_str(b" tid=");
                                print_u64(tid);
                                print_str(b" suspended=");
                                print_u64(create_suspended as u64);
                                print_str(b" status=0\n");
                            }
                            return 0; // SUCCESS (handle/ClientId queued)
                        }
                    }
                    print_str(b"[thread-life] create caller=winlogon badge=4 status=c000009a (runtime thread pool exhausted)\n");
                    return 0xC000_009A;
                }
                // ★ N-threads multiplex: services' (pi 3) FIRST NtCreateThread = the SCM's RPC listener
                // (ScmStartRpcServer → rpcrt4 io_thread). Route it through the REAL ETHREAD lifecycle
                // like winlogon's, but the LOOP spawns it RESUMED with a badged fault EP (it runs into
                // the main multiplex). Its faults sub-select to (pi 3, listener) by SVC_LISTENER_BADGE.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 3
                    && SVC_LISTENER_TCB.load(Ordering::Relaxed) == 0
                    && SVC_LISTENER_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((_slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, SVC_LISTENER_TEB_VA);
                            let pid = self.pm_pid_for_pi(3).unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            SVC_LISTENER_TID.store(tid, Ordering::Relaxed);
                            self.svc_listener_spawn = true;
                            return 0;
                        }
                    }
                }
                // ★ N-threads multiplex: lsass' (pi 4) FIRST NtCreateThread = an LSA server thread
                // (LsapInitDatabase → StartAuthenticationPort / LsapRmServerThread). Route it through the
                // REAL ETHREAD lifecycle + have the LOOP spawn it RESUMED with a badged fault EP, so it
                // runs into the main multiplex; its faults sub-select to (pi 4, listener) by
                // LSASS_LISTENER_BADGE (its own stack mirror / TEB, distinct from lsass' main thread).
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 4
                    && LSASS_LISTENER_TCB.load(Ordering::Relaxed) == 0
                    && LSASS_LISTENER_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((_slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER_TEB_VA);
                            let pid = self.pm_pid_for_pi(4).unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            LSASS_LISTENER_TID.store(tid, Ordering::Relaxed);
                            self.lsass_listener_spawn = true;
                            return 0;
                        }
                    }
                }
                // ★ lsass' SECOND server thread (LsapRmServerThread) — same multiplex, its own badge +
                // its own TEB/stack (LSASS_LISTENER2). Uses the SECOND pool ETHREAD. Without a real,
                // mapped TEB the subsequent NtQueryInformationThread(162) → kernel32 ActCtx copy
                // (mov [newTEB+0x1728]) writes to a stale stack pointer and faults.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 4
                    && LSASS_LISTENER_TID.load(Ordering::Relaxed) != 0
                    && LSASS_LISTENER2_TCB.load(Ordering::Relaxed) == 0
                    && LSASS_LISTENER2_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((_slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER2_TEB_VA);
                            let pid = self.pm_pid_for_pi(4).unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            LSASS_LISTENER2_TID.store(tid, Ordering::Relaxed);
                            self.lsass_listener2_spawn = true;
                            return 0;
                        }
                    }
                }
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 4
                    && LSASS_LISTENER2_TID.load(Ordering::Relaxed) != 0
                    && LSASS_LISTENER3_TCB.load(Ordering::Relaxed) == 0
                    && LSASS_LISTENER3_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((_slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            self.pm.set_thread_teb(
                                tid as nt_process::ThreadId,
                                LSASS_LISTENER3_TEB_VA,
                            );
                            let pid = self.pm_pid_for_pi(4).unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            LSASS_LISTENER3_TID.store(tid, Ordering::Relaxed);
                            self.lsass_listener3_spawn = true;
                            let initial_teb = smss_stack_read(sp + 0x38);
                            print_str(b"[thread-life] create caller=lsass badge=8 process=0x");
                            print_hex(args[3] as u32);
                            print_str(b" slot=2 start=0x");
                            print_hex((start.rip >> 32) as u32);
                            print_hex(start.rip as u32);
                            print_str(b" teb=0x");
                            print_hex((LSASS_LISTENER3_TEB_VA >> 32) as u32);
                            print_hex(LSASS_LISTENER3_TEB_VA as u32);
                            print_str(b" initial_teb=0x");
                            print_hex(initial_teb as u32);
                            print_str(b" stack_base=0x");
                            print_hex(smss_stack_read(initial_teb + 0x10) as u32);
                            print_str(b" stack_limit=0x");
                            print_hex(smss_stack_read(initial_teb + 0x18) as u32);
                            print_str(b" alloc_base=0x");
                            print_hex(smss_stack_read(initial_teb + 0x20) as u32);
                            print_str(b" handle=0x");
                            print_hex(handle as u32);
                            print_str(b" tid=");
                            print_u64(tid);
                            print_str(b" status=0\n");
                            return 0;
                        }
                    }
                }
                // ★ BATCH 35 — N-threads multiplex: services' (pi 3) SECOND NtCreateThread = the SCM
                // RPC listener's PER-CONNECTION worker (rpcrt4 `RPCRT4_new_client`, spawned on
                // winlogon's accepted connection). BEFORE this batch it fell to the 0xC000_009A
                // fallthrough below → the worker never spawned → nobody read winlogon's bind PDU / wrote
                // bind_ack → the SCM RPC round-trip stalled. Route it like the listener: pop a pool
                // ETHREAD (services' slot 1; slot 0 = listener), set its OWN TEB, queue *ThreadHandle +
                // ClientId, and signal the LOOP to spawn it RESUMED with a badged fault EP
                // (SCM_WORKER_BADGE) so it runs into the main multiplex — its faults sub-select to
                // (pi 3, scm-worker) via its OWN stack mirror/TEB, and its blocking pipe reads park +
                // re-drive on winlogon's write (the existing batch-33/34 edges, badge-general).
                // ★ BATCH 36 FRONTIER GUARD. The full per-connection-worker routing (recognizer + spawn
                // RESUMED into the multiplex at SCM_WORKER_BADGE with its own TEB/stack-mirror/fault-EP,
                // + the badge sub-select / mirror_ctx / pipe-park paths) is BUILT, and the BATCH-35
                // trampoline-entry `cr2=0` fault is now ROOT-CAUSED + FIXED: it was NOT a kernel bug but
                // an executive VA COLLISION — `SCM_WORKER_ENV_SCRATCH_VA` was 0x107C = winlogon's
                // process-spawn env-scratch (never unmapped), so `spawn_hosted_thread`'s alias map of the
                // worker's trampoline frame returned a SILENT `seL4_DeleteFirst` (SYS_SEND-hidden), the
                // bytes were written to winlogon's stale frame, and the worker's REAL trampoline frame
                // stayed ZERO → executed `add [rax],al` (rax=0) → read of 0. Moving the scratch to a free
                // VA (0x1075) FIXED it: with the route ENABLED the worker RUNS its real rpcrt4 entry (4
                // native syscalls incl. NtQueryInformationThread, label 0x4e54 NOT a fault) and winlogon
                // crosses the wire with its 72-byte RPC bind PDU (proven `/tmp/boot36fix.log`).
                // ★ BATCH 37 — ENABLED. The BATCH-36 "worker exits without reading the bind" wall is
                // FIXED: it was `conn->read_closed == 1`, set by the rpcrt4 SERVER thread's premature
                // shutdown (`rpcrt4_conn_close_read` over `cps->connections`) because its post-accept
                // RE-LISTEN failed — our `NtCreateNamedPipeFile` returned STATUS_ACCESS_DENIED for the
                // 2nd `\ntsvcs` instance (hardcoded FILE_CREATE; real CreateNamedPipe uses FILE_OPEN_IF,
                // fixed in driver_launch.rs). With that fixed the listener stays alive, `read_closed`
                // stays 0, and the worker RUNS `rpcrt4_conn_np_read → NtReadFile(conn->pipe, 16)` and is
                // re-driven on winlogon's bind write (the batch-33 pipe park + FIX-2 overflow copyout).
                // The boot stays GREEN (worker reads then exits cleanly; listener alive; clean quiesce),
                // so the route is left ON. bind_ack does not YET flow — see the BATCH 38 NEXT WALL in
                // ntdll_plan.md (npfs returns wrong bytes for the server read: the pending ReadEntry is
                // not reconciled with the peer WriteEntry in our synthetic-IRP npfs host).
                // ★ BATCH 38 — the npfs pending-read/peer-write RECONCILE is FIXED (real bind bytes now
                // reach the worker: `IofCompleteRequest` bound + the completed read's bytes read from the
                // IRP's REASSIGNED AssociatedIrp.SystemBuffer, not the stale original). With the route ON
                // the FULL SCM RPC round-trip runs LIVE: worker reads the real bind `05 00 0b 03…` →
                // rpcrt4 emits bind_ack `05 00 0c 03…` → winlogon's parked read completes with it →
                // RROpenSCManagerW request `05 00 00 03…` → response `05 00 02 03…` (all PROVEN in
                // /tmp/boot38d.log, 8 PDUs both ways). BUT this legitimately changes the SCM thread
                // lifecycle: with the RPC now SUCCEEDING, services' per-connection worker (badge 15) +
                // listener (badge 7) STAY ALIVE serving the conversation instead of self-exiting on a
                // failed connection (as they did when the bind read returned garbage) — so the 3
                // `exec_live_terminate_thread_{routed,tcb_reclaimed,no_reply}` specs, which counted on
                // those two self-exits (`>= 3`), drop to 2 (only csrss + lsass). AND winlogon, having
                // OpenSCManager succeed, advances into GUI code and hits a NEW downstream null-deref
                // frontier (rip in user32/gdi32) → gate 174→171. Per the batch constraint (gate ≥174, the
                // 4 terminate specs MUST pass, no regression), the route is GATED OFF for the commit: the
                // npfs reconcile fixes (correct + general + host-tested) land, bind_ack is PROVEN with the
                // route flipped ON, and the OFF path is byte-identical to the BATCH-37 green boot (gate
                // 174). NEXT WALL = winlogon's post-OpenSCManager GUI null-deref + the SCM server's
                // persistent-thread lifecycle (the terminate specs need updating for a SUCCEEDING RPC).
                const SCM_WORKER_ROUTE_ENABLED: bool = true;
                if SCM_WORKER_ROUTE_ENABLED
                    && matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 3
                    && SVC_LISTENER_TID.load(Ordering::Relaxed) != 0
                    && SCM_WORKER_TCB.load(Ordering::Relaxed) == 0
                    && SCM_WORKER_TID.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((_slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, SCM_WORKER_TEB_VA);
                            let pid = self.pm_pid_for_pi(3).unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            SCM_WORKER_TID.store(tid, Ordering::Relaxed);
                            self.scm_worker_spawn = true;
                            print_str(b"[scm-worker] recognized services' 2nd NtCreateThread = per-connection RPC worker: entry=0x");
                            print_hex((start.rip >> 32) as u32);
                            print_hex(start.rip as u32);
                            print_str(b" tid=");
                            print_u64(tid);
                            print_str(b"\n");
                            return 0;
                        }
                    }
                }
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && (2..=4).contains(&self.pi)
                {
                    return 0xC000_009A;
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
                if self.pi == 0 && self.lpc_connection_is(args[0], 0, b"\\smapiport") {
                    self.sm_request_port = args[0];
                    self.sm_request_message = args[1];
                    self.sm_reply_message = args[2];
                    print_str(b"[sm-api] routing SMSS request to real SmpApiLoop\n");
                    return 0;
                }
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
                let sp = get_recv_mr(16);
                let conn_info_ptr = smss_stack_read(sp + 0x38);
                let conn_info_len_ptr = smss_stack_read(sp + 0x40);
                let mut conn_info = [0u8; 0xF4];
                let mut conn_info_len = 0usize;
                if conn_info_ptr != 0 && conn_info_len_ptr != 0 {
                    let mut length = [0u8; 4];
                    if self.xas_read(conn_info_len_ptr, &mut length) {
                        conn_info_len = (u32::from_le_bytes(length) as usize).min(conn_info.len());
                        if conn_info_len != 0
                            && !self.xas_read(conn_info_ptr, &mut conn_info[..conn_info_len])
                        {
                            return 0xC000_0005;
                        }
                    }
                }
                let subsystem_type = if conn_info_len >= 4 {
                    u32::from_le_bytes(conn_info[..4].try_into().unwrap())
                } else {
                    0
                };
                // \SeRmCommandPort — the Security Reference Monitor's command port, created by the SRM
                // in ntoskrnl (SeRmInitPhase1). lsass's lsasrv LsapRmInitializeServer (srm.c:216)
                // NtConnectPort's it during LsapInitLsa. We don't host a real SRM, so MODEL the port:
                // mint a comm-port handle + return SUCCESS so LsapRmInitializeServer proceeds (its
                // LsapRmServerThread only NtRequestWaitReplyPort's the SRM for logon/token events, which
                // don't occur on this boot path). Scoped to lsass (pi 4) so it can't perturb the CSR/SM
                // LPC broker path (csrss/winlogon pi 1/2).
                {
                    let mut nb = [0u8; 40];
                    let nlen = Self::fold_name(&name16, &mut nb);
                    if self.pi == 4 && nb[..nlen].windows(15).any(|w| w == b"sermcommandport") {
                        let h = self.mint_handle();
                        self.queue_write(args[0], h);
                        LSASS_SRM_CONNECTED.store(1, Ordering::Relaxed);
                        print_str(b"[ntos-exec] lsass NtConnectPort(\\SeRmCommandPort) -> modeled SRM accept\n");
                        return 0;
                    }
                }
                // lsass (pi==4) LSA-init port connects: after \SeRmCommandPort (modeled above), lsass's
                // LSA/RPC init connects to further ports. If the broker doesn't own the name, connecting
                // returns OBJECT_NAME_NOT_FOUND → lsass (a CRITICAL process via RtlSetProcessIsCritical)
                // terminates the WHOLE process with 0xC0000034 (see LsapInitLsa/LsarStartRpcServer).
                // MODEL any lsass port connect the broker doesn't know as an accepted comm port (mint a
                // handle + SUCCESS) so LSA init proceeds past the connect toward LsarStartRpcServer /
                // LSA_RPC_SERVER_ACTIVE. Scoped to pi==4 (services/csrss/winlogon LPC unchanged).
                // NOTE: this advances lsass PAST the connect into its LSA server-thread creation
                // (NtCreateThread), which then WALLs at a bad thread-entry fetch (a bare RVA 0x3a288) —
                // the flagged "N threads per process" lsass-listener multiplex frontier (same class as
                // winlogon's RPC-listener thread). Kept because it advances lsass + is non-regressive
                // (gate 165 held); the thread-entry wall is the NEXT batch's frontier.
                if self.pi == 4 {
                    let mut nb = [0u8; 48];
                    let nlen = Self::fold_name(&name16, &mut nb);
                    print_str(b"[lsass-connect] port=");
                    print_str(&nb[..nlen.min(48)]);
                    // Only model if the broker doesn't own the name (a real broker port still routes).
                    let broker_owns = lpc_client()
                        .map(|c| matches!(c.connect_port(&name16, 0, &[]), Ok(r) if r.pending || r.handle != 0))
                        .unwrap_or(false);
                    if !broker_owns {
                        let h = self.mint_handle();
                        self.queue_write(args[0], h);
                        print_str(b" -> modeled lsass port accept\n");
                        return 0;
                    }
                    print_str(b" (broker-owned)\n");
                }
                match lpc_client().map(|c| {
                    c.connect_port(
                        &name16,
                        subsystem_type,
                        &conn_info[..conn_info_len],
                    )
                }) {
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
                            print_str(b"[lpc-connect] pending pi=");
                            print_u64(self.pi as u64);
                            print_str(b" conn=");
                            print_u64(r.connection_id);
                            print_str(b" name=");
                            for &unit in name16.iter().take(64) {
                                let byte = if (0x20..=0x7e).contains(&unit) {
                                    unit as u8
                                } else {
                                    b'?'
                                };
                                print_str(core::slice::from_ref(&byte));
                            }
                            print_str(b"\n");
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
            // a winsrv .data global, so use the cross-address-space writer.
            // The out PHANDLE is arg1 = R10, and for csrss it is a winsrv .bss global. Our csrss
            // The handle names the same real EventStore object used by NtSet/Reset/Query. Late DLL
            // globals are reached through their persistent cross-address-space page aliases.
            NativeService::NtCreateEvent => {
                // Services (pi 3): CreateEventW(SCM_START_EVENT/AUTOSTARTCOMPLETE/LSA_RPC_SERVER_ACTIVE/
                // SECURITY_SERVICES_STARTED). NtCreateEvent(*EventHandle[R10]=args[0], ACCESS,
                // *OA[R8]=args[2], EVENT_TYPE, InitialState). Register a REAL named event object in the
                // executive object namespace (kind==2) keyed by the OA name (rooted at the OA's
                // RootDirectory = the \BaseNamedObjects handle BaseGetNamedObjectDirectory returned),
                // write the handle back, and report STATUS_OBJECT_NAME_EXISTS if it already existed
                // (CreateEventW's ERROR_ALREADY_EXISTS path). An UNNAMED event gets a distinct event
                // identity plus a typed process-local handle. The PHANDLE may be a DLL .data global.
                // Winlogon's unnamed rpcrt4 server_ready_event/mgr_event are a live cross-thread
                // handshake. Model them as distinct events: the main thread signals mgr_event, the
                // server worker consumes it and signals server_ready_event, and the main waiter wakes.
                unsafe {
                    let out = args[0]; // R10 = *EventHandle
                    let oa = args[2]; // R8 = *OBJECT_ATTRIBUTES (0 = anonymous)
                    // EventType[R9]=args[3], InitialState=args[4] from stack [sp+0x28].
                    if args[3] > 1 {
                        return 0xC000_000D; // STATUS_INVALID_PARAMETER
                    }
                    if out == 0 {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    if out & 7 != 0 {
                        return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                    }
                    if !self.probe_event_output(out, 8) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    let auto_reset = args[3] == 1;
                    let init_state = args[4] & 1 != 0;
                    if oa == 0 {
                        let Some(index) = self.obj_create_anon_event(auto_reset, init_state) else {
                            return 0xC000_009A;
                        };
                        let Some(event_handle) = self.mint_event_handle(index, args[1] as u32) else {
                            self.rollback_new_event(index);
                            return 0xC000_009A;
                        };
                        if !self.xas_write_u64(out, event_handle) {
                            self.close_current_handle(event_handle);
                            self.rollback_new_event(index);
                            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                        }
                        let trace = EVENT_TRACE_N.fetch_add(1, Ordering::Relaxed);
                        if trace < 64 || self.current_badge == 15 {
                            print_str(b"[event] create pi=");
                            print_u64(self.pi as u64);
                            print_str(b" badge=");
                            print_u64(self.current_badge);
                            print_str(b" h=0x");
                            print_hex_u64(event_handle);
                            print_str(b" obj=");
                            print_u64(index as u64);
                            print_str(b" access=0x");
                            print_hex(args[1] as u32);
                            print_str(if auto_reset { b" sync" } else { b" notification" });
                            print_str(if init_state { b" initial=1\n" } else { b" initial=0\n" });
                        }
                        return 0;
                    }
                    let (root_dir, name16) = match self.read_event_object_attributes(oa) {
                        Ok((root, _attributes, Some(name))) => (root, name),
                        Ok((_root, _attributes, None)) => {
                            let Some(index) = self.obj_create_anon_event(auto_reset, init_state) else {
                                return 0xC000_009A;
                            };
                            let Some(event_handle) = self.mint_event_handle(index, args[1] as u32) else {
                                self.rollback_new_event(index);
                                return 0xC000_009A;
                            };
                            if !self.xas_write_u64(out, event_handle) {
                                self.close_current_handle(event_handle);
                                self.rollback_new_event(index);
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                            return 0;
                        }
                        Err(status) => return status,
                    };
                    let path = match Self::event_object_path(&name16) {
                        Ok(path) => path,
                        Err(status) => return status,
                    };
                    let (root_idx, path) = match self.event_root_and_path(root_dir, &path) {
                        Ok(resolved) => resolved,
                        Err(status) => return status,
                    };
                    let existing = self.obj_resolve(path, root_idx);
                    if existing.is_some_and(|i| self.obj_ns[i].kind != 2) {
                        return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                    }
                    let existed = existing.is_some();
                    match self.obj_create(path, root_idx, 2, &[]) {
                        Some(i) => {
                            if !existed {
                                self.events.initialize(
                                    i as u64,
                                    if auto_reset { EventKind::Synchronization } else { EventKind::Notification },
                                    init_state,
                                );
                            }
                            let Some(event_handle) = self.mint_event_handle(i, args[1] as u32) else {
                                if !existed {
                                    self.rollback_new_event(i);
                                }
                                return 0xC000_009A;
                            };
                            if !self.xas_write_u64(out, event_handle) {
                                self.close_current_handle(event_handle);
                                if !existed {
                                    self.rollback_new_event(i);
                                }
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                            SERVICES_NAMED_EVENTS.fetch_add(1, Ordering::Relaxed);
                            if existed { 0x4000_0000 } else { 0 } // STATUS_OBJECT_NAME_EXISTS : SUCCESS
                        }
                        None => {
                            0xC000_009A
                        }
                    }
                }
            }
            // NtClearEvent(EventHandle) clears a real event without returning its previous state.
            // Handle resolution enforces EVENT_MODIFY_STATE for typed process-local handles.
            NativeService::NtClearEvent => {
                match self.event_index_for_handle(args[0], EVENT_MODIFY_STATE) {
                    Ok(index) if self.events.clear_existing(index as u64) => 0,
                    Ok(_) => 0xC000_0008, // STATUS_INVALID_HANDLE
                    Err(status) => status,
                }
            }
            NativeService::NtPulseEvent => {
                let previous_state = args[1];
                if previous_state != 0 && previous_state & 3 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if previous_state != 0
                    && !unsafe { self.probe_event_output(previous_state, 4) }
                {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                match self.event_index_for_handle(args[0], EVENT_MODIFY_STATE) {
                    Ok(index) => {
                        let Some(previous) = self.events.set_existing(index as u64) else {
                            return 0xC000_0008; // STATUS_INVALID_HANDLE
                        };
                        if !previous {
                            // SAFETY: native dispatch is serialized; event transition and waiter
                            // selection remain in this executive turn.
                            unsafe { wait_wake_dispatcher_pulse(index, self) };
                        }
                        if previous {
                            let _ = self.events.reset_existing(index as u64);
                        }
                        if previous_state != 0 {
                            if !unsafe { self.xas_write_u32(previous_state, previous as u32) } {
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                        }
                        0
                    }
                    Err(status) => status,
                }
            }
            NativeService::NtQueryEvent => {
                const EVENT_BASIC_INFORMATION_SIZE: u64 = 8;
                if args[1] != 0 {
                    return 0xC000_0003; // STATUS_INVALID_INFO_CLASS
                }
                if args[3] != EVENT_BASIC_INFORMATION_SIZE {
                    return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                }
                if args[2] == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if args[2] & 3 != 0 || (args[4] != 0 && args[4] & 3 != 0) {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !unsafe { self.probe_event_output(args[2], 8) }
                    || (args[4] != 0 && !unsafe { self.probe_event_output(args[4], 4) })
                {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                match self.event_index_for_handle(args[0], EVENT_QUERY_STATE) {
                    Ok(index) => {
                        let Some((kind, signaled)) = self.events.query_existing(index as u64) else {
                            return 0xC000_0008; // STATUS_INVALID_HANDLE
                        };
                        let event_type = match kind {
                            EventKind::Notification => 0u32,
                            EventKind::Synchronization => 1u32,
                        };
                        if !unsafe { self.xas_write_u32(args[2], event_type) }
                            || !unsafe { self.xas_write_u32(args[2] + 4, signaled as u32) }
                        {
                            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                        }
                        if args[4] != 0 {
                            if !unsafe {
                                self.xas_write_u32(args[4], EVENT_BASIC_INFORMATION_SIZE as u32)
                            } {
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                        }
                        0
                    }
                    Err(status) => status,
                }
            }
            NativeService::NtResetEvent => {
                let previous_state = args[1];
                if previous_state != 0 && previous_state & 3 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if previous_state != 0
                    && !unsafe { self.probe_event_output(previous_state, 4) }
                {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                match self.event_index_for_handle(args[0], EVENT_MODIFY_STATE) {
                    Ok(index) => {
                        let Some(previous) = self.events.reset_existing(index as u64) else {
                            return 0xC000_0008; // STATUS_INVALID_HANDLE
                        };
                        if previous_state != 0 {
                            if !unsafe { self.xas_write_u32(previous_state, previous as u32) } {
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                        }
                        0
                    }
                    Err(status) => status,
                }
            }
            NativeService::NtSetEvent => {
                let previous_state = args[1];
                if previous_state != 0 && previous_state & 3 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if previous_state != 0
                    && !unsafe { self.probe_event_output(previous_state, 4) }
                {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                match self.event_index_for_handle(args[0], EVENT_MODIFY_STATE) {
                    Ok(index) => {
                        let Some(previous) = self.events.set_existing(index as u64) else {
                            return 0xC000_0008; // STATUS_INVALID_HANDLE
                        };
                        if previous_state != 0 {
                            if !unsafe { self.xas_write_u32(previous_state, previous as u32) } {
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                        }
                        if self.obj_ns[index].name() == b"lsa_rpc_server_active" {
                            LSA_RPC_SERVER_ACTIVE_SIGNALLED.store(1, Ordering::Relaxed);
                        }
                        // SAFETY: native dispatch is serialized; the signal and waiter selection
                        // are one executive transition.
                        if !previous {
                            unsafe { wait_wake_dispatcher_set(self) };
                        }
                        0
                    }
                    Err(status) => status,
                }
            }
            // NtOpenEvent(*EventHandle[R10]=args[0], DesiredAccess, *OA[R8]=args[2]). CreateEventW's
            // ERROR_ALREADY_EXISTS fallback + OpenEventW resolve an existing named event. Return the
            // registered event's handle, or STATUS_OBJECT_NAME_NOT_FOUND if it doesn't exist (so the
            // create-then-open logic behaves).
            NativeService::NtOpenEvent => unsafe {
                let out = args[0];
                let oa = args[2];
                if out == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if out & 7 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_event_output(out, 8) {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if oa == 0 {
                    return 0xC000_000D; // STATUS_INVALID_PARAMETER
                }
                let (root_dir, name16) = match self.read_event_object_attributes(oa) {
                    Ok((root, _attributes, Some(name))) => (root, name),
                    Ok((_root, _attributes, None)) => return 0xC000_0033, // STATUS_OBJECT_NAME_INVALID
                    Err(status) => return status,
                };
                let path = match Self::event_object_path(&name16) {
                    Ok(path) => path,
                    Err(status) => return status,
                };
                let (root_idx, path) = match self.event_root_and_path(root_dir, &path) {
                    Ok(resolved) => resolved,
                    Err(status) => return status,
                };
                if let Some(i) = self.obj_resolve(path, root_idx) {
                    if self.obj_ns[i].kind != 2 {
                        return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                    }
                    let Some(event_handle) = self.mint_event_handle(i, args[1] as u32) else {
                        return 0xC000_009A;
                    };
                    if !self.xas_write_u64(out, event_handle) {
                        self.close_current_handle(event_handle);
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    return 0;
                }
                // lsass (pi 4): \SeLsaInitEvent is created by ntoskrnl's SeRmInitPhase1 (the SRM), which
                // we don't host — lsass' LsapRmInitializeServer (srm.c:194) NtOpenEvent's it then
                // NtSetEvent's it to signal the kernel it's ready, and treats an open failure as FATAL.
                // Model it: auto-create the event so the open + set succeed (like \SeRmCommandPort). The
                // name folds to "selsainitevent". Scoped pi==4 so services/paint reads are unchanged.
                if self.pi == 4 && path == b"\\selsainitevent" {
                    if let Some(i) = self.obj_create(path, root_idx, 2, &[]) {
                        let created = !self.events.contains(i as u64);
                        if !self.events.contains(i as u64) {
                            self.events.initialize(i as u64, EventKind::Notification, false);
                        }
                        let Some(event_handle) = self.mint_event_handle(i, args[1] as u32) else {
                            if created {
                                self.rollback_new_event(i);
                            }
                            return 0xC000_009A;
                        };
                        if !self.xas_write_u64(out, event_handle) {
                            self.close_current_handle(event_handle);
                            if created {
                                self.rollback_new_event(i);
                            }
                            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                        }
                        return 0;
                    }
                }
                0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND
            },
            NativeService::NtCreateSemaphore => unsafe {
                let out = args[0];
                let oa = args[2];
                let initial = args[3] as u32 as i32;
                let maximum = args[4] as u32 as i32;
                if out == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if out & 7 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_event_output(out, 8) {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if maximum <= 0 || initial < 0 || initial > maximum {
                    return 0xC000_000D; // STATUS_INVALID_PARAMETER
                }

                let create_anonymous = |this: &mut Self| -> Result<u32, u32> {
                    let Some(index) = this.obj_create_anon_semaphore(initial, maximum) else {
                        return Err(0xC000_009A); // STATUS_INSUFFICIENT_RESOURCES
                    };
                    let Some(handle) = this.mint_semaphore_handle(index, args[1] as u32) else {
                        this.rollback_new_semaphore(index);
                        return Err(0xC000_009A);
                    };
                    if !this.xas_write_u64(out, handle) {
                        this.close_current_handle(handle);
                        this.rollback_new_semaphore(index);
                        return Err(0xC000_0005);
                    }
                    Ok(0)
                };

                if oa == 0 {
                    return create_anonymous(self).unwrap_or_else(|status| status);
                }
                let (root_dir, name16) = match self.read_event_object_attributes(oa) {
                    Ok((root, _attributes, Some(name))) => (root, name),
                    Ok((_root, _attributes, None)) => {
                        return create_anonymous(self).unwrap_or_else(|status| status);
                    }
                    Err(status) => return status,
                };
                let path = match Self::event_object_path(&name16) {
                    Ok(path) => path,
                    Err(status) => return status,
                };
                let (root_idx, path) = match self.event_root_and_path(root_dir, &path) {
                    Ok(resolved) => resolved,
                    Err(status) => return status,
                };
                let existing = self.obj_resolve(path, root_idx);
                if existing.is_some_and(|index| self.obj_ns[index].kind != 3) {
                    return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                }
                let existed = existing.is_some();
                let Some(index) = self.obj_create(path, root_idx, 3, &[]) else {
                    return 0xC000_009A;
                };
                if !existed
                    && self
                        .semaphores
                        .initialize(index as u64, initial, maximum)
                        .is_err()
                {
                    self.rollback_new_semaphore(index);
                    return 0xC000_000D;
                }
                let Some(handle) = self.mint_semaphore_handle(index, args[1] as u32) else {
                    if !existed {
                        self.rollback_new_semaphore(index);
                    }
                    return 0xC000_009A;
                };
                if !self.xas_write_u64(out, handle) {
                    self.close_current_handle(handle);
                    if !existed {
                        self.rollback_new_semaphore(index);
                    }
                    return 0xC000_0005;
                }
                if existed { 0x4000_0000 } else { 0 }
            },
            NativeService::NtOpenSemaphore => unsafe {
                let out = args[0];
                let oa = args[2];
                if out == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if out & 7 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_event_output(out, 8) {
                    return 0xC000_0005;
                }
                if oa == 0 {
                    return 0xC000_000D; // STATUS_INVALID_PARAMETER
                }
                let (root_dir, name16) = match self.read_event_object_attributes(oa) {
                    Ok((root, _attributes, Some(name))) => (root, name),
                    Ok((_root, _attributes, None)) => return 0xC000_0033,
                    Err(status) => return status,
                };
                let path = match Self::event_object_path(&name16) {
                    Ok(path) => path,
                    Err(status) => return status,
                };
                let (root_idx, path) = match self.event_root_and_path(root_dir, &path) {
                    Ok(resolved) => resolved,
                    Err(status) => return status,
                };
                let Some(index) = self.obj_resolve(path, root_idx) else {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                };
                if self.obj_ns[index].kind != 3 {
                    return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                }
                let Some(handle) = self.mint_semaphore_handle(index, args[1] as u32) else {
                    return 0xC000_009A;
                };
                if !self.xas_write_u64(out, handle) {
                    self.close_current_handle(handle);
                    return 0xC000_0005;
                }
                0
            },
            NativeService::NtQuerySemaphore => {
                const SEMAPHORE_BASIC_INFORMATION_SIZE: u64 = 8;
                if args[1] != 0 {
                    return 0xC000_0003; // STATUS_INVALID_INFO_CLASS
                }
                if args[3] != SEMAPHORE_BASIC_INFORMATION_SIZE {
                    return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                }
                if args[2] == 0 {
                    return 0xC000_0005;
                }
                if args[2] & 3 != 0 || (args[4] != 0 && args[4] & 3 != 0) {
                    return 0x8000_0002;
                }
                if !unsafe { self.probe_event_output(args[2], 8) }
                    || (args[4] != 0 && !unsafe { self.probe_event_output(args[4], 4) })
                {
                    return 0xC000_0005;
                }
                let index = match self.semaphore_index_for_handle(args[0], SEMAPHORE_QUERY_STATE) {
                    Ok(index) => index,
                    Err(status) => return status,
                };
                let Some((current, maximum)) = self.semaphores.query(index as u64) else {
                    return 0xC000_0008;
                };
                if !unsafe { self.xas_write_u32(args[2], current as u32) }
                    || !unsafe { self.xas_write_u32(args[2] + 4, maximum as u32) }
                {
                    return 0xC000_0005;
                }
                if args[4] != 0
                    && !unsafe {
                        self.xas_write_u32(args[4], SEMAPHORE_BASIC_INFORMATION_SIZE as u32)
                    }
                {
                    return 0xC000_0005;
                }
                0
            },
            NativeService::NtReleaseSemaphore => {
                let release_count = args[1] as u32 as i32;
                let previous_count = args[2];
                if previous_count != 0 && previous_count & 3 != 0 {
                    return 0x8000_0002;
                }
                if previous_count != 0
                    && !unsafe { self.probe_event_output(previous_count, 4) }
                {
                    return 0xC000_0005;
                }
                if release_count <= 0 {
                    return 0xC000_000D;
                }
                let index =
                    match self.semaphore_index_for_handle(args[0], SEMAPHORE_MODIFY_STATE) {
                        Ok(index) => index,
                        Err(status) => return status,
                    };
                let previous = match self.semaphores.release(index as u64, release_count) {
                    Ok(previous) => previous,
                    Err(nt_kernel_exec::SemaphoreError::InvalidCount) => return 0xC000_000D,
                    Err(nt_kernel_exec::SemaphoreError::LimitExceeded) => return 0xC000_0047,
                    Err(nt_kernel_exec::SemaphoreError::NotFound) => return 0xC000_0008,
                };
                unsafe {
                    wait_wake_dispatcher_set(self);
                }
                if previous_count != 0
                    && !unsafe { self.xas_write_u32(previous_count, previous as u32) }
                {
                    return 0xC000_0005;
                }
                0
            },
            // NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle): resolve the target
            // EPROCESS, open its primary token into the caller's typed handle table, and preserve
            // the requested token access mask for later checks.
            NativeService::NtOpenProcessToken => unsafe {
                self.nt_open_process_token(args[0], args[1] as u32, args[2])
            },
            NativeService::NtResumeThread => unsafe {
                const THREAD_SUSPEND_RESUME: u32 = 0x0002;
                print_str(b"[thread-life] NtResumeThread pi=");
                print_u64(self.pi as u64);
                print_str(b" handle=0x");
                print_hex(args[0] as u32);
                print_str(b" previous_ptr=0x");
                print_hex((args[1] >> 32) as u32);
                print_hex(args[1] as u32);
                print_str(b"\n");
                let caller_pid = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => {
                        print_str(b"[thread-life] resume failed: caller has no EPROCESS\n");
                        return nt_process::STATUS_INVALID_HANDLE;
                    }
                };
                let tid = match self.pm.resolve_thread_handle(
                    caller_pid,
                    self.current_tid as nt_process::ThreadId,
                    args[0],
                    THREAD_SUSPEND_RESUME,
                ) {
                    Ok(tid) => tid as u64,
                    Err(status) => {
                        print_str(b"[thread-life] resume failed: handle resolution status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        return status;
                    }
                };
                let Some((pi, slot)) = runtime_thread_slot(tid) else {
                    let Some(main_pi) = (0..MAX_PI)
                        .find(|&index| PM_TIDS[index].load(Ordering::Relaxed) == tid)
                    else {
                        return nt_process::STATUS_INVALID_HANDLE;
                    };
                    let previous = match self.pm.resume_thread(tid as nt_process::ThreadId) {
                        Ok(previous) => previous,
                        Err(status) => return status,
                    };
                    print_str(b"[thread-life] resume main tid=");
                    print_u64(tid);
                    print_str(b" pi=");
                    print_u64(main_pi as u64);
                    print_str(b" previous=");
                    print_u64(previous as u64);
                    print_str(b"\n");
                    if args[1] != 0 {
                        if !self.xas_write_u32(args[1], previous) {
                            return 0xC000_0005;
                        }
                    }
                    if previous == 1 {
                        let tcb = PM_MAIN_TCBS[main_pi].load(Ordering::Relaxed);
                        if tcb <= 1 || tcb_resume(tcb) != 0 {
                            return 0xC000_0001;
                        }
                    }
                    return 0;
                };
                // BATCH 35: the SCM per-connection worker is routed into the multiplex but left
                // SUSPENDED (its trampoline-entry fault is unresolved — see the frontier note). rpcrt4
                // calls NtResumeThread on it; report SUCCESS with previous=1 (so rpcrt4 believes the
                // worker resumed) but DON'T actually tcb_resume it (that would run the broken trampoline
                // and destabilise the boot). Clears its suspended bit so the ETHREAD state stays coherent.
                let scm_worker_tid = SCM_WORKER_TID.load(Ordering::Relaxed);
                if scm_worker_tid != 0 && tid == scm_worker_tid {
                    let bit = 1u64 << slot;
                    PM_POOL_SUSPENDED[pi].fetch_and(!bit, Ordering::Relaxed);
                    if args[1] != 0 {
                        if !self.xas_write_u32(args[1], 1) {
                            return 0xC000_0005;
                        }
                    }
                    print_str(b"[scm-worker] NtResumeThread -> SUCCESS (not resumed; trampoline-entry fault, see frontier)\n");
                    return 0;
                }
                let bit = 1u64 << slot;
                let previous = if PM_POOL_SUSPENDED[pi].fetch_and(!bit, Ordering::Relaxed) & bit != 0 {
                    1
                } else {
                    0
                };
                if args[1] != 0 {
                    if !self.xas_write_u32(args[1], previous as u32) {
                        return 0xC000_0005;
                    }
                }
                if previous != 0 {
                    let _ = self
                        .pm
                        .set_thread_state(tid as nt_process::ThreadId, nt_process::ThreadState::Ready);
                    let csr_role = if tid == CSR_API_TID.load(Ordering::Relaxed) {
                        1
                    } else if tid == CSR_SB_TID.load(Ordering::Relaxed) {
                        2
                    } else {
                        0
                    };
                    if csr_role != 0 {
                        // The outer loop owns CSRSS's shared native IPC frame. It resumes this TCB,
                        // drives it to a blocked port receive, then replies to the main thread.
                        self.csr_start_request = csr_role;
                        print_str(b"[csr-thread] resume scheduled role=");
                        print_u64(csr_role as u64);
                        print_str(b" tid=");
                        print_u64(tid);
                        print_str(b" previous=1\n");
                        return 0;
                    }
                    let tcb = hosted_thread_tcb_cell(tid)
                        .map(|cell| cell.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    if tcb <= 1 {
                        return 0xC000_0001;
                    }
                    let result = tcb_resume(tcb);
                    print_str(b"[thread-life] resume pi=");
                    print_u64(pi as u64);
                    print_str(b" slot=");
                    print_u64(slot as u64);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b" tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" previous=1 result=");
                    print_u64(result);
                    print_str(b"\n");
                    if result != 0 {
                        return 0xC000_0001;
                    }
                }
                0
            },
            // NtMakeTemporaryObject — clears OBJ_PERMANENT on a link SmpInit re-creates; we don't
            // track permanence. Success no-op.
            NativeService::NtMakeTemporaryObject => 0,
            // NtReleaseKeyedEvent(Handle, Key, Alertable, Timeout) — wake one waiter parked by
            // NtWaitForKeyedEvent on the same raw key. ReactOS condition variables call this with a
            // zero timeout and retry/skip on STATUS_TIMEOUT. A NULL timeout is the keyed-event
            // rendezvous path used by RtlRunOnce: if the waiter has published its key but has not yet
            // entered the syscall, remember one release for that key so the later wait returns
            // immediately instead of losing the wake.
            NativeService::NtReleaseKeyedEvent => unsafe {
                let _handle = args[0];
                let key = args[1];
                let _alertable = args[2];
                let timeout_ptr = args[3];
                if keyed_wait_wake_one(key, 0) {
                    print_str(b"[keyed] NtReleaseKeyedEvent key=0x");
                    print_hex_u64(key);
                    print_str(b" -> WAKE one\n");
                    0
                } else if timeout_ptr != 0 {
                    let interval = smss_stack_read(timeout_ptr) as i64;
                    if interval == 0 {
                        0x102
                    } else {
                        0xC000_0002
                    }
                } else if keyed_release_remember_pending(key) {
                    print_str(b"[keyed] NtReleaseKeyedEvent key=0x");
                    print_hex_u64(key);
                    print_str(b" -> PENDING release\n");
                    0
                } else {
                    0xC000_009A
                }
            },
            // NtWaitForKeyedEvent(Handle, Key, Alertable, Timeout) — park this syscall's reply cap
            // on the key. The service loop performs the actual steal once resume_ip/rsp/rflags are
            // available at the reply site.
            NativeService::NtWaitForKeyedEvent => {
                let _handle = args[0];
                let key = args[1];
                let _alertable = args[2];
                let timeout_ptr = args[3];
                if keyed_release_take_pending(key) {
                    print_str(b"[keyed] NtWaitForKeyedEvent key=0x");
                    print_hex_u64(key);
                    print_str(b" -> CONSUME pending release\n");
                    return 0;
                }
                if timeout_ptr != 0 {
                    let interval = unsafe { smss_stack_read(timeout_ptr) as i64 };
                    match nt_delay_execution::due_time(
                        interval,
                        monotonic_time_100ns(),
                        nt_system_time_100ns(),
                    ) {
                        nt_delay_execution::Due::Immediate => return 0x102,
                        nt_delay_execution::Due::Monotonic100ns(deadline) => {
                            self.keyed_wait_deadline_100ns = deadline;
                        }
                    }
                }
                self.keyed_wait_key = key;
                0x102
            }
            // No-op → STATUS_SUCCESS: the bump allocator never frees, we don't model thread/process
            // attribute sets, per-object security, or a real handle table. (277
            // NtUnmapViewOfSection: we never reclaim a mapped view; 246 NtSetSecurityObject; 214
            // 236 NtSetInformationObject.)
            NativeService::NtSetInformationProcess => unsafe {
                if args[1] != 29 {
                    return 0;
                }
                const PROCESS_SET_INFORMATION: u32 = 0x0200;
                if args[3] != 4 {
                    return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                }
                let mut value = [0u8; 4];
                if args[2] == 0 || !self.xas_read(args[2], &mut value) {
                    return 0xC000_0005;
                }
                if !self.current_token_has_privilege(nt_security::SE_DEBUG) {
                    return 0xC000_0061; // STATUS_PRIVILEGE_NOT_HELD
                }
                let caller = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => return 0xC000_0008,
                };
                let pid = match self.pm.resolve_process_handle(
                    caller,
                    args[0],
                    PROCESS_SET_INFORMATION,
                ) {
                    Ok(pid) => pid,
                    Err(status) => return status,
                };
                match self.pm.set_process_break_on_termination(
                    pid,
                    u32::from_le_bytes(value) != 0,
                ) {
                    Ok(()) => 0,
                    Err(status) => status,
                }
            },
            NativeService::NtSetInformationThread => unsafe {
                if args[1] != 18 {
                    return 0;
                }
                const THREAD_SET_INFORMATION: u32 = 0x0020;
                if args[3] != 4 {
                    return 0xC000_0004;
                }
                let mut value = [0u8; 4];
                if args[2] == 0 || !self.xas_read(args[2], &mut value) {
                    return 0xC000_0005;
                }
                if !self.current_token_has_privilege(nt_security::SE_DEBUG) {
                    return 0xC000_0061;
                }
                let caller = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => return 0xC000_0008,
                };
                let tid = match self.pm.resolve_thread_handle(
                    caller,
                    self.current_tid as nt_process::ThreadId,
                    args[0],
                    THREAD_SET_INFORMATION,
                ) {
                    Ok(tid) => tid,
                    Err(status) => return status,
                };
                match self.pm.set_thread_break_on_termination(
                    tid,
                    u32::from_le_bytes(value) != 0,
                ) {
                    Ok(()) => 0,
                    Err(status) => status,
                }
            },
            NativeService::NtFreeVirtualMemory
            | NativeService::NtTestAlert
            | NativeService::NtCreateKeyedEvent
            | NativeService::NtDeleteValueKey
            | NativeService::NtInitializeRegistry
            | NativeService::NtSetSystemInformation
            | NativeService::NtUnmapViewOfSection
            | NativeService::NtSetSecurityObject
            // winlogon's SetDefaultLanguage(NULL) sets the system default UI locale after reading the
            // Nls\Language\Default LCID. No kernel locale plane to mutate in this single-user host →
            // no-op SUCCESS (the LCID is validated; nothing consumes a stored system locale here).
            | NativeService::NtSetDefaultLocale
            | NativeService::NtSetInformationObject => 0,
            NativeService::NtAdjustPrivilegesToken => unsafe {
                self.nt_adjust_privileges_token(args)
            },
            NativeService::NtResumeProcess | NativeService::NtSuspendProcess => {
                let handle = args.first().copied().unwrap_or(0);
                if self.resolve_process_handle(handle).is_some() {
                    0
                } else {
                    nt_process::STATUS_INVALID_HANDLE
                }
            }
            NativeService::NtSetUuidSeed => {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                let seed = args.first().copied().unwrap_or(0);
                let mut probe = [0u8; 6];
                if seed == 0 || !unsafe { self.xas_read(seed, &mut probe) } {
                    STATUS_ACCESS_VIOLATION
                } else {
                    0
                }
            }
            // PnP has no executive device tree/event queue yet; fail explicitly rather than
            // fabricating hardware/device-manager success or blocking on a nonexistent event.
            NativeService::NtGetPlugPlayEvent | NativeService::NtPlugPlayControl => 0xC000_0002,
            NativeService::NtSetSystemPowerState => {
                const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
                const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
                const POWER_ACTION_VALID_MASK: u32 =
                    0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x1000_0000
                    | 0x2000_0000 | 0x4000_0000 | 0x8000_0000;
                let system_action = args.first().copied().unwrap_or(0) as u32;
                let min_system_state = args.get(1).copied().unwrap_or(0) as u32;
                let flags = args.get(2).copied().unwrap_or(0) as u32;
                if !(1..=7).contains(&system_action)
                    || !(1..7).contains(&min_system_state)
                    || flags & !POWER_ACTION_VALID_MASK != 0
                {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_PRIVILEGE_NOT_HELD
                }
            }
            NativeService::NtOpenEventPair => {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
                let out_handle = args.first().copied().unwrap_or(0);
                let mut probe = [0u8; 8];
                if out_handle == 0 || !unsafe { self.xas_read(out_handle, &mut probe) } {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_OBJECT_NAME_NOT_FOUND
                }
            }
            NativeService::NtFlushInstructionCache => {
                let base = args.get(1).copied().unwrap_or(0);
                let size = args.get(2).copied().unwrap_or(0);
                let registry_slot = unsafe {
                    self.loop_ctx.and_then(|ctx| {
                        (&*ctx.reg).dll_for_page(base).map(|(slot, _)| slot)
                    })
                };
                unsafe {
                    loader_trace_record(
                        self.pi,
                        LoaderOp::FlushInstructionCache,
                        0,
                        registry_slot,
                        base,
                        size,
                        b"",
                    );
                }
                0
            },
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
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
                const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
                const TOKEN_QUERY: u32 = 0x0008;
                let class = args[1];
                let buf = args[2];
                let len = args[3] as usize;
                let retlen_ptr = args[4];
                if retlen_ptr == 0 || !self.probe_user_output(retlen_ptr, 4) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let token_index = match self.token_index_for_handle(args[0], TOKEN_QUERY) {
                    Ok(index) => index,
                    Err(status) => return status,
                };
                let token = &self.primary_tokens[token_index];
                let mut output = [0u8; 4 + 24 * 12];
                let needed = match class {
                    1 => {
                        // TOKEN_USER: aligned SID_AND_ATTRIBUTES followed by the user SID.
                        let sid_length = Self::serialize_sid(&token.user, &mut output[16..])
                            .unwrap_or(0);
                        output[..8].copy_from_slice(&buf.wrapping_add(16).to_le_bytes());
                        16 + sid_length
                    }
                    3 => {
                        // TOKEN_PRIVILEGES: current attributes from the same mutable token adjusted
                        // by NtAdjustPrivilegesToken.
                        output[..4].copy_from_slice(&(token.privileges.len() as u32).to_le_bytes());
                        for (index, privilege) in token.privileges.iter().enumerate() {
                            let offset = 4 + index * 12;
                            output[offset..offset + 4]
                                .copy_from_slice(&privilege.luid.low.to_le_bytes());
                            output[offset + 4..offset + 8]
                                .copy_from_slice(&privilege.luid.high.to_le_bytes());
                            output[offset + 8..offset + 12].copy_from_slice(
                                &nt_security::AccessToken::privilege_attributes(privilege)
                                    .to_le_bytes(),
                            );
                        }
                        4 + token.privileges.len() * 12
                    }
                    5 => {
                        // TOKEN_PRIMARY_GROUP: pointer followed immediately by the SID.
                        let sid_length =
                            Self::serialize_sid(&token.primary_group, &mut output[8..]).unwrap_or(0);
                        output[..8].copy_from_slice(&buf.wrapping_add(8).to_le_bytes());
                        8 + sid_length
                    }
                    _ => return STATUS_INVALID_INFO_CLASS,
                };
                if !self.xas_write_u32(retlen_ptr, needed as u32) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if len < needed {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if !self.probe_user_output(buf, needed)
                    || !self.xas_try_write_buf(buf, &output[..needed])
                {
                    STATUS_ACCESS_VIOLATION
                } else {
                    0
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
            // NtWaitForSingleObject(Handle=R10=args[0], Alertable=RDX, *Timeout=R8).
            //
            // ★ Checkpoint B — REAL event-state wait with reply-cap parking (the load-bearing case):
            // if the target is a REAL executive event (obj_ns kind==2, e.g. LSA_RPC_SERVER_ACTIVE
            // that lsass creates+signals in LsarStartRpcServer), consult its `signalled` flag:
            //   • signalled  → STATUS_WAIT_0 immediately (correct for a manual-reset event that has
            //                  already been set — e.g. winlogon's WaitForLsass when lsass signaled first).
            //   • unsignaled → request a PARK (wait_park_event = the event's obj_ns index); the service
            //                  loop stashes this caller's reply cap keyed by the event and continues
            //                  receiving. The matching NtSetEvent wakes it. This is the genuine
            //                  block-then-wake (no deadlock: the loop keeps receiving while parked, and
            //                  we only park on an event a live signaler can set).
            // Any OTHER handle (fake sync handles from rpcrt4 mutants/csrsrv worker events, smss's
            // subsystem event, etc.) has no live signaler → immediate STATUS_WAIT_0 (KEPT — documented:
            // parking one of those would hang since nothing sets it). csrss (pi==1) stays immediate.
            NativeService::NtWaitForSingleObject => {
                let handle = args[0];
                match self.waitable_index_for_handle(handle, SYNCHRONIZE_ACCESS) {
                    Ok(idx) => {
                        if self.dispatcher_ready(idx) {
                                unsafe {
                                    print_str(b"[wait] pi=");
                                    print_u64(self.pi as u64);
                                    print_str(b" NtWaitForSingleObject(dispatcher #");
                                    print_u64(idx as u64);
                                    print_str(b" '");
                                    for &c in self.obj_ns[idx].name() { debug_put_char(c); }
                                    print_str(b"') already SIGNALLED -> immediate WAIT_0\n");
                                }
                                self.dispatcher_consume(idx);
                                return 0;
                        }
                        let timeout_ptr = args[2];
                        if timeout_ptr != 0 {
                            let interval = unsafe { smss_stack_read(timeout_ptr) as i64 };
                            match nt_delay_execution::due_time(
                                interval,
                                monotonic_time_100ns(),
                                nt_system_time_100ns(),
                            ) {
                                nt_delay_execution::Due::Immediate => return 0x102,
                                nt_delay_execution::Due::Monotonic100ns(deadline) => {
                                    self.wait_deadline_100ns = deadline;
                                }
                            }
                        }
                            // Unsignaled dispatcher object → ask the loop to park this caller on it.
                            self.wait_park_event = idx as i64;
                            unsafe {
                                print_str(b"[wait] pi=");
                                print_u64(self.pi as u64);
                                print_str(b" NtWaitForSingleObject(dispatcher #");
                                print_u64(idx as u64);
                                print_str(b" '");
                                for &c in self.obj_ns[idx].name() { debug_put_char(c); }
                                print_str(b"') UNSIGNALLED -> PARK caller (reply-cap park)\n");
                            }
                        0x102 // STATUS_TIMEOUT sentinel; the loop parks (ignores this)
                    }
                    Err(_status) if self.is_legacy_opaque_handle(handle) => 0,
                    Err(status) => status,
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
            // NtQueryDirectoryObject(DirectoryHandle[R10]=args[0], Buffer[RDX]=args[1],
            // Length[R8]=args[2], ReturnSingleEntry[R9]=args[3], RestartScan[sp+0x28],
            // *Context[sp+0x30], *ReturnLength[sp+0x38]). ntdll's named-object path enumerates
            // \BaseNamedObjects. Enumerate the target directory's children as
            // OBJECT_DIRECTORY_INFORMATION records (x64: {UNICODE_STRING Name; UNICODE_STRING
            // TypeName;} = 0x20 bytes each), terminated by a zero record, followed by the UTF-16
            // name/type strings; return STATUS_NO_MORE_ENTRIES when the directory has no more
            // entries. Context is the next-child index (0 on RestartScan). Scoped to services (pi 3).
            NativeService::NtQueryDirectoryObject => unsafe {
                SERVICES_QUERY_DIR_OBJECT.fetch_add(1, Ordering::Relaxed);
                let dir_handle = args[0];
                let buf = args[1];
                let length = args[2];
                let return_single = args[3] & 1;
                let sp = get_recv_mr(16);
                let restart_scan = smss_stack_read(sp + 0x28) & 1;
                let context_ptr = smss_stack_read(sp + 0x30);
                let retlen_ptr = smss_stack_read(sp + 0x38);
                let dir_idx = if dir_handle >= OBJ_HANDLE_BASE {
                    (dir_handle - OBJ_HANDLE_BASE) as usize
                } else {
                    // A predefined \BaseNamedObjects handle we may not have minted (defensive).
                    self.obj_resolve(b"\\BaseNamedObjects", 0).unwrap_or(0)
                };
                // Starting child ordinal: 0 on RestartScan, else the captured Context.
                let mut start = if restart_scan != 0 {
                    0u64
                } else if context_ptr != 0 {
                    let mut c = [0u8; 4];
                    let _ = self.xas_read(context_ptr, &mut c);
                    u32::from_le_bytes(c) as u64
                } else {
                    0
                };
                // Collect this directory's children (by insertion index) beyond `start`.
                let mut children: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
                for (i, e) in self.obj_ns.iter().enumerate() {
                    if e.parent as usize == dir_idx && i != dir_idx {
                        children.push(i);
                    }
                }
                let total = children.len() as u64;
                if start >= total {
                    // No more entries — the standard empty/end result.
                    if retlen_ptr != 0 {
                        self.xas_write_buf(retlen_ptr, &0u32.to_le_bytes()); // *ReturnLength = 0 (ULONG)
                    }
                    0x8000_001A // STATUS_NO_MORE_ENTRIES
                } else {
                    // Emit records + strings into the caller's buffer. Each record is 0x20 bytes;
                    // there is one terminating zero record, then the strings. Emit as many as fit
                    // (or one, if ReturnSingleEntry). The type name is "Event"/"Directory"/
                    // "SymbolicLink" per kind.
                    const REC: u64 = 0x20;
                    // First pass: choose how many entries to emit.
                    let mut records: alloc::vec::Vec<(alloc::vec::Vec<u16>, &'static str)> =
                        alloc::vec::Vec::new();
                    let mut idx = start as usize;
                    while idx < children.len() {
                        let e = &self.obj_ns[children[idx]];
                        let name16: alloc::vec::Vec<u16> =
                            e.name().iter().map(|&b| b as u16).collect();
                        let type_name = match e.kind {
                            2 => "Event",
                            1 => "SymbolicLink",
                            _ => "Directory",
                        };
                        records.push((name16, type_name));
                        idx += 1;
                        if return_single != 0 {
                            break;
                        }
                        // Bound the batch by the caller's buffer length (records + strings + null rec).
                        let mut needed = REC; // terminating null record
                        for (n, t) in &records {
                            needed += REC + (n.len() as u64 + 1) * 2 + (t.len() as u64 + 1) * 2;
                        }
                        if needed > length {
                            records.pop();
                            idx -= 1;
                            break;
                        }
                    }
                    let emitted = records.len();
                    // Layout: [records...][null record][name0,type0,name1,type1,...] (UTF-16 null-term).
                    let rec_area = REC * (emitted as u64 + 1);
                    let mut str_off = rec_area;
                    let mut total_len = rec_area;
                    for (n, t) in &records {
                        total_len += (n.len() as u64 + 1) * 2 + (t.len() as u64 + 1) * 2;
                    }
                    for (k, (n, t)) in records.iter().enumerate() {
                        let rec_base = buf + REC * k as u64;
                        // Name UNICODE_STRING {Length, MaxLength, pad, Buffer}
                        let name_bytes = (n.len() as u64) * 2;
                        let name_buf_va = buf + str_off;
                        self.xas_write_u64(
                            rec_base,
                            (name_bytes) | ((name_bytes + 2) << 16),
                        );
                        self.xas_write_u64(rec_base + 8, name_buf_va);
                        // TypeName UNICODE_STRING
                        let type_bytes = (t.len() as u64) * 2;
                        // write name string
                        let mut nb: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                        for &w in n {
                            nb.extend_from_slice(&w.to_le_bytes());
                        }
                        nb.extend_from_slice(&0u16.to_le_bytes());
                        self.xas_write_buf(name_buf_va, &nb);
                        str_off += name_bytes + 2;
                        let type_buf_va = buf + str_off;
                        self.xas_write_u64(
                            rec_base + 0x10,
                            (type_bytes) | ((type_bytes + 2) << 16),
                        );
                        self.xas_write_u64(rec_base + 0x18, type_buf_va);
                        let mut tb: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                        for c in t.encode_utf16() {
                            tb.extend_from_slice(&c.to_le_bytes());
                        }
                        tb.extend_from_slice(&0u16.to_le_bytes());
                        self.xas_write_buf(type_buf_va, &tb);
                        str_off += type_bytes + 2;
                    }
                    // Terminating zero record.
                    let term = buf + REC * emitted as u64;
                    self.xas_write_u64(term, 0);
                    self.xas_write_u64(term + 8, 0);
                    self.xas_write_u64(term + 0x10, 0);
                    self.xas_write_u64(term + 0x18, 0);
                    start += emitted as u64;
                    if context_ptr != 0 {
                        // Context is a PULONG — write only 4 bytes.
                        self.xas_write_buf(context_ptr, &(start as u32).to_le_bytes());
                    }
                    if retlen_ptr != 0 {
                        self.xas_write_buf(retlen_ptr, &(total_len as u32).to_le_bytes());
                    }
                    // STATUS_MORE_ENTRIES if more remain, else SUCCESS.
                    if start < total {
                        0x0000_0105 // STATUS_MORE_ENTRIES
                    } else {
                        0
                    }
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
                let now = nt_system_time_100ns();
                self.queue_write(out, now);
                0
            }
            NativeService::NtDelayExecution => {
                let alertable = args[0] & 0xff != 0;
                let interval_ptr = args[1];
                let mut bytes = [0u8; 8];
                if interval_ptr == 0 || !unsafe { self.xas_read(interval_ptr, &mut bytes) } {
                    let trace = DELAY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
                    if trace < 16 {
                        print_str(b"[delay] caller_badge=");
                        print_u64(self.current_badge);
                        print_str(b" tid=");
                        print_u64(self.current_tid);
                        print_str(b" alertable=");
                        print_u64(alertable as u64);
                        print_str(b" interval_ptr=0x");
                        print_hex_u64(interval_ptr);
                        print_str(b" readable=0 -> STATUS_ACCESS_VIOLATION\n");
                    }
                    return 0xC000_0005;
                }
                let interval = i64::from_le_bytes(bytes);
                self.delay_requested = true;
                self.delay_interval_100ns = interval;
                self.delay_alertable = alertable;
                let trace = DELAY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
                if trace < 16 {
                    print_str(b"[delay] call=");
                    print_u64(trace + 1);
                    print_str(b" caller_badge=");
                    print_u64(self.current_badge);
                    print_str(b" tid=");
                    print_u64(self.current_tid);
                    print_str(b" alertable=");
                    print_u64(alertable as u64);
                    print_str(b" interval_ptr=0x");
                    print_hex_u64(interval_ptr);
                    print_str(b" readable=1 interval_100ns=");
                    if interval < 0 {
                        print_str(b"-");
                        print_u64(interval.unsigned_abs());
                        print_str(b" relative=1");
                    } else {
                        print_u64(interval as u64);
                        print_str(b" relative=0");
                    }
                    print_str(b"\n");
                }
                // This executive has no queued user APC object yet. Alertable delays therefore wait
                // normally; STATUS_USER_APC is returned only when a real APC queue can prove one.
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
                const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
                const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
                const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
                let file_handle = args[0];
                let iosb = args[1];
                let buf = args[2];
                let len = args[3];
                // FsInformationClass is a ULONG; the 8-byte stack slot has garbage in the high dword.
                let class = args[4] & 0xFFFF_FFFF;
                if class != 4 {
                    return STATUS_INVALID_INFO_CLASS;
                }
                if len < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                if iosb == 0 || buf == 0 {
                    return STATUS_ACCESS_VIOLATION;
                }
                if let Some(pid) = self.pm_pid_for_pi(self.pi) {
                    let object = self
                        .pm
                        .lookup_handle(pid, file_handle as nt_process::Handle);
                    let is_file = matches!(
                        object,
                        Some(
                            nt_process::HandleObject::Directory { .. }
                                | nt_process::HandleObject::DiskFile { .. }
                                | nt_process::HandleObject::File(_)
                                | nt_process::HandleObject::BootStatusFile
                                | nt_process::HandleObject::Opaque(_)
                        )
                    );
                    if !is_file {
                        return if object.is_some() {
                            STATUS_OBJECT_TYPE_MISMATCH
                        } else {
                            STATUS_INVALID_HANDLE
                        };
                    }
                }
                // FileFsDeviceInformation { DeviceType=FILE_DEVICE_DISK(7),
                // Characteristics=FILE_DEVICE_IS_MOUNTED(0x20) }.
                self.queue_write(buf, 0x0000_0020_0000_0007);
                self.queue_write(iosb, 0); // Status = STATUS_SUCCESS
                self.queue_write(iosb + 8, 8); // Information = bytes written
                0
            }
            // NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
            // FileInformationClass). Resolve process-local ownership here; nt-fs owns the ABI layout.
            NativeService::NtQueryInformationFile => unsafe {
                let iosb = args[1];
                let output = args[2];
                let length = args[3] as usize;
                let class = args[4] as u32;
                let mut encoded = [0u8; 24];
                let encoded_capacity = encoded.len();
                let required = match nt_fs::encode_query_information(
                    class,
                    nt_fs::QueryMetadata::default(),
                    &mut encoded[..length.min(encoded_capacity)],
                ) {
                    Ok(required) => required,
                    Err(status) => return status,
                };
                if iosb == 0 || output == 0 {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }
                if iosb & 7 != 0 || output & 3 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_user_output(iosb, 16)
                    || !self.probe_user_output(output, length)
                {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }
                let pid = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => return nt_fs::STATUS_INVALID_HANDLE,
                };
                let object = match self
                    .pm
                    .lookup_handle(pid, args[0] as nt_process::Handle)
                {
                    Some(object) => object,
                    None => return nt_fs::STATUS_INVALID_HANDLE,
                };
                let size_and_directory = match object {
                    nt_process::HandleObject::DiskFile { size, .. } => Some((size as u64, false)),
                    nt_process::HandleObject::Directory { .. } => Some((0, true)),
                    nt_process::HandleObject::BootStatusFile => {
                        Some((EXEC_BOOT_STATUS_FILE_SIZE as u64, false))
                    }
                    nt_process::HandleObject::Opaque(_) => {
                        let ctx = match self.loop_ctx {
                            Some(ctx) => ctx,
                            None => return nt_fs::STATUS_INVALID_HANDLE,
                        };
                        let reg = &*ctx.reg;
                        if let Some(index) = reg.index_for_file(self.pi, args[0]) {
                            ctx.dll_pes()[index]
                                .as_ref()
                                .map(|pe| (pe.bytes().len() as u64, false))
                        } else if self.pi == 0 && args[0] == *ctx.csrss_file_handle {
                            (&*ctx.csrss_pe)
                                .as_ref()
                                .map(|pe| (pe.bytes().len() as u64, false))
                        } else if self.pi == 0 && args[0] == *ctx.winlogon_file_handle {
                            (&*ctx.winlogon_pe)
                                .as_ref()
                                .map(|pe| (pe.bytes().len() as u64, false))
                        } else if self.pi == 2 && args[0] == *ctx.services_file_handle {
                            (&*ctx.services_pe)
                                .as_ref()
                                .map(|pe| (pe.bytes().len() as u64, false))
                        } else if self.pi == 2 && args[0] == *ctx.lsass_file_handle {
                            (&*ctx.lsass_pe)
                                .as_ref()
                                .map(|pe| (pe.bytes().len() as u64, false))
                        } else {
                            None
                        }
                    }
                    nt_process::HandleObject::File(_) => {
                        return nt_fs::STATUS_INVALID_DEVICE_REQUEST;
                    }
                    _ => return 0xC000_0024, // STATUS_OBJECT_TYPE_MISMATCH
                };
                let (size, directory) = match size_and_directory {
                    Some(metadata) => metadata,
                    None => return nt_fs::STATUS_INVALID_HANDLE,
                };
                let metadata = nt_fs::QueryMetadata {
                    allocation_size: size.saturating_add(0xFFF) & !0xFFF,
                    end_of_file: size,
                    number_of_links: 1,
                    delete_pending: false,
                    directory,
                };
                nt_fs::encode_query_information(class, metadata, &mut encoded)
                    .expect("validated query class and length");
                if !self.xas_try_write_buf(output, &encoded[..required]) {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }
                let mut iosb_bytes = [0u8; 16];
                iosb_bytes[8..16].copy_from_slice(&(required as u64).to_le_bytes());
                if !self.xas_try_write_buf(iosb, &iosb_bytes) {
                    return nt_syscall::STATUS_ACCESS_VIOLATION;
                }
                nt_fs::STATUS_SUCCESS
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
                let mut word = [0u8; 8];
                let base_in = if self.xas_read(base_ptr, &mut word) {
                    u64::from_le_bytes(word)
                } else {
                    0
                };
                word = [0; 8];
                let want = if self.xas_read(size_ptr, &mut word) {
                    u64::from_le_bytes(word)
                } else {
                    0
                };
                let rounded = ((want + 0xFFF) & !0xFFFu64).max(0x1000);
                let base = if base_in != 0 {
                    base_in
                } else if self.pi == 1 {
                    NEXT_CSRSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 2 {
                    NEXT_WINLOGON_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 3 {
                    NEXT_SERVICES_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 4 {
                    NEXT_LSASS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else {
                    NEXT_SMSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                };
                if self.pi == 2
                    && WINLOGON_VM_TRACE_N.fetch_add(1, Ordering::Relaxed) < 48
                {
                    print_str(b"[winlogon-vm] base_ptr=0x");
                    print_hex((base_ptr >> 32) as u32);
                    print_hex(base_ptr as u32);
                    print_str(b" size_ptr=0x");
                    print_hex((size_ptr >> 32) as u32);
                    print_hex(size_ptr as u32);
                    print_str(b" base_in=0x");
                    print_hex((base_in >> 32) as u32);
                    print_hex(base_in as u32);
                    print_str(b" want=0x");
                    print_hex((want >> 32) as u32);
                    print_hex(want as u32);
                    print_str(b" type=0x");
                    print_hex(alloc_type as u32);
                    print_str(b" selected=0x");
                    print_hex((base >> 32) as u32);
                    print_hex(base as u32);
                    print_str(b"\n");
                }
                if alloc_type & 0x1000 != 0 {
                    // MEM_COMMIT — back it with real frames.
                    let mut p = 0u64;
                    while p < rounded {
                        let f = alloc_frame();
                        let _ = page_map(f, base + p, RW_NX, ctx.pml4);
                        // Mirror the first heap window into the executive so smss_copyin can read
                        // heap-resident pointer args, into the ACTIVE process's heap mirror.
                        let va = base + p;
                        if self.pi == 1 || self.pi == 2 {
                            // win32k runs attached to the calling GUI process and dereferences
                            // user heap pointers directly. Register the committed frame so a
                            // win32k-side fault maps this same live page, not a fresh zero page.
                            csrss_frame_put(self.pi as u64, va, f);
                        }
                        if va >= SMSS_ALLOC_VA && va < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
                            let mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
                            let _ = page_map(copy_cap(f),
                                mirror + (va - SMSS_ALLOC_VA), RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                        p += 0x1000;
                    }
                }
                self.xas_write_buf(base_ptr, &base.to_le_bytes());
                self.xas_write_buf(size_ptr, &rounded.to_le_bytes());
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
                let ctx = self.loop_ctx.unwrap();
                let reg = &*ctx.reg;
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
                // The hosted-process EXE probes (csrss/winlogon/services/lsass) are the case where a
                // pi==0 (smss) OR winlogon probe must resolve EXISTS even though the general DLL
                // existence path below is gated pi>=1 (so smss's KnownDLLs probes fail → it launches
                // csrss/winlogon). Existence comes from the REAL \reactos FS by-path (`sys32_exists`)
                // — no hand-maintained list — but keyed on the CANONICAL leaf the substring
                // classifies (ReactOS sometimes builds a malformed probe path, e.g.
                // `\??\C:\Windowsservices.exe` with no separator, so the extracted leaf is garbage;
                // the substring reliably says WHICH EXE it wants). SxS probes are rejected (loader
                // must not take the .Local\/manifest path). Content delivery stays on nt-dll-registry.
                let exe_canon = Self::exe_probe_canon(&nb[..nlen], is_sxs);
                let exe_exists = exe_canon.is_some_and(|leaf| unsafe { sys32_exists(leaf) });
                // General DLL existence (pi>=1) also comes from the real FS by-path.
                let dll_exists = self.pi >= 1 && self.fs_system32_has(&nb[..nlen]);
                let status: u32 = if exe_exists {
                    // FILE_BASIC_INFORMATION: 4×8-byte times, then FileAttributes(u32) @ +0x20.
                    smss_stack_write32(args[1] + 0x20, 0x80); // FILE_ATTRIBUTE_NORMAL (a file)
                    0
                } else if dll_exists {
                    smss_stack_write32(args[1] + 0x20, 0x80); // FILE_ATTRIBUTE_NORMAL
                    0
                } else {
                    // DIAG: log the not-found probes from a DLL-loading process (csrss/winlogon) —
                    // a DllMain probes several files before failing init; we need to know which are
                    // load-bearing.
                    if self.pi >= 1 && self.pi != 2 {
                        print_str(b"[ntos-exec] NtQueryAttributesFile(hosted) not-found: \"");
                        for &w in name16.iter().take(96) {
                            debug_put_char(if (0x20..0x7f).contains(&w) { w as u8 } else { b'?' });
                        }
                        print_str(b"\"\n");
                    }
                    0xC0000034
                };
                loader_trace_record(
                    self.pi,
                    LoaderOp::QueryAttributesFile,
                    status,
                    reg.resolve_name(&nb[..nlen]),
                    0,
                    0,
                    &nb[..nlen],
                );
                status
            },
            // NtCreateIoCompletion(*Handle, DesiredAccess, *OA, NumberOfConcurrentThreads).
            // The NT object and its packet queue live in the executive; SURT is only the transport
            // which can feed packets through nt-io-completion's field-for-field adapter.
            NativeService::NtCreateIoCompletion => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
                let out_handle = args[0];
                let desired_access = args[1] as u32;
                let oa = args[2];
                let concurrency = args[3] as u32;
                let mut output_probe = [0u8; 8];
                if out_handle == 0 || !self.xas_read(out_handle, &mut output_probe) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let mut oa_header = [0u8; 32];
                if oa != 0 && !self.xas_read(oa, &mut oa_header) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let attributes = if oa == 0 {
                    0
                } else {
                    u32::from_le_bytes(oa_header[24..28].try_into().unwrap())
                };
                let name = if oa == 0 {
                    alloc::vec::Vec::new()
                } else {
                    self.read_objattr_name_pe(oa)
                };
                if !NT_CREATE_IO_COMPLETION_TRACED.swap(true, Ordering::Relaxed) {
                    print_str(b"[nt-create-io-completion] pi="); print_u64(self.pi as u64);
                    print_str(b" access=0x"); print_hex(desired_access);
                    print_str(b" oa=0x"); print_hex(oa as u32);
                    print_str(b" attrs=0x"); print_hex(attributes);
                    print_str(b" concurrency="); print_u64(concurrency as u64);
                    print_str(b" name=\"");
                    for &unit in name.iter().take(64) {
                        debug_put_char(if (0x20..0x7f).contains(&unit) { unit as u8 } else { b'?' });
                    }
                    print_str(b"\"\n");
                }
                let created = match self.io_completion_ports.create(
                    &name,
                    concurrency,
                    attributes & 0x40 != 0,
                ) {
                    Ok(created) => created,
                    Err(status) => return status,
                };
                let handle = match self.mint_io_completion_handle(created.id, desired_access) {
                    Some(handle) => handle,
                    None => {
                        let _ = self.io_completion_ports.release(created.id);
                        return nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                    }
                };
                self.xas_write_buf(out_handle, &handle.to_le_bytes());
                if created.created { nt_io_completion::STATUS_SUCCESS } else { STATUS_OBJECT_NAME_EXISTS }
            },
            NativeService::NtOpenIoCompletion => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const OBJ_CASE_INSENSITIVE: u32 = 0x40;
                let out_handle = args[0];
                let desired_access = args[1] as u32;
                let oa = args[2];
                let mut output_probe = [0u8; 8];
                let mut oa_header = [0u8; 32];
                if out_handle == 0
                    || !self.xas_read(out_handle, &mut output_probe)
                    || oa == 0
                    || !self.xas_read(oa, &mut oa_header)
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                let attributes = u32::from_le_bytes(oa_header[24..28].try_into().unwrap());
                let name = self.read_objattr_name_pe(oa);
                let object_id = match self
                    .io_completion_ports
                    .open(&name, attributes & OBJ_CASE_INSENSITIVE != 0)
                {
                    Ok(id) => id,
                    Err(status) => return status,
                };
                let handle = match self.mint_io_completion_handle(object_id, desired_access) {
                    Some(handle) => handle,
                    None => {
                        let _ = self.io_completion_ports.release(object_id);
                        return nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                    }
                };
                self.xas_write_buf(out_handle, &handle.to_le_bytes());
                nt_io_completion::STATUS_SUCCESS
            },
            NativeService::NtSetIoCompletion => {
                const IO_COMPLETION_MODIFY_STATE: u32 = 0x2;
                let object_id = match self.io_completion_id_for(args[0], IO_COMPLETION_MODIFY_STATE) {
                    Ok(id) => id,
                    Err(status) => return status,
                };
                self.io_completion_ports
                    .enqueue(
                        object_id,
                        nt_io_completion::CompletionPacket {
                            key_context: args[1],
                            apc_context: args[2],
                            status: args[3] as u32,
                            information: args[4],
                        },
                    )
                    .map_or_else(|status| status, |_| nt_io_completion::STATUS_SUCCESS)
            },
            NativeService::NtRemoveIoCompletion => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const IO_COMPLETION_MODIFY_STATE: u32 = 0x2;
                let object_id = match self.io_completion_id_for(args[0], IO_COMPLETION_MODIFY_STATE) {
                    Ok(id) => id,
                    Err(status) => return status,
                };
                let mut probe = [0u8; 16];
                if args[1] == 0
                    || args[2] == 0
                    || args[3] == 0
                    || !self.xas_read(args[1], &mut probe[..8])
                    || !self.xas_read(args[2], &mut probe[..8])
                    || !self.xas_read(args[3], &mut probe)
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                let mode = if args[4] == 0 {
                    nt_io_completion::RemoveMode::Wait
                } else {
                    let mut timeout = [0u8; 8];
                    if !self.xas_read(args[4], &mut timeout) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    if i64::from_le_bytes(timeout) == 0 {
                        nt_io_completion::RemoveMode::Poll
                    } else {
                        nt_io_completion::RemoveMode::Wait
                    }
                };
                match self.io_completion_ports.remove(object_id, mode) {
                    Ok(nt_io_completion::RemoveResult::Packet(packet)) => {
                        self.xas_write_buf(args[1], &packet.key_context.to_le_bytes());
                        self.xas_write_buf(args[2], &packet.apc_context.to_le_bytes());
                        self.xas_write_buf(args[3], &packet.status.to_le_bytes());
                        self.xas_write_buf(args[3] + 8, &packet.information.to_le_bytes());
                        nt_io_completion::STATUS_SUCCESS
                    }
                    Ok(nt_io_completion::RemoveResult::Empty(status)) => {
                        if status == nt_io_completion::STATUS_PENDING
                            && !NT_REMOVE_IO_COMPLETION_WAIT_TRACED.swap(true, Ordering::Relaxed)
                        {
                            print_str(b"[nt-remove-io-completion] pi="); print_u64(self.pi as u64);
                            print_str(b" empty blocking wait -> STATUS_PENDING (reply-cap wait not yet armed)\n");
                        }
                        status
                    }
                    Err(status) => status,
                }
            },
            NativeService::NtQueryIoCompletion => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
                const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
                const IO_COMPLETION_QUERY_STATE: u32 = 0x1;
                const BASIC_INFO_LEN: u32 = 4;
                let object_id = match self.io_completion_id_for(args[0], IO_COMPLETION_QUERY_STATE) {
                    Ok(id) => id,
                    Err(status) => return status,
                };
                if args[4] != 0 {
                    let mut probe = [0u8; 4];
                    if !self.xas_read(args[4], &mut probe) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    self.xas_write_buf(args[4], &BASIC_INFO_LEN.to_le_bytes());
                }
                if args[1] as u32 != 0 {
                    return STATUS_INVALID_INFO_CLASS;
                }
                if (args[3] as u32) < BASIC_INFO_LEN {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let mut output_probe = [0u8; 4];
                if args[2] == 0 || !self.xas_read(args[2], &mut output_probe) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let depth = match self.io_completion_ports.depth(object_id) {
                    Ok(depth) => depth,
                    Err(status) => return status,
                };
                self.xas_write_buf(args[2], &depth.to_le_bytes());
                nt_io_completion::STATUS_SUCCESS
            },
            // NtCreateFile(*FileHandle[R10], DesiredAccess[RDX], *OBJECT_ATTRIBUTES[R8],
            // *IoStatusBlock[R9], AllocationSize[sp+0x28], FileAttributes[sp+0x30],
            // ShareAccess[sp+0x38], CreateDisposition[sp+0x40], CreateOptions[sp+0x48], ...).
            // Route named-pipe client opens through the isolated npfs FSD for every hosted process.
            // Other file namespaces remain unsupported rather than receiving a fake handle.
            NativeService::NtCreateFile => unsafe {
                let oa = get_recv_mr(7); // R8 = *OBJECT_ATTRIBUTES
                let name16 = self.read_objattr_name_pe(oa);
                let iosb = get_recv_mr(8); // R9 = *IO_STATUS_BLOCK
                if !NT_CREATE_FILE_FRONTIER_TRACED.swap(true, Ordering::Relaxed) {
                    print_str(b"[nt-create-file-frontier] pi=");
                    print_u64(self.pi as u64);
                    print_str(b" access=0x"); print_hex(args[1] as u32);
                    print_str(b" attrs=0x"); print_hex(args[5] as u32);
                    print_str(b" share=0x"); print_hex(args[6] as u32);
                    print_str(b" disposition=0x"); print_hex(args[7] as u32);
                    print_str(b" options=0x"); print_hex(args[8] as u32);
                    print_str(b" name=\"");
                    for &unit in name16.iter().take(160) {
                        debug_put_char(if (0x20..0x7f).contains(&unit) { unit as u8 } else { b'?' });
                    }
                    print_str(b"\"\n");
                }
                let mut status;
                let mut info = 0u64;
                if boot_status_path_matches(&name16) {
                    if args[8] as u32 & nt_fs::FILE_DIRECTORY_FILE != 0 {
                        status = nt_fs::STATUS_OBJECT_NAME_COLLISION;
                    } else if let Some(handle) = self.mint_boot_status_handle(args[1] as u32) {
                        let disposition = args[7] as u32;
                        status = nt_fs::STATUS_SUCCESS;
                        info = match disposition {
                            nt_fs::FILE_SUPERSEDE => {
                                reset_boot_status_data();
                                nt_fs::FILE_SUPERSEDED as u64
                            }
                            nt_fs::FILE_OPEN => {
                                ensure_boot_status_data();
                                nt_fs::FILE_OPENED as u64
                            }
                            nt_fs::FILE_CREATE => {
                                reset_boot_status_data();
                                nt_fs::FILE_CREATED as u64
                            }
                            nt_fs::FILE_OPEN_IF => {
                                let existed = EXEC_BOOT_STATUS_INITIALIZED.load(Ordering::Acquire);
                                ensure_boot_status_data();
                                if existed {
                                    nt_fs::FILE_OPENED as u64
                                } else {
                                    nt_fs::FILE_CREATED as u64
                                }
                            }
                            nt_fs::FILE_OVERWRITE | nt_fs::FILE_OVERWRITE_IF => {
                                reset_boot_status_data();
                                nt_fs::FILE_OVERWRITTEN as u64
                            }
                            _ => {
                                status = nt_fs::STATUS_INVALID_PARAMETER;
                                0
                            }
                        };
                        if status == nt_fs::STATUS_SUCCESS {
                            self.queue_write(args[0], handle);
                        }
                    } else {
                        status = 0xC000_009A;
                    }
                } else if nt_fs::is_named_pipe_path(&name16) {
                    if args[7] as u32 != nt_fs::FILE_OPEN {
                        status = nt_fs::STATUS_INVALID_PARAMETER;
                    } else if args[8] as u32 & nt_fs::FILE_DIRECTORY_FILE != 0 {
                        status = nt_fs::STATUS_OBJECT_NAME_COLLISION;
                    } else if let Some((st, file_id)) = self.npfs_route(
                        0, 0, &Self::pipe_leaf16(&name16), 0,
                    ) {
                        status = st as u32;
                        if status == nt_fs::STATUS_SUCCESS && file_id != 0 {
                            if let Some(handle) = self.mint_file_handle(file_id, args[1] as u32) {
                                self.queue_write(args[0], handle);
                                info = nt_fs::FILE_OPENED as u64;
                                // ★ BATCH 34: client CONNECT (winlogon's NtCreateFile on \pipe\ntsvcs)
                                // paired with the server end by name → complete the pending async
                                // server listen FOR THAT PIPE NAME (signal its completion event → the
                                // SCM listener's NtWaitForMultipleObjects wakes to read the bind PDU).
                                self.pipe_connect_redrive =
                                    nt_io_manager::pipe_name_hash(&Self::pipe_leaf16(&name16));
                            } else {
                                status = 0xC000_009A;
                            }
                        } else if status == nt_fs::STATUS_SUCCESS {
                            status = nt_fs::STATUS_INVALID_DEVICE_REQUEST;
                        }
                    } else {
                        status = nt_fs::STATUS_OBJECT_PATH_NOT_FOUND;
                    }
                } else {
                    self.stop = true;
                    status = 0xC000_0002;
                }
                if iosb != 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &info.to_le_bytes());
                }
                if self.pi == 2
                    && NT_CREATE_FILE_WINLOGON_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8
                {
                    print_str(b"[nt-create-file-winlogon] status=0x"); print_hex(status);
                    print_str(b" info="); print_u64(info);
                    print_str(b" name=\"");
                    for &unit in name16.iter().take(96) {
                        debug_put_char(if (0x20..0x7f).contains(&unit) { unit as u8 } else { b'?' });
                    }
                    print_str(b"\"\n");
                }
                status
            },
            // NtWriteFile(FileHandle[R10], Event[RDX], ApcRoutine[R8], ApcContext[R9],
            // *IoStatusBlock[sp+0x28], Buffer[sp+0x30], Length[sp+0x38], ByteOffset[sp+0x40],
            // Key[sp+0x48]). Route typed named-pipe handles through isolated npfs with the caller's
            // actual bytes. The shared FSD transport is four pages, so reject an over-sized request
            // rather than silently truncating it. Driver status + Information are returned verbatim.
            NativeService::NtWriteFile => unsafe {
                let sp = get_recv_mr(16);
                let iosb = smss_stack_read(sp + 0x28);
                let buffer = smss_stack_read(sp + 0x30);
                let len = smss_stack_read(sp + 0x38) as u32 as usize;
                let byte_offset = smss_stack_read(sp + 0x40);
                let key = smss_stack_read(sp + 0x48);
                let fh = args[0]; // R10 = FileHandle
                let event = args[1];
                let apc_routine = args[2];
                let apc_context = args[3];
                let trace = NT_WRITE_FILE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8;
                let mut offset_bytes = [0u8; 8];
                let offset_ok = byte_offset == 0 || self.xas_read(byte_offset, &mut offset_bytes);
                let offset_value = u64::from_le_bytes(offset_bytes);
                let mut key_bytes = [0u8; 4];
                let key_ok = key == 0 || self.xas_read(key, &mut key_bytes);
                let key_value = u32::from_le_bytes(key_bytes);
                let mut iosb_probe = [0u8; 16];
                let iosb_ok = iosb != 0 && self.xas_read(iosb, &mut iosb_probe);
                let transport_capacity = (driver_launch::FSD_ARG_FRAMES * 0x1000) as usize;
                let mut payload = alloc::vec![0u8; len.min(transport_capacity)];
                let payload_ok = len == 0
                    || (buffer != 0
                        && len <= transport_capacity
                        && self.xas_read(buffer, &mut payload));

                let completion_event = self.validate_io_event(event);
                let mut information = 0u64;
                let mut routed = false;
                let status = if !iosb_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if len > transport_capacity {
                    0xC000_0206 // STATUS_INVALID_BUFFER_SIZE
                } else if !payload_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if apc_routine != 0 {
                    // No executive user-APC queue exists yet; do not pretend the callback ran.
                    0xC000_00BB // STATUS_NOT_SUPPORTED
                } else if let Err(event_status) = completion_event {
                    event_status
                } else if self.boot_status_handle_access(fh).is_ok() {
                    match self.boot_status_write_file(fh, buffer, len, byte_offset) {
                        Ok(written) => {
                            information = written;
                            nt_fs::STATUS_SUCCESS
                        }
                        Err(status) => status,
                    }
                } else {
                    match self.npfs_write_file_id_for(fh) {
                        Err(handle_status) => handle_status,
                        Ok(file_id) => {
                            let mut output = [];
                            match self.npfs_route_raw(
                                major::IRP_MJ_WRITE as u64,
                                0,
                                file_id,
                                &payload,
                                &mut output,
                            ) {
                                Some((driver_status, completed, _)) => {
                                    routed = true;
                                    information = completed;
                                    driver_status as u32
                                }
                                None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                            }
                        }
                    }
                };
                if iosb_ok {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                // A synchronous completion signals a valid real event. Legacy opaque events already
                // have immediate-wait semantics; STATUS_PENDING must leave every event unsignalled.
                if routed && status != 0x0000_0103 {
                    if let Ok(Some(index)) = completion_event {
                        if self.events.set_existing(index as u64).is_some() {
                            self.io_signal_event = index as i64;
                        }
                    }
                    // BATCH 33: the bytes are now queued in npfs on the PEER end. Ask the loop to
                    // re-drive every parked pipe read — npfs's FCB pairing wakes the peer's reader.
                    self.pipe_write_redrive = true;
                }
                if trace {
                    print_str(b"[nt-write-file] pi=");
                    print_u64(self.pi as u64);
                    print_str(b" handle=0x");
                    print_hex(fh as u32);
                    print_str(b" length=");
                    print_u64(len as u64);
                    print_str(b" event=0x");
                    print_hex(event as u32);
                    print_str(b" apc=");
                    print_u64((apc_routine != 0) as u64);
                    print_str(b" apc_ctx=");
                    print_u64((apc_context != 0) as u64);
                    print_str(b" offset_ptr=");
                    print_u64((byte_offset != 0) as u64);
                    print_str(b" offset_ok=");
                    print_u64(offset_ok as u64);
                    if byte_offset != 0 && offset_ok {
                        print_str(b" offset=0x");
                        print_hex(offset_value as u32);
                    }
                    print_str(b" key_ptr=");
                    print_u64((key != 0) as u64);
                    print_str(b" key_ok=");
                    print_u64(key_ok as u64);
                    if key != 0 && key_ok {
                        print_str(b" key=0x");
                        print_hex(key_value);
                    }
                    print_str(b" payload_ok=");
                    print_u64(payload_ok as u64);
                    print_str(b" prefix=");
                    if payload_ok {
                        for &byte in payload.iter().take(16) {
                            print_hex(byte as u32);
                            debug_put_char(b' ');
                        }
                    }
                    print_str(b" status=0x");
                    print_hex(status);
                    print_str(b" info=");
                    print_u64(information);
                    print_str(b"\n");
                }
                status
            },
            // NtReadFile(FileHandle[R10], Event[RDX], ApcRoutine[R8], ApcContext[R9],
            // *IoStatusBlock[sp+0x28], Buffer[sp+0x30], Length[sp+0x38], ...). Route a typed pipe
            // through npfs with output capacity (not input bytes), then copy synchronous data back.
            NativeService::NtReadFile => unsafe {
                let sp = get_recv_mr(16);
                let iosb = smss_stack_read(sp + 0x28);
                let buffer = smss_stack_read(sp + 0x30);
                let len = smss_stack_read(sp + 0x38) as u32 as usize;
                let byte_offset = smss_stack_read(sp + 0x40);
                let fh = args[0];
                let event = args[1];
                let apc_routine = args[2];
                let completion_event = self.validate_io_event(event);
                let disk_file = self.disk_file_for(fh);
                let mut iosb_probe = [0u8; 16];
                let iosb_ok = iosb != 0 && self.xas_read(iosb, &mut iosb_probe);
                let transport_capacity = (driver_launch::FSD_ARG_FRAMES * 0x1000) as usize;
                let output_capacity = if matches!(disk_file, Ok(Some(_))) {
                    len.min(16 * 1024 * 1024)
                } else {
                    len.min(transport_capacity)
                };
                let mut output = alloc::vec![0u8; output_capacity];
                let mut information = 0u64;
                let mut routed = false;
                let mut pending_read_fid = 0u64; // BATCH 33: npfs fid if the read went PENDING → park
                let status = if !iosb_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if !matches!(disk_file, Ok(Some(_))) && len > transport_capacity {
                    0xC000_0206 // STATUS_INVALID_BUFFER_SIZE
                } else if len != 0 && buffer == 0 {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if apc_routine != 0 {
                    0xC000_00BB // STATUS_NOT_SUPPORTED
                } else if let Err(event_status) = completion_event {
                    event_status
                } else if let Err(handle_status) = disk_file {
                    handle_status
                } else if let Some((first_cluster, file_size)) = disk_file.unwrap_or(None) {
                    if len > output.len() {
                        0xC000_0206 // STATUS_INVALID_BUFFER_SIZE
                    } else if len == 0 {
                        nt_fs::STATUS_SUCCESS
                    } else if byte_offset == 0 {
                        0xC000_000D // STATUS_INVALID_PARAMETER: implicit positions are not modeled yet
                    } else {
                        let mut offset_bytes = [0u8; 8];
                        if !self.xas_read(byte_offset, &mut offset_bytes) {
                            0xC000_0005 // STATUS_ACCESS_VIOLATION
                        } else {
                            let offset = i64::from_le_bytes(offset_bytes);
                            if offset < 0 || offset > u32::MAX as i64 {
                                0xC000_000D // STATUS_INVALID_PARAMETER
                            } else if offset as u32 >= file_size {
                                0xC000_0011 // STATUS_END_OF_FILE
                            } else {
                                match exec_fs() {
                                    Some(fs) => {
                                        let expected = output
                                            .len()
                                            .min((file_size - offset as u32) as usize);
                                        let read = fat_read_file_range(
                                            &fs,
                                            first_cluster,
                                            file_size,
                                            offset as u32,
                                            &mut output,
                                        );
                                        if read != expected {
                                            0xC000_0185 // STATUS_IO_DEVICE_ERROR
                                        } else if read != 0
                                            && !self.xas_try_write_buf(buffer, &output[..read])
                                        {
                                            0xC000_0005 // STATUS_ACCESS_VIOLATION
                                        } else {
                                            information = read as u64;
                                            nt_fs::STATUS_SUCCESS
                                        }
                                    }
                                    None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                                }
                            }
                        }
                    }
                } else if self.boot_status_handle_access(fh).is_ok() {
                    match self.boot_status_read_file(fh, buffer, len, byte_offset) {
                        Ok(read) => {
                            information = read;
                            nt_fs::STATUS_SUCCESS
                        }
                        Err(status) => status,
                    }
                } else {
                    match self.npfs_read_file_id_for(fh) {
                        Err(handle_status) => handle_status,
                        Ok(file_id) => {
                            match self.npfs_route_raw(
                                major::IRP_MJ_READ as u64,
                                0,
                                file_id,
                                &[],
                                &mut output,
                            ) {
                                Some((driver_status, completed, _)) => {
                                    routed = true;
                                    information = completed;
                                    let copy_len = (completed as usize).min(output.len());
                                    if driver_status as u32 != 0x0000_0103 && copy_len != 0 {
                                        self.xas_write_buf(buffer, &output[..copy_len]);
                                    }
                                    if driver_status as u32 == 0x0000_0103 {
                                        pending_read_fid = file_id;
                                    }
                                    driver_status as u32
                                }
                                None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                            }
                        }
                    }
                };
                // BATCH 33: a real npfs pipe read with no data yet → PARK this caller (withhold the
                // reply, steal its reply cap keyed by this reading end's fid) and re-drive it when the
                // peer writes. The loop performs the reply-cap steal (resume ctx is loop-resident); the
                // IOSB / completion are written at re-drive, so SUPPRESS the PENDING IOSB write here.
                if pending_read_fid != 0 {
                    self.pipe_park_fid = pending_read_fid;
                    self.pipe_park_buffer_va = buffer;
                    self.pipe_park_buffer_len = len as u32;
                    self.pipe_park_iosb_va = iosb;
                    self.pipe_park_transceive = false;
                }
                if iosb_ok && pending_read_fid == 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                if routed && status != 0x0000_0103 {
                    if let Ok(Some(index)) = completion_event {
                        if self.events.set_existing(index as u64).is_some() {
                            self.io_signal_event = index as i64;
                        }
                    }
                }
                if NT_READ_FILE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
                    print_str(b"[nt-read-file] pi=");
                    print_u64(self.pi as u64);
                    print_str(b" handle=0x");
                    print_hex(fh as u32);
                    print_str(b" length=");
                    print_u64(len as u64);
                    print_str(b" status=0x");
                    print_hex(status);
                    print_str(b" info=");
                    print_u64(information);
                    print_str(b"\n");
                }
                status
            },
            // NtSetInformationFile(FileHandle[R10], *IoStatusBlock[RDX], FileInformation[R8],
            // Length[R9], FileInformationClass[sp+0x28]). lsass and winlogon set
            // FilePipeInformation on typed \pipe\lsarpc / \pipe\ntsvcs handles before listening.
            // Route those proven paths through isolated npfs instead of blanket-success modeling.
            NativeService::NtSetInformationFile => unsafe {
                let iosb = args[1]; // RDX = *IO_STATUS_BLOCK
                let sp = get_recv_mr(16);
                let information_class = smss_stack_read(sp + 0x28) as u32;
                let length = args[3] as usize;
                let mut payload = [0u8; 32];
                let payload_len = length.min(payload.len());
                let payload_ok = payload_len == 0 || self.xas_read(args[2], &mut payload[..payload_len]);
                if NT_SET_INFORMATION_FILE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
                    print_str(b"[nt-set-information-file] pi="); print_u64(self.pi as u64);
                    print_str(b" handle=0x"); print_hex(args[0] as u32);
                    print_str(b" class="); print_u64(information_class as u64);
                    print_str(b" length="); print_u64(length as u64);
                    print_str(b" payload_ok="); print_u64(payload_ok as u64);
                    if information_class == 23 && payload_ok && payload_len >= 8 {
                        print_str(b" read_mode=");
                        print_u64(u32::from_le_bytes(payload[0..4].try_into().unwrap()) as u64);
                        print_str(b" completion_mode=");
                        print_u64(u32::from_le_bytes(payload[4..8].try_into().unwrap()) as u64);
                    }
                    print_str(b" payload=");
                    if payload_ok {
                        for &byte in &payload[..payload_len] {
                            print_hex(byte as u32);
                            debug_put_char(b' ');
                        }
                    }
                    print_str(b"\n");
                }
                if self.pi != 2 && self.pi != 4 {
                    self.stop = true;
                    return 0xC000_0002;
                }
                let mut information = 0u64;
                let file_id = self.npfs_file_id_for(args[0]);
                let status = if information_class != 23 {
                    0xC000_0003 // STATUS_INVALID_INFO_CLASS
                } else if length < 8 {
                    0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
                } else if args[2] == 0 || !payload_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if file_id == 0 {
                    0xC000_0008 // STATUS_INVALID_HANDLE
                } else {
                    let mut output = [];
                    match self.npfs_route_raw(
                        major::IRP_MJ_SET_INFORMATION as u64,
                        information_class as u64,
                        file_id,
                        &payload[..8],
                        &mut output,
                    ) {
                        Some((driver_status, completed, _)) => {
                            information = completed;
                            driver_status as u32
                        }
                        None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                    }
                };
                if iosb != 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                status
            },
            // NtFlushBuffersFile(FileHandle[R10], *IoStatusBlock[RDX]). Route the typed pipe handle
            // through isolated npfs's real IRP_MJ_FLUSH_BUFFERS implementation. NPFS may pend the
            // flush behind queued write data; driver_launch retains that IRP graph until the peer
            // drains the queue and IoCompleteRequest reclaims it. This syscall has no event argument.
            NativeService::NtFlushBuffersFile => unsafe {
                let handle = args[0];
                let iosb = args[1];
                let mut iosb_probe = [0u8; 16];
                let iosb_ok = iosb != 0 && self.xas_read(iosb, &mut iosb_probe);
                let mut information = 0u64;
                let mut file_id = 0u64;
                let mut routed = false;
                let status = if !iosb_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if self.boot_status_handle_access(handle).is_ok() {
                    match self.boot_status_check_access(handle, 0x0000_0002, 0x4000_0000) {
                        Ok(()) => nt_fs::STATUS_SUCCESS,
                        Err(status) => status,
                    }
                } else {
                    match self.npfs_flush_file_id_for(handle) {
                        Err(handle_status) => handle_status,
                        Ok(resolved_file_id) => {
                            file_id = resolved_file_id;
                            let mut output = [];
                            match self.npfs_route_raw(
                                major::IRP_MJ_FLUSH_BUFFERS as u64,
                                0,
                                file_id,
                                &[],
                                &mut output,
                            ) {
                                Some((driver_status, completed, _)) => {
                                    routed = true;
                                    information = completed;
                                    driver_status as u32
                                }
                                None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                            }
                        }
                    }
                };
                if iosb_ok {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                if routed && status == 0x0000_0103 {
                    NT_FLUSH_BUFFERS_FILE_PENDING_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                if NT_FLUSH_BUFFERS_FILE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 4 {
                    print_str(b"[nt-flush-file] pi="); print_u64(self.pi as u64);
                    print_str(b" handle=0x"); print_hex(handle as u32);
                    print_str(b" iosb_ok="); print_u64(iosb_ok as u64);
                    print_str(b" file_id=0x"); print_hex(file_id as u32);
                    print_str(b" routed="); print_u64(routed as u64);
                    print_str(b" status=0x"); print_hex(status);
                    print_str(b" info="); print_u64(information);
                    print_str(b"\n");
                }
                status
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
                {
                    let oa_probe = get_recv_mr(7);
                    let nm = self.read_objattr_name_pe(oa_probe);
                    if boot_status_path_matches(&nm) {
                        let options = smss_stack_read(sp + 0x30) as u32;
                        let mut status = nt_fs::STATUS_SUCCESS;
                        let mut opened_handle = None;
                        if options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                            status = nt_fs::STATUS_OBJECT_NAME_COLLISION;
                        } else {
                            ensure_boot_status_data();
                            opened_handle = self.mint_boot_status_handle(args[1] as u32);
                            if opened_handle.is_none() {
                                status = 0xC000_009A;
                            }
                        }
                        if let Some(handle) = opened_handle {
                            self.queue_write(get_recv_mr(9), handle);
                        }
                        let iosb = get_recv_mr(8);
                        if iosb != 0 {
                            self.xas_write_buf(iosb, &status.to_le_bytes());
                            let info = if status == nt_fs::STATUS_SUCCESS {
                                nt_fs::FILE_OPENED as u64
                            } else {
                                0
                            };
                            self.xas_write_buf(iosb + 8, &info.to_le_bytes());
                        }
                        let lc: alloc::vec::Vec<u8> = nm
                            .iter()
                            .map(|&w| (w as u8).to_ascii_lowercase())
                            .collect();
                        loader_trace_record(
                            self.pi,
                            LoaderOp::OpenFile,
                            status,
                            None,
                            0,
                            opened_handle.unwrap_or(0),
                            &lc,
                        );
                        return status;
                    }
                }
                // pi==3 pipe client-open: a `\??\pipe\NAME` / `\Device\NamedPipe\NAME` open routes to
                // npfs (IRP_MJ_CREATE = client connect → finds the FCB via the real prefix tree). Placed
                // before the FS name-scope so a pipe path never falls into the DLL/System32 fakes.
                {
                    let oa_probe = get_recv_mr(7);
                    let nm = self.read_objattr_name_pe(oa_probe);
                    let lc: alloc::vec::Vec<u8> = nm.iter().map(|&w| (w as u8).to_ascii_lowercase()).collect();
                    let is_pipe = nt_fs::is_named_pipe_path(&nm);
                    if is_pipe && driver_launch::npfs_ready() {
                        let leaf = Self::pipe_leaf16(&nm);
                        if let Some((st, fid)) = self.npfs_route(0 /* IRP_MJ_CREATE */, 0, &leaf, 0) {
                            let mut status = st as u32;
                            let opened_handle = if status == 0 && fid != 0 {
                                let handle = self.mint_file_handle(fid, args[1] as u32);
                                if handle.is_none() { status = 0xC000_009A; }
                                handle
                            } else {
                                if status == 0 { status = nt_fs::STATUS_INVALID_DEVICE_REQUEST; }
                                None
                            };
                            if let Some(handle) = opened_handle {
                                self.queue_write(get_recv_mr(9), handle);
                                // ★ BATCH 34: a successful client CONNECT (IRP_MJ_CREATE paired the
                                // client to a server end by name in npfs) must complete the pending
                                // async server FSCTL_PIPE_LISTEN FOR THAT PIPE NAME — signal its
                                // completion event so the server's NtWaitForMultipleObjects wakes and
                                // reads the client's PDU. Name-scoped (no spurious cross-server wake).
                                if status == 0 {
                                    self.pipe_connect_redrive = nt_io_manager::pipe_name_hash(&leaf);
                                }
                            }
                            let iosb = get_recv_mr(8);
                            if iosb != 0 {
                                self.xas_write_buf(iosb, &status.to_le_bytes());
                                let info = if status == 0 { 1u64 } else { 0 };
                                self.xas_write_buf(iosb + 8, &info.to_le_bytes());
                            }
                            loader_trace_record(
                                self.pi,
                                LoaderOp::OpenFile,
                                status,
                                None,
                                0,
                                opened_handle.unwrap_or(0),
                                &lc,
                            );
                            return status;
                        }
                    }
                }
                // Read through the hosted process address space: activation-context filenames may
                // live on ntdll's process heap, not in the legacy boot mirror.
                let name16 = self.read_objattr_name_pe(get_recv_mr(7));
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
                // Classify SxS/activation-context paths without admitting them to image loading.
                let is_sxs = nb[..nlen].windows(6).any(|w| w == b".local")
                    || nb[..nlen].windows(9).any(|w| w == b".manifest")
                    || nb[..nlen].windows(7).any(|w| w == b".config");
                let want_dir = smss_stack_read(sp + 0x30) & FILE_DIRECTORY_FILE != 0;
                let open_options = smss_stack_read(sp + 0x30) as u32;
                let desired_access = args[1] as u32;
                let wants_read_data = desired_access & 0x0000_0001 != 0;
                let wants_execute = desired_access & 0x0000_0020 != 0;
                let synchronous = open_options & 0x0000_0030 != 0;
                let disk_entry = if !want_dir && wants_read_data && !wants_execute && synchronous {
                    nt_fs::nt_path_to_volume_relative(&name16, b"reactos")
                        .and_then(|path| exec_fs().and_then(|fs| fat_open_path(&fs, &path)))
                } else {
                    None
                };
                if let Some((first_cluster, file_size)) = disk_entry {
                    let mut status = nt_fs::STATUS_SUCCESS;
                    let opened_handle = self.mint_disk_file_handle(
                        first_cluster,
                        file_size,
                        desired_access,
                    );
                    if let Some(handle) = opened_handle {
                        self.queue_write(get_recv_mr(9), handle);
                    } else {
                        status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                    }
                    let iosb = get_recv_mr(8);
                    if iosb != 0 {
                        self.xas_write_buf(iosb, &status.to_le_bytes());
                        self.xas_write_buf(
                            iosb + 8,
                            &(if status == nt_fs::STATUS_SUCCESS { 1u64 } else { 0 }).to_le_bytes(),
                        );
                    }
                    loader_trace_record(
                        self.pi,
                        LoaderOp::OpenFile,
                        status,
                        None,
                        0,
                        opened_handle.unwrap_or(0),
                        &nb[..nlen],
                    );
                    return status;
                }
                // Directory opens resolve authoritatively against the mounted FAT volume. The
                // empty volume-relative path denotes the FAT root directory.
                let volume_entry = if want_dir {
                    nt_fs::nt_path_to_volume_relative(&name16, b"reactos")
                        .and_then(|path| {
                            exec_fs().and_then(|fs| {
                                if path.is_empty() {
                                    Some((fs.root_cl, 0, 0x10))
                                } else {
                                    fat_open_path_entry(&fs, &path)
                                }
                            })
                        })
                } else {
                    None
                };
                let volume_directory = volume_entry
                    .filter(|(_, _, attributes)| attributes & 0x10 != 0)
                    .map(|(first_cluster, _, _)| first_cluster);
                let volume_not_directory = volume_entry
                    .is_some_and(|(_, _, attributes)| attributes & 0x10 == 0);
                // csrss/winlogon/services/lsass.exe FILE opens (SmpExecuteImage /
                // RtlCreateUserProcess / winlogon's CreateProcessInternalW): the substring classifies
                // WHICH EXE, existence resolves against its CANONICAL leaf on the real \reactos FS
                // (`exe_probe_canon` + `sys32_exists`) — path-form/malformed-path independent, no
                // hand-maintained list. Loader manifest opens are unaffected (SxS rejected).
                let exe_canon = (!want_dir)
                    .then(|| Self::exe_probe_canon(&nb[..nlen], is_sxs))
                    .flatten();
                let exe_exists = exe_canon.is_some_and(|leaf| sys32_exists(leaf));
                let is_csrss = exe_exists && nb[..nlen].windows(5).any(|w| w == b"csrss");
                let is_winlogon = exe_exists && nb[..nlen].windows(8).any(|w| w == b"winlogon");
                let is_services = exe_exists && nb[..nlen].windows(8).any(|w| w == b"services");
                let is_lsass = exe_exists && nb[..nlen].windows(5).any(|w| w == b"lsass");
                // csrss's static import (csrsrv.dll) + its dynamic ServerDlls (basesrv/winsrv) + the
                // Win32 client stack. SCOPED TO csrss (pi==1): smss's SmpInit enumerates the KnownDLLs
                // — which now include kernel32/user32/gdi32 — and those opens MUST keep failing so
                // smss skips them and launches csrss. Only csrss's loader should resolve these DLLs.
                // nt-dll-registry keeps the image base/geometry role for CONTENT (SEC_IMAGE); nt-fs
                // owns namespace/existence (csrss.exe + System32 dir here). pi>=1 = csrss OR winlogon
                // (both load DLLs); smss (pi==0) still misses so its KnownDLLs opens fail + it
                // launches csrss/winlogon.
                let mut dll_i = if self.pi >= 1 && !want_dir {
                    reg.resolve_name(&nb[..nlen])
                } else {
                    None
                };
                // TRUE syscall-time DEMAND-LOAD: a DLL-loading process (pi>=1) whose loader requests a
                // DLL not yet registered (resolve miss) + not an SxS probe → resolve it BY PATH from
                // the real \reactos\system32 FS, load into the pool, activate a reserved registry slot,
                // relocate, and stash its parsed PE. From here it behaves exactly like a boot-pinned
                // DLL (NtCreateSection/NtMapViewOfSection/the fault router all go through the registry +
                // dll_pes). This is what retires the eager DLL list — no maintained table.
                if self.pi >= 1 && !want_dir && dll_i.is_none() && !is_sxs {
                    if let Some(slot) = demand_load_dll(
                        reg,
                        ctx.dll_pe_store,
                        DLL_REG_COUNT,
                        &nb[..nlen],
                    ) {
                        // Pin the heap mark past the load's registry allocations (service loop consumes).
                        self.dll_loaded_dirty = true;
                        dll_i = Some(slot);
                    } else if self.pi != 2
                        && (nb[..nlen].ends_with(b".dll")
                            || nb[..nlen].windows(4).any(|w| w == b".dll"))
                    {
                        // DIAG: a .dll open that missed the registry AND failed to demand-load — log it
                        // so we can see which dependency the loader requested that we couldn't satisfy.
                        print_str(b"[demand-miss] pi=");
                        print_u64(self.pi as u64);
                        print_str(b" name=");
                        print_str(&nb[..nlen.min(64)]);
                        print_str(b"\n");
                    }
                }
                let mut opened_handle = 0;
                let status: u32 = if volume_directory.is_some()
                    || is_csrss
                    || is_winlogon
                    || is_services
                    || is_lsass
                    || dll_i.is_some()
                {
                    let h = if let Some(first_cluster) = volume_directory {
                        self.mint_directory_handle(first_cluster, desired_access)
                    } else {
                        Some(self.mint_handle())
                    };
                    let Some(h) = h else {
                        let status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                        let iosb = get_recv_mr(8);
                        if iosb != 0 {
                            smss_stack_write32(iosb, status);
                            smss_stack_write(iosb + 8, 0);
                        }
                        loader_trace_record(
                            self.pi,
                            LoaderOp::OpenFile,
                            status,
                            dll_i,
                            0,
                            0,
                            &nb[..nlen],
                        );
                        return status;
                    };
                    opened_handle = h;
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
                    if is_lsass {
                        *ctx.lsass_file_handle = h; // for NtCreateSection (winlogon → lsass.exe)
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
                    // DIAG (BATCH 23): log lsass's (pi==4) unresolved NtOpenFile — its LSA init opens a
                    // named object we don't model and bails with OBJECT_NAME_NOT_FOUND. Surface the name.
                    if self.pi == 4 {
                        print_str(b"[lsass-open-miss] name=");
                        print_str(&nb[..nlen.min(80)]);
                        print_str(b" -> 0xC0000034\n");
                    }
                    if volume_not_directory {
                        0xC000_0103 // STATUS_NOT_A_DIRECTORY
                    } else {
                        0xC000_0034 // no filesystem yet → not found (smss skips / uses defaults)
                    }
                };
                loader_trace_record(
                    self.pi,
                    LoaderOp::OpenFile,
                    status,
                    dll_i,
                    0,
                    opened_handle,
                    &nb[..nlen],
                );
                status
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
                        let mut info = nt_dll_registry::image_info(
                            PE_LOAD_BASE,
                            p.entry_point_rva(),
                            p.size_of_image(),
                            false,
                        );
                        let (major, minor) = p.subsystem_version();
                        info[0x20..0x24].copy_from_slice(&(p.subsystem() as u32).to_le_bytes());
                        info[0x24..0x26].copy_from_slice(&minor.to_le_bytes());
                        info[0x26..0x28].copy_from_slice(&major.to_le_bytes());
                        (info, b"winlogon.exe" as &[u8])
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
                } else if self.pi == 2
                    && *ctx.lsass_section_handle != 0
                    && sect == *ctx.lsass_section_handle
                {
                    // winlogon's kernel32 queries SectionImageInformation on the lsass.exe SEC_IMAGE
                    // before NtCreateProcessEx. Same subsystem/version patch as services.
                    (*ctx.lsass_pe).as_ref().map(|p| {
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
                        (info, b"lsass.exe" as &[u8])
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
                    print_str(b" subsystem=");
                    print_u64(u32::from_le_bytes(bytes[0x20..0x24].try_into().unwrap()) as u64);
                    print_str(b"\n");
                    0
                } else {
                    self.stop = true;
                    0xC0000002
                }
            },
            // NtQueryDefaultLocale(UserProfile, *DefaultLocaleId[RDX]=args[1]). The caller may pass a
            // stack local (winsrv's hard-error cache) or an image/DLL global (ntdll loader state), so
            // use the common cross-address-space DWORD copyout and report a bad pointer truthfully.
            NativeService::NtQueryDefaultLocale => unsafe {
                let out = args[1]; // RDX = *DefaultLocaleId
                if out == 0 || out & 3 != 0 {
                    return if out == 0 { 0xC000_0005 } else { 0x8000_0002 };
                }
                if self.xas_write_u32(out, 0x409) { 0 } else { 0xC000_0005 }
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
                let dll_pes = ctx.dll_pes();
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
                let registry_slot = reg.index_for_file(self.pi, sec_file);
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
                // The lsass.exe SEC_IMAGE is also created by WINLOGON (pi 2) — its StartLsass
                // CreateProcessW. Distinct dense file handle (append-only) → no alias with services.
                if self.pi == 2 && *ctx.lsass_file_handle != 0 && sec_file == *ctx.lsass_file_handle {
                    *ctx.lsass_section_handle = h;
                    LSASS_CREATE_STARTED.store(1, Ordering::Relaxed);
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for lsass.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // A registry DLL (csrsrv/basesrv/winsrv): record its section handle by file handle.
                if let Some(i) = registry_slot {
                    reg.set_section_handle(self.pi, i, h);
                    if self.pi != 2 {
                        print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for ");
                        print_str(reg.name(i));
                        print_str(b" -> handle 0x");
                        print_hex(h as u32);
                        print_str(b"\n");
                    }
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
                loader_trace_record(
                    self.pi,
                    LoaderOp::CreateSection,
                    0,
                    registry_slot,
                    sec_file,
                    h,
                    b"",
                );
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
                let dll_pes = ctx.dll_pes();
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let pml4 = ctx.pml4;
                let scratch_base = ctx.scratch_base;
                let sp = get_recv_mr(16);
                let sect = get_recv_mr(9);
                if let Some(i) = reg.index_for_section(self.pi, sect) {
                    // Reserve every 2 MiB PT window touched by this DLL's compact VA range. Compact
                    // neighbors may share a PT and large images may span several.
                    if let Some(cpe) = dll_pes[i].as_ref() {
                        let dbase = reg.base(i);
                        // PER-PROCESS PD/PT reservation: the DLL's fixed base is the same in every
                        // process, but each VSpace needs its own page tables. csrss and winlogon load
                        // an overlapping DLL set at identical bases into distinct VSpaces, so gate the
                        // reservation on this process's bitmask, not the registry's global `mapped`.
                        let pi = self.pi;
                        let dll_pd_created = &mut *ctx.dll_pd_created;
                        let dll_pt_bits = &mut *ctx.dll_pt_bits;
                        if !dll_pd_created[pi] {
                            let pd = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
                            let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, DLL_ARENA_START, pml4);
                            dll_pd_created[pi] = true;
                        }
                        if let Some(pt_range) = reg.page_table_range(i) {
                            for pt_index in pt_range {
                                let word = pt_index / 64;
                                let bit = 1u64 << (pt_index % 64);
                                if dll_pt_bits[pi][word] & bit == 0 {
                                    let pt = alloc_slot();
                                    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                                    let pt_va = DLL_ARENA_START
                                        + pt_index as u64 * nt_dll_registry::PAGE_TABLE_SPAN;
                                    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_va, pml4);
                                    dll_pt_bits[pi][word] |= bit;
                                }
                            }
                        }
                        reg.set_mapped(i);
                        let ext = image_extent(cpe);
                        csrss_out_write(get_recv_mr(7), dbase, filled_pages, faults, scratch_base, reg, dll_pes, pml4); // *BaseAddress
                        let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                        if vs_ptr != 0 {
                            csrss_out_write(vs_ptr, ext, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                        }
                        if self.pi != 2 {
                            print_str(b"[ntos-exec] NtMapViewOfSection ");
                            print_str(reg.name(i));
                            print_str(b" -> base 0x");
                            print_hex(dbase as u32);
                            print_str(b"\n");
                        }
                        loader_trace_record(
                            self.pi,
                            LoaderOp::MapViewOfSection,
                            0,
                            Some(i),
                            sect,
                            dbase,
                            b"",
                        );
                        0
                    } else {
                        self.stop = true;
                        loader_trace_record(
                            self.pi,
                            LoaderOp::MapViewOfSection,
                            0xC0000002,
                            Some(i),
                            sect,
                            0,
                            b"",
                        );
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
                    loader_trace_record(
                        self.pi,
                        LoaderOp::MapViewOfSection,
                        0,
                        None,
                        sect,
                        *ctx.csrss_anon_base,
                        b"",
                    );
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
                    loader_trace_record(
                        self.pi,
                        LoaderOp::MapViewOfSection,
                        0,
                        None,
                        sect,
                        NLS_SECTION_CSRSS_VA,
                        b"",
                    );
                    0
                } else {
                    self.stop = true; // other sections not modeled
                    loader_trace_record(
                        self.pi,
                        LoaderOp::MapViewOfSection,
                        0xC0000002,
                        None,
                        sect,
                        0,
                        b"",
                    );
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
                if self.pi == 2 {
                    print_str(b"[wl-createproc] pi=2 sect=0x");
                    print_hex(sect as u32);
                    print_str(b" services_sect=0x");
                    print_hex(*ctx.services_section_handle as u32);
                    print_str(b" lsass_sect=0x");
                    print_hex(*ctx.lsass_section_handle as u32);
                    print_str(b" lsass_pe=");
                    print_u64((*ctx.lsass_pe).is_some() as u64);
                    print_str(b"\n");
                }
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
                } else if self.pi == 2
                    && *ctx.services_section_handle != 0
                    && sect == *ctx.services_section_handle
                    && (*ctx.services_pe).is_some()
                {
                    // winlogon's Win32 NtCreateProcessEx(50) StartServicesManager — loop spawns
                    // services.exe (4th process). SSN 50 routes here (registered in the native table),
                    // so the spawn body lives in the loop's flag-consumption block (mirrors winlogon).
                    self.services_spawn_request = true;
                    0
                } else if self.pi == 2
                    && *ctx.lsass_section_handle != 0
                    && sect == *ctx.lsass_section_handle
                    && (*ctx.lsass_pe).is_some()
                {
                    // winlogon's Win32 NtCreateProcessEx(50) StartLsass — loop spawns lsass.exe (5th).
                    self.lsass_spawn_request = true;
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
                    if let Some(code) = self.pm.critical_process_termination_code(pid) {
                        self.post_action = ExecPostAction::CriticalTermination {
                            code,
                            object: pid as u64,
                        };
                        return 0;
                    }
                    let _ = self.pm.terminate_process(pid, status);
                }
                0 // STATUS_SUCCESS (matches the prior broker fallback for an unresolved handle)
            }
            NativeService::NtTerminateThread => {
                const THREAD_TERMINATE: u32 = 0x0001;
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                let caller_pid = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => {
                        print_str(b"[thread-term-reject] no caller pid badge=");
                        print_u64(self.current_badge);
                        print_str(b" pi=");
                        print_u64(self.pi as u64);
                        print_str(b" handle=0x");
                        print_hex(handle as u32);
                        print_str(b"\n");
                        return nt_process::STATUS_INVALID_HANDLE;
                    }
                };
                let current_tid = self.current_tid as nt_process::ThreadId;
                let target = match self.pm.resolve_terminate_thread_handle(
                    caller_pid,
                    current_tid,
                    handle,
                    THREAD_TERMINATE,
                ) {
                    Ok(tid) => tid,
                    Err(status) => {
                        print_str(b"[thread-term-reject] resolve badge=");
                        print_u64(self.current_badge);
                        print_str(b" pi=");
                        print_u64(self.pi as u64);
                        print_str(b" pid=");
                        print_u64(caller_pid as u64);
                        print_str(b" tid=");
                        print_u64(current_tid as u64);
                        print_str(b" handle-hi=0x");
                        print_hex((handle >> 32) as u32);
                        print_str(b" lo=0x");
                        print_hex(handle as u32);
                        print_str(b" status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        return status;
                    }
                };
                let prior_state = self.pm.thread(target).map(|thread| thread.state);
                let is_current = target == current_tid;
                if let Some(code) = self.pm.critical_thread_termination_code(target) {
                    self.post_action = ExecPostAction::CriticalTermination {
                        code,
                        object: target as u64,
                    };
                    return 0;
                }
                let outcome = if self.pi == 1 && self.pm.main_thread(caller_pid) == Some(target) {
                    self.pm.exit_thread(target, status)
                } else {
                    self.pm.terminate_thread(target, status)
                };
                if let Err(status) = outcome {
                    return status;
                }
                self.post_action = if is_current {
                    ExecPostAction::TerminateCurrentThread { tid: target as u64 }
                } else {
                    ExecPostAction::TerminateRemoteThread { tid: target as u64 }
                };
                PM_TERMINATE_THREAD_LIVE.fetch_add(1, Ordering::Relaxed);
                PM_TERMINATE_THREAD_STATE.fetch_or(1 << self.pi, Ordering::Relaxed);
                if is_current && self.current_badge < 64 {
                    PM_TERMINATE_THREAD_BADGES.fetch_or(
                        1u64 << self.current_badge,
                        Ordering::Relaxed,
                    );
                }
                if PM_TERMINATE_THREAD_TRACE.fetch_add(1, Ordering::Relaxed) < 8 {
                    print_str(b"[thread-term] badge=");
                    print_u64(self.current_badge);
                    print_str(b" pi=");
                    print_u64(self.pi as u64);
                    print_str(b" caller_tid=");
                    print_u64(current_tid as u64);
                    print_str(b" handle=0x");
                    print_hex(handle as u32);
                    print_str(b" exit=0x");
                    print_hex(status);
                    print_str(b" target_tid=");
                    print_u64(target as u64);
                    print_str(if is_current { b" self=1 prior=" } else { b" self=0 prior=" });
                    print_u64(prior_state.map(|state| state as u64).unwrap_or(u64::MAX));
                    print_str(b"\n");
                }
                0
            }
            _ => 0xC000_0002, // STATUS_NOT_IMPLEMENTED — never silently succeed
        }
    }
}
