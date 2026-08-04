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

fn image_metadata_from_pe(
    pe: &nt_pe_loader::PeFile<'static>,
    pool_va: u64,
) -> nt_exe_image::ImageMetadata {
    let (major, minor) = pe.subsystem_version();
    nt_exe_image::ImageMetadata {
        pool_va,
        file_size: pe.bytes().len() as u64,
        image_size: pe.size_of_image() as u64,
        entry_rva: pe.entry_point_rva(),
        subsystem: pe.subsystem(),
        subsystem_major: major,
        subsystem_minor: minor,
    }
}

unsafe fn loaded_hosted_image_metadata(
    ctx: ExecLoopCtx,
    hosted: nt_exe_image::HostedProcessImageRef<'_>,
) -> Option<nt_exe_image::ImageMetadata> {
    let (pe, pool_va) = unsafe { (&*ctx.hosted_loaded_images).pe_and_pool_for_image(hosted)? };
    Some(image_metadata_from_pe(pe, pool_va))
}

unsafe fn record_hosted_child_exe_open(
    ctx: ExecLoopCtx,
    owner_pi: usize,
    hosted: nt_exe_image::HostedProcessImageRef<'_>,
    file_handle: u64,
) -> bool {
    let Some(metadata) = (unsafe { loaded_hosted_image_metadata(ctx, hosted) }) else {
        return false;
    };
    let opened = unsafe { &mut *ctx.exe_images }
        .open(owner_pi, hosted.leaf, file_handle, metadata)
        .is_ok();
    if opened {
        match hosted.role {
            nt_exe_image::HostedProcessRole::InteractiveShellBootstrap => {
                USERINIT_IMAGE_OPEN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
            }
            nt_exe_image::HostedProcessRole::InteractiveShell => {
                EXPLORER_IMAGE_OPEN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
    opened
}

/// `NtCreateToken`'s bounded reader over the CALLING process' address space — the executive's
/// cross-address-space copy-in behind the pure `nt_security::ClientMemory` capture contract.
/// `xas_read` resolves the stack/heap/image mirrors, the persistent frame aliases, and finally the
/// backing PE, and returns `false` for anything it cannot reach — which the capture turns into
/// `STATUS_ACCESS_VIOLATION` rather than reading garbage.
struct ExecClientMemory<'a> {
    handler: &'a ExecNtHandler,
}

impl nt_security::ClientMemory for ExecClientMemory<'_> {
    fn read(&self, va: u64, dst: &mut [u8]) -> bool {
        // SAFETY: `xas_read` only reads through the executive's own mirrors/aliases for the
        // handler's current process index; `dst` is a live local slice.
        unsafe { self.handler.xas_read(va, dst) }
    }
}

/// Render a `TOKEN_SOURCE::SourceName` (8 raw bytes, not NUL-terminated) printably.
fn captured_source_bytes(packed: u64) -> [u8; 8] {
    let mut name = packed.to_le_bytes();
    for byte in name.iter_mut() {
        if !(0x20..0x7f).contains(byte) {
            *byte = b'.';
        }
    }
    name
}

pub(crate) fn native_processor_information(
) -> nt_syscall::system_information::SystemProcessorInformation {
    use core::arch::x86_64::__cpuid;
    use nt_syscall::system_information::{amd64_processor_information_from_cpuid, X86Vendor};

    let vendor_leaf = __cpuid(0);
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&vendor_leaf.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&vendor_leaf.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&vendor_leaf.ecx.to_le_bytes());
    let vendor = match &vendor_bytes {
        b"GenuineIntel" => X86Vendor::Intel,
        b"AuthenticAMD" => X86Vendor::Amd,
        _ => X86Vendor::Other,
    };
    let version = __cpuid(1);
    let max_extended = __cpuid(0x8000_0000).eax;
    let extended_edx = if max_extended >= 0x8000_0001 {
        __cpuid(0x8000_0001).edx
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

fn native_processor_vendor_identifier() -> alloc::string::String {
    use core::arch::x86_64::__cpuid;

    let vendor_leaf = __cpuid(0);
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&vendor_leaf.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&vendor_leaf.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&vendor_leaf.ecx.to_le_bytes());
    let vendor = core::str::from_utf8(&vendor_bytes).unwrap_or("UnknownCPU");
    alloc::string::String::from(vendor)
}

fn native_processor_registry_identifier() -> alloc::string::String {
    let info = native_processor_information();
    let vendor = native_processor_vendor_identifier();
    let arch = if vendor == "AuthenticAMD" {
        "AMD64"
    } else if vendor == "GenuineIntel" {
        "Intel64"
    } else {
        "x64"
    };
    alloc::format!(
        "{} Family {} Model {} Stepping {}",
        arch,
        info.processor_level,
        info.processor_revision >> 8,
        info.processor_revision & 0xff
    )
}

fn registry_sz_bytes(value: &str) -> alloc::vec::Vec<u8> {
    let mut data = alloc::vec::Vec::new();
    for unit in value.encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes());
    data
}

fn utf16_units_to_string(units: &[u16]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for &unit in units {
        if let Some(c) = char::from_u32(unit as u32) {
            out.push(c);
        }
    }
    out
}

fn is_profile_list_sid_key_canon(path: &str) -> bool {
    let comps: alloc::vec::Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
    comps.len() == 8
        && comps[0].eq_ignore_ascii_case("Registry")
        && comps[1].eq_ignore_ascii_case("Machine")
        && comps[2].eq_ignore_ascii_case("Software")
        && comps[3].eq_ignore_ascii_case("Microsoft")
        && comps[4].eq_ignore_ascii_case("Windows NT")
        && comps[5].eq_ignore_ascii_case("CurrentVersion")
        && comps[6].eq_ignore_ascii_case("ProfileList")
        && comps[7].starts_with("s-")
}

fn native_basic_system_information() -> nt_syscall::system_information::SystemBasicInformation {
    let processors = SYSTEM_PROCESSOR_COUNT.load(Ordering::Relaxed) as u8;
    let affinity = if processors >= 64 {
        u64::MAX
    } else {
        (1u64 << processors) - 1
    };
    nt_syscall::system_information::SystemBasicInformation {
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

fn seed_time_zone(hive: Option<&RegfHive<'_>>) -> nt_kernel_exec::timezone::TimeZoneInformation {
    use nt_kernel_exec::timezone::{TimeZoneInformation, TimeZoneRegistryField};

    let mut information = TimeZoneInformation::default();
    let Some(hive) = hive else {
        return information;
    };
    let Some(key) = hive.open_key("ControlSet001\\Control\\TimeZoneInformation") else {
        return information;
    };
    for (name, field) in [
        ("Bias", TimeZoneRegistryField::Bias),
        ("StandardName", TimeZoneRegistryField::StandardName),
        ("StandardBias", TimeZoneRegistryField::StandardBias),
        ("StandardStart", TimeZoneRegistryField::StandardStart),
        ("DaylightName", TimeZoneRegistryField::DaylightName),
        ("DaylightBias", TimeZoneRegistryField::DaylightBias),
        ("DaylightStart", TimeZoneRegistryField::DaylightStart),
    ] {
        if let Some((value_type, data)) = hive.value(key, name) {
            let _ = information.apply_registry_value(field, value_type, &data);
        }
    }
    information
}

fn effective_time_zone(
    information: nt_kernel_exec::timezone::TimeZoneInformation,
    current_time: u64,
) -> nt_kernel_exec::timezone::EffectiveTimeZone {
    information.effective_at(current_time as i64).unwrap_or(
        nt_kernel_exec::timezone::EffectiveTimeZone {
            id: nt_kernel_exec::timezone::TIME_ZONE_ID_UNKNOWN,
            bias_100ns: i64::from(information.bias) * nt_kernel_exec::timezone::TICKS_PER_MINUTE,
        },
    )
}

unsafe fn publish_time_zone(
    information: nt_kernel_exec::timezone::TimeZoneInformation,
    current_time: u64,
) {
    let effective = effective_time_zone(information, current_time);
    SYSTEM_TIME_ZONE_BIAS_100NS.store(effective.bias_100ns as u64, Ordering::Relaxed);
    SYSTEM_TIME_ZONE_ID.store(effective.id, Ordering::Relaxed);
    for pi in 0..MAX_PI {
        let alias = unsafe { kuser_page_alias_get(pi) };
        if alias != 0 {
            unsafe {
                nt_ntdll_layout::kuser::publish_time_zone(
                    alias as *mut u8,
                    effective.bias_100ns,
                    effective.id,
                )
            };
        }
    }
}

#[inline(never)]
fn build_initial_object_namespace() -> alloc::vec::Vec<ObjEntry> {
    let mut v = alloc::vec::Vec::with_capacity(192);
    v.push(ObjEntry::dir(b"", 0xFF)); // 0 = root "\"
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
    let windows = v
        .iter()
        .position(|entry| entry.parent == 0 && entry.name() == b"windows")
        .expect("pre-created Windows object directory");
    v.push(ObjEntry::dir(b"windowstations", windows as u8));
    v
}

struct BootstrapProcessManagerSeed {
    pm: nt_process::ProcessManager,
    pids: [nt_process::ProcessId; 3],
    main_tids: [nt_process::ThreadId; 3],
    pool_tids: [[nt_process::ThreadId; PM_RUNTIME_THREAD_SLOTS]; 3],
}

#[inline(never)]
fn seed_bootstrap_process_manager() -> BootstrapProcessManagerSeed {
    let mut pm = nt_process::ProcessManager::new();
    let mut bootstrap_pids: [nt_process::ProcessId; 3] = [0; 3];
    let mut bootstrap_main_tids: [nt_process::ThreadId; 3] = [0; 3];
    let mut bootstrap_pool_tids: [[nt_process::ThreadId; PM_RUNTIME_THREAD_SLOTS]; 3] =
        [[0; PM_RUNTIME_THREAD_SLOTS]; 3];

    pm.set_handle_no_reuse(true);
    pm.reserve_modules(64);
    PM_PROC_COUNT.store(0, Ordering::Relaxed);
    PM_DYNAMIC_PROCESS_ALLOCATIONS.store(0, Ordering::Relaxed);
    PM_IDENTITY_OK.store(0, Ordering::Relaxed);
    PM_VSPACE_PUBLISHED_OK.store(0, Ordering::Relaxed);
    reset_hosted_gate_metadata();
    PM_MAIN_THREADS_OK.store(0, Ordering::Relaxed);
    HOSTED_THREAD_RUNTIME_OK.store(0, Ordering::Relaxed);
    PM_HANDLE_CAP_BOOT.store(0, Ordering::Relaxed);

    let smss_pid = pm.create_process("smss.exe", None, None);
    let csrss_pid = pm.create_process("csrss.exe", Some(smss_pid), None);
    let winlogon_pid = pm.create_process("winlogon.exe", Some(smss_pid), None);
    bootstrap_pids.copy_from_slice(&[smss_pid, csrss_pid, winlogon_pid]);
    for &pid in &bootstrap_pids {
        let _ = pm.set_peb_base(pid, SMSS_PEB_VA);
    }
    for (pi, &pid) in bootstrap_pids.iter().enumerate() {
        if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
            bootstrap_main_tids[pi] = tid;
        }
    }
    for (pi, &pid) in bootstrap_pids.iter().enumerate() {
        for slot in 0..PM_RUNTIME_THREAD_SLOTS {
            if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                let _ = pm.set_thread_state(tid, nt_process::ThreadState::Initialized);
                bootstrap_pool_tids[pi][slot] = tid;
            }
        }
    }
    for &pid in &bootstrap_pids {
        pm.reserve_handles(pid, PM_HANDLE_RESERVE);
    }

    BootstrapProcessManagerSeed {
        pm,
        pids: bootstrap_pids,
        main_tids: bootstrap_main_tids,
        pool_tids: bootstrap_pool_tids,
    }
}

impl ExecNtHandler {
    #[inline(never)]
    pub(crate) unsafe fn initialize_in(
        slot: *mut ExecNtHandler,
        hosted_images: *const nt_exe_image::OwnedHostedImageCatalog<8>,
    ) -> &'static mut Self {
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
        // The REAL SECURITY + SAM hives the storage host read BY PATH off
        // `\reactos\system32\config\{security,sam}`. Same mechanism as the SYSTEM hive: borrow the
        // staged bytes (no copy) and parse them read-only with nt-hive-regf.
        // SAFETY: fixed executive-lifetime mappings; the sizes are what the storage host reported
        // (0 if the file wasn't staged → None → the mount is simply absent).
        let (security_hive, sam_hive) = unsafe {
            let mount = |base: u64, size: u64| -> Option<RegfHive<'static>> {
                let n = size as usize;
                if n == 0 || !SECURITY_SAM_HIVES_MOUNTED {
                    return None;
                }
                RegfHive::new(core::slice::from_raw_parts(base as *const u8, n))
            };
            (
                mount(SECHIVEBUF_VADDR, SECURITY_HIVE_SIZE.load(Ordering::Relaxed)),
                mount(SAMHIVEBUF_VADDR, SAM_HIVE_SIZE.load(Ordering::Relaxed)),
            )
        };
        // The 4th mount: the REAL 471040 B SOFTWARE hive the storage host read BY PATH off
        // `\reactos\system32\config\software` into SWHIVEBUF. Same borrow-no-copy mechanism.
        // SAFETY: a fixed executive-lifetime mapping; the size is what the storage host reported
        // (0 if the file wasn't staged → None → the mount is simply absent).
        let software_hive = unsafe {
            let n = SOFTWARE_HIVE_SIZE.load(Ordering::Relaxed) as usize;
            if n == 0 || !SOFTWARE_HIVE_MOUNTED {
                None
            } else {
                RegfHive::new(core::slice::from_raw_parts(SWHIVEBUF_VADDR as *const u8, n))
            }
        };
        // ★ THE `\Registry\User` MOUNT TABLE. `\Registry\User\.Default` is the genuine
        // `config\default` (`$$$PROTO.HIV`) the storage host read BY PATH into DEFHIVEBUF, mounted
        // exactly where `CmpInitializeHiveList` mounts it on a real NT boot — and mounted through
        // the SAME table `NtLoadKey` uses, so a per-user hive is not a special case.
        // SAFETY: DEFHIVEBUF is a fixed executive-lifetime mapping; the size is the storage host's.
        let mut hive_mounts: alloc::vec::Vec<HiveMount> =
            alloc::vec::Vec::with_capacity(1 + USER_HIVE_SLOTS);
        unsafe {
            if let Some(hive) = crate::writable_fs::default_hive_bytes().and_then(RegfHive::new) {
                hive_mounts.push(HiveMount {
                    sel: HIVE_SEL_USER_DEFAULT,
                    canon: alloc::string::String::from(r"\registry\user\.default"),
                    mount: alloc::string::String::from(hive_mount(HIVE_SEL_USER_DEFAULT)),
                    file: alloc::string::String::from(r"\SystemRoot\System32\config\default"),
                    hive,
                    slot: None,
                    dynamic: false,
                });
            }
        }
        unsafe {
            print_str(b"[cm-hive] mounted base hives: SYSTEM=");
            print_u64(REAL_HIVE_SIZE.load(Ordering::Relaxed));
            print_str(b"B SECURITY=");
            print_u64(SECURITY_HIVE_SIZE.load(Ordering::Relaxed));
            print_str(b"B(root=");
            print_u64(security_hive.as_ref().map_or(0, |h| u64::from(h.root())));
            print_str(b" subkeys=");
            print_u64(
                security_hive
                    .as_ref()
                    .map_or(0, |h| h.subkeys(h.root()).len() as u64),
            );
            print_str(b") SAM=");
            print_u64(SAM_HIVE_SIZE.load(Ordering::Relaxed));
            print_str(b"B(root=");
            print_u64(sam_hive.as_ref().map_or(0, |h| u64::from(h.root())));
            print_str(b" subkeys=");
            print_u64(
                sam_hive
                    .as_ref()
                    .map_or(0, |h| h.subkeys(h.root()).len() as u64),
            );
            print_str(b") SOFTWARE=");
            print_u64(SOFTWARE_HIVE_SIZE.load(Ordering::Relaxed));
            print_str(b"B(root=");
            print_u64(software_hive.as_ref().map_or(0, |h| u64::from(h.root())));
            print_str(b" subkeys=");
            print_u64(
                software_hive
                    .as_ref()
                    .map_or(0, |h| h.subkeys(h.root()).len() as u64),
            );
            print_str(b") \\Registry\\User mounts=");
            print_u64(hive_mounts.len() as u64);
            print_str(b" .Default=");
            print_u64(DEFAULT_HIVE_SIZE.load(Ordering::Relaxed));
            print_str(b"B(subkeys=");
            print_u64(
                hive_mounts
                    .first()
                    .map_or(0, |m| m.hive.subkeys(m.hive.root()).len() as u64),
            );
            print_str(b")\n");
        }
        let time_zone_information = seed_time_zone(hive.as_ref());
        unsafe { publish_time_zone(time_zone_information, nt_system_time_100ns()) };
        let BootstrapProcessManagerSeed {
            pm,
            pids: bootstrap_pids,
            main_tids: bootstrap_main_tids,
            pool_tids: bootstrap_pool_tids,
        } = seed_bootstrap_process_manager();
        macro_rules! write_field {
            ($field:ident, $value:expr) => {
                unsafe {
                    core::ptr::addr_of_mut!((*slot).$field).write($value);
                }
            };
        }
        write_field!(hive, hive);
        write_field!(security_hive, security_hive);
        write_field!(sam_hive, sam_hive);
        write_field!(software_hive, software_hive);
        write_field!(hive_mounts, hive_mounts);
        write_field!(hive_mounts_dirty, false);
        write_field!(time_zone_information, time_zone_information);
        write_field!(obj_ns, build_initial_object_namespace());
        write_field!(events, nt_kernel_exec::EventStore::with_capacity(192));
        write_field!(
            semaphores,
            nt_kernel_exec::SemaphoreStore::with_capacity(192)
        );
        write_field!(mutants, nt_kernel_exec::MutantStore::with_capacity(192));
        write_field!(
            global_atoms,
            nt_kernel_exec::rtl_atom::OwnedAtomTable::with_capacity(GLOBAL_ATOM_CAPACITY).unwrap()
        );
        write_field!(
            io_completion_ports,
            nt_io_completion::CompletionPortTable::new()
        );
        write_field!(
            file_completion,
            nt_io_completion::FileCompletionTable::new()
        );
        write_field!(directory_opens, ExecDirectoryOpens::reset());
        write_field!(pi, 0);
        write_field!(current_tid, 0);
        write_field!(current_badge, 0);
        write_field!(post_action, ExecPostAction::None);
        write_field!(stop, false);
        write_field!(next_handle, FAKE_HANDLE);
        write_field!(out_writes, [(0, 0); 8]);
        write_field!(out_writes_n, 0);
        write_field!(loop_ctx, None);
        write_field!(exe_spawn_request, None);
        write_field!(thread_spawn_request, None);
        write_field!(remote_thread_request, None);
        write_field!(wait_park_event, -1);
        write_field!(wait_deadline_100ns, u64::MAX);
        write_field!(keyed_wait_key, u64::MAX);
        write_field!(keyed_wait_deadline_100ns, u64::MAX);
        write_field!(delay_requested, false);
        write_field!(delay_interval_100ns, 0);
        write_field!(delay_alertable, false);
        write_field!(io_completion_park_port, -1);
        write_field!(io_completion_key_out, 0);
        write_field!(io_completion_apc_out, 0);
        write_field!(io_completion_iosb_out, 0);
        write_field!(io_completion_deadline_100ns, u64::MAX);
        write_field!(io_completion_wake, None);
        write_field!(io_signal_event, -1);
        write_field!(pipe_park_fid, 0);
        write_field!(pipe_park_buffer_va, 0);
        write_field!(pipe_park_buffer_len, 0);
        write_field!(pipe_park_iosb_va, 0);
        write_field!(pipe_park_apc_context, 0);
        write_field!(pipe_park_event_obj_idx, u64::MAX);
        write_field!(pipe_park_transceive, false);
        write_field!(pipe_park_is_write, false);
        write_field!(dbgk_block_request, false);
        write_field!(pipe_write_redrive, false);
        write_field!(pipe_listen_fid, 0);
        write_field!(pipe_listen_event_handle, 0);
        write_field!(pipe_listen_iosb_va, 0);
        write_field!(pipe_connect_redrive, 0);
        write_field!(anon_event_seq, 0);
        write_field!(lpc_rendezvous_conn, 0);
        write_field!(lpc_rendezvous_out, 0);
        write_field!(sm_request_port, 0);
        write_field!(sm_request_message, 0);
        write_field!(sm_reply_message, 0);
        write_field!(csr_request_port, 0);
        write_field!(csr_request_message, 0);
        write_field!(csr_reply_message, 0);
        write_field!(csr_start_request, 0);
        write_field!(csr_rendezvous_conn, 0);
        write_field!(csr_rendezvous_out, 0);
        write_field!(lpc_connections, alloc::vec::Vec::with_capacity(16));
        write_field!(winlogon_csr_view, 0);
        write_field!(csr_view_mask, 0);
        write_field!(pm, pm);
        write_field!(
            process_mechanisms,
            nt_user_host::ProcessMechanismTable::new()
        );
        write_field!(hosted_images, hosted_images);
        write_field!(process_vspaces, [0; MAX_PI]);
        write_field!(temporary_process_slots, [0; MAX_PI]);
        write_field!(thread_mechanisms, nt_user_host::ThreadMechanismTable::new());
        write_field!(pool_used, [0; MAX_PI]);
        write_field!(pool_suspended, [0; MAX_PI]);
        write_field!(thread_runtime, HostedThreadRuntimes::reset());
        write_field!(win32k_session, Win32kSessionRuntime::reset());
        write_field!(token_store, nt_security::TokenStore::with_capacity(64));
        write_field!(token_dirty, false);
        write_field!(process_dirty, false);
        write_field!(overlay, nt_hive_core::RegistryOverlay::with_capacity(64));
        write_field!(overlay_dirty, false);
        write_field!(dll_loaded_dirty, false);
        write_field!(writable_fs_dirty, false);
        let handler = &mut *slot;
        for (pi, &pid) in bootstrap_pids.iter().enumerate() {
            let main_tid = bootstrap_main_tids[pi];
            if pid != 0 && main_tid != 0 {
                if let Some(image) = handler.hosted_process_image(pi) {
                    let top_badge = image.top_badge;
                    let _ = handler.publish_registered_hosted_process_metadata(image);
                    let _ = handler.register_hosted_process_identity(pi, pid, main_tid, top_badge);
                }
                for slot in 0..PM_RUNTIME_THREAD_SLOTS {
                    let tid = bootstrap_pool_tids[pi][slot];
                    if tid != 0 {
                        let _ = handler.register_hosted_pool_thread_identity(pi, slot, tid);
                    }
                }
            }
        }
        for pi in 0..MAX_PI {
            if let Some(pid) = handler.pm_pid_for_pi(pi) {
                let token = handler
                    .token_store
                    .insert(nt_security::AccessToken::system());
                let _ = handler.pm.replace_process_primary_token(pid, Some(token));
            }
        }
        handler.refresh_process_manager_gates();
        handler.provision_kernel_srm_objects();
        handler.provision_volatile_hardware_registry();
        unsafe { handler.provision_default_user_locale() };
        handler.provision_reactos_explorer_shell_com_classes();
        handler
    }

    /// Seed the kernel-owned SRM synchronization object that ReactOS creates from ntoskrnl's
    /// `SeRmInitPhase1`, plus the kernel SRM listen port. LSASS later opens/signals the event and
    /// connects to `\SeRmCommandPort`; both lookups should be ordinary object-manager queries.
    fn provision_kernel_srm_objects(&mut self) {
        const SELSA_INIT_EVENT: &[u8] = b"\\selsainitevent";
        const STATUS_SUCCESS: u32 = 0;

        match self.obj_resolve(SELSA_INIT_EVENT, 0) {
            Some(index) if self.obj_ns[index].kind == OBJ_KIND_EVENT => {
                if !self.events.contains(index as u64) {
                    self.events
                        .initialize(index as u64, EventKind::Notification, false);
                }
                print_str(b"[srm-init] found existing \\SeLsaInitEvent obj=");
                print_u64(index as u64);
                print_str(b"\n");
            }
            Some(_) => {
                print_str(b"[srm-init] \\SeLsaInitEvent name collision with non-event object\n");
            }
            None => {
                if let Some(index) = self.obj_create(SELSA_INIT_EVENT, 0, OBJ_KIND_EVENT, &[]) {
                    self.events
                        .initialize(index as u64, EventKind::Notification, false);
                    print_str(b"[srm-init] provisioned \\SeLsaInitEvent obj=");
                    print_u64(index as u64);
                    print_str(b"\n");
                } else {
                    print_str(b"[srm-init] failed to provision \\SeLsaInitEvent\n");
                }
            }
        }

        let name16: alloc::vec::Vec<u16> = "\\SeRmCommandPort".encode_utf16().collect();
        let status = match unsafe { lpc_client() } {
            Some(client) => match client.create_port(&name16, 4, 0x148, 0x2400) {
                Ok(handle) if handle != 0 => {
                    match self.register_lpc_port_object(&name16, 0, handle) {
                        Ok(index) => {
                            SRM_COMMAND_PORT_OBJECT_HANDLE.store(handle, Ordering::Relaxed);
                            print_str(b"[srm-init] registered \\SeRmCommandPort obj=");
                            print_u64(index as u64);
                            print_str(b" handle=0x");
                            print_hex((handle >> 32) as u32);
                            print_hex(handle as u32);
                            print_str(b"\n");
                            STATUS_SUCCESS
                        }
                        Err(status) => status,
                    }
                }
                Ok(_) => 0xC000_0001,
                Err(status) => status.raw() as u32,
            },
            None => 0xC000_0001,
        };
        if status != STATUS_SUCCESS {
            print_str(b"[srm-init] failed to register \\SeRmCommandPort status=0x");
            print_hex(status);
            print_str(b"\n");
        }
    }

    /// Seed the kernel-owned volatile HARDWARE hive state that ReactOS expects during early SMSS.
    /// These keys are not backed by the disk hives; on NT they are runtime registry state published
    /// from detected platform/CPU data. Keep it in the normal overlay so callers use ordinary
    /// registry handles, enumeration, and query paths.
    fn provision_volatile_hardware_registry(&mut self) {
        const REG_SZ: u32 = 1;
        const REG_DWORD: u32 = 4;
        const HARDWARE_PATHS: [&str; 5] = [
            r"\Registry\Machine\Hardware",
            r"\Registry\Machine\Hardware\Description",
            r"\Registry\Machine\Hardware\Description\System",
            r"\Registry\Machine\Hardware\Description\System\CentralProcessor",
            r"\Registry\Machine\Hardware\Description\System\CentralProcessor\0",
        ];
        let mut created = 0u32;
        for path in HARDWARE_PATHS {
            let canon = self.overlay_canon(path);
            let (_, was_created) = self.overlay.create(&canon);
            if was_created {
                created += 1;
            }
        }

        let cpu_key =
            self.overlay_canon(r"\Registry\Machine\Hardware\Description\System\CentralProcessor\0");
        let Some(cpu_index) = self.overlay.find(&cpu_key) else {
            print_str(b"[hardware-reg] CPU key provisioning failed\n");
            return;
        };
        let identifier = native_processor_registry_identifier();
        let vendor = native_processor_vendor_identifier();
        let processor = native_processor_information();
        self.overlay.set_value(
            cpu_index,
            "Identifier",
            REG_SZ,
            &registry_sz_bytes(&identifier),
        );
        self.overlay.set_value(
            cpu_index,
            "VendorIdentifier",
            REG_SZ,
            &registry_sz_bytes(&vendor),
        );
        self.overlay.set_value(
            cpu_index,
            "FeatureSet",
            REG_DWORD,
            &processor.processor_feature_bits.to_le_bytes(),
        );
        print_str(b"[hardware-reg] provisioned volatile CPU registry keys=");
        print_u64(created as u64);
        print_str(b" Identifier=\"");
        print_ascii_str(&identifier);
        print_str(b"\" VendorIdentifier=\"");
        print_ascii_str(&vendor);
        print_str(b"\" FeatureSet=0x");
        print_hex(processor.processor_feature_bits);
        print_str(b"\n");
    }

    /// Seed ReactOS shell COM classes that explorer reaches through `rshell.cpp` fallback
    /// `CoCreateInstance` calls. A normal installed system would have these under HKCR after COM
    /// registration; the staged LiveCD SOFTWARE hive does not, so the executive imports the
    /// ReactOS `.rgs` setup output through the same volatile overlay used by real registry writes.
    fn provision_reactos_explorer_shell_com_classes(&mut self) {
        let mask = nt_hive_core::seed_reactos_explorer_shell_com_classes(
            &mut self.overlay,
            r"\Registry\Machine\Software\Classes",
        );
        EXPLORER_SHELL_COM_REG_CLASSES_PROVISIONED.store(mask, Ordering::Relaxed);
        if mask != 0 {
            print_str(b"[shell-com] provisioned explorer HKCR classes mask=0x");
            print_hex(mask as u32);
            print_str(b"\n");
        }
    }

    /// ═══ THE SECOND SETUP STEP THE LIVECD SKIPS — the default user's LOCALE ═══════════════════
    ///
    /// `winlogon!SetDefaultLanguage(Session)` (`sas.c:119`) opens HKCU, reads
    /// `Control Panel\International\Locale` and returns FALSE if it is missing — and its caller
    /// `HandleLogon` treats that as fatal (`goto cleanup` → `UnloadUserProfile`, no user shell).
    /// MEASURED, at `sas.c`'s exact key:
    /// `[post-profile] query-value MISS key=\registry\user\.default\control panel\international
    /// value="locale"`.
    ///
    /// The key EXISTS in the ISO's `config\default` and has ZERO values: `hivedef.inf:156` creates
    /// `HKCU\"Control Panel\International"` empty, and the VALUE is written later by SETUP —
    /// `base/setup/lib/settings.c:968 ProcessLocaleRegistry()` does exactly
    /// `NtSetValueKey(HKU\.DEFAULT\Control Panel\International, L"Locale", REG_SZ, <LanguageId>)`.
    /// A LiveCD never runs it, so the hive it ships has no locale — the same shape of gap as the
    /// missing `ntuser.dat`.
    ///
    /// This performs that step, at setup's own location, with the machine's OWN language id: the
    /// REG_SZ under `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language\Default` in the staged
    /// SYSTEM hive — which is the same value `SetDefaultLanguage(NULL)` (the SYSTEM path, already
    /// live in this boot: it is what makes `InitializeSAS` succeed) reads. Nothing is invented:
    /// if the SYSTEM hive has no such value, nothing is written and the miss stands.
    ///
    /// ★ BYPASS SWITCH `PROVISION_DEFAULT_USER_LOCALE`.
    ///
    /// # Safety
    /// Runs during construction, below the service loop's bump-heap mark, so the overlay strings
    /// it allocates are permanent by construction (no `overlay_dirty` pin needed).
    unsafe fn provision_default_user_locale(&mut self) {
        if !PROVISION_DEFAULT_USER_LOCALE {
            return;
        }
        const NLS_LANGUAGE: &str =
            r"\Registry\Machine\System\CurrentControlSet\Control\Nls\Language";
        const USER_INTERNATIONAL: &str = r"\Registry\User\.Default\Control Panel\International";
        // The machine's language id, out of the real SYSTEM hive.
        let Some((source_ty, language_id)) = self
            .resolve_key(NLS_LANGUAGE)
            .and_then(|key| self.registry_value(key, "Default"))
        else {
            print_str(
                b"[locale-setup] HKLM\\...\\Nls\\Language\\Default absent -> no user locale\n",
            );
            return;
        };
        // `SetDefaultLanguage` rejects every other type, and setup's
        // `ProcessLocaleRegistry` writes REG_SZ explicitly rather than copying the source type.
        const REG_SZ: u32 = 1;
        if source_ty != REG_SZ {
            print_str(b"[locale-setup] HKLM\\...\\Nls\\Language\\Default is not REG_SZ -> no user locale\n");
            return;
        }
        // The target key must ALREADY exist in the prototype hive (hivedef.inf creates it empty);
        // creating it ourselves would be inventing structure rather than performing setup's step.
        if self.resolve_key(USER_INTERNATIONAL).is_none() {
            print_str(b"[locale-setup] .Default\\Control Panel\\International absent -> skipped\n");
            return;
        }
        let canon = self.overlay_canon(USER_INTERNATIONAL);
        let (index, _) = self.overlay.create(&canon);
        self.overlay
            .set_value(index, "Locale", REG_SZ, &language_id);
        DEFAULT_USER_LOCALE_BYTES.store(language_id.len() as u64, Ordering::Relaxed);
        DEFAULT_USER_LOCALE_TYPE.store(REG_SZ as u64, Ordering::Relaxed);
        print_str(b"[locale-setup] HKU\\.DEFAULT\\Control Panel\\International\\Locale <- ");
        for &byte in language_id.iter().step_by(2) {
            debug_put_char(if (0x20..0x7f).contains(&byte) {
                byte
            } else {
                b'.'
            });
        }
        print_str(b" (REG type ");
        print_u64(REG_SZ as u64);
        print_str(b", from HKLM\\SYSTEM\\...\\Nls\\Language\\Default)\n");
    }

    /// `userenv!CreateEnvironmentBlock` opens `HKCU\Volatile Environment` after the profile hive is
    /// loaded. ReactOS' profile creation path copies `config\default` into `ntuser.dat`, and that
    /// prototype hive has `Environment` but not the logon-session volatile key. On NT the session
    /// manager/profile machinery creates the key dynamically; model that as a write overlay child of
    /// the mounted user hive, so normal `NtOpenKey`/`NtQueryKey` traffic sees an empty real key.
    unsafe fn provision_user_volatile_environment(&mut self, mount_path: &str) {
        if !PROVISION_USER_VOLATILE_ENVIRONMENT {
            return;
        }
        let mut full = alloc::string::String::from(mount_path);
        full.push_str("\\Volatile Environment");
        let canon = self.overlay_canon(&full);
        if self.overlay.find(&canon).is_none() && self.overlay.len() >= OVERLAY_KEY_MAX as usize {
            print_str(b"[cm-load] volatile environment provision skipped: overlay full\n");
            return;
        }
        let (_, created) = self.overlay.create(&canon);
        self.overlay_dirty = true;
        if created {
            USER_VOLATILE_ENV_PROVISIONED.fetch_add(1, Ordering::Relaxed);
            print_str(b"[cm-load] provisioned ");
            print_ascii_str(&full);
            print_str(b"\n");
        }
    }

    fn is_dynamic_user_volatile_env_canon(canon: &str) -> bool {
        canon.starts_with(r"\registry\user\s-") && canon.ends_with(r"\volatile environment")
    }

    fn registry_map_access(desired: u32) -> u32 {
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
        const KEY_READ: u32 = 0x0002_0019;
        const KEY_WRITE: u32 = 0x0002_0006;
        const KEY_ALL_ACCESS: u32 = 0x000F_003F;
        let mut mapped = desired
            & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
        if desired & (GENERIC_READ | GENERIC_EXECUTE) != 0 {
            mapped |= KEY_READ;
        }
        if desired & GENERIC_WRITE != 0 {
            mapped |= KEY_WRITE;
        }
        if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
            mapped |= KEY_ALL_ACCESS;
        }
        mapped
    }

    /// Insert a process-local registry handle and copy it to the caller transactionally.
    unsafe fn mint_registry_key(&mut self, target: KeyRef, desired: u32, out: u64) -> u32 {
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return 0xC000_0008;
        };
        let handle = match self.pm.insert_handle(
            pid,
            nt_process::HandleObject::RegistryKey(target),
            Self::registry_map_access(desired),
        ) {
            Ok(handle) => handle,
            Err(_) => return 0xC000_009A,
        };
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        if !self.xas_write_u64(out, handle as u64) {
            let _ = self.pm.take_handle(pid, handle);
            return 0xC000_0005;
        }
        0
    }

    /// Resolve a registry handle owned by the current process and enforce the requested key right.
    fn resolve_registry_key(&self, handle: u64, required_access: u32) -> Result<KeyRef, u32> {
        if handle > u32::MAX as u64 {
            return Err(0xC000_0008);
        }
        let pid = self.pm_pid_for_pi(self.pi).ok_or(0xC000_0008u32)?;
        let object = self
            .pm
            .lookup_handle(pid, handle as nt_process::Handle)
            .ok_or(0xC000_0008u32)?;
        let nt_process::HandleObject::RegistryKey(target) = object else {
            return Err(0xC000_0024);
        };
        let access = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(0xC000_0008u32)?;
        if access & required_access != required_access {
            return Err(0xC000_0022);
        }
        Ok(target)
    }
    /// Canonical overlay path for a full NT key path (CurrentControlSet alias applied), matching
    /// `resolve_key`'s view so an overlay write and a later base-hive read agree on one key.
    pub(crate) fn overlay_canon(&self, full: &str) -> alloc::string::String {
        nt_hive_core::canon_path(&apply_ccs_alias(full))
    }

    /// The mounted base hive a non-virtual `KeyRef` belongs to, plus its in-hive cell offset. The
    /// top nibble of the `KeyRef` selects SYSTEM (0) / SOFTWARE / SECURITY / SAM — see [`hive_sel`]
    /// — or one of the `\Registry\User` mounts in [`ExecNtHandler::hive_mounts`] (`.Default` plus
    /// whatever `NtLoadKey` has mounted). Uniform: a dynamic mount resolves exactly like a boot one.
    pub(crate) fn base_hive(&self, target: KeyRef) -> Option<(&RegfHive<'static>, KeyRef)> {
        if is_virtual_registry_key(target) {
            return None;
        }
        let sel = hive_sel(target);
        let hive = match sel {
            HIVE_SEL_SOFTWARE => self.software_hive.as_ref()?,
            HIVE_SEL_SECURITY => self.security_hive.as_ref()?,
            HIVE_SEL_SAM => self.sam_hive.as_ref()?,
            HIVE_SEL_SYSTEM => self.hive.as_ref()?,
            _ => &self.hive_mounts.iter().find(|m| m.sel == sel)?.hive,
        };
        Some((hive, hive_cell(target)))
    }

    /// The NT mount path a hive selector's keys hang off. The four boot mounts are compile-time
    /// constants; a `\Registry\User` mount carries its own path (a `<SID>` is only known at
    /// `NtLoadKey` time), so this is the one place that has to be a lookup.
    pub(crate) fn hive_mount_path(&self, sel: u32) -> Option<alloc::string::String> {
        match sel {
            HIVE_SEL_SOFTWARE | HIVE_SEL_SECURITY | HIVE_SEL_SAM | HIVE_SEL_SYSTEM => {
                Some(alloc::string::String::from(hive_mount(sel)))
            }
            _ => self
                .hive_mounts
                .iter()
                .find(|m| m.sel == sel)
                .map(|m| m.mount.clone()),
        }
    }

    fn registry_target_path(&self, target: KeyRef) -> Option<alloc::string::String> {
        if target == MACHINE_ROOT_KEY {
            return Some(alloc::string::String::from(r"\registry\machine"));
        }
        if target == USER_ROOT_KEY {
            return Some(alloc::string::String::from(r"\registry\user"));
        }
        if let Some(index) = overlay_key_idx(target) {
            return self.overlay.path(index).map(alloc::string::String::from);
        }
        let (hive, cell) = self.base_hive(target)?;
        let relative = hive.key_path(cell)?;
        let mut full = self.hive_mount_path(hive_sel(target))?;
        if !relative.is_empty() {
            full.push('\\');
            full.push_str(&relative);
        }
        Some(self.overlay_canon(&full))
    }

    /// Resolve a full NT path inside the `\Registry\User` namespace against the mount table.
    /// `None` if no mount owns the path, or the mount owns it but has no such key.
    pub(crate) fn resolve_user_key(&self, full_path: &str) -> Option<KeyRef> {
        let canon = nt_hive_core::canon_path(full_path);
        for mount in &self.hive_mounts {
            if canon == mount.canon {
                return Some(mount.sel | mount.hive.root());
            }
            let Some(rest) = canon
                .strip_prefix(mount.canon.as_str())
                .and_then(|rest| rest.strip_prefix('\\'))
            else {
                continue;
            };
            // The mount OWNS this path: it resolves here or nowhere (never fall through to a
            // different mount, which would let `\Registry\User\<sid>\x` answer out of `.Default`).
            return mount.hive.open_key(rest).map(|cell| mount.sel | cell);
        }
        None
    }

    /// The effective OBJECT_ATTRIBUTES name for a registry open: the mirror-read `path`, or — when
    /// that came back EMPTY because the name is an `RTL_CONSTANT_STRING` in a `.rdata` page the
    /// process never dereferenced — the PE-backed read. (`RegOpenKeyExW(HKEY_USERS, L".Default")`
    /// in `userenv!CreateUserHive` is exactly that case.)
    ///
    /// # Safety
    /// `oa` is a caller VA read through the cross-AS reader, which bounds-checks every access.
    unsafe fn effective_objattr_name(&self, path: &str, oa: u64) -> alloc::string::String {
        if !path.is_empty() {
            return alloc::string::String::from(path);
        }
        self.read_registry_objattr_name(oa)
    }

    /// Decode a registry UNICODE_STRING from the calling process. Prefer the ordinary live-memory
    /// mirror (stack/heap/resident image), then fall back to the PE-backed reader for untouched DLL
    /// `.rdata` literals. This is the CM equivalent of ProbeForRead: dynamic names created by
    /// userenv must not be lost just because other registry callers need static-literal recovery.
    unsafe fn read_registry_ustr_units(&self, ustr_va: u64) -> alloc::vec::Vec<u16> {
        if ustr_va == 0 {
            return alloc::vec::Vec::new();
        }
        let mut expected_units = None;
        let mut len = [0u8; 2];
        if self.xas_read(ustr_va, &mut len) {
            let byte_len = u16::from_le_bytes(len) as usize;
            if byte_len & 1 == 0 {
                expected_units = Some((byte_len / 2).min(1024));
            }
        }
        let live = smss_read_ustr(ustr_va);
        if expected_units.is_some_and(|n| live.len() >= n)
            || expected_units.is_none() && !live.is_empty()
        {
            return live;
        }
        let backed = self.read_ustr_pe(ustr_va);
        if backed.len() > live.len() {
            backed
        } else {
            live
        }
    }

    unsafe fn read_registry_ustr_name(&self, ustr_va: u64) -> alloc::string::String {
        utf16_units_to_string(&self.read_registry_ustr_units(ustr_va))
    }

    unsafe fn read_registry_objattr_name(&self, oa_va: u64) -> alloc::string::String {
        if oa_va == 0 {
            return alloc::string::String::new();
        }
        let mut p = [0u8; 8];
        if !self.xas_read(oa_va + 0x10, &mut p) {
            return alloc::string::String::new();
        }
        self.read_registry_ustr_name(u64::from_le_bytes(p))
    }

    /// Split an NT registry path into its non-empty components.
    fn key_components(path: &str) -> alloc::vec::Vec<&str> {
        path.split('\\').filter(|c| !c.is_empty()).collect()
    }

    /// True if `comps` is exactly `Registry\User` (the predefined `HKEY_USERS` root).
    fn is_user_root_comps(comps: &[&str]) -> bool {
        comps.len() == 2
            && comps[0].eq_ignore_ascii_case("Registry")
            && comps[1].eq_ignore_ascii_case("User")
    }

    /// Resolve the FULL NT path of a `\Registry\User` open/load/unload target: either absolute
    /// (`\Registry\User\…`) or relative to the `HKEY_USERS` root sentinel / a key already inside
    /// the namespace. `None` when the target is not in the user namespace at all.
    fn user_namespace_target(
        &self,
        root_target: Option<KeyRef>,
        name: &str,
    ) -> Option<alloc::string::String> {
        let base = match root_target {
            None => {
                let comps = Self::key_components(name);
                if comps.len() > 2
                    && comps[0].eq_ignore_ascii_case("Registry")
                    && comps[1].eq_ignore_ascii_case("User")
                {
                    return Some(alloc::string::String::from(name));
                }
                return None;
            }
            Some(USER_ROOT_KEY) => alloc::string::String::from(r"\Registry\User"),
            Some(target) => {
                let path = self.registry_target_path(target)?;
                if path != r"\registry\user" && !path.starts_with(r"\registry\user\") {
                    return None;
                }
                path
            }
        };
        let mut full = base;
        if !name.is_empty() {
            full.push('\\');
            full.push_str(name);
        }
        Some(full)
    }

    /// `NtOpenKey` for the `\Registry\User` (`HKEY_USERS`) namespace. `Some(status)` when this open
    /// belongs to the namespace (and is therefore fully answered here), `None` to let the caller's
    /// existing resolution run unchanged.
    ///
    /// # Safety
    /// Reads the caller's OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader and mints a
    /// handle into the current process's own EPROCESS handle table.
    unsafe fn open_user_namespace_key(
        &mut self,
        root_target: Option<KeyRef>,
        path: &str,
        oa: u64,
        args: &[u64],
    ) -> Option<u32> {
        // An EMPTY mirror-read name means the OA names an `RTL_CONSTANT_STRING` in a `.rdata` page
        // the process never dereferenced — `userenv!UpdateUsersShellFolderSettings` opens
        // `SOFTWARE\…\Shell Folders` relative to the user-hive handle exactly that way — so recover
        // it from the backing PE. Only reached for an empty name, and a name that turns out NOT to
        // be in this namespace falls through with the caller's original `path` untouched.
        let name = self.effective_objattr_name(path, oa);
        // (a) The predefined `HKEY_USERS` root itself (advapi32's `MapDefaultKey`).
        if root_target.is_none() && Self::is_user_root_comps(&Self::key_components(&name)) {
            USER_ROOT_OPENED.fetch_add(1, Ordering::Relaxed);
            return Some(self.mint_registry_key(USER_ROOT_KEY, args[1] as u32, args[0]));
        }
        let full = self.user_namespace_target(root_target, &name)?;
        // (b) A created key shadows the mount, exactly as it does for the machine hives.
        let canon = self.overlay_canon(&full);
        if let Some(index) = self.overlay.find(&canon) {
            if Self::is_dynamic_user_volatile_env_canon(&canon) {
                USER_VOLATILE_ENV_OPENED.fetch_add(1, Ordering::Relaxed);
            }
            return Some(self.mint_registry_key(
                OVERLAY_KEY_TAG | index as u32,
                args[1] as u32,
                args[0],
            ));
        }
        // (c) …otherwise the mount table. A miss inside the namespace is a real NOT_FOUND (which is
        // what every `\Registry\User` open returned before this batch), never a fabricated key.
        if USER_NS_TRACED.fetch_add(1, Ordering::Relaxed) < 40 {
            print_str(b"[user-ns] pi=");
            print_u64(self.pi as u64);
            print_str(b" open ");
            print_ascii_str(&full);
            print_str(b" -> ");
            print_u64(self.resolve_user_key(&full).unwrap_or(0) as u64);
            print_str(b"\n");
        }
        match self.resolve_user_key(&full) {
            Some(key) => {
                if hive_sel(key) == HIVE_SEL_USER_DEFAULT {
                    USER_DEFAULT_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                } else {
                    USER_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                }
                Some(self.mint_registry_key(key, args[1] as u32, args[0]))
            }
            None => {
                if self.current_process_is_winlogon()
                    && post_profile_phase()
                    && POST_PROFILE_TRACED.fetch_add(1, Ordering::Relaxed) < 64
                {
                    print_str(b"[post-profile] open MISS ");
                    print_ascii_str(&full);
                    print_str(b"\n");
                }
                Some(0xC000_0034) // STATUS_OBJECT_NAME_NOT_FOUND
            }
        }
    }

    /// Explorer's COM activation path uses HKCR, which ReactOS maps to
    /// `\Registry\Machine\Software\Classes`. Resolve that subtree for pi 6 with PE-backed
    /// OBJECT_ATTRIBUTES reads so DLL `.rdata` literals work the same way as they do for services.
    ///
    /// # Safety
    /// Reads the caller's OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader and mints a
    /// handle into the current process's own EPROCESS handle table.
    unsafe fn open_explorer_classes_key(
        &mut self,
        root_target: Option<KeyRef>,
        path: &str,
        oa: u64,
        args: &[u64],
    ) -> Option<u32> {
        if !self.current_process_is_explorer() {
            return None;
        }
        let name = self.effective_objattr_name(path, oa);
        if root_target.is_none() {
            let comps = Self::key_components(&name);
            if comps.len() == 2
                && comps[0].eq_ignore_ascii_case("Registry")
                && comps[1].eq_ignore_ascii_case("Machine")
            {
                return Some(self.mint_registry_key(MACHINE_ROOT_KEY, args[1] as u32, args[0]));
            }
        }

        let full = if root_target == Some(MACHINE_ROOT_KEY) {
            let mut full = alloc::string::String::from(r"\Registry\Machine");
            if !name.is_empty() {
                full.push('\\');
                full.push_str(&name);
            }
            Some(full)
        } else if let Some(parent_path) =
            root_target.and_then(|target| self.registry_target_path(target))
        {
            if parent_path != r"\registry\machine"
                && !parent_path.starts_with(r"\registry\machine\")
            {
                return None;
            }
            let mut full = parent_path;
            if !name.is_empty() {
                full.push('\\');
                full.push_str(&name);
            }
            Some(full)
        } else if root_target.is_none() {
            Some(name)
        } else {
            None
        }?;

        let canon = self.overlay_canon(&full);
        if canon != r"\registry\machine\software\classes"
            && !canon.starts_with(r"\registry\machine\software\classes\")
        {
            return None;
        }

        if let Some(index) = self.overlay.find(&canon) {
            let bit = explorer_shell_com_class_bit_for_path(&canon);
            if bit != 0 {
                EXPLORER_SHELL_COM_CLASS_OPEN_MASK.fetch_or(bit, Ordering::Relaxed);
            }
            return Some(self.mint_registry_key(
                OVERLAY_KEY_TAG | index as u32,
                args[1] as u32,
                args[0],
            ));
        }

        if let Some(key) = self.resolve_key(&full) {
            if hive_sel(key) == HIVE_SEL_SOFTWARE {
                SOFTWARE_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
            }
            let bit = explorer_shell_com_class_bit_for_path(&canon);
            if bit != 0 {
                EXPLORER_SHELL_COM_CLASS_OPEN_MASK.fetch_or(bit, Ordering::Relaxed);
            }
            return Some(self.mint_registry_key(key, args[1] as u32, args[0]));
        }

        Some(0xC000_0034)
    }

    /// Hosted user processes after logon should resolve the mounted machine hives through the same
    /// overlay-first path services/LSA use. Earlier boot clients stay on their exact-name arms because
    /// broad pre-SAS HKLM success changes user32/winmm initialization order and regresses paint.
    ///
    /// # Safety
    /// Reads the caller's OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader and mints a
    /// handle into the current process's own EPROCESS handle table.
    unsafe fn open_hosted_machine_key(
        &mut self,
        root_target: Option<KeyRef>,
        path: &str,
        oa: u64,
        args: &[u64],
    ) -> Option<u32> {
        if self.pi < 5 {
            return None;
        }
        let name = self.effective_objattr_name(path, oa);
        if root_target.is_none() {
            let comps = Self::key_components(&name);
            if comps.len() == 2
                && comps[0].eq_ignore_ascii_case("Registry")
                && comps[1].eq_ignore_ascii_case("Machine")
            {
                return Some(self.mint_registry_key(MACHINE_ROOT_KEY, args[1] as u32, args[0]));
            }
        }

        let full = if root_target == Some(MACHINE_ROOT_KEY) {
            let mut full = alloc::string::String::from(r"\Registry\Machine");
            if !name.is_empty() {
                full.push('\\');
                full.push_str(&name);
            }
            Some(full)
        } else if let Some(parent_path) =
            root_target.and_then(|target| self.registry_target_path(target))
        {
            if parent_path != r"\registry\machine"
                && !parent_path.starts_with(r"\registry\machine\")
            {
                return None;
            }
            let mut full = parent_path;
            if !name.is_empty() {
                full.push('\\');
                full.push_str(&name);
            }
            Some(full)
        } else if root_target.is_none() {
            Some(name)
        } else {
            None
        }?;

        let canon = self.overlay_canon(&full);
        if canon != r"\registry\machine" && !canon.starts_with(r"\registry\machine\") {
            return None;
        }
        if canon == r"\registry\machine" {
            return Some(self.mint_registry_key(MACHINE_ROOT_KEY, args[1] as u32, args[0]));
        }

        if let Some(index) = self.overlay.find(&canon) {
            let bit = explorer_shell_com_class_bit_for_path(&canon);
            if bit != 0 {
                EXPLORER_SHELL_COM_CLASS_OPEN_MASK.fetch_or(bit, Ordering::Relaxed);
            }
            return Some(self.mint_registry_key(
                OVERLAY_KEY_TAG | index as u32,
                args[1] as u32,
                args[0],
            ));
        }

        if let Some(key) = self.resolve_key(&full) {
            if hive_sel(key) == HIVE_SEL_SOFTWARE {
                SOFTWARE_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
            }
            let bit = explorer_shell_com_class_bit_for_path(&canon);
            if bit != 0 {
                EXPLORER_SHELL_COM_CLASS_OPEN_MASK.fetch_or(bit, Ordering::Relaxed);
            }
            return Some(self.mint_registry_key(key, args[1] as u32, args[0]));
        }

        Some(0xC000_0034)
    }

    /// Bounded trace of a registry MISS in winlogon's post-profile window: which key, which value.
    fn trace_post_profile_registry(&self, what: &[u8], key: KeyRef, name: &str) {
        if POST_PROFILE_TRACED.fetch_add(1, Ordering::Relaxed) >= 64 {
            return;
        }
        print_str(b"[post-profile] ");
        print_str(what);
        print_str(b" MISS key=");
        match self.registry_target_path(key) {
            Some(path) => print_ascii_str(&path),
            None => {
                print_str(b"<non-hive 0x");
                print_hex(key);
                print_str(b">");
            }
        }
        print_str(b" value=\"");
        print_ascii_str(name);
        print_str(b"\"\n");
    }

    /// Read a whole file named by an NT path into `dst`, returning its byte length. Serves
    /// `NtLoadKey`'s SourceFile: the writable volume first (where a copied profile's `ntuser.dat`
    /// lives), then the read-only `\reactos` FAT reader.
    ///
    /// # Safety
    /// Borrows the mounted writable volume for the duration of the copy; single-threaded executive.
    unsafe fn read_file_by_nt_path(name16: &[u16], dst: &mut [u8]) -> Option<usize> {
        if let Some(relative) = crate::writable_fs::writable_path(name16) {
            let fs = crate::writable_fs::writable_fs()?;
            let mut path = alloc::string::String::from(r"\??\C:\");
            for &byte in &relative {
                path.push(byte as char);
            }
            let bytes = fs.file_bytes(&path)?;
            if bytes.len() > dst.len() {
                return None;
            }
            dst[..bytes.len()].copy_from_slice(bytes);
            return Some(bytes.len());
        }
        None
    }

    /// `NtLoadKey*` — ReactOS `ntoskrnl/config/ntapi.c:1148` (`NtLoadKeyEx`). Mount a `regf`
    /// hive FILE at a key in the registry namespace. Base `NtLoadKey` passes `flags = 0` and a null
    /// trust-class key; `NtLoadKey2` / `NtLoadKeyEx` feed their additional arguments here.
    ///
    /// # Safety
    /// Reads two caller OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader.
    unsafe fn nt_load_key_ex(
        &mut self,
        target_oa: u64,
        source_oa: u64,
        flags: u32,
        trust_class_key: u64,
    ) -> u32 {
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        const STATUS_REGISTRY_CORRUPT: u32 = 0xC000_014C;
        const REG_NO_LAZY_FLUSH: u32 = 0x0000_0004;
        NT_LOAD_KEY_CALLS.fetch_add(1, Ordering::Relaxed);

        if flags & !REG_NO_LAZY_FLUSH != 0 {
            return STATUS_INVALID_PARAMETER;
        }

        // `SeSinglePrivilegeCheck(SeRestorePrivilege, PreviousMode)` (ntapi.c:1168). Enforced, not
        // assumed: `userenv!AcquireRemoveRestorePrivilege(TRUE)` must really have ENABLED it on the
        // caller's token through `NtAdjustPrivilegesToken` (the LocalSystem token carries
        // SeRestorePrivilege present-but-DISABLED, exactly as ReactOS's does).
        let held = self.current_token_has_privilege(nt_security::SE_RESTORE);
        NT_LOAD_KEY_PRIVILEGE_HELD.store(held as u64, Ordering::Relaxed);
        if !held {
            NT_LOAD_KEY_NO_PRIVILEGE.fetch_add(1, Ordering::Relaxed);
            print_str(b"[cm-load] NtLoadKey REFUSED: SeRestorePrivilege not held (pi=");
            print_u64(self.pi as u64);
            print_str(b")\n");
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if trust_class_key != 0 {
            match self.resolve_registry_key(trust_class_key, 0) {
                Ok(_) => {}
                Err(status) => return status,
            }
        }

        // The TARGET key: RootDirectory (usually the HKEY_USERS handle) + the leaf name (the SID).
        let mut rd = [0u8; 8];
        if target_oa == 0 || !self.xas_read(target_oa + 8, &mut rd) {
            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
        }
        let root_dir = u64::from_le_bytes(rd);
        let root_target = if root_dir == 0 {
            None
        } else {
            match self.resolve_registry_key(root_dir, 0) {
                Ok(target) => Some(target),
                Err(status) => return status,
            }
        };
        let target_name = self.effective_objattr_name("", target_oa);
        let Some(full) = self.user_namespace_target(root_target, &target_name) else {
            // Only the `\Registry\User` namespace has hive mounts in this executive; a load
            // anywhere else is refused rather than faked.
            print_str(b"[cm-load] NtLoadKey target is not under \\Registry\\User\n");
            return STATUS_INVALID_PARAMETER;
        };
        let canon = nt_hive_core::canon_path(&full);
        if canon == r"\registry\user" {
            return STATUS_INVALID_PARAMETER;
        }
        if self.hive_mounts.iter().any(|m| m.canon == canon) {
            // The hive is already mounted here — `userenv!LoadUserProfileW` explicitly tolerates
            // ERROR_SHARING_VIOLATION as "the profile is already loaded" (profile.c:2136).
            return STATUS_SHARING_VIOLATION;
        }

        // The SOURCE file: read the whole regf out of the filesystem into a durable static slot.
        let file16 = self.read_objattr_name_pe(source_oa);
        let mut file_name = alloc::string::String::new();
        for &unit in &file16 {
            if let Some(c) = char::from_u32(unit as u32) {
                file_name.push(c);
            }
        }
        let Some(slot) = (0..USER_HIVE_SLOTS)
            .find(|s| USER_HIVE_SLOT_USED.load(Ordering::Relaxed) & (1 << s) == 0)
        else {
            print_str(b"[cm-load] NtLoadKey REFUSED: all hive slots in use\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        // SAFETY: single-threaded executive; the slot is claimed below and only released by
        // `NtUnloadKey`, which drops the borrowing mount first.
        let buffer = &mut (*core::ptr::addr_of_mut!(USER_HIVE_BUF))[slot];
        let Some(len) = Self::read_file_by_nt_path(&file16, buffer) else {
            print_str(b"[cm-load] NtLoadKey: source file unreadable: ");
            print_ascii_str(&file_name);
            print_str(b"\n");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        // SAFETY: the slot is a `'static` array; the borrow lives exactly as long as the mount.
        let bytes: &'static [u8] =
            core::slice::from_raw_parts((*core::ptr::addr_of!(USER_HIVE_BUF))[slot].as_ptr(), len);
        let Some(hive) = RegfHive::new(bytes) else {
            print_str(b"[cm-load] NtLoadKey: not a regf hive (");
            print_u64(len as u64);
            print_str(b" bytes)\n");
            return STATUS_REGISTRY_CORRUPT;
        };
        let root_subkeys = hive.subkeys(hive.root()).len() as u64;
        USER_HIVE_SLOT_USED.fetch_or(1 << slot, Ordering::Relaxed);
        let reattached = self.overlay.reattach_subtree(&canon);
        if reattached != 0 {
            NT_LOAD_KEY_OVERLAY_REATTACHED.fetch_add(reattached as u64, Ordering::Relaxed);
            self.overlay_dirty = true;
            print_str(b"[cm-load] reattached ");
            print_u64(reattached as u64);
            print_str(b" overlay key(s) for ");
            print_ascii_str(&full);
            print_str(b"\n");
        }
        self.hive_mounts.push(HiveMount {
            sel: HIVE_SEL_DYNAMIC[slot],
            canon,
            mount: full,
            file: file_name,
            hive,
            slot: Some(slot),
            dynamic: true,
        });
        self.hive_mounts_dirty = true;
        NT_LOAD_KEY_MOUNTED.fetch_add(1, Ordering::Relaxed);
        NT_LOAD_KEY_HIVE_BYTES.store(len as u64, Ordering::Relaxed);
        NT_LOAD_KEY_ROOT_SUBKEYS.store(root_subkeys, Ordering::Relaxed);
        print_str(b"[cm-load] NtLoadKey MOUNTED ");
        print_ascii_str(&self.hive_mounts[self.hive_mounts.len() - 1].mount);
        print_str(b" <- ");
        print_ascii_str(&self.hive_mounts[self.hive_mounts.len() - 1].file);
        print_str(b" bytes=");
        print_u64(len as u64);
        print_str(b" root-subkeys=");
        print_u64(root_subkeys);
        print_str(b" slot=");
        print_u64(slot as u64);
        print_str(b"\n");
        // CONTENT read-back through the namespace, not through the mount object: resolve
        // `<mount>\Environment` the way a hosted process' `NtOpenKey` would and compare its `TEMP`
        // value with the SAME value in the `.Default` prototype the profile hive was copied from.
        // Byte-for-byte equality of a non-empty value is what makes "a REAL hive is mounted here"
        // a measurement instead of a claim.
        let mount_path = self.hive_mounts[self.hive_mounts.len() - 1].mount.clone();
        self.provision_user_volatile_environment(&mount_path);
        let mut env_path = mount_path;
        env_path.push_str("\\Environment");
        let mounted_temp = self
            .resolve_key(&env_path)
            .and_then(|key| self.registry_value(key, "TEMP"));
        let default_temp = self
            .resolve_key(r"\Registry\User\.Default\Environment")
            .and_then(|key| self.registry_value(key, "TEMP"));
        match (&mounted_temp, &default_temp) {
            (Some((ty, data)), Some((dty, ddata)))
                if !data.is_empty() && ty == dty && data == ddata =>
            {
                NT_LOAD_KEY_VALUE_READBACK.store(1, Ordering::Relaxed);
                print_str(b"[cm-load] read-back \\Environment\\TEMP through the mount: ");
                print_u64(data.len() as u64);
                print_str(b" bytes, type ");
                print_u64(*ty as u64);
                print_str(b", identical to \\Registry\\User\\.Default's\n");
            }
            _ => {
                print_str(b"[cm-load] read-back MISMATCH mounted=");
                print_u64(mounted_temp.map_or(0, |(_, d)| d.len() as u64));
                print_str(b" default=");
                print_u64(default_temp.map_or(0, |(_, d)| d.len() as u64));
                print_str(b"\n");
            }
        }
        0
    }

    unsafe fn capture_driver_service_registry_path(
        &self,
        ustr_va: u64,
    ) -> Result<alloc::string::String, u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
        const MAX_DRIVER_SERVICE_PATH_BYTES: usize = 1024;

        if ustr_va == 0 {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let mut header = [0u8; 16];
        if !self.xas_read(ustr_va, &mut header) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let byte_len = u16::from_le_bytes([header[0], header[1]]) as usize;
        let maximum_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if byte_len == 0 || buffer == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if (byte_len & 1) != 0 || byte_len > maximum_len || byte_len > 0xFFFC {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if byte_len > MAX_DRIVER_SERVICE_PATH_BYTES {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let mut bytes = [0u8; MAX_DRIVER_SERVICE_PATH_BYTES];
        if !self.xas_read(buffer, &mut bytes[..byte_len]) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let mut path = alloc::string::String::new();
        for index in 0..byte_len / 2 {
            let unit = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
            if !(0x20..=0x7e).contains(&unit) {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            path.push(char::from_u32(unit as u32).ok_or(STATUS_OBJECT_NAME_INVALID)?);
        }
        Ok(path)
    }

    fn driver_service_name_from_registry_path(path: &str) -> Result<alloc::string::String, u32> {
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;

        let comps: alloc::vec::Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
        if comps.len() != 6
            || !comps[0].eq_ignore_ascii_case("Registry")
            || !comps[1].eq_ignore_ascii_case("Machine")
            || !comps[2].eq_ignore_ascii_case("System")
            || !(comps[3].eq_ignore_ascii_case("CurrentControlSet")
                || comps[3].eq_ignore_ascii_case("ControlSet001"))
            || !comps[4].eq_ignore_ascii_case("Services")
        {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let service = comps[5];
        if service.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let bytes = service.as_bytes();
        if !bytes
            .iter()
            .copied()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            || bytes.windows(2).any(|w| w == b"..")
        {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(alloc::string::String::from(service))
    }

    fn driver_object_path_for_service(service: &str) -> alloc::string::String {
        let mut path = alloc::string::String::from("\\Driver\\");
        path.push_str(service);
        path
    }

    unsafe fn nt_load_driver(&mut self, service_name_ustr: u64) -> u32 {
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        const STATUS_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
        const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

        if !self.current_token_has_privilege(nt_security::SE_LOAD_DRIVER) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        let service_path = match self.capture_driver_service_registry_path(service_name_ustr) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service = match Self::driver_service_name_from_registry_path(&service_path) {
            Ok(service) => service,
            Err(status) => return status,
        };
        let driver_object_path = Self::driver_object_path_for_service(&service);
        if driver_launch::driver_id_by_name(&driver_object_path).is_some() {
            return STATUS_IMAGE_ALREADY_LOADED;
        }

        let mut image_path = [0u8; 180];
        let Some((image_len, class)) =
            system_hive_demand_driver_launch_spec(&service, &mut image_path)
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(fs) = exec_fs() else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(_dc) =
            driver_launch::load_driver(&fs, &image_path[..image_len], class, &driver_object_path)
        else {
            return STATUS_UNSUCCESSFUL;
        };
        0
    }

    unsafe fn nt_unload_driver(&mut self, service_name_ustr: u64) -> u32 {
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

        if !self.current_token_has_privilege(nt_security::SE_LOAD_DRIVER) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        let service_path = match self.capture_driver_service_registry_path(service_name_ustr) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service = match Self::driver_service_name_from_registry_path(&service_path) {
            Ok(service) => service,
            Err(status) => return status,
        };
        let driver_object_path = Self::driver_object_path_for_service(&service);
        match driver_launch::unload_driver_by_name(&driver_object_path) {
            Ok(()) => 0,
            Err(status) => status.raw() as u32,
        }
    }

    /// `NtUnloadKey*` — ReactOS `ntoskrnl/config/ntapi.c:1796` (`NtUnloadKey2`) plus the event
    /// form. Detach a hive `NtLoadKey*` mounted: the mount goes, its backing slot is released, and
    /// the write overlay's keys under that path are detached too — otherwise the writes made
    /// through the mount would keep answering at the same path and the "unload" would be cosmetic.
    ///
    /// # Safety
    /// Reads the caller's OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader.
    unsafe fn nt_unload_key_ex(&mut self, target_oa: u64, flags: u32, event: u64) -> u32 {
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        const REG_FORCE_UNLOAD: u32 = 0x0000_0001;
        NT_UNLOAD_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
        if flags != 0 && flags != REG_FORCE_UNLOAD {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_INVALID_PARAMETER;
        }
        if !self.current_token_has_privilege(nt_security::SE_RESTORE) {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        let event_index = if event != 0 {
            match self.event_index_for_handle(event, EVENT_MODIFY_STATE) {
                Ok(index) => Some(index),
                Err(status) => {
                    NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
                    return status;
                }
            }
        } else {
            None
        };
        let oa = target_oa;
        let mut rd = [0u8; 8];
        if oa == 0 || !self.xas_read(oa + 8, &mut rd) {
            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
        }
        let root_dir = u64::from_le_bytes(rd);
        let root_target = if root_dir == 0 {
            None
        } else {
            match self.resolve_registry_key(root_dir, 0) {
                Ok(target) => Some(target),
                Err(status) => return status,
            }
        };
        let name = self.effective_objattr_name("", oa);
        let Some(full) = self.user_namespace_target(root_target, &name) else {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_INVALID_PARAMETER;
        };
        let canon = nt_hive_core::canon_path(&full);
        let Some(index) = self.hive_mounts.iter().position(|m| m.canon == canon) else {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if !self.hive_mounts[index].dynamic {
            // `.Default` is mounted by the boot, not by a caller: refusing to unload it is the
            // same refusal NT makes for a hive it did not load on request.
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_INVALID_PARAMETER;
        }
        let mount = self.hive_mounts.remove(index);
        if let Some(slot) = mount.slot {
            USER_HIVE_SLOT_USED.fetch_and(!(1u64 << slot), Ordering::Relaxed);
        }
        let overlay_detached = self.overlay.detach_subtree(&canon);
        self.overlay_dirty = true;
        self.hive_mounts_dirty = true;
        NT_UNLOAD_KEY_DETACHED.fetch_add(1, Ordering::Relaxed);
        if let Some(index) = event_index {
            let status = self.signal_event_index(index);
            if status != 0 {
                return status;
            }
        }
        print_str(b"[cm-load] NtUnloadKey DETACHED ");
        print_ascii_str(&mount.mount);
        print_str(b" overlay-keys=");
        print_u64(overlay_detached as u64);
        print_str(b" mounts-left=");
        print_u64(self.hive_mounts.len() as u64);
        print_str(b"\n");
        0
    }

    fn registry_overlay_index(&self, target: KeyRef) -> Option<usize> {
        overlay_key_idx(target).or_else(|| {
            self.registry_target_path(target)
                .and_then(|path| self.overlay.find(&path))
        })
    }

    fn registry_path_exists(&self, canon: &str) -> bool {
        matches!(
            canon,
            r"\" | r"\registry" | r"\registry\machine" | r"\registry\user"
        ) || self.overlay.find(canon).is_some()
            || self.resolve_key(canon).is_some()
    }

    fn registry_shadow_key(&mut self, target: KeyRef) -> Result<usize, u32> {
        if let Some(index) = overlay_key_idx(target) {
            return self
                .overlay
                .path(index)
                .map(|_| index)
                .ok_or(0xC000_0008u32);
        }
        let path = self.registry_target_path(target).ok_or(0xC000_0008u32)?;
        if let Some(index) = self.overlay.find(&path) {
            return Ok(index);
        }
        if self.overlay.len() >= OVERLAY_KEY_MAX as usize {
            return Err(0xC000_009A);
        }
        let (index, _) = self.overlay.create(&path);
        self.overlay_dirty = true;
        Ok(index)
    }

    fn registry_value(&self, target: KeyRef, name: &str) -> Option<(u32, alloc::vec::Vec<u8>)> {
        if let Some(index) = self.registry_overlay_index(target) {
            if self.overlay.value_is_deleted(index, name) {
                return None;
            }
            if let Some((ty, data)) = self.overlay.value(index, name) {
                return Some((ty, data.to_vec()));
            }
            let path = self.overlay.path(index)?;
            return self.resolve_key(path).and_then(|key| {
                let (hive, cell) = self.base_hive(key)?;
                hive.value(cell, name)
            });
        }
        let (hive, cell) = self.base_hive(target)?;
        hive.value(cell, name)
    }

    fn registry_values(
        &self,
        target: KeyRef,
    ) -> alloc::vec::Vec<(alloc::string::String, u32, alloc::vec::Vec<u8>)> {
        let mut values = alloc::vec::Vec::new();
        let overlay_index = self.registry_overlay_index(target);
        let base_key = if let Some(index) = overlay_index {
            self.overlay
                .path(index)
                .and_then(|path| self.resolve_key(path))
        } else if !is_virtual_registry_key(target) {
            Some(target)
        } else {
            None
        };
        if let Some((hive, base)) = base_key.and_then(|key| self.base_hive(key)) {
            let count = hive.values(base).len();
            for index in 0..count {
                let Some((name, ty, data)) = hive.value_by_index(base, index) else {
                    continue;
                };
                if let Some(overlay) = overlay_index {
                    if self.overlay.value_is_deleted(overlay, &name) {
                        continue;
                    }
                    if let Some((overlay_ty, overlay_data)) = self.overlay.value(overlay, &name) {
                        values.push((name, overlay_ty, overlay_data.to_vec()));
                        continue;
                    }
                }
                values.push((name, ty, data));
            }
        }
        if let Some(overlay) = overlay_index {
            let live = self.overlay.values_len(overlay);
            for index in 0..live {
                let Some((name, ty, data)) = self.overlay.value_by_index(overlay, index) else {
                    continue;
                };
                let exists_in_base = base_key
                    .and_then(|key| {
                        let (hive, base) = self.base_hive(key)?;
                        hive.value(base, name)
                    })
                    .is_some();
                if !exists_in_base {
                    values.push((alloc::string::String::from(name), ty, data.to_vec()));
                }
            }
        }
        values
    }

    fn registry_subkeys(&self, target: KeyRef) -> alloc::vec::Vec<alloc::string::String> {
        let mut subkeys = alloc::vec::Vec::new();
        let path = self.registry_target_path(target);
        let base_key = if let Some(index) = overlay_key_idx(target) {
            self.overlay
                .path(index)
                .and_then(|overlay_path| self.resolve_key(overlay_path))
        } else if !is_virtual_registry_key(target) {
            Some(target)
        } else {
            None
        };
        if let Some((hive, base)) = base_key.and_then(|key| self.base_hive(key)) {
            subkeys.extend(hive.subkeys(base).into_iter().map(|(name, _)| name));
        }
        if let Some(path) = path.as_deref() {
            for name in self.overlay.subkeys(path) {
                if !subkeys
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(name))
                {
                    subkeys.push(alloc::string::String::from(name));
                }
            }
        }
        subkeys
    }
    /// Resolve a fault BADGE's process index (pi) to its EPROCESS pid (the badge↔pid convergence
    /// link). Returns `None` before the ProcessManager has created that hosted process.
    pub(crate) fn pm_pid_for_pi(&self, pi: usize) -> Option<nt_process::ProcessId> {
        self.process_mechanisms
            .pid_for_pi(pi)
            .or_else(|| self.temporary_pid_for_pi(pi))
    }

    pub(crate) fn pm_main_tid_for_pi(&self, pi: usize) -> Option<nt_process::ThreadId> {
        self.thread_mechanisms.main_tid_for_pi(pi)
    }

    pub(crate) fn pm_pool_tid_for_slot(
        &self,
        pi: usize,
        slot: usize,
    ) -> Option<nt_process::ThreadId> {
        self.thread_mechanisms.pool_tid_for_slot(pi, slot)
    }

    pub(crate) fn pm_pool_slot_for_tid(&self, tid: u64) -> Option<(usize, usize)> {
        if tid == 0 || tid > u32::MAX as u64 {
            return None;
        }
        self.thread_mechanisms
            .pool_slot_for_tid(tid as nt_process::ThreadId)
    }

    pub(crate) fn observe_win32k_stock_object(&mut self, object_id: u32, handle: u32) -> bool {
        self.win32k_session.observe_stock_object(object_id, handle)
    }

    pub(crate) fn observe_global_cursor_identity(
        &mut self,
        key: &nt_kernel_exec::user_cursor::CursorLookupKey,
        handle: u32,
    ) {
        self.win32k_session.observe_cursor_identity(key, handle);
    }

    pub(crate) fn promote_global_cursor(&mut self, handle: u32) {
        self.win32k_session.promote_cursor(handle);
    }

    pub(crate) fn record_userinit_global_cursor_hit(&mut self, handle: u32) {
        self.win32k_session.record_userinit_cursor_hit(handle);
    }

    pub(crate) fn observe_builtin_class_atom(
        &mut self,
        key: &nt_kernel_exec::user_class::BuiltinClassKey,
        atom: u16,
    ) {
        self.win32k_session.observe_builtin_class(key, atom);
    }

    pub(crate) fn record_userinit_builtin_class_hit(&mut self, fn_id: u32, atom: u16) {
        self.win32k_session
            .record_userinit_builtin_class_hit(fn_id, atom);
    }

    pub(crate) fn record_userinit_builtin_class_miss(&mut self) {
        self.win32k_session.record_userinit_builtin_class_miss();
    }

    pub(crate) fn observe_class_atom_name(&mut self, atom: u16, units: &[u16]) -> bool {
        self.win32k_session.observe_class_atom_name(atom, units)
    }

    pub(crate) fn record_userinit_scrollbar_query(&mut self) {
        self.win32k_session.record_userinit_scrollbar_query();
    }

    pub(crate) fn record_userinit_scrollbar_classinfo(
        &mut self,
        atom: u16,
        style: u32,
        cb_wnd_extra: u32,
        has_proc: bool,
        copyout_ok: bool,
    ) {
        self.win32k_session.record_userinit_scrollbar_classinfo(
            atom,
            style,
            cb_wnd_extra,
            has_proc,
            copyout_ok,
        );
    }

    pub(crate) fn record_userinit_scrollbar_error(&mut self) {
        self.win32k_session.record_userinit_scrollbar_error();
    }

    pub(crate) fn publish_hosted_process_vspace(
        &mut self,
        pi: usize,
        pml4: u64,
    ) -> Result<(), u32> {
        if pi >= MAX_PI || pml4 == 0 || self.pm_pid_for_pi(pi).is_none() {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        self.process_vspaces[pi] = pml4;
        if pi < 64 {
            PM_VSPACE_PUBLISHED_OK.fetch_or(1u64 << pi, Ordering::Relaxed);
        }
        Ok(())
    }

    pub(crate) fn hosted_process_vspace(&self, pi: usize) -> Option<u64> {
        self.pm_pid_for_pi(pi)?;
        let pml4 = *self.process_vspaces.get(pi)?;
        (pml4 != 0).then_some(pml4)
    }

    fn pool_slot_bit(slot: usize) -> Option<u64> {
        (slot < PM_RUNTIME_THREAD_SLOTS).then_some(1u64 << slot)
    }

    fn claim_pool_usage_slot(&mut self, pi: usize) -> Option<usize> {
        let used = self.pool_used.get_mut(pi)?;
        let slot = (0..PM_RUNTIME_THREAD_SLOTS).find(|slot| *used & (1u64 << slot) == 0)?;
        *used |= 1u64 << slot;
        Some(slot)
    }

    pub(crate) fn pool_used_mask(&self, pi: usize) -> u64 {
        self.pool_used.get(pi).copied().unwrap_or(0)
    }

    pub(crate) fn release_pool_usage_slot(&mut self, pi: usize, slot: usize) -> bool {
        let Some(bit) = Self::pool_slot_bit(slot) else {
            return false;
        };
        let Some(used) = self.pool_used.get_mut(pi) else {
            return false;
        };
        *used &= !bit;
        true
    }

    pub(crate) fn set_pool_thread_suspended(
        &mut self,
        pi: usize,
        slot: usize,
        suspended: bool,
    ) -> bool {
        let Some(bit) = Self::pool_slot_bit(slot) else {
            return false;
        };
        let Some(mask) = self.pool_suspended.get_mut(pi) else {
            return false;
        };
        if suspended {
            *mask |= bit;
        } else {
            *mask &= !bit;
        }
        true
    }

    pub(crate) fn take_pool_thread_suspended(&mut self, pi: usize, slot: usize) -> Option<u32> {
        let bit = Self::pool_slot_bit(slot)?;
        let mask = self.pool_suspended.get_mut(pi)?;
        let was_suspended = *mask & bit != 0;
        *mask &= !bit;
        Some(was_suspended as u32)
    }

    pub(crate) fn is_pool_thread_suspended(&self, pi: usize, slot: usize) -> bool {
        let Some(bit) = Self::pool_slot_bit(slot) else {
            return false;
        };
        self.pool_suspended
            .get(pi)
            .is_some_and(|mask| *mask & bit != 0)
    }

    fn temporary_pid_for_pi(&self, pi: usize) -> Option<nt_process::ProcessId> {
        let pid = *self.temporary_process_slots.get(pi)?;
        (pid != 0).then_some(pid)
    }

    fn temporary_pi_for_pid(&self, pid: nt_process::ProcessId) -> Option<usize> {
        (pid != 0).then_some(())?;
        self.temporary_process_slots
            .iter()
            .position(|stored| *stored == pid)
    }

    pub(crate) fn register_temporary_process_slot(
        &mut self,
        pi: usize,
        pid: nt_process::ProcessId,
        pml4: u64,
    ) -> Result<(), u32> {
        if pi >= MAX_PI
            || pid == 0
            || self.pm.process(pid).is_none()
            || self.process_mechanisms.pid_for_pi(pi).is_some()
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        if self.temporary_process_slots[pi] != 0 && self.temporary_process_slots[pi] != pid {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        if self
            .temporary_pi_for_pid(pid)
            .is_some_and(|existing_pi| existing_pi != pi)
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        self.temporary_process_slots[pi] = pid;
        self.process_vspaces[pi] = pml4;
        Ok(())
    }

    pub(crate) fn clear_temporary_process_slot(&mut self, pi: usize) {
        if pi >= MAX_PI || self.process_mechanisms.pid_for_pi(pi).is_some() {
            return;
        }
        self.temporary_process_slots[pi] = 0;
        self.process_vspaces[pi] = 0;
    }

    pub(crate) fn register_temporary_pool_thread_slot(
        &mut self,
        pi: usize,
        slot: usize,
        tid: nt_process::ThreadId,
    ) -> Result<(), u32> {
        let Some(pid) = self.temporary_pid_for_pi(pi) else {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        };
        if slot >= PM_RUNTIME_THREAD_SLOTS {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        match self.pm.thread(tid) {
            Some(thread) if thread.process_id == pid => {}
            _ => return Err(nt_process::STATUS_INVALID_PARAMETER),
        }
        if self.process_mechanisms.pid_for_pi(pi).is_some() {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        self.register_hosted_pool_thread_identity(pi, slot, tid)?;
        self.release_pool_usage_slot(pi, slot);
        self.set_pool_thread_suspended(pi, slot, false);
        Ok(())
    }

    pub(crate) fn clear_temporary_pool_thread_slot(&mut self, pi: usize, slot: usize) {
        if pi >= MAX_PI
            || slot >= PM_RUNTIME_THREAD_SLOTS
            || self.temporary_pid_for_pi(pi).is_none()
            || self.process_mechanisms.pid_for_pi(pi).is_some()
        {
            return;
        }
        let _ = self.thread_mechanisms.release_pool(pi, slot);
        self.release_pool_usage_slot(pi, slot);
        self.set_pool_thread_suspended(pi, slot, false);
    }

    pub(crate) fn register_hosted_thread_tcb(
        &mut self,
        pi: usize,
        tid: u64,
        tcb: u64,
        badge: u64,
        role: HostedThreadRole,
    ) {
        if self
            .thread_runtime
            .register(pi, tid, tcb, badge, role)
            .is_some()
        {
            publish_hosted_thread_runtime_gate(pi, role);
        }
    }

    pub(crate) fn reserve_hosted_thread_runtime(
        &mut self,
        pi: usize,
        tid: u64,
        badge: u64,
        role: HostedThreadRole,
    ) -> bool {
        self.thread_runtime.reserve(pi, tid, badge, role).is_some()
    }

    pub(crate) fn register_main_thread_tcb(&mut self, pi: usize, tcb: u64) {
        if let Some(tid) = self.pm_main_tid_for_pi(pi) {
            let badge = self.hosted_process_top_badge(pi).unwrap_or(0);
            self.register_hosted_thread_tcb(pi, u64::from(tid), tcb, badge, HostedThreadRole::Main);
        }
    }

    pub(crate) fn hosted_thread_tcb(&self, tid: u64) -> Option<u64> {
        self.thread_runtime.tcb_by_tid(tid)
    }

    pub(crate) fn hosted_thread_role(&self, tid: u64) -> Option<HostedThreadRole> {
        self.thread_runtime
            .get_by_tid(tid)
            .map(|runtime| runtime.role)
    }

    fn hosted_thread_tcb_for_nt_resume_thread(&self, tid: u64) -> Option<u64> {
        if let Some(runtime) = self.thread_runtime.get_by_tid(tid) {
            if !runtime.role.can_raw_resume_from_nt_resume_thread() {
                return None;
            }
            return (runtime.tcb > 1).then_some(runtime.tcb);
        }
        None
    }

    pub(crate) fn hosted_main_thread_tcb_for_pi(&self, pi: usize) -> Option<u64> {
        self.thread_runtime.tcb_for_main_pi(pi)
    }

    pub(crate) fn hosted_thread_tcb_for_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<u64> {
        self.thread_runtime.tcb_for_role(pi, role)
    }

    pub(crate) fn hosted_thread_identity_for_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<(u64, u64, u64)> {
        let runtime = self.thread_runtime.get_by_role(pi, role)?;
        (runtime.tid != 0 && runtime.tcb > 1).then_some((runtime.tid, runtime.tcb, runtime.badge))
    }

    pub(crate) fn hosted_thread_tid_for_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<u64> {
        self.thread_runtime
            .get_by_role(pi, role)
            .map(|runtime| runtime.tid)
            .filter(|&tid| tid != 0)
    }

    pub(crate) fn hosted_thread_pi_for_badge(&self, badge: u64) -> Option<usize> {
        self.thread_runtime
            .get_by_badge(badge)
            .map(|runtime| runtime.pi)
    }

    pub(crate) fn hosted_thread_tid_for_badge(&self, badge: u64) -> Option<u64> {
        self.thread_runtime
            .get_by_badge(badge)
            .map(|runtime| runtime.tid)
            .filter(|&tid| tid != 0)
    }

    fn hosted_thread_role_for_current_badge(&self) -> Option<HostedThreadRole> {
        self.thread_runtime
            .get_by_badge(self.current_badge)
            .map(|runtime| runtime.role)
    }

    pub(crate) fn hosted_tp_worker_tcb(&self, pi: usize, slot: usize) -> Option<u64> {
        self.hosted_thread_tcb_for_role(pi, HostedThreadRole::TpWorker { slot })
    }

    pub(crate) fn first_free_hosted_tp_worker_slot(&self, pi: usize) -> Option<usize> {
        (0..TP_WORKER_SLOT_COUNT).find(|&slot| {
            self.hosted_thread_tid_for_role(pi, HostedThreadRole::TpWorker { slot })
                .is_none()
        })
    }

    pub(crate) fn reserve_hosted_tp_worker_slot(
        &mut self,
        pi: usize,
        slot: usize,
        tid: u64,
    ) -> bool {
        if pi >= MAX_PI || slot >= TP_WORKER_SLOT_COUNT {
            return false;
        }
        let badge = tp_worker_badge(pi, slot);
        if !self.reserve_hosted_thread_runtime(pi, tid, badge, HostedThreadRole::TpWorker { slot })
        {
            return false;
        }
        true
    }

    fn abandon_created_hosted_thread(&mut self, pool_slot: usize, tid: u64, handle: u64) {
        let _ = self.release_hosted_thread_runtime(tid);
        if let Some(pid) = self.pm_pid_for_pi(self.pi) {
            let _ = self.close_process_handle(pid, handle);
        }
        let thread = tid as nt_process::ThreadId;
        let _ = self
            .pm
            .set_thread_state(thread, nt_process::ThreadState::Initialized);
        self.release_pool_usage_slot(self.pi, pool_slot);
        self.set_pool_thread_suspended(self.pi, pool_slot, false);
    }

    fn reserve_created_hosted_thread_role(
        &mut self,
        pool_slot: usize,
        tid: u64,
        handle: u64,
        badge: u64,
        role: HostedThreadRole,
    ) -> bool {
        if self.hosted_thread_tid_for_role(self.pi, role).is_some()
            || !self.reserve_hosted_thread_runtime(self.pi, tid, badge, role)
        {
            self.abandon_created_hosted_thread(pool_slot, tid, handle);
            return false;
        }
        true
    }

    pub(crate) fn release_hosted_thread_runtime(
        &mut self,
        tid: u64,
    ) -> Option<HostedThreadRuntime> {
        self.thread_runtime.release_tid(tid)
    }

    fn hosted_thread_mechanism_for_tid(&self, tid: u64) -> Option<nt_user_host::ThreadMechanism> {
        if tid == 0 || tid > u32::MAX as u64 {
            return None;
        }
        let tid32 = tid as nt_process::ThreadId;
        self.thread_mechanisms.get_by_tid(tid32).or_else(|| {
            for pi in 0..MAX_PI {
                if self.pm_main_tid_for_pi(pi) == Some(tid32) {
                    return Some(nt_user_host::ThreadMechanism {
                        pi,
                        tid: tid32,
                        kind: nt_user_host::ThreadMechanismKind::Main,
                    });
                }
                for slot in 0..PM_RUNTIME_THREAD_SLOTS {
                    if self.pm_pool_tid_for_slot(pi, slot) == Some(tid32) {
                        return Some(nt_user_host::ThreadMechanism {
                            pi,
                            tid: tid32,
                            kind: nt_user_host::ThreadMechanismKind::Pool { slot },
                        });
                    }
                }
            }
            None
        })
    }

    pub(crate) fn hosted_process_image(
        &self,
        pi: usize,
    ) -> Option<nt_exe_image::HostedProcessImageRef<'_>> {
        // SAFETY: `service_sec_image` constructs the handler after the loop-owned catalog and drops
        // it before the catalog. Catalog mutations are confined to the service loop/bootstrap path;
        // handler lookups only publish or consume already-registered metadata.
        unsafe { (&*self.hosted_images).get_by_pi(pi) }
    }

    pub(crate) fn hosted_process_leaf(&self, pi: usize) -> Option<&[u8]> {
        self.hosted_process_image(pi).map(|image| image.leaf)
    }

    pub(crate) fn hosted_process_role(&self, pi: usize) -> Option<nt_exe_image::HostedProcessRole> {
        self.hosted_process_image(pi).map(|image| image.role)
    }

    pub(crate) fn primary_token_authentication_id_for_pi(
        &self,
        pi: usize,
    ) -> Option<nt_security::Luid> {
        let pid = self.pm_pid_for_pi(pi)?;
        let token = self.pm.process_primary_token(pid)?;
        Some(self.token_store.statistics(token)?.authentication_id)
    }

    pub(crate) fn primary_token_user_sid_for_pi(&self, pi: usize, out: &mut [u8]) -> Option<usize> {
        let pid = self.pm_pid_for_pi(pi)?;
        let token = self.pm.process_primary_token(pid)?;
        self.token_store.get(token)?.user.write_native(out)
    }

    pub(crate) fn hosted_process_top_badge(&self, pi: usize) -> Option<u64> {
        self.hosted_process_image(pi).map(|image| image.top_badge)
    }

    fn publish_registered_hosted_process_metadata(
        &self,
        image: nt_exe_image::HostedProcessImageRef<'_>,
    ) -> Result<(), u32> {
        if self.hosted_process_image(image.pi) != Some(image) {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        publish_hosted_gate_image(image);
        Ok(())
    }

    fn register_hosted_main_thread_identity(
        &mut self,
        pi: usize,
        tid: nt_process::ThreadId,
    ) -> Result<bool, u32> {
        match self.thread_mechanisms.claim_main(pi, tid) {
            Ok(_) => Ok(true),
            Err(nt_user_host::MechanismError::SlotOccupied)
                if self.thread_mechanisms.main_tid_for_pi(pi) == Some(tid) =>
            {
                Ok(false)
            }
            Err(_) => Err(nt_process::STATUS_INVALID_PARAMETER),
        }
    }

    fn register_hosted_process_identity(
        &mut self,
        pi: usize,
        pid: nt_process::ProcessId,
        main_tid: nt_process::ThreadId,
        top_badge: u64,
    ) -> Result<(), u32> {
        let main_claimed = self.register_hosted_main_thread_identity(pi, main_tid)?;

        match self
            .process_mechanisms
            .claim_or_get(pi, pid, main_tid, top_badge)
        {
            Ok(_) => Ok(()),
            Err(_) => {
                if main_claimed {
                    let _ = self.thread_mechanisms.release_main(pi);
                }
                Err(nt_process::STATUS_INVALID_PARAMETER)
            }
        }
    }

    fn register_hosted_pool_thread_identity(
        &mut self,
        pi: usize,
        slot: usize,
        tid: nt_process::ThreadId,
    ) -> Result<(), u32> {
        match self.thread_mechanisms.claim_pool(pi, slot, tid) {
            Ok(_) => Ok(()),
            Err(nt_user_host::MechanismError::SlotOccupied)
                if self.thread_mechanisms.pool_tid_for_slot(pi, slot) == Some(tid) =>
            {
                Ok(())
            }
            Err(_) => Err(nt_process::STATUS_INVALID_PARAMETER),
        }
    }

    fn current_pm_pid(&self) -> Option<nt_process::ProcessId> {
        self.pm_pid_for_pi(self.pi)
    }

    fn current_hosted_process_image(&self) -> Option<nt_exe_image::HostedProcessImageRef<'_>> {
        self.hosted_process_image(self.pi)
    }

    fn current_hosted_process_role(&self) -> Option<nt_exe_image::HostedProcessRole> {
        self.current_hosted_process_image().map(|image| image.role)
    }

    fn current_process_has_role(&self, role: nt_exe_image::HostedProcessRole) -> bool {
        self.current_hosted_process_role() == Some(role)
    }

    fn current_process_is_hosted_leaf(&self, leaf: &[u8]) -> bool {
        self.current_hosted_process_image()
            .is_some_and(|image| image.leaf.eq_ignore_ascii_case(leaf))
    }

    fn current_process_is_noninteractive_service(&self) -> bool {
        self.current_process_has_role(nt_exe_image::HostedProcessRole::NonInteractiveService)
    }

    fn current_process_is_services(&self) -> bool {
        self.current_process_is_hosted_leaf(b"services.exe")
    }

    fn current_process_is_smss(&self) -> bool {
        self.current_process_is_hosted_leaf(b"smss.exe")
    }

    fn current_process_is_csrss(&self) -> bool {
        self.current_process_is_hosted_leaf(b"csrss.exe")
    }

    fn current_process_is_lsass(&self) -> bool {
        self.current_process_is_hosted_leaf(b"lsass.exe")
    }

    fn current_process_is_winlogon(&self) -> bool {
        self.current_process_is_hosted_leaf(b"winlogon.exe")
    }

    fn current_process_is_userinit(&self) -> bool {
        self.current_process_is_hosted_leaf(b"userinit.exe")
    }

    fn current_process_is_explorer(&self) -> bool {
        self.current_process_is_hosted_leaf(b"explorer.exe")
    }

    fn current_process_uses_pe_backed_registry_strings(&self) -> bool {
        matches!(
            self.current_hosted_process_role(),
            Some(
                nt_exe_image::HostedProcessRole::InteractiveLogon
                    | nt_exe_image::HostedProcessRole::NonInteractiveService
                    | nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
                    | nt_exe_image::HostedProcessRole::InteractiveShell
            )
        )
    }

    fn current_process_uses_csr_client_connect(&self) -> bool {
        matches!(
            self.current_hosted_process_role(),
            Some(
                nt_exe_image::HostedProcessRole::InteractiveLogon
                    | nt_exe_image::HostedProcessRole::NonInteractiveService
                    | nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
                    | nt_exe_image::HostedProcessRole::InteractiveShell
            )
        )
    }

    fn current_hosted_thread_role(&self) -> Option<HostedThreadRole> {
        self.hosted_thread_role_for_current_badge().or_else(|| {
            self.thread_runtime
                .get_by_tid(self.current_tid)
                .map(|runtime| runtime.role)
        })
    }

    fn current_thread_has_role(&self, role: HostedThreadRole) -> bool {
        self.current_hosted_thread_role() == Some(role)
    }

    fn current_thread_is_main_process_thread(&self) -> bool {
        self.current_thread_has_role(HostedThreadRole::Main)
    }

    fn refresh_process_manager_gates(&self) {
        let mut process_count = 0u64;
        let mut identity_ok = 0u64;
        let mut main_threads_ok = 0u64;
        let mut min_handle_cap = usize::MAX;
        for pi in 0..MAX_PI {
            let Some(pid) = self.pm_pid_for_pi(pi) else {
                continue;
            };
            process_count += 1;
            min_handle_cap = min_handle_cap.min(self.pm.handle_capacity(pid));
            let distinct = (0..MAX_PI)
                .all(|other_pi| other_pi == pi || self.pm_pid_for_pi(other_pi) != Some(pid));
            if let Some(image) = self.hosted_process_image(pi) {
                if distinct
                    && self.pm.process(pid).is_some_and(|process| {
                        process
                            .image_file_name
                            .eq_ignore_ascii_case(image.process_name)
                    })
                {
                    identity_ok |= 1 << pi;
                }
            }
            let tid = self.pm_main_tid_for_pi(pi).unwrap_or(0);
            if tid != 0 {
                let running = self
                    .pm
                    .process(pid)
                    .is_some_and(|process| process.state == nt_process::ProcessState::Running);
                let cid_ok = self.pm.client_id(tid)
                    == Some(nt_process::ClientId {
                        unique_process: pid,
                        unique_thread: tid,
                    });
                if self.pm.main_thread(pid) == Some(tid) && running && cid_ok {
                    main_threads_ok |= 1 << pi;
                }
            }
        }
        PM_PROC_COUNT.store(process_count, Ordering::Relaxed);
        PM_IDENTITY_OK.store(identity_ok, Ordering::Relaxed);
        PM_MAIN_THREADS_OK.store(main_threads_ok, Ordering::Relaxed);
        PM_HANDLE_CAP_BOOT.store(
            if process_count == 0 {
                0
            } else {
                min_handle_cap as u64
            },
            Ordering::Relaxed,
        );
    }

    fn allocate_hosted_process_slot(
        &mut self,
        creator_pi: usize,
        image: nt_exe_image::HostedProcessImageRef<'_>,
    ) -> Result<usize, u32> {
        let child_pi = image.pi;
        let name = image.process_name;
        if let Some(existing_pid) = self.pm_pid_for_pi(child_pi) {
            let matches_existing = self
                .pm
                .process(existing_pid)
                .is_some_and(|process| process.image_file_name.eq_ignore_ascii_case(name));
            if matches_existing {
                return Ok(child_pi);
            }
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let parent = self
            .pm_pid_for_pi(creator_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.publish_registered_hosted_process_metadata(image)?;
        let pid = self.pm.create_process(name, Some(parent), None);
        self.process_vspaces[child_pi] = 0;
        let main_tid = self.pm.create_thread(pid, 0, 0, false)?;
        self.register_hosted_process_identity(child_pi, pid, main_tid, image.top_badge)?;
        for slot in 0..PM_RUNTIME_THREAD_SLOTS {
            if let Ok(tid) = self.pm.create_thread(pid, 0, 0, false) {
                let _ = self
                    .pm
                    .set_thread_state(tid, nt_process::ThreadState::Initialized);
                self.register_hosted_pool_thread_identity(child_pi, slot, tid)?;
            }
        }
        self.pm.reserve_handles(pid, PM_HANDLE_RESERVE);
        let (token, inherited_token) =
            if let Some(parent_token) = self.pm.process_primary_token(parent) {
                if self.token_store.retain(parent_token).is_ok() {
                    (parent_token, true)
                } else {
                    (
                        self.token_store.insert(nt_security::AccessToken::system()),
                        false,
                    )
                }
            } else {
                (
                    self.token_store.insert(nt_security::AccessToken::system()),
                    false,
                )
            };
        if let Err(status) = self.pm.replace_process_primary_token(pid, Some(token)) {
            let _ = self.token_store.release(token);
            return Err(status);
        }
        self.token_dirty = true;
        self.process_dirty = true;
        PM_DYNAMIC_PROCESS_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        self.refresh_process_manager_gates();
        unsafe {
            print_str(b"[pm-dynamic] allocated hosted process pi=");
            print_u64(child_pi as u64);
            print_str(b" pid=");
            print_u64(pid as u64);
            print_str(b" parent=");
            print_u64(parent as u64);
            print_str(b" image=");
            print_str(name.as_bytes());
            print_str(b" token=");
            print_u64(token.raw() as u64);
            print_str(if inherited_token {
                b" inherited\n" as &[u8]
            } else {
                b" system\n" as &[u8]
            });
        }
        Ok(child_pi)
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
        // Fallback (no EPROCESS for this pi yet): global monotonic value.
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Mint a process-local handle for an anonymous keyed event. The wait/release rendezvous is
    /// currently keyed by the caller's raw `Key` value, so the object only needs durable handle-table
    /// ownership plus a non-NULL value for ReactOS' per-process RTL keyed-event global.
    pub(crate) fn mint_keyed_event_handle(&mut self, access: u32) -> u64 {
        if let Some(pid) = self.pm_pid_for_pi(self.pi) {
            if let Ok(h) = self.pm.insert_handle(
                pid,
                nt_process::HandleObject::Opaque(KEYEDEVENT_HANDLE_TAG),
                access,
            ) {
                let c = self.pm.handle_count(pid) as u64;
                if c > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
                    PM_HANDLE_PEAK.store(c, Ordering::Relaxed);
                }
                PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                return h as u64;
            }
        }
        self.mint_handle()
    }

    /// Mint a process-local handle backed by a typed filesystem `FILE_OBJECT` identity.
    pub(crate) fn mint_file_handle(
        &mut self,
        file_id: u64,
        access: u32,
        synchronous: bool,
    ) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        self.file_completion
            .insert_file(file_id, synchronous)
            .ok()?;
        let handle =
            match self
                .pm
                .insert_handle(pid, nt_process::HandleObject::File(file_id), access)
            {
                Ok(handle) => handle,
                Err(_) => {
                    self.release_file_reference(file_id);
                    return None;
                }
            };
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

    fn readonly_disk_open_entry(
        name16: &[u16],
        desired_access: u32,
        open_options: u32,
    ) -> Option<(u32, u32)> {
        const FILE_EXECUTE: u32 = 0x0000_0020;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        let wants_read = desired_access & (nt_fs::FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
        let wants_execute = desired_access & (FILE_EXECUTE | GENERIC_EXECUTE) != 0;
        let synchronous = open_options
            & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
            != 0;
        if open_options & nt_fs::FILE_DIRECTORY_FILE != 0
            || !wants_read
            || wants_execute
            || !synchronous
        {
            return None;
        }
        nt_fs::nt_path_to_volume_relative(name16, b"reactos")
            .and_then(|path| unsafe { exec_fs().and_then(|fs| fat_open_path(&fs, &path)) })
    }

    fn readonly_disk_open_miss_status(name16: &[u16]) -> Option<u32> {
        let path = nt_fs::nt_path_to_volume_relative(name16, b"reactos")?;
        let fs = unsafe { exec_fs() }?;
        if path.is_empty() {
            return Some(nt_fs::STATUS_NOT_A_DIRECTORY);
        }
        Some(match unsafe { fat_open_path_entry(&fs, &path) } {
            Some((_, _, attributes)) if attributes & 0x10 != 0 => nt_fs::STATUS_NOT_A_DIRECTORY,
            Some(_) => nt_fs::STATUS_NOT_SUPPORTED,
            None => nt_fs::STATUS_OBJECT_NAME_NOT_FOUND,
        })
    }

    fn unsupported_nt_create_file(&self, name16: &[u16]) -> u32 {
        // A file namespace this host has no service for. Answer HONESTLY with
        // STATUS_NOT_IMPLEMENTED: no fabricated handle, and the CALLER decides what to do. This
        // used to also set `self.stop`, which PARKED the calling process as unrecoverable - a
        // development tripwire, not a correctness requirement. Traced once + counted so the
        // frontier stays visible rather than silent.
        if !NT_CREATE_FILE_UNSUPPORTED_TRACED.swap(true, Ordering::Relaxed) {
            print_str(b"[nt-create-file] pi=");
            print_u64(self.pi as u64);
            print_str(
                b" unsupported file namespace -> STATUS_NOT_IMPLEMENTED (honest miss, no park) name=\"",
            );
            for &unit in name16.iter().take(96) {
                debug_put_char(if (0x20..0x7f).contains(&unit) {
                    unit as u8
                } else {
                    b'?'
                });
            }
            print_str(b"\"\n");
        }
        NT_CREATE_FILE_UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
        0xC000_0002 // STATUS_NOT_IMPLEMENTED
    }

    /// Mint a process-local handle for a directory on the mounted FAT volume.
    pub(crate) fn mint_directory_handle(&mut self, first_cluster: u32, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let object_id = self.directory_opens.create(first_cluster).ok()?;
        let handle = match self.pm.insert_handle(
            pid,
            nt_process::HandleObject::Directory {
                first_cluster,
                object_id,
            },
            access,
        ) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = self.directory_opens.release(object_id);
                return None;
            }
        };
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
        let Some(object) = self.pm.lookup_handle(pid, handle as nt_process::Handle) else {
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

    /// Mint a process-local handle for a file or directory on the WRITABLE overlay volume.
    /// `file_id` is that volume's own file-object id (see `writable_fs`).
    pub(crate) fn mint_overlay_file_handle(&mut self, file_id: u64, access: u32) -> Option<u64> {
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            unsafe { crate::writable_fs::close(file_id) };
            return None;
        };
        let handle =
            match self
                .pm
                .insert_handle(pid, nt_process::HandleObject::OverlayFile(file_id), access)
            {
                Ok(handle) => handle,
                Err(_) => {
                    // The volume owns the file object until a handle takes it; give it back.
                    unsafe { crate::writable_fs::close(file_id) };
                    return None;
                }
            };
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    /// The writable-overlay file-object id behind `handle`, or `None` when the handle names some
    /// other kind of object (so the caller falls through to its existing routing).
    pub(crate) fn overlay_file_id_for(&self, handle: u64) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::OverlayFile(file_id)) => Some(file_id),
            _ => None,
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

    pub(crate) fn signal_event_index(&mut self, index: usize) -> u32 {
        let Some(previous) = self.events.set_existing(index as u64) else {
            return 0xC000_0008; // STATUS_INVALID_HANDLE
        };
        if !previous {
            // SAFETY: native dispatch is serialized; the signal and waiter selection are one
            // executive transition.
            unsafe { wait_wake_dispatcher_set(self) };
        }
        0
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
                if tag & SEMAPHORE_HANDLE_TAG_MASK == SEMAPHORE_HANDLE_TAG =>
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
            .filter(|entry| entry.kind == 3 && self.semaphores.contains(index as u64))
            .map(|_| index)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub(crate) fn mint_mutant_handle(&mut self, index: usize, access: u32) -> Option<u64> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let tag = MUTANT_HANDLE_TAG | index as u64;
        let handle = self
            .pm
            .insert_handle(
                pid,
                nt_process::HandleObject::Opaque(tag),
                nt_kernel_exec::map_mutant_access(access),
            )
            .ok()?;
        let count = self.pm.handle_count(pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(handle as u64)
    }

    pub(crate) fn mutant_index_for_handle(
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
                Some(entry) if entry.kind != 4 => Err(STATUS_OBJECT_TYPE_MISMATCH),
                _ => Err(STATUS_INVALID_HANDLE),
            };
        }
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let tag = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Opaque(tag))
                if tag & MUTANT_HANDLE_TAG_MASK == MUTANT_HANDLE_TAG =>
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
            .filter(|entry| entry.kind == 4 && self.mutants.contains(index as u64))
            .map(|_| index)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Resolve a typed process-local `DEBUG_OBJECT` handle and enforce the access the operation
    /// requires (`DbgkDebugObjectMapping`-mapped at create time).
    pub(crate) fn debug_object_for_handle(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<nt_process::dbgk::DebugObjectId, u32> {
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        let pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let object = match self.pm.lookup_handle(pid, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::DebugObject(object)) => object,
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => return Err(nt_process::STATUS_INVALID_HANDLE),
        };
        let granted = self
            .pm
            .handle_access(pid, handle as nt_process::Handle)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        if required_access != 0 && granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        if self.pm.debug_object(object).is_none() {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        Ok(object)
    }

    /// Mirror a debug object's modelled `EventsPresent` onto the dispatcher event backing it, so a
    /// parked `NtWaitForDebugEvent` waiter is woken (or re-blocked) by the ordinary wait machinery.
    pub(crate) fn sync_debug_object_signal(&mut self, object: nt_process::dbgk::DebugObjectId) {
        let Some((key, present)) = self
            .pm
            .debug_object(object)
            .map(|o| (o.host_event, o.events_present()))
        else {
            return;
        };
        if key == 0 {
            return;
        }
        let index = key - 1;
        if present {
            let _ = self.events.set_existing(index);
        } else {
            self.events.clear_existing(index);
        }
    }

    /// ★ POST-SIDE WAKE CORRECTNESS. Mirror **every** live debug object's modelled `EventsPresent`
    /// onto the dispatcher event backing it, and — when that newly signals one — run the ordinary
    /// dispatcher wake so a thread parked inside `NtWaitForDebugEvent` is resumed.
    ///
    /// Why blanket rather than per-object: debug events are posted from many places that are not
    /// the five dbgk syscall arms — the `nt-process` lifecycle (thread create / thread exit /
    /// process exit, reached through `NtCreateThread`/`NtTerminate*`) and now
    /// [`dbgk_forward_exception`](Self::dbgk_forward_exception) from the FAULT path. Before this,
    /// only the dbgk arms mirrored the signal, so an event queued by any other path marked the
    /// modelled `EventsPresent` but never set the dispatcher event and could not wake a parked
    /// debugger. This runs at the one chokepoint every syscall passes through
    /// (`NativeSyscallHandler::handle`) plus the fault-path forward, so posting is uniformly
    /// wake-correct wherever it happens.
    ///
    /// Costs nothing on a plain boot: with no debug object alive it returns on the first line, so
    /// the live syscall path is byte-identical.
    pub(crate) fn sync_debug_object_signals(&mut self) {
        if self.pm.debug_object_count() == 0 {
            return;
        }
        // Debug objects are per-debugger and few (one per `DbgUiConnectToDbg`); 8 covers every
        // realistic set, and a longer one simply keeps the objects the loop already mirrored.
        let mut ids = [0 as nt_process::dbgk::DebugObjectId; 8];
        let n = self.pm.debug_object_ids_into(&mut ids);
        let mut newly_signalled = false;
        for &object in &ids[..n] {
            let Some((key, present)) = self
                .pm
                .debug_object(object)
                .map(|o| (o.host_event, o.events_present()))
            else {
                continue;
            };
            if key == 0 {
                continue;
            }
            let index = key - 1;
            if present && !self.dispatcher_ready(index as usize) {
                newly_signalled = true;
            }
            self.sync_debug_object_signal(object);
        }
        if newly_signalled {
            unsafe { wait_wake_dispatcher_set(self) };
        }
    }

    /// `DbgkForwardException` — report a user-mode exception taken by hosted process index `pi` to
    /// that process's `EPROCESS.DebugPort`, and wake a debugger parked on it.
    ///
    /// ★ SAFETY PROPERTY: when the process is **not** being debugged this returns `false` having
    /// done nothing at all (two table lookups, no logging, no state change), so every caller's
    /// existing unrecoverable-fault handling runs byte-identically. On the current boot nothing
    /// attaches a debugger to a hosted process, so this always takes that early return.
    ///
    /// `tid_hint` is the reporting thread (0 ⇒ the process's main thread — the fault path's
    /// per-badge identity is not yet resolved where the classification happens). `first_chance` is
    /// `DbgkForwardException`'s `!SecondChance`.
    ///
    /// Returns `true` when the event was queued. The reporting thread is **not** blocked on the
    /// debugger's continue — see `ntdll_plan.md` §D for what that does and does not mean.
    pub(crate) fn dbgk_forward_exception(
        &mut self,
        pi: usize,
        tid_hint: u64,
        record: nt_process::dbgk::ExceptionRecord,
        first_chance: bool,
    ) -> bool {
        let Some(pid) = self.pm_pid_for_pi(pi) else {
            return false;
        };
        if !self.pm.is_process_being_debugged(pid) {
            return false;
        }
        let tid = match tid_hint {
            0 => self.pm.main_thread(pid).unwrap_or(0),
            hint => hint as nt_process::ThreadId,
        };
        if self
            .pm
            .report_exception(pid, tid, record, first_chance)
            .is_none()
        {
            return false;
        }
        DBGK_EXCEPTIONS_FORWARDED.fetch_add(1, Ordering::Relaxed);
        self.sync_debug_object_signals();
        true
    }

    /// ★ TARGET-SIDE BLOCKING — `DbgkpQueueMessage`'s wait on `DebugEvent->ContinueEvent`.
    ///
    /// Park the thread that just reported a debug event for hosted process `pi` on the event it
    /// queued, so it does **not** return from its fault/syscall until `NtDebugContinue` resolves it
    /// (`dbgk_wake_target`). The park itself is the ordinary reply-capability steal
    /// ([`dbgk_reporter_park`]); the stolen capability is recorded ON THE `DEBUG_EVENT`
    /// ([`nt_process::dbgk::ReporterBlock`]) — where NT keeps the waiting reporter.
    ///
    /// `kind` is the fault flavour that says which reply shape resumes it (`DBGK_BLOCK_*`);
    /// `resume_status` is what a SYSCALL-flavoured reporter returns when resumed.
    ///
    /// ★ SAFETY PROPERTY: returns `false` having done NOTHING when the process is not being
    /// debugged (the path every fault on the live boot takes), when no debug port resolves, when the
    /// reply pool is exhausted, or when the queued event could not take the block — so the caller
    /// falls back to its existing post-and-continue handling and the fault path is byte-identical.
    ///
    /// `reply_cap` names the Reply capability the reporter's blocked Call is bound to: pass **0**
    /// (every production call site) to steal the ACTIVE one out of `REPLY_MAIN_SLOT`, or an explicit
    /// capability when the caller already received the fault on a reply object of its own.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn dbgk_block_reporter(
        &mut self,
        pi: usize,
        tid_hint: u64,
        badge: u64,
        kind: u8,
        reply_cap: u64,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        resume_status: u64,
    ) -> bool {
        let Some(pid) = self.pm_pid_for_pi(pi) else {
            return false;
        };
        let Some(object) = self.pm.process_debug_port(pid) else {
            return false;
        };
        let tid = match tid_hint {
            0 => self.pm.main_thread(pid).unwrap_or(0),
            hint => hint as nt_process::ThreadId,
        };
        let client_id = nt_process::ClientId {
            unique_process: pid,
            unique_thread: tid,
        };
        let parked = if reply_cap != 0 {
            let block = nt_process::dbgk::ReporterBlock {
                kind,
                reply_cap,
                pi: pi as u32,
                tid: tid as u64,
                badge,
                resume_ip,
                resume_sp,
                resume_flags,
                resume_status,
            };
            DBGK_REPORTERS_BLOCKED.fetch_add(1, Ordering::Relaxed);
            block.is_blocked().then_some(block)
        } else {
            dbgk_reporter_park(
                kind,
                pi,
                tid as u64,
                badge,
                resume_ip,
                resume_sp,
                resume_flags,
                resume_status,
            )
        };
        let Some(block) = parked else {
            return false;
        };
        if self.pm.block_reporter(object, client_id, block) {
            return true;
        }
        // Nothing eligible took the block (no non-NOWAIT event queued for this client). Recycle the
        // stolen Reply object and let the caller's own handling proceed — the reporter is left
        // blocked exactly as `park_and_log!`'s recv-without-reply would leave it.
        dbgk_reporter_abandon(&block);
        false
    }

    /// `DbgkpWakeTarget` — apply a continue status to the reporter blocked on a resolved event.
    ///
    /// | continue status | what happens to the reporting thread |
    /// |---|---|
    /// | `DBG_CONTINUE` / `DBG_EXCEPTION_HANDLED` | **RESUMED** with its fault-flavoured reply — the exception is dismissed and it CONTINUES EXECUTION (a `#PF` retries the faulting instruction, an int3 resumes past it, a syscall returns its status) |
    /// | `DBG_EXCEPTION_NOT_HANDLED` at a FAULT | left blocked: the fault site's own unrecoverable handling stands (today's outcome). Its win32k user-mode callbacks are unwound, exactly as `park_and_log!` does |
    /// | `DBG_EXCEPTION_NOT_HANDLED` from a SYSCALL | resumed (there is no exception to decline — the syscall simply completes) |
    /// | `DBG_TERMINATE_THREAD` | **ENFORCED**: the reporting thread is really terminated and never resumed |
    /// | `DBG_TERMINATE_PROCESS` | **ENFORCED**: its whole process is terminated (every thread), and never resumed |
    ///
    /// Returns the [`WakeAction`](nt_process::dbgk::WakeAction) taken.
    pub(crate) unsafe fn dbgk_wake_target(
        &mut self,
        client_id: nt_process::ClientId,
        block: Option<nt_process::dbgk::ReporterBlock>,
        continue_status: u32,
    ) -> nt_process::dbgk::WakeAction {
        use nt_process::dbgk::{wake_action, ReporterBlock, WakeAction};
        let block = block.unwrap_or(ReporterBlock::default());
        let action = wake_action(&block, continue_status);
        match action {
            WakeAction::None => {}
            WakeAction::Resume => {
                dbgk_reporter_resume(&block);
            }
            WakeAction::LeaveBlocked => {
                dbgk_reporter_abandon(&block);
                DBGK_REPORTERS_LEFT_BLOCKED.fetch_add(1, Ordering::Relaxed);
                // The reporter will never return, so any win32k user-mode callback it owns must be
                // unwound — the same dead-client discipline `park_and_log!` applies.
                crate::win32k_glue::unwind_dead_client_user_callbacks(block.pi);
            }
            WakeAction::TerminateThread => {
                dbgk_reporter_abandon(&block);
                let _ = self.pm.terminate_thread_at(
                    client_id.unique_thread,
                    nt_process::dbgk::DBG_TERMINATE_THREAD,
                    nt_system_time_100ns() as i64,
                );
                DBGK_TERMINATES_ENFORCED.fetch_add(1, Ordering::Relaxed);
            }
            WakeAction::TerminateProcess => {
                dbgk_reporter_abandon(&block);
                let _ = self.pm.terminate_process_at(
                    client_id.unique_process,
                    nt_process::dbgk::DBG_TERMINATE_PROCESS,
                    nt_system_time_100ns() as i64,
                );
                DBGK_TERMINATES_ENFORCED.fetch_add(1, Ordering::Relaxed);
                if block.is_blocked() {
                    crate::win32k_glue::unwind_dead_client_user_callbacks(block.pi);
                }
            }
        }
        action
    }

    /// ★ THE ESCAPE HATCH. Release every reporter blocked on `object` (optionally only `pid`'s), so
    /// a debugger that dies, closes its debug object, or simply never continues can NEVER leave a
    /// target parked forever — which would be a boot that fails to quiesce.
    ///
    /// Faithful to `DbgkClearProcessDebugObject`, which marks every flushed event
    /// `STATUS_DEBUGGER_INACTIVE` and wakes its target: a **syscall** reporter is genuinely resumed
    /// (its operation completes), while a **fault** reporter — whose fault was unrecoverable and
    /// whose site would have parked it anyway — is left blocked with its Reply object recycled.
    /// Returns how many reporters were released.
    pub(crate) unsafe fn dbgk_release_blocked_reporters(
        &mut self,
        object: nt_process::dbgk::DebugObjectId,
        pid: Option<nt_process::ProcessId>,
    ) -> usize {
        let released = self.pm.drain_blocked_reporters(object, pid);
        let n = released.len();
        for (_client, block) in released {
            if block.is_fault() {
                dbgk_reporter_abandon(&block);
                crate::win32k_glue::unwind_dead_client_user_callbacks(block.pi);
            } else {
                dbgk_reporter_resume(&block);
            }
            DBGK_REPORTERS_RELEASED.fetch_add(1, Ordering::Relaxed);
        }
        n
    }

    /// Release every blocked reporter on EVERY live debug object — the unconditional, bounded
    /// backstop the boot runs before the gate. With no debug object alive it returns on its first
    /// line, so a plain boot pays nothing.
    pub(crate) unsafe fn dbgk_release_all_blocked_reporters(&mut self) -> usize {
        if self.pm.debug_object_count() == 0 {
            return 0;
        }
        let mut ids = [0 as nt_process::dbgk::DebugObjectId; 8];
        let n = self.pm.debug_object_ids_into(&mut ids);
        let mut released = 0;
        for &object in &ids[..n] {
            released += self.dbgk_release_blocked_reporters(object, None);
        }
        released
    }

    /// `DbgkMapViewOfSection` — an **IMAGE** view at `base` became mapped in hosted process index
    /// `pi`. Records it in the process's modelled module list and posts `DbgKmLoadDllApi` to its
    /// `EPROCESS.DebugPort`, waking a debugger parked on it.
    ///
    /// ★ SAFETY PROPERTY: with **no** `DEBUG_OBJECT` alive anywhere — every boot today — this
    /// returns `false` on its first line, so the section-mapping path (every DLL load, every
    /// demand-map, win32k's client mappings) is byte-identical. `report_module_load` itself is gated
    /// the same way, so not even the module list is touched.
    ///
    /// `file_handle` is the MAPPING process's own handle to the image file; the wait duplicates it
    /// into the debugger's table (`DbgkpOpenHandles`) and leaves 0 if it cannot. `name_pointer` is a
    /// pointer in the debuggee to the module name — NT reports
    /// `&NtCurrentTeb()->NtTib.ArbitraryUserPointer`.
    pub(crate) fn dbgk_module_load(
        &mut self,
        pi: usize,
        base: u64,
        file_handle: u64,
        debug_info: (u32, u32),
        name_pointer: u64,
    ) -> bool {
        if self.pm.debug_object_count() == 0 {
            return false;
        }
        let Some(pid) = self.pm_pid_for_pi(pi) else {
            return false;
        };
        let tid = self.dbgk_reporting_tid(pid);
        let module = nt_process::ProcessModule {
            pid,
            base,
            file_handle,
            debug_info_file_offset: debug_info.0,
            debug_info_size: debug_info.1,
            name_pointer,
        };
        if self.pm.report_module_load(pid, tid, module).is_none() {
            return false;
        }
        DBGK_MODULE_LOADS.fetch_add(1, Ordering::Relaxed);
        // `DbgkMapViewOfSection` queues with flags 0 ⇒ the MAPPING THREAD BLOCKS on the continue.
        // The park needs this caller's resume context, so latch the request for the reply site.
        self.dbgk_block_request = true;
        self.sync_debug_object_signals();
        true
    }

    /// `DbgkUnMapViewOfSection` — the view at `base` was unmapped from hosted process index `pi`.
    /// Posts `DbgKmUnloadDllApi` **only when `base` names a tracked IMAGE view** (the modelled form
    /// of `MmUnmapViewOfSection`'s `if (DbgBase)` guard — a data / anonymous view was never
    /// recorded). Same first-line no-debug-object early return as [`dbgk_module_load`].
    pub(crate) fn dbgk_module_unload(&mut self, pi: usize, base: u64) -> bool {
        if self.pm.debug_object_count() == 0 || base == 0 {
            return false;
        }
        let Some(pid) = self.pm_pid_for_pi(pi) else {
            return false;
        };
        let tid = self.dbgk_reporting_tid(pid);
        if self.pm.report_module_unload(pid, tid, base).is_none() {
            return false;
        }
        DBGK_MODULE_UNLOADS.fetch_add(1, Ordering::Relaxed);
        self.sync_debug_object_signals();
        true
    }

    /// ★ `DbgkpMarkProcessPeb` — write `PEB->BeingDebugged` THROUGH into the target's LIVE PEB page.
    ///
    /// `ProcessManager` already models the flag (`EPROCESS.being_debugged`, set by
    /// `debug_active_process` and cleared by `remove_process_debug` / `destroy_debug_object`), but
    /// the byte a debuggee actually reads is `NtCurrentPeb()->BeingDebugged` — `PEB+2` in its own
    /// address space. Without this write-through the whole break-in is INERT: `DbgUiRemoteBreakin`
    /// reads a zero byte, skips `DbgBreakPoint` and exits silently.
    ///
    /// The write uses the SAME general cross-process client-memory path `NtWriteVirtualMemory` uses
    /// (`client_copyout_mapped` against the target's registered frames / demand-fill scratch); every
    /// hosted process's PEB frame is registered with a permanent executive alias at spawn
    /// (`csrss_frame_put_at(pi, SMSS_PEB_VA, peb, scr + 0x1000)`), so no new mechanism is invented
    /// and the write works with or without the loop context.
    ///
    /// ★ SAFETY: only ever reached from the five dbgk service arms, none of which runs on a boot
    /// with no debugger — so the live PEB is never touched.
    pub(crate) unsafe fn dbgk_mark_process_peb(&mut self, pi: usize, being_debugged: bool) -> bool {
        // `PEB.BeingDebugged` — the byte-exact PEB layout's own constant, shared with the ntdll
        // side that READS it (`nt_ntdll::dbg::remote_breakin_action`), so the two cannot drift.
        const PEB_BEING_DEBUGGED_OFFSET: u64 = nt_ntdll_layout::PEB_BEING_DEBUGGED_OFFSET as u64;
        if pi >= MAX_PI {
            return false;
        }
        let (filled, nfilled, scratch_base) = match self.loop_ctx {
            Some(ctx) => {
                let procs = unsafe { &*ctx.procs };
                let filled: &[u64] = if pi == self.pi {
                    let current = unsafe { &*ctx.filled_pages };
                    &current[..]
                } else {
                    let per_process = unsafe { &*ctx.pfilled };
                    &per_process[pi][..]
                };
                (filled, procs[pi].faults as usize, procs[pi].scratch_base)
            }
            // Post-loop (the self-tests) there is no loop context; the PEB page is reachable through
            // its registered permanent alias, which `client_copyout_mapped` consults first.
            None => (&[][..], 0usize, 0u64),
        };
        let written = unsafe {
            img_spawn::client_copyout_mapped(
                pi as u64,
                SMSS_PEB_VA + PEB_BEING_DEBUGGED_OFFSET,
                &[u8::from(being_debugged)],
                filled,
                nfilled,
                scratch_base,
            )
        };
        if written {
            DBGK_PEB_MARKS.fetch_add(1, Ordering::Relaxed);
        }
        written
    }

    /// Write `PEB->BeingDebugged` through for every process still attached to `object` — the
    /// detach-side half of [`Self::dbgk_mark_process_peb`], used by `NtRemoveProcessDebug`'s
    /// object-wide sibling `DbgkpCloseObject` (the debugger's last handle went away).
    pub(crate) unsafe fn dbgk_clear_peb_marks_for_object(
        &mut self,
        object: nt_process::dbgk::DebugObjectId,
    ) {
        for pi in 0..MAX_PI {
            let Some(pid) = self.pm_pid_for_pi(pi) else {
                continue;
            };
            if self.pm.process_debug_port(pid) == Some(object) {
                unsafe { self.dbgk_mark_process_peb(pi, false) };
            }
        }
    }

    /// The thread a dbgk message from the current syscall reports for: the live caller when the loop
    /// has resolved one, else the process's main thread (what `dbgk_forward_exception` falls back to).
    fn dbgk_reporting_tid(&self, pid: nt_process::ProcessId) -> nt_process::ThreadId {
        match self.current_tid {
            0 => self.pm.main_thread(pid).unwrap_or(0),
            tid => tid as nt_process::ThreadId,
        }
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
                match self.semaphore_index_for_handle(handle, required_access) {
                    Ok(index) => Ok(index),
                    // Mutants are named/openable real objects now, but the executive wait path still
                    // treats them as compatibility-immediate sync handles. Parking a mutant before
                    // the scheduler models owner handoff regresses winlogon's profile/shell startup.
                    Err(STATUS_OBJECT_TYPE_MISMATCH) => Err(STATUS_OBJECT_TYPE_MISMATCH),
                    Err(status) => Err(status),
                }
            }
            Err(status) => Err(status),
        }
    }

    fn dispatcher_object_for_thread(
        &self,
        index: usize,
        thread: u64,
    ) -> Option<nt_kernel_exec::DispatcherObject> {
        match self.obj_ns.get(index).map(|entry| entry.kind) {
            Some(2) => Some(nt_kernel_exec::DispatcherObject::Event(index as u64)),
            Some(3) => Some(nt_kernel_exec::DispatcherObject::Semaphore(index as u64)),
            Some(4) => Some(nt_kernel_exec::DispatcherObject::Mutant {
                identity: index as u64,
                thread,
            }),
            _ => None,
        }
    }

    pub(crate) fn dispatcher_ready(&self, index: usize) -> bool {
        self.dispatcher_ready_for(index, self.current_tid)
    }

    pub(crate) fn dispatcher_ready_for(&self, index: usize, thread: u64) -> bool {
        self.dispatcher_object_for_thread(index, thread)
            .is_some_and(|object| {
                nt_kernel_exec::dispatcher_ready(
                    &self.events,
                    &self.semaphores,
                    &self.mutants,
                    object,
                )
            })
    }

    pub(crate) fn dispatcher_consume(&mut self, index: usize) -> bool {
        self.dispatcher_consume_for(index, self.current_tid)
    }

    pub(crate) fn dispatcher_consume_for(&mut self, index: usize, thread: u64) -> bool {
        let Some(object) = self.dispatcher_object_for_thread(index, thread) else {
            return false;
        };
        nt_kernel_exec::consume_dispatcher(
            &mut self.events,
            &mut self.semaphores,
            &mut self.mutants,
            object,
        )
    }

    pub(crate) fn is_legacy_opaque_handle(&self, handle: u64) -> bool {
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return false;
        };
        matches!(
            self.pm.lookup_handle(pid, handle as nt_process::Handle),
            Some(nt_process::HandleObject::Opaque(tag))
                if tag == 0 || tag & MUTANT_HANDLE_TAG_MASK == MUTANT_HANDLE_TAG
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

    pub(crate) fn post_io_completion_packet(
        &mut self,
        object_id: u32,
        packet: nt_io_completion::CompletionPacket,
    ) -> u32 {
        if let Some(waiter) =
            unsafe { (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS)).pop_port(object_id) }
        {
            let wake_packet = match self
                .io_completion_ports
                .remove(object_id, nt_io_completion::RemoveMode::Poll)
            {
                Ok(nt_io_completion::RemoveResult::Packet(queued)) => {
                    if let Err(status) = self.io_completion_ports.enqueue(object_id, packet) {
                        let _ = unsafe {
                            (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS)).insert(waiter)
                        };
                        return status;
                    }
                    queued
                }
                Ok(nt_io_completion::RemoveResult::Empty(_)) => packet,
                Err(status) => {
                    let _ = unsafe {
                        (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS)).insert(waiter)
                    };
                    return status;
                }
            };
            self.io_completion_wake = Some((waiter, wake_packet));
            return nt_io_completion::STATUS_SUCCESS;
        }
        self.io_completion_ports
            .enqueue(object_id, packet)
            .map_or_else(|status| status, |_| nt_io_completion::STATUS_SUCCESS)
    }

    pub(crate) fn post_file_completion(
        &mut self,
        file_id: u64,
        apc_context: u64,
        status: u32,
        information: u64,
    ) {
        if apc_context == 0 {
            return;
        }
        if let Some(binding) = self.file_completion.binding(file_id) {
            let _ = self.post_io_completion_packet(
                binding.port_id,
                nt_io_completion::CompletionPacket {
                    key_context: binding.key_context,
                    apc_context,
                    status,
                    information,
                },
            );
        }
    }

    pub(crate) fn release_file_reference(&mut self, file_id: u64) {
        if let Ok(Some(port_id)) = self.file_completion.release_file(file_id) {
            let _ = self.io_completion_ports.release(port_id);
        }
    }
    /// ★ CROSS-VSPACE `NtCreateThread` — a genuine ADDITIONAL thread inside a FOREIGN process
    /// (`RtlCreateUserThread(ProcessHandle != NtCurrentProcess)`; `DbgUiIssueRemoteBreakin`'s
    /// break-in thread is the first real user). This is the POLICY half of `PspCreateThread`:
    ///
    /// 1. **Access check** — creating a thread in another process is a privileged capability
    ///    operation, so the `ProcessHandle` is re-resolved through `resolve_process_for_access`
    ///    demanding `PROCESS_CREATE_THREAD` (0x0002). A handle without it is `STATUS_ACCESS_DENIED`,
    ///    an unknown handle `STATUS_INVALID_HANDLE` — never an ambient side effect.
    /// 2. The target must be ALIVE with a published hosted VSpace, and not exiting.
    /// 3. The start context (`CONTEXT.Rip` = start routine, `.Rcx` = parameter) is read out of the
    ///    caller's `ThreadContext` argument — this is what makes the created thread the RIGHT
    ///    thread rather than "some thread somewhere".
    /// 4. A real ETHREAD is claimed from the **TARGET's** pool (the thread belongs to the target),
    ///    its TEB VA bound, and a TYPED `Thread(tid)` handle minted in the **CALLER's** table.
    /// 5. `*ThreadHandle` / `*ClientId {target pid, new tid}` out-params are queued.
    /// 6. The MECHANISM (the seL4 thread in the target's VSpace) is requested from the loop, which
    ///    owns the main fault endpoint the new thread is badged onto.
    pub(crate) unsafe fn create_remote_thread(&mut self, args: &[u64]) -> u32 {
        const PROCESS_CREATE_THREAD: u32 = 0x0002;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        macro_rules! reject {
            ($why:expr, $status:expr) => {{
                print_str(b"[remote-thread] reject ");
                print_str($why);
                print_str(b"\n");
                return $status;
            }};
        }
        let Some(caller_pid) = self.pm_pid_for_pi(self.pi) else {
            reject!(b"no-caller-pid", nt_process::STATUS_INVALID_HANDLE);
        };
        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[3], PROCESS_CREATE_THREAD) {
                Ok(resolved) => resolved,
                Err(status) => {
                    if status != 0xC000_0022 {
                        print_str(b"[remote-thread] reject resolve status=0x");
                        print_hex(status);
                        print_str(b"\n");
                    }
                    return status;
                }
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            reject!(
                b"target-terminating",
                nt_process::STATUS_PROCESS_IS_TERMINATING
            );
        }
        let Some(pml4) = self.hosted_process_vspace(target_pi) else {
            reject!(
                b"no-target-vspace",
                nt_process::STATUS_PROCESS_IS_TERMINATING
            );
        };
        // The caller's remaining NtCreateThread arguments live on its stack (x64: 5th..8th).
        let sp = unsafe { get_recv_mr(16) };
        let cid_ptr = unsafe { smss_stack_read(sp + 0x28) };
        let ctx_va = unsafe { smss_stack_read(sp + 0x30) };
        if ctx_va == 0 {
            reject!(b"null-thread-context", STATUS_INVALID_PARAMETER);
        }
        let start = nt_thread_start::Amd64ThreadContext::read(
            |address| unsafe { smss_stack_read(address) },
            ctx_va,
        );
        if start.rip == 0 {
            reject!(b"null-start-address", STATUS_INVALID_PARAMETER);
        }
        let create_suspended = unsafe { smss_stack_read(sp + 0x40) } != 0;
        // The bounded per-process thread windows are a shared resource with the ntdll thread-pool
        // workers — one window per extra thread of that process.
        let Some(slot) = self.first_free_hosted_tp_worker_slot(target_pi) else {
            reject!(b"no-free-thread-slot", STATUS_INSUFFICIENT_RESOURCES);
        };
        let Some((pool_slot, tid)) = self.claim_pool_thread(target_pi, start.rip, create_suspended)
        else {
            reject!(b"no-pool-ethread", STATUS_INSUFFICIENT_RESOURCES);
        };
        let thread = tid as nt_process::ThreadId;
        if !self.reserve_hosted_tp_worker_slot(target_pi, slot, tid) {
            let _ = self
                .pm
                .set_thread_state(thread, nt_process::ThreadState::Initialized);
            self.release_pool_usage_slot(target_pi, pool_slot);
            reject!(b"reserve-thread-slot", STATUS_INSUFFICIENT_RESOURCES);
        }
        let handle = match self.pm.insert_handle(
            caller_pid,
            nt_process::HandleObject::Thread(thread),
            args[1] as u32,
        ) {
            Ok(handle) => handle as u64,
            Err(status) => {
                let _ = self.release_hosted_thread_runtime(tid);
                let _ = self
                    .pm
                    .set_thread_state(thread, nt_process::ThreadState::Initialized);
                self.release_pool_usage_slot(target_pi, pool_slot);
                reject!(b"handle-insert", status);
            }
        };
        if !self.set_pool_thread_suspended(target_pi, pool_slot, create_suspended) {
            let _ = self.release_hosted_thread_runtime(tid);
            let _ = self.close_process_handle(caller_pid, handle);
            let _ = self
                .pm
                .set_thread_state(thread, nt_process::ThreadState::Initialized);
            self.release_pool_usage_slot(target_pi, pool_slot);
            reject!(b"suspend-state", STATUS_INSUFFICIENT_RESOURCES);
        }
        self.pm.set_thread_teb(thread, tp_worker_teb_va(slot));
        let _ = self
            .pm
            .set_thread_create_time(thread, nt_system_time_100ns() as i64);
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        PM_REMOTE_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
        self.queue_write(args[0], handle);
        if cid_ptr != 0 {
            self.queue_write(cid_ptr, target_pid as u64);
            self.queue_write(cid_ptr + 8, tid);
        }
        self.remote_thread_request = Some(RemoteThreadRequest {
            target_pi,
            slot,
            pml4,
            start,
            cid_proc: target_pid as u64,
            cid_thread: tid,
            resume: !create_suspended,
        });
        print_str(b"[remote-thread] cross-vspace create caller_pi=");
        print_u64(self.pi as u64);
        print_str(b" target_pi=");
        print_u64(target_pi as u64);
        print_str(b" slot=");
        print_u64(slot as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" entry=0x");
        print_hex((start.rip >> 32) as u32);
        print_hex(start.rip as u32);
        print_str(b" param=0x");
        print_hex(start.rcx as u32);
        print_str(b" suspended=");
        print_u64(create_suspended as u64);
        print_str(b"\n");
        0
    }

    /// Claim the next free pre-created pool ETHREAD belonging to hosted process `pi` and bind the
    /// caller-supplied start routine (alloc-free field writes, reset-safe — the pool exists so
    /// runtime thread creation never allocates under the per-syscall bump heap). Returns
    /// `(pool slot, tid)`, releasing the slot again on any failure. `pi` is a PARAMETER, not
    /// `self.pi`: a cross-VSpace `NtCreateThread` creates a thread that belongs to the TARGET
    /// process, so it must come out of the TARGET's pool.
    pub(crate) fn claim_pool_thread(
        &mut self,
        pi: usize,
        entry: u64,
        create_suspended: bool,
    ) -> Option<(usize, u64)> {
        let slot = self.claim_pool_usage_slot(pi)?;
        let tid = match self.pm_pool_tid_for_slot(pi, slot) {
            Some(tid) => tid as u64,
            None => {
                self.release_pool_usage_slot(pi, slot);
                return None;
            }
        };
        let t = tid as nt_process::ThreadId;
        let prepared = if self
            .pm
            .thread(t)
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        {
            self.pm
                .reuse_reclaimed_thread(t, entry, create_suspended)
                .is_ok()
        } else {
            self.pm.set_thread_start_address(t, entry)
                && if create_suspended {
                    self.pm.suspend_thread(t).is_ok()
                } else {
                    self.pm
                        .set_thread_state(t, nt_process::ThreadState::Running)
                        .is_ok()
                }
        };
        if !prepared {
            self.release_pool_usage_slot(pi, slot);
            return None;
        }
        Some((slot, tid))
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
        let (slot, tid) = match self.claim_pool_thread(self.pi, entry, create_suspended) {
            Some(claimed) => claimed,
            None => {
                // A refused runtime thread create surfaces to the caller only as
                // STATUS_INSUFFICIENT_RESOURCES (rpcrt4 prints `error=5aa` and drops the
                // connection), so NAME the reason: which pool, how full, and whether the pre-created
                // ETHREAD pool had a slot at all.
                if crate::PM_POOL_REFUSALS.fetch_add(1, Ordering::Relaxed) < 8 {
                    unsafe {
                        print_str(b"[thread-pool] REFUSED NtCreateThread pi=");
                        print_u64(self.pi as u64);
                        print_str(b" used-mask=0x");
                        print_hex(self.pool_used_mask(self.pi) as u32);
                        print_str(b" slots=");
                        print_u64(PM_RUNTIME_THREAD_SLOTS as u64);
                        print_str(b" pool-tids:");
                        for index in 0..PM_RUNTIME_THREAD_SLOTS {
                            print_str(b" ");
                            print_u64(
                                self.pm_pool_tid_for_slot(self.pi, index)
                                    .map(u64::from)
                                    .unwrap_or(0),
                            );
                        }
                        print_str(b"\n");
                    }
                }
                return None;
            }
        };
        let t = tid as nt_process::ThreadId;
        let h =
            match self
                .pm
                .insert_handle(pid, nt_process::HandleObject::Thread(t), desired_access)
            {
                Ok(handle) => handle,
                Err(_) => {
                    if create_suspended {
                        let _ = self.pm.resume_thread(t);
                    }
                    let _ = self
                        .pm
                        .set_thread_state(t, nt_process::ThreadState::Initialized);
                    self.release_pool_usage_slot(self.pi, slot);
                    return None;
                }
            };
        let _ = self
            .pm
            .set_thread_create_time(t, nt_system_time_100ns() as i64);
        if !self.set_pool_thread_suspended(self.pi, slot, create_suspended) {
            let _ = self.close_process_handle(pid, h as u64);
            let _ = self
                .pm
                .set_thread_state(t, nt_process::ThreadState::Initialized);
            self.release_pool_usage_slot(self.pi, slot);
            return None;
        }
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        PM_GENERAL_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
        Some((slot, tid, h as u64))
    }

    unsafe fn create_generic_local_tp_worker_thread(&mut self, args: &[u64]) -> Option<u32> {
        if args.len() <= 3 || args[3] != u64::MAX || self.pi >= MAX_PI {
            return None;
        }
        let pid = self.pm_pid_for_pi(self.pi)?;
        let sp = get_recv_mr(16);
        let ctx_va = smss_stack_read(sp + 0x30);
        let start =
            nt_thread_start::Amd64ThreadContext::read(|address| smss_stack_read(address), ctx_va);
        let scheduler_rva = img_spawn::OUR_TP_WORKER_RVA.load(Ordering::Relaxed);
        let completion_rva = img_spawn::OUR_TP_COMPLETION_WORKER_RVA.load(Ordering::Relaxed);
        let scheduler_entry = NTDLL_BASE.wrapping_add(scheduler_rva);
        let completion_entry = NTDLL_BASE.wrapping_add(completion_rva);

        // Native ntdll starts directly at RtlpWorkerThread. Kernel32's installed hook starts at
        // BaseThreadStartup and carries RtlpWorkerThread in RCX. Keep those stable slot preferences;
        // all other same-process creates claim the next available generic worker slot.
        let preferred_slot = if scheduler_rva != 0
            && (start.rip == scheduler_entry || start.rcx == scheduler_entry)
        {
            Some(0)
        } else if completion_rva != 0
            && (start.rip == completion_entry || start.rcx == completion_entry)
        {
            Some(1)
        } else {
            None
        };
        let tp_slot = if let Some(slot) = preferred_slot {
            self.hosted_thread_tid_for_role(self.pi, HostedThreadRole::TpWorker { slot })
                .is_none()
                .then_some(slot)
        } else {
            let lsa_extra_connection = crate::LSA_RPC_EXTRA_CONNECTION_WORKERS
                && self.current_process_is_lsass()
                && self.current_thread_has_role(HostedThreadRole::LsassListener3)
                && self
                    .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsaWorker)
                    .is_some();
            let slot = self.first_free_hosted_tp_worker_slot(self.pi);
            if lsa_extra_connection {
                if slot.is_some() {
                    crate::LSA_RPC_EXTRA_WORKERS_CLAIMED.fetch_add(1, Ordering::Relaxed);
                    print_str(
                        b"[lsa-worker] additional \\lsarpc connection: claiming a generic worker slot\n",
                    );
                } else {
                    print_str(
                        b"[lsa-worker] additional \\lsarpc connection: no free generic worker slot\n",
                    );
                }
            }
            slot
        };
        let Some(tp_slot) = tp_slot else {
            print_str(b"[tp-worker] no free local worker slot pi=");
            print_u64(self.pi as u64);
            print_str(b" pid=");
            print_u64(pid as u64);
            print_str(b" entry=0x");
            print_hex((start.rip >> 32) as u32);
            print_hex(start.rip as u32);
            print_str(b"\n");
            return Some(0xC000_009A);
        };

        let create_suspended = smss_stack_read(sp + 0x40) != 0;
        let Some((pool_slot, tid, handle)) =
            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
        else {
            return Some(0xC000_009A);
        };
        if !self.reserve_hosted_tp_worker_slot(self.pi, tp_slot, tid) {
            self.abandon_created_hosted_thread(pool_slot, tid, handle);
            return Some(0xC000_009A);
        }
        self.pm
            .set_thread_teb(tid as nt_process::ThreadId, tp_worker_teb_va(tp_slot));
        self.queue_write(args[0], handle);
        let cid_ptr = smss_stack_read(sp + 0x28);
        if cid_ptr != 0 {
            self.queue_write(cid_ptr, pid as u64);
            self.queue_write(cid_ptr + 8, tid);
        }
        self.thread_spawn_request = Some(HostedThreadSpawnRequest::TpWorker {
            pi: self.pi,
            slot: tp_slot,
        });
        print_str(b"[tp-worker] claimed pi=");
        print_u64(self.pi as u64);
        print_str(b" badge=");
        print_u64(tp_worker_badge(self.pi, tp_slot));
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" entry=0x");
        print_hex((start.rip >> 32) as u32);
        print_hex(start.rip as u32);
        print_str(b" suspended=");
        print_u64(create_suspended as u64);
        if tp_slot != 0 {
            print_str(b" slot=");
            print_u64(tp_slot as u64);
        }
        print_str(b"\n");
        Some(0)
    }

    /// Bind a hosted process's MAIN THREAD to its real image entry at the actual seL4 spawn — the
    /// "route NtCreateThread through pm at real spawn time" step (the thread object was pre-created
    /// at boot for the non-leaking heap solution; this alloc-free field write completes it).
    pub(crate) fn bind_main_thread_entry(&mut self, pi: usize, entry: u64) {
        if let Some(tid) = self.pm_main_tid_for_pi(pi) {
            if self.pm.set_thread_start_address(tid, entry) {
                let _ = self.pm.set_thread_teb(tid, SMSS_TEB_VA);
                let _ = self
                    .pm
                    .set_thread_create_time(tid, nt_system_time_100ns() as i64);
                PM_THREAD_BINDS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    /// Apply native `NtOpenProcess` selector and access policy after the caller structures have
    /// been captured from its address space. Publication of the returned handle remains the
    /// caller's responsibility so copyout can be transactional.
    pub(crate) fn open_process_captured(
        &mut self,
        object_attributes: nt_ntdll_layout::ObjectAttributes,
        client_id: Option<nt_ntdll_layout::ClientId>,
        desired_access: u32,
    ) -> Result<(nt_process::ProcessId, nt_process::Handle), u32> {
        const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        let has_name = object_attributes.object_name != 0;
        if has_name && client_id.is_some() || !has_name && client_id.is_none() {
            return Err(STATUS_INVALID_PARAMETER_MIX);
        }
        if has_name {
            // EPROCESS objects are not yet registered in the object-manager namespace.
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let client_id = client_id.unwrap();
        let client_id = nt_process::process_client_id_from_native(
            client_id.unique_process,
            client_id.unique_thread,
        )?;
        let caller_pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let handle = self.pm.open_process_by_client_id(
            caller_pid,
            client_id,
            nt_process::map_process_access(desired_access),
        )?;
        Ok((caller_pid, handle))
    }

    pub(crate) fn account_published_pm_handle(&self, owner: nt_process::ProcessId) {
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        let count = self.pm.handle_count(owner) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
    }

    unsafe fn capture_object_attributes(
        &self,
        address: u64,
    ) -> Option<nt_ntdll_layout::ObjectAttributes> {
        let mut value = core::mem::MaybeUninit::<nt_ntdll_layout::ObjectAttributes>::uninit();
        let bytes = core::slice::from_raw_parts_mut(
            value.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<nt_ntdll_layout::ObjectAttributes>(),
        );
        self.xas_read(address, bytes).then(|| value.assume_init())
    }

    unsafe fn capture_client_id(&self, address: u64) -> Option<nt_ntdll_layout::ClientId> {
        let mut value = core::mem::MaybeUninit::<nt_ntdll_layout::ClientId>::uninit();
        let bytes = core::slice::from_raw_parts_mut(
            value.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<nt_ntdll_layout::ClientId>(),
        );
        self.xas_read(address, bytes).then(|| value.assume_init())
    }

    unsafe fn nt_open_process(
        &mut self,
        process_handle: u64,
        desired_access: u32,
        object_attributes: u64,
        client_id: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        if !self.probe_user_output(process_handle, core::mem::size_of::<u64>()) {
            return STATUS_ACCESS_VIOLATION;
        }
        let client_id = if client_id == 0 {
            None
        } else {
            if client_id & 3 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            let Some(client_id) = self.capture_client_id(client_id) else {
                return STATUS_ACCESS_VIOLATION;
            };
            Some(client_id)
        };
        if object_attributes & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let Some(object_attributes) = self.capture_object_attributes(object_attributes) else {
            return STATUS_ACCESS_VIOLATION;
        };
        let (owner, handle) =
            match self.open_process_captured(object_attributes, client_id, desired_access) {
                Ok(opened) => opened,
                Err(status) => return status,
            };
        if !self.xas_write_u64(process_handle, handle as u64) {
            let _ = self.pm.take_handle(owner, handle);
            return STATUS_ACCESS_VIOLATION;
        }
        self.account_published_pm_handle(owner);
        0
    }

    /// Apply native `NtOpenThread` selector and access policy after capturing the caller inputs.
    pub(crate) fn open_thread_captured(
        &mut self,
        object_attributes: nt_ntdll_layout::ObjectAttributes,
        client_id: Option<nt_ntdll_layout::ClientId>,
        desired_access: u32,
    ) -> Result<(nt_process::ProcessId, nt_process::Handle), u32> {
        const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        let has_name = object_attributes.object_name != 0;
        if has_name && client_id.is_some() || !has_name && client_id.is_none() {
            return Err(STATUS_INVALID_PARAMETER_MIX);
        }
        if has_name {
            // ETHREAD objects are not yet registered in the object-manager namespace.
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let client_id = client_id.unwrap();
        let client_id = nt_process::thread_client_id_from_native(
            client_id.unique_process,
            client_id.unique_thread,
        )?;
        let caller_pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let handle = self.pm.open_thread_by_client_id(
            caller_pid,
            client_id,
            nt_process::map_thread_access(desired_access),
        )?;
        Ok((caller_pid, handle))
    }

    unsafe fn nt_open_thread(
        &mut self,
        thread_handle: u64,
        desired_access: u32,
        object_attributes: u64,
        client_id: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        if !self.probe_user_output(thread_handle, core::mem::size_of::<u64>()) {
            return STATUS_ACCESS_VIOLATION;
        }
        let client_id = if client_id == 0 {
            None
        } else {
            if client_id & 3 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            let Some(client_id) = self.capture_client_id(client_id) else {
                return STATUS_ACCESS_VIOLATION;
            };
            Some(client_id)
        };
        if object_attributes & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let Some(object_attributes) = self.capture_object_attributes(object_attributes) else {
            return STATUS_ACCESS_VIOLATION;
        };
        let (owner, handle) =
            match self.open_thread_captured(object_attributes, client_id, desired_access) {
                Ok(opened) => opened,
                Err(status) => return status,
            };
        if !self.xas_write_u64(thread_handle, handle as u64) {
            let _ = self.pm.take_handle(owner, handle);
            return STATUS_ACCESS_VIOLATION;
        }
        self.account_published_pm_handle(owner);
        0
    }

    pub(crate) fn thread_query_length(information_class: u32) -> Result<usize, u32> {
        match information_class {
            0 => Ok(0x30),
            1 => Ok(0x20),
            9 | 11 => Ok(8),
            12 | 14 | 16 | 18 | 20 => Ok(4),
            17 => Ok(1),
            _ => Err(nt_process::STATUS_INVALID_INFO_CLASS),
        }
    }

    pub(crate) fn thread_set_length(information_class: u32) -> Result<usize, u32> {
        match information_class {
            9 | 14 => Ok(8),
            17 => Ok(0),
            18 => Ok(4),
            38 => Ok(0x10),
            _ => Err(nt_process::STATUS_INVALID_INFO_CLASS),
        }
    }

    pub(crate) fn set_thread_information_captured(
        &mut self,
        handle: u64,
        information_class: u32,
        value: u64,
    ) -> u32 {
        if information_class == 18 && !self.current_token_has_privilege(nt_security::SE_DEBUG) {
            return 0xC000_0061;
        }
        const THREAD_SET_INFORMATION: u32 = 0x0020;
        let caller = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let tid = match self.pm.resolve_thread_handle(
            caller,
            self.current_tid as nt_process::ThreadId,
            handle,
            THREAD_SET_INFORMATION,
        ) {
            Ok(tid) => tid,
            Err(status) => return status,
        };
        let update = match information_class {
            9 => self.pm.set_thread_win32_start_address(tid, value),
            14 => self.pm.set_thread_disable_boost(tid, value != 0),
            17 => self.pm.set_thread_hide_from_debugger(tid),
            18 => self
                .pm
                .set_thread_break_on_termination(tid, value as u32 != 0),
            _ => return nt_process::STATUS_INVALID_INFO_CLASS,
        };
        update.map_or_else(|status| status, |()| 0)
    }

    pub(crate) fn resolve_thread_for_set(&self, handle: u64) -> Result<nt_process::ThreadId, u32> {
        const THREAD_SET_INFORMATION: u32 = 0x0020;
        let caller = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.pm.resolve_thread_handle(
            caller,
            self.current_tid as nt_process::ThreadId,
            handle,
            THREAD_SET_INFORMATION,
        )
    }

    pub(crate) fn set_thread_name_resolved(
        &mut self,
        tid: nt_process::ThreadId,
        name: &[u16],
    ) -> u32 {
        self.pm
            .set_thread_name(tid, name)
            .map_or_else(|status| status, |()| 0)
    }

    unsafe fn nt_set_thread_name(
        &mut self,
        handle: u64,
        information: u64,
        information_length: u32,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        if information_length != 0x10 {
            return nt_process::STATUS_INFO_LENGTH_MISMATCH;
        }
        if information & 7 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let mut descriptor = [0u8; 0x10];
        if information == 0 || !self.xas_read(information, &mut descriptor) {
            return STATUS_ACCESS_VIOLATION;
        }
        let raw_byte_length = u16::from_le_bytes(descriptor[0..2].try_into().unwrap()) as usize;
        let byte_length = raw_byte_length & !1;
        let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());

        let tid = match self.resolve_thread_for_set(handle) {
            Ok(tid) => tid,
            Err(status) => return status,
        };
        if buffer == 0 {
            return self
                .pm
                .set_thread_name(tid, &[])
                .map_or_else(|status| status, |()| 0);
        }
        if raw_byte_length != 0 && buffer & 1 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !self.probe_user_input(buffer, raw_byte_length) {
            return STATUS_ACCESS_VIOLATION;
        }
        if byte_length == 0 {
            return self
                .pm
                .set_thread_name(tid, &[])
                .map_or_else(|status| status, |()| 0);
        }
        if byte_length > nt_process::THREAD_NAME_MAX_UNITS * 2 {
            return 0xC000_009A;
        }
        let mut bytes = [0u8; nt_process::THREAD_NAME_MAX_UNITS * 2];
        if !self.xas_read(buffer, &mut bytes[..byte_length]) {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
        for (index, chunk) in bytes[..byte_length].chunks_exact(2).enumerate() {
            name[index] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        self.pm
            .set_thread_name(tid, &name[..byte_length / 2])
            .map_or_else(|status| status, |()| 0)
    }

    pub(crate) fn query_thread_information_captured(
        &self,
        handle: u64,
        information_class: u32,
    ) -> Result<([u8; 0x30], usize), u32> {
        let caller_pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let current_tid = self.current_tid as nt_process::ThreadId;
        let mut output = [0u8; 0x30];
        let length = match information_class {
            0 => {
                let basic = self
                    .pm
                    .query_thread_basic(caller_pid, current_tid, handle)?;
                let teb = if basic.teb_base_address != 0 {
                    basic.teb_base_address
                } else if self.current_process_is_smss() {
                    SMSS_TEB_VA
                } else {
                    TEB_VA
                };
                output[0..4].copy_from_slice(&basic.exit_status.to_le_bytes());
                output[8..16].copy_from_slice(&teb.to_le_bytes());
                output[0x10..0x18]
                    .copy_from_slice(&(basic.client_id.unique_process as u64).to_le_bytes());
                output[0x18..0x20]
                    .copy_from_slice(&(basic.client_id.unique_thread as u64).to_le_bytes());
                output[0x20..0x28].copy_from_slice(&basic.affinity_mask.to_le_bytes());
                output[0x28..0x2C].copy_from_slice(&basic.priority.to_le_bytes());
                output[0x2C..0x30].copy_from_slice(&basic.base_priority.to_le_bytes());
                0x30
            }
            1 => {
                let times = self
                    .pm
                    .query_thread_times(caller_pid, current_tid, handle)?;
                for (index, value) in [
                    times.create_time,
                    times.exit_time,
                    times.kernel_time,
                    times.user_time,
                ]
                .iter()
                .enumerate()
                {
                    output[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
                }
                0x20
            }
            9 | 11 => {
                let start_address =
                    self.pm
                        .thread_start_address(caller_pid, current_tid, handle)?;
                let value = if information_class == 9 {
                    start_address
                } else {
                    0
                };
                output[..8].copy_from_slice(&value.to_le_bytes());
                8
            }
            12 | 14 | 18 | 20 => {
                let value =
                    self.pm
                        .query_thread_u32(caller_pid, current_tid, handle, information_class)?;
                output[..4].copy_from_slice(&value.to_le_bytes());
                4
            }
            16 => {
                const THREAD_QUERY_INFORMATION: u32 = 0x0040;
                let tid = self.pm.resolve_thread_handle(
                    caller_pid,
                    current_tid,
                    handle,
                    THREAD_QUERY_INFORMATION,
                )?;
                let pending = unsafe {
                    (&*core::ptr::addr_of!(PIPE_WAITERS)).has_thread(tid as u64)
                        || (&*core::ptr::addr_of!(PIPE_ASYNC_LISTENS)).has_thread(tid as u64)
                };
                output[..4].copy_from_slice(&(pending as u32).to_le_bytes());
                4
            }
            17 => {
                let value =
                    self.pm
                        .query_thread_u32(caller_pid, current_tid, handle, information_class)?;
                output[0] = value as u8;
                1
            }
            _ => return Err(nt_process::STATUS_INVALID_INFO_CLASS),
        };
        Ok((output, length))
    }

    pub(crate) fn query_thread_name_captured(
        &self,
        handle: u64,
        name: &mut [u16; nt_process::THREAD_NAME_MAX_UNITS],
    ) -> Result<usize, u32> {
        let caller_pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.pm.query_thread_name(
            caller_pid,
            self.current_tid as nt_process::ThreadId,
            handle,
            name,
        )
    }

    unsafe fn nt_query_thread_name(
        &self,
        handle: u64,
        information: u64,
        information_length: u32,
        return_length: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
        if information != 0 {
            if information & 7 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if !self.probe_user_output(information, information_length as usize) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if return_length != 0 && !self.probe_user_output(return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
        let mut required = 0u32;
        let mut status = match self.query_thread_name_captured(handle, &mut name) {
            Ok(units) => {
                required = (0x10 + units * 2) as u32;
                if information_length < required {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    let mut output = [0u8; 0x10 + nt_process::THREAD_NAME_MAX_UNITS * 2];
                    if units != 0 {
                        let byte_length = (units * 2) as u16;
                        output[0..2].copy_from_slice(&byte_length.to_le_bytes());
                        output[2..4].copy_from_slice(&byte_length.to_le_bytes());
                        output[8..16]
                            .copy_from_slice(&information.wrapping_add(0x10).to_le_bytes());
                        for (index, unit) in name[..units].iter().enumerate() {
                            output[0x10 + index * 2..0x12 + index * 2]
                                .copy_from_slice(&unit.to_le_bytes());
                        }
                    }
                    if self.xas_try_write_buf(information, &output[..required as usize]) {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                }
            }
            Err(status) => status,
        };
        if return_length != 0 && !self.xas_write_u32(return_length, required) {
            status = STATUS_ACCESS_VIOLATION;
        }
        status
    }

    unsafe fn nt_query_information_thread(
        &self,
        handle: u64,
        information_class: u32,
        information: u64,
        information_length: u32,
        return_length: u64,
    ) -> u32 {
        if information_class == 38 {
            return self.nt_query_thread_name(
                handle,
                information,
                information_length,
                return_length,
            );
        }
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        let expected = match Self::thread_query_length(information_class) {
            Ok(length) => length,
            Err(status) => return status,
        };
        if information_length as usize != expected {
            return nt_process::STATUS_INFO_LENGTH_MISMATCH;
        }
        if information != 0 {
            if information & 3 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            let mut probe = [0u8; 0x30];
            if !self.xas_read(information, &mut probe[..expected]) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if return_length != 0 && !self.probe_user_output(return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut status = match self.query_thread_information_captured(handle, information_class) {
            Ok((output, length)) => {
                if self.xas_try_write_buf(information, &output[..length]) {
                    if information_class == 0 {
                        WL_LISTENER_TEB_QUERIED.fetch_add(1, Ordering::Relaxed);
                    }
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
            Err(status) => status,
        };
        if return_length != 0 && !self.xas_write_u32(return_length, expected as u32) {
            status = STATUS_ACCESS_VIOLATION;
        }
        status
    }

    fn process_query_length(information_class: u32, information_length: u32) -> Result<usize, u32> {
        let exact = |expected: usize| {
            if information_length as usize == expected {
                Ok(expected)
            } else {
                Err(nt_process::STATUS_INFO_LENGTH_MISMATCH)
            }
        };
        match information_class {
            0 => exact(0x30), // PROCESS_BASIC_INFORMATION
            1 => match information_length {
                // QUOTA_LIMITS / QUOTA_LIMITS_EX
                0x30 | 0x58 => Ok(information_length as usize),
                _ => Err(nt_process::STATUS_INFO_LENGTH_MISMATCH),
            },
            2 => exact(0x30), // IO_COUNTERS
            3 => match information_length {
                // VM_COUNTERS / VM_COUNTERS_EX
                0x58 | 0x60 => Ok(information_length as usize),
                _ => Err(nt_process::STATUS_INFO_LENGTH_MISMATCH),
            },
            4 => exact(0x20),  // KERNEL_USER_TIMES
            7 => exact(0x08),  // ProcessDebugPort
            12 => exact(0x04), // ProcessDefaultHardErrorMode
            18 => exact(0x02), // PROCESS_PRIORITY_CLASS
            20 => exact(0x04), // ProcessHandleCount
            23 => exact(0x24), // PROCESS_DEVICEMAP_INFORMATION
            24 => exact(0x04), // PROCESS_SESSION_INFORMATION
            26 => exact(0x08), // ProcessWow64Information
            28 => exact(0x04), // ProcessLUIDDeviceMapsEnabled
            29 => exact(0x04), // ProcessBreakOnTermination
            30 => exact(0x08), // ProcessDebugObjectHandle
            31 => exact(0x04), // ProcessDebugFlags
            33 => exact(0x04), // ProcessIoPriority
            34 => exact(0x04), // ProcessExecuteFlags
            36 => exact(0x04), // ProcessCookie
            37 => exact(0x40), // SECTION_IMAGE_INFORMATION
            38 => exact(0x08), // ProcessCycleTime
            39 => exact(0x04), // ProcessPagePriority
            _ => Err(nt_process::STATUS_INVALID_INFO_CLASS),
        }
    }

    fn process_virtual_footprint(&self, pid: nt_process::ProcessId) -> u64 {
        if self.pm_pid_for_pi(self.pi) == Some(pid) {
            if let Some(ctx) = self.loop_ctx {
                return ctx.img_end.saturating_sub(PE_LOAD_BASE).max(0x1000);
            }
        }
        let section = self
            .pm
            .process(pid)
            .and_then(|process| process.image_section)
            .and_then(|section| self.pm.image_section(section));
        section
            .map(|section| section.size_of_image() as u64)
            .unwrap_or(0x1000)
            .max(0x1000)
    }

    unsafe fn current_process_image_information(&self) -> Option<[u8; 0x40]> {
        let ctx = self.loop_ctx?;
        if ctx.pe.is_null() {
            return None;
        }
        let pe = &*ctx.pe;
        let metadata = image_metadata_from_pe(pe, PE_LOAD_BASE);
        let mut info = nt_dll_registry::image_info(
            PE_LOAD_BASE,
            metadata.entry_rva,
            metadata.image_size as u32,
            false,
        );
        info[0x20..0x24].copy_from_slice(&(metadata.subsystem as u32).to_le_bytes());
        info[0x24..0x26].copy_from_slice(&metadata.subsystem_minor.to_le_bytes());
        info[0x26..0x28].copy_from_slice(&metadata.subsystem_major.to_le_bytes());
        Some(info)
    }

    fn process_image_name_units(
        &self,
        pid: nt_process::ProcessId,
        win32_path: bool,
        out: &mut [u16],
    ) -> usize {
        let Some(process) = self.pm.process(pid) else {
            return 0;
        };
        let hosted = self
            .pi_for_pid(pid)
            .and_then(|pi| self.hosted_process_image(pi));
        let system32 = hosted
            .map(|image| image.image_root == nt_exe_image::HostedImageRoot::System32)
            .unwrap_or(true);
        let prefix = if win32_path {
            if system32 {
                b"C:\\ReactOS\\System32\\" as &[u8]
            } else {
                b"C:\\ReactOS\\"
            }
        } else if system32 {
            b"\\Device\\Harddisk0\\Partition1\\reactos\\system32\\" as &[u8]
        } else {
            b"\\Device\\Harddisk0\\Partition1\\reactos\\" as &[u8]
        };
        let mut n = 0usize;
        for &byte in prefix.iter().chain(process.image_file_name.as_bytes()) {
            if n == out.len() {
                break;
            }
            out[n] = byte as u16;
            n += 1;
        }
        n
    }

    unsafe fn nt_query_process_image_name(
        &self,
        handle: u64,
        information_class: u32,
        information: u64,
        information_length: u32,
        return_length: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        const UNICODE_STRING_SIZE: usize = 0x10;
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let pid = match self.pm.resolve_process_handle(
            caller_pid,
            handle,
            nt_process::PROCESS_QUERY_INFORMATION,
        ) {
            Ok(pid) => pid,
            Err(status) => return status,
        };
        let mut units = [0u16; 300];
        let units_len = self.process_image_name_units(pid, information_class == 43, &mut units);
        let byte_len = (units_len * 2) as u16;
        let max_len = byte_len.saturating_add(2);
        let required = UNICODE_STRING_SIZE + max_len as usize;
        if return_length != 0 && !self.probe_user_output(return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }
        if (information_length as usize) < required {
            if return_length != 0 {
                let _ = self.xas_write_u32(return_length, required as u32);
            }
            return nt_process::STATUS_INFO_LENGTH_MISMATCH;
        }
        if information == 0 || information & 1 != 0 {
            return if information & 1 != 0 {
                STATUS_DATATYPE_MISALIGNMENT
            } else {
                STATUS_ACCESS_VIOLATION
            };
        }
        if !self.probe_user_output(information, required) {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut output = [0u8; UNICODE_STRING_SIZE + 300 * 2 + 2];
        output[0..2].copy_from_slice(&byte_len.to_le_bytes());
        output[2..4].copy_from_slice(&max_len.to_le_bytes());
        output[8..16].copy_from_slice(&information.wrapping_add(0x10).to_le_bytes());
        for (index, unit) in units[..units_len].iter().enumerate() {
            let off = UNICODE_STRING_SIZE + index * 2;
            output[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let mut status = if self.xas_try_write_buf(information, &output[..required]) {
            0
        } else {
            STATUS_ACCESS_VIOLATION
        };
        if return_length != 0 && !self.xas_write_u32(return_length, required as u32) {
            status = STATUS_ACCESS_VIOLATION;
        }
        status
    }

    unsafe fn query_process_information_captured(
        &mut self,
        handle: u64,
        information_class: u32,
        information_length: usize,
    ) -> Result<([u8; 0x60], usize, Option<nt_process::Handle>), u32> {
        let caller_pid = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let mut output = [0u8; 0x60];
        let mut published_handle = None;
        fn put_u32(output: &mut [u8], off: usize, value: u32) {
            output[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put_i32(output: &mut [u8], off: usize, value: i32) {
            output[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put_u64(output: &mut [u8], off: usize, value: u64) {
            output[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }
        fn put_i64(output: &mut [u8], off: usize, value: i64) {
            output[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        let length = match information_class {
            0 => {
                let basic = self.pm.query_process_basic(caller_pid, handle)?;
                put_u32(&mut output, 0, basic.exit_status);
                put_u64(&mut output, 8, basic.peb_base_address);
                put_u64(&mut output, 0x10, basic.affinity_mask);
                put_i32(&mut output, 0x18, basic.base_priority);
                put_u64(&mut output, 0x20, basic.unique_process_id as u64);
                put_u64(
                    &mut output,
                    0x28,
                    basic.inherited_from_unique_process_id as u64,
                );
                0x30
            }
            1 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u64(&mut output, 0x10, 204_800);
                put_u64(&mut output, 0x18, 1_413_120);
                put_u64(&mut output, 0x20, u64::MAX);
                put_u64(&mut output, 0x28, u64::MAX);
                if information_length == 0x58 {
                    put_u64(&mut output, 0x30, 0);
                    put_u64(&mut output, 0x38, 0);
                    put_u64(&mut output, 0x40, 0);
                    put_u64(&mut output, 0x48, 0);
                    put_u32(&mut output, 0x50, 0);
                    put_u32(&mut output, 0x54, 0);
                }
                information_length
            }
            2 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                0x30
            }
            3 => {
                let pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                let virtual_size = self.process_virtual_footprint(pid);
                let working_set = virtual_size.max(0x4000);
                put_u64(&mut output, 0x00, virtual_size);
                put_u64(&mut output, 0x08, virtual_size);
                put_u32(&mut output, 0x10, 0);
                put_u64(&mut output, 0x18, working_set);
                put_u64(&mut output, 0x20, working_set);
                put_u64(&mut output, 0x48, virtual_size);
                put_u64(&mut output, 0x50, virtual_size);
                if information_length == 0x60 {
                    put_u64(&mut output, 0x58, virtual_size);
                }
                information_length
            }
            4 => {
                let times = self.pm.query_process_times(caller_pid, handle)?;
                put_i64(&mut output, 0x00, times.create_time);
                put_i64(&mut output, 0x08, times.exit_time);
                put_i64(&mut output, 0x10, times.kernel_time);
                put_i64(&mut output, 0x18, times.user_time);
                0x20
            }
            7 => {
                let value = self.pm.query_process_debug_port(caller_pid, handle)?;
                put_u64(&mut output, 0, value);
                0x08
            }
            12 => {
                let pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                let mode = self
                    .pm
                    .process_default_hard_error_processing(pid)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
                put_u32(&mut output, 0, mode);
                0x04
            }
            18 => {
                let priority = self.pm.query_process_priority_class(caller_pid, handle)?;
                output[0] = 0;
                output[1] = priority;
                0x02
            }
            20 => {
                put_u32(
                    &mut output,
                    0,
                    self.pm.query_process_handle_count(caller_pid, handle)?,
                );
                0x04
            }
            23 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                0x24
            }
            24 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u32(&mut output, 0, 0);
                0x04
            }
            26 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u64(&mut output, 0, 0);
                0x08
            }
            28 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u32(&mut output, 0, 0);
                0x04
            }
            29 => {
                let pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                let enabled = self
                    .pm
                    .process_break_on_termination(pid)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)? as u32;
                put_u32(&mut output, 0, enabled);
                0x04
            }
            30 => {
                let pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                let Some(object) = self.pm.process_debug_port(pid) else {
                    return Err(nt_process::dbgk::STATUS_PORT_NOT_SET);
                };
                let debug_handle = self.pm.insert_handle(
                    caller_pid,
                    nt_process::HandleObject::DebugObject(object),
                    nt_process::dbgk::DEBUG_OBJECT_ALL_ACCESS,
                )?;
                self.account_published_pm_handle(caller_pid);
                published_handle = Some(debug_handle);
                put_u64(&mut output, 0, debug_handle as u64);
                0x08
            }
            31 => {
                put_u32(
                    &mut output,
                    0,
                    self.pm.query_process_debug_flags(caller_pid, handle)?,
                );
                0x04
            }
            33 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u32(&mut output, 0, 2);
                0x04
            }
            34 => {
                if handle != u64::MAX {
                    return Err(nt_process::STATUS_INVALID_PARAMETER);
                }
                put_u32(&mut output, 0, 0);
                0x04
            }
            36 => {
                if handle != u64::MAX {
                    return Err(nt_process::STATUS_INVALID_PARAMETER);
                }
                let time = nt_system_time_100ns();
                let mut candidate = time as u32
                    ^ (time >> 32) as u32
                    ^ caller_pid
                    ^ self.current_tid as u32
                    ^ (self.pi as u32).wrapping_mul(0x9E37_79B9);
                if candidate == 0 {
                    candidate = 0xBB40_E64E;
                }
                let cookie = self
                    .pm
                    .get_or_initialize_process_cookie(caller_pid, candidate)
                    .ok_or(0xC000_009Au32)?;
                put_u32(&mut output, 0, cookie);
                0x04
            }
            37 => {
                if handle != u64::MAX {
                    return Err(nt_process::STATUS_INVALID_PARAMETER);
                }
                let Some(info) = self.current_process_image_information() else {
                    return Err(nt_process::STATUS_INVALID_HANDLE);
                };
                output[..0x40].copy_from_slice(&info);
                0x40
            }
            38 => {
                let times = self.pm.query_process_times(caller_pid, handle)?;
                put_u64(
                    &mut output,
                    0,
                    times.kernel_time.saturating_add(times.user_time) as u64,
                );
                0x08
            }
            39 => {
                let _pid = self.pm.resolve_process_handle(
                    caller_pid,
                    handle,
                    nt_process::PROCESS_QUERY_INFORMATION,
                )?;
                put_u32(&mut output, 0, 5);
                0x04
            }
            _ => return Err(nt_process::STATUS_INVALID_INFO_CLASS),
        };
        Ok((output, length, published_handle))
    }

    unsafe fn nt_query_information_process(
        &mut self,
        handle: u64,
        information_class: u32,
        information: u64,
        information_length: u32,
        return_length: u64,
    ) -> u32 {
        if information_class == 27 || information_class == 43 {
            return self.nt_query_process_image_name(
                handle,
                information_class,
                information,
                information_length,
                return_length,
            );
        }
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
        let expected = match Self::process_query_length(information_class, information_length) {
            Ok(length) => length,
            Err(status) => return status,
        };
        if information == 0 {
            return STATUS_ACCESS_VIOLATION;
        }
        if information & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !self.probe_user_output(information, expected) {
            return STATUS_ACCESS_VIOLATION;
        }
        if return_length != 0 && !self.probe_user_output(return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut status =
            match self.query_process_information_captured(handle, information_class, expected) {
                Ok((output, length, published_handle)) => {
                    if self.xas_try_write_buf(information, &output[..length]) {
                        0
                    } else {
                        if let Some(handle) = published_handle {
                            if let Some(caller_pid) = self.pm_pid_for_pi(self.pi) {
                                let _ = self.close_process_handle(caller_pid, handle as u64);
                            }
                        }
                        STATUS_ACCESS_VIOLATION
                    }
                }
                Err(status) => status,
            };
        if return_length != 0 && !self.xas_write_u32(return_length, expected as u32) {
            status = STATUS_ACCESS_VIOLATION;
        }
        status
    }
    /// Resolve a `NtTerminateProcess`/`NtOpenProcess`-style ProcessHandle to the target EPROCESS pid.
    /// `NtCurrentProcess()` (`-1`) → the caller (self-terminate). A real child ProcessHandle is now
    /// resolved via path 1b's value→object index: process handles are dense typed `Process(pid)`
    /// entries in the CALLER's EPROCESS handle table, so `lookup_handle(caller, handle)` returns the
    /// target pid. Returns `None` for an unknown/untyped handle; each syscall maps that to its native
    /// error/fallback behavior.
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
        self.process_mechanisms
            .pi_for_pid(pid)
            .or_else(|| self.temporary_pi_for_pid(pid))
    }

    pub(crate) fn resolve_process_for_access(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<(nt_process::ProcessId, usize), u32> {
        let caller = self
            .pm_pid_for_pi(self.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let pid = self
            .pm
            .resolve_process_handle(caller, handle, required_access)?;
        let pi = self
            .pi_for_pid(pid)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        Ok((pid, pi))
    }

    unsafe fn user_memory_read(&self, memory: SyscallUserMemory, va: u64, dst: &mut [u8]) -> bool {
        match memory {
            SyscallUserMemory::CurrentProcess => self.xas_read(va, dst),
            SyscallUserMemory::CsrThreadStack { sb } => csr_thread_stack_copyin(sb, va, dst),
        }
    }

    unsafe fn user_memory_write(&self, memory: SyscallUserMemory, va: u64, src: &[u8]) -> bool {
        match memory {
            SyscallUserMemory::CurrentProcess => self.xas_try_write_buf(va, src),
            SyscallUserMemory::CsrThreadStack { sb } => csr_thread_stack_copyout(sb, va, src),
        }
    }

    unsafe fn user_memory_probe_output(
        &self,
        memory: SyscallUserMemory,
        va: u64,
        len: usize,
    ) -> bool {
        match memory {
            SyscallUserMemory::CurrentProcess => self.probe_user_output(va, len),
            SyscallUserMemory::CsrThreadStack { sb } => csr_thread_stack_has_range(sb, va, len),
        }
    }

    pub(crate) unsafe fn nt_resume_thread_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const THREAD_SUSPEND_RESUME: u32 = 0x0002;
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

        let thread_handle = args[0];
        let previous_count = args[1];
        print_str(b"[thread-life] NtResumeThread pi=");
        print_u64(self.pi as u64);
        print_str(b" handle=0x");
        print_hex(thread_handle as u32);
        print_str(b" previous_ptr=0x");
        print_hex((previous_count >> 32) as u32);
        print_hex(previous_count as u32);
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
            thread_handle,
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
        let Some(mechanism) = self.hosted_thread_mechanism_for_tid(tid) else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        let (pi, slot) = match mechanism.kind {
            nt_user_host::ThreadMechanismKind::Main => {
                let main_pi = mechanism.pi;
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
                if previous_count != 0
                    && !self.user_memory_write(memory, previous_count, &previous.to_le_bytes())
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                if previous == 1 {
                    let tcb = self.hosted_main_thread_tcb_for_pi(main_pi).unwrap_or(0);
                    if tcb <= 1 || tcb_resume(tcb) != 0 {
                        return STATUS_UNSUCCESSFUL;
                    }
                }
                return 0;
            }
            nt_user_host::ThreadMechanismKind::Pool { slot } => (mechanism.pi, slot),
        };

        if self.hosted_thread_role(tid) == Some(HostedThreadRole::ScmWorker) {
            let _ = self.take_pool_thread_suspended(pi, slot);
            if previous_count != 0
                && !self.user_memory_write(memory, previous_count, &1u32.to_le_bytes())
            {
                return STATUS_ACCESS_VIOLATION;
            }
            print_str(b"[scm-worker] NtResumeThread -> SUCCESS (not resumed; trampoline-entry fault, see frontier)\n");
            return 0;
        }

        let Some(previous) = self.take_pool_thread_suspended(pi, slot) else {
            return nt_process::STATUS_INVALID_PARAMETER;
        };
        if previous_count != 0
            && !self.user_memory_write(memory, previous_count, &(previous as u32).to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if previous != 0 {
            let _ = self
                .pm
                .set_thread_state(tid as nt_process::ThreadId, nt_process::ThreadState::Ready);
            let csr_role = match self.hosted_thread_role(tid) {
                Some(HostedThreadRole::CsrApi) => 1,
                Some(HostedThreadRole::CsrSbApi) => 2,
                _ => 0,
            };
            if csr_role != 0 {
                self.csr_start_request = csr_role;
                print_str(b"[csr-thread] resume scheduled role=");
                print_u64(csr_role as u64);
                print_str(b" tid=");
                print_u64(tid);
                print_str(b" previous=1\n");
                return 0;
            }
            let tcb = self
                .hosted_thread_tcb_for_nt_resume_thread(tid)
                .unwrap_or(0);
            if tcb <= 1 {
                return STATUS_UNSUCCESSFUL;
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
                return STATUS_UNSUCCESSFUL;
            }
        }
        0
    }

    fn query_object_type_name(
        &self,
        object: nt_process::HandleObject,
        namespace_kind: Option<u8>,
    ) -> &'static [u8] {
        match namespace_kind {
            Some(0) => b"Directory",
            Some(1) => b"SymbolicLink",
            Some(2) => b"Event",
            Some(3) => b"Semaphore",
            Some(4) => b"Mutant",
            _ => match object {
                nt_process::HandleObject::Process(_) => b"Process",
                nt_process::HandleObject::Thread(_) => b"Thread",
                nt_process::HandleObject::Section(_) => b"Section",
                nt_process::HandleObject::File(_)
                | nt_process::HandleObject::DiskFile { .. }
                | nt_process::HandleObject::Directory { .. }
                | nt_process::HandleObject::OverlayFile(_)
                | nt_process::HandleObject::BootStatusFile => b"File",
                nt_process::HandleObject::IoCompletion(_) => b"IoCompletion",
                nt_process::HandleObject::RegistryKey(_) => b"Key",
                nt_process::HandleObject::Token(_) | nt_process::HandleObject::TokenObject(_) => {
                    b"Token"
                }
                nt_process::HandleObject::DebugObject(_) => b"DebugObject",
                nt_process::HandleObject::Opaque(tag)
                    if tag & EVENT_HANDLE_TAG_MASK == EVENT_HANDLE_TAG =>
                {
                    b"Event"
                }
                nt_process::HandleObject::Opaque(tag)
                    if tag & SEMAPHORE_HANDLE_TAG_MASK == SEMAPHORE_HANDLE_TAG =>
                {
                    b"Semaphore"
                }
                nt_process::HandleObject::Opaque(tag)
                    if tag & MUTANT_HANDLE_TAG_MASK == MUTANT_HANDLE_TAG =>
                {
                    b"Mutant"
                }
                nt_process::HandleObject::Opaque(tag) if tag == KEYEDEVENT_HANDLE_TAG => {
                    b"KeyedEvent"
                }
                nt_process::HandleObject::Opaque(_) => b"Object",
            },
        }
    }

    fn query_object_namespace_index(
        &self,
        object: nt_process::HandleObject,
        direct_index: Option<usize>,
    ) -> Option<usize> {
        if let Some(index) = direct_index {
            return self.obj_ns.get(index).map(|_| index);
        }
        let tag = match object {
            nt_process::HandleObject::Opaque(tag) => tag,
            _ => return None,
        };
        let index = if tag & EVENT_HANDLE_TAG_MASK == EVENT_HANDLE_TAG
            || tag & SEMAPHORE_HANDLE_TAG_MASK == SEMAPHORE_HANDLE_TAG
            || tag & MUTANT_HANDLE_TAG_MASK == MUTANT_HANDLE_TAG
        {
            (tag & 0xFFFF_FFFF) as usize
        } else {
            return None;
        };
        self.obj_ns.get(index).map(|_| index)
    }

    fn query_object_resolve(
        &self,
        handle: u64,
    ) -> Result<(nt_process::HandleObject, u32, Option<usize>), u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const PSEUDO_GRANTED_ACCESS: u32 = 0x001F_FFFF;
        let caller = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        if handle == u64::MAX {
            return Ok((
                nt_process::HandleObject::Process(caller),
                PSEUDO_GRANTED_ACCESS,
                None,
            ));
        }
        if handle == u64::MAX - 1 {
            let tid = self.current_tid as nt_process::ThreadId;
            self.pm.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
            return Ok((
                nt_process::HandleObject::Thread(tid),
                PSEUDO_GRANTED_ACCESS,
                None,
            ));
        }
        if handle >= OBJ_HANDLE_BASE {
            let index = (handle - OBJ_HANDLE_BASE) as usize;
            self.obj_ns.get(index).ok_or(STATUS_INVALID_HANDLE)?;
            return Ok((
                nt_process::HandleObject::Opaque(handle),
                PSEUDO_GRANTED_ACCESS,
                Some(index),
            ));
        }
        if handle > u32::MAX as u64 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let handle32 = handle as nt_process::Handle;
        let object = self
            .pm
            .lookup_handle(caller, handle32)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let access = self
            .pm
            .handle_access(caller, handle32)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok((object, access, None))
    }

    fn query_object_handle_flags(&self, handle: u64) -> Result<nt_process::HandleFlags, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        if handle == u64::MAX || handle == u64::MAX - 1 || handle >= OBJ_HANDLE_BASE {
            self.query_object_resolve(handle)?;
            return Ok(nt_process::HandleFlags::default());
        }
        if handle > u32::MAX as u64 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let caller = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        self.pm
            .handle_flags(caller, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn query_object_namespace_path(&self, index: usize, out: &mut [u8]) -> usize {
        let mut chain = [0usize; 16];
        let mut count = 0usize;
        let mut cur = Some(index);
        while let Some(i) = cur {
            if count == chain.len() || self.obj_ns.get(i).is_none() {
                break;
            }
            chain[count] = i;
            count += 1;
            let parent = self.obj_ns[i].parent;
            cur = if parent == 0xFF {
                None
            } else {
                Some(parent as usize)
            };
        }
        if out.is_empty() {
            return 0;
        }
        let mut n = 0usize;
        out[n] = b'\\';
        n += 1;
        for pos in (0..count).rev() {
            let entry = &self.obj_ns[chain[pos]];
            if entry.parent == 0xFF {
                continue;
            }
            if n > 1 {
                if n == out.len() {
                    break;
                }
                out[n] = b'\\';
                n += 1;
            }
            for &b in entry.name() {
                if n == out.len() {
                    return n;
                }
                out[n] = b;
                n += 1;
            }
        }
        n
    }

    fn write_ascii_utf16le(src: &[u8], dst: &mut [u8]) -> usize {
        let mut n = 0usize;
        for &b in src {
            if n + 1 >= dst.len() {
                break;
            }
            dst[n] = b;
            dst[n + 1] = 0;
            n += 2;
        }
        n
    }

    unsafe fn write_query_object_return_length(
        &self,
        memory: SyscallUserMemory,
        return_length: u64,
        needed: u32,
    ) -> Result<(), u32> {
        if return_length == 0 {
            return Ok(());
        }
        if !self.user_memory_write(memory, return_length, &needed.to_le_bytes()) {
            return Err(0xC000_0005);
        }
        Ok(())
    }

    pub(crate) unsafe fn nt_query_object_with_user_memory(
        &self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
        const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
        const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
        const OBJECT_BASIC_INFORMATION_SIZE: usize = 56;
        const OBJECT_NAME_INFORMATION_SIZE: usize = 16;
        const OBJECT_TYPE_INFORMATION_SIZE: usize = 104;
        const OBJECT_HANDLE_FLAG_INFORMATION_SIZE: usize = 2;

        let handle = args.first().copied().unwrap_or(0);
        let class = args.get(1).copied().unwrap_or(u64::MAX) as u32;
        let information = args.get(2).copied().unwrap_or(0);
        let length = args.get(3).copied().unwrap_or(0) as usize;
        let return_length = args.get(4).copied().unwrap_or(0);

        if return_length != 0 && !self.user_memory_probe_output(memory, return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }
        if class == 3 || class == 5 {
            let _ = self.write_query_object_return_length(
                memory,
                return_length,
                length.min(u32::MAX as usize) as u32,
            );
            return STATUS_NOT_IMPLEMENTED;
        }

        let (object, granted_access, namespace_index) = match self.query_object_resolve(handle) {
            Ok(target) => target,
            Err(status) => return status,
        };
        let namespace_kind =
            namespace_index.and_then(|index| self.obj_ns.get(index).map(|e| e.kind));
        let type_name = self.query_object_type_name(object, namespace_kind);

        match class {
            0 => {
                let mut name_ascii = [0u8; 256];
                let name_len = self
                    .query_object_namespace_index(object, namespace_index)
                    .map(|index| self.query_object_namespace_path(index, &mut name_ascii))
                    .unwrap_or(0);
                let type_info_len = (OBJECT_TYPE_INFORMATION_SIZE + type_name.len() * 2 + 2) as u32;
                let name_info_len = if name_len == 0 {
                    OBJECT_NAME_INFORMATION_SIZE as u32
                } else {
                    (OBJECT_NAME_INFORMATION_SIZE + name_len * 2 + 2) as u32
                };
                if self
                    .write_query_object_return_length(
                        memory,
                        return_length,
                        OBJECT_BASIC_INFORMATION_SIZE as u32,
                    )
                    .is_err()
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                if length != OBJECT_BASIC_INFORMATION_SIZE
                    || !self.user_memory_probe_output(memory, information, length)
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let mut output = [0u8; OBJECT_BASIC_INFORMATION_SIZE];
                output[4..8].copy_from_slice(&granted_access.to_le_bytes());
                output[8..12].copy_from_slice(&1u32.to_le_bytes()); // HandleCount
                output[12..16].copy_from_slice(&1u32.to_le_bytes()); // PointerCount
                output[36..40].copy_from_slice(&name_info_len.to_le_bytes());
                output[40..44].copy_from_slice(&type_info_len.to_le_bytes());
                if self.user_memory_write(memory, information, &output) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
            1 => {
                let mut name_ascii = [0u8; 256];
                let name_len = self
                    .query_object_namespace_index(object, namespace_index)
                    .map(|index| self.query_object_namespace_path(index, &mut name_ascii))
                    .unwrap_or(0);
                let name_bytes = name_len * 2;
                let needed = if name_len == 0 {
                    OBJECT_NAME_INFORMATION_SIZE
                } else {
                    OBJECT_NAME_INFORMATION_SIZE + name_bytes + 2
                };
                if self
                    .write_query_object_return_length(
                        memory,
                        return_length,
                        needed.min(u32::MAX as usize) as u32,
                    )
                    .is_err()
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                if length < needed || !self.user_memory_probe_output(memory, information, needed) {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let mut output = [0u8; OBJECT_NAME_INFORMATION_SIZE + 256 * 2 + 2];
                if name_len != 0 {
                    output[0..2].copy_from_slice(&(name_bytes as u16).to_le_bytes());
                    output[2..4].copy_from_slice(&((name_bytes + 2) as u16).to_le_bytes());
                    output[8..16].copy_from_slice(&(information + 16).to_le_bytes());
                    Self::write_ascii_utf16le(
                        &name_ascii[..name_len],
                        &mut output[OBJECT_NAME_INFORMATION_SIZE..],
                    );
                }
                if self.user_memory_write(memory, information, &output[..needed]) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
            2 => {
                let type_bytes = type_name.len() * 2;
                let needed = OBJECT_TYPE_INFORMATION_SIZE + type_bytes + 2;
                if self
                    .write_query_object_return_length(
                        memory,
                        return_length,
                        needed.min(u32::MAX as usize) as u32,
                    )
                    .is_err()
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                if length < needed || !self.user_memory_probe_output(memory, information, needed) {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let mut output = [0u8; OBJECT_TYPE_INFORMATION_SIZE + 64];
                output[0..2].copy_from_slice(&(type_bytes as u16).to_le_bytes());
                output[2..4].copy_from_slice(&((type_bytes + 2) as u16).to_le_bytes());
                output[8..16].copy_from_slice(&(information + 104).to_le_bytes());
                output[16..20].copy_from_slice(&1u32.to_le_bytes()); // TotalNumberOfObjects
                output[20..24].copy_from_slice(&1u32.to_le_bytes()); // TotalNumberOfHandles
                output[84..88].copy_from_slice(&0x001F_FFFFu32.to_le_bytes());
                output[89] = 1; // MaintainHandleCount
                Self::write_ascii_utf16le(type_name, &mut output[OBJECT_TYPE_INFORMATION_SIZE..]);
                if self.user_memory_write(memory, information, &output[..needed]) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
            4 => {
                let flags = match self.query_object_handle_flags(handle) {
                    Ok(flags) => flags,
                    Err(status) => return status,
                };
                if self
                    .write_query_object_return_length(
                        memory,
                        return_length,
                        OBJECT_HANDLE_FLAG_INFORMATION_SIZE as u32,
                    )
                    .is_err()
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                if length != OBJECT_HANDLE_FLAG_INFORMATION_SIZE
                    || !self.user_memory_probe_output(memory, information, length)
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let output = [flags.inherit as u8, flags.protect_from_close as u8];
                if self.user_memory_write(memory, information, &output) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
            _ => {
                let _ = self.write_query_object_return_length(
                    memory,
                    return_length,
                    length.min(u32::MAX as usize) as u32,
                );
                STATUS_INVALID_INFO_CLASS
            }
        }
    }

    pub(crate) unsafe fn nt_set_information_object_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
        const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;
        const OBJECT_SESSION_INFORMATION: u32 = 5;
        const OBJECT_HANDLE_FLAG_INFORMATION_SIZE: usize = 2;

        let handle = args.first().copied().unwrap_or(0);
        let class = args.get(1).copied().unwrap_or(u64::MAX) as u32;
        let information = args.get(2).copied().unwrap_or(0);
        let length = args.get(3).copied().unwrap_or(0) as usize;

        match class {
            OBJECT_HANDLE_FLAG_INFORMATION => {
                if length != OBJECT_HANDLE_FLAG_INFORMATION_SIZE {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let mut encoded = [0u8; OBJECT_HANDLE_FLAG_INFORMATION_SIZE];
                if information == 0 || !self.user_memory_read(memory, information, &mut encoded) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if handle == u64::MAX || handle == u64::MAX - 1 || handle >= OBJ_HANDLE_BASE {
                    return STATUS_INVALID_HANDLE;
                }
                if handle > u32::MAX as u64 {
                    return STATUS_INVALID_HANDLE;
                }
                let Some(caller) = self.pm_pid_for_pi(self.pi) else {
                    return STATUS_INVALID_HANDLE;
                };
                let flags = nt_process::HandleFlags {
                    inherit: encoded[0] != 0,
                    protect_from_close: encoded[1] != 0,
                };
                self.pm
                    .set_handle_flags(caller, handle as nt_process::Handle, flags)
                    .map_or_else(|status| status, |_| 0)
            }
            OBJECT_SESSION_INFORMATION => {
                if handle < OBJ_HANDLE_BASE {
                    return STATUS_INVALID_HANDLE;
                }
                let index = (handle - OBJ_HANDLE_BASE) as usize;
                match self.obj_ns.get(index) {
                    Some(entry) if entry.kind == 0 => 0,
                    Some(_) => STATUS_INVALID_HANDLE,
                    None => STATUS_INVALID_HANDLE,
                }
            }
            _ => STATUS_INVALID_INFO_CLASS,
        }
    }

    pub(crate) unsafe fn nt_allocate_virtual_memory_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const HIGHEST_VAD_ADDRESS: u64 = 0x0000_07ff_fffd_ffff;
        let ctx = self.loop_ctx.unwrap();
        let base_ptr = args[1];
        let size_ptr = args[3];
        let zero_bits = args[2];
        let allocation_type = args[4] as u32;
        let protection = args[5] as u32;
        if let Err(status) =
            nt_address_space::validate_allocate_parameters(zero_bits, allocation_type, protection)
        {
            return status;
        }
        if !self.user_memory_probe_output(memory, base_ptr, 8)
            || !self.user_memory_probe_output(memory, size_ptr, 8)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut word = [0u8; 8];
        if !self.user_memory_read(memory, base_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let base_in = u64::from_le_bytes(word);
        if !self.user_memory_read(memory, size_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let want = u64::from_le_bytes(word);
        if base_in > HIGHEST_VAD_ADDRESS {
            return nt_address_space::STATUS_INVALID_PARAMETER_2;
        }
        if HIGHEST_VAD_ADDRESS + 1 - base_in < want || want == 0 {
            return nt_address_space::STATUS_INVALID_PARAMETER_4;
        }
        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], PROCESS_VM_OPERATION) {
                Ok(target) => target,
                Err(status) => return status,
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        if allocation_type & nt_address_space::MEM_LARGE_PAGES != 0 {
            if !self.current_token_has_privilege(nt_security::SE_LOCK_MEMORY) {
                return STATUS_PRIVILEGE_NOT_HELD;
            }
            return STATUS_INVALID_PARAMETER;
        }
        if allocation_type & (nt_address_space::MEM_PHYSICAL | nt_address_space::MEM_WRITE_WATCH)
            != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        let copy_on_write = matches!(
            protection & 0xff,
            nt_address_space::PAGE_WRITECOPY | nt_address_space::PAGE_EXECUTE_WRITECOPY
        );
        let created_vad = base_in == 0 || allocation_type & nt_address_space::MEM_RESERVE != 0;
        if created_vad && copy_on_write {
            return nt_address_space::STATUS_INVALID_PAGE_PROTECTION;
        }
        let placement_limit = if base_in == 0 && zero_bits != 0 {
            let highest = u64::MAX >> zero_bits;
            if highest > HIGHEST_VAD_ADDRESS {
                return nt_address_space::STATUS_INVALID_PARAMETER_3;
            }
            PRIVATE_VM_LIMIT.min(highest + 1)
        } else {
            PRIVATE_VM_LIMIT
        };
        let procs = &mut *ctx.procs;
        let target = procs[target_pi];
        if target.pml4 == 0 || target.scratch_base == 0 {
            return nt_process::STATUS_INVALID_HANDLE;
        }
        let vm_map = (core::ptr::addr_of_mut!(PROCESS_VM_REGIONS)
            as *mut nt_address_space::VmRegionMap<VM_REGION_CAPACITY>)
            .add(target_pi);
        // STATIC scratch, not stack — see the matching note in the free path.
        let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *before = core::ptr::read(vm_map);
        *after = *before;
        let plan = match after.allocate_below(
            (base_in != 0).then_some(base_in),
            want,
            allocation_type,
            protection,
            placement_limit,
        ) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        crate::note_high_water(&crate::VM_REGION_HW, after.extent_count() as u64);
        if !created_vad && allocation_type != nt_address_space::MEM_RESET && copy_on_write {
            return nt_address_space::STATUS_INVALID_PAGE_PROTECTION;
        }
        if self.current_process_is_winlogon()
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
            print_hex(args[4] as u32);
            print_str(b" selected=0x");
            print_hex((plan.base >> 32) as u32);
            print_hex(plan.base as u32);
            print_str(b"\n");
        }

        let mut page = plan.base;
        let mut changed_end = plan.base;
        let mut map_status = 0u32;
        while page < plan.base + plan.size {
            let old = before.extent_at(page);
            let new = after.extent_at(page);
            if new.is_some_and(|extent| extent.state == nt_address_space::VmExtentState::Committed)
            {
                if old
                    .is_none_or(|extent| extent.state != nt_address_space::VmExtentState::Committed)
                {
                    if let Err(status) = vm_map_private_page(
                        target_pi,
                        page,
                        new.unwrap().protection,
                        target.pml4,
                        target.scratch_base,
                    ) {
                        map_status = status;
                        break;
                    }
                } else if old.unwrap().protection != new.unwrap().protection {
                    if let Err(status) = vm_reprotect_private_page(
                        target_pi,
                        page,
                        old.unwrap().protection,
                        new.unwrap().protection,
                        target.pml4,
                    ) {
                        map_status = status;
                        break;
                    }
                }
            }
            page += 0x1000;
            changed_end = page;
        }
        if map_status != 0 {
            page = plan.base;
            while page < changed_end {
                let old = before.extent_at(page);
                let new = after.extent_at(page);
                if old
                    .is_none_or(|extent| extent.state != nt_address_space::VmExtentState::Committed)
                    && new.is_some_and(|extent| {
                        extent.state == nt_address_space::VmExtentState::Committed
                    })
                {
                    vm_unmap_private_page(target_pi, page);
                } else if let (Some(old), Some(new)) = (old, new) {
                    if old.state == nt_address_space::VmExtentState::Committed
                        && new.state == nt_address_space::VmExtentState::Committed
                        && old.protection != new.protection
                    {
                        let _ = vm_reprotect_private_page(
                            target_pi,
                            page,
                            new.protection,
                            old.protection,
                            target.pml4,
                        );
                    }
                }
                page += 0x1000;
            }
            return map_status;
        }
        core::ptr::write(vm_map, *after);
        let size_written = self.user_memory_write(memory, size_ptr, &plan.size.to_le_bytes());
        let base_written = self.user_memory_write(memory, base_ptr, &plan.base.to_le_bytes());
        if !created_vad && (!size_written || !base_written) {
            return STATUS_ACCESS_VIOLATION;
        }
        NTALLOC_SERVICED.fetch_add(1, Ordering::Relaxed);
        0
    }

    pub(crate) unsafe fn nt_protect_virtual_memory_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        let base_ptr = args[1];
        let size_ptr = args[2];
        let oldprot_ptr = args[4];
        if !self.user_memory_probe_output(memory, base_ptr, 8)
            || !self.user_memory_probe_output(memory, size_ptr, 8)
            || (oldprot_ptr != 0 && !self.user_memory_probe_output(memory, oldprot_ptr, 4))
        {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut word = [0u8; 8];
        if !self.user_memory_read(memory, base_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let base = u64::from_le_bytes(word);
        if !self.user_memory_read(memory, size_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let size = u64::from_le_bytes(word);
        if oldprot_ptr != 0 && !self.user_memory_write(memory, oldprot_ptr, &0x04u32.to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }

        let registry_slot = self
            .loop_ctx
            .and_then(|ctx| (&*ctx.reg).dll_for_page(base).map(|(slot, _)| slot));
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
    }

    unsafe fn nt_copy_virtual_memory(&mut self, args: &[u64], read: bool) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;

        let remote = args[1];
        let local = args[2];
        let length = args[3];
        let count_ptr = args[4];
        let valid_range = |base: u64| {
            base.checked_add(length)
                .is_some_and(|end| end <= USER_ADDRESS_LIMIT)
        };
        if !valid_range(remote) || !valid_range(local) {
            return STATUS_ACCESS_VIOLATION;
        }
        if count_ptr != 0 {
            if !self.probe_user_output(count_ptr, 8) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if length == 0 {
            if count_ptr != 0 {
                let _ = self.xas_write_u64(count_ptr, 0);
            }
            return 0;
        }

        let required_access = if read {
            PROCESS_VM_READ
        } else {
            PROCESS_VM_WRITE
        };
        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], required_access) {
                Ok(target) => target,
                Err(status) => {
                    if count_ptr != 0 {
                        let _ = self.xas_write_u64(count_ptr, 0);
                    }
                    return status;
                }
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            if count_ptr != 0 {
                let _ = self.xas_write_u64(count_ptr, 0);
            }
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }

        let ctx = match self.loop_ctx {
            Some(ctx) => ctx,
            None => {
                if count_ptr != 0 {
                    let _ = self.xas_write_u64(count_ptr, 0);
                }
                return STATUS_PARTIAL_COPY;
            }
        };
        let procs = &mut *ctx.procs;
        let target = procs[target_pi];
        if target.pml4 == 0 || target.scratch_base == 0 {
            if count_ptr != 0 {
                let _ = self.xas_write_u64(count_ptr, 0);
            }
            return nt_process::STATUS_INVALID_HANDLE;
        }
        let (target_filled, target_faults) = if target_pi == self.pi {
            (&*ctx.filled_pages, *ctx.faults as usize)
        } else {
            (&(*ctx.pfilled)[target_pi], procs[target_pi].faults as usize)
        };
        let target_vm = core::ptr::read(
            (core::ptr::addr_of!(PROCESS_VM_REGIONS)
                as *const nt_address_space::VmRegionMap<VM_REGION_CAPACITY>)
                .add(target_pi),
        );

        let mut transferred = 0u64;
        let mut buffer = [0u8; 256];
        while transferred < length {
            let remote_address = remote + transferred;
            let local_address = local + transferred;
            let remote_page = 0x1000 - (remote_address as usize & 0xfff);
            let local_page = 0x1000 - (local_address as usize & 0xfff);
            let chunk = (length - transferred)
                .min(buffer.len() as u64)
                .min(remote_page as u64)
                .min(local_page as u64) as usize;
            let private_extent = target_vm.extent_at(remote_address);
            let protection_allows = private_extent.is_none()
                || if read {
                    target_vm.permits_read(remote_address)
                } else {
                    target_vm.permits_write(remote_address)
                };
            let mut local_copied = false;
            let mut remote_copied = false;
            let copied = if !protection_allows {
                false
            } else if read {
                remote_copied = client_copyin_process_mapped(
                    target_pi as u64,
                    remote_address,
                    &mut buffer[..chunk],
                    target_filled,
                    target_faults,
                    target.scratch_base,
                    target_pi == self.pi,
                );
                local_copied =
                    remote_copied && self.xas_try_write_buf(local_address, &buffer[..chunk]);
                local_copied
            } else {
                local_copied = self.xas_read(local_address, &mut buffer[..chunk]);
                remote_copied = local_copied
                    && if target_pi == self.pi {
                        self.xas_try_write_buf(remote_address, &buffer[..chunk])
                    } else {
                        client_copyout_mapped(
                            target_pi as u64,
                            remote_address,
                            &buffer[..chunk],
                            target_filled,
                            target_faults,
                            target.scratch_base,
                        )
                    };
                remote_copied
            };
            if !copied {
                if self.current_process_is_winlogon() && target_pi != self.pi {
                    let (frame, _) =
                        csrss_frame_get_exact(target_pi as u64, remote_address & !0xfff);
                    print_str(b"[remote-vm] write failed target_pi=");
                    print_u64(target_pi as u64);
                    print_str(b" remote=0x");
                    print_hex((remote_address >> 32) as u32);
                    print_hex(remote_address as u32);
                    print_str(b" local=0x");
                    print_hex((local_address >> 32) as u32);
                    print_hex(local_address as u32);
                    print_str(b" chunk=0x");
                    print_hex(chunk as u32);
                    print_str(b" local_ok=");
                    print_u64(local_copied as u64);
                    print_str(b" remote_ok=");
                    print_u64(remote_copied as u64);
                    print_str(b" protection_ok=");
                    print_u64(protection_allows as u64);
                    print_str(b" frame=0x");
                    print_hex(frame as u32);
                    print_str(b" vad=");
                    print_u64(private_extent.is_some() as u64);
                    print_str(b"\n");
                }
                break;
            }
            transferred += chunk as u64;
        }
        if count_ptr != 0 {
            let _ = self.xas_write_u64(count_ptr, transferred);
        }
        if transferred == length {
            0
        } else {
            STATUS_PARTIAL_COPY
        }
    }

    unsafe fn nt_free_virtual_memory(&mut self, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const HIGHEST_USER_ADDRESS: u64 = 0x0000_07ff_fffe_ffff;

        let free_type = args[3] as u32;
        if free_type != nt_address_space::MEM_RELEASE && free_type != nt_address_space::MEM_DECOMMIT
        {
            return nt_address_space::STATUS_INVALID_PARAMETER_4;
        }
        let base_ptr = args[1];
        let size_ptr = args[2];
        if !self.probe_user_output(base_ptr, 8) || !self.probe_user_output(size_ptr, 4) {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut word = [0u8; 8];
        if !self.xas_read(base_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let base = u64::from_le_bytes(word);
        if !self.xas_read(size_ptr, &mut word) {
            return STATUS_ACCESS_VIOLATION;
        }
        let size = u64::from_le_bytes(word);
        if base >= HIGHEST_USER_ADDRESS {
            return nt_address_space::STATUS_INVALID_PARAMETER_2;
        }
        if HIGHEST_USER_ADDRESS - base < size {
            return STATUS_INVALID_PARAMETER_3;
        }

        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], PROCESS_VM_OPERATION) {
                Ok(target) => target,
                Err(status) => return status,
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        let vm_map = (core::ptr::addr_of_mut!(PROCESS_VM_REGIONS)
            as *mut nt_address_space::VmRegionMap<VM_REGION_CAPACITY>)
            .add(target_pi);
        // ★ The before/after snapshots live in STATIC scratch, never on the stack. The executive's
        // rootserver stack floats immediately after its loaded image and is only a few pages; a
        // whole `VmRegionMap` is kilobytes, so taking two copies per call overflowed straight into
        // the guard page the moment [`VM_REGION_CAPACITY`] was raised (measured: a `#PF err=6` in
        // the executive at `.bss_end + 0x898`, one page past the mapped image, during smss' spawn).
        // Single-threaded executive, and neither scratch outlives this call.
        let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *before = core::ptr::read(vm_map);
        *after = *before;
        let plan = match after.free(base, size, free_type) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        let mut page = plan.base;
        while page < plan.base + plan.size {
            let old = before.extent_at(page);
            let new = after.extent_at(page);
            if old.is_some_and(|extent| extent.state == nt_address_space::VmExtentState::Committed)
                && new
                    .is_none_or(|extent| extent.state != nt_address_space::VmExtentState::Committed)
            {
                vm_unmap_private_page(target_pi, page);
            }
            page += 0x1000;
        }
        core::ptr::write(vm_map, *after);
        let _ = self.xas_write_u64(size_ptr, plan.size);
        let _ = self.xas_write_u64(base_ptr, plan.base);
        0
    }

    fn token_id_for_handle(
        &self,
        handle: u64,
        required_access: u32,
    ) -> Result<nt_security::TokenId, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
        let caller = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let object = self
            .pm
            .lookup_handle(caller, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let token = match object {
            nt_process::HandleObject::TokenObject(token) => token,
            nt_process::HandleObject::Token(pid) => self
                .pm
                .process_primary_token(pid)
                .ok_or(STATUS_INVALID_HANDLE)?,
            _ => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        let granted = self
            .pm
            .handle_access(caller, handle as nt_process::Handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if granted & required_access != required_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.token_store
            .get(token)
            .map(|_| token)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn current_token_has_privilege(&self, name: &str) -> bool {
        self.pm
            .effective_token(self.current_tid as nt_process::ThreadId)
            .and_then(|token| self.token_store.get(token))
            .is_some_and(|token| token.has_privilege(name))
    }

    unsafe fn write_access_check_privilege_set(
        &self,
        privilege_set: u64,
        privilege_set_length: u64,
        captured_length: u32,
        privileges_used: &[&'static str],
    ) -> Result<(), u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        const PRIVILEGE_SET_MIN_SIZE: usize = 20; // sizeof(PRIVILEGE_SET), including ANYSIZE_ARRAY[1].
        const PRIVILEGE_SET_HEADER_SIZE: usize = 8;
        const LUID_AND_ATTRIBUTES_SIZE: usize = 12;
        const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

        let mut luids = [nt_security::Luid::default(); 4];
        let mut count = 0usize;
        for name in privileges_used {
            let Some(luid) = nt_security::luid_for_privilege_name(name) else {
                continue;
            };
            let Some(slot) = luids.get_mut(count) else {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            };
            *slot = luid;
            count += 1;
        }
        let required = PRIVILEGE_SET_HEADER_SIZE
            .checked_add(
                count
                    .checked_mul(LUID_AND_ATTRIBUTES_SIZE)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?,
            )
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .max(PRIVILEGE_SET_MIN_SIZE);
        if captured_length < required as u32 {
            if !self.xas_write_u32(privilege_set_length, required as u32) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            return Err(STATUS_BUFFER_TOO_SMALL);
        }

        let mut output = [0u8; 64];
        output[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        for (index, luid) in luids[..count].iter().enumerate() {
            let offset = PRIVILEGE_SET_HEADER_SIZE + index * LUID_AND_ATTRIBUTES_SIZE;
            output[offset..offset + 4].copy_from_slice(&luid.low.to_le_bytes());
            output[offset + 4..offset + 8].copy_from_slice(&luid.high.to_le_bytes());
            output[offset + 8..offset + 12]
                .copy_from_slice(&SE_PRIVILEGE_USED_FOR_ACCESS.to_le_bytes());
        }
        if !self.xas_try_write_buf(privilege_set, &output[..required]) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(())
    }

    /// `NtAccessCheck(SecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet,
    /// PrivilegeSetLength, GrantedAccess, AccessStatus)` — `ntoskrnl/se/accesschk.c:NtAccessCheck`.
    unsafe fn nt_access_check(&mut self, ctx: &NativeCallContext, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_GENERIC_NOT_MAPPED: u32 = 0xC000_00E6;
        const STATUS_NO_IMPERSONATION_TOKEN: u32 = 0xC000_005C;
        const TOKEN_QUERY: u32 = 0x0008;
        const GENERIC_MASK: u32 = nt_security::GENERIC_ALL
            | nt_security::GENERIC_EXECUTE
            | nt_security::GENERIC_READ
            | nt_security::GENERIC_WRITE;

        if args.len() < 8 {
            return STATUS_INVALID_PARAMETER;
        }

        let mut mapping_bytes = [0u8; 16];
        if args[3] == 0 || !self.xas_read(args[3], &mut mapping_bytes) {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut privilege_set_length_bytes = [0u8; 4];
        if args[5] == 0 || !self.xas_read(args[5], &mut privilege_set_length_bytes) {
            return STATUS_ACCESS_VIOLATION;
        }
        let captured_privilege_set_length = u32::from_le_bytes(privilege_set_length_bytes);
        if captured_privilege_set_length != 0
            && !self.probe_user_output(args[4], captured_privilege_set_length as usize)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if !self.probe_user_output(args[6], 4) || !self.probe_user_output(args[7], 4) {
            return STATUS_ACCESS_VIOLATION;
        }

        let desired_access = args[2] as u32;
        if desired_access & GENERIC_MASK != 0 {
            return STATUS_GENERIC_NOT_MAPPED;
        }

        let token_id = match self.token_id_for_handle(args[1], TOKEN_QUERY) {
            Ok(token) => token,
            Err(status) => return status,
        };
        let token = match self.token_store.get(token_id) {
            Some(token) => token,
            None => return STATUS_INVALID_HANDLE,
        };
        if token.token_type != nt_security::TokenType::Impersonation {
            return STATUS_NO_IMPERSONATION_TOKEN;
        }
        if token.impersonation_level < nt_security::SecurityImpersonationLevel::Identification {
            return nt_security::STATUS_BAD_IMPERSONATION_LEVEL;
        }

        let mapping = nt_security::GenericMapping {
            generic_read: u32::from_le_bytes(mapping_bytes[0..4].try_into().unwrap()),
            generic_write: u32::from_le_bytes(mapping_bytes[4..8].try_into().unwrap()),
            generic_execute: u32::from_le_bytes(mapping_bytes[8..12].try_into().unwrap()),
            generic_all: u32::from_le_bytes(mapping_bytes[12..16].try_into().unwrap()),
        };
        let sd = {
            let memory = ExecClientMemory { handler: &*self };
            nt_security::capture_security_descriptor(&memory, args[0])
        };
        let sd = match sd {
            Ok(sd) => sd,
            Err(status) => return status,
        };
        if sd.owner.is_none() || sd.group.is_none() {
            return nt_security::STATUS_INVALID_SECURITY_DESCR;
        }

        let mode = if ctx.previous_mode == nt_syscall::ProcessorMode::KernelMode {
            nt_security::ProcessorMode::KernelMode
        } else {
            nt_security::ProcessorMode::UserMode
        };
        let result = nt_security::access_check(&sd, token, desired_access, &mapping, mode);
        if let Err(status) = self.write_access_check_privilege_set(
            args[4],
            args[5],
            captured_privilege_set_length,
            &result.privileges_used,
        ) {
            return status;
        }
        if !self.xas_write_u32(args[6], result.granted_access)
            || !self.xas_write_u32(args[7], result.status)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        0
    }

    /// `NtSetInformationProcess(ProcessAccessToken)`: capture the native two-HANDLE structure, but
    /// assign only its Token member. ReactOS fills Thread in advapi32 and the kernel deliberately
    /// ignores it (`ntoskrnl/ps/query.c`, ProcessAccessToken), so resolving that handle here would
    /// reject valid callers. TokenStore does not yet model token ancestry; require the real enabled
    /// assignment privilege for the independent interactive logon token used by CreateProcessAsUser.
    unsafe fn nt_set_process_access_token(&mut self, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const PROCESS_SET_INFORMATION: u32 = 0x0200;
        const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;

        if args[3] != 16 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let mut captured = [0u8; 16];
        if args[2] == 0 || !self.xas_read(args[2], &mut captured) {
            return STATUS_ACCESS_VIOLATION;
        }
        let token_handle = u64::from_le_bytes(captured[..8].try_into().unwrap());
        let caller = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return STATUS_INVALID_HANDLE,
        };
        let target = match self
            .pm
            .resolve_process_handle(caller, args[0], PROCESS_SET_INFORMATION)
        {
            Ok(pid) => pid,
            Err(status) => return status,
        };
        let token = match self.token_id_for_handle(token_handle, TOKEN_ASSIGN_PRIMARY) {
            Ok(token) => token,
            Err(status) => return status,
        };
        if !self.current_token_has_privilege(nt_security::SE_ASSIGN_PRIMARY_TOKEN) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        if self
            .token_store
            .get(token)
            .is_none_or(|token| token.token_type != nt_security::TokenType::Primary)
        {
            return nt_security::STATUS_BAD_TOKEN_TYPE;
        }
        if self.token_store.retain(token).is_err() {
            return STATUS_INVALID_HANDLE;
        }
        let old = match self.pm.replace_process_primary_token(target, Some(token)) {
            Ok(old) => old,
            Err(status) => {
                let _ = self.token_store.release(token);
                return status;
            }
        };
        if let Some(old) = old {
            let _ = self.token_store.release(old);
        }
        if self.pi_for_pid(target) == Some(5) {
            USERINIT_PRIMARY_TOKEN_ASSIGNED.fetch_add(1, Ordering::Relaxed);
        }
        0
    }

    fn release_handle_object(&mut self, object: nt_process::HandleObject) {
        match object {
            nt_process::HandleObject::TokenObject(token) => {
                let _ = self.token_store.release(token);
            }
            nt_process::HandleObject::IoCompletion(id) => {
                let _ = self.io_completion_ports.release(id);
            }
            nt_process::HandleObject::File(file_id) => {
                self.release_file_reference(file_id);
            }
            nt_process::HandleObject::Directory { object_id, .. } => {
                let _ = self.directory_opens.release(object_id);
            }
            // The last handle on a writable-overlay file object: run the volume's cleanup/close
            // (which actions a pending delete) and free the FILE_OBJECT.
            nt_process::HandleObject::OverlayFile(file_id) => {
                unsafe { crate::writable_fs::close(file_id) };
                self.writable_fs_dirty = true;
            }
            // DbgkpCloseObject: the debugger's last handle went away — mark the object inactive,
            // detach every debuggee, and drop it.
            nt_process::HandleObject::DebugObject(object) => {
                if self.pm.release_debug_object_handle(object).unwrap_or(false) {
                    // ★ ESCAPE HATCH: the DEBUGGER IS GONE. Release every target still blocked on
                    // one of this object's events before the object (and its event list) is dropped
                    // — otherwise a debugger that dies mid-event would leave a reporter parked
                    // forever and the boot could never quiesce.
                    unsafe { self.dbgk_release_blocked_reporters(object, None) };
                    // `DbgkpMarkProcessPeb(Process, FALSE)` for every debuggee this object still
                    // holds — done BEFORE the detach, while the attachment is still resolvable.
                    unsafe { self.dbgk_clear_peb_marks_for_object(object) };
                    self.pm.destroy_debug_object(object);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn close_process_handle_checked(
        &mut self,
        pid: nt_process::ProcessId,
        handle: u64,
    ) -> Result<bool, u32> {
        match self
            .pm
            .take_handle_for_close(pid, handle as nt_process::Handle)
        {
            Ok(object) => {
                self.release_handle_object(object);
                PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(nt_process::STATUS_INVALID_HANDLE) => Ok(false),
            Err(status) => Err(status),
        }
    }

    pub(crate) fn close_process_handle(&mut self, pid: nt_process::ProcessId, handle: u64) -> bool {
        self.close_process_handle_checked(pid, handle)
            .unwrap_or(false)
    }

    fn release_process_handles(&mut self, pid: nt_process::ProcessId) {
        while let Some(object) = self.pm.take_any_handle(pid) {
            self.release_handle_object(object);
            PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn duplicate_process_handle_with_access(
        &mut self,
        source_pid: nt_process::ProcessId,
        source_handle: nt_process::Handle,
        target_pid: nt_process::ProcessId,
        desired_access: Option<u32>,
    ) -> Result<nt_process::Handle, u32> {
        let object = self
            .pm
            .lookup_handle(source_pid, source_handle)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let desired_access = desired_access.map(|access| match object {
            nt_process::HandleObject::TokenObject(_) | nt_process::HandleObject::Token(_) => {
                nt_security::map_token_access(access)
            }
            _ => access,
        });
        let handle = self.pm.duplicate_handle_with_access(
            source_pid,
            source_handle,
            target_pid,
            desired_access,
        )?;
        let retained = match object {
            nt_process::HandleObject::TokenObject(token) => self
                .token_store
                .retain(token)
                .map_err(|_| nt_process::STATUS_INVALID_HANDLE),
            nt_process::HandleObject::IoCompletion(id) => self.io_completion_ports.retain(id),
            nt_process::HandleObject::File(file_id) => self.file_completion.retain_file(file_id),
            nt_process::HandleObject::Directory { object_id, .. } => {
                self.directory_opens.retain(object_id)
            }
            nt_process::HandleObject::OverlayFile(file_id) => {
                self.writable_fs_dirty = true;
                unsafe { crate::writable_fs::retain(file_id) }
            }
            _ => Ok(()),
        };
        if let Err(status) = retained {
            // The table copy does not own the backing object until retain succeeds.
            let _ = self.pm.take_handle(target_pid, handle);
            return Err(status);
        }
        // ★ Record the logon token crossing into winlogon: `LsapLogonUser`'s closing
        // `NtDuplicateObject(NtCurrentProcess(), TokenHandle, ClientProcessHandle, &Reply.Token, …)`
        // (authpackage.c:1712). Only the token the `NtCreateToken` service minted counts.
        if let nt_process::HandleObject::TokenObject(token) = object {
            if token.raw() as u64 == SE_CREATE_TOKEN_ID.load(Ordering::Relaxed)
                && SE_CREATE_TOKEN_ID.load(Ordering::Relaxed) != 0
                && self.pi_for_pid(target_pid) == Some(2)
            {
                WINLOGON_LOGON_TOKEN_HANDLE.store(handle as u64, Ordering::Relaxed);
                WINLOGON_LOGON_TOKEN_DUPLICATES.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(handle)
    }

    /// Transfer one existing token reference into a new caller-local handle. Every failure path
    /// releases that reference; success leaves the handle as its sole owner.
    unsafe fn insert_owned_token_handle(
        &mut self,
        caller_pid: nt_process::ProcessId,
        token: nt_security::TokenId,
        desired_access: u32,
        out: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
        let handle = match self.pm.insert_handle(
            caller_pid,
            nt_process::HandleObject::TokenObject(token),
            nt_security::map_token_access(desired_access),
        ) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = self.token_store.release(token);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        };
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        let count = self.pm.handle_count(caller_pid) as u64;
        if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
            PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
        }
        if !self.xas_write_u64(out, handle as u64) {
            if let Ok(object) = self.pm.take_handle(caller_pid, handle) {
                self.release_handle_object(object);
            }
            return STATUS_ACCESS_VIOLATION;
        }
        0
    }

    pub(crate) unsafe fn nt_open_process_token(
        &mut self,
        process_handle: u64,
        desired_access: u32,
        out: u64,
    ) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        if !self.probe_user_output(out, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let target_pid = match self.resolve_process_handle(process_handle) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        if self.pi_for_pid(target_pid).is_none() {
            return STATUS_INVALID_HANDLE;
        }
        let token = match self.pm.process_primary_token(target_pid) {
            Some(token) => token,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return STATUS_INVALID_HANDLE,
        };
        if self.token_store.retain(token).is_err() {
            return STATUS_INVALID_HANDLE;
        }
        self.insert_owned_token_handle(caller_pid, token, desired_access, out)
    }

    unsafe fn nt_duplicate_token(&mut self, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const TOKEN_DUPLICATE: u32 = 0x0002;

        let token_type = match args[4] as u32 {
            1 => nt_security::TokenType::Primary,
            2 => nt_security::TokenType::Impersonation,
            _ => return STATUS_INVALID_PARAMETER,
        };
        let out = args[5];
        if !self.probe_user_output(out, 8) {
            return STATUS_ACCESS_VIOLATION;
        }

        let mut level = nt_security::SecurityImpersonationLevel::Anonymous;
        if args[2] != 0 {
            let mut oa = [0u8; 48];
            if !self.xas_read(args[2], &mut oa) {
                return STATUS_ACCESS_VIOLATION;
            }
            if u32::from_le_bytes(oa[0..4].try_into().unwrap()) != 48 {
                return STATUS_INVALID_PARAMETER;
            }
            let qos = u64::from_le_bytes(oa[40..48].try_into().unwrap());
            if qos != 0 {
                let mut captured = [0u8; 12];
                if !self.xas_read(qos, &mut captured) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if u32::from_le_bytes(captured[0..4].try_into().unwrap()) != 12 {
                    return STATUS_INVALID_PARAMETER;
                }
                level = match nt_security::SecurityImpersonationLevel::try_from(u32::from_le_bytes(
                    captured[4..8].try_into().unwrap(),
                )) {
                    Ok(level) => level,
                    Err(status) => return status,
                };
            }
        }

        let source = match self.token_id_for_handle(args[0], TOKEN_DUPLICATE) {
            Ok(token) => token,
            Err(status) => return status,
        };
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let desired_access = if args[1] as u32 == 0 {
            match self
                .pm
                .handle_access(caller_pid, args[0] as nt_process::Handle)
            {
                Some(access) => access,
                None => return nt_process::STATUS_INVALID_HANDLE,
            }
        } else {
            args[1] as u32
        };
        let duplicate =
            match self
                .token_store
                .duplicate(source, token_type, level, (args[3] as u8) != 0)
            {
                Ok(token) => token,
                Err(status) => return status,
            };
        let status = self.insert_owned_token_handle(caller_pid, duplicate, desired_access, out);
        if status == 0 {
            self.token_dirty = true;
        }
        status
    }

    /// `NtCreateToken(TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId,`
    /// `ExpirationTime, TokenUser, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup,`
    /// `TokenDefaultDacl, TokenSource)` — `ntoskrnl/se/tokenlif.c:1559`.
    ///
    /// The **widest** service the executive hosts by argument-*meaning*: thirteen arguments, of
    /// which the first four ride in `r10/rdx/r8/r9` and args 5..13 come off the caller's stack. The
    /// dispatcher's generic marshaller already gathers them (arity 13 from the shared
    /// `nt_syscall_abi` table, read at `[rsp+0x28 + 8*i]` through the client mirror), so this
    /// handler receives a flat `args[0..13]` — but it must NOT assume it: a short vector means the
    /// stack copy-in failed and the call fails closed.
    ///
    /// Six of the thirteen arguments point at **variable-length structures in the caller's address
    /// space**, several of which are themselves arrays of pointers to SIDs. That capture is the
    /// pure, host-tested `nt_security::create_token` walk; everything here is the kernel-side
    /// policy around it: probe the output handle, check the token type, enforce
    /// `SeCreateTokenPrivilege`, capture the QoS impersonation level out of `ObjectAttributes`, and
    /// insert the resulting token object + a handle to it in the caller's own handle table.
    unsafe fn nt_create_token(&mut self, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;

        SE_CREATE_TOKEN_CALLS.fetch_add(1, Ordering::Relaxed);
        SE_CREATE_TOKEN_ARGC.store(args.len() as u64, Ordering::Relaxed);
        // ★ WIDE-ARGUMENT GUARD. Args 5..13 are the nine stack slots; if the dispatcher could not
        // read them all it hands a short vector, and every structure pointer we need lives THERE.
        if args.len() < 13 {
            SE_CREATE_TOKEN_LAST_STATUS.store(STATUS_INVALID_PARAMETER as u64, Ordering::Relaxed);
            return STATUS_INVALID_PARAMETER;
        }
        SE_CREATE_TOKEN_STACK_ARGS.store(
            args[4..13].iter().filter(|value| **value != 0).count() as u64,
            Ordering::Relaxed,
        );

        let out = args[0];
        let desired_access = args[1] as u32;
        let object_attributes = args[2];
        if !self.probe_user_output(out, 8) {
            SE_CREATE_TOKEN_LAST_STATUS.store(STATUS_ACCESS_VIOLATION as u64, Ordering::Relaxed);
            return STATUS_ACCESS_VIOLATION;
        }
        // ReactOS checks the token type BEFORE the privilege check, so a garbage type is reported
        // as STATUS_BAD_TOKEN_TYPE even to an unprivileged caller (tokenlif.c:1686).
        if args[3] as u32 != 1 && args[3] as u32 != 2 {
            SE_CREATE_TOKEN_LAST_STATUS.store(STATUS_BAD_TOKEN_TYPE as u64, Ordering::Relaxed);
            return STATUS_BAD_TOKEN_TYPE;
        }
        // ★ `SeSinglePrivilegeCheck(SeCreateTokenPrivilege, PreviousMode)` (tokenlif.c:1695). The
        // caller's EFFECTIVE token (impersonation token if one is set, else the process primary
        // token) must hold the privilege ENABLED. lsass' LocalSystem token has it present-but-
        // disabled by default and enables it itself in `LsapRmInitializeServer` ->
        // `RtlAdjustPrivilege(SE_CREATE_TOKEN_PRIVILEGE, TRUE, FALSE, ...)` (lsasrv.c:314), which
        // runs through the real `NtAdjustPrivilegesToken` service.
        if !self.current_token_has_privilege(nt_security::SE_CREATE_TOKEN) {
            SE_CREATE_TOKEN_PRIV_DENIED.fetch_add(1, Ordering::Relaxed);
            SE_CREATE_TOKEN_LAST_STATUS.store(STATUS_PRIVILEGE_NOT_HELD as u64, Ordering::Relaxed);
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        // `ObjectAttributes->SecurityQualityOfService->ImpersonationLevel`, captured exactly as
        // `nt_duplicate_token` does. An absent OA / QoS leaves the level Anonymous.
        let mut level = nt_security::SecurityImpersonationLevel::Anonymous;
        if object_attributes != 0 {
            let mut oa = [0u8; 48];
            if !self.xas_read(object_attributes, &mut oa) {
                SE_CREATE_TOKEN_LAST_STATUS
                    .store(STATUS_ACCESS_VIOLATION as u64, Ordering::Relaxed);
                return STATUS_ACCESS_VIOLATION;
            }
            if u32::from_le_bytes(oa[0..4].try_into().unwrap()) != 48 {
                SE_CREATE_TOKEN_LAST_STATUS
                    .store(STATUS_INVALID_PARAMETER as u64, Ordering::Relaxed);
                return STATUS_INVALID_PARAMETER;
            }
            let qos = u64::from_le_bytes(oa[40..48].try_into().unwrap());
            if qos != 0 {
                let mut captured = [0u8; 12];
                if !self.xas_read(qos, &mut captured) {
                    SE_CREATE_TOKEN_LAST_STATUS
                        .store(STATUS_ACCESS_VIOLATION as u64, Ordering::Relaxed);
                    return STATUS_ACCESS_VIOLATION;
                }
                level = match nt_security::SecurityImpersonationLevel::try_from(u32::from_le_bytes(
                    captured[4..8].try_into().unwrap(),
                )) {
                    Ok(level) => level,
                    Err(status) => {
                        SE_CREATE_TOKEN_LAST_STATUS.store(status as u64, Ordering::Relaxed);
                        return status;
                    }
                };
            }
        }

        let request = nt_security::CreateTokenArgs {
            token_type: args[3] as u32,
            authentication_id: args[4],
            expiration_time: args[5],
            token_user: args[6],
            token_groups: args[7],
            token_privileges: args[8],
            token_owner: args[9],
            token_primary_group: args[10],
            token_default_dacl: args[11],
            token_source: args[12],
        };
        // The bounded cross-address-space capture. Scoped so the immutable borrow of `self` ends
        // before the token store is mutated.
        let captured = {
            let memory = ExecClientMemory { handler: &*self };
            nt_security::capture_token(&memory, &request, level)
        };
        let captured = match captured {
            Ok(captured) => captured,
            Err(status) => {
                SE_CREATE_TOKEN_CAPTURE_FAILS.fetch_add(1, Ordering::Relaxed);
                SE_CREATE_TOKEN_LAST_STATUS.store(status as u64, Ordering::Relaxed);
                return status;
            }
        };

        let Some(caller_pid) = self.pm_pid_for_pi(self.pi) else {
            SE_CREATE_TOKEN_LAST_STATUS
                .store(nt_process::STATUS_INVALID_HANDLE as u64, Ordering::Relaxed);
            return nt_process::STATUS_INVALID_HANDLE;
        };
        let user_rid = captured.token.user.sub_authorities.last().copied();
        let user_subauths = captured.token.user.sub_authorities.len() as u64;
        let group_count = captured.token.groups.len() as u64;
        // ★ Does the token lsasrv minted carry a LOGON SID (`SE_GROUP_LOGON_ID`)?
        // `winlogon!AllowAccessOnSession` scans `TOKEN_GROUPS` for exactly this and dereferences an
        // UNINITIALISED local when it finds nothing (measured: a read fault at `RtlLengthSid+0x5`,
        // `ntdll+0x1acc5`, with a garbage `LogonSid`). Counted so the claim is a measurement.
        let logon_sid_groups = captured.token.groups.iter().filter(|g| g.logon_id).count() as u64;
        SE_CREATE_TOKEN_LOGON_SIDS.store(logon_sid_groups, Ordering::Relaxed);
        let privilege_count = captured.token.privileges.len() as u64;
        let authentication_id = captured.token.authentication_id;
        let token_type = captured.token.token_type;
        let source_name = u64::from_le_bytes(captured.source.name);

        let token = self.token_store.insert_created(
            captured.token,
            captured.expiration_time,
            captured.source,
        );
        let status = self.insert_owned_token_handle(caller_pid, token, desired_access, out);
        SE_CREATE_TOKEN_LAST_STATUS.store(status as u64, Ordering::Relaxed);
        if status != 0 {
            // `insert_owned_token_handle` already released the token on every failure path.
            return status;
        }
        // The token body was allocated ABOVE this iteration's bump-heap mark; pin the mark past it
        // so the minted token survives the per-syscall reset (same contract as NtDuplicateToken).
        self.token_dirty = true;
        SE_CREATE_TOKEN_MINTED.fetch_add(1, Ordering::Relaxed);
        if SE_CREATE_TOKEN_PI.load(Ordering::Relaxed) == u64::MAX {
            // Read the shape back OUT OF THE STORE, not out of the captured value, so the recorded
            // evidence is what the token object actually holds.
            let stored = self.token_store.get(token);
            SE_CREATE_TOKEN_PI.store(self.pi as u64, Ordering::Relaxed);
            SE_CREATE_TOKEN_ID.store(token.raw() as u64, Ordering::Relaxed);
            SE_CREATE_TOKEN_USER_RID.store(user_rid.unwrap_or(u32::MAX) as u64, Ordering::Relaxed);
            SE_CREATE_TOKEN_USER_SUBAUTHS.store(user_subauths, Ordering::Relaxed);
            SE_CREATE_TOKEN_GROUPS.store(
                stored.map(|t| t.groups.len() as u64).unwrap_or(group_count),
                Ordering::Relaxed,
            );
            SE_CREATE_TOKEN_PRIVS.store(
                stored
                    .map(|t| t.privileges.len() as u64)
                    .unwrap_or(privilege_count),
                Ordering::Relaxed,
            );
            SE_CREATE_TOKEN_AUTH_LUID.store(
                (authentication_id.high as u32 as u64) << 32 | authentication_id.low as u64,
                Ordering::Relaxed,
            );
            SE_CREATE_TOKEN_TYPE.store(token_type as u64, Ordering::Relaxed);
            SE_CREATE_TOKEN_SOURCE_NAME.store(source_name, Ordering::Relaxed);
            let mut handle_out = [0u8; 8];
            if self.xas_read(out, &mut handle_out) {
                SE_CREATE_TOKEN_HANDLE.store(u64::from_le_bytes(handle_out), Ordering::Relaxed);
            }
            print_str(b"[se-token] NtCreateToken minted pi=");
            print_u64(self.pi as u64);
            print_str(b" id=");
            print_u64(token.raw() as u64);
            print_str(b" type=");
            print_u64(token_type as u64);
            print_str(b" user-rid=");
            print_u64(user_rid.unwrap_or(u32::MAX) as u64);
            print_str(b" subauths=");
            print_u64(user_subauths);
            print_str(b" groups=");
            print_u64(group_count);
            print_str(b" logon-sid-groups=");
            print_u64(logon_sid_groups);
            print_str(b" privs=");
            print_u64(privilege_count);
            print_str(b" authid=0x");
            print_hex(authentication_id.high as u32);
            print_hex(authentication_id.low);
            print_str(b" source=");
            print_str(&captured_source_bytes(source_name));
            print_str(b" stack-args=");
            print_u64(SE_CREATE_TOKEN_STACK_ARGS.load(Ordering::Relaxed));
            print_str(b"/9\n");
        }
        0
    }

    unsafe fn nt_open_thread_token(&mut self, args: &[u64], extended: bool) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_CANT_OPEN_ANONYMOUS: u32 = 0xC000_00A6;
        const STATUS_NO_TOKEN: u32 = 0xC000_007C;
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;

        let out = args[if extended { 4 } else { 3 }];
        if !self.probe_user_output(out, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let tid = match self.pm.resolve_thread_handle(
            caller_pid,
            self.current_tid as nt_process::ThreadId,
            args[0],
            THREAD_QUERY_INFORMATION,
        ) {
            Ok(tid) => tid,
            Err(status) => return status,
        };
        let context = match self.pm.thread_impersonation(tid) {
            Some(context) => context,
            None => return STATUS_NO_TOKEN,
        };
        if context.level == nt_security::SecurityImpersonationLevel::Anonymous {
            return STATUS_CANT_OPEN_ANONYMOUS;
        }

        // OpenAsSelf affects the object access check identity. The current token model has no token
        // DACL yet, so both identities grant the requested mask without changing which token opens.
        let owned = if context.copy_on_open {
            match self.token_store.duplicate(
                context.token,
                nt_security::TokenType::Impersonation,
                context.level,
                context.effective_only,
            ) {
                Ok(token) => token,
                Err(status) => return status,
            }
        } else {
            if let Err(status) = self.token_store.retain(context.token) {
                return status;
            }
            context.token
        };
        let status = self.insert_owned_token_handle(caller_pid, owned, args[1] as u32, out);
        if status == 0 && context.copy_on_open {
            self.token_dirty = true;
        }
        status
    }

    unsafe fn nt_set_thread_impersonation_token(&mut self, args: &[u64]) -> u32 {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
        const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
        const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
        const TOKEN_IMPERSONATE: u32 = 0x0004;

        if args[3] != 8 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let mut captured = [0u8; 8];
        if args[2] == 0 || !self.xas_read(args[2], &mut captured) {
            return STATUS_ACCESS_VIOLATION;
        }
        let token_handle = u64::from_le_bytes(captured);
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
        let tid = match self.pm.resolve_thread_handle(
            caller_pid,
            self.current_tid as nt_process::ThreadId,
            args[0],
            THREAD_SET_THREAD_TOKEN,
        ) {
            Ok(tid) => tid,
            Err(status) => return status,
        };

        let replacement = if token_handle == 0 {
            None
        } else {
            let token = match self.token_id_for_handle(token_handle, TOKEN_IMPERSONATE) {
                Ok(token) => token,
                Err(status) => return status,
            };
            let (token_type, level) = match self.token_store.get(token) {
                Some(token) => (token.token_type, token.impersonation_level),
                None => return nt_process::STATUS_INVALID_HANDLE,
            };
            if token_type != nt_security::TokenType::Impersonation {
                return STATUS_BAD_TOKEN_TYPE;
            }
            if let Err(status) = self.token_store.retain(token) {
                return status;
            }
            Some(nt_process::ImpersonationContext {
                token,
                copy_on_open: false,
                effective_only: false,
                level,
            })
        };

        let old = match self.pm.replace_thread_impersonation(tid, replacement) {
            Ok(old) => old,
            Err(status) => {
                if let Some(context) = replacement {
                    let _ = self.token_store.release(context.token);
                }
                return status;
            }
        };

        let teb = self
            .pm
            .thread(tid)
            .map(|thread| thread.teb_base)
            .unwrap_or(0);
        let teb = if teb != 0 {
            teb
        } else if tid == self.current_tid as nt_process::ThreadId {
            if self.current_process_is_smss() {
                SMSS_TEB_VA
            } else {
                TEB_VA
            }
        } else {
            0
        };
        if teb != 0 {
            let mut state = [0u8; 8];
            state[..4]
                .copy_from_slice(&(if replacement.is_some() { u32::MAX } else { 0 }).to_le_bytes());
            state[4] = u8::from(replacement.is_some());
            if !self.xas_try_write_buf(
                teb + nt_ntdll_layout::TEB_IMPERSONATION_LOCALE_OFFSET,
                &state,
            ) {
                let _ = self.pm.replace_thread_impersonation(tid, old);
                if let Some(context) = replacement {
                    let _ = self.token_store.release(context.token);
                }
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if let Some(context) = old {
            let _ = self.token_store.release(context.token);
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

        let required_access =
            TOKEN_ADJUST_PRIVILEGES | if previous_state != 0 { TOKEN_QUERY } else { 0 };
        let token_id = match self.token_id_for_handle(args[0], required_access) {
            Ok(token) => token,
            Err(status) => return status,
        };
        let plan = match self.token_store.get(token_id) {
            Some(token) => token.plan_privilege_adjustment(disable_all, &requested),
            None => return nt_process::STATUS_INVALID_HANDLE,
        };
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
        let result = match self.token_store.adjust_privileges(
            token_id,
            disable_all,
            &requested,
            &mut previous[..plan.changed],
        ) {
            Ok(result) => result,
            Err(status) => return status,
        };
        if previous_state != 0 {
            let mut output = [0u8; 4 + 24 * 12];
            output[..4].copy_from_slice(&(result.changed as u32).to_le_bytes());
            for (index, privilege) in previous[..result.changed].iter().enumerate() {
                let offset = 4 + index * 12;
                output[offset..offset + 4].copy_from_slice(&privilege.luid.low.to_le_bytes());
                output[offset + 4..offset + 8].copy_from_slice(&privilege.luid.high.to_le_bytes());
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
            let _ = self.close_process_handle(pid, handle);
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
        if !self.xas_read(oa_va + 0x10, &mut p) {
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
        if !self.xas_read(ustr_va, &mut lm) || !self.xas_read(ustr_va + 8, &mut bp) {
            return alloc::vec::Vec::new();
        }
        let buffer_va = u64::from_le_bytes(bp);
        let n = ((u16::from_le_bytes(lm) as usize) / 2).min(1024);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let va = buffer_va + (i as u64) * 2;
            let mut w = [0u8; 2];
            if self.xas_read(va, &mut w) {
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
    /// (main image / ntdll / a registered DLL). Hosted GUI/service registry strings are often
    /// `RTL_CONSTANT_STRING` literals in DLL `.rdata` pages the process never dereferences (the
    /// executive is the first reader), so the page is not demand-faulted and not in any mirror or
    /// frame table — but its bytes are exactly the (relocation-free) `.rdata` file content, which we
    /// read via the loaded PE. Handles a read that spans a page boundary.
    pub(crate) unsafe fn xas_read(&self, va: u64, dst: &mut [u8]) -> bool {
        if va.checked_add(dst.len() as u64).is_none() {
            return false;
        }
        let dynamic_stack =
            self.current_process_is_winlogon() && wl_listener_stack_contains(va, dst.len());
        if dynamic_stack {
            let Some(ctx) = self.loop_ctx.as_ref() else {
                return false;
            };
            return client_copyin_mapped(
                self.pi as u64,
                va,
                dst,
                &*ctx.filled_pages,
                *ctx.faults as usize,
                ctx.scratch_base,
            );
        }
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
    /// [`client_copyout_or_fill_mapped`] (mirror → backed page alias → demand-fill from the DLL PE).
    /// No-op if there is no loop context. Used for hosted-process NtOpenKey handle copyout.
    pub(crate) unsafe fn xas_write_u64(&self, va: u64, val: u64) -> bool {
        if let Some(ctx) = self.loop_ctx {
            let filled_pages = &mut *ctx.filled_pages;
            let faults = &mut *ctx.faults;
            let reg = &*ctx.reg;
            let dll_pes = ctx.dll_pes();
            client_copyout_or_fill_mapped(
                self.pi as u64,
                va,
                &val.to_le_bytes(),
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

    /// Publish the two user-visible outputs of a successful `NtCreateProcess[Ex]`: the process
    /// handle and the child PEB pointer returned through the creator TEB's ArbitraryUserPointer.
    pub(crate) unsafe fn publish_created_process(
        &self,
        process_handle_out: u64,
        process_handle: u64,
        child_peb: u64,
    ) -> bool {
        let Some(teb) = self
            .pm
            .thread_teb(self.current_tid as nt_process::ThreadId)
            .filter(|teb| *teb != 0)
        else {
            return false;
        };
        let Some(peb_out) = teb.checked_add(nt_ntdll_layout::TEB_ARBITRARY_USER_POINTER_OFFSET)
        else {
            return false;
        };
        self.xas_write_u64(peb_out, child_peb)
            && self.xas_write_u64(process_handle_out, process_handle)
    }

    /// Cross-address-space DWORD copyout without imposing 8-byte alignment on the user pointer.
    pub(crate) unsafe fn xas_write_u32(&self, va: u64, val: u32) -> bool {
        if let Some(ctx) = self.loop_ctx {
            let filled_pages = &mut *ctx.filled_pages;
            let faults = &mut *ctx.faults;
            let reg = &*ctx.reg;
            let dll_pes = ctx.dll_pes();
            client_copyout_or_fill_mapped(
                self.pi as u64,
                va,
                &val.to_le_bytes(),
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

    /// Probe an arbitrary readable user range, including image and DLL `.rdata` that has not faulted
    /// into the process yet.
    pub(crate) unsafe fn probe_user_input(&self, va: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if va == 0 || va.checked_add(len as u64).is_none() {
            return false;
        }
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
        true
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
        if self.current_process_is_winlogon() && wl_listener_stack_contains(va, len) {
            return client_range_has_backing(self.pi as u64, va, len);
        }
        let stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
        let stack_end = stack_base + ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
        if va >= stack_base && end <= stack_end
            || va >= SMSS_ALLOC_VA && end <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW
        {
            return true;
        }
        // ★ A hosted thread's stack GROWS BELOW its declared window. `ACTIVE_STACK_BASE/SIZE` are
        // the pages the spawn pre-mapped; a deeper frame simply faults and the service loop
        // demand-maps it, so a legitimate buffer can sit below `stack_base` and still be fully
        // backed. kernel32's `FindFirstFileExW` is exactly that case — it puts a 16 KiB
        // `DECLSPEC_ALIGN(4) BYTE DirectoryInfo[FIND_DATA_SIZE]` scratch buffer plus its
        // IO_STATUS_BLOCK on the caller's stack (`kernel32/client/file/find.c:694`), which for
        // winlogon lands ~12 KiB below the 16 KiB declared window. The window test alone called
        // that unreachable, so `NtQueryDirectoryFile` returned STATUS_ACCESS_VIOLATION and
        // `CopyDirectory` reported `GetLastError() == 998` (ERROR_NOACCESS).
        //
        // This clause is a strictly MONOTONE widening: it runs only where the code already
        // returned false, and it does not assume anything — it asks whether every page of the
        // range REALLY has backing in the caller's VSpace, the same `client_range_has_backing`
        // test the winlogon listener stack above already uses. Unmapped memory is still refused.
        const STACK_GROWTH_WINDOW: u64 = 0x10_0000; // 1 MiB, the PE's committed stack reserve
        if end <= stack_end && va >= stack_base.saturating_sub(STACK_GROWTH_WINDOW) {
            return client_range_has_backing(self.pi as u64, va, len);
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
                    && unsafe { scratch_for(page, filled_pages, faults, ctx.scratch_base) }
                        .is_none()
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
    /// Used for hosted-process registry info-structure copyout (KEY_*_INFORMATION into a heap buffer).
    pub(crate) unsafe fn xas_write_buf(&self, va: u64, src: &[u8]) {
        let _ = self.xas_try_write_buf(va, src);
    }

    pub(crate) unsafe fn xas_try_write_buf(&self, va: u64, src: &[u8]) -> bool {
        let dynamic_stack =
            self.current_process_is_winlogon() && wl_listener_stack_contains(va, src.len());
        if dynamic_stack {
            let Some(ctx) = self.loop_ctx.as_ref() else {
                return false;
            };
            return client_copyout_mapped(
                self.pi as u64,
                va,
                src,
                &*ctx.filled_pages,
                *ctx.faults as usize,
                ctx.scratch_base,
            );
        }
        if smss_copyout(va, src) {
            return true;
        }
        if let Some(ctx) = self.loop_ctx.as_ref() {
            if client_copyout_mapped(
                self.pi as u64,
                va,
                src,
                &*ctx.filled_pages,
                *ctx.faults as usize,
                ctx.scratch_base,
            ) {
                return true;
            }
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
    /// hosted-process registry name strings (key names + value names).
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

    unsafe fn read_directory_pattern(
        &self,
        ustr_va: u64,
        output: &mut [u16; nt_fs::MAX_DIRECTORY_NAME],
    ) -> Result<usize, u32> {
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        if ustr_va == 0 {
            return Ok(0);
        }
        let mut header = [0u8; 16];
        if !self.xas_read(ustr_va, &mut header) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let byte_len = u16::from_le_bytes([header[0], header[1]]) as usize;
        let maximum_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if byte_len & 1 != 0 || byte_len > maximum_len || byte_len / 2 > output.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if byte_len == 0 {
            return Ok(0);
        }
        if buffer == 0 {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let mut bytes = [0u8; nt_fs::MAX_DIRECTORY_NAME * 2];
        if !self.xas_read(buffer, &mut bytes[..byte_len]) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        for index in 0..byte_len / 2 {
            output[index] = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
        }
        Ok(byte_len / 2)
    }
    /// Cross-AS OBJECT_ATTRIBUTES.ObjectName read (OA+0x10 → PUNICODE_STRING) via [`read_ustr_pe`],
    /// so a name Buffer in a not-yet-faulted DLL `.rdata` page resolves from the PE. Used for hosted
    /// process registry key opens (see `read_objattr_name`, whose scratch-alias fallback only reaches
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

    /// Render a complete FILE_BASIC_INFORMATION with the backing volume's real attributes. This
    /// volume does not track timestamps, so zero is the honest value for all four time fields.
    unsafe fn write_file_basic_attributes(&self, output: u64, attributes: u32) -> bool {
        let mut basic = [0u8; 40];
        basic[0x20..0x24].copy_from_slice(&attributes.to_le_bytes());
        self.xas_try_write_buf(output, &basic)
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

    fn rollback_new_mutant(&mut self, index: usize) {
        if index + 1 == self.obj_ns.len() {
            self.obj_ns.pop();
            self.mutants.remove(index as u64);
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
                        wide <= 0x7f
                            && (wide as u8).to_ascii_lowercase() == ascii.to_ascii_lowercase()
                    })
        })
    }

    fn lpc_name_equals_ascii(name16: &[u16], expected: &[u8]) -> bool {
        name16.len() == expected.len()
            && name16.iter().zip(expected.iter()).all(|(&wide, &ascii)| {
                wide <= 0x7f && (wide as u8).to_ascii_lowercase() == ascii.to_ascii_lowercase()
            })
    }

    pub(crate) unsafe fn connect_srm_command_port(
        &mut self,
        name16: &[u16],
        subsystem_type: u32,
        conn_info: &[u8],
        port_handle_out: u64,
    ) -> u32 {
        const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

        let Some(listen_handle) = self.lpc_port_handle_for_name16(name16) else {
            print_str(b"[srm-rdv] \\SeRmCommandPort is not registered in the LPC broker\n");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };

        let Some(lpc) = lpc_client() else {
            print_str(b"[srm-rdv] LPC broker unavailable for \\SeRmCommandPort connect\n");
            return STATUS_UNSUCCESSFUL;
        };
        let connect = match lpc.connect_port(name16, subsystem_type, conn_info) {
            Ok(connect) if connect.pending && connect.connection_id != 0 => connect,
            Ok(connect) => {
                print_str(b"[srm-rdv] expected a pending broker connection, got handle=0x");
                print_hex((connect.handle >> 32) as u32);
                print_hex(connect.handle as u32);
                print_str(b" pending=");
                print_u64(connect.pending as u64);
                print_str(b"\n");
                return STATUS_UNSUCCESSFUL;
            }
            Err(status) => {
                print_str(b"[srm-rdv] broker rejected \\SeRmCommandPort connect status=0x");
                print_hex(status.raw() as u32);
                print_str(b"\n");
                return status.raw() as u32;
            }
        };

        match lpc.reply_wait_receive(listen_handle) {
            Ok(received)
                if received.connection_id == connect.connection_id
                    && received.msg_type == nt_lpc_client::LPC_CONNECTION_REQUEST => {}
            Ok(received) => {
                print_str(b"[srm-rdv] broker receive returned unexpected conn=");
                print_u64(received.connection_id);
                print_str(b" type=");
                print_u64(received.msg_type as u64);
                print_str(b"\n");
                return STATUS_UNSUCCESSFUL;
            }
            Err(status) => {
                print_str(b"[srm-rdv] broker receive failed status=0x");
                print_hex(status.raw() as u32);
                print_str(b"\n");
                return status.raw() as u32;
            }
        }

        let server_handle = match lpc.accept_connect(connect.connection_id, true, 0) {
            Ok(handle) if handle != 0 => handle,
            Ok(_) => {
                print_str(
                    b"[srm-rdv] broker accepted \\SeRmCommandPort with a null server handle\n",
                );
                return STATUS_UNSUCCESSFUL;
            }
            Err(status) => {
                print_str(b"[srm-rdv] broker accept failed status=0x");
                print_hex(status.raw() as u32);
                print_str(b"\n");
                return status.raw() as u32;
            }
        };

        let client_handle = match lpc.complete_connect(connect.connection_id) {
            Ok((client_handle, completed_id))
                if client_handle != 0 && completed_id == connect.connection_id =>
            {
                client_handle
            }
            Ok((client_handle, completed_id)) => {
                print_str(b"[srm-rdv] broker complete returned client=0x");
                print_hex((client_handle >> 32) as u32);
                print_hex(client_handle as u32);
                print_str(b" conn=");
                print_u64(completed_id);
                print_str(b"\n");
                return STATUS_UNSUCCESSFUL;
            }
            Err(status) => {
                print_str(b"[srm-rdv] broker complete failed status=0x");
                print_hex(status.raw() as u32);
                print_str(b"\n");
                return status.raw() as u32;
            }
        };

        self.queue_write(port_handle_out, client_handle);
        self.cache_lpc_connection(connect.connection_id, client_handle, name16);
        LSASS_SRM_CONNECTED.store(1, Ordering::Relaxed);
        print_str(b"[srm-rdv] kernel SRM accepted \\SeRmCommandPort conn=");
        print_u64(connect.connection_id);
        print_str(b" server=0x");
        print_hex((server_handle >> 32) as u32);
        print_hex(server_handle as u32);
        print_str(b" client=0x");
        print_hex((client_handle >> 32) as u32);
        print_hex(client_handle as u32);
        print_str(b"\n");
        0
    }

    pub(crate) unsafe fn service_srm_request_reply(&mut self, reqmsg: u64, replymsg: u64) -> u32 {
        const PORT_MESSAGE_HEADER_LEN: u64 = 0x28;
        const SRM_API_OFFSET: u64 = PORT_MESSAGE_HEADER_LEN;
        const SRM_RESULT_OFFSET: u64 = PORT_MESSAGE_HEADER_LEN + 4;
        const SRM_LUID_OFFSET: u64 = PORT_MESSAGE_HEADER_LEN + 4;
        const RM_AUDIT_SET_COMMAND: u32 = 1;
        const RM_CREATE_LOGON_SESSION: u32 = 2;
        const RM_DELETE_LOGON_SESSION: u32 = 3;
        const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

        let mut header = [0u8; 4];
        if !self.xas_read(reqmsg, &mut header) {
            return STATUS_ACCESS_VIOLATION;
        }
        let total_len = u16::from_le_bytes([header[2], header[3]]) as u64;
        let mut api_bytes = [0u8; 4];
        if total_len < SRM_API_OFFSET + 4 || !self.xas_read(reqmsg + SRM_API_OFFSET, &mut api_bytes)
        {
            return STATUS_INVALID_PARAMETER;
        }

        let api_number = u32::from_le_bytes(api_bytes);
        let mut result_status = 0u32;
        let mut luid = [0u8; 8];
        match api_number {
            RM_AUDIT_SET_COMMAND => {}
            RM_CREATE_LOGON_SESSION | RM_DELETE_LOGON_SESSION => {
                if total_len < SRM_LUID_OFFSET + 8
                    || !self.xas_read(reqmsg + SRM_LUID_OFFSET, &mut luid)
                {
                    result_status = STATUS_INVALID_PARAMETER;
                }
            }
            _ => {
                result_status = STATUS_INVALID_PARAMETER;
            }
        }

        if replymsg == 0
            || !self.xas_try_write_buf(
                replymsg + 0x04,
                &nt_lpc_abi::msg_type::LPC_REPLY.to_le_bytes(),
            )
            || !self.xas_try_write_buf(replymsg + SRM_RESULT_OFFSET, &result_status.to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }

        print_str(b"[srm] serviced \\SeRmCommandPort ApiNumber=");
        print_u64(api_number as u64);
        if matches!(
            api_number,
            RM_CREATE_LOGON_SESSION | RM_DELETE_LOGON_SESSION
        ) && result_status == 0
        {
            print_str(b" luid=0x");
            print_hex(u32::from_le_bytes(luid[4..8].try_into().unwrap()));
            print_hex(u32::from_le_bytes(luid[0..4].try_into().unwrap()));
        }
        print_str(b" status=0x");
        print_hex(result_status);
        print_str(b"\n");
        0
    }

    /// Service a Win32 process' kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort).
    ///
    /// csrss owns \Windows\ApiPort and pending connects are completed by the real
    /// CsrApiRequestThread rendezvous. The executive still fills the CSR connect reply payload the
    /// client reads back, because the isolated LPC broker does not carry that payload yet.
    /// kernel32's BaseDllInitialize is FATAL on a failed connect and then
    /// dereferences the shared static server data (`Peb->ReadOnlyStaticServerData[BASESRV]->
    /// WindowsDirectory`), so this must hand back real, mapped memory:
    ///  - `ClientView` (PORT_VIEW LpcWrite) ViewBase = a 64 KiB RW region kernel32 RtlCreateHeaps over.
    ///  - `ConnectionInfo` (CSR_API_CONNECTINFO) SharedSectionBase/Heap, SharedStaticServerData (→ an
    ///    array whose [BASESRV=1] slot points at a BASE_STATIC_SERVER_DATA with valid Windows dirs),
    ///    and ServerProcessId.
    /// All out-params are client STACK locals (ConnectionInfo/LpcWrite) reached via the mirror; the
    /// backing regions are mapped into the client's own VSpace (lazily, once). Returns STATUS_SUCCESS.
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
        // (1) Connect through the broker (Pending under Manual). Authentic accept mirrors the SM path:
        // record the pending connection id + caller *PortHandle so the loop drives `csr_rendezvous`.
        // csrss's real CsrApiRequestThread must issue NtReplyWaitReceivePort →
        // CsrApiHandleConnectionRequest → NtAcceptConnectPort → NtCompleteConnectPort. Synchronous
        // broker handles and locally minted handles bypass that server boundary and are rejected.
        if !self.current_process_uses_csr_client_connect() {
            print_str(b"[csr] NtSecureConnectPort(\\Windows\\ApiPort) from non-CSR client role -> failing\n");
            CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
            return 0xC000_0001;
        }
        if self.lpc_port_handle_for_name16(name16).is_none() {
            print_str(b"[csr] NtSecureConnectPort(\\Windows\\ApiPort) has no named port object -> failing\n");
            CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
            return 0xC000_0034;
        }
        let mut pending = false;
        if let Some(c) = lpc_client() {
            match c.connect_port(name16, 2, &[]) {
                Ok(r) if r.pending && r.connection_id != 0 => {
                    self.csr_rendezvous_conn = r.connection_id;
                    self.csr_rendezvous_out = porthandle_ptr;
                    pending = true;
                }
                Ok(r) => {
                    print_str(b"[csr] broker returned non-pending ApiPort connect; handle=0x");
                    print_hex((r.handle >> 32) as u32);
                    print_hex(r.handle as u32);
                    print_str(b" conn=");
                    print_u64(r.connection_id);
                    print_str(b" -> failing, CSR accept must be real\n");
                }
                Err(_) => {
                    print_str(
                        b"[csr] broker failed NtSecureConnectPort(\\Windows\\ApiPort) -> failing\n",
                    );
                }
            }
        } else {
            print_str(b"[csr] LPC broker unavailable for NtSecureConnectPort(\\Windows\\ApiPort) -> failing\n");
        }
        if !pending {
            CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
            return 0xC000_0001;
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
                    // WindowsDirectory = L"C:\Windows" (10 wchars)
                    core::ptr::write_volatile((bssd + 0x00) as *mut u16, 10 * 2);
                    core::ptr::write_volatile((bssd + 0x02) as *mut u16, 11 * 2);
                    core::ptr::write_volatile(
                        (bssd + 0x08) as *mut u64,
                        WINLOGON_CSR_STATIC_VA + 0x3000,
                    );
                    // WindowsSystemDirectory = L"C:\Windows\System32" (19 wchars)
                    core::ptr::write_volatile((bssd + 0x10) as *mut u16, 19 * 2);
                    core::ptr::write_volatile((bssd + 0x12) as *mut u16, 20 * 2);
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
                    // BASE_STATIC_SERVER_DATA.SysInfo starts at +0x140 on x64. ReactOS kernel32
                    // consumes PageSize and AllocationGranularity here when creating every thread
                    // stack, so publish the same record as NtQuerySystemInformation class 0.
                    let sysinfo = native_basic_system_information().encode();
                    core::ptr::copy_nonoverlapping(
                        sysinfo.as_ptr(),
                        (bssd + 0x140) as *mut u8,
                        sysinfo.len(),
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
        // (5) *PortHandle = &CsrApiPort (an ntdll .data global). The loop writes the real client
        // communication-port handle after `csr_rendezvous` completes the pending connection.
        WINLOGON_CSR_CONNECTED.store(1, Ordering::Relaxed);
        CSR_CONNECTED_MASK.fetch_or(1u64 << self.pi, Ordering::Relaxed);
        print_str(b"[csr] pi=");
        print_u64(self.pi as u64);
        print_str(
            b" NtSecureConnectPort(\\Windows\\ApiPort) -> queued REAL CsrApiRequestThread accept; conn=",
        );
        print_u64(self.csr_rendezvous_conn);
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
        if kind == OBJ_KIND_SYMBOLIC_LINK {
            let t = target.len().min(40);
            e.target[..t].copy_from_slice(&target[..t]);
            e.target_len = t as u8;
        }
        self.obj_ns.push(e);
        Some(self.obj_ns.len() - 1)
    }

    pub(crate) fn lpc_port_handle_by_ascii(&self, path: &[u8]) -> Option<u64> {
        let index = self.obj_resolve(path, 0)?;
        let entry = self.obj_ns.get(index)?;
        if entry.kind == OBJ_KIND_LPC_PORT && entry.payload != 0 {
            Some(entry.payload)
        } else {
            None
        }
    }

    pub(crate) fn lpc_port_handle_for_name16(&self, name16: &[u16]) -> Option<u64> {
        let mut nbuf = [0u8; 40];
        let nlen = Self::fold_name(name16, &mut nbuf);
        if nlen == 0 {
            return None;
        }
        self.lpc_port_handle_by_ascii(&nbuf[..nlen])
    }

    pub(crate) fn register_lpc_port_object(
        &mut self,
        name16: &[u16],
        root_idx: usize,
        handle: u64,
    ) -> Result<usize, u32> {
        const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
        const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

        if handle == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let mut nbuf = [0u8; 40];
        let nlen = Self::fold_name(name16, &mut nbuf);
        if nlen == 0 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if let Some(index) = self.obj_resolve(&nbuf[..nlen], root_idx) {
            if self.obj_ns[index].kind != OBJ_KIND_LPC_PORT {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            self.obj_ns[index].payload = handle;
            return Ok(index);
        }
        let Some(index) = self.obj_create(&nbuf[..nlen], root_idx, OBJ_KIND_LPC_PORT, &[]) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        self.obj_ns[index].payload = handle;
        Ok(index)
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
        e.kind = OBJ_KIND_EVENT;
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
        entry.kind = OBJ_KIND_SEMAPHORE;
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

    pub(crate) fn obj_create_anon_mutant(&mut self, initial_owner: Option<u64>) -> Option<usize> {
        if self.obj_ns.len() >= self.obj_ns.capacity() {
            return None;
        }
        let n = self.anon_event_seq;
        self.anon_event_seq = self.anon_event_seq.wrapping_add(1);
        let name = [
            b'm',
            (n & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
        ];
        let mut entry = ObjEntry::dir(&name, 250);
        entry.kind = OBJ_KIND_MUTANT;
        self.obj_ns.push(entry);
        let index = self.obj_ns.len() - 1;
        self.mutants.initialize(index as u64, initial_owner);
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
        // ★ `\Registry\User\…` — the per-user hive namespace, served by the mount table so every
        // generic consumer of `resolve_key` (path-exists, value/subkey reads, `NtCreateKey`'s
        // parent check, the overlay's base-hive fall-through) composes with a loaded hive for free.
        if comps.len() >= 3
            && comps[0].eq_ignore_ascii_case("Registry")
            && comps[1].eq_ignore_ascii_case("User")
        {
            return self.resolve_user_key(&aliased);
        }
        if comps.len() < 3
            || !comps[0].eq_ignore_ascii_case("Registry")
            || !comps[1].eq_ignore_ascii_case("Machine")
        {
            return None;
        }
        // The FOUR REAL mounted regf hives. SYSTEM is untagged (its cell offsets ARE the KeyRef);
        // SOFTWARE, SECURITY and SAM carry a hive-selector tag in the top nibble so a later
        // handle→hive resolution can't confuse them (see `hive_sel`/`base_hive`).
        if comps[2].eq_ignore_ascii_case("System") {
            return self.hive.as_ref()?.open_key(&comps[3..].join("\\"));
        }
        if comps[2].eq_ignore_ascii_case("SECURITY") {
            let cell = self
                .security_hive
                .as_ref()?
                .open_key(&comps[3..].join("\\"))?;
            return Some(HIVE_SEL_SECURITY | cell);
        }
        if comps[2].eq_ignore_ascii_case("SAM") {
            let cell = self.sam_hive.as_ref()?.open_key(&comps[3..].join("\\"))?;
            return Some(HIVE_SEL_SAM | cell);
        }
        // The 4th mount — the REAL 471040 B SOFTWARE hive at `\Registry\Machine\SOFTWARE`. Placed
        // last so no pre-existing resolution changes: before it, every non-Winlogon Software key
        // fell out of this function as `None`.
        if comps[2].eq_ignore_ascii_case("SOFTWARE") {
            let cell = self
                .software_hive
                .as_ref()?
                .open_key(&comps[3..].join("\\"))?;
            return Some(HIVE_SEL_SOFTWARE | cell);
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
    /// Does `\reactos\<leaf>` exist as a regular file on the executive's mounted FAT volume?
    /// `explorer.exe` is a shell image at `%SystemRoot%`, not System32, so its admission has to use
    /// the same real-FS root lookup as the PE preloader instead of the caller's transient DOS path.
    fn fs_reactos_root_has_file(leaf: &[u8]) -> bool {
        if leaf.is_empty() {
            return false;
        }
        unsafe {
            let Some(fs) = exec_fs() else {
                return false;
            };
            let mut path = [0u8; 96];
            let mut n = 0usize;
            for &c in b"reactos\\" {
                path[n] = c;
                n += 1;
            }
            for &c in leaf {
                if n == path.len() {
                    return false;
                }
                path[n] = c;
                n += 1;
            }
            fat_open_path(&fs, &path[..n]).is_some()
        }
    }

    fn hosted_image_exists(image: nt_exe_image::HostedProcessImageRef<'_>) -> bool {
        match image.image_root {
            nt_exe_image::HostedImageRoot::System32 => unsafe { sys32_exists(image.leaf) },
            nt_exe_image::HostedImageRoot::SystemRoot => Self::fs_reactos_root_has_file(image.leaf),
        }
    }

    /// Classify a folded probe path through the runtime hosted-executable catalog and return the
    /// registered image entry, so existence resolves against the real file and its registered root
    /// rather than a possibly-malformed extracted leaf.
    /// `None` if it isn't a recognized EXE probe or if it's an SxS/actctx probe (which must fail so
    /// the loader doesn't take the .Local\/manifest path). The caller still confirms the leaf on the
    /// real FS.
    fn exe_probe_image<'a>(
        catalog: &'a nt_exe_image::OwnedHostedImageCatalog<8>,
        folded: &[u8],
        is_sxs: bool,
    ) -> Option<nt_exe_image::HostedProcessImageRef<'a>> {
        catalog.probe_image(folded, is_sxs)
    }
}
impl NativeSyscallHandler for ExecNtHandler {
    /// The dispatcher's entry point. It is a thin wrapper so that ONE thing is guaranteed to run
    /// after **every** service arm however it returned (most arms `return` early from the giant
    /// match): the debug-object signal mirror. Any arm that queues a debug event — the five dbgk
    /// services, and equally the `nt-process` lifecycle sources reached through
    /// `NtCreateThread`/`NtTerminateThread`/`NtTerminateProcess` — therefore signals the dispatcher
    /// event a parked `NtWaitForDebugEvent` waits on. With no debug object alive (the plain boot)
    /// this is a single load and a branch.
    fn handle(
        &mut self,
        ctx: &NativeCallContext,
        args: &[u64],
        out: &mut alloc::vec::Vec<u8>,
    ) -> u32 {
        let status = self.handle_service(ctx, args, out);
        self.sync_debug_object_signals();
        status
    }
}

impl NativeSyscallHandler for &mut ExecNtHandler {
    fn handle(
        &mut self,
        ctx: &NativeCallContext,
        args: &[u64],
        out: &mut alloc::vec::Vec<u8>,
    ) -> u32 {
        <ExecNtHandler as NativeSyscallHandler>::handle(&mut **self, ctx, args, out)
    }
}

impl ExecNtHandler {
    fn handle_service(
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
            // bindings — the per-pi DLL registry — consistent). Handles explicitly marked
            // protect-from-close now fail like NT; a close of a handle the executive doesn't own
            // stays benign for the hosted boot path. A win32k USER-object handle is closed through
            // that owning table so a duplicated desktop handle has an independent lifetime.
            NativeService::NtClose => {
                let mut closed = false;
                if let Some(loop_ctx) = self.loop_ctx {
                    unsafe {
                        let _ = (&mut *loop_ctx.exe_images).close(self.pi, args[0]);
                    }
                }
                if let Some(pid) = self.pm_pid_for_pi(self.pi) {
                    match self.close_process_handle_checked(pid, args[0]) {
                        Ok(was_closed) => closed = was_closed,
                        Err(status) => return status,
                    }
                }
                if !closed && unsafe { crate::win32k_subsystem::close_user_object_handle(args[0]) }
                {
                    PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                }
                0 // STATUS_SUCCESS
            }
            // NtAllocateLocallyUniqueId(*LocallyUniqueId[R10]) — `ExAllocateLocallyUniqueId`
            // (`references/reactos/ntoskrnl/ex/uuid.c:335`): atomically post-increment the global
            // `ExpLuid` (seeded at `0x3e9`, increment 1) and return the PREVIOUS value. This is the
            // real kernel primitive every logon-session identity is minted from — msgina's
            // `MyLogonUser` calls it for the interactive logon's `LogonId` before `LsaLogonUser`.
            NativeService::NtAllocateLocallyUniqueId => {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                if args[0] == 0 {
                    return STATUS_ACCESS_VIOLATION;
                }
                let luid = EXP_LUID.fetch_add(1, Ordering::Relaxed);
                if unsafe { !self.xas_write_u64(args[0], luid) } {
                    self.queue_write(args[0], luid);
                }
                0
            }
            NativeService::NtOpenProcess => unsafe {
                self.nt_open_process(args[0], args[1] as u32, args[2], args[3])
            },
            NativeService::NtOpenThread => unsafe {
                self.nt_open_thread(args[0], args[1] as u32, args[2], args[3])
            },
            NativeService::NtQueryInformationThread => unsafe {
                self.nt_query_information_thread(
                    args[0],
                    args[1] as u32,
                    args[2],
                    args[3] as u32,
                    args[4],
                )
            },
            NativeService::NtIsProcessInJob => {
                // No hosted process is currently assigned to a job object. Still validate the process
                // handle so callers get a real handle-table answer before the "not in job" result.
                const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
                match self.resolve_process_for_access(args[0], PROCESS_QUERY_INFORMATION) {
                    Ok(_) => 0,
                    Err(status) => status,
                }
            },
            // NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, *TargetHandle,
            // DesiredAccess, HandleAttributes, Options). Resolve both process handles in the
            // caller's table, then duplicate the typed object into the target EPROCESS table. This
            // preserves shared identities such as msgina's worker-completion event instead of
            // copying an unowned scalar handle value.
            NativeService::NtDuplicateObject => {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
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
                    let user_same_process_duplicate =
                        source_pid == target_pid && options & DUPLICATE_SAME_ACCESS != 0;
                    if user_same_process_duplicate {
                        if let Some(handle) = unsafe {
                            crate::win32k_subsystem::duplicate_user_object_handle(args[1])
                        } {
                            Ok(Some(handle))
                        } else {
                            match self.duplicate_process_handle_with_access(
                                source_pid,
                                args[1] as nt_process::Handle,
                                target_pid,
                                desired_access,
                            ) {
                                Ok(handle) => {
                                    native_duplicate = true;
                                    Ok(Some(handle as u64))
                                }
                                Err(status) => Err(status),
                            }
                        }
                    } else {
                        match self.duplicate_process_handle_with_access(
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
                    }
                };

                if options & DUPLICATE_CLOSE_SOURCE != 0 {
                    let closed_native = self.close_process_handle(source_pid, args[1]);
                    if closed_native
                        || unsafe {
                            crate::win32k_subsystem::close_user_object_handle(args[1])
                        }
                    {
                        if !closed_native {
                            PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                        }
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
                        if !unsafe { self.xas_write_u64(args[3], handle) } {
                            if native_duplicate {
                                let _ = self.close_process_handle(
                                    target_pid_for_peak.unwrap(),
                                    handle,
                                );
                            } else {
                                let _ = unsafe {
                                    crate::win32k_subsystem::close_user_object_handle(handle)
                                };
                            }
                            return STATUS_ACCESS_VIOLATION;
                        }
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
                // Noninteractive services: RegOpenKeyExW key-name strings are RTL_CONSTANT_STRING
                // literals in DLL `.rdata` pages that the process NEVER dereferences (the
                // executive is the first reader), so the page is not demand-faulted → unreachable by
                // the mirror/frame table. Read the static content straight from the backing PE image
                // (`read_objattr_name_pe`). Scoped by hosted image role so winlogon/csrss paint-time
                // OA-name reads stay mirror-only (byte-identical).
                let name16 = if self.current_process_is_noninteractive_service() {
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
                let root_target = if root_dir == 0 {
                    None
                } else {
                    match self.resolve_registry_key(root_dir, 0) {
                        Ok(target) => Some(target),
                        Err(status) => return status,
                    }
                };
                // IFEO leaf names can be counted strings in an untouched image/ntdll `.rdata`
                // page. Recover them through the PE-aware reader only when the relative root is the
                // real IFEO overlay; keep legacy paint-time name handling unchanged everywhere else.
                let root_is_ifeo = root_target
                    .and_then(|target| self.registry_target_path(target))
                    .is_some_and(|root| {
                        root.ends_with(r"\image file execution options")
                    });
                if path.is_empty() && root_is_ifeo {
                    for &w in &self.read_objattr_name_pe(oa) {
                        if let Some(c) = char::from_u32(w as u32) {
                            path.push(c);
                        }
                    }
                }
                if let Some(status) = self.open_explorer_classes_key(root_target, &path, oa, args) {
                    return status;
                }
                if let Some(status) = self.open_hosted_machine_key(root_target, &path, oa, args) {
                    return status;
                }
                // Registry overlays are machine-global, so keys created by configuration code must
                // be openable by every process. This is especially important for loader IFEO keys:
                // a configured image option may be created by services/setup and consumed while
                // SMSS, CSRSS, or winlogon loads an image. Restricting overlay lookup to pi 3/4 made
                // those real values permanently unreachable. This exact-key lookup changes nothing
                // when the overlay is empty and does not synthesize missing SOFTWARE paths.
                let overlay_full = if root_target == Some(MACHINE_ROOT_KEY) {
                    let mut full = alloc::string::String::from(r"\Registry\Machine\");
                    full.push_str(&path);
                    Some(full)
                } else if let Some(parent) =
                    root_target.and_then(|target| self.registry_target_path(target))
                {
                    let mut full = parent;
                    if !path.is_empty() {
                        full.push('\\');
                        full.push_str(&path);
                    }
                    Some(full)
                } else if root_target.is_none() {
                    Some(path.clone())
                } else {
                    None
                };
                if let Some(ref full) = overlay_full {
                    let canon = self.overlay_canon(full);
                    if let Some(index) = self.overlay.find(&canon) {
                        if Self::is_dynamic_user_volatile_env_canon(&canon) {
                            USER_VOLATILE_ENV_OPENED.fetch_add(1, Ordering::Relaxed);
                        }
                        return self.mint_registry_key(
                            OVERLAY_KEY_TAG | index as u32,
                            args[1] as u32,
                            args[0],
                        );
                    }
                }
                // ★ `\Registry\User` (HKEY_USERS) — the per-user hive namespace. EXACT-NAMESPACE
                // scoped: only the predefined root and names under it are answered here, so every
                // HKLM/HKCR open (including the paint-time reads the arms below deliberately keep
                // narrow) is byte-identical to before. Today every `\Registry\User` open returns
                // NOT_FOUND, so nothing that currently succeeds can change.
                if let Some(status) = self.open_user_namespace_key(root_target, &path, oa, args) {
                    return status;
                }
                // winlogon (pi 2) — msgina's registry names are often `RTL_CONSTANT_STRING` literals
                // in `.rdata` pages winlogon/advapi32 never touch, so the plain copyin mirror returns
                // EMPTY. Recover the exact name from the backing PE image, then resolve only the
                // predefined `\Registry\Machine` root and the real Winlogon SOFTWARE-hive key here.
                if self.current_process_is_winlogon() {
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
                        let full = if Self::key_components(&eff_name)
                            .get(0)
                            .is_some_and(|c| c.eq_ignore_ascii_case("Registry"))
                        {
                            eff_name.clone()
                        } else {
                            let mut full = alloc::string::String::from(r"\Registry\Machine\");
                            full.push_str(&eff_name);
                            full
                        };
                        if let Some(kr) = self.resolve_key(&full) {
                            if hive_sel(kr) == HIVE_SEL_SOFTWARE {
                                SOFTWARE_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                            }
                            WINLOGON_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                            return self.mint_registry_key(kr, args[1] as u32, args[0]);
                        }
                        return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                    }
                    // COUNT ONLY — no `return`, no synthesized key, no outcome change. See
                    // `is_profile_list_key`: this open is the structural witness that the real
                    // `WLX_SAS_ACTION_LOGON` was returned and `HandleLogon` ran. It must still MISS
                    // (the SOFTWARE hive is not mounted here), so the profile load fails honestly.
                    if is_profile_list_key(&eff_name) {
                        WINLOGON_PROFILE_LIST_OPENS.fetch_add(1, Ordering::Relaxed);
                    }
                    // Exact `\Registry\Machine` predefined-HKLM open (rd absolute) → sentinel handle.
                    if root_target.is_none() {
                        let comps: alloc::vec::Vec<&str> =
                            eff_name.split('\\').filter(|c| !c.is_empty()).collect();
                        if comps.len() == 2
                            && comps[0].eq_ignore_ascii_case("Registry")
                            && comps[1].eq_ignore_ascii_case("Machine")
                        {
                            return self.mint_registry_key(
                                MACHINE_ROOT_KEY,
                                args[1] as u32,
                                args[0],
                            );
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
                            return self.mint_registry_key(kr, args[1] as u32, args[0]);
                        }
                    }
                    // ★ THE 4TH MOUNT'S ROUTE for winlogon — `ProfileList`, resolved for real
                    // against the newly mounted SOFTWARE hive. winlogon's HKLM subkey opens arrive
                    // with RootDirectory == the machine-root sentinel, and the arm further down
                    // answers every such open NOT_FOUND: that is exactly why
                    // `Software\Microsoft\Windows NT\CurrentVersion\ProfileList` was Error 2 and
                    // `GetProfilesDirectoryW` failed. Same shape, and the same reason, as the
                    // `is_nls_language_key` route immediately above.
                    //
                    // ★ EXACT-NAME scoped, and MEASURED to need to be. The general form — "accept
                    // any pi==2 open that resolves into the SOFTWARE hive" — was tried and it
                    // REGRESSED THE DESKTOP PAINT (gate 241 -> 218/99, 23 FAILs incl.
                    // `exec_win32k_desktop_painted`, `exec_winlogon_sas_window`, all 7
                    // `exec_msgina_*`): `Microsoft\Windows NT\CurrentVersion\Drivers32` then
                    // resolved for the first time, winmm's DllMain took its real legacy-driver path
                    // (beepmidi/msacm32.drv/msacm32 + a `system.ini` probe), and the SAS window's
                    // `WM_NCCREATE` ended in a win32k `#PF` at `cr2=0xb0` —
                    // "WL: Failed to create SAS window" -> "WL: Failed to initialize SAS". This is
                    // the SAME hazard the keyboard-layout and Winlogon-key notes above record:
                    // broadly succeeding HKLM opens regress the paint. So this stays exact-name, in
                    // the established pattern, and the general hosted-service mechanism serves SOFTWARE
                    // everywhere else (absolute opens, noninteractive services, relative opens off a SOFTWARE handle,
                    // `registry_value(s)`, `registry_subkeys`, the overlay).
                    if is_profile_list_key(&eff_name) {
                        let full = alloc::format!("\\Registry\\Machine\\{}", eff_name);
                        if let Some(kr) = self.resolve_key(&full) {
                            if hive_sel(kr) == HIVE_SEL_SOFTWARE {
                                SOFTWARE_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                                WINLOGON_PROFILE_LIST_HITS.fetch_add(1, Ordering::Relaxed);
                                return self.mint_registry_key(kr, args[1] as u32, args[0]);
                            }
                        }
                    }
                }
                // Noninteractive services: resolve HKLM predefined roots + machine-relative subkeys
                // against the real hives. A predefined `\Registry\Machine` open → the sentinel
                // machine-root handle; a subkey relative to it (RootDirectory == the machine-root target)
                // or an absolute `\Registry\Machine\...` path → `resolve_key`; a subkey relative to a
                // real hive handle → `open_key_from`. Self-contained + returns, so winlogon/csrss
                // paint-time key hacks below are untouched (byte-identical).
                if self.current_process_is_noninteractive_service() {
                    // Compute the FULL NT path being opened (predefined-root + overlay-relative
                    // cases). `None` = a hive-handle-relative open (path unknown, resolved below).
                    let full_opt: Option<alloc::string::String> = if root_target
                        == Some(MACHINE_ROOT_KEY)
                    {
                        let mut full = alloc::string::String::from(r"\Registry\Machine\");
                        full.push_str(&path);
                        Some(full)
                    } else if let Some(parent_path) =
                        root_target.and_then(|target| self.registry_target_path(target))
                    {
                        Some({
                            let mut full = parent_path;
                            if !path.is_empty() {
                                full.push('\\');
                                full.push_str(&path);
                            }
                            full
                        })
                    } else {
                        // Absolute open (root_dir == 0). The predefined `\Registry\Machine` open
                        // itself → the sentinel machine-root handle.
                        let comps: alloc::vec::Vec<&str> =
                            path.split('\\').filter(|c| !c.is_empty()).collect();
                        if comps.len() == 2
                            && comps[0].eq_ignore_ascii_case("Registry")
                            && comps[1].eq_ignore_ascii_case("Machine")
                        {
                            return self.mint_registry_key(
                                MACHINE_ROOT_KEY,
                                args[1] as u32,
                                args[0],
                            );
                        }
                        Some(path.clone())
                    };
                    // Overlay-FIRST: a created key shadows the base hive. Before services creates
                    // anything the overlay is empty, so this is byte-identical to the prior path.
                    if let Some(ref full) = full_opt {
                        let canon = self.overlay_canon(full);
                        if let Some(oidx) = self.overlay.find(&canon) {
                            return self.mint_registry_key(
                                OVERLAY_KEY_TAG | (oidx as u32),
                                args[1] as u32,
                                args[0],
                            );
                        }
                    }
                    // Base-hive resolution (unchanged from the read-only seam).
                    let cell: Option<KeyRef> = full_opt
                        .as_ref()
                        .and_then(|full| self.resolve_key(full));
                    if let Some(cell) = cell {
                        // `LSA_HIVE_ROOT_OPENED` means what its name says — an open resolved
                        // against the real SECURITY or SAM mount. Test those two selectors
                        // EXPLICITLY rather than "not SYSTEM": since the SOFTWARE hive became the
                        // 4th mount, "not SYSTEM" also catches services'/lsass' HKLM\Software opens
                        // and the counter drifted 3 -> 15 with no LSA meaning. SOFTWARE opens are
                        // counted by `SOFTWARE_HIVE_KEY_OPENED` instead.
                        if hive_sel(cell) == HIVE_SEL_SECURITY || hive_sel(cell) == HIVE_SEL_SAM {
                            LSA_HIVE_ROOT_OPENED.fetch_add(1, Ordering::Relaxed);
                            if hive_sel(cell) == HIVE_SEL_SAM {
                                SAM_HIVE_ROOT_OPENED.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if hive_sel(cell) == HIVE_SEL_SOFTWARE {
                            SOFTWARE_HIVE_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                        }
                        return self.mint_registry_key(cell, args[1] as u32, args[0]);
                    }
                    // NOTE (SAM/SECURITY batch): `\Registry\Machine\{SECURITY,SAM}` used to be
                    // AUTO-CREATED in the overlay here on any lsass.exe open. That was a fabrication and
                    // it actively BROKE the LSA bring-up: lsasrv's `LsapIsDatabaseInstalled()` probes
                    // `SECURITY\Policy` with a plain open, so an auto-create made it answer TRUE, the
                    // real first-boot `LsapCreateDatabaseKeys`/`LsapCreateDatabaseObjects` install was
                    // SKIPPED, and `LsapGetDomainInfo` then failed reading a `PolAcDmS` nobody wrote.
                    // Both hives are now REAL read-only regf mounts (see `resolve_key`), so their root
                    // resolves above and a missing subkey MISSES honestly - which is precisely what
                    // makes lsasrv install its own database.
                    if let Some(ref full) = full_opt {
                        if is_lsa_hive_path(full) {
                            LSA_HIVE_OPEN_MISS.fetch_add(1, Ordering::Relaxed);
                            // BYPASS ARM ONLY (`SECURITY_SAM_HIVES_MOUNTED == false`): the PRE-BATCH
                            // behaviour — fabricate an empty overlay hive root on any lsass
                            // SECURITY/SAM open. Kept solely so the bypass experiment reproduces the
                            // old steady state (gate 220) instead of diverging into a hang; the live
                            // path never takes it.
                            if !SECURITY_SAM_HIVES_MOUNTED && self.current_process_is_lsass() {
                                let canon = self.overlay_canon(full);
                                let (oidx, _) = self.overlay.create(&canon);
                                self.overlay_dirty = true;
                                return self.mint_registry_key(
                                    OVERLAY_KEY_TAG | (oidx as u32),
                                    args[1] as u32,
                                    args[0],
                                );
                            }
                        }
                        // samsrv's `SamIConnect` → `SampOpenDbObject(NULL, NULL, L"SAM", …)`: the
                        // bare leaf `SAM` opened with a NULL RootDirectory means its `SamKeyHandle`
                        // is NULL — `SamIInitialize` never reached `SampInitDatabase`. That is the
                        // batch's honest wall; count it so the gate can assert it EXACTLY.
                        if root_dir == 0 && full.eq_ignore_ascii_case("SAM") {
                            SAM_CONNECT_NULL_ROOT_MISS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                // Early keyboard-layout open. advapi32's HKLM predefined-root handle does not always
                // arrive as RootDirectory on this path, so accept either the sentinel-relative form
                // or a machine-relative absolute name, but resolve only the exact real SYSTEM hive key.
                let keyboard_layout_full =
                    if root_target == Some(MACHINE_ROOT_KEY) && is_keyboard_layout_key(&path) {
                        let mut full = alloc::string::String::from(r"\Registry\Machine\");
                        full.push_str(&path);
                        Some(full)
                    } else if root_target.is_none() && is_keyboard_layout_key(&path) {
                        let comps = Self::key_components(&path);
                        if comps.len() >= 2
                            && comps[0].eq_ignore_ascii_case("Registry")
                            && comps[1].eq_ignore_ascii_case("Machine")
                        {
                            Some(path.clone())
                        } else {
                            let mut full = alloc::string::String::from(r"\Registry\Machine\");
                            full.push_str(&path);
                            Some(full)
                        }
                    } else {
                        None
                    };
                if let Some(full) = keyboard_layout_full {
                    if let Some(cell) = self.resolve_key(&full) {
                        KBD_LAYOUT_KEY_OPENED.fetch_add(1, Ordering::Relaxed);
                        return self.mint_registry_key(cell, args[1] as u32, args[0]);
                    }
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                // A subkey open relative to the predefined-root sentinel that is NOT the keyboard key:
                // NOT_FOUND (preserves the pre-fix outcome for all non-keyboard predefined subkeys).
                if root_target == Some(MACHINE_ROOT_KEY) {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                // An absolute open whose name is an unreadable DLL `.rdata` static (empty path) is a
                // predefined-root open (HKLM/HKCU/HKCR); hand back the sentinel so MapDefaultKey
                // succeeds (else the keyboard subkey open never fires). Non-keyboard subkeys stay
                // not-found via the match above.
                if root_target.is_none()
                    && path.is_empty()
                    && SERVICES_CREATE_STARTED.load(Ordering::Relaxed) == 0
                {
                    return self.mint_registry_key(MACHINE_ROOT_KEY, args[1] as u32, args[0]);
                }
                // Once winlogon's Win32 create for services.exe has begun, an empty-name absolute open
                // is BasepIsProcessAllowed's AppCertDlls key (its .rdata static reads empty in the
                // mirror). Return NOT_FOUND so BasepIsProcessAllowed skips RtlQueryRegistryValues and
                // returns SUCCESS (else that query fails c0000002 → "Process not allowed to launch").
                // The keyboard-layout path that needs the machine-root key runs long before this.
                if root_target.is_none() && path.is_empty() {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                let cell = if let Some(parent) = root_target {
                    // Relative open against a real base-hive handle: stay in the SAME mounted hive
                    // (re-apply its selector to the resolved cell).
                    self.base_hive(parent).and_then(|(hive, base)| {
                        hive.open_key_from(base, &path)
                            .map(|cell| hive_sel(parent) | cell)
                    })
                } else {
                    self.resolve_key(&path)
                };
                match cell {
                    Some(cell) => self.mint_registry_key(cell, args[1] as u32, args[0]),
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtCreateKey(*KeyHandle[0], DesiredAccess[1], *ObjectAttributes[2], TitleIndex, *Class,
            // CreateOptions, *Disposition[sp+0x38]). The CM WRITE plane: create-or-open a key in the
            // in-memory overlay ([`RegistryOverlay`]) that shadows the read-only base hive. services.exe's
            // ScmCreateServiceDatabase creates volatile keys (Control\ServiceCurrent, group list) here;
            // lsass.exe creates SECURITY/SAM policy state on first boot.
            NativeService::NtCreateKey => unsafe {
                if args[0] == 0 || !self.probe_user_output(args[0], 8) {
                    return 0xC000_0005;
                }
                let oa = args[2];
                let mut rd = [0u8; 8];
                if oa == 0 || !self.xas_read(oa + 8, &mut rd) {
                    return 0xC000_0005;
                }
                let root_dir = u64::from_le_bytes(rd);
                let root_target = if root_dir == 0 {
                    None
                } else {
                    match self.resolve_registry_key(root_dir, 0x4) {
                        Ok(target) => Some(target),
                        Err(status) => return status,
                    }
                };
                let name = self.read_registry_objattr_name(oa);
                // Resolve the full NT path: predefined HKLM root, absolute, or overlay-relative.
                let full: Option<alloc::string::String> = if root_target == Some(MACHINE_ROOT_KEY) {
                    let mut f = alloc::string::String::from(r"\Registry\Machine\");
                    f.push_str(&name);
                    Some(f)
                } else if root_target.is_none() {
                    Some(name.clone())
                } else if let Some(oidx) = root_target.and_then(overlay_key_idx)
                {
                    self.overlay.path(oidx).map(|p| {
                        let mut f = alloc::string::String::from(p);
                        if !name.is_empty() {
                            f.push('\\');
                            f.push_str(&name);
                        }
                        f
                    })
                } else if let Some(parent) = root_target {
                    // A create relative to a REAL base-hive handle (SYSTEM / SECURITY / SAM): build
                    // the full NT path from that hive's own mount point. lsasrv's
                    // `LsapCreateDatabaseKeys` creates `Policy`/`Accounts`/`Domains`/`Secrets`
                    // relative to its `\Registry\Machine\SECURITY` handle through exactly this arm.
                    self.registry_target_path(parent).map(|base| {
                        let mut f = base;
                        if !name.is_empty() {
                            f.push('\\');
                            f.push_str(&name);
                        }
                        f
                    })
                } else {
                    None
                };
                let full = match full {
                    Some(f) => f,
                    None => return 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                };
                let canon = self.overlay_canon(&full);
                if canon == r"\" {
                    return 0xC000_003B; // STATUS_OBJECT_PATH_SYNTAX_BAD
                }
                let parent = canon
                    .rsplit_once('\\')
                    .map(|(parent, _)| if parent.is_empty() { r"\" } else { parent })
                    .unwrap_or(r"\");
                if !self.registry_path_exists(parent) {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                // Disposition: CREATED unless the key already exists in the overlay OR the base hive.
                let existed =
                    self.overlay.find(&canon).is_some() || self.resolve_key(&full).is_some();
                if self.overlay.find(&canon).is_none()
                    && self.overlay.len() >= OVERLAY_KEY_MAX as usize
                {
                    return 0xC000_009A;
                }
                let (oidx, _) = self.overlay.create(&canon);
                self.overlay_dirty = true;
                // Provenance counters for the LSA/SAM gate specs: keys created by lsasrv's OWN
                // `LsapCreateDatabaseKeys`/`LsapCreateDatabaseObjects` under SECURITY\Policy, and by
                // samsrv's OWN `SampSetupCreateServer` under SAM.
                if canon.starts_with(r"\registry\machine\security\policy") {
                    LSA_POLICY_KEYS_CREATED.fetch_add(1, Ordering::Relaxed);
                } else if canon.starts_with(r"\registry\machine\sam\") {
                    SAM_SETUP_KEYS_CREATED.fetch_add(1, Ordering::Relaxed);
                } else if canon.ends_with(r"\computername\activecomputername") {
                    // kernel32's `SetActiveComputerNameToRegistry` (`client/compname.c:131`) —
                    // reached from `GetComputerNameExW(ComputerNameNetBIOS)` inside rpcrt4's
                    // `rpcrt4_ncacn_np_handoff`. Its tail is `NtFlushKey`, so this key existing
                    // proves that whole sequence ran instead of walling on the unserviced SSN 83.
                    ACTIVE_COMPUTER_NAME_KEY_CREATED.fetch_add(1, Ordering::Relaxed);
                } else if self.current_process_is_winlogon() && is_profile_list_sid_key_canon(&canon) {
                    PROFILE_LIST_SID_KEYS_CREATED.fetch_add((!existed) as u64, Ordering::Relaxed);
                    if PROFILE_LIST_VALUE_TRACE.fetch_add(1, Ordering::Relaxed) < 16 {
                        print_str(b"[profile-list] NtCreateKey ");
                        print_ascii_str(&canon);
                        if existed {
                            print_str(b" opened\n");
                        } else {
                            print_str(b" created\n");
                        }
                    }
                }
                let status = self.mint_registry_key(
                    OVERLAY_KEY_TAG | (oidx as u32),
                    args[1] as u32,
                    args[0],
                );
                if status != 0 {
                    return status;
                }
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
            // A write to a base-hive handle (not an overlay key) is a no-op success too (we don't
            // shadow arbitrary base keys for writes yet).
            NativeService::NtSetValueKey => unsafe {
                let key = match self.resolve_registry_key(args[0], 0x2) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let oidx = match self.registry_shadow_key(key) {
                    Ok(index) => index,
                    Err(status) => return status,
                };
                let name = self.read_registry_ustr_name(args[1]);
                let ty = args[3] as u32; // R9 = Type
                let sp = get_recv_mr(16);
                let data_ptr = smss_stack_read(sp + 0x28); // [sp+0x28] = Data
                let data_size = smss_stack_read(sp + 0x30) as u32 as usize;
                if data_size != 0 && data_ptr == 0 {
                    return 0xC000_0005;
                }
                let mut data = alloc::vec::Vec::new();
                if data.try_reserve_exact(data_size).is_err() {
                    return 0xC000_009A;
                }
                data.resize(data_size, 0);
                if data_size != 0 && !self.xas_read(data_ptr, &mut data) {
                    return 0xC000_0005;
                }
                // The account-domain SID lsasrv mints in `LsapCreateRandomDomainSid` and persists as
                // the `PolAcDmS` policy attribute's DEFAULT value. Record its length + SID header so
                // the gate can assert real SID structure (Revision 1, 4 sub-authorities, NT
                // authority 5) rather than "a write happened".
                if name.is_empty()
                    && self.overlay.path(oidx) == Some(r"\registry\machine\security\policy\polacdms")
                {
                    LSA_ACCT_DOMAIN_SID_LEN.store(data.len() as u64, Ordering::Relaxed);
                    let mut head = [0u8; 8];
                    let n = data.len().min(8);
                    head[..n].copy_from_slice(&data[..n]);
                    LSA_ACCT_DOMAIN_SID_HEAD.store(u64::from_le_bytes(head), Ordering::Relaxed);
                }
                self.overlay.set_value(oidx, &name, ty, &data);
                if self.current_process_is_winlogon() {
                    if let Some(path) = self.overlay.path(oidx) {
                        if is_profile_list_sid_key_canon(path) {
                            PROFILE_LIST_SID_VALUE_SETS.fetch_add(1, Ordering::Relaxed);
                            let name_lc = name.to_ascii_lowercase();
                            if name_lc == "profileimagepath" {
                                PROFILE_LIST_PROFILE_IMAGE_PATH_SETS.fetch_add(1, Ordering::Relaxed);
                            } else if name_lc == "refcount" {
                                PROFILE_LIST_REFCOUNT_SETS.fetch_add(1, Ordering::Relaxed);
                            }
                            if PROFILE_LIST_VALUE_TRACE.fetch_add(1, Ordering::Relaxed) < 16 {
                                print_str(b"[profile-list] NtSetValueKey ");
                                print_ascii_str(path);
                                print_str(b" value=\"");
                                print_ascii_str(&name);
                                print_str(b"\" type=");
                                print_u64(ty as u64);
                                print_str(b" bytes=");
                                print_u64(data.len() as u64);
                                print_str(b"\n");
                            }
                        }
                    }
                }
                self.overlay_dirty = true;
                0 // STATUS_SUCCESS
            },
            // `NtFlushKey(IN HANDLE KeyHandle)` — `references/reactos/ntoskrnl/config/ntapi.c:1085`.
            // NT's own body is: reference the key object by handle (**no access mask** — it passes 0
            // to `ObReferenceObjectByHandle`), fail `STATUS_KEY_DELETED` if the KCB is deleted, else
            // `CmFlushKey(kcb, FALSE)`. `CmFlushKey` (`cmapi.c`) ends in `HvSyncHive`, and
            // `HvSyncHive` (`sdk/lib/cmlib/hivewrt.c:466`) **returns TRUE immediately for a
            // `HIVE_VOLATILE` hive** ("avoid any write operations on volatile hives") and likewise
            // when the dirty vector holds no dirty block ("literally nothing to do").
            //
            // That is EXACTLY this host's registry: the mounted `regf` hives are READ-ONLY and every
            // runtime key/value lives in the in-memory write overlay, which IS the store — there is
            // no separate write-behind cache to drain and no backing file to sync. So the faithful
            // answer is `STATUS_SUCCESS` after a REAL handle resolution, not a fabricated success:
            // a bad handle still returns the real error (`resolve_registry_key`), the counter below
            // proves the service actually ran, and nothing is claimed to have been persisted.
            NativeService::NtFlushKey => {
                let key = match self.resolve_registry_key(args[0], 0) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                REG_FLUSH_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
                // A key that lives in the write overlay (rather than the read-only `regf` mount) is
                // the volatile-hive case verbatim. Pure check — a flush must never CREATE anything.
                if overlay_key_idx(key).is_some() {
                    REG_FLUSH_KEY_VOLATILE.fetch_add(1, Ordering::Relaxed);
                }
                0 // STATUS_SUCCESS — HvSyncHive's volatile / no-dirty-block early return
            }
            // ★ NtLoadKey* / NtUnloadKey* — mount and detach a per-user `regf` hive at
            // `HKEY_USERS\<SID>`. `userenv!CreateUserProfileExW` and `LoadUserProfileW` usually go
            // through the base APIs (`RegLoadKeyW`/`RegUnLoadKeyW`), but the ntdll-visible variants
            // are backed by the same real CM path instead of being left as gaps.
            NativeService::NtLoadKey => unsafe { self.nt_load_key_ex(args[0], args[1], 0, 0) },
            NativeService::NtLoadKey2 => unsafe {
                self.nt_load_key_ex(args[0], args[1], args[2] as u32, 0)
            },
            NativeService::NtLoadKeyEx => unsafe {
                self.nt_load_key_ex(args[0], args[1], args[2] as u32, args[3])
            },
            NativeService::NtUnloadKey => unsafe { self.nt_unload_key_ex(args[0], 0, 0) },
            NativeService::NtUnloadKey2 => unsafe {
                self.nt_unload_key_ex(args[0], args[1] as u32, 0)
            },
            NativeService::NtUnloadKeyEx => unsafe { self.nt_unload_key_ex(args[0], 0, args[1]) },
            NativeService::NtLoadDriver => unsafe { self.nt_load_driver(args[0]) },
            NativeService::NtUnloadDriver => unsafe { self.nt_unload_driver(args[0]) },
            NativeService::NtDeleteValueKey => unsafe {
                let key = match self.resolve_registry_key(args[0], 0x2) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let name = self.read_registry_ustr_name(args[1]);
                if self.registry_value(key, &name).is_none() {
                    return 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
                }
                let index = match self.registry_shadow_key(key) {
                    Ok(index) => index,
                    Err(status) => return status,
                };
                if !self.overlay.delete_value(index, &name) {
                    return 0xC000_0008;
                }
                self.overlay_dirty = true;
                0
            },
            // NtEnumerateValueKey(KeyHandle[0], Index[1], InfoClass[2], KeyValueInfo[3], Length[4],
            // *ResultLength[5]). Enumerate the value at Index from the real hive + copy the
            // KEY_VALUE_*_INFORMATION out; SmpInit reads the Environment/DOS-Devices/etc. values.
            NativeService::NtEnumerateValueKey => unsafe {
                let key = match self.resolve_registry_key(args[0], 0x1) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let use_xas_write = self.pi >= 2;
                let byname: Option<(alloc::string::String, u32, alloc::vec::Vec<u8>)> =
                    self.registry_values(key).into_iter().nth(args[1] as usize);
                match byname {
                    None => 0x8000_001A, // STATUS_NO_MORE_ENTRIES
                    Some((name, ty, data)) => {
                        let info = build_key_value_info(args[2], &name, ty, &data);
                        let total = (info.len() as u32).to_le_bytes();
                        if use_xas_write {
                            if !self.xas_try_write_buf(args[5], &total) {
                                return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                            }
                        } else {
                            smss_copyout(args[5], &total); // *ResultLength
                        }
                        if info.len() > args[4] as usize {
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            if use_xas_write {
                                if !self.xas_try_write_buf(args[3], &info) {
                                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                                }
                            } else {
                                smss_copyout(args[3], &info);
                            }
                            0 // STATUS_SUCCESS
                        }
                    }
                }
            },
            // NtEnumerateKey(KeyHandle[0], Index[1], KeyInformationClass[2], KeyInformation[3],
            // Length[4], *ResultLength[5]). Hosted service processes enumerate REAL subkeys of hive
            // keys here (for example, ScmCreateServiceDatabase walks
            // HKLM\SYSTEM\CurrentControlSet\Services).
            NativeService::NtEnumerateKey => unsafe {
                NT_ENUMERATE_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
                let key = match self.resolve_registry_key(args[0], 0x8) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let subs = self.registry_subkeys(key);
                let idx = args[1] as usize;
                if idx >= subs.len() {
                    return 0x8000_001A; // STATUS_NO_MORE_ENTRIES
                }
                let name16: alloc::vec::Vec<u16> = subs[idx].encode_utf16().collect();
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
                let total_bytes = total.to_le_bytes();
                if self.pi >= 2 {
                    if !self.xas_try_write_buf(args[5], &total_bytes) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                } else {
                    smss_copyout(args[5], &total_bytes); // *ResultLength (stack local)
                }
                if (args[4] as usize) < info.len() {
                    return 0x8000_0005; // STATUS_BUFFER_OVERFLOW
                }
                self.xas_write_buf(args[3], &info); // KeyInformation (heap buffer)
                0 // STATUS_SUCCESS
            },
            // NtQueryKey(KeyHandle[0], KeyInformationClass[1], KeyInformation[2], Length[3],
            // *ResultLength[4]). RegQueryInfoKeyW (KeyFullInformation) reads the subkey/value
            // counts + max name lengths of a hive key to size its RegEnumKeyExW buffers.
            NativeService::NtQueryKey => unsafe {
                let key = match self.resolve_registry_key(args[0], 0x1) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let use_xas_write = self.pi >= 2;
                let subs = self.registry_subkeys(key);
                let vals = self.registry_values(key);
                let subkeys = subs.len() as u32;
                let max_name = subs.iter().map(|name| name.len()).max().unwrap_or(0) as u32 * 2;
                let values = vals.len() as u32;
                let max_vname = vals.iter().map(|(name, _, _)| name.len()).max().unwrap_or(0) as u32
                    * 2;
                let max_vdata = vals.iter().map(|(_, _, data)| data.len()).max().unwrap_or(0) as u32;
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
                info[0x28..0x2c].copy_from_slice(&max_vdata.to_le_bytes());
                if values == 0
                    && self
                        .registry_target_path(key)
                        .as_deref()
                        .is_some_and(Self::is_dynamic_user_volatile_env_canon)
                {
                    USER_VOLATILE_ENV_QUERIED_EMPTY.fetch_add(1, Ordering::Relaxed);
                }
                let total = struct_size.to_le_bytes();
                if use_xas_write {
                    if !self.xas_try_write_buf(args[4], &total) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                } else {
                    smss_copyout(args[4], &total); // *ResultLength
                }
                if (args[3] as usize) < struct_size as usize {
                    return 0x8000_0005; // STATUS_BUFFER_OVERFLOW
                }
                if use_xas_write {
                    if !self.xas_try_write_buf(args[2], &info) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                } else {
                    self.xas_write_buf(args[2], &info);
                }
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
                // Hosted noninteractive service RPC servers route creates through the REAL isolated npfs
                // FSD → NpFsdCreateNamedPipe builds a real FCB/CCB + FILE_OBJECT (server end). Earlier
                // GUI boot clients keep the modeled-fake path (byte-identical: winlogon's \pipe\winreg
                // never connects).
                let mut info: u64 = 2; // FILE_CREATED
                let mut routed_file_id = 0;
                if self.current_process_is_noninteractive_service() {
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
                    // parks. Name-scoped to `\ntsvcs` (SCM) and services.exe, so lsass/other pipes are unaffected.
                    let is_ntsvcs = leaf.len() >= 7
                        && leaf[1..7].iter().zip(b"ntsvcs".iter()).all(|(&w, &c)| w as u8 == c);
                    if self.current_process_is_services() && is_ntsvcs {
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
                    // BATCH 40: same re-create cap for lsass' `\lsarpc` LSA RPC server. Once
                    // winlogon crosses msgina GINA init and drives its logon flow, lsass re-creates the
                    // `\lsarpc` server pipe unboundedly (no live terminating client under TCG) → the boot
                    // never quiesces. Cap → STATUS_PIPE_NOT_AVAILABLE → the LSA listener parks → gate.
                    let is_lsarpc = leaf.len() >= 7
                        && leaf[1..7].iter().zip(b"lsarpc".iter()).all(|(&w, &c)| w as u8 == c);
                    if self.current_process_is_lsass() && is_lsarpc {
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
                    let options = args[6] as u32;
                    let synchronous = options
                        & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT
                            | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
                        != 0;
                    let Some(handle) =
                        self.mint_file_handle(routed_file_id, args[1] as u32, synchronous)
                    else {
                        self.queue_write(get_recv_mr(9), 0);
                        if iosb != 0 {
                            self.xas_write_buf(
                                iosb,
                                &nt_io_completion::STATUS_INSUFFICIENT_RESOURCES.to_le_bytes(),
                            );
                            self.xas_write_buf(iosb + 8, &0u64.to_le_bytes());
                        }
                        return nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                    };
                    handle
                } else {
                    self.mint_handle()
                };
                // *FileHandle (R10): for noninteractive services it's a DLL .data global → the
                // cross-AS writer; earlier GUI boot clients keep the legacy stack write.
                if self.current_process_is_noninteractive_service() {
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
                // Hosted pipe clients route FSCTLs (LISTEN/WAIT/TRANSCEIVE) to npfs for tracked pipe
                // handles. npfs's NpFsdFileSystemControl runs the real state machine on the CCB.
                // FSCTL_PIPE_LISTEN on a server pipe with no client returns pending-listen semantics;
                // early clients without real pipe handles keep the modeled path.
                let fsctl = args[5];
                let mut status: u64 = 0;
                let mut information = 0u64;
                // Match IopXxxControlFile: validate the caller's completion event for
                // EVENT_MODIFY_STATE and clear it before issuing every request. In particular,
                // rpcrt4 reuses a manual-reset event when it rearms a pipe listener; leaving the
                // previous completion signalled manufactures a second accepted connection.
                let event_obj_idx = if args[1] != 0 {
                    match self.event_index_for_handle(args[1], EVENT_MODIFY_STATE) {
                        Ok(index) => {
                            let _ = self.events.reset_existing(index as u64);
                            index as u64
                        }
                        Err(event_status) => return event_status,
                    }
                } else {
                    u64::MAX
                };
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
                // ★ BATCH 34 — the SAME invariant for REAL ncacn_np SCM/LSA listeners. rpcrt4 posts
                // FSCTL_PIPE_LISTEN on EACH listener pipe; if it returns SUCCESS/STATUS_PIPE_CONNECTED
                // it signals the listen event immediately and loops into an infinite create-instance
                // runaway. A freshly-created server instance with no client must report STATUS_PENDING;
                // only pipe_listen_complete_named wakes it with io_status.Status = SUCCESS.
                let is_pipe_listen = (fsctl as u32) == 0x0011_0008;
                let force_pending_listen = is_pipe_listen
                    && (self.current_process_is_winlogon()
                        || self.current_process_is_noninteractive_service());
                if force_pending_listen {
                    status = 0x103; // STATUS_PENDING
                }
                let fid = self.npfs_file_id_for(args[0]);
                let is_pipe_transceive = (fsctl as u32) == 0x0011_C017;
                let mut transceive_file_retained = false;
                if fid != 0 && !force_pending_listen {
                    let input_len = (args[7] as usize).min(0x4000);
                    let output_len = (args[9] as usize).min(0x4000);
                    let mut input = alloc::vec![0u8; input_len];
                    let mut output = alloc::vec![0u8; output_len];
                    if (input_len == 0 || self.xas_read(args[6], &mut input))
                        && (output_len == 0 || args[8] != 0)
                    {
                        let prepared = if is_pipe_transceive {
                            let waiter_table = &*core::ptr::addr_of!(PIPE_WAITERS);
                            let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
                            let reply_capacity = REPLY_MAIN_SLOT.load(Ordering::Relaxed) != 0
                                && (0..WAIT_REPLY_POOL_N).any(|index| {
                                    used & (1u64 << index) == 0
                                        && WAIT_REPLY_POOL[index].load(Ordering::Relaxed) != 0
                                });
                            if !waiter_table.has_capacity()
                                || waiter_table.parked_on(fid)
                                || !reply_capacity
                            {
                                Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES)
                            } else {
                                self.file_completion.retain_file(fid).map(|()| {
                                    transceive_file_retained = true;
                                })
                            }
                        } else {
                            Ok(())
                        };
                        match prepared {
                            Err(preparation_status) => status = preparation_status as u64,
                            Ok(()) => {
                                if let Some((st, completed, _)) =
                                    self.npfs_route_raw(0xd, fsctl, fid, &input, &mut output)
                                {
                                    status = st as u64;
                                    information = completed;
                                    if completed != 0 && args[8] != 0 {
                                        let copy_len = (completed as usize).min(output.len());
                                        self.xas_write_buf(args[8], &output[..copy_len]);
                                    }
                                }
                            }
                        }
                    }
                }
                if transceive_file_retained && status as u32 != 0x0000_0103 {
                    self.release_file_reference(fid);
                }
                // BATCH 33: an FSCTL_PIPE_TRANSCEIVE (write-then-read) on a real npfs pipe that returns
                // PENDING has no response bytes yet → PARK this caller keyed by the reading end fid, and
                // re-drive it when the peer writes the response (the loop steals the reply cap; the
                // response is delivered to args[8]/IOSB at re-drive, so SUPPRESS the PENDING IOSB here).
                if fid != 0
                    && is_pipe_transceive
                    && (status as u32) == 0x0000_0103
                    && args[8] != 0
                {
                    self.pipe_park_fid = fid;
                    self.pipe_park_buffer_va = args[8];
                    self.pipe_park_buffer_len = args[9] as u32;
                    self.pipe_park_iosb_va = iosb;
                    self.pipe_park_apc_context = args[3];
                    self.pipe_park_event_obj_idx = event_obj_idx;
                    self.pipe_park_transceive = true;
                }
                // ★ BATCH 34 — the async ncacn_np SERVER completion edge. A service server posting an
                // OVERLAPPED FSCTL_PIPE_LISTEN (0x110008) that npfs returns STATUS_PENDING for (no client
                // yet, NpSetListeningPipeState → IoMarkIrpPending) does NOT block on this syscall — the
                // thread continues to NtWaitForMultipleObjects([mgr_event, listen_event]). Record the
                // pending async listen keyed by the SERVER fid, carrying the completion EVENT (RDX =
                // args[1], resolved to its obj_ns index in the SERVER's OWN handle table NOW while `pi`
                // names the server) + the listen IOSB VA. On the peer connect/write the loop completes it
                // (fills the IOSB SUCCESS + signals the event → the server's wait-array wakes). SUPPRESS
                // the PENDING IOSB write here (overlapped: the IOSB is written at completion, not now).
                if self.current_process_is_noninteractive_service()
                    && (fsctl as u32) == 0x0011_0008
                    && (status as u32) == 0x0000_0103
                    && fid != 0
                {
                    let table = &mut *core::ptr::addr_of_mut!(crate::PIPE_ASYNC_LISTENS);
                    if table
                        .arm(nt_io_manager::AsyncListen {
                            server_file_id: fid,
                            event_obj_idx,
                            pi: self.pi as u32,
                            tid: self.current_tid,
                            badge: self.current_badge,
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
                if fid != 0 && is_pipe_transceive && (status as u32) != 0x0000_0103 {
                    self.pipe_write_redrive = true;
                }
                if self.current_process_is_winlogon() && fsctl as u32 == 0x0011_0018
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
            // *ResultLength[5]). SmpInit reads Identifier/VendorIdentifier from the kernel-owned
            // volatile HARDWARE overlay to build PROCESSOR_IDENTIFIER. Real-hive values by name
            // continue to fall through to the mounted hives.
            NativeService::NtQueryValueKey => unsafe {
                let key = match self.resolve_registry_key(args[0], 0x1) {
                    Ok(key) => key,
                    Err(status) => return status,
                };
                let output_length = args[4] as u32 as usize;
                if args[5] == 0 || !self.probe_user_output(args[5], 4) {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if output_length != 0
                    && (args[3] == 0 || !self.probe_user_output(args[3], output_length))
                {
                    return 0xC000_0005;
                }
                // Hosted GUI/service processes commonly pass value names from DLL `.rdata` literals the
                // stack/heap/image mirror can't reach, so read them from the backing PE (`read_ustr_pe`).
                // read_ustr_pe uses xas_read → resolves any resident/PE page.
                let key_path = self.registry_target_path(key);
                let key_is_ifeo = key_path
                    .as_deref()
                    .is_some_and(|path| path.contains(r"\image file execution options\"));
                let shell_com_inproc_bit = if self.current_process_is_hosted_leaf(b"explorer.exe") {
                    key_path
                        .as_deref()
                        .map_or(0, explorer_shell_com_inproc_class_bit_for_path)
                } else {
                    0
                };
                let pe_backed_registry_strings =
                    self.current_process_uses_pe_backed_registry_strings();
                let name16 = if pe_backed_registry_strings
                    || key_is_ifeo
                    || shell_com_inproc_bit != 0
                {
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
                // Set for hosted processes reading real-hive values: their out-params are often
                // advapi/userenv heap or stack buffers the plain mirror can't reach. Predefined-root
                // and overlay reads stay on their narrow paths unless a call site below proves it
                // needs cross-AS copyout.
                let mut use_xas_write =
                    shell_com_inproc_bit != 0 || self.current_process_is_noninteractive_service();
                if pe_backed_registry_strings && !is_virtual_registry_key(key) {
                    // Hosted clients reading a value out of a REAL MOUNTED HIVE (not an overlay or
                    // predefined-root handle): their out-params are advapi/userenv heap or stack the
                    // plain mirror can't reach, so the copyout below must go cross-AS. Early live cases:
                    //   • SetDefaultLanguage(NULL) → the `Default` value of the SYSTEM-hive key
                    //     `...\Control\Nls\Language` (opened via is_nls_language_key). Was:
                    //     mirror-only → None → NOT_FOUND → SetDefaultLanguage FALSE →
                    //     InitializeSAS FALSE → ExitProcess(2).
                    //   • GetProfilesDirectoryW → `ProfilesDirectory` under the SOFTWARE-hive key
                    //     `Software\Microsoft\Windows NT\CurrentVersion\ProfileList`.
                    // Scoped by `!is_virtual_registry_key`, so overlay/predefined-root reads stay
                    // on their narrow paths.
                    use_xas_write = true;
                }
                let val: Option<(u32, alloc::vec::Vec<u8>)> = self.registry_value(key, &name_lc);
                let key_is_real_winlogon = key_path.as_deref().is_some_and(is_winlogon_key);
                if self.current_process_is_winlogon() && key_is_real_winlogon {
                    if let Some((ty, ref data)) = val {
                        WINLOGON_KEY_VALUES_SERVED.fetch_add(1, Ordering::Relaxed);
                        if name_lc == "userinit" {
                            WINLOGON_USERINIT_READS.fetch_add(1, Ordering::Relaxed);
                            WINLOGON_USERINIT_TYPE.store(ty as u64, Ordering::Relaxed);
                            WINLOGON_USERINIT_BYTES.store(data.len() as u64, Ordering::Relaxed);
                            use_xas_write = true;
                            if WINLOGON_USERINIT_READS.load(Ordering::Relaxed) == 1 {
                                print_str(b"[wl-shell] WlxActivateUserShell Userinit = \"");
                                for pair in data.chunks_exact(2) {
                                    let unit = u16::from_le_bytes([pair[0], pair[1]]);
                                    if unit == 0 {
                                        break;
                                    }
                                    debug_put_char(if (0x20..0x7f).contains(&unit) {
                                        unit as u8
                                    } else {
                                        b'?'
                                    });
                                }
                                print_str(b"\" (REG type ");
                                print_u64(ty as u64);
                                print_str(b", from the real SOFTWARE hive)\n");
                            }
                        } else if name_lc == "defaultpassword" {
                            WINLOGON_DEFAULT_PASSWORD_READS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                // A `PolAcDm[NS]` account-domain attribute served back through
                // `LsapGetObjectAttribute` — lsasrv's `LsapGetDomainInfo` at LSA init, and msv1_0's
                // `GetAccountDomainSid` on the real logon path (counted separately while an
                // `LsaLogonUser` is in flight, which is the credential-validation proof).
                if val.is_some()
                    && self
                        .registry_target_path(key)
                        .is_some_and(|p| p.starts_with(r"\registry\machine\security\policy\polacdm"))
                {
                    LSA_ACCT_DOMAIN_ATTR_READS.fetch_add(1, Ordering::Relaxed);
                    if LSA_LOGON_IN_FLIGHT.load(Ordering::Relaxed) != 0 {
                        LSA_ACCT_DOMAIN_ATTR_READS_IN_LOGON.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // POST-PROFILE FRONTIER: once the user hive is loaded, winlogon's remaining
                // `HandleLogon` steps (`CreateUserEnvironment` → `SetDefaultLanguage` →
                // `AllowAccessOnSession` → `StartUserShell`) fail through `WARN`, which the shipped
                // binary does not print. A missed value read is the only externally visible
                // evidence of which step gave up, so name the KEY and the VALUE.
                if self.current_process_is_winlogon() && val.is_none() && post_profile_phase() {
                    self.trace_post_profile_registry(b"query-value", key, &name_lc);
                }
                if val.is_some() && shell_com_inproc_bit != 0 {
                    if name_lc.is_empty() {
                        EXPLORER_SHELL_COM_INPROC_DEFAULT_MASK
                            .fetch_or(shell_com_inproc_bit, Ordering::Relaxed);
                    } else if name_lc == "threadingmodel" {
                        EXPLORER_SHELL_COM_THREADING_MODEL_MASK
                            .fetch_or(shell_com_inproc_bit, Ordering::Relaxed);
                    }
                }
                match val {
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND — smss uses defaults
                    Some((ty, data)) => {
                        // KeyValuePartialInformation (class 2) carries no name.
                        let info = build_key_value_info(args[2], "", ty, &data);
                        // *ResultLength: use the cross-AS writer for hosted real-hive reads (advapi's
                        // out-param may be a heap/stack the plain mirror can't reach — same reason as
                        // the data write below); everything else stays mirror-only (byte-identical).
                        let result_length = (info.len() as u32).to_le_bytes();
                        let result_length_written = if use_xas_write {
                            self.xas_try_write_buf(args[5], &result_length)
                        } else {
                            smss_copyout(args[5], &result_length)
                        };
                        if !result_length_written {
                            return 0xC000_0005;
                        }
                        if info.len() > output_length {
                            // BUFFER_OVERFLOW: real NtQueryValueKey still fills as much of the buffer as
                            // fits (the KEY_VALUE_PARTIAL_INFORMATION header carries Type + DataLength,
                            // which advapi's RegQueryValueExW reads to size the retry / set dwSize when
                            // lpData is NULL). Writing NOTHING left advapi with a garbage dwType/dwSize →
                            // SetDefaultLanguage bailed. Write the truncated prefix so the header lands.
                            let n = output_length;
                            if n > 0 {
                                let written = if use_xas_write {
                                    self.xas_try_write_buf(args[3], &info[..n])
                                } else {
                                    smss_copyout(args[3], &info[..n])
                                };
                                if !written {
                                    return 0xC000_0005;
                                }
                            }
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            // Hosted out-buffers may be advapi32 heap allocations the mirror
                            // can't reach → use the cross-AS writer so the value data actually lands.
                            let written = if use_xas_write {
                                self.xas_try_write_buf(args[3], &info)
                            } else {
                                smss_copyout(args[3], &info)
                            };
                            if !written {
                                return 0xC000_0005;
                            }
                            // ★ A value COPIED OUT of the 4th mount, in full, to a hosted process.
                            // `ProfilesDirectory` is the one `userenv!GetProfilesDirectoryW`
                            // (`profile.c:1592`) reads — it is what makes winlogon's post-logon
                            // `LoadUserProfileW` advance past its old `ERROR_FILE_NOT_FOUND`.
                            if !is_virtual_registry_key(key) && hive_sel(key) == HIVE_SEL_SOFTWARE {
                                SOFTWARE_HIVE_VALUE_READS.fetch_add(1, Ordering::Relaxed);
                                if self.current_process_is_winlogon()
                                    && name_lc == "profilesdirectory"
                                {
                                    WINLOGON_PROFILES_DIR_READS.fetch_add(1, Ordering::Relaxed);
                                }
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
                    encode_system_module_information, query_plan,
                    system_module_information_required_length, SystemInformationKind,
                    SystemModuleEntry, SystemTimeOfDayInformation,
                    RTL_PROCESS_MODULES_HEADER_SIZE, SYSTEM_MODULE_INFORMATION_CLASS,
                    SYSTEM_BASIC_INFORMATION_CLASS,
                    SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS,
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
                        | SYSTEM_MODULE_INFORMATION_CLASS
                        | SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS
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

                if class == SYSTEM_MODULE_INFORMATION_CLASS {
                    let mut snapshot = [SystemModuleEntry::EMPTY; SYSTEM_MODULE_REGISTRY_CAP];
                    let module_count = snapshot_system_modules(&mut snapshot);
                    let required_length =
                        system_module_information_required_length(module_count).unwrap_or(usize::MAX);
                    let return_length = required_length.min(u32::MAX as usize) as u32;
                    if retlen_ptr != 0 {
                        self.xas_write_u32(retlen_ptr, return_length);
                    }

                    if len < RTL_PROCESS_MODULES_HEADER_SIZE {
                        return nt_syscall::STATUS_INFO_LENGTH_MISMATCH;
                    }

                    let copy_length = len.min(required_length);
                    let mut output = alloc::vec![0u8; copy_length];
                    let status =
                        match encode_system_module_information(&mut output, &snapshot[..module_count])
                        {
                            Ok(_) => 0,
                            Err(error) => error.status,
                        };
                    if !self.xas_try_write_buf(buf, &output) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    return status;
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
                        let output = native_basic_system_information().encode();
                        self.xas_try_write_buf(buf, &output)
                    }
                    SystemInformationKind::Processor => {
                        let output = native_processor_information().encode();
                        self.xas_try_write_buf(buf, &output)
                    }
                    SystemInformationKind::TimeOfDay => {
                        let current_time = nt_system_time_100ns();
                        let effective =
                            effective_time_zone(self.time_zone_information, current_time);
                        if SYSTEM_TIME_ZONE_BIAS_100NS.load(Ordering::Relaxed)
                            != effective.bias_100ns as u64
                            || SYSTEM_TIME_ZONE_ID.load(Ordering::Relaxed) != effective.id
                        {
                            unsafe {
                                publish_time_zone(self.time_zone_information, current_time)
                            };
                        }
                        let output = SystemTimeOfDayInformation {
                            boot_time_100ns: NT_SYSTEM_TIME_BOOT_100NS,
                            current_time_100ns: current_time,
                            time_zone_bias_100ns: effective.bias_100ns,
                            time_zone_id: effective.id,
                        }
                        .encode();
                        self.xas_try_write_buf(buf, &output[..plan.copy_length])
                    }
                    SystemInformationKind::CurrentTimeZone => {
                        let output = self.time_zone_information.encode();
                        self.xas_try_write_buf(buf, &output)
                    }
                };
                if wrote { 0 } else { STATUS_ACCESS_VIOLATION }
            },
            // NtQueryInformationProcess(Handle, Class, Buffer, Len, *RetLen).
            NativeService::NtQueryInformationProcess => unsafe {
                self.nt_query_information_process(
                    args[0],
                    args[1] as u32,
                    args[2],
                    args[3] as u32,
                    args[4],
                )
            },
            // NtProtectVirtualMemory(Process, *Base, *Size, NewProtect, *OldProtect[arg5]=args[4]).
            // The common helper keeps the normal process and CSR worker user-memory views aligned.
            NativeService::NtProtectVirtualMemory => unsafe {
                self.nt_protect_virtual_memory_with_user_memory(
                    args,
                    SyscallUserMemory::CurrentProcess,
                )
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
            NativeService::NtOpenThreadToken => unsafe {
                self.nt_open_thread_token(args, false)
            },
            NativeService::NtOpenThreadTokenEx => unsafe {
                self.nt_open_thread_token(args, true)
            },
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
                const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
                const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
                // Robust .rdata-capable name read (csrss's \Windows\ApiPort name is in csrsrv .rdata,
                // unreachable by the mirror-only smss_read_objattr_name) so the port registers under
                // its real name → winlogon's NtSecureConnectPort matches it → the authentic CSR accept.
                let mut name16 = self.read_objattr_name(args[1]);
                if name16.is_empty() {
                    name16 = smss_read_objattr_name(args[1]);
                }
                if name16.is_empty() {
                    print_str(b"[lpc-port] NtCreatePort missing ObjectName -> failing\n");
                    return STATUS_OBJECT_NAME_INVALID;
                }

                let mut root_bytes = [0u8; 8];
                let _ = self.xas_read(args[1] + 8, &mut root_bytes);
                let root_dir = u64::from_le_bytes(root_bytes);
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };

                let Some(client) = lpc_client() else {
                    print_str(b"[lpc-port] broker unavailable for NtCreatePort -> failing\n");
                    return STATUS_UNSUCCESSFUL;
                };
                let handle = match client.create_port(&name16, args[2] as u32, args[3] as u32, 0) {
                    Ok(handle) if handle != 0 => handle,
                    Ok(_) => return STATUS_UNSUCCESSFUL,
                    Err(status) => return status.raw() as u32,
                };
                match self.register_lpc_port_object(&name16, root_idx, handle) {
                    Ok(_) => {}
                    Err(status) => return status,
                }
                self.queue_write(args[0], handle);
                // ★ LSA RENDEZVOUS (identify the server port). lsass' lsasrv `StartAuthenticationPort`
                // (`references/reactos/dll/win32/lsasrv/authport.c:364`) creates `\LsaAuthenticationPort`
                // and hands the handle to its `AuthPortThreadRoutine`, which then blocks in
                // `NtReplyWaitReceivePort(AuthPortHandle, …)`. The loop recognizes that handle by
                // resolving the named port object, not by a creation-order or global-handle side table.
                {
                    let mut nb = [0u8; 48];
                    let nlen = Self::fold_name(&name16, &mut nb);
                    if self.current_process_is_lsass()
                        && nb[..nlen]
                            .windows(b"lsaauthenticationport".len())
                            .any(|w| w == b"lsaauthenticationport")
                    {
                        LSA_AUTH_PORT_OBJECT_HANDLE.store(handle, Ordering::Relaxed);
                        print_str(b"[lsa-rdv] lsass NtCreatePort(\\LsaAuthenticationPort) -> broker port handle=0x");
                        print_hex((handle >> 32) as u32);
                        print_hex(handle as u32);
                        print_str(b"\n");
                    }
                }
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
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_csrss()
                    && args[3] == u64::MAX
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::CsrSbApi)
                        .is_none()
                {
                    unsafe {
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
                            let top_badge = self.hosted_process_top_badge(self.pi).unwrap_or(0);
                            let (role, badge, teb) = match slot {
                                0 => (HostedThreadRole::CsrApi, top_badge, CSR_TEB_VA),
                                1 => (HostedThreadRole::CsrSbApi, top_badge, CSR_SB_TEB_VA),
                                _ => {
                                    self.abandon_created_hosted_thread(slot, tid, handle);
                                    return 0xC000_009A;
                                }
                            };
                            if !self.reserve_created_hosted_thread_role(
                                slot, tid, handle, badge, role,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::Csr { slot });
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
                //
                // A FOREIGN `ProcessHandle` has TWO distinct meanings, and NT tells them apart the
                // same way we do here — by whether the target already HAS its initial thread:
                //   * the process's INITIAL thread, the second half of `RtlCreateUserProcess`
                //     ("create the process, then its first thread"). The pre-created main ETHREAD +
                //     the seL4 main TCB the spawn already built ARE that thread → bind them (below).
                //   * any SUBSEQUENT thread — a genuine additional thread that must be BUILT inside
                //     the target's address space (`RtlCreateUserThread(ProcessHandle != self)`, i.e.
                //     `DbgUiIssueRemoteBreakin` / `CreateRemoteThread`) → `create_remote_thread`.
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
                        let target_pi = self.pi_for_pid(target_pid);
                        if target_pi.is_some_and(|pi| {
                            PM_INITIAL_THREAD_DONE.load(Ordering::Relaxed) & (1u64 << pi) != 0
                        }) {
                            // The target already has its initial thread ⇒ REAL cross-VSpace create.
                            return self.create_remote_thread(args);
                        }
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
                            let tcb = self.hosted_main_thread_tcb_for_pi(target_pi).unwrap_or(0);
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
                        // This target now HAS its initial thread; any further foreign create for it
                        // is a genuine additional thread (the cross-VSpace path above).
                        if let Some(pi) = target_pi {
                            PM_INITIAL_THREAD_DONE.fetch_or(1u64 << pi, Ordering::Relaxed);
                        }
                        return 0;
                    }
                }
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_winlogon()
                    && args[3] == u64::MAX
                    && self
                        .hosted_thread_tid_for_role(
                            self.pi,
                            HostedThreadRole::WinlogonWorker { slot: 2 },
                        )
                        .is_none()
                {
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
                            let (role, badge, teb) = match slot {
                                0 => (
                                    HostedThreadRole::WinlogonListener,
                                    WINLOGON_WORKER_BADGE,
                                    WL_LISTENER_TEB_VA,
                                ),
                                1 => (
                                    HostedThreadRole::WinlogonWorker { slot },
                                    WINLOGON_WORKER2_BADGE,
                                    WL_WORKER2_TEB_VA,
                                ),
                                2 => (
                                    HostedThreadRole::WinlogonWorker { slot },
                                    WINLOGON_WORKER3_BADGE,
                                    WL_WORKER3_TEB_VA,
                                ),
                                _ => {
                                    self.abandon_created_hosted_thread(slot, tid, handle);
                                    return 0xC000_009A;
                                }
                            };
                            if !self.reserve_created_hosted_thread_role(
                                slot, tid, handle, badge, role,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle = R10
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64); // ClientId.UniqueProcess
                                self.queue_write(cid_ptr + 8, tid); // ClientId.UniqueThread
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::Winlogon { slot });
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
                // ★ N-threads multiplex: services.exe's FIRST NtCreateThread = the SCM's RPC listener
                // (ScmStartRpcServer → rpcrt4 io_thread). Route it through the REAL ETHREAD lifecycle
                // like winlogon's, but the LOOP spawns it RESUMED with a badged fault EP (it runs into
                // the main multiplex). Its faults sub-select by SVC_LISTENER_BADGE.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_services()
                    && self.current_thread_is_main_process_thread()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::ServicesListener)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                SVC_LISTENER_BADGE,
                                HostedThreadRole::ServicesListener,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, SVC_LISTENER_TEB_VA);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::ServicesListener);
                            return 0;
                        }
                    }
                }
                // ★ N-threads multiplex: lsass.exe's FIRST NtCreateThread = an LSA server thread
                // (LsapInitDatabase → StartAuthenticationPort / LsapRmServerThread). Route it through the
                // REAL ETHREAD lifecycle + have the LOOP spawn it RESUMED with a badged fault EP, so it
                // runs into the main multiplex; its faults sub-select to the LSA listener by
                // LSASS_LISTENER_BADGE (its own stack mirror / TEB, distinct from lsass' main thread).
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_lsass()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                LSASS_LISTENER_BADGE,
                                HostedThreadRole::LsassListener,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER_TEB_VA);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::LsassListener { slot: 0 });
                            return 0;
                        }
                    }
                }
                // ★ lsass' SECOND server thread (LsapRmServerThread) — same multiplex, its own badge +
                // its own TEB/stack (LSASS_LISTENER2). Uses the SECOND pool ETHREAD. Without a real,
                // mapped TEB the subsequent NtQueryInformationThread(162) → kernel32 ActCtx copy
                // (mov [newTEB+0x1728]) writes to a stale stack pointer and faults.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_lsass()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener)
                        .is_some()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener2)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                LSASS_LISTENER2_BADGE,
                                HostedThreadRole::LsassListener2,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm.set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER2_TEB_VA);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::LsassListener { slot: 1 });
                            return 0;
                        }
                    }
                }
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_lsass()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener2)
                        .is_some()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener3)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30);
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                LSASS_LISTENER3_BADGE,
                                HostedThreadRole::LsassListener3,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm.set_thread_teb(
                                tid as nt_process::ThreadId,
                                LSASS_LISTENER3_TEB_VA,
                            );
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle);
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::LsassListener { slot: 2 });
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
                // ★ BATCH 35 — N-threads multiplex: services.exe's SECOND NtCreateThread = the SCM
                // RPC listener's PER-CONNECTION worker (rpcrt4 `RPCRT4_new_client`, spawned on
                // winlogon's accepted connection). BEFORE this batch it fell to the 0xC000_009A
                // fallthrough below → the worker never spawned → nobody read winlogon's bind PDU / wrote
                // bind_ack → the SCM RPC round-trip stalled. Route it like the listener: pop a pool
                // ETHREAD (services' slot 1; slot 0 = listener), set its OWN TEB, queue *ThreadHandle +
                // ClientId, and signal the LOOP to spawn it RESUMED with a badged fault EP
                // (SCM_WORKER_BADGE) so it runs into the main multiplex — its faults sub-select to
                // the SCM worker role via its OWN stack mirror/TEB, and its blocking pipe reads park +
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
                // OpenSCManager succeed, advances into GUI code. That route is now enabled: the SCM
                // RPC success path and persistent listener/worker lifecycle are part of the boot
                // frontier, so this recognizer remains keyed by caller identity rather than order.
                const SCM_WORKER_ROUTE_ENABLED: bool = true;
                if SCM_WORKER_ROUTE_ENABLED
                    && matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_services()
                    && self.current_thread_has_role(HostedThreadRole::ServicesListener)
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::ServicesListener)
                        .is_some()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::ScmWorker)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                SCM_WORKER_BADGE,
                                HostedThreadRole::ScmWorker,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, SCM_WORKER_TEB_VA);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::ScmWorker);
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
                // ★ THE LSA SELF-RPC WORKER — lsass.exe's `NtCreateThread` issued FROM its
                // `\pipe\lsarpc` `RPCRT4_server_thread` (badge LSASS_LISTENER3). In rpcrt4 that call is
                // `RPCRT4_new_client(cconn)` → `CreateThread(RPCRT4_io_thread, conn)`
                // (`rpc_server.c:626`), reached from `rpcrt4_protseq_np_wait_for_new_connection`
                // (`rpc_transport.c:1057`) once the accepted connection has been handed off. It is the
                // EXACT counterpart of services' SCM `\ntsvcs` worker above, and it is the thread that
                // reads the LSA RPC bind PDU and answers `LsarOpenPolicy`.
                //
                // Before this recognizer existed the call fell through to the generic paths and no
                // per-connection worker was ever routed — which is why lsass' own `LsaOpenPolicy`
                // (samsrv's `SampGetAccountDomainInfo`, a SELF-RPC into lsass' own LSA RPC surface)
                // blocked forever on its bind_ack read. Identified by CALLER IDENTITY (lsass.exe + the
                // \lsarpc server thread role), never by creation order.
                //
                // ★★ ROUTE ENABLED. The formerly isolated wall is no longer the
                // dispatch-correlation one. With `LSA_WORKER_ROUTE_ENABLED = true` the whole
                // self-RPC RUNS FOR REAL: the worker reads the 72-byte bind (`05 00 0b 03`),
                // `process_bind_packet` writes the 68-byte bind_ack (`05 00 0c 03`) which wakes
                // lsass' own parked client read, the client writes the 56-byte `LsarOpenPolicy`
                // request (`05 00 00 03`), the worker reads it and `QueueUserWorkItem`s
                // `RPCRT4_worker_thread`, and that thread runs the real server stub (it opens
                // `SECURITY\Policy` with KEY_ALL_ACCESS) and writes the 48-byte RESPONSE
                // (`05 00 02 03`). npfs is exonerated (its write completes: `[fsd-ret] ret=0`,
                // `[fsd-done] st=0 info=48`), and so is the dispatch CORRELATION: BOTH substrates
                // now speak seL4 `Call` ⇄ MCS reply objects (`docs/transport-migration.md` Phases
                // 1-2), so a misordered completion is unrepresentable and the executive's answer is
                // a non-blocking `reply_on`. The userspace correlation planes this comment used to
                // name (the `SH_REQ_SEQ` handshake, the per-dispatch token binding) are DELETED.
                //
                // ★ THIS IS THE WALL PHASE 4 RE-TESTS. What it stopped on (measured, instrumented,
                // on the pre-migration transport): the executive's WAKE `Send` for a
                // fresh top-level win32k dispatch (`csrss -> SSN 0x1002`) never returns. The
                // instrumented boot sampled win32k's TCB RIP immediately before every wake: 907 of
                // 908 healthy wakes sample the component's completion-`Send`+2 (win32k runnable, on
                // its way back to its receive), 3 sample the receive syscall itself — and the ONE
                // wake that never completes is the only sample at that receive+2. That wake `Send`
                // NO LONGER EXISTS (the executive replies on a reply object instead). The
                // dispatch-endpoint cap is stable across all 909 wakes (no cap clobber). So the
                // remaining wall is win32k RENDEZVOUS AVAILABILITY under the route's extra
                // concurrency, not reply correlation — a different, newly-separated problem. A
                // timing-perturbed route-ON run also diverges earlier and loses the desktop paint,
                // so the route is NOT safe to enable yet. The counter below still records that
                // `RPCRT4_new_client` was genuinely REACHED. No logon, token or RPC reply is
                // fabricated.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_lsass()
                    && self.current_thread_has_role(HostedThreadRole::LsassListener3)
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener3)
                        .is_some()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsaWorker)
                        .is_none()
                {
                    // Counted whether or not the route is enabled: reaching here PROVES lsass'
                    // `\lsarpc` server thread got through `rpcrt4_ncacn_np_handoff` (the
                    // `GetComputerNameA` -> `NtFlushKey` wall) and called `RPCRT4_new_client`.
                    LSA_RPC_NEW_CLIENT_REQUESTS.fetch_add(1, Ordering::Relaxed);
                }
                if crate::LSA_WORKER_ROUTE_ENABLED
                    && matches!(ctx.service, NativeService::NtCreateThread)
                    && self.current_process_is_lsass()
                    && self.current_thread_has_role(HostedThreadRole::LsassListener3)
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsassListener3)
                        .is_some()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::LsaWorker)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let ctx_va = smss_stack_read(sp + 0x30); // arg6 = Context*
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            ctx_va,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                LSA_WORKER_BADGE,
                                HostedThreadRole::LsaWorker,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, LSA_WORKER_TEB_VA);
                            let pid = self.current_pm_pid().unwrap_or(0);
                            self.queue_write(args[0], handle); // *ThreadHandle
                            let cid_ptr = smss_stack_read(sp + 0x28);
                            if cid_ptr != 0 {
                                self.queue_write(cid_ptr, pid as u64);
                                self.queue_write(cid_ptr + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::LsaWorker);
                            print_str(b"[lsa-worker] recognized lsass' \\lsarpc server-thread NtCreateThread = per-connection RPC worker: entry=0x");
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
                    && self.current_process_is_smss()
                    && self
                        .hosted_thread_tid_for_role(self.pi, HostedThreadRole::SmLoop)
                        .is_none()
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let context = smss_stack_read(sp + 0x30);
                        let start = nt_thread_start::Amd64ThreadContext::read(
                            |address| smss_stack_read(address),
                            context,
                        );
                        let create_suspended = smss_stack_read(sp + 0x40) != 0;
                        if let Some((slot, tid, handle)) =
                            self.nt_create_thread_handle(start.rip, create_suspended, args[1] as u32)
                        {
                            if !self.reserve_created_hosted_thread_role(
                                slot,
                                tid,
                                handle,
                                self.hosted_process_top_badge(self.pi).unwrap_or(0),
                                HostedThreadRole::SmLoop,
                            ) {
                                return 0xC000_009A;
                            }
                            self.pm
                                .set_thread_teb(tid as nt_process::ThreadId, SM_TEB_VA);
                            self.queue_write(args[0], handle);
                            let client_id = smss_stack_read(sp + 0x28);
                            if client_id != 0 {
                                self.queue_write(
                                    client_id,
                                    self.current_pm_pid().unwrap_or(0) as u64,
                                );
                                self.queue_write(client_id + 8, tid);
                            }
                            self.thread_spawn_request =
                                Some(HostedThreadSpawnRequest::SmLoop);
                            return 0;
                        }
                        return 0xC000_009A;
                    }
                }
                // Generic same-process NtCreateThread fallback. Named SM/CSR/RPC routes above keep
                // their custom layouts; every remaining local hosted thread gets a real generic
                // ETHREAD, TEB, ClientId, fault badge, and seL4 TCB.
                if let Some(status) =
                    unsafe { self.create_generic_local_tp_worker_thread(args) }
                {
                    return status;
                }
                // A successful NtCreateThread must publish a typed Thread handle backed by an
                // ETHREAD. Do not mint an opaque handle for an unrecognized or exhausted route:
                // callers immediately query that handle as a thread, and fake success only defers
                // the failure to STATUS_INVALID_HANDLE while corrupting their control flow.
                0xC000_009A // STATUS_INSUFFICIENT_RESOURCES
            }
            // NtSecureConnectPort — the CSR client connect (kernel32's CsrClientConnectToServer →
            // \Windows\ApiPort, from each Win32 client's BaseDllInitialize). The SECURE variant (SecurityQos +
            // ServerSid) is CSR-only in this system: SmConnectToSm uses plain NtConnectPort(33), so 218
            // unambiguously means "a Win32 client connecting to CSR". A client's pending broker
            // connect is completed by the real CsrApiRequestThread rendezvous; the executive fills
            // CSR_API_CONNECTINFO (SharedSection pointers + BASE_STATIC_SERVER_DATA) and the LpcWrite
            // PORT_VIEW because that connect payload is not carried by the isolated broker yet.
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
            // message DATA plane. SM requests are already driven through real SmpApiLoop. CSR API
            // requests now use the same shape when csrss's CsrApiRequestThread is parked on
            // \Windows\ApiPort. If the real worker is unavailable, fail visibly instead of writing a
            // modeled CSR success reply.
            NativeService::NtRequestWaitReplyPort => unsafe {
                if self.current_process_is_smss()
                    && self.lpc_connection_is(args[0], 0, b"\\smapiport")
                {
                    self.sm_request_port = args[0];
                    self.sm_request_message = args[1];
                    self.sm_reply_message = args[2];
                    print_str(b"[sm-api] routing SMSS request to real SmpApiLoop\n");
                    return 0;
                }
                if self.lpc_connection_is(args[0], self.pi, b"\\windows\\apiport") {
                    if CSR_API_RECEIVE_PARKED.load(Ordering::Relaxed) != 0 {
                        self.csr_request_port = args[0];
                        self.csr_request_message = args[1];
                        self.csr_reply_message = args[2];
                        print_str(b"[csr-api] routing CSR request to real CsrApiRequestThread\n");
                        return 0;
                    }
                    CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[csr-api] no parked real CsrApiRequestThread for \\Windows\\ApiPort request -> failing\n");
                    return 0xC000_0001;
                }
                if self.lpc_connection_is(args[0], self.pi, b"\\sermcommandport") {
                    return self.service_srm_request_reply(args[1], args[2]);
                }
                print_str(b"[lpc-msg] NtRequestWaitReplyPort on an unregistered LPC connection -> failing\n");
                0xC000_0008 // STATUS_INVALID_HANDLE
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
                // \SeRmCommandPort — ReactOS' kernel SRM creates this command port before LSASS.
                // LSASS connects during LsapRmInitializeServer; the executive owns the SRM side, drains
                // the broker's connection request, accepts it, and completes it through the same LPC
                // state machine as the user-mode SM/CSR/LSA rendezvous paths.
                if self.current_process_is_lsass()
                    && Self::lpc_name_equals_ascii(&name16, b"\\sermcommandport")
                {
                    return self.connect_srm_command_port(
                        &name16,
                        subsystem_type,
                        &conn_info[..conn_info_len],
                        args[0],
                    );
                }
                if self.lpc_port_handle_for_name16(&name16).is_none() {
                    print_str(b"[lpc-connect] no named LPC port object for ");
                    for &unit in name16.iter().take(64) {
                        let byte = if (0x20..=0x7e).contains(&unit) {
                            unit as u8
                        } else {
                            b'?'
                        };
                        print_str(core::slice::from_ref(&byte));
                    }
                    print_str(b" -> failing\n");
                    return 0xC000_0034;
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
                //
                // ★ LSA RENDEZVOUS. lsass' REAL `LsapHandlePortConnection`
                // (`references/reactos/dll/win32/lsasrv/authport.c:196`) reaches this syscall after the
                // loop woke its `AuthPortThreadRoutine` with winlogon's connection request. The
                // connection id is the one the loop parked the connector on, so this is a REAL broker
                // accept carrying the server's OWN Accept decision (R9) and PortContext (RDX = the
                // LSAP_LOGON_CONTEXT it just built). No override, no fabricated handle.
                let lsa_conn = LSA_PENDING_CONN.load(Ordering::Relaxed);
                if self.current_process_is_lsass() && lsa_conn != 0 {
                    let accept = args[3] != 0;
                    let port_context = args[1];
                    let server_handle = lpc_client()
                        .and_then(|c| c.accept_connect(lsa_conn, accept, port_context).ok())
                        .unwrap_or(0);
                    self.queue_write(args[0], server_handle);
                    LSA_PORT_CONTEXT.store(port_context, Ordering::Relaxed);
                    LSA_ACCEPT_DECISION.store(1 + u64::from(accept), Ordering::Relaxed);
                    print_str(b"[lsa-rdv] real LsapHandlePortConnection NtAcceptConnectPort accept=");
                    print_u64(accept as u64);
                    print_str(b" server-port=0x");
                    print_hex(server_handle as u32);
                    print_str(b" context=0x");
                    print_hex((port_context >> 32) as u32);
                    print_hex(port_context as u32);
                    print_str(b"\n");
                    if !accept {
                        // The server REFUSED. Do not fabricate a completion — the loop wakes the
                        // connector with the refusal status the real server produced.
                        LSA_COMPLETE_PENDING.store(2, Ordering::Relaxed);
                    }
                    return if server_handle != 0 { 0 } else { 0xC000_0001 };
                }
                let h = self.mint_handle();
                self.queue_write(args[0], h);
                0
            },
            NativeService::NtCompleteConnectPort => unsafe {
                // ★ LSA RENDEZVOUS: the real server finished its accept — complete through the broker
                // and hand the LOOP the client comm-port handle to publish into winlogon's *PortHandle.
                let lsa_conn = LSA_PENDING_CONN.load(Ordering::Relaxed);
                if self.current_process_is_lsass() && lsa_conn != 0 {
                    match lpc_client().and_then(|c| c.complete_connect(lsa_conn).ok()) {
                        Some((client_handle, _)) => {
                            LSA_CLIENT_HANDLE.store(client_handle, Ordering::Relaxed);
                            LSA_COMPLETE_PENDING.store(1, Ordering::Relaxed);
                            0
                        }
                        None => {
                            LSA_COMPLETE_PENDING.store(2, Ordering::Relaxed);
                            0xC000_0001
                        }
                    }
                } else {
                    0
                }
            },
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
                // Hosted services: CreateEventW(SCM_START_EVENT/AUTOSTARTCOMPLETE/LSA_RPC_SERVER_ACTIVE/
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
            NativeService::NtCreateMutant => unsafe {
                let out = args[0];
                let oa = args[2];
                let initial_owner = args[3] != 0;
                if out == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if out & 7 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_event_output(out, 8) {
                    return 0xC000_0005;
                }
                let owner = initial_owner.then_some(self.current_tid);

                let create_anonymous = |this: &mut Self| -> Result<u32, u32> {
                    let Some(index) = this.obj_create_anon_mutant(owner) else {
                        return Err(0xC000_009A);
                    };
                    let Some(handle) = this.mint_mutant_handle(index, args[1] as u32) else {
                        this.rollback_new_mutant(index);
                        return Err(0xC000_009A);
                    };
                    if !this.xas_write_u64(out, handle) {
                        this.close_current_handle(handle);
                        this.rollback_new_mutant(index);
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
                if existing.is_some_and(|index| self.obj_ns[index].kind != 4) {
                    return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                }
                let existed = existing.is_some();
                let Some(index) = self.obj_create(path, root_idx, 4, &[]) else {
                    return 0xC000_009A;
                };
                let initialized = self.mutants.contains(index as u64);
                if !initialized {
                    self.mutants.initialize(index as u64, owner);
                }
                let Some(handle) = self.mint_mutant_handle(index, args[1] as u32) else {
                    if !existed {
                        self.rollback_new_mutant(index);
                    }
                    return 0xC000_009A;
                };
                if !self.xas_write_u64(out, handle) {
                    self.close_current_handle(handle);
                    if !existed {
                        self.rollback_new_mutant(index);
                    }
                    return 0xC000_0005;
                }
                if existed && initialized { 0x4000_0000 } else { 0 }
            },
            NativeService::NtOpenMutant => unsafe {
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
                if self.obj_ns[index].kind != 4 {
                    return 0xC000_0024; // STATUS_OBJECT_TYPE_MISMATCH
                }
                if !self.mutants.contains(index as u64) {
                    return 0xC000_0008; // STATUS_INVALID_HANDLE
                }
                let Some(handle) = self.mint_mutant_handle(index, args[1] as u32) else {
                    return 0xC000_009A;
                };
                if !self.xas_write_u64(out, handle) {
                    self.close_current_handle(handle);
                    return 0xC000_0005;
                }
                0
            },
            NativeService::NtReleaseMutant => {
                let previous_count = args[1];
                if previous_count != 0 && previous_count & 3 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if previous_count != 0
                    && !unsafe { self.probe_event_output(previous_count, 4) }
                {
                    return 0xC000_0005;
                }
                let index = match self.mutant_index_for_handle(args[0], 0) {
                    Ok(index) => index,
                    Err(status) => return status,
                };
                let previous = match self.mutants.release(index as u64, self.current_tid) {
                    Ok(previous) => previous,
                    Err(nt_kernel_exec::MutantError::NotFound) => return 0xC000_0008,
                    // Older boot scaffolding modeled mutant release as success for any live handle.
                    // Keep that tolerance in the executive until mutant waits participate in real
                    // owner transfer; strict store semantics are covered in nt-kernel-exec tests.
                    Err(nt_kernel_exec::MutantError::NotOwned) => 0,
                };
                unsafe {
                    wait_wake_dispatcher_set(self);
                    if previous_count != 0
                        && !self.xas_write_u32(previous_count, previous as u32)
                    {
                        return 0xC000_0005;
                    }
                }
                0
            },
            // NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle): resolve the target
            // EPROCESS, open its primary token into the caller's typed handle table, and preserve
            // the requested token access mask for later checks.
            NativeService::NtOpenProcessToken => unsafe {
                self.nt_open_process_token(args[0], args[1] as u32, args[2])
            },
            NativeService::NtOpenProcessTokenEx => unsafe {
                self.nt_open_process_token(args[0], args[1] as u32, args[3])
            },
            NativeService::NtDuplicateToken => unsafe { self.nt_duplicate_token(args) },
            // NtCreateToken — 13 args (4 register + 9 stack). See `nt_create_token`.
            NativeService::NtCreateToken => unsafe { self.nt_create_token(args) },
            NativeService::NtAccessCheck => unsafe { self.nt_access_check(ctx, args) },
            NativeService::NtResumeThread => unsafe {
                self.nt_resume_thread_with_user_memory(args, SyscallUserMemory::CurrentProcess)
            },
            // NtMakeTemporaryObject — clears OBJ_PERMANENT on a link SmpInit re-creates; we don't
            // track permanence. Success no-op.
            NativeService::NtMakeTemporaryObject => 0,
            // NtCreateKeyedEvent(*OutHandle, AccessMask, ObjectAttributes, Flags). ReactOS'
            // RtlpInitializeKeyedEvent ignores the returned status and later asserts that its
            // process-global keyed-event handle is non-NULL, so success must publish a real handle.
            NativeService::NtCreateKeyedEvent => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
                const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

                let out_handle = args[0];
                let desired_access = args[1] as u32;
                let _object_attributes = args[2];
                let flags = args[3];
                if flags != 0 {
                    return STATUS_INVALID_PARAMETER;
                }
                if out_handle == 0 {
                    return STATUS_ACCESS_VIOLATION;
                }
                if out_handle & 7 != 0 {
                    return STATUS_DATATYPE_MISALIGNMENT;
                }
                if !self.probe_event_output(out_handle, 8) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let handle = self.mint_keyed_event_handle(desired_access);
                if !self.xas_write_u64(out_handle, handle) {
                    self.close_current_handle(handle);
                    return STATUS_ACCESS_VIOLATION;
                }
                0
            },
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
            // Model the process information classes now used on the live boot route. Unknown classes
            // still degrade as success for compatibility with existing callers that only probe whether
            // the setter exists.
            NativeService::NtSetInformationProcess => unsafe {
                if args[1] == 9 {
                    return self.nt_set_process_access_token(args);
                }
                if args[1] == 12 {
                    const PROCESS_SET_INFORMATION: u32 = 0x0200;
                    if args[3] != 4 {
                        return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                    }
                    let mut value = [0u8; 4];
                    if args[2] == 0 || !self.xas_read(args[2], &mut value) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
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
                    return match self.pm.set_process_default_hard_error_processing(
                        pid,
                        u32::from_le_bytes(value),
                    ) {
                        Ok(()) => 0,
                        Err(status) => status,
                    };
                }
                if args[1] == 18 {
                    const PROCESS_SET_INFORMATION: u32 = 0x0200;
                    if args[3] != 2 {
                        return 0xC000_0004; // STATUS_INFO_LENGTH_MISMATCH
                    }
                    let mut value = [0u8; 2];
                    if args[2] == 0 || !self.xas_read(args[2], &mut value) {
                        return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                    }
                    let priority_class = value[1];
                    if priority_class == nt_process::PROCESS_PRIORITY_CLASS_REALTIME
                        && !self.current_token_has_privilege(nt_security::SE_INCREASE_BASE_PRIORITY)
                    {
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
                    return match self.pm.set_process_priority_class(pid, priority_class) {
                        Ok(()) => 0,
                        Err(status) => status,
                    };
                }
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
                let information_class = args[1] as u32;
                if information_class == 5 {
                    return self.nt_set_thread_impersonation_token(args);
                }
                if information_class == 38 {
                    return self.nt_set_thread_name(args[0], args[2], args[3] as u32);
                }
                let expected = match Self::thread_set_length(information_class) {
                    Ok(length) => length,
                    _ => return 0,
                };
                if args[3] as usize != expected {
                    return 0xC000_0004;
                }
                let mut value = [0u8; 8];
                if expected != 0 {
                    if args[2] & 3 != 0 {
                        return 0x8000_0002;
                    }
                    if args[2] == 0 || !self.xas_read(args[2], &mut value[..expected]) {
                        return 0xC000_0005;
                    }
                }
                self.set_thread_information_captured(
                    args[0],
                    information_class,
                    u64::from_le_bytes(value),
                )
            },
            NativeService::NtSetSystemInformation => unsafe {
                use nt_syscall::system_information::{
                    set_current_time_zone_plan, SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS,
                    SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE,
                };

                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

                let class = args[0] as u32;
                if class != SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS {
                    return 0;
                }
                let buffer = args[1];
                let length = args[2] as usize;
                if length != 0 && buffer & 3 != 0 {
                    return STATUS_DATATYPE_MISALIGNMENT;
                }
                if length != 0 {
                    let Some(last) = buffer.checked_add(length as u64 - 1) else {
                        return STATUS_ACCESS_VIOLATION;
                    };
                    if last > 0x0000_07ff_fffe_ffff {
                        return STATUS_ACCESS_VIOLATION;
                    }
                }
                let copy_length = match set_current_time_zone_plan(length) {
                    Ok(copy_length) => copy_length,
                    Err(status) => return status,
                };
                let mut encoded = [0u8; SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE];
                if copy_length != encoded.len() || !self.xas_read(buffer, &mut encoded) {
                    return STATUS_ACCESS_VIOLATION;
                }
                let Some(information) =
                    nt_kernel_exec::timezone::TimeZoneInformation::decode_prefix(&encoded)
                else {
                    return 0xC000_0004;
                };
                self.time_zone_information = information;
                // The hosted clock is already UTC-backed, so changing timezone metadata does not
                // retime a local CMOS clock. Publish the new bias/id to every KUSER page instead.
                unsafe { publish_time_zone(information, nt_system_time_100ns()) };
                0
            },
            NativeService::NtFreeVirtualMemory => unsafe { self.nt_free_virtual_memory(args) },
            NativeService::NtReadVirtualMemory => unsafe {
                self.nt_copy_virtual_memory(args, true)
            },
            NativeService::NtWriteVirtualMemory => unsafe {
                self.nt_copy_virtual_memory(args, false)
            },
            // NtUnmapViewOfSection(ProcessHandle, BaseAddress). We still never RECLAIM a mapped
            // view (the bump allocator never frees) → STATUS_SUCCESS exactly as before; what is new
            // is `DbgkUnMapViewOfSection`, which reports the unmap of an IMAGE view to the calling
            // process's debugger. Only a view this process's map path RECORDED is an image view, so
            // a data/anonymous base reports nothing — `MmUnmapViewOfSection`'s `if (DbgBase)`. With
            // no debugger the helper returns on its first line.
            NativeService::NtUnmapViewOfSection => {
                self.dbgk_module_unload(self.pi, args.get(1).copied().unwrap_or(0));
                0
            }
            NativeService::NtTestAlert
            | NativeService::NtInitializeRegistry
            | NativeService::NtSetSecurityObject
            // winlogon's SetDefaultLanguage(NULL) sets the system default UI locale after reading the
            // Nls\Language\Default LCID. No kernel locale plane to mutate in this single-user host →
            // no-op SUCCESS (the LCID is validated; nothing consumes a stored system locale here).
            | NativeService::NtSetDefaultLocale => 0,
            NativeService::NtSetInformationObject => unsafe {
                self.nt_set_information_object_with_user_memory(
                    args,
                    SyscallUserMemory::CurrentProcess,
                )
            },
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
                const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
                const TOKEN_QUERY: u32 = 0x0008;
                let class = args[1];
                let buf = args[2];
                let len = args[3] as usize;
                let retlen_ptr = args[4];
                if retlen_ptr == 0 || !self.probe_user_output(retlen_ptr, 4) {
                    return STATUS_ACCESS_VIOLATION;
                }
                if class == 9 && len != 4 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let token_id = match self.token_id_for_handle(args[0], TOKEN_QUERY) {
                    Ok(token) => token,
                    Err(status) => return status,
                };
                // ★ The LOGON TOKEN round trip. `LsapLogonUser` ends by duplicating the token it
                // minted into the CLIENT process (`NtDuplicateObject(..., ClientProcessHandle, ...,
                // DUPLICATE_CLOSE_SOURCE)`, authpackage.c:1712). Count winlogon (pi 2) querying THAT
                // token object — proof the handle crossed processes and resolves to the same object
                // the `NtCreateToken` service inserted, not to winlogon's own primary token.
                if self.current_process_is_winlogon()
                    && token_id.raw() as u64 == SE_CREATE_TOKEN_ID.load(Ordering::Relaxed)
                    && SE_CREATE_TOKEN_ID.load(Ordering::Relaxed) != 0
                {
                    WINLOGON_LOGON_TOKEN_QUERIES.fetch_add(1, Ordering::Relaxed);
                }
                let token = match self.token_store.get(token_id) {
                    Some(token) => token,
                    None => return 0xC000_0008,
                };
                // The modeled tokens have a 500-byte dynamic charge, which bounds a replacement
                // default ACL query to 500 bytes including its pointer.
                let mut output = [0u8; 512];
                let needed = match class {
                    1 => {
                        // TOKEN_USER: aligned SID_AND_ATTRIBUTES followed by the user SID.
                        let sid_length = token.user.write_native(&mut output[16..]).unwrap_or(0);
                        output[..8].copy_from_slice(&buf.wrapping_add(16).to_le_bytes());
                        16 + sid_length
                    }
                    2 => {
                        // TOKEN_GROUPS. `userenv!CheckForGuestsAndAdmins` (profile.c:365) and
                        // `winlogon!AllowAccessOnSession` (security.c:1400) both size this buffer
                        // with a NULL/zero-length query and REQUIRE the `STATUS_BUFFER_TOO_SMALL`
                        // (⇒ ERROR_INSUFFICIENT_BUFFER) answer; returning INVALID_INFO_CLASS made
                        // them report `Error 87` and give up. Encoding lives in `nt-security`.
                        match nt_security::encode_token_groups(token, buf, &mut output) {
                            Ok(encoded) => encoded.required_length,
                            Err(_) => return 0xC000_0078, // STATUS_INVALID_SID
                        }
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
                    4 => {
                        // TOKEN_OWNER: pointer followed immediately by the current owner SID.
                        match nt_security::encode_token_owner(token, buf, &mut output) {
                            Ok(encoded) => encoded.required_length,
                            Err(_) => return 0xC000_0078, // STATUS_INVALID_SID
                        }
                    }
                    5 => {
                        // TOKEN_PRIMARY_GROUP: pointer followed immediately by the SID.
                        let sid_length =
                            token.primary_group.write_native(&mut output[8..]).unwrap_or(0);
                        output[..8].copy_from_slice(&buf.wrapping_add(8).to_le_bytes());
                        8 + sid_length
                    }
                    6 => {
                        // TOKEN_DEFAULT_DACL: null pointer or in-buffer lossless native ACL.
                        nt_security::encode_token_default_dacl(token, buf, &mut output)
                            .required_length
                    }
                    8 => {
                        output[..4].copy_from_slice(&(token.token_type as u32).to_le_bytes());
                        4
                    }
                    9 => {
                        if token.token_type != nt_security::TokenType::Impersonation {
                            return STATUS_INVALID_INFO_CLASS;
                        }
                        output[..4]
                            .copy_from_slice(&(token.impersonation_level as u32).to_le_bytes());
                        4
                    }
                    10 => {
                        let statistics = match self.token_store.statistics(token_id) {
                            Some(statistics) => statistics,
                            None => return 0xC000_0008,
                        };
                        nt_security::encode_token_statistics(statistics, &mut output)
                            .required_length
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
            // *RetLen[arg5]=args[4]).
            NativeService::NtQueryObject => unsafe {
                self.nt_query_object_with_user_memory(args, SyscallUserMemory::CurrentProcess)
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
            // entries. Context is the next-child index (0 on RestartScan).
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
                            OBJ_KIND_EVENT => "Event",
                            OBJ_KIND_SYMBOLIC_LINK => "SymbolicLink",
                            OBJ_KIND_SEMAPHORE => "Semaphore",
                            OBJ_KIND_MUTANT => "Mutant",
                            OBJ_KIND_LPC_PORT => "Port",
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
                                | nt_process::HandleObject::OverlayFile(_)
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
            // NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            // FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName,
            // RestartScan). Directory-open state is shared by duplicated handles.
            NativeService::NtQueryDirectoryFile => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
                const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
                const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
                const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
                const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
                const GENERIC_READ: u32 = 0x8000_0000;
                const GENERIC_ALL: u32 = 0x1000_0000;
                const MAX_QUERY_BUFFER: usize = 1024 * 1024;

                let iosb = args[4];
                let output = args[5];
                crate::writable_fs::trace_dir_refusal(
                    b"call", self.pi, args[0], iosb, output, args[6] as usize, args[7],
                );
                if args[2] != 0 {
                    crate::writable_fs::trace_dir_refusal(
                        b"REFUSED apc-unsupported", self.pi, args[0], iosb, output, args[6] as usize, args[7],
                    );
                    return STATUS_NOT_SUPPORTED;
                }
                let event_index = if args[1] == 0 {
                    None
                } else {
                    match self.event_index_for_handle(args[1], 0) {
                        Ok(index) => Some(index),
                        Err(status) => return status,
                    }
                };
                // ★ STACK-ARGUMENT WIDTHS. `Length` is a **ULONG** and `ReturnSingleEntry` /
                // `RestartScan` are **BOOLEAN**s, but they are 5th+ arguments and therefore live on
                // the caller's stack: MSVC stores them with a 32-bit `mov dword ptr [rsp+N]` and
                // leaves the upper half of the 8-byte slot holding whatever was there before (in
                // practice the high half of a previously-stored pointer, `0x0000_0100`). Reading
                // the slot as a full u64 saw `0x0000_0100_0000_4000` for a 16384-byte buffer, which
                // failed the `MAX_QUERY_BUFFER` bound and returned STATUS_INSUFFICIENT_RESOURCES ⇒
                // `GetLastError() == 1450` — the wall `CopyDirectory`'s `FindNextFileW` hit at
                // `directory.c:160`. Truncating to the declared parameter width is what the real
                // syscall stub does.
                //
                // ★ SCOPED, deliberately. The truncation is correct for EVERY caller, but applying
                // it on the read-only FAT path also makes a large population of previously-failing
                // loader enumerations succeed at once across smss/csrss/services/lsass — a real
                // behaviour change which was MEASURED to destabilise the boot (each such call
                // rescans a ~700-entry `\reactos` directory twice, and the boot stopped reaching
                // its quiesce inside the gate's time budget). So it is applied to the WRITABLE
                // VOLUME only; the read-only path keeps its pre-batch bound, unchanged. Widening
                // the FAT path — with a per-`FILE_OBJECT` scan cache to pay for it — is a separate,
                // tracked step, not something to smuggle in behind a profile batch.
                let overlay_target = self
                    .pm_pid_for_pi(self.pi)
                    .and_then(|pid| self.pm.lookup_handle(pid, args[0] as nt_process::Handle))
                    .is_some_and(|object| {
                        matches!(object, nt_process::HandleObject::OverlayFile(_))
                    });
                let raw_length = if overlay_target { args[6] & 0xFFFF_FFFF } else { args[6] };
                let length = match usize::try_from(raw_length) {
                    Ok(length) if length <= MAX_QUERY_BUFFER => length,
                    _ => return STATUS_INSUFFICIENT_RESOURCES,
                };
                let information_class = args[7] as u32;
                let (return_single_entry, restart_scan) = if overlay_target {
                    (args[8] as u8 != 0, args[10] as u8 != 0)
                } else {
                    (args[8] != 0, args[10] != 0)
                };
                if iosb == 0 || output == 0 {
                    return STATUS_ACCESS_VIOLATION;
                }
                // ★ NT requires the FileInformation buffer to be **ULONG**-aligned, not ULONGLONG:
                // `IopQueryDirectoryFile` checks `(ULONG_PTR)FileInformation & (sizeof(ULONG)-1)`.
                // kernel32's `FindFirstFileExW` relies on exactly that — its 16 KiB scratch buffer
                // is declared `DECLSPEC_ALIGN(4) BYTE DirectoryInfo[FIND_DATA_SIZE]`
                // (`kernel32/client/file/find.c:694`, with the comment "NtQueryDirectoryFile
                // requires the buffer to be ULONG-aligned"). Our 8-byte gate was stricter than the
                // kernel it models, so a legitimately 4-aligned buffer was rejected with
                // STATUS_DATATYPE_MISALIGNMENT ⇒ `GetLastError() == 998`. The IO_STATUS_BLOCK is
                // still ULONGLONG-aligned (a pointer-sized field pair), as NT requires.
                if iosb & 7 != 0 || output & 3 != 0 {
                    crate::writable_fs::QUERY_DIR_MISALIGNED.fetch_add(1, Ordering::Relaxed);
                    crate::writable_fs::trace_dir_refusal(
                        b"REFUSED misaligned", self.pi, args[0], iosb, output, length, args[7],
                    );
                    return STATUS_DATATYPE_MISALIGNMENT;
                }
                if !self.probe_user_output(iosb, 16) {
                    crate::writable_fs::QUERY_DIR_IOSB_UNREACHABLE.fetch_add(1, Ordering::Relaxed);
                    crate::writable_fs::trace_dir_refusal(
                        b"REFUSED iosb-unreachable", self.pi, args[0], iosb, output, length, args[7],
                    );
                    return STATUS_ACCESS_VIOLATION;
                }
                if !self.probe_user_output(output, length) {
                    crate::writable_fs::QUERY_DIR_BUFFER_UNREACHABLE.fetch_add(1, Ordering::Relaxed);
                    crate::writable_fs::trace_dir_refusal(
                        b"REFUSED buffer-unreachable", self.pi, args[0], iosb, output, length, args[7],
                    );
                    return STATUS_ACCESS_VIOLATION;
                }

                let pid = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => return nt_fs::STATUS_INVALID_HANDLE,
                };
                let handle = args[0] as nt_process::Handle;
                let (first_cluster, object_id) = match self.pm.lookup_handle(pid, handle) {
                    Some(nt_process::HandleObject::Directory {
                        first_cluster,
                        object_id,
                    }) => (first_cluster, object_id),
                    // ★ THE WRITABLE FILESYSTEM OVERLAY: enumerate what is really on the volume.
                    // The cursor lives in the volume's own FILE_OBJECT, so a resumed scan and a
                    // RestartScan behave exactly as they do for the read-only FAT directories.
                    Some(nt_process::HandleObject::OverlayFile(file_id)) => {
                        let granted = self.pm.handle_access(pid, handle).unwrap_or(0);
                        if granted & (FILE_LIST_DIRECTORY | GENERIC_READ | GENERIC_ALL) == 0 {
                            crate::writable_fs::trace_dir_refusal(
                                b"REFUSED access-denied", self.pi, args[0], iosb, output, length, granted as u64,
                            );
                            return nt_fs::STATUS_ACCESS_DENIED;
                        }
                        let mut pattern = [0u16; nt_fs::MAX_DIRECTORY_NAME];
                        let pattern_len = match self.read_directory_pattern(args[9], &mut pattern) {
                            Ok(length) => length,
                            Err(status) => {
                                crate::writable_fs::trace_dir_refusal(
                                    b"REFUSED pattern-unreadable", self.pi, args[9], iosb, output, length, status as u64,
                                );
                                return status;
                            }
                        };
                        let pattern = (args[9] != 0).then_some(&pattern[..pattern_len]);
                        let mut encoded = alloc::vec::Vec::new();
                        if encoded.try_reserve_exact(length).is_err() {
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                        encoded.resize(length, 0);
                        // NOTE: deliberately NOT `writable_fs_dirty`. Reaching this arm means a
                        // volume file object already exists, so the volume is mounted and an
                        // enumeration mutates only the FILE_OBJECT's fixed-size cursor — nothing
                        // is allocated that must outlive the syscall. Pinning here would strand
                        // this `length`-byte encode buffer (16 KiB for every `FindFirstFileW`)
                        // on the no-free bump heap for the rest of the boot.
                        let result = crate::writable_fs::query_directory(
                            file_id,
                            information_class,
                            return_single_entry,
                            pattern,
                            restart_scan,
                            &mut encoded,
                        );
                        let mut iosb_bytes = [0u8; 16];
                        iosb_bytes[..4].copy_from_slice(&result.status.to_le_bytes());
                        iosb_bytes[8..]
                            .copy_from_slice(&(result.information as u64).to_le_bytes());
                        if !self.xas_try_write_buf(output, &encoded[..result.information])
                            || !self.xas_try_write_buf(iosb, &iosb_bytes)
                        {
                            return STATUS_ACCESS_VIOLATION;
                        }
                        if let Some(index) = event_index {
                            if self.events.set_existing(index as u64).is_none() {
                                return nt_fs::STATUS_INVALID_HANDLE;
                            }
                            let _ = wait_wake_dispatcher(self, None);
                        }
                        return result.status;
                    }
                    Some(_) => {
                        crate::writable_fs::trace_dir_refusal(
                            b"REFUSED type-mismatch", self.pi, args[0], iosb, output, length, args[7],
                        );
                        return STATUS_OBJECT_TYPE_MISMATCH;
                    }
                    None => {
                        crate::writable_fs::trace_dir_refusal(
                            b"REFUSED no-handle", self.pi, args[0], iosb, output, length, args[7],
                        );
                        return nt_fs::STATUS_INVALID_HANDLE;
                    }
                };
                let granted = self.pm.handle_access(pid, handle).unwrap_or(0);
                if granted & (FILE_LIST_DIRECTORY | GENERIC_READ | GENERIC_ALL) == 0 {
                    return nt_fs::STATUS_ACCESS_DENIED;
                }
                let open = match self.directory_opens.get(object_id) {
                    Ok(open) if open.first_cluster == first_cluster => *open,
                    _ => return nt_fs::STATUS_INVALID_HANDLE,
                };
                let fs = match exec_fs() {
                    Some(fs) => fs,
                    None => return 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                };

                let mut pattern = [0u16; nt_fs::MAX_DIRECTORY_NAME];
                let pattern_len = match self.read_directory_pattern(args[9], &mut pattern) {
                    Ok(length) => length,
                    Err(status) => return status,
                };
                let pattern = (args[9] != 0).then_some(&pattern[..pattern_len]);

                let mut entry_count = 0usize;
                fat_visit_directory(&fs, first_cluster, |_| {
                    entry_count = entry_count.saturating_add(1);
                    true
                });
                let mut entries = alloc::vec::Vec::new();
                if entries.try_reserve_exact(entry_count).is_err() {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                fat_visit_directory(&fs, first_cluster, |entry| {
                    entries.push(entry);
                    true
                });

                let mut encoded = alloc::vec::Vec::new();
                if encoded.try_reserve_exact(length).is_err() {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                encoded.resize(length, 0);
                let result = {
                    let directory = match self.directory_opens.get_mut(object_id) {
                        Ok(directory) => directory,
                        Err(status) => return status,
                    };
                    nt_fs::query_directory(
                        &mut directory.query,
                        &entries,
                        information_class,
                        return_single_entry,
                        pattern,
                        restart_scan,
                        &mut encoded,
                    )
                };
                let mut iosb_bytes = [0u8; 16];
                iosb_bytes[..4].copy_from_slice(&result.status.to_le_bytes());
                iosb_bytes[8..].copy_from_slice(&(result.information as u64).to_le_bytes());
                if !self.xas_try_write_buf(output, &encoded[..result.information])
                    || !self.xas_try_write_buf(iosb, &iosb_bytes)
                {
                    if let Ok(directory) = self.directory_opens.get_mut(object_id) {
                        directory.query = open.query;
                    }
                    return STATUS_ACCESS_VIOLATION;
                }
                if let Some(index) = event_index {
                    if self.events.set_existing(index as u64).is_none() {
                        return nt_fs::STATUS_INVALID_HANDLE;
                    }
                    let _ = wait_wake_dispatcher(self, None);
                }
                result.status
            }
            // NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
            // FileInformationClass). Resolve process-local ownership here; nt-fs owns the ABI layout.
            NativeService::NtQueryInformationFile => unsafe {
                let iosb = args[1];
                let output = args[2];
                let length = args[3] as usize;
                let class = args[4] as u32;
                // 40 = the largest class this encoder produces (FILE_BASIC_INFORMATION); it was 24
                // when FILE_STANDARD_INFORMATION was the only one supported.
                let mut encoded = [0u8; 40];
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
                    // ★ THE WRITABLE FILESYSTEM OVERLAY: the size/kind the volume really holds.
                    nt_process::HandleObject::OverlayFile(file_id) => {
                        crate::writable_fs::standard_information(file_id)
                            .map(|info| (info.end_of_file, info.is_directory))
                    }
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
                        } else if let Some(index) =
                            (&*ctx.exe_images).index_for_file(self.pi, args[0])
                        {
                            (&*ctx.exe_images)
                                .get(index)
                                .map(|slot| (slot.metadata.file_size, false))
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
            // *RegionSize[R9]=args[3], Type[arg5]=args[4], Protect). The fixed VAD policy selects
            // the target process's range; newly committed pages are mapped into that target PML4.
            NativeService::NtAllocateVirtualMemory => unsafe {
                self.nt_allocate_virtual_memory_with_user_memory(
                    args,
                    SyscallUserMemory::CurrentProcess,
                )
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
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
                let ctx = self.loop_ctx.unwrap();
                let reg = &*ctx.reg;
                let name16 = self.read_objattr_name_pe(args[0]);
                if name16.is_empty() {
                    return STATUS_OBJECT_NAME_INVALID;
                }
                // ★ THE WRITABLE FILESYSTEM OVERLAY answers by-path attribute queries for its own
                // namespace — `GetFileAttributesW` is how `LoadUserProfileW` (profile.c:2085) asks
                // whether the user's hive already exists, and how `CreateDirectoryPath` probes.
                // A miss here is a REAL miss (the file is not on the volume), never a fake EXISTS.
                if let Some(relative) = crate::writable_fs::writable_path(&name16) {
                    self.writable_fs_dirty = true;
                    return match crate::writable_fs::query_attributes(&relative) {
                        Some(info)
                            if self.write_file_basic_attributes(args[1], info.attributes) =>
                        {
                            nt_fs::STATUS_SUCCESS
                        }
                        Some(_) => STATUS_ACCESS_VIOLATION,
                        None => nt_fs::STATUS_OBJECT_NAME_NOT_FOUND,
                    };
                }
                // General read-only namespace lookup. This is intentionally below the writable
                // mount so C:\Profiles remains overlay-backed, but above the loader-specific EXE/DLL
                // probes. In particular msgina passes C:\Windows as userinit's current directory;
                // the canonicalizer maps it to the real FAT `reactos` directory and this returns its
                // genuine FILE_ATTRIBUTE_DIRECTORY bit.
                if let Some(attributes) = crate::fs_loader::query_nt_path_attributes(&name16) {
                    return if self.write_file_basic_attributes(args[1], attributes) {
                        nt_fs::STATUS_SUCCESS
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
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
                // csrss/winlogon). Existence comes from the REAL \reactos FS by-path and the shared
                // hosted-image catalog root — no hand-maintained list — keyed on the CANONICAL leaf
                // the substring classifies (ReactOS sometimes builds a malformed probe path, e.g.
                // `\??\C:\Windowsservices.exe` with no separator, so the extracted leaf is garbage;
                // the substring reliably says WHICH EXE it wants). SxS probes are rejected (loader
                // must not take the .Local\/manifest path). Content delivery stays on nt-dll-registry.
                let catalog = &*ctx.exe_image_catalog;
                let exe_exists = Self::exe_probe_image(catalog, &nb[..nlen], is_sxs)
                    .is_some_and(Self::hosted_image_exists);
                // General DLL existence (pi>=1) also comes from the real FS by-path.
                let dll_exists = self.pi >= 1 && self.fs_system32_has(&nb[..nlen]);
                let status: u32 = if exe_exists {
                    // FILE_BASIC_INFORMATION: 4×8-byte times, then FileAttributes(u32) @ +0x20.
                    if self.write_file_basic_attributes(args[1], nt_fs::FILE_ATTRIBUTE_NORMAL) {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                } else if dll_exists {
                    if self.write_file_basic_attributes(args[1], nt_fs::FILE_ATTRIBUTE_NORMAL) {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
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
                let packet = nt_io_completion::CompletionPacket {
                    key_context: args[1],
                    apc_context: args[2],
                    status: args[3] as u32,
                    information: args[4],
                };
                self.post_io_completion_packet(object_id, packet)
            },
            NativeService::NtRemoveIoCompletion => unsafe {
                const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
                const IO_COMPLETION_MODIFY_STATE: u32 = 0x2;
                let object_id = match self.io_completion_id_for(args[0], IO_COMPLETION_MODIFY_STATE) {
                    Ok(id) => id,
                    Err(status) => return status,
                };
                if !self.probe_user_output(args[1], 8)
                    || !self.probe_user_output(args[2], 8)
                    || !self.probe_user_output(args[3], 16)
                {
                    return STATUS_ACCESS_VIOLATION;
                }
                let timeout_interval = if args[4] == 0 {
                    None
                } else {
                    let mut timeout = [0u8; 8];
                    if !self.xas_read(args[4], &mut timeout) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    Some(i64::from_le_bytes(timeout))
                };
                let mode = if timeout_interval == Some(0) {
                    nt_io_completion::RemoveMode::Poll
                } else {
                    nt_io_completion::RemoveMode::Wait
                };
                match self.io_completion_ports.remove(object_id, mode) {
                    Ok(nt_io_completion::RemoveResult::Packet(packet)) => {
                        let copied = self
                            .xas_try_write_buf(args[2], &packet.apc_context.to_le_bytes())
                            && self.xas_try_write_buf(args[1], &packet.key_context.to_le_bytes())
                            && self.xas_try_write_buf(args[3], &packet.status.to_le_bytes())
                            && self.xas_try_write_buf(
                                args[3] + 8,
                                &packet.information.to_le_bytes(),
                            );
                        if copied {
                            nt_io_completion::STATUS_SUCCESS
                        } else {
                            STATUS_ACCESS_VIOLATION
                        }
                    }
                    Ok(nt_io_completion::RemoveResult::Empty(status)) => {
                        if status != nt_io_completion::STATUS_PENDING {
                            return status;
                        }
                        let deadline = match timeout_interval {
                            None => u64::MAX,
                            Some(interval) => match nt_delay_execution::due_time(
                                interval,
                                monotonic_time_100ns(),
                                nt_system_time_100ns(),
                            ) {
                                nt_delay_execution::Due::Immediate => {
                                    return nt_io_completion::STATUS_TIMEOUT;
                                }
                                nt_delay_execution::Due::Monotonic100ns(deadline) => deadline,
                            },
                        };
                        self.io_completion_park_port = object_id as i64;
                        self.io_completion_key_out = args[1];
                        self.io_completion_apc_out = args[2];
                        self.io_completion_iosb_out = args[3];
                        self.io_completion_deadline_100ns = deadline;
                        if !NT_REMOVE_IO_COMPLETION_WAIT_TRACED.swap(true, Ordering::Relaxed) {
                            print_str(b"[nt-remove-io-completion] pi="); print_u64(self.pi as u64);
                            print_str(b" empty blocking wait -> reply-cap park armed\n");
                        }
                        nt_io_completion::STATUS_PENDING
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
                    } else {
                        let leaf = Self::pipe_leaf16(&name16);
                        match self.npfs_route(0, 0, &leaf, 0) {
                            Some((st, file_id)) => {
                                status = st as u32;
                                if status == nt_fs::STATUS_SUCCESS && file_id != 0 {
                                    let options = args[8] as u32;
                                    let synchronous = options
                                        & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT
                                            | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
                                        != 0;
                                    if let Some(handle) =
                                        self.mint_file_handle(file_id, args[1] as u32, synchronous)
                                    {
                                        self.queue_write(args[0], handle);
                                        info = nt_fs::FILE_OPENED as u64;
                                        // ★ BATCH 34: client CONNECT (winlogon's NtCreateFile on \pipe\ntsvcs)
                                        // paired with the server end by name → complete the pending async
                                        // server listen FOR THAT PIPE NAME (signal its completion event → the
                                        // SCM listener's NtWaitForMultipleObjects wakes to read the bind PDU).
                                        let pipe_hash = nt_io_manager::pipe_name_hash(&leaf);
                                        self.pipe_connect_redrive = pipe_hash;
                                        crate::pipe_fid_name_remember(file_id, pipe_hash);
                                    } else {
                                        status = 0xC000_009A;
                                    }
                                } else if status == nt_fs::STATUS_SUCCESS {
                                    status = nt_fs::STATUS_INVALID_DEVICE_REQUEST;
                                }
                            }
                            None => status = nt_fs::STATUS_OBJECT_PATH_NOT_FOUND,
                        };
                    }
                } else if let Some(relative) = crate::writable_fs::writable_path(&name16) {
                    // ★ THE WRITABLE FILESYSTEM OVERLAY. The path resolved into a declared writable
                    // mount prefix (see `writable_fs::WRITABLE_PREFIXES`) — this is the seam the
                    // previous batch's STATUS_NOT_IMPLEMENTED miss left open, and it is where
                    // `CreateDirectoryW("C:\Profiles")` (userenv/profile.c:929) now lands. The
                    // disposition, `FILE_DIRECTORY_FILE`, and `FileAttributes` are passed straight
                    // through to a REAL file system: a create that cannot be satisfied still fails
                    // with the correct NTSTATUS, and no handle is fabricated.
                    self.writable_fs_dirty = true;
                    let (st, file_id, information) = crate::writable_fs::create(
                        &relative,
                        args[1] as u32,
                        args[5] as u32,
                        args[6] as u32,
                        args[7] as u32,
                        args[8] as u32,
                    );
                    status = st;
                    info = information;
                    if args[8] as u32 & nt_fs::FILE_DIRECTORY_FILE != 0 {
                        if status == nt_fs::STATUS_SUCCESS && info == nt_fs::FILE_CREATED as u64 {
                            crate::writable_fs::note_directory_create(self.pi, &relative, true);
                        } else if status == nt_fs::STATUS_OBJECT_NAME_COLLISION {
                            crate::writable_fs::note_directory_create(self.pi, &relative, false);
                        }
                    } else if status == nt_fs::STATUS_SUCCESS
                        && info == nt_fs::FILE_CREATED as u64
                    {
                        crate::writable_fs::note_profile_file_create(self.pi, &relative);
                    }
                    if let Some(file_id) = file_id {
                        match self.mint_overlay_file_handle(file_id, args[1] as u32) {
                            Some(handle) => self.queue_write(args[0], handle),
                            None => {
                                status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                                info = 0;
                            }
                        }
                    }
                } else if args[7] as u32 == nt_fs::FILE_OPEN {
                    if let Some((first_cluster, file_size)) = Self::readonly_disk_open_entry(
                        &name16,
                        args[1] as u32,
                        args[8] as u32,
                    ) {
                        status = nt_fs::STATUS_SUCCESS;
                        info = nt_fs::FILE_OPENED as u64;
                        match self.mint_disk_file_handle(first_cluster, file_size, args[1] as u32) {
                            Some(handle) => {
                                self.queue_write(args[0], handle);
                                let count = NT_CREATE_FILE_READONLY_FAT_OPENS
                                    .fetch_add(1, Ordering::Relaxed);
                                if count < 8 {
                                    print_str(b"[nt-create-file] pi=");
                                    print_u64(self.pi as u64);
                                    print_str(b" read-only FAT open size=");
                                    print_u64(file_size as u64);
                                    print_str(b" name=\"");
                                    for &unit in name16.iter().take(96) {
                                        debug_put_char(if (0x20..0x7f).contains(&unit) {
                                            unit as u8
                                        } else {
                                            b'?'
                                        });
                                    }
                                    print_str(b"\"\n");
                                }
                            }
                            None => {
                                status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                                info = 0;
                            }
                        }
                    } else if let Some(miss_status) = Self::readonly_disk_open_miss_status(&name16) {
                        status = miss_status;
                        let count = NT_CREATE_FILE_READONLY_FAT_MISSES.fetch_add(1, Ordering::Relaxed);
                        if count < 8 {
                            print_str(b"[nt-create-file] pi=");
                            print_u64(self.pi as u64);
                            print_str(b" read-only FAT miss status=0x");
                            print_hex(status);
                            print_str(b" name=\"");
                            for &unit in name16.iter().take(96) {
                                debug_put_char(if (0x20..0x7f).contains(&unit) {
                                    unit as u8
                                } else {
                                    b'?'
                                });
                            }
                            print_str(b"\"\n");
                        }
                    } else {
                        status = self.unsupported_nt_create_file(&name16);
                    }
                } else {
                    status = self.unsupported_nt_create_file(&name16);
                }
                if iosb != 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &info.to_le_bytes());
                }
                if self.current_process_is_winlogon()
                    && NT_CREATE_FILE_WINLOGON_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 40
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
                // The writable overlay is served IN-PROCESS from the volume and never crosses the
                // isolated-FSD argument window, so it is not bounded by it (see the matching note
                // on `NtReadFile`). It gets a copy-chunk-sized staging bound instead — exactly the
                // 64 KiB buffer `kernel32!CopyLoop` allocates.
                const OVERLAY_IO_CAP: usize = 64 * 1024;
                let write_capacity = if self.overlay_file_id_for(fh).is_some() {
                    OVERLAY_IO_CAP
                } else {
                    transport_capacity
                };
                let mut payload = alloc::vec![0u8; len.min(write_capacity)];
                let payload_ok = len == 0
                    || (buffer != 0
                        && len <= write_capacity
                        && self.xas_read(buffer, &mut payload));

                let completion_event = self.validate_io_event(event);
                let mut information = 0u64;
                let mut routed = false;
                let mut completion_file_id = 0u64;
                let mut pending_write_fid = 0u64;
                let mut async_file_retained = false;
                let mut status = if !iosb_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if len > write_capacity {
                    0xC000_0206 // STATUS_INVALID_BUFFER_SIZE
                } else if !payload_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if apc_routine != 0 {
                    let file_id = self.npfs_file_id_for(fh);
                    if file_id != 0 && self.file_completion.binding(file_id).is_some() {
                        0xC000_000D // STATUS_INVALID_PARAMETER
                    } else {
                        // No executive user-APC queue exists yet; do not pretend the callback ran.
                        0xC000_00BB // STATUS_NOT_SUPPORTED
                    }
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
                } else if let Some(file_id) = self.overlay_file_id_for(fh) {
                    // ★ THE WRITABLE FILESYSTEM OVERLAY: a real write of the caller's real bytes.
                    // `ByteOffset == NULL` (or the FILE_USE_FILE_POINTER_POSITION sentinel) uses and
                    // advances the file object's own position, exactly like an FSD.
                    self.writable_fs_dirty = true;
                    let explicit = (byte_offset != 0 && offset_ok)
                        .then_some(offset_value)
                        .filter(|value| *value != u64::MAX);
                    let (status, written) =
                        crate::writable_fs::write(file_id, explicit, &payload[..len]);
                    information = written as u64;
                    status
                } else {
                    match self.npfs_write_file_id_for(fh) {
                        Err(handle_status) => handle_status,
                        Ok(file_id) => {
                            completion_file_id = file_id;
                            let synchronous =
                                self.file_completion.is_synchronous(file_id).unwrap_or(true);
                            let waiter_table =
                                unsafe { &*core::ptr::addr_of!(PIPE_WAITERS) };
                            // ★★ PER-DIRECTION PIPE PARKING — MEASURED, GATED OFF (Phase 4).
                            //
                            // The direction-BLIND predicate makes a connection half-duplex: an
                            // already-pending READ refuses this WRITE with
                            // STATUS_INSUFFICIENT_RESOURCES. That is a silent functional degrade,
                            // and it is the EXACT reason the LSA self-RPC's 48-byte `LsarOpenPolicy`
                            // RESPONSE is lost, so `LsaOpenPolicy` never returns to samsrv —
                            // rpcrt4's ncacn_np server keeps a read pending on the connection while
                            // `RPCRT4_worker_thread` writes the response on the SAME connection. The
                            // re-drive already completes the two from separate per-direction stashes
                            // (`take_completed_write` / `take_completed_read`), so allowing one
                            // pending read AND one pending write per connection is well-formed
                            // (`PipeWaiterTable::parked_on_dir`, host-tested).
                            //
                            // MEASURED WITH IT ON, one foreground boot: the response writes SUCCEED
                            // (status=0 info=48, repeatedly), `SamIConnect-null-root-miss` goes
                            // 1 -> 0, `sam-setup-keys` 2 -> 36, `sam-mount-opens` 1 -> 2, and lsass
                            // reaches `NtCreateNamedPipeFile(\samr)` — i.e. `SamIConnect` succeeds
                            // and samsrv publishes its own RPC endpoint. It is a REAL advance.
                            //
                            // It was gated OFF for one batch on the reading that the boot then
                            // "spends its whole budget cycling that self-RPC" and loses the desktop
                            // paint to the 45 s no-progress watchdog. That reading was WRONG: the
                            // budget was being eaten by an HPET interrupt storm in the executive's
                            // own delay timer (2,745,189 deliveries that woke nothing in one boot),
                            // which the self-RPC was merely the first thing to arm. See
                            // `LSA_WORKER_ROUTE_ENABLED` and `exec_delay_timer_disarms`. With the
                            // timer fixed the paint is deterministic (768/768 over six consecutive
                            // boots) and this is ON.
                            const PIPE_FULL_DUPLEX_PARK: bool = true;
                            let waiter_capacity = waiter_table.has_capacity()
                                && !waiter_table.parked_on_dir(file_id, true)
                                && (PIPE_FULL_DUPLEX_PARK
                                    || !waiter_table.parked_on(file_id));
                            let sync_reply_capacity = if synchronous {
                                let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
                                (0..WAIT_REPLY_POOL_N).any(|index| {
                                    used & (1u64 << index) == 0
                                        && WAIT_REPLY_POOL[index].load(Ordering::Relaxed) != 0
                                })
                            } else {
                                true
                            };
                            let prepared = if !waiter_capacity || !sync_reply_capacity {
                                Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES)
                            } else {
                                self.file_completion.retain_file(file_id).map(|()| {
                                    async_file_retained = true;
                                })
                            };
                            match prepared {
                                Err(status) => status,
                                Ok(()) => {
                                    if let Ok(Some(index)) = completion_event {
                                        let _ = self.events.reset_existing(index as u64);
                                    }
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
                                            if driver_status as u32 == 0x0000_0103 {
                                                pending_write_fid = file_id;
                                            }
                                            driver_status as u32
                                        }
                                        None => 0xC000_00A3, // STATUS_DEVICE_NOT_READY
                                    }
                                }
                            }
                        }
                    }
                };
                if async_file_retained && pending_write_fid == 0 {
                    self.release_file_reference(completion_file_id);
                }
                if pending_write_fid != 0 {
                    let synchronous = self
                        .file_completion
                        .is_synchronous(pending_write_fid)
                        .unwrap_or(true);
                    let event_obj_idx = completion_event
                        .ok()
                        .flatten()
                        .map_or(u64::MAX, |index| index as u64);
                    if synchronous {
                        self.pipe_park_fid = pending_write_fid;
                        self.pipe_park_buffer_va = 0;
                        self.pipe_park_buffer_len = 0;
                        self.pipe_park_iosb_va = iosb;
                        self.pipe_park_apc_context = apc_context;
                        self.pipe_park_event_obj_idx = event_obj_idx;
                        self.pipe_park_transceive = false;
                        self.pipe_park_is_write = true;
                    } else {
                        let waiter = nt_io_manager::PipeWaiter {
                            file_id: pending_write_fid,
                            pi: self.pi as u32,
                            tid: self.current_tid,
                            badge: self.current_badge,
                            buffer_va: 0,
                            buffer_len: 0,
                            iosb_va: iosb,
                            apc_context,
                            event_obj_idx,
                            reply_cap: 0,
                            resume_ip: 0,
                            resume_sp: 0,
                            resume_flags: 0,
                            is_transceive: false,
                            is_write: true,
                        };
                        if unsafe { (&mut *core::ptr::addr_of_mut!(PIPE_WAITERS)).park(waiter) }
                            .is_none()
                        {
                            if async_file_retained {
                                self.release_file_reference(pending_write_fid);
                            }
                            // ★ A full table is a SILENT FUNCTIONAL DEGRADE, not a hang: this write
                            // would have completed on the peer's read, and instead fails. This is
                            // exactly how the LSA self-RPC's 48-byte `LsarOpenPolicy` RESPONSE was
                            // lost. Count + log it (see `PIPE_WAITER_N`).
                            if crate::PIPE_WAITERS_FULL.fetch_add(1, Ordering::Relaxed) < 8 {
                                print_str(b"[pipe-park] table FULL -> async WRITE degraded to STATUS_INSUFFICIENT_RESOURCES fid=0x");
                                print_hex(pending_write_fid as u32);
                                print_str(b"\n");
                            }
                            status = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                            pending_write_fid = 0;
                        }
                    }
                }
                if iosb_ok && pending_write_fid == 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                // A synchronous completion signals a valid real event. Legacy opaque events already
                // have immediate-wait semantics; STATUS_PENDING must leave every event unsignalled.
                if routed && status != 0x0000_0103 {
                    if status & 0xC000_0000 != 0xC000_0000 {
                        self.post_file_completion(
                            completion_file_id,
                            apc_context,
                            status,
                            information,
                        );
                    }
                    if let Ok(Some(index)) = completion_event {
                        if self.events.set_existing(index as u64).is_some() {
                            self.io_signal_event = index as i64;
                        }
                    }
                    // BATCH 33: the bytes are now queued in npfs on the PEER end. Ask the loop to
                    // re-drive every parked pipe read — npfs's FCB pairing wakes the peer's reader.
                    if status & 0xC000_0000 != 0xC000_0000 {
                        self.pipe_write_redrive = true;
                    }
                }
                // ★ LSA SELF-RPC instrumentation. Every MS-RPC PDU (`rpc_ver == 5`) written onto lsass'
                // OWN `\pipe\lsarpc`, split by which side of the self-RPC wrote it: the per-connection
                // WORKER (badge LSA_WORKER_BADGE — bind_ack / the LsarOpenPolicy response) versus lsass'
                // main thread acting as the CLIENT (advapi32's auto-bind + the request). Name-scoped via
                // the fid→pipe-name map, so no other pipe traffic can inflate it.
                if self.current_process_is_lsass()
                    && payload_ok
                    && len >= 4
                    && payload.first() == Some(&5)
                    && crate::pipe_fid_name_hash(self.npfs_file_id_for(fh))
                        == lsarpc_pipe_name_hash()
                {
                    let pdu_type = payload.get(2).copied().unwrap_or(0xFF) as u64;
                    if self.current_badge == LSA_WORKER_BADGE {
                        LSA_WORKER_PDU_WRITES.fetch_add(1, Ordering::Relaxed);
                        let _ = LSA_WORKER_FIRST_REPLY_TYPE.compare_exchange(
                            0xFF,
                            pdu_type,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    } else {
                        LSA_SELF_RPC_CLIENT_WRITES.fetch_add(1, Ordering::Relaxed);
                    }
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
                let apc_context = args[3];
                let completion_event = self.validate_io_event(event);
                let disk_file = self.disk_file_for(fh);
                let mut iosb_probe = [0u8; 16];
                let iosb_ok = iosb != 0 && self.xas_read(iosb, &mut iosb_probe);
                let transport_capacity = (driver_launch::FSD_ARG_FRAMES * 0x1000) as usize;
                // ★ THE WRITABLE OVERLAY IS NOT ON THE FSD TRANSPORT. `transport_capacity` is the
                // isolated-FSD argument window (4 frames = 16 KiB); an overlay read is served
                // in-process from the volume into its OWN buffer and never crosses it, so it must
                // not inherit that cap — and it needs no `output` staging buffer at all.
                // MEASURED (batch 58): `kernel32!CopyLoop` allocates a **64 KiB** copy buffer and
                // issues `NtReadFile(len = 0x10000)`, which this arm refused with
                // STATUS_INVALID_BUFFER_SIZE => `GetLastError() == 1784` (ERROR_INVALID_USER_BUFFER)
                // — the wall `CopyDirectory` hit at `userenv/directory.c:148` after creating the
                // whole destination tree and opening BOTH files.
                let overlay_file = self.overlay_file_id_for(fh);
                let output_capacity = if matches!(disk_file, Ok(Some(_))) {
                    len.min(16 * 1024 * 1024)
                } else if overlay_file.is_some() {
                    0
                } else {
                    len.min(transport_capacity)
                };
                let mut output = alloc::vec![0u8; output_capacity];
                let mut information = 0u64;
                let mut routed = false;
                let mut pending_read_fid = 0u64; // BATCH 33: npfs fid if the read went PENDING → park
                let mut completion_file_id = 0u64;
                let mut async_file_retained = false;
                let mut status = if !iosb_ok {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if !matches!(disk_file, Ok(Some(_)))
                    && overlay_file.is_none()
                    && len > transport_capacity
                {
                    0xC000_0206 // STATUS_INVALID_BUFFER_SIZE
                } else if len != 0 && buffer == 0 {
                    0xC000_0005 // STATUS_ACCESS_VIOLATION
                } else if apc_routine != 0 {
                    let file_id = self.npfs_file_id_for(fh);
                    if file_id != 0 && self.file_completion.binding(file_id).is_some() {
                        0xC000_000D // STATUS_INVALID_PARAMETER
                    } else {
                        0xC000_00BB // STATUS_NOT_SUPPORTED
                    }
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
                } else if let Some(file_id) = self.overlay_file_id_for(fh) {
                    // ★ THE WRITABLE FILESYSTEM OVERLAY: read back what was really written.
                    self.writable_fs_dirty = true;
                    let mut explicit = None;
                    let mut bad_offset = false;
                    if byte_offset != 0 {
                        let mut offset_bytes = [0u8; 8];
                        if self.xas_read(byte_offset, &mut offset_bytes) {
                            let value = u64::from_le_bytes(offset_bytes);
                            if value != u64::MAX {
                                explicit = Some(value);
                            }
                        } else {
                            bad_offset = true;
                        }
                    }
                    if bad_offset {
                        0xC000_0005 // STATUS_ACCESS_VIOLATION
                    } else {
                        let (status, bytes) = crate::writable_fs::read(file_id, explicit, len);
                        if status == nt_fs::STATUS_SUCCESS
                            && !bytes.is_empty()
                            && !self.xas_try_write_buf(buffer, &bytes)
                        {
                            0xC000_0005 // STATUS_ACCESS_VIOLATION
                        } else {
                            information = bytes.len() as u64;
                            status
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
                            completion_file_id = file_id;
                            let synchronous =
                                self.file_completion.is_synchronous(file_id).unwrap_or(true);
                            let waiter_table =
                                unsafe { &*core::ptr::addr_of!(PIPE_WAITERS) };
                            // Per-direction (see `PIPE_FULL_DUPLEX_PARK` at the NtWriteFile
                            // pre-check, which carries the full rationale + measurements). ON.
                            const PIPE_FULL_DUPLEX_PARK: bool = true;
                            let waiter_capacity = waiter_table.has_capacity()
                                && !waiter_table.parked_on_dir(file_id, false)
                                && (PIPE_FULL_DUPLEX_PARK
                                    || !waiter_table.parked_on(file_id));
                            let sync_reply_capacity = if synchronous {
                                let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
                                (0..WAIT_REPLY_POOL_N).any(|index| {
                                    used & (1u64 << index) == 0
                                        && WAIT_REPLY_POOL[index].load(Ordering::Relaxed) != 0
                                })
                            } else {
                                true
                            };
                            let prepared = if !waiter_capacity || !sync_reply_capacity {
                                Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES)
                            } else {
                                self.file_completion.retain_file(file_id).map(|()| {
                                    async_file_retained = true;
                                })
                            };
                            match prepared {
                                Err(status) => status,
                                Ok(()) => {
                                    if let Ok(Some(index)) = completion_event {
                                        let _ = self.events.reset_existing(index as u64);
                                    }
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
                                            // LSA self-RPC: a PDU delivered SYNCHRONOUSLY (npfs had
                                            // the peer's message already queued). Same attribution as
                                            // the parked-read re-drive path.
                                            if self.current_process_is_lsass()
                                                && output.first() == Some(&5)
                                                && crate::pipe_fid_name_hash(file_id)
                                                    == lsarpc_pipe_name_hash()
                                            {
                                                let pdu_type =
                                                    output.get(2).copied().unwrap_or(0xFF) as u64;
                                                if self.current_badge == LSA_WORKER_BADGE {
                                                    LSA_WORKER_PDU_READS
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    let _ = LSA_WORKER_FIRST_PDU_TYPE
                                                        .compare_exchange(
                                                            0xFF,
                                                            pdu_type,
                                                            Ordering::Relaxed,
                                                            Ordering::Relaxed,
                                                        );
                                                } else {
                                                    LSA_SELF_RPC_CLIENT_READS
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
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
                        }
                    }
                };
                if async_file_retained && pending_read_fid == 0 {
                    self.release_file_reference(completion_file_id);
                }
                if pending_read_fid != 0 {
                    let synchronous = self
                        .file_completion
                        .is_synchronous(pending_read_fid)
                        .unwrap_or(true);
                    let event_obj_idx = completion_event
                        .ok()
                        .flatten()
                        .map_or(u64::MAX, |index| index as u64);
                    if synchronous {
                        self.pipe_park_fid = pending_read_fid;
                        self.pipe_park_buffer_va = buffer;
                        self.pipe_park_buffer_len = len as u32;
                        self.pipe_park_iosb_va = iosb;
                        self.pipe_park_apc_context = apc_context;
                        self.pipe_park_event_obj_idx = event_obj_idx;
                        self.pipe_park_transceive = false;
                    } else {
                        let waiter = nt_io_manager::PipeWaiter {
                            file_id: pending_read_fid,
                            pi: self.pi as u32,
                            tid: self.current_tid,
                            badge: self.current_badge,
                            buffer_va: buffer,
                            buffer_len: len as u32,
                            iosb_va: iosb,
                            apc_context,
                            event_obj_idx,
                            reply_cap: 0,
                            resume_ip: 0,
                            resume_sp: 0,
                            resume_flags: 0,
                            is_transceive: false,
                            is_write: false,
                        };
                        let parked = unsafe {
                            (&mut *core::ptr::addr_of_mut!(PIPE_WAITERS)).park(waiter)
                        };
                        if parked.is_none() {
                            if async_file_retained {
                                self.release_file_reference(pending_read_fid);
                            }
                            if crate::PIPE_WAITERS_FULL.fetch_add(1, Ordering::Relaxed) < 8 {
                                print_str(b"[pipe-park] table FULL -> async READ degraded to STATUS_INSUFFICIENT_RESOURCES fid=0x");
                                print_hex(pending_read_fid as u32);
                                print_str(b"\n");
                            }
                            status = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                            pending_read_fid = 0;
                        }
                    }
                }
                if iosb_ok && pending_read_fid == 0 {
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &information.to_le_bytes());
                }
                if routed && status != 0x0000_0103 {
                    if status & 0xC000_0000 != 0xC000_0000 {
                        self.post_file_completion(
                            completion_file_id,
                            apc_context,
                            status,
                            information,
                        );
                    }
                    if let Ok(Some(index)) = completion_event {
                        if self.events.set_existing(index as u64).is_some() {
                            self.io_signal_event = index as i64;
                        }
                    }
                    self.pipe_write_redrive = true;
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
                // ★ 64, not 32. The staging buffer TRUNCATES the caller's structure to its own
                // size, so a 40-byte `FILE_BASIC_INFORMATION` (the class `kernel32!SetLastWriteTime`
                // uses at the end of every `CopyFileW`) arrived as 32 bytes and the volume
                // correctly rejected it with STATUS_INFO_LENGTH_MISMATCH => `GetLastError() == 24`
                // (ERROR_BAD_LENGTH) — measured as the wall `CopyDirectory` hit at
                // `userenv/directory.c:148` AFTER the file's bytes had already been copied.
                let mut payload = [0u8; 64];
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
                if iosb == 0 || !self.probe_user_output(iosb, 16) {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                let mut information = 0u64;
                // ★ THE WRITABLE FILESYSTEM OVERLAY owns its own file objects' information classes
                // (position / end-of-file / disposition / basic). Checked first so an overlay handle
                // never falls into the pipe-only classes below.
                if let Some(file_id) = self.overlay_file_id_for(args[0]) {
                    self.writable_fs_dirty = true;
                    let status = if !payload_ok {
                        0xC000_0005 // STATUS_ACCESS_VIOLATION
                    } else {
                        crate::writable_fs::set_information(
                            file_id,
                            information_class,
                            &payload[..payload_len],
                        )
                    };
                    self.xas_write_buf(iosb, &status.to_le_bytes());
                    self.xas_write_buf(iosb + 8, &0u64.to_le_bytes());
                    return status;
                }
                let status = match information_class {
                    23 => {
                        let file_id = self.npfs_file_id_for(args[0]);
                        if !self.current_process_is_winlogon() && !self.current_process_is_lsass() {
                            0xC000_0002 // STATUS_NOT_IMPLEMENTED
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
                        }
                    }
                    30 => {
                        const IO_COMPLETION_MODIFY_STATE: u32 = 0x2;
                        if length < 16 {
                            0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
                        } else if args[2] == 0 || !payload_ok {
                            0xC000_0005 // STATUS_ACCESS_VIOLATION
                        } else {
                            let file_id = self.npfs_file_id_for(args[0]);
                            if file_id == 0 {
                                0xC000_0008 // STATUS_INVALID_HANDLE
                            } else if let Err(status) =
                                self.file_completion.can_associate(file_id)
                            {
                                status
                            } else {
                                let port_handle =
                                    u64::from_le_bytes(payload[0..8].try_into().unwrap());
                                let key_context =
                                    u64::from_le_bytes(payload[8..16].try_into().unwrap());
                                match self.io_completion_id_for(
                                    port_handle,
                                    IO_COMPLETION_MODIFY_STATE,
                                ) {
                                    Err(status) => status,
                                    Ok(port_id) => {
                                        match self.io_completion_ports.retain(port_id) {
                                            Err(status) => status,
                                            Ok(()) => {
                                                let binding =
                                                    nt_io_completion::FileCompletionBinding {
                                                        port_id,
                                                        key_context,
                                                    };
                                                match self
                                                    .file_completion
                                                    .associate(file_id, binding)
                                                {
                                                    Ok(()) => nt_io_completion::STATUS_SUCCESS,
                                                    Err(status) => {
                                                        let _ = self
                                                            .io_completion_ports
                                                            .release(port_id);
                                                        status
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => 0xC000_0003, // STATUS_INVALID_INFO_CLASS
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
                } else if self.overlay_file_id_for(handle).is_some() {
                    // The writable volume is coherent by construction (RAM-backed) — a flush has
                    // nothing to push. When the backing becomes FAT write-through this is the seam
                    // that has to push it.
                    nt_fs::STATUS_SUCCESS
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
                // Named-pipe client open: a `\??\pipe\NAME` / `\Device\NamedPipe\NAME` open routes to
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
                                let options = args[5] as u32;
                                let synchronous = options
                                    & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT
                                        | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
                                    != 0;
                                let handle =
                                    self.mint_file_handle(fid, args[1] as u32, synchronous);
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
                                    // Remember the CLIENT end's fid→pipe-name too (the server end is
                                    // registered at NtCreateNamedPipeFile). This is what lets the LSA
                                    // self-RPC instrumentation below be NAME-SCOPED to `\lsarpc`
                                    // rather than "any pi-4 pipe write".
                                    crate::pipe_fid_name_remember(
                                        fid,
                                        nt_io_manager::pipe_name_hash(&leaf),
                                    );
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
                // ★ THE WRITABLE FILESYSTEM OVERLAY (see the same route in NtCreateFile). An open
                // inside a declared writable mount prefix is served by the writable volume — never
                // by the read-only FAT reader or the DLL/System32 existence fakes below, which is
                // why this is placed BEFORE all of them. `NtOpenFile` is `NtCreateFile` with
                // disposition FILE_OPEN, so a missing path misses honestly.
                if let Some(relative) = crate::writable_fs::writable_path(&name16) {
                    self.writable_fs_dirty = true;
                    let (mut status, file_id, information) = crate::writable_fs::create(
                        &relative,
                        args[1] as u32,                      // DesiredAccess (RDX)
                        0,                                   // FileAttributes: N/A to an open
                        smss_stack_read(sp + 0x28) as u32,   // ShareAccess
                        nt_fs::FILE_OPEN,
                        smss_stack_read(sp + 0x30) as u32,   // OpenOptions
                    );
                    let mut opened_handle = 0u64;
                    if let Some(file_id) = file_id {
                        match self.mint_overlay_file_handle(file_id, args[1] as u32) {
                            Some(handle) => {
                                opened_handle = handle;
                                self.queue_write(get_recv_mr(9), handle);
                            }
                            None => status = 0xC000_009A, // STATUS_INSUFFICIENT_RESOURCES
                        }
                    }
                    let iosb = get_recv_mr(8);
                    if iosb != 0 {
                        self.xas_write_buf(iosb, &status.to_le_bytes());
                        let info = if status == nt_fs::STATUS_SUCCESS {
                            information
                        } else {
                            0
                        };
                        self.xas_write_buf(iosb + 8, &info.to_le_bytes());
                    }
                    loader_trace_record(
                        self.pi,
                        LoaderOp::OpenFile,
                        status,
                        None,
                        0,
                        opened_handle,
                        &nb[..nlen],
                    );
                    return status;
                }
                // Classify SxS/activation-context paths without admitting them to image loading.
                let is_sxs = nb[..nlen].windows(6).any(|w| w == b".local")
                    || nb[..nlen].windows(9).any(|w| w == b".manifest")
                    || nb[..nlen].windows(7).any(|w| w == b".config");
                let want_dir = smss_stack_read(sp + 0x30) & FILE_DIRECTORY_FILE != 0;
                let open_options = smss_stack_read(sp + 0x30) as u32;
                let desired_access = args[1] as u32;
                let disk_entry =
                    Self::readonly_disk_open_entry(&name16, desired_access, open_options);
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
                let volume_entry =
                    nt_fs::nt_path_to_volume_relative(&name16, b"reactos").and_then(|path| {
                        exec_fs().and_then(|fs| {
                            if path.is_empty() {
                                Some((fs.root_cl, 0, 0x10))
                            } else {
                                fat_open_path_entry(&fs, &path)
                            }
                        })
                    });
                let volume_directory = if want_dir {
                    volume_entry
                        .filter(|(_, _, attributes)| attributes & 0x10 != 0)
                        .map(|(first_cluster, _, _)| first_cluster)
                } else {
                    None
                };
                let volume_not_directory = volume_entry
                    .is_some_and(|(_, _, attributes)| attributes & 0x10 == 0);
                // csrss/winlogon/services/lsass.exe FILE opens (SmpExecuteImage /
                // RtlCreateUserProcess / winlogon's CreateProcessInternalW): the substring classifies
                // WHICH EXE, existence resolves against its CANONICAL leaf + root on the real
                // \reactos FS (runtime hosted-image catalog) — path-form/malformed-path
                // independent, no hand-maintained list. Loader manifest opens are unaffected (SxS
                // rejected).
                let catalog = &*ctx.exe_image_catalog;
                let hosted_exe_image =
                    (!want_dir)
                        .then(|| Self::exe_probe_image(catalog, &nb[..nlen], is_sxs))
                        .flatten()
                        .filter(|image| Self::hosted_image_exists(*image));
                let hosted_exe_leaf = hosted_exe_image.map(|image| image.leaf);
                let userinit_shell_probe = if self.current_process_is_userinit() && !want_dir && !is_sxs {
                    if nb[..nlen].windows(8).any(|w| w == b"explorer") {
                        Some(b"explorer.exe" as &[u8])
                    } else if nb[..nlen].windows(3).any(|w| w == b"cmd") {
                        Some(b"cmd.exe" as &[u8])
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(leaf) = userinit_shell_probe {
                    let attempt = USERINIT_SHELL_IMAGE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                    if attempt == 0 {
                        bump_progress();
                    }
                    if leaf == b"explorer.exe" {
                        USERINIT_EXPLORER_IMAGE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                    }
                    if attempt < 8 {
                        print_str(b"[userinit-shell] NtOpenFile shell image probe ");
                        print_str(leaf);
                        print_str(b" raw=");
                        print_str(&nb[..nlen.min(80)]);
                        print_str(b"\n");
                    }
                }
                // ★ THE 6TH PROCESS' IMAGE OPEN. `msgina!WlxActivateUserShell` →
                // `WlxStartApplication` → `CreateProcessAsUserW` reaches
                // `kernel32!CreateProcessInternalW`'s image open for `userinit.exe`
                // (`proc.c:2745`). Counted separately from success: the generic image table now
                // accepts the real file and carries it through SectionImageInformation, while pi=5
                // process publication remains the next mechanism boundary.
                if self.current_process_is_winlogon()
                    && !want_dir
                    && nb[..nlen].windows(8).any(|w| w == b"userinit")
                {
                    WINLOGON_USERINIT_IMAGE_OPENS.fetch_add(1, Ordering::Relaxed);
                }
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
                    let load =
                        demand_load_dll_result(reg, ctx.dll_pe_store, DLL_REG_COUNT, &nb[..nlen]);
                    match load {
                        Ok(slot) => {
                            // Pin the heap mark past the load's registry allocations (service loop consumes).
                            self.dll_loaded_dirty = true;
                            dll_i = Some(slot);
                        }
                        Err(err) => {
                            // DIAG: a .dll open that missed the registry AND failed to demand-load —
                            // log it so we can see which dependency the loader requested that we
                            // couldn't satisfy.
                            if !self.current_process_is_winlogon()
                                && (nb[..nlen].ends_with(b".dll")
                                    || nb[..nlen].windows(4).any(|w| w == b".dll"))
                            {
                                print_str(b"[demand-miss] pi=");
                                print_u64(self.pi as u64);
                                print_str(b" reason=");
                                print_str(err.tag());
                                match err {
                                    DemandLoadError::StoreTooSmall { slot, store_len } => {
                                        print_str(b" slot=");
                                        print_u64(slot as u64);
                                        print_str(b" store_len=");
                                        print_u64(store_len as u64);
                                    }
                                    DemandLoadError::PoolExhausted { size } => {
                                        print_str(b" size=");
                                        print_u64(size as u64);
                                    }
                                    DemandLoadError::ShortRead { expected, actual } => {
                                        print_str(b" expected=");
                                        print_u64(expected as u64);
                                        print_str(b" actual=");
                                        print_u64(actual as u64);
                                    }
                                    DemandLoadError::ArenaExhausted { image_size } => {
                                        print_str(b" image_size=");
                                        print_u64(image_size);
                                    }
                                    DemandLoadError::UnsupportedImageName
                                    | DemandLoadError::SxsProbe
                                    | DemandLoadError::DeniedDiverter
                                    | DemandLoadError::NoReservedSlot
                                    | DemandLoadError::NoMountedFs
                                    | DemandLoadError::FileMissing
                                    | DemandLoadError::EmptyFile
                                    | DemandLoadError::PeParseFailed => {}
                                }
                                print_str(b" name=");
                                print_str(&nb[..nlen.min(64)]);
                                print_str(b"\n");
                            }
                        }
                    }
                }
                let mut opened_handle = 0;
                let status: u32 = if volume_directory.is_some()
                    || hosted_exe_leaf.is_some()
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
                    if let Some(image) = hosted_exe_image {
                        let _ = record_hosted_child_exe_open(ctx, self.pi, image, h);
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
                    // DIAG (BATCH 23): log lsass.exe's unresolved NtOpenFile — its LSA init opens a
                    // named object we don't model and bails with OBJECT_NAME_NOT_FOUND. Surface the name.
                    if self.current_process_is_lsass() {
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
                let info: Option<([u8; 64], &[u8])> = if let Some(i) = reg.index_for_section(self.pi, sect) {
                    reg.image_info(i).map(|b| (b, reg.name(i)))
                } else if let Some(index) =
                    (&*ctx.exe_images).index_for_section(self.pi, sect)
                {
                    (&*ctx.exe_images).get(index).map(|slot| {
                        let metadata = slot.metadata;
                        let mut info = nt_dll_registry::image_info(
                            PE_LOAD_BASE,
                            metadata.entry_rva,
                            metadata.image_size as u32,
                            false,
                        );
                        info[0x20..0x24]
                            .copy_from_slice(&(metadata.subsystem as u32).to_le_bytes());
                        info[0x24..0x26]
                            .copy_from_slice(&metadata.subsystem_minor.to_le_bytes());
                        info[0x26..0x28]
                            .copy_from_slice(&metadata.subsystem_major.to_le_bytes());
                        (info, slot.leaf())
                    })
                } else {
                    None
                };
                if class == 1 && info.is_some() {
                    let (bytes, who) = info.unwrap();
                    if who == b"userinit.exe" {
                        USERINIT_IMAGE_QUERIES.fetch_add(1, Ordering::Relaxed);
                    } else if who == b"explorer.exe" {
                        EXPLORER_IMAGE_QUERIES.fetch_add(1, Ordering::Relaxed);
                    }
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
                if let Ok(index) =
                    (&mut *ctx.exe_images).create_section(self.pi, sec_file, h)
                {
                    let leaf = (&*ctx.exe_images).get(index).unwrap().leaf();
                    if leaf == b"services.exe" {
                        SERVICES_CREATE_STARTED.store(1, Ordering::Relaxed);
                    } else if leaf == b"lsass.exe" {
                        LSASS_CREATE_STARTED.store(1, Ordering::Relaxed);
                    } else if leaf == b"userinit.exe" {
                        USERINIT_IMAGE_SECTIONS.fetch_add(1, Ordering::Relaxed);
                    } else if leaf == b"explorer.exe" {
                        EXPLORER_IMAGE_SECTIONS.fetch_add(1, Ordering::Relaxed);
                    }
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for ");
                    print_str(leaf);
                    print_str(b" -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // A registry DLL (csrsrv/basesrv/winsrv): record its section handle by file handle.
                if let Some(i) = registry_slot {
                    reg.set_section_handle(self.pi, i, h);
                    if !self.current_process_is_winlogon() {
                        print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for ");
                        print_str(reg.name(i));
                        print_str(b" -> handle 0x");
                        print_hex(h as u32);
                        print_str(b"\n");
                    }
                }
                // Anonymous (no FileHandle) section from csrss — its CSR SharedSection shared memory.
                // Record the requested size (from *MaximumSize = R9) so NtMapViewOfSection can back it.
                if sec_file == 0
                    && self.current_process_is_csrss()
                    && *ctx.csrss_anon_section_handle == 0
                {
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
                        if !self.current_process_is_winlogon() {
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
                        // ★ `DbgkMapViewOfSection` — THE image-view chokepoint. This branch is the
                        // one place a SEC_IMAGE view genuinely becomes mapped for a hosted process
                        // (the anonymous CSR section + the named NLS section below are data views
                        // and deliberately do NOT report, matching `Section->u.Flags.Image`). The
                        // `DebugInfo*` pair is `RtlImageNtHeader(BaseOfDll)->FileHeader`'s COFF
                        // symbol-table fields; the name pointer is the mapping thread's
                        // `NtTib.ArbitraryUserPointer`. With no debugger the call returns on its
                        // first line.
                        if self.pm.debug_object_count() != 0 {
                            let dbg_file = reg.file_handle(self.pi, i);
                            let dbg_info = cpe.debug_info();
                            self.dbgk_module_load(
                                self.pi,
                                dbase,
                                dbg_file,
                                dbg_info,
                                SMSS_TEB_VA + 0x28,
                            );
                        }
                        0
                    } else {
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
                } else if self.current_process_is_csrss()
                    && *ctx.csrss_anon_section_handle != 0
                    && sect == *ctx.csrss_anon_section_handle
                {
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
                    print_str(b"[ntos-exec] NtMapViewOfSection unsupported pi=");
                    print_u64(self.pi as u64);
                    print_str(b" section=0x");
                    print_hex(sect as u32);
                    print_str(b"\n");
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
            // SectionHandle through the executable image table, reserve the process publication, then
            // let the loop build the seL4 mechanism from the same SpawnRequest used by Win32 children.
            NativeService::NtCreateProcess => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let sp = get_recv_mr(16);
                let sect = smss_stack_read(sp + 0x30); // SectionHandle
                let slot_info = {
                    let table = &*ctx.exe_images;
                    table.index_for_section(self.pi, sect).and_then(|index| {
                        table.get(index).map(|slot| {
                            let mut leaf = [0u8; nt_exe_image::MAX_EXE_LEAF];
                            let leaf_len = slot.leaf().len();
                            leaf[..leaf_len].copy_from_slice(slot.leaf());
                            (index, leaf, leaf_len)
                        })
                    })
                };
                let Some((slot_index, leaf, leaf_len)) = slot_info else {
                    self.stop = true;
                    return 0xC000_0002;
                };
                let leaf = &leaf[..leaf_len];
                if self.current_process_is_winlogon() || self.current_process_is_userinit() {
                    print_str(if self.current_process_is_winlogon() {
                        b"[wl-createproc] pi=2 sect=0x" as &[u8]
                    } else {
                        b"[userinit-createproc] pi=5 sect=0x" as &[u8]
                    });
                    print_hex(sect as u32);
                    print_str(b" exe-slot=");
                    print_u64(slot_index as u64 + 1);
                    print_str(b"\n");
                }
                let catalog = &*ctx.exe_image_catalog;
                let Some(image) = catalog.get_by_leaf(leaf) else {
                    self.stop = true;
                    return 0xC000_0002;
                };
                if let Err(status) = self.allocate_hosted_process_slot(self.pi, image) {
                    return status;
                }
                match image.role {
                    nt_exe_image::HostedProcessRole::InteractiveShellBootstrap => {
                        USERINIT_CREATE_PROCESS_REQUESTS.fetch_add(1, Ordering::Relaxed);
                    }
                    nt_exe_image::HostedProcessRole::InteractiveShell => {
                        EXPLORER_CREATE_PROCESS_REQUESTS.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                // RtlCreateUserProcess/CreateProcessAsUserW names the parent process with a real
                // process handle (commonly NtCurrentProcess). Keep image launch policy out of the
                // catalog; the parent check belongs to the handle table.
                if self.resolve_process_handle(args[3]) != self.pm_pid_for_pi(self.pi) {
                    return nt_process::STATUS_INVALID_HANDLE;
                }
                let table = &mut *ctx.exe_images;
                match table.reserve_spawn_owned_registered(
                    catalog,
                    self.pi,
                    sect,
                    args[1] as u32,
                    get_recv_mr(9),
                ) {
                    Ok(request) => {
                        self.exe_spawn_request = Some(request);
                        0
                    }
                    Err(_) => 0xC000_000D,
                }
            },
            // NtTerminateProcess(ProcessHandle[R10]=args[0], ExitStatus[RDX]=args[1]). Route NT's two
            // user-mode shutdown phases through pm: NULL means terminate every other thread and return
            // so kernel32 can unload/notify; NtCurrentProcess/real handle means final self-kill and the
            // service loop must drop the reply before deleting the caller TCB.
            NativeService::NtTerminateProcess => {
                PM_TERMINATE_CALLS.fetch_add(1, Ordering::Relaxed);
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                let kill_by_handle = handle != 0;
                let caller_pid = match self.pm_pid_for_pi(self.pi) {
                    Some(pid) => pid,
                    None => return nt_process::STATUS_INVALID_HANDLE,
                };
                let pid = if kill_by_handle {
                    match self.resolve_process_handle(handle) {
                        Some(pid) => pid,
                        None => return nt_process::STATUS_INVALID_HANDLE,
                    }
                } else {
                    caller_pid
                };
                if let Some(code) = self.pm.critical_process_termination_code(pid) {
                    self.post_action = ExecPostAction::CriticalTermination {
                        code,
                        object: pid as u64,
                    };
                    return 0;
                }
                let process_index = self.pi_for_pid(pid).map(|pi| pi as u8);
                let current_tid = self.current_tid as nt_process::ThreadId;
                let exit_time = nt_system_time_100ns() as i64;
                if !kill_by_handle && pid == caller_pid {
                    if let Err(status) = self.pm.terminate_process_other_threads_at(
                        pid,
                        current_tid,
                        status,
                        exit_time,
                    ) {
                        return status;
                    }
                    if let Some(process_index) = process_index {
                        self.post_action = ExecPostAction::TerminateProcess {
                            process_index,
                            current_tid: current_tid as u64,
                            drop_reply: false,
                        };
                    }
                } else {
                    if let Err(status) = self.pm.terminate_process_at(pid, status, exit_time) {
                        return status;
                    }
                    self.release_process_handles(pid);
                    if let Some(process_index) = process_index {
                        let is_current = pid == caller_pid;
                        self.post_action = ExecPostAction::TerminateProcess {
                            process_index,
                            current_tid: if is_current { current_tid as u64 } else { 0 },
                            drop_reply: is_current,
                        };
                    }
                }
                0 // STATUS_SUCCESS
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
                let target_pid = self
                    .pm
                    .thread(target)
                    .map(|thread| thread.process_id)
                    .unwrap_or(caller_pid);
                let is_current = target == current_tid;
                if let Some(code) = self.pm.critical_thread_termination_code(target) {
                    self.post_action = ExecPostAction::CriticalTermination {
                        code,
                        object: target as u64,
                    };
                    return 0;
                }
                let exit_time = nt_system_time_100ns() as i64;
                let outcome = if self.current_process_is_csrss()
                    && self.pm.main_thread(caller_pid) == Some(target)
                {
                    self.pm.exit_thread_at(target, status, exit_time)
                } else {
                    self.pm.terminate_thread_at(target, status, exit_time)
                };
                if let Err(status) = outcome {
                    return status;
                }
                if self.pm.is_process_signaled(target_pid) {
                    self.release_process_handles(target_pid);
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
            // --- Dbgk: the user-mode debugging plane (`ntoskrnl/dbgk`) -------------------------
            //
            // The five debug-object services our ntdll's DbgUi* wrappers issue. Each resolves a
            // typed `HandleObject::DebugObject` out of the caller's REAL EPROCESS handle table and
            // drives the real `nt_process::dbgk` DEBUG_OBJECT (queue/waiter/continue), then mirrors
            // the object's `EventsPresent` onto its backing dispatcher event so a blocking
            // NtWaitForDebugEvent parks and wakes through the SAME machinery as every other wait.

            // NtCreateDebugObject(*DebugHandle[R10]=args[0], DesiredAccess, *OA[R8]=args[2], Flags).
            NativeService::NtCreateDebugObject => unsafe {
                let out = args[0];
                if out == 0 {
                    return 0xC000_0005; // STATUS_ACCESS_VIOLATION
                }
                if out & 7 != 0 {
                    return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
                }
                if !self.probe_event_output(out, 8) {
                    return 0xC000_0005;
                }
                let Some(pid) = self.pm_pid_for_pi(self.pi) else {
                    return nt_process::STATUS_INVALID_HANDLE;
                };
                let object = match self.pm.create_debug_object(args[3] as u32) {
                    Ok(object) => object,
                    Err(status) => return status,
                };
                // DebugObject->EventsPresent: a REAL notification dispatcher object (index+1 is
                // stored so 0 stays "unbound" when the namespace is full).
                if let Some(index) = self.obj_create_anon_event(false, false) {
                    if let Some(o) = self.pm.debug_object_mut(object) {
                        o.host_event = index as u64 + 1;
                    }
                }
                let access = nt_process::dbgk::map_debug_object_access(args[1] as u32);
                let Ok(handle) = self.pm.insert_handle(
                    pid,
                    nt_process::HandleObject::DebugObject(object),
                    access,
                ) else {
                    self.pm.destroy_debug_object(object);
                    return 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                };
                if !self.xas_write_u64(out, handle as u64) {
                    let _ = self.pm.close_handle(pid, handle);
                    self.pm.destroy_debug_object(object);
                    return 0xC000_0005;
                }
                DBGK_OBJECTS_CREATED.fetch_add(1, Ordering::Relaxed);
                0
            },

            // NtDebugActiveProcess(ProcessHandle[R10]=args[0], DebugHandle=args[1]).
            NativeService::NtDebugActiveProcess => {
                let object = match self.debug_object_for_handle(
                    args[1],
                    nt_process::dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                ) {
                    Ok(object) => object,
                    Err(status) => return status,
                };
                const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
                let (target, target_pi) =
                    match self.resolve_process_for_access(args[0], PROCESS_SUSPEND_RESUME) {
                        Ok(resolved) => resolved,
                        Err(status) => return status,
                    };
                let debugger = nt_process::ClientId {
                    unique_process: self.pm_pid_for_pi(self.pi).unwrap_or(0),
                    unique_thread: self.current_tid as nt_process::ThreadId,
                };
                match self.pm.debug_active_process(target, object, debugger) {
                    Ok(posted) => {
                        // ★ `DbgkpSetProcessDebugObject` → `DbgkpMarkProcessPeb(Process, TRUE)`:
                        // the modelled flag is not enough — write it through to the target's LIVE
                        // PEB page, which is the byte `DbgUiRemoteBreakin` (and every
                        // `IsDebuggerPresent`) actually reads.
                        unsafe { self.dbgk_mark_process_peb(target_pi, true) };
                        self.sync_debug_object_signal(object);
                        DBGK_ATTACHES.fetch_add(1, Ordering::Relaxed);
                        DBGK_FAKE_MESSAGES.fetch_add(posted as u64, Ordering::Relaxed);
                        0
                    }
                    Err(status) => status,
                }
            }

            // NtWaitForDebugEvent(DebugHandle[R10]=args[0], Alertable, *Timeout=args[2],
            //                     *StateChange=args[3]).
            NativeService::NtWaitForDebugEvent => unsafe {
                let object = match self.debug_object_for_handle(
                    args[0],
                    nt_process::dbgk::DEBUG_OBJECT_WAIT_STATE_CHANGE,
                ) {
                    Ok(object) => object,
                    Err(status) => return status,
                };
                let state_change = args[3];
                if state_change == 0 {
                    return 0xC000_0005;
                }
                if !self.probe_user_output(
                    state_change,
                    nt_process::dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE,
                ) {
                    return 0xC000_0005;
                }
                let debugger = self.pm_pid_for_pi(self.pi).unwrap_or(0);
                let result = match self.pm.wait_for_debug_event(object, debugger) {
                    Ok(result) => result,
                    Err(status) => return status,
                };
                self.sync_debug_object_signal(object);
                if let Some(result) = result {
                    if !self.xas_try_write_buf(state_change, &result.state_change) {
                        return 0xC000_0005;
                    }
                    DBGK_WAITS_SERVED.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                // Nothing reportable. An immediate (zero/positive) timeout returns STATUS_TIMEOUT;
                // anything else parks the caller on the object's EventsPresent dispatcher event, so
                // the queue-side signal wakes it through the ordinary wait machinery.
                let timeout_ptr = args[2];
                if timeout_ptr != 0 {
                    let interval = smss_stack_read(timeout_ptr) as i64;
                    match nt_delay_execution::due_time(
                        interval,
                        monotonic_time_100ns(),
                        nt_system_time_100ns(),
                    ) {
                        nt_delay_execution::Due::Immediate => return 0x102, // STATUS_TIMEOUT
                        nt_delay_execution::Due::Monotonic100ns(deadline) => {
                            self.wait_deadline_100ns = deadline;
                        }
                    }
                }
                match self.pm.debug_object(object).map(|o| o.host_event) {
                    Some(key) if key != 0 => {
                        self.wait_park_event = (key - 1) as i64;
                        0x102 // parked; the loop ignores this sentinel
                    }
                    // No dispatcher object could be bound at create time — report the timeout
                    // rather than parking on nothing.
                    _ => 0x102,
                }
            },

            // NtDebugContinue(DebugHandle[R10]=args[0], *AppClientId=args[1], ContinueStatus).
            NativeService::NtDebugContinue => unsafe {
                let object = match self.debug_object_for_handle(
                    args[0],
                    nt_process::dbgk::DEBUG_OBJECT_WAIT_STATE_CHANGE,
                ) {
                    Ok(object) => object,
                    Err(status) => return status,
                };
                let client_id_ptr = args[1];
                if client_id_ptr == 0 {
                    return 0xC000_0005;
                }
                let mut raw = [0u8; 16];
                if !smss_copyin(client_id_ptr, &mut raw) {
                    return 0xC000_0005;
                }
                let client_id = nt_process::ClientId {
                    unique_process: u64::from_le_bytes(raw[0..8].try_into().unwrap()) as u32,
                    unique_thread: u64::from_le_bytes(raw[8..16].try_into().unwrap()) as u32,
                };
                match self
                    .pm
                    .debug_continue(object, client_id, args[2] as u32)
                {
                    Ok(event) => {
                        // ★ `DbgkpWakeTarget`: apply the continue status to the reporting thread
                        // blocked on this event — resume it, leave the fault site's handling
                        // standing, or ENFORCE a DBG_TERMINATE_THREAD / DBG_TERMINATE_PROCESS.
                        self.dbgk_wake_target(
                            event.client_id,
                            event.reporter_block(),
                            args[2] as u32,
                        );
                        self.sync_debug_object_signal(object);
                        DBGK_CONTINUES.fetch_add(1, Ordering::Relaxed);
                        0
                    }
                    Err(status) => status,
                }
            },

            // NtRemoveProcessDebug(ProcessHandle[R10]=args[0], DebugHandle=args[1]).
            NativeService::NtRemoveProcessDebug => {
                let object = match self.debug_object_for_handle(
                    args[1],
                    nt_process::dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                ) {
                    Ok(object) => object,
                    Err(status) => return status,
                };
                const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
                let (target, target_pi) =
                    match self.resolve_process_for_access(args[0], PROCESS_SUSPEND_RESUME) {
                        Ok(resolved) => resolved,
                        Err(status) => return status,
                    };
                // ★ ESCAPE HATCH: this debuggee's queued events are about to be flushed, so every
                // reporter blocked on one must be released FIRST or it would stay parked forever.
                unsafe { self.dbgk_release_blocked_reporters(object, Some(target)) };
                match self.pm.remove_process_debug(target, object) {
                    Ok(_flushed) => {
                        // `DbgkClearProcessDebugObject` → `DbgkpMarkProcessPeb(Process, FALSE)`.
                        unsafe { self.dbgk_mark_process_peb(target_pi, false) };
                        self.sync_debug_object_signal(object);
                        DBGK_DETACHES.fetch_add(1, Ordering::Relaxed);
                        0
                    }
                    Err(status) => status,
                }
            }

            _ => 0xC000_0002, // STATUS_NOT_IMPLEMENTED — never silently succeed
        }
    }
}
