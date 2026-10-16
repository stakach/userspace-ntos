//! The full required `Nt*` **trap-stub bodies** — the classic x86 form, macro-generated over the
//! shared SSN table.
//!
//! Each exported `Nt*` stub is the canonical native-syscall thunk:
//!
//! ```text
//!     mov r10, rcx        ; syscall clobbers rcx, so the 1st arg is preserved in r10
//!     mov eax, <ssn>      ; the system-service number
//!     syscall             ; -> faults as UnknownSyscall on our kernel, serviced via the fault EP
//!     ret
//! ```
//!
//! ★ For the trap backend, args beyond the 4th **stay on the caller's stack** — the kernel reads
//! them there. There is deliberately NO stack thunk here: the x64 syscall ABI *is* the calling
//! convention the compiler already set up, so a naked `syscall; ret` forwards every argument
//! (register + stack) untouched. (The seL4/SURT backends, which must *gather* the stack tail into an
//! IPC message, use [`crate::marshal`] instead — that's where ">4 args" needs explicit work.)
//!
//! Both transports use typed naked Windows-ABI functions. Native transport retains its argument
//! vector on the stack and stages the complete request again after an explicit retry. Internal
//! ntdll callers enter the same generated functions; there is no compiler-framed IPC emitter.
//! Host tests check complete shared-service coverage and exact arity. Native PE execution probes
//! separately validate the emitted assembly, including transport clobbers across retry.

/// A generated trap stub's metadata: export name, SSN, and parameter count. On the x86_64 target the
/// matching naked function exists (see [`generate_trap_stubs!`]); this table exists on every target
/// so the complete coverage (right SSN/arity) is host-testable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TrapStubMeta {
    /// The `Nt*` export name.
    pub name: &'static str,
    /// The SSN baked into the stub's `mov eax, <ssn>`.
    pub ssn: u32,
    /// The service's parameter count (register-width args).
    pub argc: u8,
}

/// Immutable code-address retention metadata, never an invocation API.
#[cfg(target_arch = "x86_64")]
#[repr(transparent)]
pub struct TrapStubAddress(*const ());

// These pointers name immutable generated code and are never dereferenced as data.
#[cfg(target_arch = "x86_64")]
unsafe impl Sync for TrapStubAddress {}

#[cfg(all(target_arch = "x86_64", feature = "native_transport", target_os = "windows"))]
macro_rules! native_seh {
    ($($text:literal),+) => { concat!($($text),+) };
}

#[cfg(all(target_arch = "x86_64", feature = "native_transport", not(target_os = "windows")))]
macro_rules! native_seh {
    ($($text:literal),+) => { "" };
}

macro_rules! define_stub_arity {
    ($fn:ident, $name:literal, $ssn:literal, 0) => {
        define_typed_stub!($fn, $name, $ssn, 0, ());
    };
    ($fn:ident, $name:literal, $ssn:literal, 1) => {
        define_typed_stub!($fn, $name, $ssn, 1, (a0));
    };
    ($fn:ident, $name:literal, $ssn:literal, 2) => {
        define_typed_stub!($fn, $name, $ssn, 2, (a0, a1));
    };
    ($fn:ident, $name:literal, $ssn:literal, 3) => {
        define_typed_stub!($fn, $name, $ssn, 3, (a0, a1, a2));
    };
    ($fn:ident, $name:literal, $ssn:literal, 4) => {
        define_typed_stub!($fn, $name, $ssn, 4, (a0, a1, a2, a3));
    };
    ($fn:ident, $name:literal, $ssn:literal, 5) => {
        define_typed_stub!($fn, $name, $ssn, 5, (a0, a1, a2, a3, a4));
    };
    ($fn:ident, $name:literal, $ssn:literal, 6) => {
        define_typed_stub!($fn, $name, $ssn, 6, (a0, a1, a2, a3, a4, a5));
    };
    ($fn:ident, $name:literal, $ssn:literal, 7) => {
        define_typed_stub!($fn, $name, $ssn, 7, (a0, a1, a2, a3, a4, a5, a6));
    };
    ($fn:ident, $name:literal, $ssn:literal, 8) => {
        define_typed_stub!($fn, $name, $ssn, 8, (a0, a1, a2, a3, a4, a5, a6, a7));
    };
    ($fn:ident, $name:literal, $ssn:literal, 9) => {
        define_typed_stub!($fn, $name, $ssn, 9, (a0, a1, a2, a3, a4, a5, a6, a7, a8));
    };
    ($fn:ident, $name:literal, $ssn:literal, 10) => {
        define_typed_stub!($fn, $name, $ssn, 10, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9));
    };
    ($fn:ident, $name:literal, $ssn:literal, 11) => {
        define_typed_stub!($fn, $name, $ssn, 11, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10));
    };
    ($fn:ident, $name:literal, $ssn:literal, 12) => {
        define_typed_stub!($fn, $name, $ssn, 12, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11));
    };
    ($fn:ident, $name:literal, $ssn:literal, 13) => {
        define_typed_stub!($fn, $name, $ssn, 13, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12));
    };
    ($fn:ident, $name:literal, $ssn:literal, 14) => {
        define_typed_stub!($fn, $name, $ssn, 14, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13));
    };
    ($fn:ident, $name:literal, $ssn:literal, 15) => {
        define_typed_stub!($fn, $name, $ssn, 15, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14));
    };
    ($fn:ident, $name:literal, $ssn:literal, 16) => {
        define_typed_stub!($fn, $name, $ssn, 16, (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15));
    };
}

#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
macro_rules! invoke_stub_arity {
    ($fn:ident, 0, $args:ident) => { unsafe { $fn() } };
    ($fn:ident, 1, $args:ident) => { unsafe { $fn($args[0]) } };
    ($fn:ident, 2, $args:ident) => { unsafe { $fn($args[0], $args[1]) } };
    ($fn:ident, 3, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2]) } };
    ($fn:ident, 4, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3]) } };
    ($fn:ident, 5, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4]) } };
    ($fn:ident, 6, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5]) } };
    ($fn:ident, 7, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6]) } };
    ($fn:ident, 8, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7]) } };
    ($fn:ident, 9, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8]) } };
    ($fn:ident, 10, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9]) } };
    ($fn:ident, 11, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10]) } };
    ($fn:ident, 12, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10], $args[11]) } };
    ($fn:ident, 13, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10], $args[11], $args[12]) } };
    ($fn:ident, 14, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10], $args[11], $args[12], $args[13]) } };
    ($fn:ident, 15, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10], $args[11], $args[12], $args[13], $args[14]) } };
    ($fn:ident, 16, $args:ident) => { unsafe { $fn($args[0], $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7], $args[8], $args[9], $args[10], $args[11], $args[12], $args[13], $args[14], $args[15]) } };
}

macro_rules! define_typed_stub {
    ($fn:ident, $name:literal, $ssn:literal, $argc:literal, ($($arg:ident),*)) => {
        #[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
        #[unsafe(naked)]
        #[export_name = $name]
        #[allow(unused_variables)]
        pub unsafe extern "win64" fn $fn($($arg: u64),*) -> u64 {
            core::arch::naked_asm!(
                "mov r10, rcx",
                concat!("mov eax, ", stringify!($ssn)),
                "syscall",
                "ret",
            );
        }

        #[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
        #[unsafe(naked)]
        #[export_name = $name]
        #[allow(unused_variables)]
        pub unsafe extern "win64" fn $fn($($arg: u64),*) -> u64 {
            core::arch::naked_asm!(
                native_seh!(".seh_proc ", $name),
                // The argument vector belongs to this invocation, not the mutable IPC buffer.
                "push rdi",
                native_seh!(".seh_pushreg rdi"),
                "push rsi",
                native_seh!(".seh_pushreg rsi"),
                "push r15",
                native_seh!(".seh_pushreg r15"),
                "push r12",
                native_seh!(".seh_pushreg r12"),
                "push r13",
                native_seh!(".seh_pushreg r13"),
                "sub rsp, 128",
                native_seh!(".seh_stackalloc 128"),
                native_seh!(".seh_endprologue"),
                "mov [rsp], rcx",
                "mov [rsp + 8], rdx",
                "mov [rsp + 16], r8",
                "mov [rsp + 24], r9",
                "lea rsi, [rsp + 208]", // entry RSP + 0x28: fifth Windows argument
                "lea rdi, [rsp + 32]",
                concat!("mov ecx, ", stringify!($argc)),
                "sub ecx, 4",
                "jle 2f",
                "rep movsq",
                "2:",
                // Recompute every transport coordinate and restage every argument after retry.
                "mov rax, qword ptr gs:[0x30]",
                "movabs r11, {sec_image_main_teb}",
                "cmp rax, r11",
                "je 3f",
                "movabs r11, {pe_main_teb}",
                "cmp rax, r11",
                "jne 4f",
                "3:",
                "movabs rax, {main_ipc_buffer}",
                "jmp 5f",
                "4:",
                "sub rax, {worker_ipc_delta}",
                "5:",
                "lea rsi, [rsp + 16]",
                "lea rdi, [rax + 0x28]", // MR4 onward: arguments three and later
                concat!("mov ecx, ", stringify!($argc)),
                "sub ecx, 2",
                "jle 6f",
                "rep movsq",
                "6:",
                "mov r9, [rsp]",
                "mov r15, [rsp + 8]",
                "lea r8, [rsp + 168]", // original Windows entry RSP, not helper geometry
                concat!("mov r10d, ", stringify!($ssn)),
                "mov edi, 6",
                "mov esi, {msginfo}",
                "xor r12d, r12d",
                "xor r13d, r13d",
                "mov rdx, -1",
                "syscall",
                // Ordinary status and explicit acquisition retry have distinct exact envelopes.
                "cmp rsi, 1",
                "je 7f",
                "cmp rsi, 6",
                "jne 8f",
                "movabs rax, {retry_reply}",
                "cmp r10, rax",
                "je 2b",
                "8:",
                "ud2",
                "7:",
                "mov rax, r10",
                "add rsp, 128",
                "pop r13",
                "pop r12",
                "pop r15",
                "pop rsi",
                "pop rdi",
                "ret",
                native_seh!(".seh_endproc"),
                sec_image_main_teb = const nt_syscall_abi::NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA,
                pe_main_teb = const nt_syscall_abi::NT_NATIVE_PE_MAIN_TEB_VA,
                main_ipc_buffer = const nt_syscall_abi::NT_NATIVE_MAIN_IPC_BUFFER_VA,
                worker_ipc_delta = const nt_syscall_abi::NT_NATIVE_WORKER_IPC_BUFFER_DELTA,
                msginfo = const nt_syscall_abi::native_syscall_message_info($argc),
                retry_reply = const nt_syscall_abi::NT_NATIVE_RETRY_REPLY,
            );
        }
    };
}

/// Generate typed exports, coverage metadata, and internal dispatch from the same service list.
macro_rules! generate_trap_stubs {
    ( $( ($fn:ident, $name:literal, $ssn:literal, $argc:tt) ),* $(,)? ) => {
        $( define_stub_arity!($fn, $name, $ssn, $argc); )*

        pub const TRAP_STUBS: &[TrapStubMeta] = &[
            $( TrapStubMeta { name: $name, ssn: $ssn, argc: $argc }, )*
        ];

        /// Exact arity from the same generated service list as the callable entries.
        pub const fn native_stub_argc(ssn: u32) -> Option<u8> {
            match ssn {
                $( $ssn => Some($argc), )*
                _ => None,
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[used]
        pub static TRAP_STUB_ADDRS: &[TrapStubAddress] = &[
            $( TrapStubAddress($fn as *const ()), )*
        ];

        /// Invoke the same typed Windows-ABI entry point exported from ntdll.
        ///
        /// # Safety
        /// This must run in a hosted native thread. Arguments must satisfy the selected NT
        /// service's pointer, handle and lifetime contracts.
        #[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
        pub unsafe fn invoke_native_stub(ssn: u32, arguments: &[u64]) -> Result<u64, NativeStubError> {
            validate_native_stub_arguments(ssn, arguments.len())?;
            match ssn {
                $( $ssn => Ok(invoke_stub_arity!($fn, $argc, arguments)), )*
                _ => Err(NativeStubError::UnknownService),
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeStubError {
    UnknownService,
    ArgumentCount,
}

/// Enforce the generated export's exact shared-service arity before reading argument slots.
pub fn validate_native_stub_arguments(ssn: u32, count: usize) -> Result<(), NativeStubError> {
    let argc = native_stub_argc(ssn).ok_or(NativeStubError::UnknownService)?;
    if count != usize::from(argc) {
        return Err(NativeStubError::ArgumentCount);
    }
    Ok(())
}

// Required Nt* services, sysfuncs.lst-derived SSNs. Sorted by SSN (matches the shared table).
generate_trap_stubs! {
    (nt_accept_connect_port, "NtAcceptConnectPort", 0, 6),
    (nt_access_check, "NtAccessCheck", 1, 8),
    (nt_access_check_and_audit_alarm, "NtAccessCheckAndAuditAlarm", 2, 11),
    (nt_access_check_by_type, "NtAccessCheckByType", 3, 11),
    (nt_access_check_by_type_result_list, "NtAccessCheckByTypeResultList", 5, 11),
    (nt_add_atom, "NtAddAtom", 8, 3),
    (nt_adjust_groups_token, "NtAdjustGroupsToken", 11, 6),
    (nt_adjust_privileges_token, "NtAdjustPrivilegesToken", 12, 6),
    (nt_allocate_locally_unique_id, "NtAllocateLocallyUniqueId", 15, 1),
    (nt_allocate_user_physical_pages, "NtAllocateUserPhysicalPages", 16, 3),
    (nt_allocate_virtual_memory, "NtAllocateVirtualMemory", 18, 6),
    (nt_apphelp_cache_control, "NtApphelpCacheControl", 19, 2),
    (nt_assign_process_to_job_object, "NtAssignProcessToJobObject", 21, 2),
    (nt_callback_return, "NtCallbackReturn", 22, 3),
    (nt_cancel_device_wakeup_request, "NtCancelDeviceWakeupRequest", 23, 1),
    (nt_cancel_io_file, "NtCancelIoFile", 24, 2),
    (nt_cancel_timer, "NtCancelTimer", 25, 2),
    (nt_clear_event, "NtClearEvent", 26, 1),
    (nt_close, "NtClose", 27, 1),
    (nt_close_object_audit_alarm, "NtCloseObjectAuditAlarm", 28, 3),
    (nt_complete_connect_port, "NtCompleteConnectPort", 31, 1),
    (nt_connect_port, "NtConnectPort", 33, 8),
    (nt_continue, "NtContinue", 34, 2),
    (nt_create_debug_object, "NtCreateDebugObject", 35, 4),
    (nt_create_directory_object, "NtCreateDirectoryObject", 36, 3),
    (nt_create_event, "NtCreateEvent", 37, 5),
    (nt_create_file, "NtCreateFile", 39, 11),
    (nt_create_io_completion, "NtCreateIoCompletion", 40, 4),
    (nt_create_job_object, "NtCreateJobObject", 41, 3),
    (nt_create_job_set, "NtCreateJobSet", 42, 3),
    (nt_create_key, "NtCreateKey", 43, 7),
    (nt_create_mailslot_file, "NtCreateMailslotFile", 44, 8),
    (nt_create_mutant, "NtCreateMutant", 45, 4),
    (nt_create_named_pipe_file, "NtCreateNamedPipeFile", 46, 14),
    (nt_create_paging_file, "NtCreatePagingFile", 47, 4),
    (nt_create_port, "NtCreatePort", 48, 5),
    (nt_create_process, "NtCreateProcess", 49, 8),
    (nt_create_process_ex, "NtCreateProcessEx", 50, 9),
    (nt_create_section, "NtCreateSection", 52, 7),
    (nt_create_semaphore, "NtCreateSemaphore", 53, 5),
    (nt_create_symbolic_link_object, "NtCreateSymbolicLinkObject", 54, 4),
    (nt_create_thread, "NtCreateThread", 55, 8),
    (nt_create_timer, "NtCreateTimer", 56, 4),
    (nt_create_token, "NtCreateToken", 57, 13),
    (nt_debug_active_process, "NtDebugActiveProcess", 59, 2),
    (nt_debug_continue, "NtDebugContinue", 60, 3),
    (nt_delay_execution, "NtDelayExecution", 61, 2),
    (nt_delete_atom, "NtDeleteAtom", 62, 1),
    (nt_delete_key, "NtDeleteKey", 66, 1),
    (nt_delete_object_audit_alarm, "NtDeleteObjectAuditAlarm", 67, 3),
    (nt_delete_value_key, "NtDeleteValueKey", 68, 2),
    (nt_device_io_control_file, "NtDeviceIoControlFile", 69, 10),
    (nt_display_string, "NtDisplayString", 70, 1),
    (nt_duplicate_object, "NtDuplicateObject", 71, 7),
    (nt_duplicate_token, "NtDuplicateToken", 72, 6),
    (nt_enumerate_key, "NtEnumerateKey", 75, 6),
    (nt_enumerate_value_key, "NtEnumerateValueKey", 77, 6),
    (nt_filter_token, "NtFilterToken", 79, 6),
    (nt_find_atom, "NtFindAtom", 80, 3),
    (nt_flush_buffers_file, "NtFlushBuffersFile", 81, 2),
    (nt_flush_instruction_cache, "NtFlushInstructionCache", 82, 3),
    (nt_flush_key, "NtFlushKey", 83, 1),
    (nt_flush_virtual_memory, "NtFlushVirtualMemory", 84, 4),
    (nt_free_user_physical_pages, "NtFreeUserPhysicalPages", 86, 3),
    (nt_free_virtual_memory, "NtFreeVirtualMemory", 87, 4),
    (nt_fs_control_file, "NtFsControlFile", 88, 10),
    (nt_get_context_thread, "NtGetContextThread", 89, 2),
    (nt_get_device_power_state, "NtGetDevicePowerState", 90, 2),
    (nt_get_plug_play_event, "NtGetPlugPlayEvent", 91, 4),
    (nt_get_write_watch, "NtGetWriteWatch", 92, 7),
    (nt_impersonate_anonymous_token, "NtImpersonateAnonymousToken", 93, 1),
    (nt_impersonate_client_of_port, "NtImpersonateClientOfPort", 94, 2),
    (nt_impersonate_thread, "NtImpersonateThread", 95, 3),
    (nt_initialize_registry, "NtInitializeRegistry", 96, 1),
    (nt_initiate_power_action, "NtInitiatePowerAction", 97, 4),
    (nt_is_process_in_job, "NtIsProcessInJob", 98, 2),
    (nt_is_system_resume_automatic, "NtIsSystemResumeAutomatic", 99, 0),
    (nt_listen_port, "NtListenPort", 100, 2),
    (nt_load_driver, "NtLoadDriver", 101, 1),
    (nt_load_key, "NtLoadKey", 102, 2),
    (nt_load_key2, "NtLoadKey2", 103, 3),
    (nt_load_key_ex, "NtLoadKeyEx", 104, 4),
    (nt_lock_file, "NtLockFile", 105, 10),
    (nt_lock_virtual_memory, "NtLockVirtualMemory", 108, 4),
    (nt_make_permanent_object, "NtMakePermanentObject", 109, 1),
    (nt_make_temporary_object, "NtMakeTemporaryObject", 110, 1),
    (nt_map_user_physical_pages, "NtMapUserPhysicalPages", 111, 3),
    (nt_map_user_physical_pages_scatter, "NtMapUserPhysicalPagesScatter", 112, 3),
    (nt_map_view_of_section, "NtMapViewOfSection", 113, 10),
    (nt_notify_change_directory_file, "NtNotifyChangeDirectoryFile", 116, 9),
    (nt_notify_change_key, "NtNotifyChangeKey", 117, 10),
    (nt_open_directory_object, "NtOpenDirectoryObject", 119, 3),
    (nt_open_event, "NtOpenEvent", 120, 3),
    (nt_open_event_pair, "NtOpenEventPair", 121, 3),
    (nt_open_file, "NtOpenFile", 122, 6),
    (nt_open_io_completion, "NtOpenIoCompletion", 123, 3),
    (nt_open_job_object, "NtOpenJobObject", 124, 3),
    (nt_open_key, "NtOpenKey", 125, 3),
    (nt_open_mutant, "NtOpenMutant", 126, 3),
    (nt_open_object_audit_alarm, "NtOpenObjectAuditAlarm", 127, 12),
    (nt_open_process, "NtOpenProcess", 128, 4),
    (nt_open_process_token, "NtOpenProcessToken", 129, 3),
    (nt_open_process_token_ex, "NtOpenProcessTokenEx", 130, 4),
    (nt_open_section, "NtOpenSection", 131, 3),
    (nt_open_semaphore, "NtOpenSemaphore", 132, 3),
    (nt_open_symbolic_link_object, "NtOpenSymbolicLinkObject", 133, 3),
    (nt_open_thread, "NtOpenThread", 134, 4),
    (nt_open_thread_token, "NtOpenThreadToken", 135, 4),
    (nt_open_thread_token_ex, "NtOpenThreadTokenEx", 136, 5),
    (nt_open_timer, "NtOpenTimer", 137, 3),
    (nt_plug_play_control, "NtPlugPlayControl", 138, 3),
    (nt_power_information, "NtPowerInformation", 139, 5),
    (nt_privilege_check, "NtPrivilegeCheck", 140, 3),
    (nt_privilege_object_audit_alarm, "NtPrivilegeObjectAuditAlarm", 141, 6),
    (nt_privileged_service_audit_alarm, "NtPrivilegedServiceAuditAlarm", 142, 5),
    (nt_protect_virtual_memory, "NtProtectVirtualMemory", 143, 5),
    (nt_pulse_event, "NtPulseEvent", 144, 2),
    (nt_query_attributes_file, "NtQueryAttributesFile", 145, 2),
    (nt_query_debug_filter_state, "NtQueryDebugFilterState", 148, 2),
    (nt_query_default_locale, "NtQueryDefaultLocale", 149, 2),
    (nt_query_default_ui_language, "NtQueryDefaultUILanguage", 150, 1),
    (nt_query_directory_file, "NtQueryDirectoryFile", 151, 11),
    (nt_query_directory_object, "NtQueryDirectoryObject", 152, 7),
    (nt_query_ea_file, "NtQueryEaFile", 154, 9),
    (nt_query_event, "NtQueryEvent", 155, 5),
    (nt_query_full_attributes_file, "NtQueryFullAttributesFile", 156, 2),
    (nt_query_information_atom, "NtQueryInformationAtom", 157, 5),
    (nt_query_information_file, "NtQueryInformationFile", 158, 5),
    (nt_query_information_job_object, "NtQueryInformationJobObject", 159, 5),
    (nt_query_information_process, "NtQueryInformationProcess", 161, 5),
    (nt_query_information_thread, "NtQueryInformationThread", 162, 5),
    (nt_query_information_token, "NtQueryInformationToken", 163, 5),
    (nt_query_install_ui_language, "NtQueryInstallUILanguage", 164, 1),
    (nt_query_io_completion, "NtQueryIoCompletion", 166, 5),
    (nt_query_key, "NtQueryKey", 167, 5),
    (nt_query_mutant, "NtQueryMutant", 169, 5),
    (nt_query_object, "NtQueryObject", 170, 5),
    (nt_query_performance_counter, "NtQueryPerformanceCounter", 173, 2),
    (nt_query_quota_information_file, "NtQueryQuotaInformationFile", 174, 9),
    (nt_query_section, "NtQuerySection", 175, 5),
    (nt_query_security_object, "NtQuerySecurityObject", 176, 5),
    (nt_query_semaphore, "NtQuerySemaphore", 177, 5),
    (nt_query_symbolic_link_object, "NtQuerySymbolicLinkObject", 178, 3),
    (nt_query_system_environment_value_ex, "NtQuerySystemEnvironmentValueEx", 180, 5),
    (nt_query_system_information, "NtQuerySystemInformation", 181, 4),
    (nt_query_system_time, "NtQuerySystemTime", 182, 1),
    (nt_query_timer, "NtQueryTimer", 183, 5),
    (nt_query_value_key, "NtQueryValueKey", 185, 6),
    (nt_query_virtual_memory, "NtQueryVirtualMemory", 186, 6),
    (nt_query_volume_information_file, "NtQueryVolumeInformationFile", 187, 5),
    (nt_queue_apc_thread, "NtQueueApcThread", 188, 5),
    (nt_raise_exception, "NtRaiseException", 189, 3),
    (nt_raise_hard_error, "NtRaiseHardError", 190, 6),
    (nt_read_file, "NtReadFile", 191, 9),
    (nt_read_file_scatter, "NtReadFileScatter", 192, 9),
    (nt_read_virtual_memory, "NtReadVirtualMemory", 194, 5),
    (nt_register_thread_terminate_port, "NtRegisterThreadTerminatePort", 195, 1),
    (nt_release_keyed_event, "NtReleaseKeyedEvent", 291, 4),
    (nt_release_mutant, "NtReleaseMutant", 196, 2),
    (nt_release_semaphore, "NtReleaseSemaphore", 197, 3),
    (nt_remove_io_completion, "NtRemoveIoCompletion", 198, 5),
    (nt_remove_process_debug, "NtRemoveProcessDebug", 199, 2),
    (nt_rename_key, "NtRenameKey", 200, 2),
    (nt_replace_key, "NtReplaceKey", 201, 3),
    (nt_reply_port, "NtReplyPort", 202, 2),
    (nt_reply_wait_receive_port, "NtReplyWaitReceivePort", 203, 4),
    (nt_request_device_wakeup, "NtRequestDeviceWakeup", 206, 1),
    (nt_request_wait_reply_port, "NtRequestWaitReplyPort", 208, 3),
    (nt_request_wakeup_latency, "NtRequestWakeupLatency", 209, 1),
    (nt_reset_event, "NtResetEvent", 210, 2),
    (nt_reset_write_watch, "NtResetWriteWatch", 211, 3),
    (nt_restore_key, "NtRestoreKey", 212, 3),
    (nt_resume_process, "NtResumeProcess", 213, 1),
    (nt_resume_thread, "NtResumeThread", 214, 2),
    (nt_save_key, "NtSaveKey", 215, 2),
    (nt_save_key_ex, "NtSaveKeyEx", 216, 3),
    (nt_secure_connect_port, "NtSecureConnectPort", 218, 9),
    (nt_set_context_thread, "NtSetContextThread", 221, 2),
    (nt_set_debug_filter_state, "NtSetDebugFilterState", 222, 3),
    (nt_set_default_hard_error_port, "NtSetDefaultHardErrorPort", 223, 1),
    (nt_set_default_locale, "NtSetDefaultLocale", 224, 2),
    (nt_set_default_ui_language, "NtSetDefaultUILanguage", 225, 1),
    (nt_set_ea_file, "NtSetEaFile", 227, 4),
    (nt_set_event, "NtSetEvent", 228, 2),
    (nt_set_information_debug_object, "NtSetInformationDebugObject", 232, 5),
    (nt_set_information_file, "NtSetInformationFile", 233, 5),
    (nt_set_information_job_object, "NtSetInformationJobObject", 234, 4),
    (nt_set_information_object, "NtSetInformationObject", 236, 4),
    (nt_set_information_process, "NtSetInformationProcess", 237, 4),
    (nt_set_information_thread, "NtSetInformationThread", 238, 4),
    (nt_set_information_token, "NtSetInformationToken", 239, 4),
    (nt_set_io_completion, "NtSetIoCompletion", 241, 5),
    (nt_set_quota_information_file, "NtSetQuotaInformationFile", 245, 4),
    (nt_set_security_object, "NtSetSecurityObject", 246, 3),
    (nt_set_system_environment_value_ex, "NtSetSystemEnvironmentValueEx", 248, 5),
    (nt_set_system_information, "NtSetSystemInformation", 249, 3),
    (nt_set_system_power_state, "NtSetSystemPowerState", 250, 3),
    (nt_set_system_time, "NtSetSystemTime", 251, 2),
    (nt_set_thread_execution_state, "NtSetThreadExecutionState", 252, 2),
    (nt_set_timer, "NtSetTimer", 253, 7),
    (nt_set_timer_resolution, "NtSetTimerResolution", 254, 3),
    (nt_set_uuid_seed, "NtSetUuidSeed", 255, 1),
    (nt_set_value_key, "NtSetValueKey", 256, 6),
    (nt_set_volume_information_file, "NtSetVolumeInformationFile", 257, 5),
    (nt_shutdown_system, "NtShutdownSystem", 258, 1),
    (nt_signal_and_wait_for_single_object, "NtSignalAndWaitForSingleObject", 259, 4),
    (nt_suspend_process, "NtSuspendProcess", 262, 1),
    (nt_suspend_thread, "NtSuspendThread", 263, 2),
    (nt_terminate_job_object, "NtTerminateJobObject", 265, 2),
    (nt_terminate_process, "NtTerminateProcess", 266, 2),
    (nt_terminate_thread, "NtTerminateThread", 267, 2),
    (nt_test_alert, "NtTestAlert", 268, 0),
    (nt_trace_event, "NtTraceEvent", 269, 4),
    (nt_unload_driver, "NtUnloadDriver", 271, 1),
    (nt_unload_key, "NtUnloadKey", 272, 1),
    (nt_unload_key2, "NtUnloadKey2", 273, 2),
    (nt_unload_key_ex, "NtUnloadKeyEx", 274, 2),
    (nt_unlock_file, "NtUnlockFile", 275, 5),
    (nt_unlock_virtual_memory, "NtUnlockVirtualMemory", 276, 4),
    (nt_unmap_view_of_section, "NtUnmapViewOfSection", 277, 2),
    (nt_wait_for_keyed_event, "NtWaitForKeyedEvent", 292, 4),
    (nt_wait_for_debug_event, "NtWaitForDebugEvent", 279, 4),
    (nt_wait_for_multiple_objects, "NtWaitForMultipleObjects", 280, 5),
    (nt_wait_for_single_object, "NtWaitForSingleObject", 281, 3),
    (nt_write_file, "NtWriteFile", 284, 9),
    (nt_write_file_gather, "NtWriteFileGather", 285, 9),
    (nt_write_virtual_memory, "NtWriteVirtualMemory", 287, 5),
    (nt_yield_execution, "NtYieldExecution", 288, 0),
    (nt_create_keyed_event, "NtCreateKeyedEvent", 289, 4),
    (nt_cancel_io_file_ex, "NtCancelIoFileEx", 0x300, 3),
    (nt_compare_objects, "NtCompareObjects", 0x301, 2),
    (nt_create_low_box_token, "NtCreateLowBoxToken", 0x302, 9),
    (nt_create_private_namespace, "NtCreatePrivateNamespace", 0x303, 4),
    (nt_create_user_process, "NtCreateUserProcess", 0x304, 11),
    (nt_delete_private_namespace, "NtDeletePrivateNamespace", 0x305, 1),
    (nt_get_nls_section_ptr, "NtGetNlsSectionPtr", 0x306, 5),
    (nt_open_private_namespace, "NtOpenPrivateNamespace", 0x307, 4),
    (nt_query_system_information_ex, "NtQuerySystemInformationEx", 0x308, 6),
    (nt_remove_io_completion_ex, "NtRemoveIoCompletionEx", 0x309, 6),
    (nt_set_information_virtual_memory, "NtSetInformationVirtualMemory", 0x30a, 6),
    (nt_trace_control, "NtTraceControl", 0x30b, 6),
    (nt_acquire_cmf_view_ownership, "NtAcquireCMFViewOwnership", 0x400, 3),
    (nt_add_boot_entry, "NtAddBootEntry", 0x401, 2),
    (nt_add_driver_entry, "NtAddDriverEntry", 0x402, 2),
    (nt_alert_multiple_thread_by_thread_id, "NtAlertMultipleThreadByThreadId", 0x403, 4),
    (nt_alert_resume_thread, "NtAlertResumeThread", 0x404, 2),
    (nt_alert_thread, "NtAlertThread", 0x405, 1),
    (nt_alert_thread_by_thread_id, "NtAlertThreadByThreadId", 0x406, 1),
    (nt_allocate_reserve_object, "NtAllocateReserveObject", 0x407, 3),
    (nt_allocate_uuids, "NtAllocateUuids", 0x408, 4),
    (nt_allocate_virtual_memory_ex, "NtAllocateVirtualMemoryEx", 0x409, 7),
    (nt_alpc_cancel_message, "NtAlpcCancelMessage", 0x40a, 3),
    (nt_alpc_connect_port_ex, "NtAlpcConnectPortEx", 0x40b, 11),
    (nt_alpc_create_port_section, "NtAlpcCreatePortSection", 0x40c, 6),
    (nt_alpc_create_resource_reserve, "NtAlpcCreateResourceReserve", 0x40d, 4),
    (nt_alpc_create_section_view, "NtAlpcCreateSectionView", 0x40e, 3),
    (nt_alpc_create_security_context, "NtAlpcCreateSecurityContext", 0x40f, 3),
    (nt_alpc_delete_port_section, "NtAlpcDeletePortSection", 0x410, 3),
    (nt_alpc_delete_resource_reserve, "NtAlpcDeleteResourceReserve", 0x411, 3),
    (nt_alpc_delete_section_view, "NtAlpcDeleteSectionView", 0x412, 3),
    (nt_alpc_delete_security_context, "NtAlpcDeleteSecurityContext", 0x413, 3),
    (nt_alpc_disconnect_port, "NtAlpcDisconnectPort", 0x414, 2),
    (nt_alpc_impersonate_client_container_of_port, "NtAlpcImpersonateClientContainerOfPort", 0x415, 3),
    (nt_alpc_impersonate_client_of_port, "NtAlpcImpersonateClientOfPort", 0x416, 3),
    (nt_alpc_open_sender_process, "NtAlpcOpenSenderProcess", 0x417, 6),
    (nt_alpc_open_sender_thread, "NtAlpcOpenSenderThread", 0x418, 6),
    (nt_alpc_query_information, "NtAlpcQueryInformation", 0x419, 5),
    (nt_alpc_query_information_message, "NtAlpcQueryInformationMessage", 0x41a, 6),
    (nt_alpc_revoke_security_context, "NtAlpcRevokeSecurityContext", 0x41b, 3),
    (nt_alpc_set_information, "NtAlpcSetInformation", 0x41c, 4),
    (nt_are_mapped_files_the_same, "NtAreMappedFilesTheSame", 0x41d, 2),
    (nt_associate_wait_completion_packet, "NtAssociateWaitCompletionPacket", 0x41e, 8),
    (nt_cancel_synchronous_io_file, "NtCancelSynchronousIoFile", 0x41f, 3),
    (nt_cancel_wait_completion_packet, "NtCancelWaitCompletionPacket", 0x420, 2),
    (nt_commit_complete, "NtCommitComplete", 0x421, 2),
    (nt_commit_enlistment, "NtCommitEnlistment", 0x422, 2),
    (nt_commit_transaction, "NtCommitTransaction", 0x423, 2),
    (nt_compact_keys, "NtCompactKeys", 0x424, 2),
    (nt_compare_tokens, "NtCompareTokens", 0x425, 3),
    (nt_compress_key, "NtCompressKey", 0x426, 1),
    (nt_continue_ex, "NtContinueEx", 0x427, 2),
    (nt_convert_between_auxiliary_counter_and_performance_counter, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", 0x428, 4),
    (nt_create_enlistment, "NtCreateEnlistment", 0x429, 8),
    (nt_create_event_pair, "NtCreateEventPair", 0x42a, 3),
    (nt_create_key_transacted, "NtCreateKeyTransacted", 0x42b, 8),
    (nt_create_profile, "NtCreateProfile", 0x42c, 9),
    (nt_create_resource_manager, "NtCreateResourceManager", 0x42d, 7),
    (nt_create_section_ex, "NtCreateSectionEx", 0x42e, 9),
    (nt_create_thread_ex, "NtCreateThreadEx", 0x42f, 11),
    (nt_create_transaction, "NtCreateTransaction", 0x430, 10),
    (nt_create_transaction_manager, "NtCreateTransactionManager", 0x431, 6),
    (nt_create_wait_completion_packet, "NtCreateWaitCompletionPacket", 0x432, 3),
    (nt_create_waitable_port, "NtCreateWaitablePort", 0x433, 5),
    (nt_create_wnf_state_name, "NtCreateWnfStateName", 0x434, 7),
    (nt_create_worker_factory, "NtCreateWorkerFactory", 0x435, 10),
    (nt_delete_boot_entry, "NtDeleteBootEntry", 0x436, 1),
    (nt_delete_driver_entry, "NtDeleteDriverEntry", 0x437, 1),
    (nt_delete_file, "NtDeleteFile", 0x438, 1),
    (nt_delete_wnf_state_data, "NtDeleteWnfStateData", 0x439, 2),
    (nt_delete_wnf_state_name, "NtDeleteWnfStateName", 0x43a, 1),
    (nt_enumerate_boot_entries, "NtEnumerateBootEntries", 0x43b, 2),
    (nt_enumerate_driver_entries, "NtEnumerateDriverEntries", 0x43c, 2),
    (nt_enumerate_system_environment_values_ex, "NtEnumerateSystemEnvironmentValuesEx", 0x43d, 3),
    (nt_enumerate_transaction_object, "NtEnumerateTransactionObject", 0x43e, 5),
    (nt_extend_section, "NtExtendSection", 0x43f, 2),
    (nt_flush_buffers_file_ex, "NtFlushBuffersFileEx", 0x440, 5),
    (nt_flush_install_ui_language, "NtFlushInstallUILanguage", 0x441, 2),
    (nt_flush_process_write_buffers, "NtFlushProcessWriteBuffers", 0x442, 0),
    (nt_flush_write_buffer, "NtFlushWriteBuffer", 0x443, 0),
    (nt_freeze_registry, "NtFreezeRegistry", 0x444, 1),
    (nt_freeze_transactions, "NtFreezeTransactions", 0x445, 2),
    (nt_get_current_processor_number, "NtGetCurrentProcessorNumber", 0x446, 0),
    (nt_get_current_processor_number_ex, "NtGetCurrentProcessorNumberEx", 0x447, 1),
    (nt_get_mui_registry_info, "NtGetMUIRegistryInfo", 0x448, 3),
    (nt_get_next_process, "NtGetNextProcess", 0x449, 5),
    (nt_get_next_thread, "NtGetNextThread", 0x44a, 6),
    (nt_get_notification_resource_manager, "NtGetNotificationResourceManager", 0x44b, 7),
    (nt_initialize_nls_files, "NtInitializeNlsFiles", 0x44c, 3),
    (nt_is_ui_language_comitted, "NtIsUILanguageComitted", 0x44d, 0),
    (nt_lock_product_activation_keys, "NtLockProductActivationKeys", 0x44e, 2),
    (nt_lock_registry_key, "NtLockRegistryKey", 0x44f, 1),
    (nt_map_cmf_module, "NtMapCMFModule", 0x450, 6),
    (nt_map_view_of_section_ex, "NtMapViewOfSectionEx", 0x451, 9),
    (nt_modify_boot_entry, "NtModifyBootEntry", 0x452, 1),
    (nt_modify_driver_entry, "NtModifyDriverEntry", 0x453, 1),
    (nt_notify_change_directory_file_ex, "NtNotifyChangeDirectoryFileEx", 0x454, 10),
    (nt_notify_change_multiple_keys, "NtNotifyChangeMultipleKeys", 0x455, 12),
    (nt_open_enlistment, "NtOpenEnlistment", 0x456, 5),
    (nt_open_key_ex, "NtOpenKeyEx", 0x457, 4),
    (nt_open_key_transacted, "NtOpenKeyTransacted", 0x458, 4),
    (nt_open_key_transacted_ex, "NtOpenKeyTransactedEx", 0x459, 5),
    (nt_open_keyed_event, "NtOpenKeyedEvent", 0x45a, 3),
    (nt_open_resource_manager, "NtOpenResourceManager", 0x45b, 5),
    (nt_open_session, "NtOpenSession", 0x45c, 3),
    (nt_open_transaction, "NtOpenTransaction", 0x45d, 5),
    (nt_open_transaction_manager, "NtOpenTransactionManager", 0x45e, 6),
    (nt_pre_prepare_complete, "NtPrePrepareComplete", 0x45f, 2),
    (nt_pre_prepare_enlistment, "NtPrePrepareEnlistment", 0x460, 2),
    (nt_prepare_complete, "NtPrepareComplete", 0x461, 2),
    (nt_prepare_enlistment, "NtPrepareEnlistment", 0x462, 2),
    (nt_propagation_complete, "NtPropagationComplete", 0x463, 4),
    (nt_propagation_failed, "NtPropagationFailed", 0x464, 3),
    (nt_query_boot_entry_order, "NtQueryBootEntryOrder", 0x465, 2),
    (nt_query_boot_options, "NtQueryBootOptions", 0x466, 2),
    (nt_query_directory_file_ex, "NtQueryDirectoryFileEx", 0x467, 10),
    (nt_query_driver_entry_order, "NtQueryDriverEntryOrder", 0x468, 2),
    (nt_query_information_by_name, "NtQueryInformationByName", 0x469, 5),
    (nt_query_information_enlistment, "NtQueryInformationEnlistment", 0x46a, 5),
    (nt_query_information_port, "NtQueryInformationPort", 0x46b, 5),
    (nt_query_information_resource_manager, "NtQueryInformationResourceManager", 0x46c, 5),
    (nt_query_information_transaction, "NtQueryInformationTransaction", 0x46d, 5),
    (nt_query_information_transaction_manager, "NtQueryInformationTransactionManager", 0x46e, 5),
    (nt_query_information_worker_factory, "NtQueryInformationWorkerFactory", 0x46f, 5),
    (nt_query_interval_profile, "NtQueryIntervalProfile", 0x470, 2),
    (nt_query_license_value, "NtQueryLicenseValue", 0x471, 5),
    (nt_query_multiple_value_key, "NtQueryMultipleValueKey", 0x472, 6),
    (nt_query_open_sub_keys, "NtQueryOpenSubKeys", 0x473, 2),
    (nt_query_open_sub_keys_ex, "NtQueryOpenSubKeysEx", 0x474, 4),
    (nt_query_port_information_process, "NtQueryPortInformationProcess", 0x475, 0),
    (nt_query_system_environment_value, "NtQuerySystemEnvironmentValue", 0x476, 4),
    (nt_query_timer_resolution, "NtQueryTimerResolution", 0x477, 3),
    (nt_query_wnf_state_data, "NtQueryWnfStateData", 0x478, 6),
    (nt_query_wnf_state_name_information, "NtQueryWnfStateNameInformation", 0x479, 5),
    (nt_queue_apc_thread_ex, "NtQueueApcThreadEx", 0x47a, 6),
    (nt_queue_apc_thread_ex2, "NtQueueApcThreadEx2", 0x47b, 7),
    (nt_read_only_enlistment, "NtReadOnlyEnlistment", 0x47c, 2),
    (nt_read_request_data, "NtReadRequestData", 0x47d, 6),
    (nt_recover_enlistment, "NtRecoverEnlistment", 0x47e, 2),
    (nt_recover_resource_manager, "NtRecoverResourceManager", 0x47f, 1),
    (nt_recover_transaction_manager, "NtRecoverTransactionManager", 0x480, 1),
    (nt_register_protocol_address_information, "NtRegisterProtocolAddressInformation", 0x481, 5),
    (nt_release_cmf_view_ownership, "NtReleaseCMFViewOwnership", 0x482, 0),
    (nt_release_worker_factory_worker, "NtReleaseWorkerFactoryWorker", 0x483, 1),
    (nt_rename_transaction_manager, "NtRenameTransactionManager", 0x484, 2),
    (nt_replace_partition_unit, "NtReplacePartitionUnit", 0x485, 3),
    (nt_reply_wait_receive_port_ex, "NtReplyWaitReceivePortEx", 0x486, 5),
    (nt_reply_wait_reply_port, "NtReplyWaitReplyPort", 0x487, 2),
    (nt_request_port, "NtRequestPort", 0x488, 2),
    (nt_rollback_complete, "NtRollbackComplete", 0x489, 2),
    (nt_rollback_enlistment, "NtRollbackEnlistment", 0x48a, 2),
    (nt_rollback_transaction, "NtRollbackTransaction", 0x48b, 2),
    (nt_rollforward_transaction_manager, "NtRollforwardTransactionManager", 0x48c, 2),
    (nt_save_merged_keys, "NtSaveMergedKeys", 0x48d, 3),
    (nt_set_boot_entry_order, "NtSetBootEntryOrder", 0x48e, 2),
    (nt_set_boot_options, "NtSetBootOptions", 0x48f, 2),
    (nt_set_driver_entry_order, "NtSetDriverEntryOrder", 0x490, 2),
    (nt_set_event_boost_priority, "NtSetEventBoostPriority", 0x491, 1),
    (nt_set_high_event_pair, "NtSetHighEventPair", 0x492, 1),
    (nt_set_high_wait_low_event_pair, "NtSetHighWaitLowEventPair", 0x493, 1),
    (nt_set_information_enlistment, "NtSetInformationEnlistment", 0x494, 4),
    (nt_set_information_key, "NtSetInformationKey", 0x495, 4),
    (nt_set_information_resource_manager, "NtSetInformationResourceManager", 0x496, 4),
    (nt_set_information_transaction, "NtSetInformationTransaction", 0x497, 4),
    (nt_set_information_transaction_manager, "NtSetInformationTransactionManager", 0x498, 4),
    (nt_set_information_worker_factory, "NtSetInformationWorkerFactory", 0x499, 4),
    (nt_set_interval_profile, "NtSetIntervalProfile", 0x49a, 2),
    (nt_set_io_completion_ex, "NtSetIoCompletionEx", 0x49b, 6),
    (nt_set_ldt_entries, "NtSetLdtEntries", 0x49c, 4),
    (nt_set_low_event_pair, "NtSetLowEventPair", 0x49d, 1),
    (nt_set_low_wait_high_event_pair, "NtSetLowWaitHighEventPair", 0x49e, 1),
    (nt_set_system_environment_value, "NtSetSystemEnvironmentValue", 0x49f, 2),
    (nt_shutdown_worker_factory, "NtShutdownWorkerFactory", 0x4a0, 2),
    (nt_single_phase_reject, "NtSinglePhaseReject", 0x4a1, 2),
    (nt_start_profile, "NtStartProfile", 0x4a2, 1),
    (nt_stop_profile, "NtStopProfile", 0x4a3, 1),
    (nt_subscribe_wnf_state_change, "NtSubscribeWnfStateChange", 0x4a4, 4),
    (nt_system_debug_control, "NtSystemDebugControl", 0x4a5, 6),
    (nt_thaw_registry, "NtThawRegistry", 0x4a6, 0),
    (nt_thaw_transactions, "NtThawTransactions", 0x4a7, 0),
    (nt_translate_file_path, "NtTranslateFilePath", 0x4a8, 4),
    (nt_unmap_view_of_section_ex, "NtUnmapViewOfSectionEx", 0x4a9, 3),
    (nt_unsubscribe_wnf_state_change, "NtUnsubscribeWnfStateChange", 0x4aa, 1),
    (nt_update_wnf_state_data, "NtUpdateWnfStateData", 0x4ab, 7),
    (nt_vdm_control, "NtVdmControl", 0x4ac, 2),
    (nt_wait_for_alert_by_thread_id, "NtWaitForAlertByThreadId", 0x4ad, 2),
    (nt_wait_for_multiple_objects32, "NtWaitForMultipleObjects32", 0x4ae, 5),
    (nt_wait_for_work_via_worker_factory, "NtWaitForWorkViaWorkerFactory", 0x4af, 2),
    (nt_wait_high_event_pair, "NtWaitHighEventPair", 0x4b0, 1),
    (nt_wait_low_event_pair, "NtWaitLowEventPair", 0x4b1, 1),
    (nt_worker_factory_worker_ready, "NtWorkerFactoryWorkerReady", 0x4b2, 1),
    (nt_write_request_data, "NtWriteRequestData", 0x4b3, 6),
    (nt_alpc_accept_connect_port, "NtAlpcAcceptConnectPort", 0x700, 9),
    (nt_alpc_connect_port, "NtAlpcConnectPort", 0x701, 11),
    (nt_alpc_create_port, "NtAlpcCreatePort", 0x702, 3),
    (nt_alpc_send_wait_receive_port, "NtAlpcSendWaitReceivePort", 0x703, 8),
}

/// Look up a generated trap stub's metadata by export name.
pub fn trap_stub(name: &str) -> Option<TrapStubMeta> {
    TRAP_STUBS.iter().copied().find(|stub| stub.name == name)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use nt_syscall_abi::{ssn_of, NT_SYSCALLS};
    use std::collections::BTreeSet;

    #[test]
    fn generates_all_required_stubs() {
        assert_eq!(TRAP_STUBS.len(), NT_SYSCALLS.len());
    }

    #[test]
    fn every_required_service_has_a_trap_stub_with_matching_ssn() {
        for e in NT_SYSCALLS {
            let m = trap_stub(e.name).unwrap_or_else(|| panic!("no trap stub for {}", e.name));
            assert_eq!(m.ssn, e.ssn, "SSN mismatch for {}", e.name);
            assert_eq!(m.ssn, ssn_of(e.name).unwrap());
            // Arity resolved from the shared table (non-zero for anything that takes args).
            assert_eq!(m.argc, nt_syscall_abi::argc_of(e.name));
        }
    }

    #[test]
    fn no_duplicate_names_or_ssns_in_generated_set() {
        let names: BTreeSet<_> = TRAP_STUBS.iter().map(|s| s.name).collect();
        assert_eq!(names.len(), TRAP_STUBS.len(), "duplicate stub name");
        let ssns: BTreeSet<_> = TRAP_STUBS.iter().map(|s| s.ssn).collect();
        assert_eq!(ssns.len(), TRAP_STUBS.len(), "duplicate stub SSN");
    }

    #[test]
    fn generated_ssns_match_the_shared_abi_exactly() {
        // Every generated stub SSN must appear in the shared table (no drift between the naked-asm
        // immediate and the executive's dispatch numbering).
        for s in TRAP_STUBS {
            assert_eq!(ssn_of(s.name), Some(s.ssn), "{} drifted", s.name);
        }
    }

    #[test]
    fn native_internal_invocation_requires_exact_shared_arity() {
        for stub in TRAP_STUBS {
            let count = usize::from(stub.argc);
            assert_eq!(native_stub_argc(stub.ssn), nt_syscall_abi::exact_argc_of(stub.name));
            assert_eq!(validate_native_stub_arguments(stub.ssn, count), Ok(()));
            assert_eq!(
                validate_native_stub_arguments(stub.ssn, count + 1),
                Err(NativeStubError::ArgumentCount)
            );
            if count != 0 {
                assert_eq!(
                    validate_native_stub_arguments(stub.ssn, count - 1),
                    Err(NativeStubError::ArgumentCount)
                );
            }
        }
        assert_eq!(
            validate_native_stub_arguments(u32::MAX, 0),
            Err(NativeStubError::UnknownService)
        );
        assert_eq!(native_stub_argc(u32::MAX), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn generated_entries_have_callable_windows_signatures() {
        let _: unsafe extern "win64" fn() -> u64 = nt_yield_execution;
        let _: unsafe extern "win64" fn(u64) -> u64 = nt_close;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64) -> u64 = nt_open_file;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            nt_map_view_of_section;
        let _: unsafe extern "win64" fn(u64, u64, u64) -> u64 = nt_alpc_create_port;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            nt_alpc_accept_connect_port;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            nt_alpc_connect_port;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            nt_alpc_send_wait_receive_port;
        let _: unsafe extern "win64" fn(u64, u64, u64) -> u64 = nt_cancel_io_file_ex;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 = nt_create_private_namespace;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            nt_create_user_process;
        let _: unsafe extern "win64" fn(u64, u64, u64, u64, u64, u64) -> u64 =
            nt_trace_control;
    }
}
