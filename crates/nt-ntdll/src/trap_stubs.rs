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
                // The argument vector belongs to this invocation, not the mutable IPC buffer.
                "push rdi",
                "push rsi",
                "push r15",
                "push r12",
                "push r13",
                "sub rsp, 128",
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
    }
}
