//! The full 188 `Nt*` **trap-stub bodies** — the classic x86 form, macro-generated over the shared
//! SSN table.
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
//! The bodies are `#[cfg(target_arch = "x86_64")]` naked functions (no host equivalent — a host
//! can't issue the trap). What IS host-tested is that the generator covers **all 188** required
//! services with the correct SSN + arity: see [`TRAP_STUBS`] and the tests. This keeps the
//! generation itself under test even though the asm is target-only.

use nt_syscall_abi::argc_of;

/// A generated trap stub's metadata: export name, SSN, and parameter count. On the x86_64 target the
/// matching naked function exists (see [`generate_trap_stubs!`]); this table exists on every target
/// so the *coverage* (all 188, right SSN/arity) is host-testable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TrapStubMeta {
    /// The `Nt*` export name.
    pub name: &'static str,
    /// The SSN baked into the stub's `mov eax, <ssn>`.
    pub ssn: u32,
    /// The service's parameter count (register-width args).
    pub argc: u8,
}

/// Emit a `#[unsafe(naked)]` x86_64 trap stub per `(fn_ident, "ExportName", ssn)` triple, and build
/// the host-visible [`TRAP_STUBS`] coverage table over the same set.
///
/// On non-x86_64 hosts only the metadata table is emitted (no naked body) — the generation is still
/// exercised by the tests. On x86_64 the naked bodies are the real exported ntdll stubs.
macro_rules! generate_trap_stubs {
    ( $( ($fn:ident, $name:literal, $ssn:literal) ),* $(,)? ) => {
        $(
            // ── TRAP transport (default): `mov r10,rcx; mov eax,<ssn>; syscall; ret` ────────────
            // Faults as UnknownSyscall → serviced via the fault EP. Kept as the fallback (real ntdll
            // / pi>=1). Selected when the `native_transport` feature is OFF.
            #[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
            #[unsafe(naked)]
            // Export under the REAL Windows `Nt*` name (not the snake_case fn ident), so the PE
            // export directory lists `NtClose`/`NtCreateFile`/… — the names hosted binaries import.
            #[export_name = $name]
            /// Generated `Nt*` trap stub: `mov r10,rcx; mov eax,<ssn>; syscall; ret`.
            pub extern "C" fn $fn() {
                core::arch::naked_asm!(
                    "mov r10, rcx",
                    concat!("mov eax, ", stringify!($ssn)),
                    "syscall",
                    "ret",
                );
            }

            // ── NATIVE seL4-Call transport (ntdll_plan Step 6.A) ────────────────────────────────
            // A real native seL4 `Call(CT_FAULT)` carrying the NT_NATIVE_SYSCALL request message
            // (SSN + rsp + 4 register args), reading NTSTATUS from the reply MR0. See
            // `crate::native_call` for the wire layout. Selected when `native_transport` is ON.
            //
            // Windows-ABI entry: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4, args5+ on the stack; rsp at
            // entry points AT the return address (caller's stack args at [rsp+0x28]…). We capture
            // that rsp (MR1) so the executive reads stack args + writes stack out-params via its
            // mirror — a native Call transfers no rsp/stack (unlike the UnknownSyscall fault frame).
            #[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
            #[unsafe(naked)]
            #[export_name = $name]
            /// Generated `Nt*` native-Call stub (seL4 `Call` on CT_FAULT; NTSTATUS in reply MR0).
            pub extern "C" fn $fn() {
                core::arch::naked_asm!(
                    // Stash args3/4 into the IPC buffer as MR4/MR5 (only 4 MRs ride in registers).
                    // IPC buffer word[i] = MR i at byte (8 + i*8); MR4 @ +0x28, MR5 @ +0x30.
                    "movabs rax, 0x00000100105FB000",   // IPCBUF_VADDR (fixed per-process VA)
                    "mov qword ptr [rax + 0x28], r8",   // MR4 = arg3
                    "mov qword ptr [rax + 0x30], r9",   // MR5 = arg4
                    // Build the register message. Capture rsp (MR1) BEFORE any push.
                    "mov r8, rsp",                      // MR1 = caller rsp
                    "mov r9, rcx",                      // MR2 = arg1 (rcx)
                    "mov r15, rdx",                     // MR3 = arg2 (rdx)
                    concat!("mov r10d, ", stringify!($ssn)), // MR0 = SSN
                    "mov edi, 6",                       // rdi = CT_FAULT cap slot
                    // rsi = msginfo = (NT_NATIVE_SYSCALL_LABEL<<12) | length(6) = 0x4E54_6006.
                    "mov esi, 0x04E54006",              // rsi = (0x4E54<<12)|6 = label 0x4E54, len 6
                    "mov rdx, -1",                      // rdx = SysCall (native seL4 Call)
                    "syscall",                          // native seL4 Call → executive Recv/Reply
                    // Reply: MR0 (r10) = NTSTATUS. Move to rax (the C return register) and ret.
                    "mov rax, r10",
                    "ret",
                );
            }
        )*

        /// The full generated trap-stub coverage table (metadata; the naked bodies are target-only).
        pub const TRAP_STUBS: &[TrapStubMeta] = &[
            $( TrapStubMeta { name: $name, ssn: $ssn, argc: 0 }, )*
        ];

        /// A `#[used]` array of every naked trap stub's address. Referencing the stubs here forces
        /// the linker to RETAIN them when this rlib is linked into the [`nt-ntdll-dll`] cdylib —
        /// otherwise dead-code elimination would drop the `Nt*` exports (nothing else references the
        /// naked bodies). Target-only (the naked bodies only exist on x86_64). Not host-tested (it's
        /// a linker-retention anchor, not logic); the coverage of the same set is under test via
        /// [`TRAP_STUBS`].
        #[cfg(target_arch = "x86_64")]
        #[used]
        pub static TRAP_STUB_ADDRS: &[unsafe extern "C" fn()] = &[
            $( $fn, )*
        ];
    };
}

// The 188 required Nt* services, sysfuncs.lst-derived SSN. Sorted by SSN (matches the shared table).
generate_trap_stubs! {
    (nt_accept_connect_port, "NtAcceptConnectPort", 0),
    (nt_access_check, "NtAccessCheck", 1),
    (nt_access_check_and_audit_alarm, "NtAccessCheckAndAuditAlarm", 2),
    (nt_access_check_by_type, "NtAccessCheckByType", 3),
    (nt_access_check_by_type_result_list, "NtAccessCheckByTypeResultList", 5),
    (nt_add_atom, "NtAddAtom", 8),
    (nt_adjust_groups_token, "NtAdjustGroupsToken", 11),
    (nt_adjust_privileges_token, "NtAdjustPrivilegesToken", 12),
    (nt_allocate_locally_unique_id, "NtAllocateLocallyUniqueId", 15),
    (nt_allocate_user_physical_pages, "NtAllocateUserPhysicalPages", 16),
    (nt_allocate_virtual_memory, "NtAllocateVirtualMemory", 18),
    (nt_apphelp_cache_control, "NtApphelpCacheControl", 19),
    (nt_assign_process_to_job_object, "NtAssignProcessToJobObject", 21),
    (nt_cancel_device_wakeup_request, "NtCancelDeviceWakeupRequest", 23),
    (nt_cancel_io_file, "NtCancelIoFile", 24),
    (nt_cancel_timer, "NtCancelTimer", 25),
    (nt_clear_event, "NtClearEvent", 26),
    (nt_close, "NtClose", 27),
    (nt_close_object_audit_alarm, "NtCloseObjectAuditAlarm", 28),
    (nt_complete_connect_port, "NtCompleteConnectPort", 31),
    (nt_connect_port, "NtConnectPort", 33),
    (nt_create_directory_object, "NtCreateDirectoryObject", 36),
    (nt_create_event, "NtCreateEvent", 37),
    (nt_create_file, "NtCreateFile", 39),
    (nt_create_io_completion, "NtCreateIoCompletion", 40),
    (nt_create_job_object, "NtCreateJobObject", 41),
    (nt_create_job_set, "NtCreateJobSet", 42),
    (nt_create_key, "NtCreateKey", 43),
    (nt_create_mailslot_file, "NtCreateMailslotFile", 44),
    (nt_create_mutant, "NtCreateMutant", 45),
    (nt_create_named_pipe_file, "NtCreateNamedPipeFile", 46),
    (nt_create_paging_file, "NtCreatePagingFile", 47),
    (nt_create_port, "NtCreatePort", 48),
    (nt_create_process_ex, "NtCreateProcessEx", 50),
    (nt_create_section, "NtCreateSection", 52),
    (nt_create_semaphore, "NtCreateSemaphore", 53),
    (nt_create_symbolic_link_object, "NtCreateSymbolicLinkObject", 54),
    (nt_create_thread, "NtCreateThread", 55),
    (nt_create_timer, "NtCreateTimer", 56),
    (nt_create_token, "NtCreateToken", 57),
    (nt_delay_execution, "NtDelayExecution", 61),
    (nt_delete_atom, "NtDeleteAtom", 62),
    (nt_delete_key, "NtDeleteKey", 66),
    (nt_delete_object_audit_alarm, "NtDeleteObjectAuditAlarm", 67),
    (nt_delete_value_key, "NtDeleteValueKey", 68),
    (nt_device_io_control_file, "NtDeviceIoControlFile", 69),
    (nt_display_string, "NtDisplayString", 70),
    (nt_duplicate_object, "NtDuplicateObject", 71),
    (nt_duplicate_token, "NtDuplicateToken", 72),
    (nt_enumerate_key, "NtEnumerateKey", 75),
    (nt_enumerate_value_key, "NtEnumerateValueKey", 77),
    (nt_filter_token, "NtFilterToken", 79),
    (nt_find_atom, "NtFindAtom", 80),
    (nt_flush_buffers_file, "NtFlushBuffersFile", 81),
    (nt_flush_instruction_cache, "NtFlushInstructionCache", 82),
    (nt_flush_key, "NtFlushKey", 83),
    (nt_flush_virtual_memory, "NtFlushVirtualMemory", 84),
    (nt_free_user_physical_pages, "NtFreeUserPhysicalPages", 86),
    (nt_free_virtual_memory, "NtFreeVirtualMemory", 87),
    (nt_fs_control_file, "NtFsControlFile", 88),
    (nt_get_context_thread, "NtGetContextThread", 89),
    (nt_get_device_power_state, "NtGetDevicePowerState", 90),
    (nt_get_write_watch, "NtGetWriteWatch", 92),
    (nt_impersonate_anonymous_token, "NtImpersonateAnonymousToken", 93),
    (nt_impersonate_thread, "NtImpersonateThread", 95),
    (nt_initialize_registry, "NtInitializeRegistry", 96),
    (nt_initiate_power_action, "NtInitiatePowerAction", 97),
    (nt_is_process_in_job, "NtIsProcessInJob", 98),
    (nt_is_system_resume_automatic, "NtIsSystemResumeAutomatic", 99),
    (nt_listen_port, "NtListenPort", 100),
    (nt_load_driver, "NtLoadDriver", 101),
    (nt_load_key, "NtLoadKey", 102),
    (nt_lock_file, "NtLockFile", 105),
    (nt_lock_virtual_memory, "NtLockVirtualMemory", 108),
    (nt_make_permanent_object, "NtMakePermanentObject", 109),
    (nt_make_temporary_object, "NtMakeTemporaryObject", 110),
    (nt_map_user_physical_pages, "NtMapUserPhysicalPages", 111),
    (nt_map_user_physical_pages_scatter, "NtMapUserPhysicalPagesScatter", 112),
    (nt_map_view_of_section, "NtMapViewOfSection", 113),
    (nt_notify_change_directory_file, "NtNotifyChangeDirectoryFile", 116),
    (nt_notify_change_key, "NtNotifyChangeKey", 117),
    (nt_open_directory_object, "NtOpenDirectoryObject", 119),
    (nt_open_event, "NtOpenEvent", 120),
    (nt_open_file, "NtOpenFile", 122),
    (nt_open_job_object, "NtOpenJobObject", 124),
    (nt_open_key, "NtOpenKey", 125),
    (nt_open_mutant, "NtOpenMutant", 126),
    (nt_open_object_audit_alarm, "NtOpenObjectAuditAlarm", 127),
    (nt_open_process, "NtOpenProcess", 128),
    (nt_open_process_token, "NtOpenProcessToken", 129),
    (nt_open_section, "NtOpenSection", 131),
    (nt_open_semaphore, "NtOpenSemaphore", 132),
    (nt_open_symbolic_link_object, "NtOpenSymbolicLinkObject", 133),
    (nt_open_thread, "NtOpenThread", 134),
    (nt_open_thread_token, "NtOpenThreadToken", 135),
    (nt_open_timer, "NtOpenTimer", 137),
    (nt_power_information, "NtPowerInformation", 139),
    (nt_privilege_check, "NtPrivilegeCheck", 140),
    (nt_privilege_object_audit_alarm, "NtPrivilegeObjectAuditAlarm", 141),
    (nt_privileged_service_audit_alarm, "NtPrivilegedServiceAuditAlarm", 142),
    (nt_protect_virtual_memory, "NtProtectVirtualMemory", 143),
    (nt_pulse_event, "NtPulseEvent", 144),
    (nt_query_attributes_file, "NtQueryAttributesFile", 145),
    (nt_query_default_locale, "NtQueryDefaultLocale", 149),
    (nt_query_default_ui_language, "NtQueryDefaultUILanguage", 150),
    (nt_query_directory_file, "NtQueryDirectoryFile", 151),
    (nt_query_directory_object, "NtQueryDirectoryObject", 152),
    (nt_query_ea_file, "NtQueryEaFile", 154),
    (nt_query_event, "NtQueryEvent", 155),
    (nt_query_full_attributes_file, "NtQueryFullAttributesFile", 156),
    (nt_query_information_atom, "NtQueryInformationAtom", 157),
    (nt_query_information_file, "NtQueryInformationFile", 158),
    (nt_query_information_job_object, "NtQueryInformationJobObject", 159),
    (nt_query_information_process, "NtQueryInformationProcess", 161),
    (nt_query_information_thread, "NtQueryInformationThread", 162),
    (nt_query_information_token, "NtQueryInformationToken", 163),
    (nt_query_install_ui_language, "NtQueryInstallUILanguage", 164),
    (nt_query_key, "NtQueryKey", 167),
    (nt_query_object, "NtQueryObject", 170),
    (nt_query_performance_counter, "NtQueryPerformanceCounter", 173),
    (nt_query_section, "NtQuerySection", 175),
    (nt_query_security_object, "NtQuerySecurityObject", 176),
    (nt_query_symbolic_link_object, "NtQuerySymbolicLinkObject", 178),
    (nt_query_system_environment_value_ex, "NtQuerySystemEnvironmentValueEx", 180),
    (nt_query_system_information, "NtQuerySystemInformation", 181),
    (nt_query_system_time, "NtQuerySystemTime", 182),
    (nt_query_value_key, "NtQueryValueKey", 185),
    (nt_query_virtual_memory, "NtQueryVirtualMemory", 186),
    (nt_query_volume_information_file, "NtQueryVolumeInformationFile", 187),
    (nt_queue_apc_thread, "NtQueueApcThread", 188),
    (nt_raise_hard_error, "NtRaiseHardError", 190),
    (nt_read_file, "NtReadFile", 191),
    (nt_read_file_scatter, "NtReadFileScatter", 192),
    (nt_read_virtual_memory, "NtReadVirtualMemory", 194),
    (nt_release_keyed_event, "NtReleaseKeyedEvent", 291),
    (nt_release_mutant, "NtReleaseMutant", 196),
    (nt_release_semaphore, "NtReleaseSemaphore", 197),
    (nt_remove_io_completion, "NtRemoveIoCompletion", 198),
    (nt_replace_key, "NtReplaceKey", 201),
    (nt_reply_port, "NtReplyPort", 202),
    (nt_reply_wait_receive_port, "NtReplyWaitReceivePort", 203),
    (nt_request_device_wakeup, "NtRequestDeviceWakeup", 206),
    (nt_request_wait_reply_port, "NtRequestWaitReplyPort", 208),
    (nt_request_wakeup_latency, "NtRequestWakeupLatency", 209),
    (nt_reset_event, "NtResetEvent", 210),
    (nt_reset_write_watch, "NtResetWriteWatch", 211),
    (nt_restore_key, "NtRestoreKey", 212),
    (nt_resume_thread, "NtResumeThread", 214),
    (nt_save_key, "NtSaveKey", 215),
    (nt_set_context_thread, "NtSetContextThread", 221),
    (nt_set_default_hard_error_port, "NtSetDefaultHardErrorPort", 223),
    (nt_set_default_locale, "NtSetDefaultLocale", 224),
    (nt_set_event, "NtSetEvent", 228),
    (nt_set_information_debug_object, "NtSetInformationDebugObject", 232),
    (nt_set_information_file, "NtSetInformationFile", 233),
    (nt_set_information_job_object, "NtSetInformationJobObject", 234),
    (nt_set_information_object, "NtSetInformationObject", 236),
    (nt_set_information_process, "NtSetInformationProcess", 237),
    (nt_set_information_thread, "NtSetInformationThread", 238),
    (nt_set_information_token, "NtSetInformationToken", 239),
    (nt_set_io_completion, "NtSetIoCompletion", 241),
    (nt_set_security_object, "NtSetSecurityObject", 246),
    (nt_set_system_environment_value_ex, "NtSetSystemEnvironmentValueEx", 248),
    (nt_set_system_information, "NtSetSystemInformation", 249),
    (nt_set_system_time, "NtSetSystemTime", 251),
    (nt_set_thread_execution_state, "NtSetThreadExecutionState", 252),
    (nt_set_timer, "NtSetTimer", 253),
    (nt_set_value_key, "NtSetValueKey", 256),
    (nt_set_volume_information_file, "NtSetVolumeInformationFile", 257),
    (nt_shutdown_system, "NtShutdownSystem", 258),
    (nt_signal_and_wait_for_single_object, "NtSignalAndWaitForSingleObject", 259),
    (nt_suspend_thread, "NtSuspendThread", 263),
    (nt_terminate_job_object, "NtTerminateJobObject", 265),
    (nt_terminate_process, "NtTerminateProcess", 266),
    (nt_terminate_thread, "NtTerminateThread", 267),
    (nt_unload_driver, "NtUnloadDriver", 271),
    (nt_unload_key, "NtUnloadKey", 272),
    (nt_unlock_file, "NtUnlockFile", 275),
    (nt_unlock_virtual_memory, "NtUnlockVirtualMemory", 276),
    (nt_unmap_view_of_section, "NtUnmapViewOfSection", 277),
    (nt_wait_for_keyed_event, "NtWaitForKeyedEvent", 292),
    (nt_wait_for_multiple_objects, "NtWaitForMultipleObjects", 280),
    (nt_wait_for_single_object, "NtWaitForSingleObject", 281),
    (nt_write_file, "NtWriteFile", 284),
    (nt_write_file_gather, "NtWriteFileGather", 285),
    (nt_write_virtual_memory, "NtWriteVirtualMemory", 287),
    (nt_yield_execution, "NtYieldExecution", 288),
    (nt_create_keyed_event, "NtCreateKeyedEvent", 289),
}

/// Look up a generated trap stub's metadata by export name, filling in its arity from the shared
/// ABI table (the const table above carries `argc: 0`; the real arity is resolved here to keep a
/// single source of truth for arities).
pub fn trap_stub(name: &str) -> Option<TrapStubMeta> {
    TRAP_STUBS.iter().find(|s| s.name == name).map(|s| TrapStubMeta {
        name: s.name,
        ssn: s.ssn,
        argc: argc_of(s.name),
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use nt_syscall_abi::{ssn_of, NT_SYSCALLS};
    use std::collections::BTreeSet;

    #[test]
    fn generates_all_188_required_stubs() {
        assert_eq!(TRAP_STUBS.len(), 188);
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
}
