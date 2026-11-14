//! The win32k route of the syscall arm (issue #382, loop hoist).
//!
//! A service number in the win32k range: argument staging, the dispatch into the hosted
//! win32k component, and the copy-back of its results.
//!
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::*;

#[inline(never)]
pub(super) unsafe fn syscall_win32k_route(
    lp: &mut LoopState<'_>,
    ev: &Event,
    call: &Syscall,
    sc: &mut SyscallOutcome,
) -> ControlFlow<Turn> {
    let mut nt_handler = &mut *lp.handler;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let dll_pe_store = &mut *lp.images.dll_pe_store;
    let reg = &mut *lp.images.reg;
    let Event { pi, scratch_base, pml4, .. } = *ev;
    let Syscall { current_tid, .. } = *call;
    let process_role = nt_handler.hosted_process_role(pi);
    let winlogon_gui_client =
        process_role == Some(nt_exe_image::HostedProcessRole::InteractiveLogon);
    let userinit_gui_client = process_role
        == Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap);
    let explorer_gui_client =
        process_role == Some(nt_exe_image::HostedProcessRole::InteractiveShell);
    let observed_explorer_gui_client = nt_handler.hosted_process_observation_role(pi)
        == Some(nt_exe_image::HostedProcessRole::InteractiveShell);
    let shell_gui_client = matches!(
        process_role,
        Some(
            nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
                | nt_exe_image::HostedProcessRole::InteractiveShell
        )
    );
    let registered_gui_client = registered_gui_dispatch_client(&nt_handler, pi, lp.msg.badge, current_tid);
    let uses_client_gdi = registered_gui_client;
    let svc_noninteractive =
        process_role.is_some_and(|role| role.is_noninteractive_service_class());
    let dialog_modal_expected_ssn = if winlogon_gui_client {
        winlogon_dialog_modal_expected_ssn()
    } else {
        0
    };
    let modal_message_buffer = get_recv_mr(9);
    let dialog_modal_dispatch = dialog_modal_expected_ssn != 0
        && dialog_modal_expected_ssn == lp.msg.m0
        && if WINLOGON_DIALOG_MODAL_COMPLETED.load(Ordering::Relaxed) != 0 {
            winlogon_dialog_modal_thread_is_owner(lp.msg.badge, current_tid)
        } else {
            winlogon_dialog_modal_thread_matches(
                lp.msg.badge,
                current_tid,
                modal_message_buffer,
            )
        };
    let explorer_direct_gdi_draw = observed_explorer_gui_client
        && matches!(
            lp.msg.m0,
            NTGDI_BIT_BLT_SSN
                | NTGDI_STRETCH_BLT_SSN
                | NTGDI_LINE_TO_SSN
                | NTGDI_PAT_BLT_SSN
                | NTGDI_POLY_PAT_BLT_SSN
                | NTGDI_ALPHA_BLEND_SSN
                | NTGDI_STRETCH_DIBITS_INTERNAL_SSN
                | NTUSER_FILL_WINDOW_SSN
                | NTGDI_RECTANGLE_SSN
                | nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN
        );
    if dialog_modal_dispatch {
        print_str(b"[dialog-pump] routing real modal SSN=");
        print_hex(lp.msg.m0 as u32);
        print_str(b"\n");
        if WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
            > WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
        {
            WINLOGON_LOGGED_OUT_SAS_RAN.store(1, Ordering::Relaxed);
        }
    }
    let sas_hwnd = if winlogon_gui_client {
        core::ptr::read_volatile(
            (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND)
                as *const u64,
        )
    } else {
        0
    };
    if winlogon_gui_client {
        observe_winlogon_sas_logon_state();
    }
    if winlogon_gui_client
        && lp.msg.m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
        && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0
        && !winlogon_dialog_modal_target_alive()
        && winlogon_dialog_modal_thread_is_owner(lp.msg.badge, current_tid)
    {
        // A destroyed IDD_LOGON is only an ERROR while nobody has typed into it. Once
        // the credential keystrokes went in, `EndDialog` destroying it is the dialog
        // reaching its DECISION — the intended outcome, not a fault.
        if !winlogon_credential_started() {
            print_str(
                b"[dialog-pump] ERROR target destroyed before credential input\n",
            );
            WINLOGON_DIALOG_MODAL_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        print_str(b"[dialog-pump] correlated IDD_LOGON was destroyed; parking modal GetMessage\n");
        sc.handled = false;
        sc.wl_milestone_park = true;
    } else if winlogon_gui_client
        && lp.msg.m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
        && WINLOGON_DIALOG_MODAL_DRAINED.load(Ordering::Relaxed) != 0
        && winlogon_dialog_modal_thread_is_owner(lp.msg.badge, current_tid)
    {
        // ★ HEADLESS CREDENTIAL INPUT. The dialog is painted and its pump is about to
        // block for a keystroke nobody can type. Post real WM_CHARs / VK_RETURN into
        // its real edit control through the REAL NtUserPostMessage (exactly the shim
        // that stands in for Ctrl-Alt-Del), then let this GetMessage run — the queue is
        // non-empty, so it returns instead of blocking win32k. When there is nothing
        // left to type the blocking GetMessage is parked as before.
        let Some(peb_mirror) = hosted_peb_mirror_for_pi(pi) else {
            return ControlFlow::Break(lp.reject_hosted_ingress())
        };
        let client_teb = nt_handler
            .pm
            .thread_teb(current_tid as nt_process::ThreadId)
            .filter(|teb| *teb != 0)
            .unwrap_or(SMSS_TEB_VA);
        let route =
            winlogon_credential_injection_route(win32k_client_context_for_thread(
                &nt_handler,
                pi,
                lp.msg.badge,
                current_tid,
                hosted_thread_tcb_or_zero(&nt_handler, current_tid),
                nt_handler.hosted_thread_role(current_tid),
                client_teb,
                peb_mirror,
                scratch_base,
            ));
        if !route {
            print_str(b"[dialog-pump] real IDD_LOGON queue drained; parking its blocking GetMessage\n");
            sc.handled = false;
            sc.wl_milestone_park = true;
        }
    } else if winlogon_gui_client
        && lp.msg.m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
        && sas_hwnd != 0
        && lp.msg.m3 == sas_hwnd
        && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0
        && WINLOGON_MSGLOOP_MILESTONE.load(Ordering::Relaxed) == 0
    {
        WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
        print_str(b"[wl-main] winlogon entered its SAS message loop; routing real GetMessage for posted WLX_WM_SAS\n");
    }
    // Tell win32k_dispatch WHICH client this call belongs to (csrss pi 1 / winlogon pi 2 /
    // services pi 3 / lsass pi 4) so it attaches win32k's client window to this client's frames
    // (per-client cross-AS client memory — services' OBJECT_ATTRIBUTES / USERCONNECT
    // resolve to SERVICES' frames, not the stale csrss/winlogon frame at the same VA).
    // The w32_client_attach / csrss_frame_get / map_win32k_user_heap_into_client machinery is
    // fully pi-keyed (bit `1<<pi`), so a 3rd GUI client needs no new state — same recipe
    // that made winlogon the 2nd client. The reply is caller-agnostic: REPLY_MAIN is
    // bound to THIS caller at its recv, so it resumes exactly services (no reply-spin).
    W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    // Count every win32k dispatch for census/gate evidence. This is deliberately not a
    // liveness policy: real GUI clients can make thousands of win32k calls while still
    // loading code, faulting pages, running user callbacks, and painting. True stalls are
    // handled by the wall-clock progress watchdog at the loop top.
    {
        bump_w32_total_dispatch(pi);
        // FORWARD-PROGRESS CENSUS: the win32k SHADOW table lands in the same per-process
        // histogram as the native table (high half). Without this the census could see
        // only the native syscalls, and every "the UI work grew" claim about a win32k
        // frontier was unmeasured by construction.
        {
            let bucket = ssn_bucket(lp.msg.m0);
            match pi {
                4 => LSASS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                3 => SERVICES_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                2 => WINLOGON_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                1 => CSRSS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                6 => EXPLORER_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            if nt_handler.hosted_process_observation_role(pi)
                == Some(nt_exe_image::HostedProcessRole::Win32Subsystem)
            {
                crate::csrss_thread_probe::record_syscall(lp.msg.m0);
            }
            // …and the WALL-CLOCK, which is the whole point: this arm runs a nested
            // pump, so the main loop's badge census cannot see any of the time spent
            // here. It also ticks the periodic dump, so a non-quiescing boot reports.
            w32_census_enter(lp.msg.m0);
        }
    }
    // Phase 2c Milestone C: a win32k NtUser/NtGdi system call (SSN >= 0x1000) issued by
    // csrss (winsrv's UserServerDllInitialization) OR by winlogon (its user32 DllMain's
    // NtUserProcessConnect + WinMain's window-station/desktop calls) — the SECOND hosted
    // GUI client. Forward it to the parked win32k component through the persistent dispatch
    // loop; the handler runs in win32k's OWN context (GS=KPCR / session heap). Both clients
    // are serviced ONE AT A TIME by the main loop (FIFO recv), each bound to REPLY_MAIN at
    // its recv, so the reply (client_reply_on(REPLY_MAIN)) resumes exactly this caller
    // — csrss and winlogon never orphan each other. Scalar + handle args ride the registers
    // exactly as the native x64 syscall passed them (arg1=R10, arg2=RDX, arg3=R8, arg4=R9);
    // pointer/buffer args are marshaled per SSN as needed. Per-process stack/heap
    // mirrors are already selected by `pi` above (smss_stack_read reaches winlogon's stack).
    let a0 = get_recv_mr(9); // R10 = arg1
    let a1 = lp.msg.m3; // RDX = arg2
    let a2 = get_recv_mr(7); // R8 = arg3
    let a3 = get_recv_mr(8); // R9 = arg4
    let sp = get_recv_mr(16); // real syscall-entry RSP for win32k stack args
    if lp.msg.m0 == 0x1002 {
        let n = NTUSER_CALL_ONE_PARAM_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 192 {
            print_str(b"[ntuser-oneparam] #");
            print_u64(n);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" tid=");
            print_u64(current_tid as u64);
            print_str(b" param=0x");
            print_hex_u64(a0);
            print_str(b" routine=0x");
            print_hex(a1 as u32);
            print_str(b" a2=0x");
            print_hex_u64(a2);
            print_str(b" a3=0x");
            print_hex_u64(a3);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b"\n");
        }
    }
    // NtUserInitialize(dwWinVersion=a0, hPowerRequestEvent=a1, hMediaRequestEvent=a2):
    // winsrv created these events via NtCreateEvent into its own image globals. Forward
    // exactly what the caller supplied; no executive-side substitution is permitted.
    if lp.msg.m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE_REAL {
        print_str(b"[ntuser-init] raw power=0x");
        print_hex((a1 >> 32) as u32);
        print_hex(a1 as u32);
        print_str(b" media=0x");
        print_hex((a2 >> 32) as u32);
        print_hex(a2 as u32);
        print_str(b"\n");
    }
    let Some(dispatch_peb_mirror) = hosted_peb_mirror_for_pi(pi) else {
        return ControlFlow::Break(lp.reject_hosted_ingress())
    };
    let dispatch_client_teb = nt_handler
        .pm
        .thread_teb(current_tid as nt_process::ThreadId)
        .filter(|teb| *teb != 0)
        .unwrap_or(SMSS_TEB_VA);
    let dispatch_client = win32k_client_context_for_thread(
        &nt_handler,
        pi,
        lp.msg.badge,
        current_tid,
        hosted_thread_tcb_or_zero(&nt_handler, current_tid),
        nt_handler.hosted_thread_role(current_tid),
        dispatch_client_teb,
        dispatch_peb_mirror,
        scratch_base,
    );
    trace_cursor_lookup_owner(
        "preentry", dispatch_client, lp.msg.m0, 0, None, false, false, false,
    );
    'root_gui_dispatch: {
    let Some(dispatch_id) = win32k_glue::next_win32k_dispatch_id() else {
        // No shared ARG or provider state belongs to this call yet. Preserve its
        // bound Reply and let the ordinary syscall tail return the failure.
        sc.result = nt_process::STATUS_INSUFFICIENT_RESOURCES as u64;
        sc.handled = true;
        sc.wl_milestone_park = false;
        break 'root_gui_dispatch;
    };
    trace_cursor_lookup_owner(
        "dispatch-id", dispatch_client, lp.msg.m0, dispatch_id, None, false, false, false,
    );
    // CROSS-AS ARG MARSHALING. NtUserProcessConnect(handle, USERCONNECT* buf, size): the
    // buffer is a client user pointer (usually its stack) NOT mapped in win32k's VSpace.
    // Passing it raw makes win32k's handler fault/spin on an address win32k_dispatch can't
    // resolve. Copy the caller's input buffer into the shared ARG frame (mapped in BOTH),
    // dispatch with the ARG-frame pointer, then copy win32k's out-params back to the same
    // caller process.
    let has_buf = lp.msg.m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE; // 0x10FA = NtUserProcessConnect
    let current_pid = nt_handler.pm_pid_for_pi(pi);
    let mut d_a0 = if has_buf
        && (a0 == 0xFFFF_FFFF_FFFF_FFFF
            || (current_pid.is_some()
                && nt_handler.resolve_process_handle(a0) == current_pid))
    {
        // The component's Ob layer accepts only this narrow connect handle for the
        // current process. Real handles must be resolved by ProcessManager before they are
        // translated, so arbitrary process-typed values cannot alias to the current EPROCESS.
        win32k_subsystem::FAKE_PROCESS_HANDLE
    } else {
        a0
    };
    let mut userconnect_capture_status = 0u32;
    let (mut d_a1, blen) = if has_buf {
        let arg = win32k_subsystem::WIN32K_ARG_VADDR;
        let n = if a2 <= win32k_subsystem::WIN32K_ARG_GENERAL_BYTES {
            a2
        } else {
            userconnect_capture_status = nt_process::STATUS_INVALID_PARAMETER;
            0
        };
        core::ptr::write_bytes(
            arg as *mut u8,
            0,
            win32k_subsystem::WIN32K_ARG_GENERAL_BYTES as usize,
        );
        let input = core::slice::from_raw_parts_mut(arg as *mut u8, n as usize);
        if userconnect_capture_status == 0
            && !nt_handler.capture_process_identity(pi).is_some_and(|process| {
                img_spawn::client_copyin_process_mapped_for(
                    pi as u64,
                    process,
                    a1,
                    input,
                    scratch_base,
                )
            })
        {
            userconnect_capture_status = nt_address_space::STATUS_ACCESS_VIOLATION;
        }
        if userconnect_capture_status != 0 {
            let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
            if failures < 8 {
                print_str(
                    b"[win32k-svc] NtUserProcessConnect USERCONNECT copy-in failed pi=",
                );
                print_u64(pi as u64);
                print_str(b" buffer=0x");
                print_hex((a1 >> 32) as u32);
                print_hex(a1 as u32);
                print_str(b" bytes=");
                print_u64(a2);
                print_str(b" status=0x");
                print_hex(userconnect_capture_status);
                print_str(b"\n");
            }
        }
        (arg, n)
    } else {
        (a1, 0)
    };
    let msg_syscall = registered_gui_client
        && a0 != 0
        && (lp.msg.m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
            || lp.msg.m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
            || lp.msg.m0 == nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN);
    let msg_returns_to_client = msg_syscall
        && (lp.msg.m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
            || lp.msg.m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN);
    let mut message_output_stage = None;
    let mut message_output_stage_failed = false;
    if msg_syscall {
        let arg = win32k_subsystem::WIN32K_ARG_VADDR;
        if msg_returns_to_client {
            if let Some(stage) = win32k_glue::acquire_win32k_message_stage() {
                core::ptr::write_bytes(
                    stage.provider_pointer as *mut u8,
                    0,
                    stage.capacity as usize,
                );
                d_a0 = stage.provider_pointer;
                message_output_stage = Some(stage);
            } else {
                message_output_stage_failed = true;
            }
        } else {
            let input =
                core::slice::from_raw_parts_mut(arg as *mut u8, WIN32K_MSG_BYTES);
            if nt_handler.capture_process_identity(pi).is_some_and(|process| {
                img_spawn::client_copyin_process_mapped_for(
                    pi as u64,
                    process,
                    a0,
                    input,
                    scratch_base,
                )
            }) {
                d_a0 = arg;
            } else {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] GUI MSG copy-in failed ssn=0x");
                    print_hex(lp.msg.m0 as u32);
                    print_str(b" buffer=0x");
                    print_hex_u64(a0);
                    print_str(b"\n");
                }
            }
        }
    }
    // Serial output is synchronous under TCG. Sample the generic dispatch stream rather
    // than maintaining a list of currently hot SSNs; exact per-client/per-SSN counters
    // remain available in the census, and every provider wall still prints below.
    let w32_log = bounded_trace_sample(&W32_DISPATCH_TRACE, 128);
    if w32_log {
        print_str(b"[win32k-svc] ");
        print_str(win32k_client_label(&nt_handler, pi));
        print_str(b" -> SSN 0x");
        print_hex(lp.msg.m0 as u32);
        print_str(b" (dispatch)\n");
    }
    // ── NT ARGUMENT CAPTURE for `NtUserRegisterClassExWOW` (SSN 0x10b4).
    // a1 = ClassName and a2 = ClsVersion are client `PUNICODE_STRING`s whose descriptor
    // and `Buffer` both belong to the caller's address space. Real NT probes and captures
    // them before win32k consumes them. Do the same at the executive's cross-VSpace boundary:
    // stage a bounded descriptor for atoms/resources too, and stage readable nonzero buffers
    // regardless of whether they live in the main image, a DLL, stack, or heap.
    //
    // The shared ARG frame is mapped in both VSpaces. Required capture failures must
    // stop provider dispatch rather than forwarding a raw foreign user pointer.
    let mut d_a2 = a2;
    let mut d_a3 = a3;
    let register_class_process = (lp.msg.m0 == 0x10b4)
        .then(|| nt_handler.capture_process_identity(pi))
        .flatten();
    let mut register_class_probe_failed = false;
    let mut register_class_strings = None;
    let mut register_class_graph = None;
    let mut register_class_stack_args = [0u64; 3];
    let mut register_class_stack_arg_count = 0usize;
    let mut create_window_stack_args = [0u64; 11];
    let mut create_window_stack_arg_count = 0usize;
    let mut create_window_probe_failed = false;
    let mut open_dcw_stack_args = [0u64; 3];
    let mut open_dcw_stack_arg_count = 0usize;
    let mut open_dcw_dhpdev_copyout = (0u64, 0u64);
    let mut build_hwnd_list_stack_args =
        [0u64; nt_kernel_exec::user_window_list::BUILD_HWND_LIST_STACK_ARGUMENTS];
    let mut build_hwnd_list_stack_arg_count = 0usize;
    let mut build_hwnd_list_call: Option<nt_kernel_exec::user_window_list::BuildHwndListCall> =
        None;
    let mut get_icon_info_stack_args = [0u64; 2];
    let mut get_icon_info_stack_arg_count = 0usize;
    let mut get_icon_info_probe_failed = false;
    let mut get_icon_info_probe_failure = 0u64;
    let mut get_icon_info_probe_aux0 = 0u64;
    let mut get_icon_info_probe_aux1 = 0u64;
    let mut get_icon_info_copyout = CapturedGetIconInfo::empty();
    let mut create_bitmap_stack_args = [0u64; 1];
    let mut create_bitmap_stack_arg_count = 0usize;
    let mut create_bitmap_probe_failed = false;
    let mut create_dib_section_stack_args = [0u64; 5];
    let mut create_dib_section_stack_arg_count = 0usize;
    let mut create_dib_section_probe_failed = false;
    let mut create_dib_section_probe_failure = 0u64;
    let mut create_dib_section_probe_aux0 = 0u64;
    let mut create_dib_section_probe_aux1 = 0u64;
    let mut create_dib_section_probe_aux2 = 0u64;
    let mut create_dib_section_bits_copyout = (0u64, 0u64);
    let mut create_dibitmap_stack_args = [0u64; 7];
    let mut create_dibitmap_stack_arg_count = 0usize;
    let mut create_dibitmap_probe_failed = false;
    let mut create_dibitmap_probe_failure = 0u64;
    let mut create_dibitmap_probe_aux0 = 0u64;
    let mut create_dibitmap_probe_aux1 = 0u64;
    let mut create_dibitmap_probe_aux2 = 0u64;
    let mut bulk_stage = None;
    let mut stretch_dibits_stack_args = [0u64; 12];
    let mut stretch_dibits_stack_arg_count = 0usize;
    let mut stretch_dibits_probe_failed = false;
    let mut stretch_dibits_probe_failure = 0u64;
    let mut stretch_dibits_probe_aux0 = 0u64;
    let mut stretch_dibits_probe_aux1 = 0u64;
    let mut stretch_dibits_probe_aux2 = 0u64;
    let mut ext_text_out_stack_args = [0u64; 5];
    let mut ext_text_out_stack_arg_count = 0usize;
    let mut ext_text_out_probe_failed = false;
    let mut paint_output_stage = None;
    let mut paint_output_claim = None;
    let mut paint_output_stage_failed = false;
    let mut paintstruct_probe_failed = false;
    let mut user_rect_probe_failed = false;
    let mut text_metrics_copyout = (0u64, 0u64, 0usize);
    let mut text_metrics_probe_failed = false;
    let mut get_text_extent_stack_args = [0u64; 1];
    let mut get_text_extent_stack_arg_count = 0usize;
    let mut get_text_extent_copyout = (0u64, 0u64);
    let mut get_text_extent_probe_failed = false;
    let mut text_extent_stack_args = [0u64; 4];
    let mut text_extent_stack_arg_count = 0usize;
    let mut text_extent_copyout = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0usize);
    let mut text_extent_probe_failed = false;
    let mut char_width_stack_args = [0u64; 2];
    let mut char_width_stack_arg_count = 0usize;
    let mut char_width_copyout = (0u64, 0u64, 0usize);
    let mut char_width_probe_failed = false;
    let mut load_keyboard_layout_stack_args = [0u64; 3];
    let mut load_keyboard_layout_stack_arg_count = 0usize;
    let mut load_keyboard_layout_probe_failed = false;
    let mut message_call_stack_args = [0u64; 3];
    let mut message_call_stack_arg_count = 0usize;
    let mut message_call_copyout = (0u64, 0u64, 0usize);
    let mut message_call_probe_failed = false;
    let mut set_window_pos_stack_args = [0u64; 3];
    let mut set_window_pos_stack_arg_count = 0usize;
    let mut set_window_pos_probe_failed = false;
    let mut defer_window_pos_stack_args = [0u64; 4];
    let mut defer_window_pos_stack_arg_count = 0usize;
    let mut defer_window_pos_probe_failed = false;
    let mut get_atom_name_probe_failed = false;
    let mut get_class_info_probe_failed = false;
    let mut def_set_text_probe_failed = false;
    let mut wallpaper_spi_probe_failed = false;
    let mut find_cursor_icon_probe_failed = false;
    let mut register_window_message_probe_failed = false;
    let mut set_cursor_icon_data_probe_failed = false;
    if lp.msg.m0 == 0x103d {
        // NtUserFindExistingCursorIcon probes two client UNICODE_STRING descriptors and
        // a FINDEXISTINGCURICONPARAM. The resource string can be MAKEINTRESOURCE, in
        // which case Length is zero and Buffer is the integer identity; preserve that
        // descriptor shape while rebasing only real counted-string buffers.
        match stage_cursor_lookup_args(
            pi as u64,
            d_a0,
            d_a1,
            d_a2,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        ) {
            Some((module, resource, params)) => {
                d_a0 = module;
                d_a1 = resource;
                d_a2 = params;
                let n = FIND_CURSOR_ICON_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 24 {
                    print_str(b"[w32marshal] NtUserFindExistingCursorIcon pi=");
                    print_u64(pi as u64);
                    print_str(b" module=0x");
                    print_hex_u64(a0);
                    print_str(b" resource=0x");
                    print_hex_u64(a1);
                    print_str(b" params=0x");
                    print_hex_u64(a2);
                    print_str(b" staged=0x");
                    print_hex_u64(module);
                    print_str(b"/0x");
                    print_hex_u64(resource);
                    print_str(b"/0x");
                    print_hex_u64(params);
                    print_str(b"\n");
                }
            }
            None => {
                find_cursor_icon_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == 0x10b4 {
        let captured = register_class_process.and_then(|process| {
            let name = try_capture_client_string_arg_for(
                pi as u64, process, d_a1, false, false,
                filled_pages, lp.exit.faults as usize, scratch_base,
            )?;
            let version = try_capture_client_string_arg_for(
                pi as u64, process, d_a2, false, false,
                filled_pages, lp.exit.faults as usize, scratch_base,
            )?;
            let addresses = nt_kernel_exec::user_class::register_class_tail_addresses(sp)?;
            let tail = addresses.map(|va| {
                client_read_u64_for(
                    pi as u64, process, va, scratch_base,
                )
            });
            Some((name, version, [tail[0]?, tail[1]?, tail[2]?]))
        });
        if let Some((name, version, tail)) = captured {
            d_a1 = name.desc;
            d_a2 = version.desc;
            register_class_strings = Some((name, version));
            register_class_stack_args = tail;
            register_class_stack_arg_count = tail.len();
        } else {
            register_class_probe_failed = true;
        }
    } else if lp.msg.m0 == 0x1036 {
        // NtUserRegisterWindowMessage takes one client PUNICODE_STRING. ReactOS probes and
        // captures it before adding the atom; isolated win32k needs the same cross-VSpace
        // capture or shell message registration can fault on a foreign user pointer while
        // inside an explorer callback.
        let capture = nt_handler.capture_process_identity(pi).and_then(|process| {
            try_capture_client_string_arg_for(
                pi as u64,
                process,
                d_a0,
                false,
                false,
                filled_pages,
                lp.exit.faults as usize,
                scratch_base,
            )
        });
        if let Some(capture) = capture {
            d_a0 = capture.desc;
            if explorer_gui_client {
                if EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES
                    .fetch_add(1, Ordering::Relaxed)
                    == 0
                {
                    note_boot_progress(
                        BootProgress::ExplorerMessageRegistrationObserved,
                    );
                }
            }
        } else {
            register_window_message_probe_failed = true;
        }
    } else if lp.msg.m0 == nt_kernel_exec::user_window_list::BUILD_HWND_LIST_SSN {
        // NtUserBuildHwndList writes both the needed count and the HWND array through
        // caller-owned user pointers. Isolated win32k cannot safely probe those VAs
        // directly, so stage the outputs in the shared ARG page and copy the real
        // win32k result back after dispatch. The pinned service takes eight arguments;
        // the four register arguments are forwarded as the caller passed them.
        let tail = nt_kernel_exec::user_window_list::build_hwnd_list_tail_addresses(sp)
            .and_then(|addresses| {
                let tail = addresses.map(|va| {
                    client_read_u64_mapped(pi as u64, va, scratch_base)
                });
                Some([tail[0]?, tail[1]?, tail[2]?, tail[3]?])
            });
        if let Some(tail) = tail {
            let call = nt_kernel_exec::user_window_list::BuildHwndListCall::capture(
                [a0, a1, a2, a3],
                tail,
            );
            if call.needed != 0 {
                let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                let staged_list = arg;
                let staged_needed = arg + WIN32K_BUILD_HWND_LIST_COUNT_OFFSET;
                core::ptr::write_bytes(
                    staged_list as *mut u8,
                    0,
                    WIN32K_BUILD_HWND_LIST_STAGE_BYTES,
                );
                build_hwnd_list_stack_args = call.staged_tail(
                    staged_list,
                    staged_needed,
                    WIN32K_BUILD_HWND_LIST_MAX_HANDLES,
                );
                build_hwnd_list_stack_arg_count = build_hwnd_list_stack_args.len();
                build_hwnd_list_call = Some(call);

                let n = BUILD_HWND_LIST_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 8 {
                    print_str(b"[w32marshal] NtUserBuildHwndList pi=");
                    print_u64(pi as u64);
                    print_str(b" children=");
                    print_u64(call.children as u64);
                    print_str(b" non-immersive=");
                    print_u64(call.non_immersive as u64);
                    print_str(b" tid=");
                    print_u64(call.thread_id as u64);
                    print_str(b" c=");
                    print_u64(call.capacity as u64);
                    print_str(b" forwarded=");
                    print_u64(build_hwnd_list_stack_args[1]);
                    print_str(b" list=0x");
                    print_hex_u64(call.list);
                    print_str(b" needed=0x");
                    print_hex_u64(call.needed);
                    print_str(b"\n");
                }
            }
        }
    } else if lp.msg.m0 == 0x104e {
        // NtUserGetIconInfo has three optional caller-owned outputs: ICONINFO, two
        // UNICODE_STRING descriptors/buffers, and a DWORD bpp pointer in the stack tail.
        // The ReactOS user32 LR_COPYFROMRESOURCE path first asks only for string sizes
        // with partially initialized descriptors, then calls again with heap buffers.
        // Stage those output graphs before isolated win32k probes them.
        if sp == 0 {
            get_icon_info_probe_failed = true;
            get_icon_info_probe_failure = GET_ICON_INFO_FAIL_MISSING_SP;
        } else {
            let pbpp = client_read_u64_mapped(
                pi as u64,
                sp + 0x28,
                scratch_base,
            );
            let b_internal = client_read_u64_mapped(
                pi as u64,
                sp + 0x30,
                scratch_base,
            );
            if let (Some(pbpp), Some(b_internal)) = (pbpp, b_internal) {
                let fixed_slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed)
                    % RC_ARG_CAPTURE_SLOTS;
                let fixed_base = rc_arg_slot_base(fixed_slot);
                core::ptr::write_bytes(
                    fixed_base as *mut u8,
                    0,
                    RC_ARG_CAPTURE_SLOT as usize,
                );

                if d_a1 != 0 {
                    d_a1 = fixed_base;
                    get_icon_info_copyout.iconinfo_client = a1;
                    get_icon_info_copyout.iconinfo_out = fixed_base;
                    if pbpp != 0 {
                        get_icon_info_copyout.bpp_client = pbpp;
                        get_icon_info_copyout.bpp_out =
                            fixed_base + GET_ICON_INFO_BPP_OFF;
                    }
                }
                if d_a2 != 0 {
                    match stage_unicode_string_output_for_win32k(
                        pi as u64,
                        d_a2,
                        scratch_base,
                    ) {
                        Some(capture) => {
                            d_a2 = capture.desc_out;
                            get_icon_info_copyout.module = Some(capture);
                        }
                        None => {
                            get_icon_info_probe_failed = true;
                            get_icon_info_probe_failure = GET_ICON_INFO_FAIL_DESC_COPY;
                            get_icon_info_probe_aux0 = a2;
                            get_icon_info_probe_aux1 = 1;
                        }
                    }
                }
                if !get_icon_info_probe_failed && d_a3 != 0 {
                    match stage_unicode_string_output_for_win32k(
                        pi as u64,
                        d_a3,
                        scratch_base,
                    ) {
                        Some(capture) => {
                            d_a3 = capture.desc_out;
                            get_icon_info_copyout.resource = Some(capture);
                        }
                        None => {
                            get_icon_info_probe_failed = true;
                            get_icon_info_probe_failure = GET_ICON_INFO_FAIL_DESC_COPY;
                            get_icon_info_probe_aux0 = a3;
                            get_icon_info_probe_aux1 = 2;
                        }
                    }
                }

                if !get_icon_info_probe_failed {
                    get_icon_info_stack_args = [
                        if d_a1 != 0 && pbpp != 0 {
                            fixed_base + GET_ICON_INFO_BPP_OFF
                        } else {
                            0
                        },
                        b_internal as u32 as u64,
                    ];
                    get_icon_info_stack_arg_count = get_icon_info_stack_args.len();
                    let n = GET_ICON_INFO_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                    if n < 24 {
                        print_str(b"[w32marshal] NtUserGetIconInfo pi=");
                        print_u64(pi as u64);
                        print_str(b" icon=0x");
                        print_hex_u64(a0);
                        print_str(b" info=0x");
                        print_hex_u64(a1);
                        print_str(b" module=0x");
                        print_hex_u64(a2);
                        print_str(b" resource=0x");
                        print_hex_u64(a3);
                        print_str(b" bpp=0x");
                        print_hex_u64(pbpp);
                        print_str(b" staged=0x");
                        print_hex_u64(d_a1);
                        print_str(b"/0x");
                        print_hex_u64(d_a2);
                        print_str(b"/0x");
                        print_hex_u64(d_a3);
                        print_str(b"\n");
                    }
                }
            } else {
                get_icon_info_probe_failed = true;
                get_icon_info_probe_failure = GET_ICON_INFO_FAIL_STACK_TAIL;
            }
        }
    } else if lp.msg.m0 == 0x106c && sp != 0 && uses_client_gdi {
        // NtGdiCreateBitmap's fifth argument is an optional client pointer to
        // initialized bitmap bits. ReactOS probes and copies that range before
        // UnsafeSetBitmapBits; isolated win32k must receive a pointer in its own address
        // space, not a raw hosted-client VA that may later collapse inside EngCopyBits.
        let bits = client_read_u64_mapped(
            pi as u64,
            sp + 0x28,
            scratch_base,
        );
        if let Some(bits) = bits {
            create_bitmap_stack_args = [0];
            create_bitmap_stack_arg_count = create_bitmap_stack_args.len();
            let size = ntgdi_create_bitmap_bits_size(a0, a1, a2, a3);
            if bits != 0 {
                if let Some(bytes) = size {
                    if bytes <= WIN32K_CREATE_BITMAP_STAGE_BYTES {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            bits,
                            bytes,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                        core::ptr::write_bytes(
                            arg as *mut u8,
                            0,
                            WIN32K_CREATE_BITMAP_STAGE_BYTES,
                        );
                        let input =
                            core::slice::from_raw_parts_mut(arg as *mut u8, bytes);
                        if img_spawn::client_copyin_mapped(
                            pi as u64,
                            bits,
                            input,
                            scratch_base,
                        ) {
                            create_bitmap_stack_args = [arg];
                            let n = CREATE_BITMAP_MARSHAL_TRACE
                                .fetch_add(1, Ordering::Relaxed);
                            if n < 24 {
                                print_str(b"[w32marshal] NtGdiCreateBitmap pi=");
                                print_u64(pi as u64);
                                print_str(b" ");
                                print_u64(a0 as u32 as u64);
                                print_str(b"x");
                                print_u64(a1 as u32 as u64);
                                print_str(b" planes=");
                                print_u64(a2 as u32 as u64);
                                print_str(b" bpp=");
                                print_u64(a3 as u32 as u64);
                                print_str(b" bits=0x");
                                print_hex_u64(bits);
                                print_str(b" bytes=");
                                print_u64(bytes as u64);
                                print_str(b"\n");
                            }
                        } else {
                            create_bitmap_probe_failed = true;
                        }
                    } else {
                        create_bitmap_probe_failed = true;
                    }
                }
            } else {
                let n = CREATE_BITMAP_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 24 {
                    print_str(b"[w32marshal] NtGdiCreateBitmap explicit-null pi=");
                    print_u64(pi as u64);
                    print_str(b" ");
                    print_u64(a0 as u32 as u64);
                    print_str(b"x");
                    print_u64(a1 as u32 as u64);
                    print_str(b" planes=");
                    print_u64(a2 as u32 as u64);
                    print_str(b" bpp=");
                    print_u64(a3 as u32 as u64);
                    print_str(b"\n");
                }
            }
        } else {
            create_bitmap_probe_failed = true;
        }
    } else if lp.msg.m0 == 0x109b && uses_client_gdi {
        // NtGdiCreateDIBSection takes a caller-owned BITMAPINFO in a3 and writes the
        // returned DIB storage pointer through the fifth stack-tail argument. Stage both
        // endpoints so isolated win32k never probes explorer's raw heap/stack VAs.
        if sp == 0 {
            create_dib_section_probe_failed = true;
            create_dib_section_probe_failure = CREATE_DIB_SECTION_FAIL_MISSING_SP;
        } else {
            let mut tail_ok = true;
            let mut i = 0usize;
            while i < create_dib_section_stack_args.len() {
                match client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28 + i as u64 * 8,
                    scratch_base,
                ) {
                    Some(value) => create_dib_section_stack_args[i] = value,
                    None => {
                        tail_ok = false;
                        create_dib_section_probe_failure =
                            CREATE_DIB_SECTION_FAIL_STACK_TAIL;
                        create_dib_section_probe_aux0 = i as u64;
                        break;
                    }
                }
                i += 1;
            }
            if !tail_ok {
                create_dib_section_probe_failed = true;
            } else {
                let i_usage = create_dib_section_stack_args[0] as u32 as u64;
                let cj_header = create_dib_section_stack_args[1] as u32 as u64;
                let fl = create_dib_section_stack_args[2] as u32 as u64;
                let color_space = create_dib_section_stack_args[3];
                let client_bits_out = create_dib_section_stack_args[4];
                let arena_cap = win32k_subsystem::WIN32K_BULK_ARENA_BYTES;
                let mut layout_ok = a3 != 0 && cj_header >= 12 && cj_header <= arena_cap;
                if !layout_ok {
                    create_dib_section_probe_failure = CREATE_DIB_SECTION_FAIL_LAYOUT;
                    create_dib_section_probe_aux0 = a3;
                    create_dib_section_probe_aux1 = cj_header;
                    create_dib_section_probe_aux2 = arena_cap;
                }
                let mut header_capture = alloc::vec::Vec::new();
                let mut staged_bmi_bytes = cj_header;
                if layout_ok {
                    if header_capture.try_reserve_exact(cj_header as usize).is_err() {
                        layout_ok = false;
                        create_dib_section_probe_failure = CREATE_DIB_SECTION_FAIL_LAYOUT;
                        create_dib_section_probe_aux0 = a3;
                        create_dib_section_probe_aux1 = cj_header;
                        create_dib_section_probe_aux2 = arena_cap;
                    } else {
                        header_capture.resize(cj_header as usize, 0);
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            a3,
                            cj_header as usize,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                    }
                    if layout_ok && !img_spawn::client_copyin_mapped(
                        pi as u64, a3, &mut header_capture, scratch_base,
                    ) {
                        layout_ok = false;
                        create_dib_section_probe_failure =
                            CREATE_DIB_SECTION_FAIL_BMI_COPY;
                        create_dib_section_probe_aux0 = a3;
                        create_dib_section_probe_aux1 = cj_header;
                    } else if layout_ok {
                        match nt_kernel_exec::gdi_bitmap::bitmap_info_size(
                            &header_capture,
                            i_usage as u32,
                        ) {
                            Some(bytes)
                                if bytes as u64 >= 12 && bytes as u64 <= arena_cap =>
                            {
                                staged_bmi_bytes = bytes as u64;
                            }
                            _ => {
                                layout_ok = false;
                                create_dib_section_probe_failure =
                                    CREATE_DIB_SECTION_FAIL_BMI_SIZE;
                                create_dib_section_probe_aux0 = a3;
                                create_dib_section_probe_aux1 = cj_header;
                                create_dib_section_probe_aux2 = i_usage;
                            }
                        }
                    }
                }
                // The fixed header capture can be longer than the computed color
                // table span. Keep both the declared header and any extra table bytes.
                let staged_info_extent = staged_bmi_bytes.max(cj_header);
                let bits_offset = align_up_u64(staged_info_extent, 8);
                let total_bytes = bits_offset.and_then(|offset| offset.checked_add(
                    if client_bits_out != 0 { 8 } else { 0 }
                ));
                let stage = if layout_ok {
                    total_bytes
                        .and_then(nt_hosted_runtime::Win32kBulkLayout::flat)
                        .and_then(|layout| win32k_bulk_mapping::reserve(
                            pi as u32,
                            nt_handler.hosted_process_generation(pi).unwrap_or(0),
                            layout,
                        ))
                } else {
                    None
                };
                if layout_ok && stage.is_none() {
                    layout_ok = false;
                    create_dib_section_probe_failure = CREATE_DIB_SECTION_FAIL_LAYOUT;
                    create_dib_section_probe_aux0 = staged_bmi_bytes;
                    create_dib_section_probe_aux1 = if client_bits_out != 0 { 8 } else { 0 };
                    create_dib_section_probe_aux2 = arena_cap;
                }
                let base = stage.map_or(0, |stage| stage.base());
                let staged_bmi = base;
                let staged_bits_out = if layout_ok && client_bits_out != 0 {
                    base + bits_offset.expect("checked DIBSection bits offset")
                } else { 0 };
                bulk_stage = stage;
                if !layout_ok {
                    create_dib_section_probe_failed = true;
                } else {
                    core::ptr::copy_nonoverlapping(
                        header_capture.as_ptr(), staged_bmi as *mut u8, header_capture.len(),
                    );
                    let bmi_copied = if staged_bmi_bytes <= cj_header {
                        true
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            a3,
                            staged_bmi_bytes as usize,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let bmi_out = core::slice::from_raw_parts_mut(
                            staged_bmi as *mut u8,
                            staged_bmi_bytes as usize,
                        );
                        img_spawn::client_copyin_mapped(
                            pi as u64,
                            a3,
                            bmi_out,
                            scratch_base,
                        )
                    };
                    if bmi_copied {
                        d_a2 = a2 as u32 as u64;
                        d_a3 = staged_bmi;
                        create_dib_section_stack_args =
                            [i_usage, cj_header, fl, color_space, staged_bits_out];
                        create_dib_section_stack_arg_count =
                            create_dib_section_stack_args.len();
                        create_dib_section_bits_copyout =
                            (client_bits_out, staged_bits_out);
                        let n = CREATE_DIB_SECTION_MARSHAL_TRACE
                            .fetch_add(1, Ordering::Relaxed);
                        if n < 24 {
                            print_str(b"[w32marshal] NtGdiCreateDIBSection pi=");
                            print_u64(pi as u64);
                            print_str(b" hdc=0x");
                            print_hex_u64(a0);
                            print_str(b" section=0x");
                            print_hex_u64(a1);
                            print_str(b" offset=0x");
                            print_hex(a2 as u32);
                            print_str(b" bmi=0x");
                            print_hex_u64(a3);
                            print_str(b" usage=0x");
                            print_hex(i_usage as u32);
                            print_str(b" header=");
                            print_u64(cj_header);
                            print_str(b" info=");
                            print_u64(staged_bmi_bytes);
                            print_str(b" out=0x");
                            print_hex_u64(client_bits_out);
                            print_str(b" staged=0x");
                            print_hex_u64(staged_bmi);
                            print_str(b"/0x");
                            print_hex_u64(staged_bits_out);
                            print_str(b"\n");
                        }
                    } else {
                        create_dib_section_probe_failed = true;
                        create_dib_section_probe_failure =
                            CREATE_DIB_SECTION_FAIL_BMI_COPY;
                        create_dib_section_probe_aux0 = a3;
                        create_dib_section_probe_aux1 = staged_bmi_bytes;
                    }
                }
            }
        }
    } else if lp.msg.m0 == 0x10a0 && uses_client_gdi {
        // NtGdiCreateDIBitmapInternal receives a DIB bits pointer and BITMAPINFO in the
        // stack tail. ReactOS probes and copies them before GreCreateDIBitmapInternal;
        // isolated win32k must receive provider-owned pointers rather than explorer's
        // client heap addresses.
        if sp == 0 {
            create_dibitmap_probe_failed = true;
            create_dibitmap_probe_failure = CREATE_DIBITMAP_FAIL_MISSING_SP;
        } else {
            let mut tail_ok = true;
            let mut i = 0usize;
            while i < create_dibitmap_stack_args.len() {
                match client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28 + i as u64 * 8,
                    scratch_base,
                ) {
                    Some(value) => create_dibitmap_stack_args[i] = value,
                    None => {
                        tail_ok = false;
                        create_dibitmap_probe_failure = CREATE_DIBITMAP_FAIL_STACK_TAIL;
                        create_dibitmap_probe_aux0 = i as u64;
                        break;
                    }
                }
                i += 1;
            }
            if !tail_ok {
                create_dibitmap_probe_failed = true;
            } else {
                let pj_init = create_dibitmap_stack_args[0];
                let pbmi = create_dibitmap_stack_args[1];
                let i_usage = create_dibitmap_stack_args[2] as u32 as u64;
                let cj_max_info = create_dibitmap_stack_args[3] as u32 as u64;
                let cj_max_bits = create_dibitmap_stack_args[4] as u32 as u64;
                let fl = create_dibitmap_stack_args[5] as u32 as u64;
                let wants_init_bits =
                    pj_init != 0 && ((a3 as u32) & (CBM_INIT as u32)) != 0;
                let input_valid = (pbmi == 0 || cj_max_info >= 12)
                    && (!wants_init_bits || cj_max_bits != 0);
                let stage_needed = pbmi != 0 || wants_init_bits;
                let bits_bytes = if wants_init_bits { cj_max_bits } else { 0 };
                let layout = if pbmi != 0 {
                    nt_hosted_runtime::Win32kBulkLayout::dib(bits_bytes, cj_max_info)
                } else {
                    nt_hosted_runtime::Win32kBulkLayout::flat(bits_bytes)
                };
                let stage = if input_valid && stage_needed {
                    layout.and_then(|layout| win32k_bulk_mapping::reserve(
                        pi as u32,
                        nt_handler.hosted_process_generation(pi).unwrap_or(0),
                        layout,
                    ))
                } else {
                    None
                };
                let base = stage.map_or(0, |stage| stage.base());
                let cap = stage.map_or(0, |stage| stage.capacity());
                bulk_stage = stage;
                let mut offset = 0u64;
                let mut layout_ok = input_valid
                    && (!stage_needed || stage.is_some())
                    && (pbmi == 0 || cj_max_info <= cap)
                    && (!wants_init_bits || cj_max_bits <= cap);
                if !layout_ok {
                    create_dibitmap_probe_failure = if input_valid && stage_needed {
                        CREATE_DIBITMAP_FAIL_STAGE_RESOURCE
                    } else {
                        CREATE_DIBITMAP_FAIL_LAYOUT
                    };
                    create_dibitmap_probe_aux0 = pbmi;
                    create_dibitmap_probe_aux1 = cj_max_info;
                    create_dibitmap_probe_aux2 = cj_max_bits;
                }
                let staged_bits = if layout_ok && wants_init_bits {
                    let out = base + offset;
                    match offset
                        .checked_add(cj_max_bits)
                        .and_then(|next| align_up_u64(next, 8))
                    {
                        Some(next) if next <= cap => offset = next,
                        _ => {
                            layout_ok = false;
                            create_dibitmap_probe_failure =
                                CREATE_DIBITMAP_FAIL_BITS_OVERFLOW;
                            create_dibitmap_probe_aux0 = offset;
                            create_dibitmap_probe_aux1 = cj_max_bits;
                            create_dibitmap_probe_aux2 = cap;
                        }
                    }
                    out
                } else {
                    0
                };
                let staged_pbmi = if layout_ok && pbmi != 0 {
                    let out = base + offset;
                    match offset
                        .checked_add(cj_max_info)
                        .and_then(|next| align_up_u64(next, 8))
                    {
                        Some(next) if next <= cap => offset = next,
                        _ => {
                            layout_ok = false;
                            create_dibitmap_probe_failure =
                                CREATE_DIBITMAP_FAIL_BMI_OVERFLOW;
                            create_dibitmap_probe_aux0 = offset;
                            create_dibitmap_probe_aux1 = cj_max_info;
                            create_dibitmap_probe_aux2 = cap;
                        }
                    }
                    out
                } else {
                    0
                };
                if !layout_ok {
                    create_dibitmap_probe_failed = true;
                } else {
                    let copied_bits = if !wants_init_bits {
                        true
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            pj_init,
                            cj_max_bits as usize,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let bits_out = core::slice::from_raw_parts_mut(
                            staged_bits as *mut u8,
                            cj_max_bits as usize,
                        );
                        img_spawn::client_copyin_mapped(
                            pi as u64,
                            pj_init,
                            bits_out,
                            scratch_base,
                        )
                    };
                    if !copied_bits {
                        create_dibitmap_probe_failed = true;
                        create_dibitmap_probe_failure = CREATE_DIBITMAP_FAIL_BITS_COPY;
                        create_dibitmap_probe_aux0 = pj_init;
                        create_dibitmap_probe_aux1 = cj_max_bits;
                    } else {
                        let copied_bmi = if pbmi == 0 {
                            true
                        } else {
                            prefill_client_copyin_dll_range_pages(
                                pi as u64,
                                pbmi,
                                cj_max_info as usize,
                                scratch_base,
                                &reg,
                                dll_pe_store.as_slice(),
                            );
                            let bmi_out = core::slice::from_raw_parts_mut(
                                staged_pbmi as *mut u8,
                                cj_max_info as usize,
                            );
                            img_spawn::client_copyin_mapped(
                                pi as u64,
                                pbmi,
                                bmi_out,
                                scratch_base,
                            )
                        };
                        if copied_bmi {
                            create_dibitmap_stack_args[0] = staged_bits;
                            create_dibitmap_stack_args[1] = staged_pbmi;
                            create_dibitmap_stack_args[2] = i_usage;
                            create_dibitmap_stack_args[3] = cj_max_info;
                            create_dibitmap_stack_args[4] = cj_max_bits;
                            create_dibitmap_stack_args[5] = fl;
                            create_dibitmap_stack_arg_count =
                                create_dibitmap_stack_args.len();
                            let n = CREATE_DIBITMAP_MARSHAL_TRACE
                                .fetch_add(1, Ordering::Relaxed);
                            if n < 24 {
                                print_str(
                                    b"[w32marshal] NtGdiCreateDIBitmapInternal pi=",
                                );
                                print_u64(pi as u64);
                                print_str(b" hdc=0x");
                                print_hex_u64(a0);
                                print_str(b" ");
                                print_u64(a1 as u32 as u64);
                                print_str(b"x");
                                print_u64(a2 as u32 as u64);
                                print_str(b" init=0x");
                                print_hex(a3 as u32);
                                print_str(b" bits=0x");
                                print_hex_u64(pj_init);
                                print_str(b" bmi=0x");
                                print_hex_u64(pbmi);
                                print_str(b" info=");
                                print_u64(cj_max_info);
                                print_str(b" bits-bytes=");
                                print_u64(cj_max_bits);
                                print_str(b" staged=0x");
                                print_hex_u64(staged_bits);
                                print_str(b"/0x");
                                print_hex_u64(staged_pbmi);
                                print_str(b" bytes=");
                                print_u64(offset);
                                print_str(b"\n");
                            }
                        } else {
                            create_dibitmap_probe_failed = true;
                            create_dibitmap_probe_failure =
                                CREATE_DIBITMAP_FAIL_BMI_COPY;
                            create_dibitmap_probe_aux0 = pbmi;
                            create_dibitmap_probe_aux1 = cj_max_info;
                        }
                    }
                }
            }
        }
    } else if lp.msg.m0 == 0x1082 && uses_client_gdi {
        // NtGdiStretchDIBitsInternal receives the converted BITMAPINFO and optional DIB
        // bits from gdi32's client heap. Stage those buffers in win32k-owned memory before
        // isolated win32k validates pbmi/pjInit, preserving the Windows x64 32-bit scalar
        // argument shape in the stack tail.
        if sp == 0 {
            stretch_dibits_probe_failed = true;
            stretch_dibits_probe_failure = STRETCH_DIBITS_FAIL_MISSING_SP;
        } else {
            let mut tail_ok = true;
            let mut i = 0usize;
            while i < stretch_dibits_stack_args.len() {
                match client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28 + i as u64 * 8,
                    scratch_base,
                ) {
                    Some(value) => stretch_dibits_stack_args[i] = value,
                    None => {
                        tail_ok = false;
                        stretch_dibits_probe_failure = STRETCH_DIBITS_FAIL_STACK_TAIL;
                        stretch_dibits_probe_aux0 = i as u64;
                        break;
                    }
                }
                i += 1;
            }
            if !tail_ok {
                stretch_dibits_probe_failed = true;
            } else {
                let cy_dst = stretch_dibits_stack_args[0] as i32 as i64 as u64;
                let x_src = stretch_dibits_stack_args[1] as i32 as i64 as u64;
                let y_src = stretch_dibits_stack_args[2] as i32 as i64 as u64;
                let cx_src = stretch_dibits_stack_args[3] as i32 as i64 as u64;
                let cy_src = stretch_dibits_stack_args[4] as i32 as i64 as u64;
                let pj_init = stretch_dibits_stack_args[5];
                let pbmi = stretch_dibits_stack_args[6];
                let dw_usage = stretch_dibits_stack_args[7] as u32 as u64;
                let dw_rop = stretch_dibits_stack_args[8] as u32 as u64;
                let cj_max_info = stretch_dibits_stack_args[9] as u32 as u64;
                let cj_max_bits = stretch_dibits_stack_args[10] as u32 as u64;
                let bits_reserved = if pj_init == 0 { 0 } else { cj_max_bits.max(8) };
                let input_valid = pbmi != 0 && cj_max_info >= 12
                    && cj_max_bits <= win32k_subsystem::WIN32K_BULK_ARENA_BYTES;
                let stage = if input_valid {
                    nt_hosted_runtime::Win32kBulkLayout::dib(bits_reserved, cj_max_info)
                        .and_then(|layout| win32k_bulk_mapping::reserve(
                            pi as u32,
                            nt_handler.hosted_process_generation(pi).unwrap_or(0),
                            layout,
                        ))
                } else {
                    None
                };
                let base = stage.map_or(0, |stage| stage.base());
                let cap = stage.map_or(0, |stage| stage.capacity());
                bulk_stage = stage;
                let mut offset = 0u64;
                let mut layout_ok = input_valid && stage.is_some() && cj_max_info <= cap;
                if !layout_ok {
                    stretch_dibits_probe_failure = STRETCH_DIBITS_FAIL_LAYOUT;
                    stretch_dibits_probe_aux0 = pbmi;
                    stretch_dibits_probe_aux1 = cj_max_info;
                    stretch_dibits_probe_aux2 = cj_max_bits;
                }
                let staged_bits = if layout_ok && pj_init != 0 {
                    let out = base + offset;
                    match offset
                        .checked_add(bits_reserved)
                        .and_then(|next| align_up_u64(next, 8))
                    {
                        Some(next) if next <= cap => offset = next,
                        _ => {
                            layout_ok = false;
                            stretch_dibits_probe_failure =
                                STRETCH_DIBITS_FAIL_BITS_OVERFLOW;
                            stretch_dibits_probe_aux0 = offset;
                            stretch_dibits_probe_aux1 = bits_reserved;
                            stretch_dibits_probe_aux2 = cap;
                        }
                    }
                    out
                } else {
                    0
                };
                let staged_pbmi = if layout_ok {
                    let out = base + offset;
                    match offset
                        .checked_add(cj_max_info)
                        .and_then(|next| align_up_u64(next, 8))
                    {
                        Some(next) if next <= cap => offset = next,
                        _ => {
                            layout_ok = false;
                            stretch_dibits_probe_failure =
                                STRETCH_DIBITS_FAIL_BMI_OVERFLOW;
                            stretch_dibits_probe_aux0 = offset;
                            stretch_dibits_probe_aux1 = cj_max_info;
                            stretch_dibits_probe_aux2 = cap;
                        }
                    }
                    out
                } else {
                    0
                };
                if !layout_ok {
                    stretch_dibits_probe_failed = true;
                } else {
                    let copied_bits = if pj_init == 0 || cj_max_bits == 0 {
                        true
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            pj_init,
                            cj_max_bits as usize,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let bits_out = core::slice::from_raw_parts_mut(
                            staged_bits as *mut u8,
                            cj_max_bits as usize,
                        );
                        img_spawn::client_copyin_mapped(
                            pi as u64,
                            pj_init,
                            bits_out,
                            scratch_base,
                        )
                    };
                    if !copied_bits {
                        stretch_dibits_probe_failed = true;
                        stretch_dibits_probe_failure = STRETCH_DIBITS_FAIL_BITS_COPY;
                        stretch_dibits_probe_aux0 = pj_init;
                        stretch_dibits_probe_aux1 = cj_max_bits;
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            pbmi,
                            cj_max_info as usize,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let bmi_out = core::slice::from_raw_parts_mut(
                            staged_pbmi as *mut u8,
                            cj_max_info as usize,
                        );
                        if img_spawn::client_copyin_mapped(
                            pi as u64,
                            pbmi,
                            bmi_out,
                            scratch_base,
                        ) {
                            stretch_dibits_stack_args[0] = cy_dst;
                            stretch_dibits_stack_args[1] = x_src;
                            stretch_dibits_stack_args[2] = y_src;
                            stretch_dibits_stack_args[3] = cx_src;
                            stretch_dibits_stack_args[4] = cy_src;
                            stretch_dibits_stack_args[5] = staged_bits;
                            stretch_dibits_stack_args[6] = staged_pbmi;
                            stretch_dibits_stack_args[7] = dw_usage;
                            stretch_dibits_stack_args[8] = dw_rop;
                            stretch_dibits_stack_args[9] = cj_max_info;
                            stretch_dibits_stack_args[10] = cj_max_bits;
                            stretch_dibits_stack_arg_count =
                                stretch_dibits_stack_args.len();
                            let n = STRETCH_DIBITS_MARSHAL_TRACE
                                .fetch_add(1, Ordering::Relaxed);
                            if n < 24 {
                                print_str(
                                    b"[w32marshal] NtGdiStretchDIBitsInternal pi=",
                                );
                                print_u64(pi as u64);
                                print_str(b" hdc=0x");
                                print_hex_u64(a0);
                                print_str(b" bits=0x");
                                print_hex_u64(pj_init);
                                print_str(b" bmi=0x");
                                print_hex_u64(pbmi);
                                print_str(b" info=");
                                print_u64(cj_max_info);
                                print_str(b" bits-bytes=");
                                print_u64(cj_max_bits);
                                print_str(b" rop=0x");
                                print_hex(dw_rop as u32);
                                print_str(b" staged=0x");
                                print_hex_u64(staged_bits);
                                print_str(b"/0x");
                                print_hex_u64(staged_pbmi);
                                print_str(b" bytes=");
                                print_u64(offset);
                                print_str(b"\n");
                            }
                        } else {
                            stretch_dibits_probe_failed = true;
                            stretch_dibits_probe_failure = STRETCH_DIBITS_FAIL_BMI_COPY;
                            stretch_dibits_probe_aux0 = pbmi;
                            stretch_dibits_probe_aux1 = cj_max_info;
                        }
                    }
                }
            }
        }
    } else if lp.msg.m0 == nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN && uses_client_gdi {
        // NtGdiExtTextOutW probes/copies its caller-owned RECT, WCHAR string, and
        // optional Dx array before GreExtTextOutW consumes them. Do that capture at the
        // cross-VSpace boundary so nested WM_PAINT text draws never hand isolated win32k
        // raw explorer/winlogon heap pointers.
        if sp == 0 {
            ext_text_out_probe_failed = true;
        } else {
            let mut tail = [0u64; 5];
            let mut tail_ok = true;
            let mut i = 0usize;
            while i < tail.len() {
                match client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28 + i as u64 * 8,
                    scratch_base,
                ) {
                    Some(value) => tail[i] = value,
                    None => {
                        tail_ok = false;
                        break;
                    }
                }
                i += 1;
            }
            if !tail_ok {
                ext_text_out_probe_failed = true;
            } else {
                let unsafe_rect = tail[0];
                let unsafe_string = tail[1];
                let count = tail[2] as u32 as u64;
                let unsafe_dx = tail[3];
                let codepage = tail[4] as u32 as u64;
                let fu_options = a3 as u32 as u64;
                let dx_units = if fu_options & ETO_PDY != 0 { 2 } else { 1 };
                let string_bytes = count.checked_mul(2);
                let dx_bytes = if unsafe_dx != 0 && count != 0 {
                    count
                        .checked_mul(4)
                        .and_then(|bytes| bytes.checked_mul(dx_units))
                } else {
                    Some(0)
                };
                if count > 0xffff || (count != 0 && unsafe_string == 0) {
                    ext_text_out_probe_failed = true;
                } else if let (Some(string_bytes), Some(dx_bytes)) =
                    (string_bytes, dx_bytes)
                {
                    let mut offset = 0u64;
                    let mut layout_ok = true;
                    let rect_offset = if unsafe_rect != 0 {
                        let out = offset;
                        match offset.checked_add(16).and_then(|next| align_up_u64(next, 8)) {
                            Some(next) => offset = next,
                            None => layout_ok = false,
                        }
                        out
                    } else {
                        0
                    };
                    let dx_offset = if layout_ok && dx_bytes != 0 {
                        let out = offset;
                        match offset.checked_add(dx_bytes).and_then(|next| align_up_u64(next, 8)) {
                            Some(next) => offset = next,
                            None => layout_ok = false,
                        }
                        out
                    } else {
                        0
                    };
                    let string_offset = if layout_ok && string_bytes != 0 {
                        let out = offset;
                        match offset.checked_add(string_bytes).and_then(|next| align_up_u64(next, 8)) {
                            Some(next) => offset = next,
                            None => layout_ok = false,
                        }
                        out
                    } else {
                        0
                    };
                    let stage = if layout_ok && offset != 0 {
                        nt_hosted_runtime::Win32kBulkLayout::flat(offset)
                            .and_then(|layout| win32k_bulk_mapping::reserve(
                                pi as u32,
                                nt_handler.hosted_process_generation(pi).unwrap_or(0),
                                layout,
                            ))
                    } else {
                        None
                    };
                    let base = stage.map_or(0, |stage| stage.base());
                    bulk_stage = stage;
                    let staged_rect = if unsafe_rect != 0 { base + rect_offset } else { 0 };
                    let staged_dx = if dx_bytes != 0 { base + dx_offset } else { 0 };
                    let staged_string = if string_bytes != 0 { base + string_offset } else { 0 };
                    if !layout_ok || (offset != 0 && stage.is_none()) {
                        ext_text_out_probe_failed = true;
                    } else {
                        let rect_ok = unsafe_rect == 0 || {
                            prefill_client_copyin_dll_range_pages(
                                pi as u64,
                                unsafe_rect,
                                16,
                                scratch_base,
                                &reg,
                                dll_pe_store.as_slice(),
                            );
                            img_spawn::client_copyin_mapped(
                                pi as u64,
                                unsafe_rect,
                                core::slice::from_raw_parts_mut(
                                    staged_rect as *mut u8,
                                    16,
                                ),
                                scratch_base,
                            )
                        };
                        let dx_ok = unsafe_dx == 0 || dx_bytes == 0 || {
                            prefill_client_copyin_dll_range_pages(
                                pi as u64,
                                unsafe_dx,
                                dx_bytes as usize,
                                scratch_base,
                                &reg,
                                dll_pe_store.as_slice(),
                            );
                            img_spawn::client_copyin_mapped(
                                pi as u64,
                                unsafe_dx,
                                core::slice::from_raw_parts_mut(
                                    staged_dx as *mut u8,
                                    dx_bytes as usize,
                                ),
                                scratch_base,
                            )
                        };
                        let string_ok = count == 0 || {
                            prefill_client_copyin_dll_range_pages(
                                pi as u64,
                                unsafe_string,
                                string_bytes as usize,
                                scratch_base,
                                &reg,
                                dll_pe_store.as_slice(),
                            );
                            img_spawn::client_copyin_mapped(
                                pi as u64,
                                unsafe_string,
                                core::slice::from_raw_parts_mut(
                                    staged_string as *mut u8,
                                    string_bytes as usize,
                                ),
                                scratch_base,
                            )
                        };
                        if rect_ok && dx_ok && string_ok {
                            d_a3 = fu_options;
                            ext_text_out_stack_args = [
                                staged_rect,
                                staged_string,
                                count,
                                staged_dx,
                                codepage,
                            ];
                            ext_text_out_stack_arg_count =
                                ext_text_out_stack_args.len();
                            let n = EXT_TEXT_OUT_MARSHAL_TRACE
                                .fetch_add(1, Ordering::Relaxed);
                            if n < 48 {
                                print_str(b"[w32marshal] NtGdiExtTextOutW pi=");
                                print_u64(pi as u64);
                                print_str(b" hdc=0x");
                                print_hex_u64(a0);
                                print_str(b" count=");
                                print_u64(count);
                                print_str(b" options=0x");
                                print_hex(fu_options as u32);
                                print_str(b" rect=0x");
                                print_hex_u64(unsafe_rect);
                                print_str(b" str=0x");
                                print_hex_u64(unsafe_string);
                                print_str(b" dx=0x");
                                print_hex_u64(unsafe_dx);
                                print_str(b" bytes=");
                                print_u64(offset);
                                print_str(b"\n");
                            }
                        } else {
                            ext_text_out_probe_failed = true;
                        }
                    }
                } else {
                    ext_text_out_probe_failed = true;
                }
            }
        }
    } else if matches!(
        lp.msg.m0,
        NTUSER_INVALIDATE_RECT_SSN
            | NTUSER_REDRAW_WINDOW_SSN
            | NTUSER_VALIDATE_RECT_SSN
    ) {
        // These USER paint-region calls take an optional caller-owned RECT input.
        // ReactOS probes/copies it before mutating update regions; in the split
        // kernel that copy belongs at the executive/win32k boundary.
        let rect_ptr = a1;
        let rect_needed = rect_ptr != 0
            && !(matches!(lp.msg.m0, NTUSER_INVALIDATE_RECT_SSN | NTUSER_VALIDATE_RECT_SSN)
                && a0 == 0);
        if rect_needed {
            let arg = win32k_subsystem::WIN32K_ARG_VADDR;
            core::ptr::write_bytes(arg as *mut u8, 0, WIN32K_RECT_STAGE_BYTES);
            prefill_client_copyin_dll_range_pages(
                pi as u64,
                rect_ptr,
                WIN32K_RECT_STAGE_BYTES,
                scratch_base,
                &reg,
                dll_pe_store.as_slice(),
            );
            let input = core::slice::from_raw_parts_mut(
                arg as *mut u8,
                WIN32K_RECT_STAGE_BYTES,
            );
            if nt_handler.capture_process_identity(pi).is_some_and(|process| {
                img_spawn::client_copyin_process_mapped_for(
                    pi as u64,
                    process,
                    rect_ptr,
                    input,
                    scratch_base,
                )
            }) {
                d_a1 = arg;
                let n = USER_RECT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 48 {
                    print_str(b"[w32marshal] USER RECT input pi=");
                    print_u64(pi as u64);
                    print_str(b" ssn=0x");
                    print_hex(lp.msg.m0 as u32);
                    print_str(b" hwnd=0x");
                    print_hex_u64(a0);
                    print_str(b" rect=0x");
                    print_hex_u64(rect_ptr);
                    let left = core::ptr::read_unaligned(arg as *const u32);
                    let top = core::ptr::read_unaligned((arg + 4) as *const u32);
                    let right = core::ptr::read_unaligned((arg + 8) as *const u32);
                    let bottom = core::ptr::read_unaligned((arg + 12) as *const u32);
                    print_str(b" value=(");
                    print_hex(left);
                    print_str(b",");
                    print_hex(top);
                    print_str(b",");
                    print_hex(right);
                    print_str(b",");
                    print_hex(bottom);
                    print_str(b")");
                    print_str(b" staged=0x");
                    print_hex_u64(arg);
                    print_str(b"\n");
                }
            } else {
                user_rect_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == NTUSER_GET_UPDATE_RECT_SSN {
        // NtUserGetUpdateRect writes a RECTL to the caller after
        // co_UserGetUpdateRect, even when the return value is FALSE. Stage the output
        // so win32k writes provider-owned memory, then copy it back after dispatch.
        if d_a1 != 0 {
            if let Some(process) = nt_handler.capture_process_identity(pi) {
                if let Some(stage) = win32k_glue::acquire_win32k_paint_stage() {
                    d_a1 = stage.provider_pointer;
                    paint_output_stage = Some(stage);
                    paint_output_claim = Some(nt_user_callback::PaintOutputClaim {
                        process,
                        client_pointer: a1,
                    });
                } else {
                    paint_output_stage_failed = true;
                }
            } else {
                user_rect_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == NTUSER_BEGIN_PAINT_SSN {
        // NtUserBeginPaint writes a caller-owned PAINTSTRUCT after IntBeginPaint returns.
        // Stage that out-param in the shared win32k argument page so isolated win32k never
        // receives an explorer/winlogon stack VA.
        if d_a1 == 0 {
            paintstruct_probe_failed = true;
        } else if let Some(process) = nt_handler.capture_process_identity(pi) {
            if let Some(stage) = win32k_glue::acquire_win32k_paint_stage() {
                d_a1 = stage.provider_pointer;
                paint_output_stage = Some(stage);
                paint_output_claim = Some(nt_user_callback::PaintOutputClaim {
                    process,
                    client_pointer: a1,
                });
            } else {
                paint_output_stage_failed = true;
            }
        } else {
            paintstruct_probe_failed = true;
        }
    } else if lp.msg.m0 == NTUSER_END_PAINT_SSN {
        // NtUserEndPaint probes and copies the caller's PAINTSTRUCT before IntEndPaint.
        // Capture it into provider-owned memory at the cross-VSpace boundary.
        if d_a1 == 0 {
            paintstruct_probe_failed = true;
        } else {
            let arg = win32k_subsystem::WIN32K_ARG_VADDR;
            core::ptr::write_bytes(arg as *mut u8, 0, WIN32K_PAINTSTRUCT_STAGE_BYTES);
            prefill_client_copyin_dll_range_pages(
                pi as u64,
                d_a1,
                WIN32K_PAINTSTRUCT_STAGE_BYTES,
                scratch_base,
                &reg,
                dll_pe_store.as_slice(),
            );
            let input = core::slice::from_raw_parts_mut(
                arg as *mut u8,
                WIN32K_PAINTSTRUCT_STAGE_BYTES,
            );
            if nt_handler.capture_process_identity(pi).is_some_and(|process| {
                img_spawn::client_copyin_process_mapped_for(
                    pi as u64,
                    process,
                    d_a1,
                    input,
                    scratch_base,
                )
            }) {
                d_a1 = arg;
                let n = PAINTSTRUCT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    print_str(b"[w32marshal] NtUserEndPaint pi=");
                    print_u64(pi as u64);
                    print_str(b" hwnd=0x");
                    print_hex_u64(a0);
                    print_str(b" ps=0x");
                    print_hex_u64(a1);
                    print_str(b" staged=0x");
                    print_hex_u64(arg);
                    print_str(b"\n");
                }
            } else {
                paintstruct_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == 0x125c {
        // NtUserLoadKeyboardLayoutEx has a client PUNICODE_STRING KLID in its stack
        // tail. ReactOS probes/copies it before loading the layout; isolated win32k must
        // see a provider-owned descriptor and tail, not the hosted caller's raw stack.
        let captured = nt_handler.capture_process_identity(pi).and_then(|process| {
            let addresses = nt_kernel_exec::user_string::three_stack_tail_addresses(sp)?;
            let pusz_klid = client_read_u64_for(
                pi as u64, process, addresses[0], scratch_base,
            )?;
            let dw_new_kl = client_read_u64_for(
                pi as u64, process, addresses[1], scratch_base,
            )?;
            let flags = client_read_u64_for(
                pi as u64, process, addresses[2], scratch_base,
            )?;
            let staged_klid = capture_required_client_unicode_string_arg(
                pi as u64, process, pusz_klid, scratch_base,
            )?;
            Some((pusz_klid, staged_klid, dw_new_kl, flags))
        });
        if let Some((pusz_klid, staged_klid, dw_new_kl, flags)) = captured {
            load_keyboard_layout_stack_args = [staged_klid, dw_new_kl, flags];
            load_keyboard_layout_stack_arg_count = load_keyboard_layout_stack_args.len();
            let n = LOAD_KEYBOARD_LAYOUT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                let length = core::ptr::read_unaligned(staged_klid as *const u16) as u64;
                print_str(b"[w32marshal] NtUserLoadKeyboardLayoutEx pi=");
                print_u64(pi as u64);
                print_str(b" klid=0x");
                print_hex_u64(pusz_klid);
                print_str(b" bytes=");
                print_u64(length);
                print_str(b" new=0x");
                print_hex(dw_new_kl as u32);
                print_str(b" flags=0x");
                print_hex(flags as u32);
                print_str(b"\n");
            }
        } else {
            load_keyboard_layout_probe_failed = true;
        }
    } else if lp.msg.m0 == NTUSER_MESSAGE_CALL_SSN && sp != 0 {
        // NtUserMessageCall carries its final three arguments on the client stack:
        // ResultInfo, dwType/FNID, and Ansi. During a real api0 WM_PAINT callback this is
        // usually DefWindowProcW, whose kernel-side IntBeginPaint/IntEndPaint path must
        // clear WNDS_PAINTNOTPROCESSED. Do the NT probe/capture step at the
        // cross-VSpace boundary so isolated win32k sees stable provider-owned tail args.
        let result_info = client_read_u64_mapped(
            pi as u64,
            sp + 0x28,
            scratch_base,
        );
        let dw_type = client_read_u64_mapped(
            pi as u64,
            sp + 0x30,
            scratch_base,
        );
        let ansi = client_read_u64_mapped(
            pi as u64,
            sp + 0x38,
            scratch_base,
        );
        if let (Some(result_info), Some(dw_type), Some(ansi)) =
            (result_info, dw_type, ansi)
        {
            if matches!(dw_type, FNID_DEFWINDOWPROC | FNID_SENDMESSAGE) {
                let staged_result = if result_info == 0 {
                    0
                } else {
                    let base = win32k_subsystem::WIN32K_ARG_VADDR;
                    let mut seed = [0u8; 8];
                    if !img_spawn::client_copyin_mapped(
                        pi as u64,
                        result_info,
                        &mut seed,
                        scratch_base,
                    ) {
                        message_call_probe_failed = true;
                        0
                    } else {
                        core::ptr::copy_nonoverlapping(
                            seed.as_ptr(),
                            base as *mut u8,
                            seed.len(),
                        );
                        base
                    }
                };
                if !message_call_probe_failed {
                    message_call_stack_args = [staged_result, dw_type, ansi];
                    message_call_stack_arg_count = message_call_stack_args.len();
                    message_call_copyout = (
                        result_info,
                        staged_result,
                        if result_info == 0 { 0 } else { 8 },
                    );
                    let n = MESSAGE_CALL_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                    if n < 32 {
                        print_str(b"[w32marshal] NtUserMessageCall pi=");
                        print_u64(pi as u64);
                        print_str(b" hwnd=0x");
                        print_hex_u64(a0);
                        print_str(b" msg=0x");
                        print_hex(a1 as u32);
                        print_str(b" result=0x");
                        print_hex_u64(result_info);
                        print_str(b" fnid=0x");
                        print_hex(dw_type as u32);
                        print_str(b" ansi=");
                        print_u64(ansi as u32 as u64);
                        print_str(b"\n");
                    }
                }
            }
        } else {
            message_call_probe_failed = true;
        }
    } else if lp.msg.m0 == NTUSER_MESSAGE_CALL_SSN {
        message_call_probe_failed = true;
    } else if lp.msg.m0 == NTUSER_SET_WINDOW_POS_SSN {
        // NtUserSetWindowPos' cx/cy/uFlags tail is part of the syscall trap frame.
        // Stage it explicitly so isolated win32k consumes the real geometry rather
        // than probing a hosted user stack from the wrong VSpace.
        let tail = nt_handler.capture_process_identity(pi).and_then(|process| {
            let addresses = nt_kernel_exec::user_string::three_stack_tail_addresses(sp)?;
            nt_kernel_exec::user_string::capture_stack_tail(addresses, |address| {
                client_read_u64_for(
                    pi as u64, process, address, scratch_base,
                )
            })
        });
        if let Some(tail) = tail {
            d_a2 = a2 as i32 as i64 as u64;
            d_a3 = a3 as i32 as i64 as u64;
            set_window_pos_stack_args = [
                tail[0] as i32 as i64 as u64,
                tail[1] as i32 as i64 as u64,
                tail[2] as u32 as u64,
            ];
            set_window_pos_stack_arg_count = set_window_pos_stack_args.len();
            let n = SET_WINDOW_POS_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                print_str(b"[w32marshal] NtUserSetWindowPos pi=");
                print_u64(pi as u64);
                print_str(b" hwnd=0x");
                print_hex_u64(a0);
                print_str(b" after=0x");
                print_hex_u64(a1);
                print_str(b" pos=");
                print_u64(d_a2 as i32 as i64 as u64);
                print_str(b",");
                print_u64(d_a3 as i32 as i64 as u64);
                print_str(b" size=");
                print_u64(set_window_pos_stack_args[0] as i32 as i64 as u64);
                print_str(b"x");
                print_u64(set_window_pos_stack_args[1] as i32 as i64 as u64);
                print_str(b" flags=0x");
                print_hex(set_window_pos_stack_args[2] as u32);
                print_str(b"\n");
            }
        } else {
            set_window_pos_probe_failed = true;
        }
    } else if lp.msg.m0 == NTUSER_DEFER_WINDOW_POS_SSN {
        // NtUserDeferWindowPos' final four scalar arguments are part of the syscall
        // trap frame on NT. Isolated win32k cannot rely on a hosted caller stack being
        // mapped in its VSpace, so capture the tail at the executive boundary and pass a
        // normal staged stack tail through the registered win32k service table arity.
        let tail = nt_handler.capture_process_identity(pi).and_then(|process| {
            let addresses = nt_kernel_exec::user_string::four_stack_tail_addresses(sp)?;
            nt_kernel_exec::user_string::capture_stack_tail(addresses, |address| {
                client_read_u64_for(
                    pi as u64, process, address, scratch_base,
                )
            })
        });
        if let Some(tail) = tail {
            d_a3 = a3 as i32 as i64 as u64;
            defer_window_pos_stack_args = [
                tail[0] as i32 as i64 as u64,
                tail[1] as i32 as i64 as u64,
                tail[2] as i32 as i64 as u64,
                tail[3] as u32 as u64,
            ];
            defer_window_pos_stack_arg_count = defer_window_pos_stack_args.len();
            let n = DEFER_WINDOW_POS_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                print_str(b"[w32marshal] NtUserDeferWindowPos pi=");
                print_u64(pi as u64);
                print_str(b" hdwp=0x");
                print_hex_u64(a0);
                print_str(b" hwnd=0x");
                print_hex_u64(a1);
                print_str(b" after=0x");
                print_hex_u64(a2);
                print_str(b" pos=");
                print_u64(d_a3 as i32 as i64 as u64);
                print_str(b",");
                print_u64(defer_window_pos_stack_args[0] as i32 as i64 as u64);
                print_str(b" size=");
                print_u64(defer_window_pos_stack_args[1] as i32 as i64 as u64);
                print_str(b"x");
                print_u64(defer_window_pos_stack_args[2] as i32 as i64 as u64);
                print_str(b" flags=0x");
                print_hex(defer_window_pos_stack_args[3] as u32);
                print_str(b"\n");
            }
        } else {
            defer_window_pos_probe_failed = true;
        }
    } else if lp.msg.m0 == NTGDI_GET_TEXT_METRICS_W_SSN && uses_client_gdi {
        // NtGdiGetTextMetricsW writes a caller-owned TMW_INTERNAL. Let win32k probe and
        // fill provider-owned memory, then copy the exact caller-requested byte count
        // back across the hosted-process boundary.
        let cj = a2 as u32 as usize;
        if (cj != 0 && d_a1 == 0) || cj > WIN32K_TEXT_METRICS_STAGE_BYTES {
            text_metrics_probe_failed = true;
        } else {
            let staged_tmwi = win32k_subsystem::WIN32K_ARG_VADDR;
            core::ptr::write_bytes(
                staged_tmwi as *mut u8,
                0,
                WIN32K_TEXT_METRICS_STAGE_BYTES,
            );
            d_a1 = staged_tmwi;
            d_a2 = cj as u32 as u64;
            text_metrics_copyout = (a1, staged_tmwi, cj);
            let n = TEXT_METRICS_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 24 {
                print_str(b"[w32marshal] NtGdiGetTextMetricsW pi=");
                print_u64(pi as u64);
                print_str(b" hdc=0x");
                print_hex_u64(a0);
                print_str(b" out=0x");
                print_hex_u64(a1);
                print_str(b" bytes=");
                print_u64(cj as u64);
                print_str(b"\n");
            }
        }
    } else if lp.msg.m0 == NTGDI_GET_TEXT_EXTENT_SSN && uses_client_gdi {
        // NtGdiGetTextExtent(hdc, string, count, size, fl) is the non-Ex facade over
        // NtGdiGetTextExtentExW. Its WCHAR input and SIZE output are caller-owned, and
        // the final fl argument lives in the x64 stack tail.
        if sp == 0 {
            get_text_extent_probe_failed = true;
        } else {
            let fl = client_read_u64_mapped(
                pi as u64,
                sp + 0x28,
                scratch_base,
            );
            if let Some(fl) = fl {
                let count = a2 as u32;
                let count_negative = (count as i32) < 0;
                let string_bytes = (count as usize).checked_mul(2);
                if count_negative || d_a3 == 0 || (count != 0 && d_a1 == 0) {
                    get_text_extent_probe_failed = true;
                } else if let Some(string_bytes) = string_bytes {
                    let base = win32k_subsystem::WIN32K_ARG_VADDR;
                    let staged_string = if count != 0 { base } else { 0 };
                    let mut offset = string_bytes as u64;
                    let mut layout_ok = true;
                    if let Some(next) = align_up_u64(offset, 8) {
                        offset = next;
                    } else {
                        layout_ok = false;
                    }
                    let staged_size = if layout_ok {
                        let out = base + offset;
                        offset += 8;
                        out
                    } else {
                        0
                    };
                    if !layout_ok || offset > WIN32K_TEXT_EXTENT_STAGE_BYTES as u64 {
                        get_text_extent_probe_failed = true;
                    } else {
                        core::ptr::write_bytes(
                            base as *mut u8,
                            0,
                            WIN32K_TEXT_EXTENT_STAGE_BYTES,
                        );
                        let copied_string = if count == 0 {
                            true
                        } else {
                            prefill_client_copyin_dll_range_pages(
                                pi as u64,
                                d_a1,
                                string_bytes,
                                scratch_base,
                                &reg,
                                dll_pe_store.as_slice(),
                            );
                            img_spawn::client_copyin_mapped(
                                pi as u64,
                                d_a1,
                                core::slice::from_raw_parts_mut(
                                    staged_string as *mut u8,
                                    string_bytes,
                                ),
                                scratch_base,
                            )
                        };
                        if copied_string {
                            d_a1 = staged_string;
                            d_a3 = staged_size;
                            get_text_extent_stack_args = [fl as u32 as u64];
                            get_text_extent_stack_arg_count =
                                get_text_extent_stack_args.len();
                            get_text_extent_copyout = (a3, staged_size);
                            let n = TEXT_EXTENT_MARSHAL_TRACE
                                .fetch_add(1, Ordering::Relaxed);
                            if n < 24 {
                                print_str(b"[w32marshal] NtGdiGetTextExtent pi=");
                                print_u64(pi as u64);
                                print_str(b" hdc=0x");
                                print_hex_u64(a0);
                                print_str(b" count=");
                                print_u64(count as u64);
                                print_str(b" str=0x");
                                print_hex_u64(a1);
                                print_str(b" size=0x");
                                print_hex_u64(a3);
                                print_str(b" fl=0x");
                                print_hex(fl as u32);
                                print_str(b" bytes=");
                                print_u64(offset);
                                print_str(b"\n");
                            }
                        } else {
                            get_text_extent_probe_failed = true;
                        }
                    }
                } else {
                    get_text_extent_probe_failed = true;
                }
            } else {
                get_text_extent_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == 0x10cb && uses_client_gdi {
        // NtGdiGetCharWidthW copies an optional caller WCHAR/glyph array and then writes
        // Count INT/FLOAT-sized widths back to the caller. Stage both sides explicitly so
        // nested win32k dispatches do not discover fl/Buffer through a foreign stack.
        let fl = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x28,
                scratch_base,
            )
        } else {
            None
        };
        let client_buffer = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x30,
                scratch_base,
            )
        } else {
            None
        };
        if let (Some(fl), Some(client_buffer)) = (fl, client_buffer) {
            let count = a2 as u32;
            let input_bytes = if d_a3 != 0 {
                (count as usize).checked_mul(2)
            } else {
                Some(0)
            };
            let output_bytes = (count as usize).checked_mul(4);
            if count == 0 || client_buffer == 0 {
                char_width_probe_failed = true;
            } else if let (Some(input_bytes), Some(output_bytes)) =
                (input_bytes, output_bytes)
            {
                let base = win32k_subsystem::WIN32K_ARG_VADDR;
                let cap = WIN32K_CHAR_WIDTH_STAGE_BYTES as u64;
                let staged_pwc = if d_a3 != 0 { base } else { 0 };
                let mut offset = input_bytes as u64;
                let mut layout_ok = true;
                if let Some(next) = align_up_u64(offset, 8) {
                    offset = next;
                } else {
                    layout_ok = false;
                }
                let staged_buffer = if layout_ok {
                    let out = base + offset;
                    offset += output_bytes as u64;
                    out
                } else {
                    0
                };
                if !layout_ok || offset > cap {
                    char_width_probe_failed = true;
                } else {
                    core::ptr::write_bytes(
                        base as *mut u8,
                        0,
                        WIN32K_CHAR_WIDTH_STAGE_BYTES,
                    );
                    let copied_input = if d_a3 == 0 {
                        true
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            d_a3,
                            input_bytes,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let input = core::slice::from_raw_parts_mut(
                            staged_pwc as *mut u8,
                            input_bytes,
                        );
                        img_spawn::client_copyin_mapped(
                            pi as u64,
                            d_a3,
                            input,
                            scratch_base,
                        )
                    };
                    if copied_input {
                        d_a3 = staged_pwc;
                        char_width_stack_args = [fl, staged_buffer];
                        char_width_stack_arg_count = char_width_stack_args.len();
                        char_width_copyout =
                            (client_buffer, staged_buffer, output_bytes);
                        let n =
                            CHAR_WIDTH_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                        if n < 24 {
                            print_str(b"[w32marshal] NtGdiGetCharWidthW pi=");
                            print_u64(pi as u64);
                            print_str(b" first=");
                            print_u64(a1 as u32 as u64);
                            print_str(b" count=");
                            print_u64(count as u64);
                            print_str(b" pwc=0x");
                            print_hex_u64(a3);
                            print_str(b" fl=0x");
                            print_hex(fl as u32);
                            print_str(b" out=0x");
                            print_hex_u64(client_buffer);
                            print_str(b" bytes=");
                            print_u64(offset);
                            print_str(b"\n");
                        }
                    } else {
                        char_width_probe_failed = true;
                    }
                }
            } else {
                char_width_probe_failed = true;
            }
        } else {
            char_width_probe_failed = true;
        }
    } else if lp.msg.m0 == 0x11d9 && uses_client_gdi {
        // NtGdiGetTextExtentExW has one client input buffer and three possible output
        // buffers in its stack tail. Isolated win32k must see only win32k-owned VAs; the
        // executive copies results back to the hosted client after a TRUE service return.
        let fit = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x28,
                scratch_base,
            )
        } else {
            None
        };
        let dx = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x30,
                scratch_base,
            )
        } else {
            None
        };
        let size = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x38,
                scratch_base,
            )
        } else {
            None
        };
        let fl = if sp != 0 {
            client_read_u64_mapped(
                pi as u64,
                sp + 0x40,
                scratch_base,
            )
        } else {
            None
        };
        if let (Some(fit), Some(dx), Some(size), Some(fl)) = (fit, dx, size, fl) {
            let count = a2 as u32;
            let count_negative = (count as i32) < 0;
            let wants_fit = fit != 0 && count != 0;
            let wants_dx = dx != 0 && count != 0;
            let string_bytes = (count as usize).checked_mul(2);
            let dx_bytes = if wants_dx {
                (count as usize).checked_mul(4)
            } else {
                Some(0)
            };
            if count_negative || size == 0 || (count != 0 && d_a1 == 0) {
                text_extent_probe_failed = true;
            } else if let (Some(string_bytes), Some(dx_bytes)) =
                (string_bytes, dx_bytes)
            {
                let base = win32k_subsystem::WIN32K_ARG_VADDR;
                let cap = WIN32K_TEXT_EXTENT_STAGE_BYTES as u64;
                let staged_string = if count != 0 { base } else { 0 };
                let mut offset = string_bytes as u64;
                let mut layout_ok = true;
                if let Some(next) = align_up_u64(offset, 8) {
                    offset = next;
                } else {
                    layout_ok = false;
                }
                let staged_fit = if layout_ok && wants_fit {
                    let out = base + offset;
                    if let Some(next) = align_up_u64(offset + 4, 8) {
                        offset = next;
                    } else {
                        layout_ok = false;
                    }
                    out
                } else {
                    0
                };
                let staged_dx = if layout_ok && wants_dx {
                    let out = base + offset;
                    if let Some(next) = align_up_u64(offset + dx_bytes as u64, 8) {
                        offset = next;
                    } else {
                        layout_ok = false;
                    }
                    out
                } else {
                    0
                };
                let staged_size = if layout_ok {
                    let out = base + offset;
                    offset += 8;
                    out
                } else {
                    0
                };
                if !layout_ok || offset > cap {
                    text_extent_probe_failed = true;
                } else {
                    core::ptr::write_bytes(
                        base as *mut u8,
                        0,
                        WIN32K_TEXT_EXTENT_STAGE_BYTES,
                    );
                    let copied_string = if count == 0 {
                        true
                    } else {
                        prefill_client_copyin_dll_range_pages(
                            pi as u64,
                            d_a1,
                            string_bytes,
                            scratch_base,
                            &reg,
                            dll_pe_store.as_slice(),
                        );
                        let input = core::slice::from_raw_parts_mut(
                            staged_string as *mut u8,
                            string_bytes,
                        );
                        img_spawn::client_copyin_mapped(
                            pi as u64,
                            d_a1,
                            input,
                            scratch_base,
                        )
                    };
                    if copied_string {
                        d_a1 = staged_string;
                        text_extent_stack_args =
                            [staged_fit, staged_dx, staged_size, fl];
                        text_extent_stack_arg_count = text_extent_stack_args.len();
                        text_extent_copyout = (
                            if wants_fit { fit } else { 0 },
                            staged_fit,
                            if wants_dx { dx } else { 0 },
                            staged_dx,
                            size,
                            staged_size,
                            dx_bytes,
                        );
                        let n =
                            TEXT_EXTENT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                        if n < 24 {
                            print_str(b"[w32marshal] NtGdiGetTextExtentExW pi=");
                            print_u64(pi as u64);
                            print_str(b" count=");
                            print_u64(count as u64);
                            print_str(b" str=0x");
                            print_hex_u64(a1);
                            print_str(b" fit=0x");
                            print_hex_u64(fit);
                            print_str(b" dx=0x");
                            print_hex_u64(dx);
                            print_str(b" size=0x");
                            print_hex_u64(size);
                            print_str(b" bytes=");
                            print_u64(offset);
                            print_str(b"\n");
                        }
                    } else {
                        text_extent_probe_failed = true;
                    }
                }
            } else {
                text_extent_probe_failed = true;
            }
        } else {
            text_extent_probe_failed = true;
        }
    } else if lp.msg.m0 == 0x10de && uses_client_gdi {
        // NtGdiOpenDCW probes/copies the caller's optional device name before opening
        // the DC. Capture interactive clients' counted strings at the executive boundary
        // so nested GDI calls from user callbacks do not hand isolated win32k a foreign
        // user VA. Non-interactive services take the light path below.
        d_a0 = capture_client_string_arg(
            pi as u64,
            d_a0,
            false,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        );
        d_a2 = capture_client_string_arg(
            pi as u64,
            d_a2,
            false,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        );
        d_a1 = capture_client_devmodew_arg(
            pi as u64,
            d_a1,
            scratch_base,
        );
        let mut open_dcw_tail_read = false;
        let mut open_dcw_b_display = u64::MAX;
        let mut open_dcw_hspool = u64::MAX;
        let mut open_dcw_dhpdev_out = u64::MAX;
        if sp != 0 {
            let b_display = client_read_u64_mapped(
                pi as u64,
                sp + 0x28,
                scratch_base,
            );
            let hspool = client_read_u64_mapped(
                pi as u64,
                sp + 0x30,
                scratch_base,
            );
            let dhpdev_out = client_read_u64_mapped(
                pi as u64,
                sp + 0x38,
                scratch_base,
            );
            if let (Some(b_display), Some(hspool), Some(dhpdev_out)) =
                (b_display, hspool, dhpdev_out)
            {
                open_dcw_tail_read = true;
                open_dcw_b_display = b_display;
                open_dcw_hspool = hspool;
                open_dcw_dhpdev_out = dhpdev_out;
                if dhpdev_out != 0 {
                    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed)
                        % RC_ARG_CAPTURE_SLOTS;
                    let staged_out = rc_arg_slot_base(slot);
                    core::ptr::write_bytes(
                        staged_out as *mut u8,
                        0,
                        RC_ARG_CAPTURE_SLOT as usize,
                    );
                    open_dcw_stack_args = [b_display, hspool, staged_out];
                    open_dcw_stack_arg_count = open_dcw_stack_args.len();
                    open_dcw_dhpdev_copyout = (dhpdev_out, staged_out);
                }
            }
        }
        let n = OPEN_DCW_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[w32marshal] NtGdiOpenDCW pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" dev=0x");
            print_hex_u64(a0);
            print_str(b"->0x");
            print_hex_u64(d_a0);
            print_str(b" devmode=0x");
            print_hex_u64(a1);
            print_str(b"->0x");
            print_hex_u64(d_a1);
            print_str(b" logaddr=0x");
            print_hex_u64(a2);
            print_str(b"->0x");
            print_hex_u64(d_a2);
            print_str(b" type=");
            print_u64(a3);
            print_str(b" tail-read=");
            print_u64(open_dcw_tail_read as u64);
            print_str(b" display=0x");
            print_hex_u64(open_dcw_b_display);
            print_str(b" hspool=0x");
            print_hex_u64(open_dcw_hspool);
            print_str(b" dhpdev-out=0x");
            print_hex_u64(open_dcw_dhpdev_out);
            print_str(b" staged=");
            print_u64((open_dcw_stack_arg_count == open_dcw_stack_args.len()) as u64);
            print_str(b"\n");
        }
    } else if lp.msg.m0 == 0x1077 {
        if shell_gui_client && pi < 64 {
            INTERACTIVE_SHELL_CREATE_WINDOW_ATTEMPT_MASK
                .fetch_or(1u64 << pi, Ordering::Relaxed);
        }
        // `NtUserCreateWindowEx` takes LARGE_STRING ClassName/ClsVersion/WindowName.
        if sp == 0 {
            create_window_probe_failed = true;
        } else {
            let mut tail_ok = true;
            let mut i = 0usize;
            while i < create_window_stack_args.len() {
                match client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28 + i as u64 * 8,
                    scratch_base,
                ) {
                    Some(value) => create_window_stack_args[i] = value,
                    None => {
                        tail_ok = false;
                        break;
                    }
                }
                i += 1;
            }
            if tail_ok {
                create_window_stack_arg_count = create_window_stack_args.len();
            } else {
                create_window_probe_failed = true;
            }
        }
        // CreateWindowEx class/version/window names are client-owned LARGE_STRING
        // graphs, even for built-in controls whose literals live in user32.dll (for
        // example ComboLBox during the msgina logon dialog). Isolated win32k must see a
        // provider-owned copy or fail visibly on an unreadable graph.
        prefill_client_large_string_pages(
            pi as u64,
            d_a1,
            scratch_base,
            &reg,
            dll_pe_store.as_slice(),
        );
        prefill_client_large_string_pages(
            pi as u64,
            d_a2,
            scratch_base,
            &reg,
            dll_pe_store.as_slice(),
        );
        prefill_client_large_string_pages(
            pi as u64,
            d_a3,
            scratch_base,
            &reg,
            dll_pe_store.as_slice(),
        );
        let original_a1 = d_a1;
        let original_a2 = d_a2;
        let original_a3 = d_a3;
        d_a1 = capture_client_string_arg(
            pi as u64,
            d_a1,
            true,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        );
        d_a2 = capture_client_string_arg(
            pi as u64,
            d_a2,
            true,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        );
        d_a3 = capture_client_string_arg(
            pi as u64,
            d_a3,
            true,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        );
        if explorer_gui_client
            && (d_a1 != original_a1 || d_a2 != original_a2 || d_a3 != original_a3)
        {
            EXPLORER_CREATE_WINDOW_STRING_CAPTURES.fetch_add(1, Ordering::Relaxed);
        }
    } else if lp.msg.m0 == 0x1080 {
        // NtUserDefSetText takes HWND plus a client PLARGE_STRING. It often runs from
        // DefWindowProc while win32k is parked in a user callback; capture the counted
        // string before isolated win32k probes the client's raw pointer graph.
        if d_a1 != 0 {
            let capture = nt_handler.capture_process_identity(pi).and_then(|process| {
                prefill_client_large_string_pages_for(
                    pi as u64, process, d_a1, scratch_base, &reg, dll_pe_store.as_slice(),
                );
                try_capture_client_string_arg_for(
                    pi as u64, process, d_a1, true, true,
                    filled_pages, lp.exit.faults as usize, scratch_base,
                )
            });
            match capture {
                Some(capture) => {
                    d_a1 = capture.desc;
                    let n = DEF_SET_TEXT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                    if n < 16 {
                        print_str(b"[w32marshal] NtUserDefSetText pi=");
                        print_u64(pi as u64);
                        print_str(b" hwnd=0x");
                        print_hex_u64(a0);
                        print_str(b" desc=0x");
                        print_hex_u64(a1);
                        print_str(b" len=");
                        print_u64(capture.length);
                        print_str(b" max=");
                        print_u64(capture.maximum);
                        print_str(b" ansi=");
                        print_u64(capture.ansi as u64);
                        print_str(b" buf=0x");
                        print_hex_u64(capture.buffer);
                        print_str(b" staged=0x");
                        print_hex_u64(capture.staged_buffer);
                        print_str(b"\n");
                    }
                }
                None => {
                    def_set_text_probe_failed = true;
                }
            }
        }
    } else if lp.msg.m0 == 0x1041 && a0 == 0x14 {
        // SystemParametersInfoW(SPI_SETDESKWALLPAPER) passes a user-mode UNICODE_STRING
        // descriptor, and that descriptor's Buffer is another user pointer. Capture the graph
        // at the executive boundary before isolated win32k's SpiSetWallpaper probes it.
        if d_a2 != 0 {
            let captured = nt_handler.capture_process_identity(pi).and_then(|process| {
                try_capture_client_string_arg_for(
                    pi as u64, process, d_a2, false, false,
                    filled_pages, lp.exit.faults as usize, scratch_base,
                )
            });
            if let Some(capture) =
                captured.filter(|capture| capture.length <= RC_WALLPAPER_MAX_BYTES)
            {
                d_a2 = capture.desc;
                if userinit_gui_client {
                    let n = USERINIT_WALLPAPER_SPI_CAPTURES.fetch_add(1, Ordering::Relaxed);
                    if n < 4 {
                        print_str(b"[w32marshal] userinit captured SPI_SETDESKWALLPAPER UNICODE_STRING arg=0x");
                        print_hex((a2 >> 32) as u32);
                        print_hex(a2 as u32);
                        print_str(b" -> 0x");
                        print_hex((capture.desc >> 32) as u32);
                        print_hex(capture.desc as u32);
                        print_str(b"\n");
                    }
                }
            } else {
                wallpaper_spi_probe_failed = true;
            }
        }
    } else if lp.msg.m0 == 0x10a8 {
        // NtUserSetCursorIconData probes/captures a pointer-rich CURSORDATA graph before
        // installing cursor/icon frames. Stage that graph into provider-owned shared memory
        // so animated cursor setup cannot leave win32k with client-private aspcur/aicur
        // pointers that later fault during WM_PAINT icon drawing.
        match stage_cursor_icon_data_args(
            pi as u64,
            nt_handler.hosted_process_generation(pi).unwrap_or(0),
            d_a0,
            d_a1,
            d_a2,
            d_a3,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        ) {
            Some((module, resource, data, stage)) => {
                d_a1 = module;
                d_a2 = resource;
                d_a3 = data;
                bulk_stage = Some(stage);
            }
            None => {
                set_cursor_icon_data_probe_failed = true;
            }
        }
    }
    if lp.msg.m0 == 0x10b4 && !register_class_probe_failed {
        if let Some(graph) = register_class_process.and_then(|process| {
            capture_register_class_graph(
                pi as u64, process, a0, a3,
                filled_pages, lp.exit.faults as usize, scratch_base,
            )
        }) {
            d_a0 = graph.wnd;
            d_a3 = graph.menu;
            register_class_graph = Some(graph);
        } else {
            register_class_probe_failed = true;
        }
    }
    let cursor_identity_key = if lp.msg.m0 == 0x103d {
        capture_find_existing_cursor_key(
            pi as u64,
            a0,
            a1,
            a2,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        )
    } else if lp.msg.m0 == 0x10a8 {
        capture_cursor_set_data_key(
            pi as u64,
            a1,
            a2,
            a3,
            filled_pages,
            lp.exit.faults as usize,
            scratch_base,
        )
    } else {
        None
    };
    let builtin_class_args = if lp.msg.m0 == 0x10b4
        && !register_class_probe_failed
        && register_class_stack_arg_count == register_class_stack_args.len()
    {
        Some((
            register_class_stack_args[0] as u32,
            register_class_stack_args[1] as u32,
        ))
    } else {
        None
    };
    let builtin_class_attempt = builtin_class_args.is_some_and(|(fn_id, flags)| {
        (nt_kernel_exec::user_class::FNID_BUILTIN_FIRST
            ..=nt_kernel_exec::user_class::FNID_BUILTIN_LAST)
            .contains(&fn_id)
            && flags == 0
    });
    let builtin_class_key = builtin_class_args.and_then(|(fn_id, flags)| {
        let graph = register_class_graph?;
        let (name, version) = register_class_strings?;
        capture_builtin_class_key(graph, name, version, fn_id, flags)
    });
    let registered_class_atom_name = if lp.msg.m0 == 0x10b4 && !register_class_probe_failed {
        register_class_strings.and_then(|(name, _)| {
            staged_class_name_identity(
                name.desc, name.desc + 0x20, RC_ARG_BUF_CAP, false,
            ).and_then(|(_, atom_name)| atom_name)
        })
    } else {
        None
    };
    let userinit_gui_client = nt_handler.hosted_process_role(pi)
        == Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap);
    let get_atom_name_capture = if lp.msg.m0 == 0x10ad {
        let capture = nt_handler.capture_process_identity(pi).and_then(|process| {
            capture_get_atom_name_out(
                pi as u64, process, a1, scratch_base,
            )
        });
        if let Some(capture) = capture {
            d_a1 = capture.desc_out;
            let n = GET_ATOM_NAME_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[w32marshal] NtUserGetAtomName pi=");
                print_u64(pi as u64);
                print_str(b" atom=0x");
                print_hex(a0 as u32);
                print_str(b" desc=0x");
                print_hex_u64(a1);
                print_str(b" max=");
                print_u64(capture.maximum as u64);
                print_str(b"\n");
            }
            Some(capture)
        } else {
            get_atom_name_probe_failed = true;
            None
        }
    } else {
        None
    };
    let get_class_info_stack_ok = if lp.msg.m0 == 0x10bd {
        client_read_u64_mapped(
            pi as u64,
            sp + 0x28,
            scratch_base,
        )
        .is_some()
    } else {
        true
    };
    let get_class_info_capture = if lp.msg.m0 == 0x10bd {
        let capture = get_class_info_stack_ok
            .then(|| {
                capture_get_class_info_graph(
                    pi as u64,
                    a1,
                    a2,
                    a3,
                    filled_pages,
                    lp.exit.faults as usize,
                    scratch_base,
                )
            })
            .flatten();
        if let Some(capture) = capture {
            d_a1 = capture.class_desc;
            d_a2 = capture.wnd_out;
            d_a3 = if a3 == 0 { 0 } else { capture.menu_out };
            Some(capture)
        } else {
            get_class_info_probe_failed = true;
            None
        }
    } else {
        None
    };
    let get_class_name_capture = if lp.msg.m0 == 0x107c {
        let capture = capture_get_class_name_out(
            pi as u64,
            a2,
            scratch_base,
        );
        if let Some(capture) = capture {
            d_a2 = capture.desc_out;
            Some(capture)
        } else {
            None
        }
    } else {
        None
    };
    // NtUserCreateWindowStation(0x122f) and NtUserCreateDesktop(0x122d) both take a
    // client OBJECT_ATTRIBUTES whose ObjectName points at a client UNICODE_STRING and
    // buffer. Capture that bounded graph into the win32k argument window so both the
    // real handler and our post-dispatch observers see a component-local pointer graph.
    if lp.msg.m0 == 0x122f || lp.msg.m0 == 0x122d {
        let mut oa = [0u8; 0x30];
        let oa_ok = img_spawn::client_copyin_mapped(
            pi as u64,
            a0,
            &mut oa,
            scratch_base,
        );
        let object_name = if oa_ok {
            u64::from_le_bytes(oa[0x10..0x18].try_into().unwrap())
        } else {
            0
        };
        let mut name = [0u8; 0x10];
        let name_ok = object_name != 0
            && img_spawn::client_copyin_mapped(
                pi as u64,
                object_name,
                &mut name,
                scratch_base,
            );
        let name_lengths = if name_ok {
            u32::from_le_bytes(name[0..4].try_into().unwrap())
        } else {
            0
        };
        let name_buffer = if name_ok {
            u64::from_le_bytes(name[8..16].try_into().unwrap())
        } else {
            0
        };
        let mut prefix = [0u8; 8];
        let prefix_ok = name_buffer != 0
            && img_spawn::client_copyin_mapped(
                pi as u64,
                name_buffer,
                &mut prefix,
                scratch_base,
            );
        print_str(b"[w32diag] user-object OA ssn=0x");
        print_hex(lp.msg.m0 as u32);
        print_str(b" OA=0x");
        print_hex((a0 >> 32) as u32);
        print_hex(a0 as u32);
        print_str(b" real-Length=0x");
        print_hex(smss_stack_read(a0) as u32);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" graph=");
        print_u64(oa_ok as u64);
        print_str(b"/");
        print_u64(name_ok as u64);
        print_str(b"/");
        print_u64(prefix_ok as u64);
        print_str(b" ObjectName=0x");
        print_hex((object_name >> 32) as u32);
        print_hex(object_name as u32);
        print_str(b" LenMax=0x");
        print_hex(name_lengths);
        print_str(b" Buffer=0x");
        print_hex((name_buffer >> 32) as u32);
        print_hex(name_buffer as u32);
        print_str(b" text4=0x");
        print_hex(u64::from_le_bytes(prefix) as u32);
        print_str(b"\n");

        // win32k is an isolated component, so capture the nested user pointer graph at
        // the executive boundary just as NtUserCreateWindowStation's ProbeForRead block
        // does in a monolithic kernel. Preserve scalar handles/flags and the caller's
        // security descriptor pointer; only the OA, counted-string descriptor, and its
        // bounded UTF-16 buffer need rebasing into the shared argument window.
        let name_len = (name_lengths & 0xffff) as usize;
        let name_max = (name_lengths >> 16) as usize;
        let arg = win32k_subsystem::WIN32K_ARG_VADDR;
        let arg_bytes = win32k_subsystem::WIN32K_ARG_GENERAL_BYTES as usize;
        let graph_valid = oa_ok
            && name_ok
            && prefix_ok
            && name_len != 0
            && name_len & 1 == 0
            && name_len <= name_max
            && name_max <= arg_bytes - 0x40;
        if graph_valid {
            core::ptr::write_bytes(arg as *mut u8, 0, arg_bytes);
            core::ptr::copy_nonoverlapping(oa.as_ptr(), arg as *mut u8, oa.len());
            core::ptr::copy_nonoverlapping(
                name.as_ptr(),
                (arg + 0x30) as *mut u8,
                name.len(),
            );
            let name_out =
                core::slice::from_raw_parts_mut((arg + 0x40) as *mut u8, name_max);
            if img_spawn::client_copyin_mapped(
                pi as u64,
                name_buffer,
                name_out,
                scratch_base,
            ) {
                core::ptr::write_unaligned((arg + 0x10) as *mut u64, arg + 0x30);
                core::ptr::write_unaligned((arg + 0x38) as *mut u64, arg + 0x40);
                d_a0 = arg;
                print_str(b"[w32marshal] captured named user-object OA graph ssn=0x");
                print_hex(lp.msg.m0 as u32);
                print_str(b" bytes=");
                print_u64(0x40 + name_max as u64);
                print_str(b"\n");
            }
        }
    }
    let session_cursor_hit = if lp.msg.m0 == 0x103d {
        cursor_identity_key
            .as_ref()
            .and_then(|key| nt_handler.lookup_global_cursor_identity(key))
    } else {
        None
    };
    if let Some(handle) = session_cursor_hit {
        let n = SESSION_CURSOR_SERVE_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[win32k-session] ");
            print_str(win32k_client_label(&nt_handler, pi));
            print_str(b" NtUserFindExistingCursorIcon -> 0x");
            print_hex(handle);
            print_str(b"\n");
        }
    }
    let session_builtin_class_atom = if lp.msg.m0 == 0x10b4 && builtin_class_attempt {
        builtin_class_key
            .as_ref()
            .and_then(|key| nt_handler.lookup_builtin_class_atom(key))
    } else {
        None
    };
    if let Some(atom) = session_builtin_class_atom {
        let n = SESSION_BUILTIN_CLASS_SERVE_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[win32k-session] ");
            print_str(win32k_client_label(&nt_handler, pi));
            print_str(b" NtUserRegisterClassExWOW builtin atom=0x");
            print_hex(atom as u32);
            if let Some(key) = builtin_class_key.as_ref() {
                print_str(b" fnid=0x");
                print_hex(key.fn_id());
            }
            print_str(b"\n");
        }
    }
    let session_atom_name_chars = if lp.msg.m0 == 0x10ad {
        get_atom_name_capture.and_then(|capture| {
            stage_session_atom_name(&mut nt_handler, a0 as u16, capture)
        })
    } else {
        None
    };
    if let Some(chars) = session_atom_name_chars {
        let n = SESSION_ATOM_NAME_SERVE_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[win32k-session] ");
            print_str(win32k_client_label(&nt_handler, pi));
            print_str(b" NtUserGetAtomName atom=0x");
            print_hex(a0 as u32);
            print_str(b" chars=");
            print_u64(chars);
            print_str(b"\n");
        }
    }
    let mut dispatch_return = None;
    let mut dispatch_entered = false;
    let mut dispatch_context = None;
    let (mut st, mut ok): (u64, bool) = if sc.wl_milestone_park {
        // The bootstrap milestone owner handles this intentional park below.
        (0, false)
    } else if message_output_stage_failed {
        (0xC000_009A, true)
    } else if paint_output_stage_failed {
        (0xC000_009A, true)
    } else if register_class_probe_failed {
        (0, true)
    } else if wallpaper_spi_probe_failed {
        (0, true)
    } else if userconnect_capture_status != 0 {
        (u64::from(userconnect_capture_status), true)
    } else if register_window_message_probe_failed {
        (0, true)
    } else if let Some(handle) = session_cursor_hit {
        (handle as u64, true)
    } else if let Some(atom) = session_builtin_class_atom {
        (atom as u64, true)
    } else if let Some(chars) = session_atom_name_chars {
        (chars, true)
    } else if find_cursor_icon_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(
                b"[win32k-svc] NtUserFindExistingCursorIcon input probe failed pi=",
            );
            print_u64(pi as u64);
            print_str(b" module=0x");
            print_hex_u64(a0);
            print_str(b" resource=0x");
            print_hex_u64(a1);
            print_str(b" params=0x");
            print_hex_u64(a2);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if set_cursor_icon_data_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserSetCursorIconData input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hcursor=0x");
            print_hex_u64(a0);
            print_str(b" module=0x");
            print_hex_u64(a1);
            print_str(b" resource=0x");
            print_hex_u64(a2);
            print_str(b" data=0x");
            print_hex_u64(a3);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if get_icon_info_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserGetIconInfo output probe failed pi=");
            print_u64(pi as u64);
            print_str(b" icon=0x");
            print_hex_u64(a0);
            print_str(b" info=0x");
            print_hex_u64(a1);
            print_str(b" module=0x");
            print_hex_u64(a2);
            print_str(b" resource=0x");
            print_hex_u64(a3);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" reason=");
            print_u64(get_icon_info_probe_failure);
            print_str(b" aux=");
            print_u64(get_icon_info_probe_aux0);
            print_str(b"/");
            print_u64(get_icon_info_probe_aux1);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if create_bitmap_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiCreateBitmap input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" ");
            print_u64(a0 as u32 as u64);
            print_str(b"x");
            print_u64(a1 as u32 as u64);
            print_str(b" planes=");
            print_u64(a2 as u32 as u64);
            print_str(b" bpp=");
            print_u64(a3 as u32 as u64);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if create_dib_section_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiCreateDIBSection input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hdc=0x");
            print_hex_u64(a0);
            print_str(b" bmi=0x");
            print_hex_u64(a3);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" reason=");
            print_u64(create_dib_section_probe_failure);
            print_str(b" usage=0x");
            print_hex(create_dib_section_stack_args[0] as u32);
            print_str(b" header=");
            print_u64(create_dib_section_stack_args[1] as u32 as u64);
            print_str(b" out=0x");
            print_hex_u64(create_dib_section_stack_args[4]);
            print_str(b" aux=");
            print_u64(create_dib_section_probe_aux0);
            print_str(b"/");
            print_u64(create_dib_section_probe_aux1);
            print_str(b"/");
            print_u64(create_dib_section_probe_aux2);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if create_dibitmap_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(
                b"[win32k-svc] NtGdiCreateDIBitmapInternal input probe failed pi=",
            );
            print_u64(pi as u64);
            print_str(b" hdc=0x");
            print_hex_u64(a0);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" reason=");
            print_u64(create_dibitmap_probe_failure);
            print_str(b" bits=0x");
            print_hex_u64(create_dibitmap_stack_args[0]);
            print_str(b" bmi=0x");
            print_hex_u64(create_dibitmap_stack_args[1]);
            print_str(b" info=");
            print_u64(create_dibitmap_stack_args[3]);
            print_str(b" bits-bytes=");
            print_u64(create_dibitmap_stack_args[4]);
            print_str(b" aux=");
            print_u64(create_dibitmap_probe_aux0);
            print_str(b"/");
            print_u64(create_dibitmap_probe_aux1);
            print_str(b"/");
            print_u64(create_dibitmap_probe_aux2);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if stretch_dibits_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(
                b"[win32k-svc] NtGdiStretchDIBitsInternal input probe failed pi=",
            );
            print_u64(pi as u64);
            print_str(b" hdc=0x");
            print_hex_u64(a0);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" reason=");
            print_u64(stretch_dibits_probe_failure);
            print_str(b" bits=0x");
            print_hex_u64(stretch_dibits_stack_args[5]);
            print_str(b" bmi=0x");
            print_hex_u64(stretch_dibits_stack_args[6]);
            print_str(b" info=");
            print_u64(stretch_dibits_stack_args[9]);
            print_str(b" bits-bytes=");
            print_u64(stretch_dibits_stack_args[10]);
            print_str(b" aux=");
            print_u64(stretch_dibits_probe_aux0);
            print_str(b"/");
            print_u64(stretch_dibits_probe_aux1);
            print_str(b"/");
            print_u64(stretch_dibits_probe_aux2);
            print_str(b" -> 0\n");
        }
        (0, true)
    } else if ext_text_out_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiExtTextOutW input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hdc=0x");
            print_hex_u64(a0);
            print_str(b" options=0x");
            print_hex(a3 as u32);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if user_rect_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] USER RECT probe failed pi=");
            print_u64(pi as u64);
            print_str(b" ssn=0x");
            print_hex(lp.msg.m0 as u32);
            print_str(b" hwnd=0x");
            print_hex_u64(a0);
            print_str(b" rect=0x");
            print_hex_u64(a1);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if paintstruct_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] paint PAINTSTRUCT probe failed pi=");
            print_u64(pi as u64);
            print_str(b" ssn=0x");
            print_hex(lp.msg.m0 as u32);
            print_str(b" hwnd=0x");
            print_hex_u64(a0);
            print_str(b" ps=0x");
            print_hex_u64(a1);
            print_str(b" -> 0\n");
        }
        (0, true)
    } else if text_extent_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiGetTextExtentExW input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" count=");
            print_u64(a2 as u32 as u64);
            print_str(b" str=0x");
            print_hex_u64(a1);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if text_metrics_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiGetTextMetricsW output probe failed pi=");
            print_u64(pi as u64);
            print_str(b" out=0x");
            print_hex_u64(a1);
            print_str(b" bytes=");
            print_u64(a2 as u32 as u64);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if get_text_extent_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiGetTextExtent input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" count=");
            print_u64(a2 as u32 as u64);
            print_str(b" str=0x");
            print_hex_u64(a1);
            print_str(b" size=0x");
            print_hex_u64(a3);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if load_keyboard_layout_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserLoadKeyboardLayoutEx KLID probe failed pi=");
            print_u64(pi as u64);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if char_width_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtGdiGetCharWidthW input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" count=");
            print_u64(a2 as u32 as u64);
            print_str(b" pwc=0x");
            print_hex_u64(a3);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if message_call_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserMessageCall stack probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hwnd=0x");
            print_hex_u64(a0);
            print_str(b" msg=0x");
            print_hex(a1 as u32);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if set_window_pos_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserSetWindowPos stack probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hwnd=0x");
            print_hex_u64(a0);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if defer_window_pos_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserDeferWindowPos stack probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hdwp=0x");
            print_hex_u64(a0);
            print_str(b" hwnd=0x");
            print_hex_u64(a1);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else if get_atom_name_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserGetAtomName output probe failed pi=");
            print_u64(pi as u64);
            print_str(b" atom=0x");
            print_hex(a0 as u32);
            print_str(b" desc=0x");
            print_hex_u64(a1);
            print_str(b" -> 0\n");
        }
        (0, true)
    } else if get_class_info_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserGetClassInfo capture failed pi=");
            print_u64(pi as u64);
            print_str(b" class=0x");
            print_hex_u64(a1);
            print_str(b" wndclass=0x");
            print_hex_u64(a2);
            print_str(b" menu=0x");
            print_hex_u64(a3);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> 0\n");
        }
        (0, true)
    } else if def_set_text_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserDefSetText input probe failed pi=");
            print_u64(pi as u64);
            print_str(b" hwnd=0x");
            print_hex_u64(a0);
            print_str(b" desc=0x");
            print_hex_u64(a1);
            print_str(b" -> FALSE\n");
        }
        (0, true)
    } else if create_window_probe_failed {
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserCreateWindowEx stack probe failed pi=");
            print_u64(pi as u64);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" -> NULL\n");
        }
        (0, true)
    } else {
        // Forward the real syscall-entry stack pointer to win32k. The component derives
        // exact arity from win32k's SSPT and reads only the required tail args through
        // the attached client-memory path.
        let client = dispatch_client;
        if pi >= 1 && lp.msg.m0 == 0x1077 && a3 != 0 {
            prefill_client_large_string_pages(
                pi as u64,
                a3,
                scratch_base,
                &reg,
                dll_pe_store.as_slice(),
            );
        }
        crate::teb_tail_watch(pi, 1, lp.msg.m0, 0);
        // ★ `KiSystemCallHandler`'s win32k arm (ntoskrnl/ke/amd64/traphandler.c:180):
        // BEFORE dispatching any win32k system call, if the caller's
        // `TEB.GdiBatchCount != 0`, run `KeGdiFlushUserBatch`. Without this step
        // `gdi32!GdiAllocBatchCommand`'s `GdiTebBatch.Offset` never resets and the
        // deferred-GDI records march straight through the caller's TEB — the single root
        // cause of the whole TEB-clobber family (batches 53/59/60) and of winlogon's
        // `#GP` in `RtlEnterCriticalSection` on rpcrt4's `TEB.ReservedForNtRpc`.
        let gdi_teb_alias = dispatch_client.logical_caller
            .and_then(|logical| nt_handler.hosted_gui_thread_teb_alias_for(logical))
            .unwrap_or(0);
        crate::observe_gdi_batch_before_dispatch(client, gdi_teb_alias);
        let open_dcw_staged_stack =
            lp.msg.m0 == 0x10de && open_dcw_stack_arg_count == open_dcw_stack_args.len();
        let build_hwnd_list_staged_stack = lp.msg.m0
            == nt_kernel_exec::user_window_list::BUILD_HWND_LIST_SSN
            && build_hwnd_list_stack_arg_count == build_hwnd_list_stack_args.len();
        let get_icon_info_staged_stack = lp.msg.m0 == 0x104e
            && get_icon_info_stack_arg_count == get_icon_info_stack_args.len();
        let create_bitmap_staged_stack = lp.msg.m0 == 0x106c
            && create_bitmap_stack_arg_count == create_bitmap_stack_args.len();
        let create_dib_section_staged_stack = lp.msg.m0 == 0x109b
            && create_dib_section_stack_arg_count
                == create_dib_section_stack_args.len();
        let create_dibitmap_staged_stack = lp.msg.m0 == 0x10a0
            && create_dibitmap_stack_arg_count == create_dibitmap_stack_args.len();
        let stretch_dibits_staged_stack = lp.msg.m0 == 0x1082
            && stretch_dibits_stack_arg_count == stretch_dibits_stack_args.len();
        let ext_text_out_staged_stack = lp.msg.m0
            == nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN
            && ext_text_out_stack_arg_count == ext_text_out_stack_args.len();
        let get_text_extent_staged_stack = lp.msg.m0 == NTGDI_GET_TEXT_EXTENT_SSN
            && get_text_extent_stack_arg_count == get_text_extent_stack_args.len();
        let text_extent_staged_stack =
            lp.msg.m0 == 0x11d9 && text_extent_stack_arg_count == text_extent_stack_args.len();
        let char_width_staged_stack =
            lp.msg.m0 == 0x10cb && char_width_stack_arg_count == char_width_stack_args.len();
        let register_class_staged_stack = lp.msg.m0 == 0x10b4
            && register_class_stack_arg_count == register_class_stack_args.len();
        let create_window_staged_stack = lp.msg.m0 == 0x1077
            && create_window_stack_arg_count == create_window_stack_args.len();
        let load_keyboard_layout_staged_stack = lp.msg.m0 == 0x125c
            && load_keyboard_layout_stack_arg_count
                == load_keyboard_layout_stack_args.len();
        let message_call_staged_stack = lp.msg.m0 == NTUSER_MESSAGE_CALL_SSN
            && message_call_stack_arg_count == message_call_stack_args.len();
        let set_window_pos_staged_stack = lp.msg.m0 == NTUSER_SET_WINDOW_POS_SSN
            && set_window_pos_stack_arg_count == set_window_pos_stack_args.len();
        let defer_window_pos_staged_stack = lp.msg.m0 == NTUSER_DEFER_WINDOW_POS_SSN
            && defer_window_pos_stack_arg_count == defer_window_pos_stack_args.len();
        // Keep the original SP in the dispatch context for callback/completion
        // observers. win32k_dispatch_wide still sends SH_REQ_CALLER_SP=0 when
        // stack_args is non-empty, so the component consumes only the staged tail.
        let (dispatch_sp, dispatch_stack_args): (u64, &[u64]) = if open_dcw_staged_stack
        {
            (sp, &open_dcw_stack_args)
        } else if build_hwnd_list_staged_stack {
            (sp, &build_hwnd_list_stack_args)
        } else if get_icon_info_staged_stack {
            (sp, &get_icon_info_stack_args)
        } else if create_bitmap_staged_stack {
            (sp, &create_bitmap_stack_args)
        } else if create_dib_section_staged_stack {
            (sp, &create_dib_section_stack_args)
        } else if create_dibitmap_staged_stack {
            (sp, &create_dibitmap_stack_args)
        } else if stretch_dibits_staged_stack {
            (sp, &stretch_dibits_stack_args)
        } else if ext_text_out_staged_stack {
            (sp, &ext_text_out_stack_args)
        } else if get_text_extent_staged_stack {
            (sp, &get_text_extent_stack_args)
        } else if text_extent_staged_stack {
            (sp, &text_extent_stack_args)
        } else if char_width_staged_stack {
            (sp, &char_width_stack_args)
        } else if register_class_staged_stack {
            (sp, &register_class_stack_args)
        } else if create_window_staged_stack {
            (sp, &create_window_stack_args)
        } else if load_keyboard_layout_staged_stack {
            (sp, &load_keyboard_layout_stack_args)
        } else if message_call_staged_stack {
            (sp, &message_call_stack_args)
        } else if set_window_pos_staged_stack {
            (sp, &set_window_pos_stack_args)
        } else if defer_window_pos_staged_stack {
            (sp, &defer_window_pos_stack_args)
        } else {
            (sp, &[])
        };
        let dispatch_ssn =
            if lp.msg.m0 == win32k_subsystem::SSN_NT_USER_USER_HANDLE_GRANT_ACCESS {
                match nt_handler.job_id_for_user_handle_grant(d_a1) {
                    Ok(job) => {
                        d_a1 = job as u64;
                        d_a3 = 0;
                    }
                    Err(error) => {
                        d_a1 = 0;
                        d_a3 = error as u64;
                    }
                }
                win32k_subsystem::SSN_WIN32_JOB_USER_HANDLE
            } else {
                lp.msg.m0
            };
        trace_cursor_lookup_owner(
            "pre-dispatch", client, lp.msg.m0, dispatch_id, None, false, false, false,
        );
        let mut r = dispatch_win32k_for_client_with_completion_args(
            &mut nt_handler,
            dispatch_id,
            dispatch_ssn,
            d_a0,
            d_a1,
            d_a2,
            d_a3,
            dispatch_sp,
            dispatch_stack_args,
            [a0, a1, a2, a3],
            message_output_stage.or(paint_output_stage),
            paint_output_claim,
            client,
            &mut dispatch_return,
            &mut dispatch_entered,
            &mut dispatch_context,
        );
        trace_cursor_lookup_owner(
            "provider-return", client, lp.msg.m0, dispatch_id,
            dispatch_context.map(|context| context.lane),
            dispatch_entered, !r.1, false,
        );
        let inline_batch_records = win32k_glue::completed_gdi_batch_records(
            dispatch_return, r.0, r.1,
        );
        if explorer_direct_gdi_draw && r.1 {
            if EXPLORER_DIRECT_GDI_DRAW_RETURNS.fetch_add(1, Ordering::Relaxed) == 0 {
                note_boot_progress(BootProgress::ExplorerDirectDrawObserved);
            }
        }
        // ★ win32k just ran KeStackAttachProcess'd to this client and may have written
        // SERVER data through its TEB pages — OBSERVE (do not yet repair) the TEB-tail
        // invariants the client's own CRT depends on, so the frontier has a number.
        crate::teb_tail_watch(pi, 2, lp.msg.m0, 0);
        crate::observe_client_teb_tail(pi);
        // The credential READ-BACK. A single-line edit control renders itself with
        // `EDIT_PaintText -> TextOutW -> NtGdiExtTextOutW(hdc, x, y, opts, lprc,
        // es->text + col, count, …)` (args 5..9 ride the win64 stack tail). The string
        // it hands GDI IS the control's live text buffer, so matching our injected user
        // name there proves the real edit control holds what was typed into it.
        if winlogon_gui_client
            && lp.msg.m0 == nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN
            && sp != 0
        {
            let string = client_read_u64_mapped(
                pi as u64,
                sp + 0x30,
                scratch_base,
            );
            let count = client_read_u64_mapped(
                pi as u64,
                sp + 0x38,
                scratch_base,
            );
            if let (Some(string), Some(count)) = (string, count) {
                winlogon_credential_observe_text_out(string, count);
            }
        }
        if open_dcw_staged_stack && r.1 && r.0 != 0 {
            let (client_out, staged_out) = open_dcw_dhpdev_copyout;
            let dhpdev = core::ptr::read_unaligned(staged_out as *const u64);
            if client_out != 0
                && !img_spawn::client_write_u64_mapped(
                    pi as u64,
                    client_out,
                    dhpdev,
                    scratch_base,
                )
            {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(
                        b"[win32k-svc] NtGdiOpenDCW pUMDHPDEV copy-out failed pi=",
                    );
                    print_u64(pi as u64);
                    print_str(b" buffer=0x");
                    print_hex_u64(client_out);
                    print_str(b"\n");
                }
                r = (0xC000_0001, false);
            }
        }
        if let Some(call) = build_hwnd_list_call.filter(|_| build_hwnd_list_staged_stack && r.1) {
            let (client_list, client_needed) = (call.list, call.needed);
            let staged_list = win32k_subsystem::WIN32K_ARG_VADDR;
            let copy_out = call.copy_out(
                r.0 as u32,
                core::ptr::read_unaligned(
                    (staged_list + WIN32K_BUILD_HWND_LIST_COUNT_OFFSET) as *const u32,
                ),
                WIN32K_BUILD_HWND_LIST_MAX_HANDLES,
            );
            let handles_to_copy = copy_out.handles;
            let needed_ok = copy_out.needed.is_none_or(|needed| {
                img_spawn::client_write_mapped(
                    pi as u64,
                    client_needed,
                    &needed.to_le_bytes(),
                    scratch_base,
                )
            });
            let handles_ok = handles_to_copy == 0
                || img_spawn::client_copyout_mapped(
                    pi as u64,
                    client_list,
                    core::slice::from_raw_parts(
                        staged_list as *const u8,
                        handles_to_copy * 8,
                    ),
                    scratch_base,
                );
            if !needed_ok || !handles_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] NtUserBuildHwndList copy-out failed pi=");
                    print_u64(pi as u64);
                    print_str(b" list=0x");
                    print_hex_u64(client_list);
                    print_str(b" needed=0x");
                    print_hex_u64(client_needed);
                    print_str(b" handles=");
                    print_u64(handles_to_copy as u64);
                    print_str(b"\n");
                }
                r = (0xC000_0005, false);
            }
        }
        if get_icon_info_staged_stack && r.1 && r.0 != 0 {
            if !copy_back_get_icon_info(
                pi as u64,
                get_icon_info_copyout,
                scratch_base,
            ) {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] NtUserGetIconInfo copy-out failed pi=");
                    print_u64(pi as u64);
                    print_str(b" info=0x");
                    print_hex_u64(get_icon_info_copyout.iconinfo_client);
                    print_str(b" module=");
                    print_u64(get_icon_info_copyout.module.is_some() as u64);
                    print_str(b" resource=");
                    print_u64(get_icon_info_copyout.resource.is_some() as u64);
                    print_str(b" bpp=0x");
                    print_hex_u64(get_icon_info_copyout.bpp_client);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if r.1 {
            if let (Some(stage), Some(claim)) = (paint_output_stage, paint_output_claim) {
                let published = win32k_glue::published_win32k_paint_output_length(stage)
                    .unwrap_or(u32::MAX);
                let bytes = core::slice::from_raw_parts(
                    stage.provider_pointer as *const u8,
                    stage.capacity as usize,
                );
                if !copy_completed_paint_output(
                    &mut nt_handler,
                    pi,
                    lp.msg.m0,
                    claim,
                    published,
                    bytes,
                    scratch_base,
                ) {
                    r = (0, true);
                }
            }
        }
        if lp.msg.m0 == NTGDI_GET_TEXT_METRICS_W_SSN && r.1 && r.0 != 0 {
            let (client_tmwi, staged_tmwi, output_bytes) = text_metrics_copyout;
            let tmwi_ok = output_bytes == 0
                || (client_tmwi != 0
                    && img_spawn::client_write_mapped(
                        pi as u64,
                        client_tmwi,
                        core::slice::from_raw_parts(
                            staged_tmwi as *const u8,
                            output_bytes,
                        ),
                        scratch_base,
                    ));
            if !tmwi_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] NtGdiGetTextMetricsW copy-out failed pi=");
                    print_u64(pi as u64);
                    print_str(b" out=0x");
                    print_hex_u64(client_tmwi);
                    print_str(b" bytes=");
                    print_u64(output_bytes as u64);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if get_text_extent_staged_stack && r.1 && r.0 != 0 {
            let (client_size, staged_size) = get_text_extent_copyout;
            let size_ok = img_spawn::client_write_mapped(
                pi as u64,
                client_size,
                core::slice::from_raw_parts(staged_size as *const u8, 8),
                scratch_base,
            );
            if !size_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] NtGdiGetTextExtent copy-out failed pi=");
                    print_u64(pi as u64);
                    print_str(b" size=0x");
                    print_hex_u64(client_size);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if text_extent_staged_stack && r.1 && r.0 != 0 {
            let (
                client_fit,
                staged_fit,
                client_dx,
                staged_dx,
                client_size,
                staged_size,
                dx_bytes,
            ) = text_extent_copyout;
            let size_ok = img_spawn::client_write_mapped(
                pi as u64,
                client_size,
                core::slice::from_raw_parts(staged_size as *const u8, 8),
                scratch_base,
            );
            let fit_ok = client_fit == 0
                || img_spawn::client_write_mapped(
                    pi as u64,
                    client_fit,
                    core::slice::from_raw_parts(staged_fit as *const u8, 4),
                    scratch_base,
                );
            let dx_ok = client_dx == 0
                || dx_bytes == 0
                || img_spawn::client_copyout_mapped(
                    pi as u64,
                    client_dx,
                    core::slice::from_raw_parts(staged_dx as *const u8, dx_bytes),
                    scratch_base,
                );
            if !size_ok || !fit_ok || !dx_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(
                        b"[win32k-svc] NtGdiGetTextExtentExW copy-out failed pi=",
                    );
                    print_u64(pi as u64);
                    print_str(b" fit=0x");
                    print_hex_u64(client_fit);
                    print_str(b" dx=0x");
                    print_hex_u64(client_dx);
                    print_str(b" size=0x");
                    print_hex_u64(client_size);
                    print_str(b" dx-bytes=");
                    print_u64(dx_bytes as u64);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if char_width_staged_stack && r.1 && r.0 != 0 {
            let (client_buffer, staged_buffer, output_bytes) = char_width_copyout;
            let out_ok = output_bytes == 0
                || img_spawn::client_copyout_mapped(
                    pi as u64,
                    client_buffer,
                    core::slice::from_raw_parts(
                        staged_buffer as *const u8,
                        output_bytes,
                    ),
                    scratch_base,
                );
            if !out_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] NtGdiGetCharWidthW copy-out failed pi=");
                    print_u64(pi as u64);
                    print_str(b" out=0x");
                    print_hex_u64(client_buffer);
                    print_str(b" bytes=");
                    print_u64(output_bytes as u64);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if create_dib_section_staged_stack && r.1 && r.0 != 0 {
            let (client_bits_out, staged_bits_out) = create_dib_section_bits_copyout;
            let bits_ok = client_bits_out == 0
                || img_spawn::client_copyout_mapped(
                    pi as u64,
                    client_bits_out,
                    core::slice::from_raw_parts(staged_bits_out as *const u8, 8),
                    scratch_base,
                );
            if !bits_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(
                        b"[win32k-svc] NtGdiCreateDIBSection bits copy-out failed pi=",
                    );
                    print_u64(pi as u64);
                    print_str(b" out=0x");
                    print_hex_u64(client_bits_out);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if message_call_staged_stack && r.1 {
            let (client_result, staged_result, output_bytes) = message_call_copyout;
            let result_ok = output_bytes == 0
                || img_spawn::client_copyout_mapped(
                    pi as u64,
                    client_result,
                    core::slice::from_raw_parts(
                        staged_result as *const u8,
                        output_bytes,
                    ),
                    scratch_base,
                );
            if !result_ok {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(
                        b"[win32k-svc] NtUserMessageCall result copy-out failed pi=",
                    );
                    print_u64(pi as u64);
                    print_str(b" result=0x");
                    print_hex_u64(client_result);
                    print_str(b"\n");
                }
                r = (0, true);
            }
        }
        if r.1 {
            observe_completed_gdi_batch_flush(&mut nt_handler, client.logical_caller,
                inline_batch_records);
            observe_completed_desktop_dispatch(&mut nt_handler, client.logical_caller,
                lp.msg.m0, [a0, a1, a2, a3], r.0, dispatch_return);
        }
        if observed_explorer_gui_client && r.1 && r.0 != 0 {
            match lp.msg.m0 {
                NTUSER_BEGIN_PAINT_SSN => {
                    if EXPLORER_BEGIN_PAINTS.fetch_add(1, Ordering::Relaxed) == 0 {
                        note_boot_progress(BootProgress::ExplorerBeginPaintObserved);
                    }
                }
                NTUSER_END_PAINT_SSN => {
                    EXPLORER_END_PAINTS.fetch_add(1, Ordering::Relaxed);
                    note_boot_progress(BootProgress::ExplorerEndPaintObserved);
                }
                _ => {}
            }
        }
        // DIAG: dump the retrieved MSG for winlogon's SAS GetMessage (a0=R10=&Msg). MSG =
        // {hwnd@0, message@8, wParam@0x10, lParam@0x18}. Confirms whether the injected
        // WLX_WM_SAS (0x659) reaches winlogon so DispatchMessageW runs SASWindowProc.
        if winlogon_gui_client
            && (lp.msg.m0 == 0x1006 || lp.msg.m0 == 0x1001)
            && a0 != 0
            && r.1
            && message_output_stage
                .and_then(|stage| win32k_glue::published_win32k_output_length(stage))
                == Some(WIN32K_MSG_BYTES as u32)
        {
            let msg_ptr = if msg_returns_to_client { d_a0 } else { a0 };
            let hwnd = if msg_returns_to_client {
                core::ptr::read_unaligned(msg_ptr as *const u64)
            } else {
                smss_stack_read(msg_ptr)
            };
            let message = if msg_returns_to_client {
                core::ptr::read_unaligned((msg_ptr + 8) as *const u64)
            } else {
                smss_stack_read(msg_ptr + 8)
            };
            let wparam = if msg_returns_to_client {
                core::ptr::read_unaligned((msg_ptr + 0x10) as *const u64)
            } else {
                smss_stack_read(msg_ptr + 0x10)
            };
            let message_is_milestone = matches!(
                message as u32,
                nt_user_callback::WLX_WM_SAS | 0x0100 | 0x0102
            );
            if message_is_milestone
                || bounded_trace_sample(&WINLOGON_MESSAGE_TRACE, 64)
            {
                print_str(b"[wl-diag] GetMessage retrieved MSG hwnd=0x");
                print_hex(hwnd as u32);
                print_str(b" message=0x");
                print_hex(message as u32);
                print_str(b" wParam=0x");
                print_hex(wparam as u32);
                print_str(b" (ret=0x");
                print_hex(r.0 as u32);
                print_str(b")\n");
            }
            if r.0 == 1 {
                // Count the injected credential keystrokes that genuinely came back
                // out of win32k's real message queue into the dialog's real pump.
                winlogon_credential_observe_retrieved(hwnd, message as u32, wparam);
            }
            if r.0 == 1
                && message as u32 == nt_user_callback::WLX_WM_SAS
                && wparam == nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL
            {
                let sas_hwnd = core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR
                        + win32k_subsystem::SH_SAS_HWND)
                        as *const u64,
                );
                if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
                    && WINLOGON_SAS1_RETRIEVED.swap(1, Ordering::Relaxed) == 0
                {
                    WINLOGON_PAINT_RETURNS_AT_SAS1.store(
                        win32k_glue::real_wm_paint_callback_returns(),
                        Ordering::Relaxed,
                    );
                } else if hwnd == sas_hwnd
                    && WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed) != 0
                {
                    if WINLOGON_SAS2_RETRIEVED.swap(1, Ordering::Relaxed) == 0 {
                        WINLOGON_KEY_OPENED_AT_INJECT.store(
                            WINLOGON_KEY_OPENED.load(Ordering::Relaxed),
                            Ordering::Relaxed,
                        );
                        WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
                        print_str(
                            b"[wl-main] winlogon retrieved second WLX_WM_SAS from real queue\n",
                        );
                    }
                }
                let session = core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR
                        + win32k_subsystem::SH_SAS_SESSION)
                        as *const u64,
                );
                let _ = winlogon_dialog_observe_sas_message(
                    session,
                    hwnd,
                    message as u32,
                    wparam,
                );
            }
        }
        if nt_handler.hosted_process_role(pi)
            == Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
            && lp.msg.m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
            && r.0 == 0
        {
            let main_tid = nt_handler
                .pm_main_tid_for_pi(pi)
                .map(u64::from)
                .unwrap_or(0);
            let _ = post_winlogon_second_sas_after_welcome_drain(
                dispatch_client.logical_caller,
                pi,
                nt_handler.hosted_process_generation(pi).unwrap_or(0),
                lp.msg.badge,
                current_tid,
                hosted_thread_tcb_or_zero(&nt_handler, current_tid),
                nt_handler.hosted_thread_role(current_tid),
                nt_handler.hosted_process_role(pi),
                nt_handler.hosted_process_top_badge(pi).unwrap_or(0),
                main_tid,
                nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                dispatch_client_teb,
                dispatch_peb_mirror,
                scratch_base,
                win32k_token_context(&nt_handler, pi),
            );
        }
        r
    };
    let handoff = admit_pending_win32k_dispatch(
        &mut nt_handler, HostedContinuationDestination::Win32k,
    );
    if handoff.retained_failure {
        // A yielded pump has already transferred its pending snapshot. Preserve
        // both Replies and the durable owner; ordinary syscall output is forbidden.
        procs[pi].faults = lp.exit.faults;
        procs[pi].first = lp.exit.first;
        procs[pi].ntfaults = lp.exit.ntfaults;
        pfilled[pi] = *filled_pages;
        lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
        lp.exit.stop_ssn = lp.msg.m0;
        lp.exit.record(b"win32k-dispatch-retained");
        return ControlFlow::Break(Turn::Exit);
    }
    let callback_suspended = handoff.callback_suspended;
    trace_cursor_lookup_owner(
        "handoff", dispatch_client, lp.msg.m0, dispatch_id,
        dispatch_context.map(|context| context.lane),
        dispatch_entered, handoff.parked || callback_suspended,
        callback_suspended,
    );
    sc.component_suspension_admitted_dispatch_id = handoff.admitted_dispatch_id;
    sc.component_suspension_park_request = handoff.parked;
    sc.component_root_maintenance_ticket = handoff.maintenance_ticket;
    if let Some(stage) = bulk_stage.take() {
        let suspended = callback_suspended || handoff.parked;
        let bound = if suspended {
            dispatch_entered
                && dispatch_context.is_some_and(|context| {
                    (handoff.admitted_dispatch_id == 0
                        || handoff.admitted_dispatch_id == context.dispatch_id)
                        && win32k_bulk_mapping::retain(
                            stage, context, pi as u32,
                            nt_handler.hosted_process_generation(pi).unwrap_or(0),
                        )
                })
        } else {
            let provider_completed = dispatch_entered
                && dispatch_return.and_then(|receipt| receipt.handler_value()).is_some();
            win32k_bulk_mapping::settle(stage, dispatch_entered, provider_completed)
        };
        if !bound {
            print_str(b"[win32k-bulk] exact DIB lease settlement failed\n");
            park();
        }
    }
    if handoff.parked { sc.redirected_user_callback = true; }
    let direct_provider_output_len = if ok
        && !callback_suspended
        && !sc.component_suspension_park_request
        && msg_returns_to_client
        && message_output_stage.is_some()
    {
        let report_output_failure = |published: Option<u32>| {
            print_str(b"[win32k-msg-output-rejected] ssn=");
            print_hex_u64(lp.msg.m0);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b" result=");
            print_hex_u64(st);
            print_str(b" expected=");
            print_u64(if nt_user_callback::message_dispatch_output_length_matches_result(lp.msg.m0, st, 0) {
                0
            } else {
                u64::from(nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES)
            });
            print_str(b" published=");
            if let Some(length) = published {
                print_u64(u64::from(length));
            } else {
                print_str(b"missing-or-invalid");
            }
            if let Some(stage) = message_output_stage {
                print_str(b" stage=");
                print_hex_u64(stage.provider_pointer);
                print_str(b" capacity=");
                print_u64(u64::from(stage.capacity));
            }
            print_str(b"\n");
        };
        match message_output_stage
            .and_then(|stage| win32k_glue::published_win32k_output_length(stage))
        {
            Some(len)
                if nt_user_callback::message_dispatch_output_length_matches_result(
                    lp.msg.m0, st, len,
                ) =>
            {
                len
            }
            Some(length) => {
                report_output_failure(Some(length));
                st = 0xC000_0001;
                ok = false;
                u32::MAX
            }
            None => {
                report_output_failure(None);
                st = 0xC000_0001;
                ok = false;
                u32::MAX
            }
        }
    } else {
        0
    };
    // `DispatchMessage` paint proof is authoritative only after the api0 callback
    // continuation returns; the completed-dispatch hook samples that final MSG.
    if dialog_modal_dispatch
        && !callback_suspended
        && !sc.component_suspension_park_request
        && lp.msg.m0 != nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN
    {
        let staged_msg = msg_returns_to_client && message_output_stage.is_some();
        let msg_ptr = if staged_msg { d_a0 } else { a0 };
        let hwnd = if msg_ptr != 0 {
            if staged_msg {
                core::ptr::read_unaligned(msg_ptr as *const u64)
            } else {
                smss_stack_read(msg_ptr)
            }
        } else {
            0
        };
        let message = if msg_ptr != 0 {
            if staged_msg {
                core::ptr::read_unaligned((msg_ptr + 8) as *const u32)
            } else {
                smss_stack_read(msg_ptr + 8) as u32
            }
        } else {
            0
        };
        if !winlogon_dialog_modal_observe(lp.msg.m0, st, hwnd, message) {
            sc.handled = false;
            sc.wl_milestone_park = true;
        }
    }
    if callback_suspended {
        let Some(peb_mirror) = hosted_peb_mirror_for_pi(pi) else {
            return ControlFlow::Break(lp.reject_hosted_ingress())
        };
        let client_teb = nt_handler
            .pm
            .thread_teb(current_tid as nt_process::ThreadId)
            .filter(|teb| *teb != 0)
            .unwrap_or(SMSS_TEB_VA);
        sc.redirected_user_callback = win32k_glue::begin_controlled_user_callback_redirect(
            win32k_client_context_for_thread(
                &nt_handler,
                pi,
                lp.msg.badge,
                current_tid,
                hosted_thread_tcb_or_zero(&nt_handler, current_tid),
                nt_handler.hosted_thread_role(current_tid),
                client_teb,
                peb_mirror,
                scratch_base,
            ),
        );
        if !sc.redirected_user_callback {
            print_str(b"[win32k-callback-redirect-cancel] phase=before ssn=");
            print_hex_u64(lp.msg.m0);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b" result=");
            print_hex_u64(st);
            print_str(b" ok=");
            print_u64(u64::from(ok));
            print_str(b"\n");
            let resumed = win32k_glue::cancel_suspended_user_callback();
            print_str(b"[win32k-callback-redirect-cancel] phase=after ssn=");
            print_hex_u64(lp.msg.m0);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b" resumed-status=");
            print_hex_u64(u64::from(resumed.0 as u32));
            print_str(b" resumed-ok=");
            print_u64(u64::from(resumed.1));
            print_str(b"\n");
            st = resumed.0 as u32 as u64;
            ok = resumed.1;
        }
    } else if !sc.component_suspension_park_request && ok {
        if !win32k_glue::validate_active_callback_syscall_resume(dispatch_client) {
            sc.active_callback_bad_resume = true;
            st = 0xC000_0005;
            ok = false;
        }
    }
    if ok && !sc.redirected_user_callback && msg_returns_to_client {
        if direct_provider_output_len as usize == WIN32K_MSG_BYTES {
            let output =
                core::slice::from_raw_parts(d_a0 as *const u8, WIN32K_MSG_BYTES);
            if !img_spawn::client_copyout_mapped(
                pi as u64,
                a0,
                output,
                scratch_base,
            ) {
                let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                if failures < 8 {
                    print_str(b"[win32k-svc] GUI MSG copy-out failed ssn=0x");
                    print_hex(lp.msg.m0 as u32);
                    print_str(b" buffer=0x");
                    print_hex_u64(a0);
                    print_str(b"\n");
                }
                st = 0;
            }
        }
    }
    if msg_syscall && ok && !sc.redirected_user_callback {
        let n = GUI_MESSAGE_DIAG_N.fetch_add(1, Ordering::Relaxed);
        if n < 128 || n.is_power_of_two() {
            let mut msg = [0u8; WIN32K_MSG_BYTES];
            let copy_ok = if msg_returns_to_client {
                msg.copy_from_slice(core::slice::from_raw_parts(
                    d_a0 as *const u8,
                    WIN32K_MSG_BYTES,
                ));
                true
            } else {
                nt_handler.capture_process_identity(pi).is_some_and(|process| {
                    img_spawn::client_copyin_process_mapped_for(
                        pi as u64,
                        process,
                        a0,
                        &mut msg,
                        scratch_base,
                    )
                })
            };
            let hwnd = u64::from_le_bytes(msg[0..8].try_into().unwrap_or([0; 8]));
            let message = u32::from_le_bytes(msg[8..12].try_into().unwrap_or([0; 4]));
            let wparam =
                u64::from_le_bytes(msg[0x10..0x18].try_into().unwrap_or([0; 8]));
            let lparam =
                u64::from_le_bytes(msg[0x18..0x20].try_into().unwrap_or([0; 8]));
            let time = u32::from_le_bytes(msg[0x20..0x24].try_into().unwrap_or([0; 4]));
            print_str(b"[gui-msg] ssn=0x");
            print_hex(lp.msg.m0 as u32);
            print_str(b" ret=0x");
            print_hex(st as u32);
            print_str(b" msgptr=0x");
            print_hex_u64(a0);
            print_str(b" hfilter=0x");
            print_hex_u64(a1);
            print_str(b" min=0x");
            print_hex(a2 as u32);
            print_str(b" max=0x");
            print_hex(a3 as u32);
            print_str(b" copy=");
            print_u64(if copy_ok { 1 } else { 0 });
            print_str(b" hwnd=0x");
            print_hex_u64(hwnd);
            print_str(b" message=0x");
            print_hex(message);
            print_str(b" wParam=0x");
            print_hex_u64(wparam);
            print_str(b" lParam=0x");
            print_hex_u64(lparam);
            print_str(b" time=");
            print_u64(time as u64);
            print_str(b"\n");
        }
    }
    if !callback_suspended && !sc.component_suspension_park_request {
        if let Some(stage) = message_output_stage {
            let _ = win32k_glue::release_win32k_message_stage(stage);
        }
        if let Some(stage) = paint_output_stage {
            let _ = win32k_glue::release_win32k_paint_stage(stage);
        }
    }
    if ok && !sc.redirected_user_callback {
        if let Some(capture) = get_class_info_capture {
            if st != 0 {
                if !copy_back_get_class_info(
                    pi,
                    capture,
                    scratch_base,
                ) {
                    st = 0;
                }
            }
        }
        if let Some(capture) = get_class_name_capture {
            if st != 0
                && !copy_back_get_class_name(
                    pi as u64,
                    capture,
                    st,
                    scratch_base,
                )
            {
                st = 0;
            }
        }
        if let Some(capture) = get_atom_name_capture {
            if st != 0
                && !copy_back_get_atom_name(
                    nt_handler,
                    pi as u64,
                    capture,
                    st,
                    scratch_base,
                )
            {
                st = 0;
            }
        }
    }
    if ok && !sc.redirected_user_callback && userinit_gui_client {
        if lp.msg.m0 == 0x103d && st != 0 {
            nt_handler.record_userinit_global_cursor_hit(st as u32);
        }
        if lp.msg.m0 == 0x10b4 && builtin_class_attempt {
            if st != 0 {
                if let Some((fn_id, _)) = builtin_class_args {
                    nt_handler.record_userinit_builtin_class_hit(fn_id, st as u16);
                }
            } else {
                nt_handler.record_userinit_builtin_class_miss();
            }
        }
    }
    if ok && !sc.redirected_user_callback && lp.msg.m0 == 0x10b4 && st != 0 && !svc_noninteractive
    {
        if let Some(name) = registered_class_atom_name.as_ref() {
            nt_handler.observe_class_atom_name(st as u16, name.as_slice());
        }
    }
    if ok
        && !sc.redirected_user_callback
        && lp.msg.m0 == 0x10d4
        && st != 0
        && !svc_noninteractive
        && nt_handler.observe_win32k_stock_object(a0 as u32, st as u32)
    {
        print_str(b"[win32k-svc] NtGdiGetStockObject(0x10d4) OBSERVED object=");
        print_u64(a0 as u32 as u64);
        print_str(b" -> real handle 0x");
        print_hex(st as u32);
        print_str(b"\n");
    }
    if winlogon_gui_client && ok && !sc.redirected_user_callback {
        if lp.msg.m0 == 0x10a8 && st != 0 {
            if let Some(key) = cursor_identity_key.as_ref() {
                nt_handler.observe_global_cursor_identity(key, a0 as u32);
            }
        } else if lp.msg.m0 == 0x1283 && st != 0 {
            nt_handler.promote_global_cursor(a0 as u32);
        }
        if lp.msg.m0 == 0x10b4 && st != 0 {
            if let Some(key) = builtin_class_key.as_ref() {
                nt_handler.observe_builtin_class_atom(key, st as u16);
            }
        }
    }
    if has_buf && ok && st == 0 && !sc.redirected_user_callback {
        let userconnect = core::slice::from_raw_parts_mut(
            win32k_subsystem::WIN32K_ARG_VADDR as *mut u8,
            blen as usize,
        );
        if complete_ntuser_process_connect_copyout(
            &mut nt_handler,
            pi,
            pml4,
            a1,
            userconnect,
            scratch_base,
        ) {
            // NtUserProcessConnect (0x10FA) returned STATUS_SUCCESS for this GUI client
            // and its USERCONNECT was copied back to the caller.
            W32_CONNECTED_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
        } else {
            ok = false;
            st = 0xC000_0001;
        }
    }
    // Use the request's sampling decision for the matching status line. Real provider
    // walls still print, but an intentional wait-park is not a failed dispatch.
    if !sc.redirected_user_callback
        && !sc.wl_milestone_park
        && (!ok || w32_log)
    {
        print_str(b"[win32k-svc] ");
        print_str(win32k_client_label(&nt_handler, pi));
        print_str(b" SSN 0x");
        print_hex(lp.msg.m0 as u32);
        print_str(if ok {
            b" -> status=0x"
        } else {
            b" -> WALL status=0x"
        });
        print_hex(st as u32);
        print_str(b"\n");
    }
    // ★ CLIENT-GDI HANDLE-TABLE ALIAS. The early win32k process-create callout maps
    // the canonical Section and writes PEB+0xf8 before gdi32's GdiProcessSetup. The
    // user-attribute area also precedes client-side GdiValidateHandle. Winlogon needs this for the
    // msgina dialog DC/font setup; later interactive shell clients use the same cataloged
    // role path instead of fixed pi checks.
    if uses_client_gdi {
        let gdi_va = win32k_glue::map_gdi_shared_handle_table_into_client(
            &mut nt_handler,
            pml4,
            pi,
        );
        let gdi_attributes =
            win32k_glue::map_gdi_user_attributes_into_client(&mut nt_handler, pml4, pi);
        if gdi_va != 0 && gdi_attributes {
            record_hosted_client_gdi_mapping(
                &mut nt_handler, pi, gdi_va, dispatch_client.logical_caller,
            );
        }
    }
    if sc.redirected_user_callback {
        sc.result = nt_user_callback::STATUS_PENDING as u32 as u64;
    } else if ok {
        sc.result = st; // pointer-width NtUser/NtGdi return value back to the caller
        if winlogon_gui_client && lp.msg.m0 == 0x1077 && st != 0 {
            observe_winlogon_completed_dispatch(
                win32k_glue::CompletedWin32kDispatch::new(lp.msg.m0, [a0, a1, a2, a3], sp, st),
                scratch_base,
            );
        }
        // ★ BATCH 45 — QUIESCE at the InitializeSAS-complete milestone. `UserSetLogonNotifyWindow`
        // (0x127c) is winlogon's DEFINING final interactive step: it registers its logon-notify
        // window, which happens exactly once after the SAS window exists. Past this, winlogon
        // enters its SAS message loop (an infinite NtUserGetMessage wait we don't service) and
        // never returns to the executive → the boot would never quiesce and the gate never runs
        // (the BATCH-44 620s timeout). This is the win32k analogue of the listener milestone
        // parks below: winlogon's TCB stays blocked at this proven-advanced steady state, the boot
        // quiesces, and the gate runs cleanly. Gated on the SAS HWND milestone so we only park
        // once winlogon actually created its window (never on the old NULL-HWND failure path).
        if winlogon_gui_client
            && lp.msg.m0 == 0x127c
            && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0
        {
            // UserSetLogonNotifyWindow success = the SAS window + logon-notify registration is
            // done. winlogon now runs the InitializeSAS tail (SetDefaultLanguage) + WinMain's
            // post-SAS setup (RemoveStatusMessage, GetSetupType, PostMessage(WLX_WM_SAS),
            // NtInitializeRegistry) then enters its GetMessage loop. Do NOT park here — let it
            // advance; the message-loop milestone park (0x1006/0x1001 above) is its real steady
            // state. (Reaching 0x127c-success now requires the PsLookup/gpidLogon fix, else the
            // logon-process access check would fail SetLogonNotifyWindow → InitializeSAS FALSE.)
            print_str(b"[wl-main] winlogon registered logon-notify window (0x127c) = SAS window ready -> advancing to post-SAS setup\n");
        }
    } else {
        sc.handled = false; // dispatch wall — stop with the SSN recorded
        sc.result = 0xC0000001;
    }
    }
    ControlFlow::Continue(())
}
