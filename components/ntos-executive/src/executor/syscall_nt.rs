//! The NT route of the syscall arm (issue #382, loop hoist).
//!
//! A service the native dispatcher or the ALPC table implements: argument capture, the
//! dispatch through `ExecNtHandler`, and the handler's post-actions.
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_flow::*;
use super::loop_receive::receive;
use super::*;

#[inline(never)]
pub(super) unsafe fn syscall_nt_route(
    lp: &mut LoopState<'_>,
    ev: &Event,
    call: &Syscall,
    sc: &mut SyscallOutcome,
    route: nt_syscall_abi::NativeIngressRoute,
) -> ControlFlow<Turn> {
    let mut nt_handler = &mut *lp.handler;
    let nt_dispatcher = lp.dispatcher;
    let fault_ep = lp.ingress.fault_ep;
    let delay_queue = lp.ingress.delay_queue;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let exe_images = &mut *lp.images.exe_images;
    let exe_image_catalog = &mut *lp.images.exe_image_catalog;
    let hosted_loaded_images_ptr = lp.images.hosted_loaded_images_ptr;
    let ntdll = lp.images.ntdll;
    let Event { event_runtime, pi, native_ingress_request, scratch_base, .. } = *ev;
    let Syscall {
        native_call_transport, resume_ip, sp, flags, syscall_reply_context, current_tid,
        table_entry, ..
    } = *call;
    let origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
    // x64 native syscall args: arg1=R10 (the stub's `mov r10,rcx`; RCX itself is the
    // syscall return address), arg2=RDX, arg3=R8, arg4=R9, then arg5+ on the caller's
    // stack at [rsp+0x28], [rsp+0x30], … RDX rides in m3; R8/R9/R10 + the stack come
    // from the IPC buffer / stack mirror.
    let mut argv = [0u64; nt_syscall_abi::MAX_STUB_ARGS as usize];
    argv[0] = get_recv_mr(9); // R10
    argv[1] = lp.msg.m3; // RDX
    argv[2] = get_recv_mr(7); // R8
    argv[3] = get_recv_mr(8); // R9
    let n = match route {
        nt_syscall_abi::NativeIngressRoute::Alpc(service) => service.argument_count(),
        nt_syscall_abi::NativeIngressRoute::Table => table_entry
            .expect("table route lost registered service").max_args as usize,
    }.min(argv.len());
    let mut stack_args_valid = true;
    let retained_arguments = nt_handler.active_synchronous_file_retry.as_ref()
        .and_then(|ingress| ingress.waiter().transfer_parameters)
        .map(|parameters| parameters.arguments);
    if let Some(arguments) = retained_arguments {
        // begin_ingress authenticated this exact service/thread/badge. These are the
        // invocation's original value arguments, not mutable retry stack or IPC words.
        if n != arguments.len() {
            stack_args_valid = false;
        } else {
            argv[..n].copy_from_slice(&arguments);
        }
    } else if native_call_transport {
        let request = native_ingress_request
            .expect("native dispatch lost its owned argument words");
        if request.length() < nt_syscall_abi::native_syscall_request_len(n as u8) as usize
            || n > nt_syscall_abi::MAX_STUB_ARGS as usize
        {
            stack_args_valid = false;
        } else {
            for (index, argument) in argv.iter_mut().take(n).enumerate() {
                *argument = request.argument(index)
                    .expect("validated native request lost an argument");
            }
        }
    } else {
        for i in 4..n {
            let Some(argument_va) = sp.checked_add(0x28 + (i as u64 - 4) * 8) else {
                stack_args_valid = false;
                break;
            };
            let mut bytes = [0u8; 8];
            if client_copyin_mapped(
                pi as u64,
                argument_va,
                &mut bytes,
                scratch_base,
            ) {
                argv[i] = u64::from_le_bytes(bytes);
            } else {
                stack_args_valid = false;
                break;
            }
        }
    }
    // Refresh the handler's per-call executive context, then clear the stop side-signal
    // + out-write queue so a migrated handler can raise them (group A/B signals).
    nt_handler.post_action = ExecPostAction::None;
    nt_handler.stop = false;
    assert!(nt_handler.current_apc_handoff.is_none(),
        "previous syscall leaked a current APC handoff");
    nt_handler.context_continue_redirected = false;
    nt_handler.user_timer_rearm_requested = false;
    nt_handler.job_time_rearm_requested = false;
    nt_handler.system_time_change = None;
    nt_handler.out_writes_n = 0;
    nt_handler.exe_spawn_request = None;
    nt_handler.exe_spawn_new_process = false;
    nt_handler.thread_spawn_request = None;
    nt_handler.wait_park_event = -1;
    nt_handler.wait_alertable = false;
    nt_handler.wait_timeout = PendingWaitTimeout::none();
    nt_handler.wait_park_count = 0;
    nt_handler.wait_park_all = false;
    nt_handler.keyed_wait_key = u64::MAX;
    nt_handler.keyed_wait_timeout = PendingWaitTimeout::none();
    nt_handler.keyed_release_wait_key = u64::MAX;
    nt_handler.keyed_release_wait_timeout = PendingWaitTimeout::none();
    nt_handler.delay_requested = false;
    nt_handler.delay_interval_100ns = 0;
    nt_handler.delay_alertable = false;
    nt_handler.thread_alert_wait = None;
    nt_handler.io_completion_park_port = -1;
    nt_handler.io_completion_key_out = 0;
    nt_handler.io_completion_apc_out = 0;
    nt_handler.io_completion_iosb_out = 0;
    nt_handler.io_completion_timeout = PendingWaitTimeout::none();
    nt_handler.io_signal_event = -1;
    assert!(
        nt_handler.pending_file_io_reservation.is_none(),
        "previous syscall leaked a pending File owner reservation"
    );
    assert!(nt_handler.pending_file_io_transfer.is_none(),
        "previous syscall retained an accepted File transfer");
    assert!(nt_handler.pending_native_directory_open_transfer.is_none(),
        "previous syscall retained a native directory Reply transfer");
    assert!(nt_handler.pending_native_file_target_transfer.is_none(),
        "previous syscall retained a native file target Reply transfer");
    assert!(nt_handler.pending_native_directory_effect_transfer.is_none(),
        "previous syscall retained a native directory effect Reply transfer");
    nt_handler.pending_file_io_wait = false;
    assert!(
        nt_handler.pending_driver_start_transfer.is_none(),
        "previous syscall leaked a driver START continuation reservation"
    );
    assert!(
        nt_handler.pending_pnp_operation_transfer.is_none(),
        "previous syscall leaked a PnP operation continuation reservation"
    );
    assert!(nt_handler.pending_synchronous_file_wait.is_none(),
        "previous syscall retained an unpublished File waiter");
    assert!(
        nt_handler.pending_file_cleanup_wait.is_none(),
        "previous syscall leaked a File cleanup continuation reservation"
    );
    assert!(
        nt_handler.pending_file_irp_drain.is_none(),
        "previous syscall leaked a File IRP drain reservation"
    );
    nt_handler.dbgk_block_request = false;
    nt_handler.pipe_endpoint_progress = false;
    nt_handler.lpc_endpoint_progress = false;
    nt_handler.lpc_reply_published = false;
    if let Some(stale) = nt_handler.lpc_receive_park.take() {
        lpc_receive_wait_cancel_reservation(stale.reservation);
        panic!("previous syscall leaked an LPC receive continuation reservation");
    }
    if let Some(stale) = nt_handler.lpc_connect_park.take() {
        lpc_connect_wait_cancel_reservation(stale.reservation);
        panic!("previous syscall leaked an LPC connect continuation reservation");
    }
    if let Some(stale) = nt_handler.lpc_request_park.take() {
        lpc_request_wait_cancel_reservation(stale.reservation);
        panic!("previous syscall leaked an LPC request continuation reservation");
    }
    let _ = lpc_connect_completion_drain(&mut nt_handler);
    let lock_preflight = if stack_args_valid && lp.msg.m0 == SSN_NT_LOCK_VM {
        crate::vm_lock_pagein_work::submit(&mut nt_handler,
            &argv[..4], resume_ip, sp, flags, native_call_transport)
            .map(|()| true)
    } else { Ok(false) };
    let vm_copy_preflight = if stack_args_valid
        && matches!(lp.msg.m0, SSN_NT_READ_VM | SSN_NT_WRITE_VM)
    {
        crate::vm_copy_work::submit(&mut nt_handler, &argv[..5],
            lp.msg.m0 == SSN_NT_READ_VM, resume_ip, sp, flags,
            native_call_transport).map(|()| true)
    } else { Ok(false) };
    let copy_preflight = if stack_args_valid
        && matches!(lp.msg.m0, SSN_NT_QUERY_SYSTEM_INFO | SSN_NT_QUERY_DEFAULT_LOCALE)
    {
        crate::native_image_pagein_work::submit_syscall_copy(
            &mut nt_handler, pi, lp.msg.m0 as u32,
            [argv[0], argv[1], argv[2], argv[3]],
            origin, resume_ip, sp, flags, native_call_transport,
        )
    } else { Ok(false) };
    if matches!(lock_preflight, Ok(true)) {
        thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
        {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            crate::vm_lock_pagein_work::redrive(&mut nt_handler);
        }
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    } else if matches!(vm_copy_preflight, Ok(true)) {
        thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
        {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            crate::vm_copy_work::redrive(&mut nt_handler);
        }
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    } else if matches!(copy_preflight, Ok(true)) {
        thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
        {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            crate::native_image_pagein_work::redrive(&mut nt_handler, &nt_dispatcher);
        }
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    } else if let Err(status) = lock_preflight {
        sc.result = status as u64;
    } else if let Err(status) = vm_copy_preflight {
        sc.result = status as u64;
    } else if let Err(status) = copy_preflight {
        sc.result = status as u64;
    } else if !stack_args_valid {
        if lp.msg.m0 as u32 == SSN_NT_QUERY_KEY as u32 {
            let arguments = [argv[0], argv[1], argv[2], argv[3], argv[4]];
            crate::registry_query_diagnostics::reject(
                &nt_handler, b"argument-capture", &arguments, 0xC000_0005, None,
            );
        }
        sc.result = 0xC000_0005;
    } else if nt_handler.active_synchronous_file_retry.as_ref()
        .is_some_and(|ingress| !ingress.matches_handle(argv[0]))
    {
        sc.result = nt_fs::STATUS_INVALID_PARAMETER as u64;
    } else if nt_syscall_abi::NativeAlpcService::from_call(lp.msg.m0, native_call_transport)
        == Some(nt_syscall_abi::NativeAlpcService::CreatePort)
    {
        sc.handled = true;
        if lp.diag.alpc_create_ingress_trace.fetch_add(1, Ordering::Relaxed) < 8 {
            print_str(b"[native-alpc-create-ingress] badge=");
            print_u64(lp.msg.badge);
            print_str(b" output=0x");
            print_hex_u64(argv[0]);
            print_str(b" object_attributes=0x");
            print_hex_u64(argv[1]);
            print_str(b" port_attributes=0x");
            print_hex_u64(argv[2]);
            print_str(b"\n");
        }
        match crate::native_alpc_create_work::begin(&mut nt_handler,
            [argv[0], argv[1], argv[2]]) {
            Err(status) => sc.result = status as u64,
            Ok(()) => {
                thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
                {
                    let _message = crate::ipc_message::SavedMessageBuffer::capture();
                    crate::native_alpc_create_work::redrive(&mut nt_handler);
                }
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
    } else if nt_syscall_abi::NativeAlpcService::from_call(lp.msg.m0, native_call_transport)
        == Some(nt_syscall_abi::NativeAlpcService::ConnectPort)
    {
        sc.handled = true;
        print_str(b"[native-alpc-connect-ingress] badge=");
        print_u64(lp.msg.badge);
        print_str(b" tcb=0x");
        print_hex_u64(event_runtime.tcb);
        print_str(b" flags=0x");
        print_hex_u64(argv[4]);
        print_str(b"\n");
        match crate::native_alpc_connect_accept_work::begin_connect(&mut nt_handler,
            [argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6],
                argv[7], argv[8], argv[9], argv[10]]) {
            Err(status) => {
                print_str(b"[native-alpc-connect-begin] rejected status=0x");
                print_hex_u64(status as u64);
                print_str(b"\n");
                sc.result = status as u64;
            }
            Ok(()) => {
                print_str(b"[native-alpc-connect-begin] retained\n");
                thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
                {
                    let _message = crate::ipc_message::SavedMessageBuffer::capture();
                    crate::native_alpc_connect_accept_work::redrive(&mut nt_handler);
                }
                print_str(b"[native-alpc-connect-begin] redrove\n");
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
    } else if nt_syscall_abi::NativeAlpcService::from_call(lp.msg.m0, native_call_transport)
        == Some(nt_syscall_abi::NativeAlpcService::AcceptConnectPort)
    {
        sc.handled = true;
        match crate::native_alpc_connect_accept_work::begin_accept(&mut nt_handler,
            [argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6],
                argv[7], argv[8]]) {
            Err(status) => sc.result = status as u64,
            Ok(()) => {
                thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
                {
                    let _message = crate::ipc_message::SavedMessageBuffer::capture();
                    crate::native_alpc_connect_accept_work::redrive(&mut nt_handler);
                }
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
    } else if nt_syscall_abi::NativeAlpcService::from_call(lp.msg.m0, native_call_transport)
        == Some(nt_syscall_abi::NativeAlpcService::SendWaitReceivePort)
    {
        sc.handled = true;
        let ingress = crate::native_alpc_send_receive_work::begin(&mut nt_handler,
            [argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]]);
        let trace = lp.diag.alpc_send_ingress_trace.fetch_add(1, Ordering::Relaxed);
        if trace < 16 {
            let mut return_bytes = [0u8; 8];
            let return_readable = nt_handler.xas_read(sp, &mut return_bytes);
            print_str(b"[native-alpc-send-ingress] #");
            print_u64(trace);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" port=0x");
            print_hex_u64(argv[0]);
            print_str(b" raw-mr2=0x");
            print_hex_u64(native_ingress_request
                .and_then(|request| request.word(2)).unwrap_or(0));
            print_str(b" caller=0x");
            print_hex_u64(if return_readable { u64::from_le_bytes(return_bytes) }
                else { 0 });
            print_str(b" flags=0x");
            print_hex_u64(argv[1]);
            print_str(b" send=0x");
            print_hex_u64(argv[2]);
            print_str(b" receive=0x");
            print_hex_u64(argv[4]);
            print_str(b" size=0x");
            print_hex_u64(argv[5]);
            print_str(b" timeout=0x");
            print_hex_u64(argv[7]);
            print_str(b" status=0x");
            print_hex_u64(ingress.as_ref().err().copied().unwrap_or(0x103) as u64);
            print_str(b"\n");
        }
        match ingress {
            Err(status) => sc.result = status as u64,
            Ok(()) => {
                thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
                let alpc_reply_committed = {
                    let _message = crate::ipc_message::SavedMessageBuffer::capture();
                    crate::native_alpc_send_receive_work::redrive(&mut nt_handler)
                };
                if alpc_reply_committed.is_some() {
                    let _ = lpc_component_reply_commit_drain(&mut nt_handler);
                }
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
    } else if native_call_transport && lp.msg.m0 as u32 == SSN_NT_CLOSE as u32
        && crate::native_alpc_close_work::recognizes(&nt_handler, argv[0])
    {
        sc.handled = true;
        match crate::native_alpc_close_work::begin(&mut nt_handler, argv[0]) {
            Err(status) => sc.result = status as u64,
            Ok(()) => {
                thread_wait_state_park_badge_waiting(&mut nt_handler, lp.msg.badge);
                {
                    let _message = crate::ipc_message::SavedMessageBuffer::capture();
                    crate::native_alpc_close_work::redrive(&mut nt_handler);
                }
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
    } else {
        crate::probe_reset();
        let dispatch_generation = nt_handler.hosted_process_generation(pi);
        let installer_span = installer_child_span_census::begin(
            &nt_handler, pi, current_tid, lp.msg.badge, lp.msg.m0 as u32);
        let dispatch_started = crate::disk_census_ticks();
        let res =
            nt_dispatcher.dispatch(lp.msg.m0 as u32, &argv[..n], &origin, &mut nt_handler);
        sc.current_apc_handoff = nt_handler.current_apc_handoff.take();
        let elapsed_ticks = crate::disk_census_ticks().wrapping_sub(dispatch_started);
        crate::record_native_dispatch_ticks(lp.msg.m0, elapsed_ticks);
        native_process_time_census::record_dispatch(
            pi, dispatch_generation,
            table_entry.map(|entry| entry.service), res.status,
            elapsed_ticks,
        );
        installer_child_span_census::returned(
            &nt_handler, installer_span, lp.msg.badge, lp.msg.m0 as u32, res.status);
        sc.result = res.status as u64;
        if lp.msg.m0 == SSN_NT_CREATE_THREAD {
            let caller = nt_handler.thread_runtime.executable_by_tid(current_tid)
                .filter(|runtime| runtime.pi == pi && runtime.badge == lp.msg.badge)
                .map(|runtime| runtime.binding());
            if caller.is_some_and(|caller| unsafe {
                crate::exec_handler::initial_thread_creation::take_retry_transferred(caller)
            }) {
                assert_eq!(res.status, nt_user_callback::STATUS_PENDING as u32);
                assert_eq!(nt_handler.out_writes_n, 0,
                    "retained no-effect process callout has no caller copyout");
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
                crate::exec_handler::initial_thread_creation::redrive_retry_no_effect(
                    &mut nt_handler,
                );
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            let suspended_target = caller.and_then(|caller| {
                crate::exec_handler::initial_thread_creation::suspended_for_caller(
                    &nt_handler, caller,
                )
            });
            if res.status == nt_user_callback::STATUS_PENDING as u32 {
                print_str(b"[initial-create-handoff] caller/target/pi/tid/badge=");
                print_u64(caller.is_some() as u64);
                print_str(b"/");
                print_u64(suspended_target.is_some() as u64);
                print_str(b"/");
                print_u64(pi as u64);
                print_str(b"/");
                print_u64(current_tid);
                print_str(b"/");
                print_u64(lp.msg.badge);
                print_str(b"\n");
                assert!(suspended_target.is_some(),
                    "pending initial creation must retain its exact caller Reply");
            }
            if let Some(target) = suspended_target {
                assert_eq!(res.status, nt_user_callback::STATUS_PENDING as u32);
                assert_eq!(nt_handler.out_writes_n, 0,
                    "suspended initial creation cannot publish output before provider return");
                let handoff = admit_pending_win32k_dispatch(
                    &mut nt_handler,
                    HostedContinuationDestination::InitialThread(
                        nt_user_host::process_create_callout::InitialThreadReplyOrigin::new(
                            caller.expect("suspended initial creation has exact caller"), target,
                        ).expect("foreign initial Reply requires distinct valid owners"),
                    ),
                );
                if handoff.retained_failure {
                    // The pending win32k snapshot and original Reply remain owned.
                    // Never turn this refusal into a process-creation reply.
                    procs[pi].faults = lp.exit.faults;
                    procs[pi].first = lp.exit.first;
                    procs[pi].ntfaults = lp.exit.ntfaults;
                    pfilled[pi] = *filled_pages;
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = lp.msg.m0;
                    lp.exit.record(b"win32k-initial-dispatch-retained");
                    return ControlFlow::Break(Turn::Exit);
                }
                assert!(handoff.parked || handoff.callback_suspended,
                    "suspended process callout lost its native yield owner");
                assert!(!handoff.callback_suspended,
                    "initial process callout user callback requires retained source Reply transfer");
                sc.component_suspension_admitted_dispatch_id = handoff.admitted_dispatch_id;
                sc.component_suspension_park_request = handoff.parked;
                sc.redirected_user_callback = handoff.parked;
            }
        }
        if crate::registry_mutation_work::take_transferred() {
            // The durable mutation owner already captured and rotated this Reply.
            // STATUS_PENDING is internal state, never the syscall's terminal reply.
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            crate::registry_mutation_work::redrive(&mut nt_handler, &mut *delay_queue);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if crate::mutable_hive_mutation_work::take_transferred() {
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            crate::mutable_hive_mutation_work::redrive(&mut nt_handler, &mut *delay_queue);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if crate::section_metadata_work::take_transferred() {
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            crate::section_metadata_work::redrive(&mut nt_handler, &mut *delay_queue);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if crate::process_image_snapshot_work::take_transferred() {
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            crate::process_image_snapshot_work::redrive(&mut nt_handler,
                &mut *delay_queue, ntdll, fault_ep, procs, exe_images,
                &*exe_image_catalog, hosted_loaded_images_ptr);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if pi == 3 && lp.msg.m0 == 161 {
            let trace = SERVICES_NQIP_TRACE.fetch_add(1, Ordering::Relaxed);
            if trace < 24 || trace.is_power_of_two() {
                print_str(b"[services-nqip] #");
                print_u64(trace);
                print_str(b" badge=");
                print_u64(lp.msg.badge);
                print_str(b" handle=0x");
                print_hex_u64(argv[0]);
                print_str(b" class=");
                print_u64(argv[1]);
                print_str(b" buf=0x");
                print_hex_u64(argv[2]);
                print_str(b" len=0x");
                print_hex_u64(argv[3]);
                print_str(b" retlen=0x");
                print_hex_u64(argv[4]);
                print_str(b" status=0x");
                print_hex(sc.result as u32);
                if (argv[1] == 12 || argv[1] == 36) && argv[2] != 0 {
                    let mut value_bytes = [0u8; 4];
                    if client_copyin_mapped(
                        pi as u64,
                        argv[2],
                        &mut value_bytes,
                        scratch_base,
                    ) {
                        print_str(b" value=0x");
                        print_hex(u32::from_le_bytes(value_bytes));
                    } else {
                        print_str(b" value=<unreadable>");
                    }
                }
                print_str(b" sp=0x");
                print_hex_u64(sp);
                print_str(b" resume-ip=0x");
                print_hex_u64(resume_ip);
                print_str(b"\n");
            }
        }
        if nt_handler.context_continue_redirected {
            sc.redirected_context_continue = true;
        }
        if nt_handler.stop {
            sc.handled = false; // handler couldn't service → stop with the SSN recorded
        }
    }
    // A successful self-termination is a control-flow action, not a status-returning
    // syscall. First delete/replace the Reply object bound to this fault (so no send can
    // resume it), then suspend/delete the exact badge-selected TCB, and receive the next
    // caller immediately. Remote termination tears down its target but still replies to
    // the caller through the normal tail below.
    let job_terminations = core::mem::take(&mut nt_handler.pending_job_terminations);
    let caller_job_terminated = job_terminations.contains(&(pi as u8));
    let mut post_action = nt_handler.post_action;
    if caller_job_terminated
        && !matches!(post_action, ExecPostAction::CriticalTermination { .. })
    {
        post_action = ExecPostAction::TerminateProcess {
            process_index: pi as u8,
            current_tid: nt_handler.current_tid,
            drop_reply: true,
        };
    }
    let apc_owned_terminating_reply = sc.current_apc_handoff.is_some()
        && matches!(post_action,
            ExecPostAction::TerminateCurrentThread { .. }
            | ExecPostAction::TerminateProcess { drop_reply: true, .. }
            | ExecPostAction::CriticalTermination { .. });
    if apc_owned_terminating_reply {
        crate::current_apc::cancel_tail(
            &mut nt_handler,
            sc.current_apc_handoff.take().expect("terminating APC handoff missing"),
        );
    }
    if let Some(mut ingress) = nt_handler.active_synchronous_file_retry.take() {
        let identity = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
            .reject_ingress(&mut ingress, sc.result as u32)
            .expect("unconsumed File ingress lost its exact claim");
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
        synchronous_file_cancellation::drive(&mut nt_handler, identity);
    }
    if let Some((mut waiter, reservation)) = nt_handler.pending_synchronous_file_wait.take() {
        // Counted acquisition must be published or rolled back before job teardown
        // and post-action exits can release another owner of this File.
        if !matches!(post_action, ExecPostAction::None) {
            synchronous_file_cancellation::cancel_unpublished(
                &mut nt_handler, reservation, waiter,
            );
        } else {
            if waiter.native_call_transport {
                waiter.reply_mrs[0] = waiter.service_number as u64;
                waiter.reply_mrs[1] = sp;
                waiter.reply_mrs[2] = argv[0];
                waiter.reply_mrs[3] = argv[1];
                waiter.reply_mrs[4] = argv[2];
                waiter.reply_mrs[5] = argv[3];
            } else {
                waiter.reply_mrs = syscall_reply_context.regs;
            }
            if synchronous_file_wait_park(waiter, reservation) {
                sc.synchronous_file_wait_parked = true;
                let waiter_tid = nt_handler.current_tid;
                let apc_interrupted =
                    reconcile_user_apc_file_wait(&mut nt_handler, waiter_tid);
                if !apc_interrupted {
                    trace_smss_file_busy_wait(waiter);
                    trace_indefinite_wait_park(
                        &nt_handler, lp.msg.badge, live_top_badges(&nt_handler),
                        lp.parks.crash_parked, lp.parks.wait_parked,
                    );
                    mark_wait_parked(
                        &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                    )?;
                }
            } else {
                PENDING_FILE_IO_TRANSFER_FAILURES.fetch_add(1, Ordering::Relaxed);
                synchronous_file_cancellation::cancel_unpublished(
                    &mut nt_handler, reservation, waiter,
                );
                sc.result = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES as u64;
            }
        }
    }
    let handoff = file_dispatch_handoff::before_post_action(
        &mut nt_handler, post_action, native_call_transport, resume_ip, sp, flags,
    );
    if handoff.inline_retirement_needs_redrive() {
        inline_file_retirement::redrive(&mut nt_handler);
    }
    sc.published_file_io = file_dispatch_handoff::finish_after_inline_retirement(
        &mut nt_handler, handoff,
    );
    let post_action_process = match post_action {
        ExecPostAction::TerminateProcess { process_index, .. } => Some(process_index),
        _ => None,
    };
    teardown_job_terminated_processes(
        job_terminations,
        pi as u8,
        post_action_process,
        &mut *delay_queue,
        &mut nt_handler,
    );
    match post_action {
        ExecPostAction::ContinueCurrentThread {
            tid,
            tcb,
            context,
        } => {
            // The kernel validates before mutation, then installs state and cancels
            // the old reply in the same restart. Never delete that reply beforehand.
            let applied = if nt_handler.hosted_thread_tcb(tid) == Some(tcb) {
                crate::spawn_hosts::shared_ingress::owner::runtime::restart_hosted(
                    REPLY_MAIN_SLOT.load(Ordering::Relaxed), tcb, &context,
                ).expect("uncertain context restart retains its hosted Call owner")
            } else {
                Err(u64::MAX)
            };
            if applied.is_ok() {
                print_str(b"[seh-continue] tid=");
                print_u64(tid);
                print_str(b" rip=0x");
                print_hex_u64(context.registers[nt_user_callback::USER_CONTEXT_RIP]);
                print_str(b" rsp=0x");
                print_hex_u64(context.registers[nt_user_callback::USER_CONTEXT_RSP]);
                print_str(b" -> recv without reply\n");
                procs[pi].faults = lp.exit.faults;
                procs[pi].first = lp.exit.first;
                procs[pi].ntfaults = lp.exit.ntfaults;
                pfilled[pi] = *filled_pages;
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            print_str(b"[seh-continue] failed tid=");
            print_u64(tid);
            print_str(b" write=");
            print_u64(applied.unwrap_err());
            print_str(b"\n");
            sc.redirected_context_continue = false;
            nt_handler.context_continue_redirected = false;
            sc.result = 0xC000_0001;
        }
        ExecPostAction::TerminateCurrentThread { tid } => {
            assert_eq!(tcb_suspend_r(event_runtime.tcb), 0,
                "self termination must retain acknowledged stop before Reply cancellation");
            let trace_index =
                THREAD_TERM_ROOT_TCB_TRACE.fetch_add(1, Ordering::Relaxed);
            if trace_index < 8 {
                crate::win32k_glue::trace_hosted_tcb_debug_state(
                    b"thread-term-root-before",
                    1,
                    REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                );
            }
            let reply_dropped = !apc_owned_terminating_reply
                && drop_current_hosted_reply();
            let mechanism_deleted =
                terminate_hosted_thread_mechanism(tid, &mut *delay_queue, &mut nt_handler);
            if reply_dropped && mechanism_deleted {
                PM_TERMINATE_THREAD_NO_REPLY.fetch_add(1, Ordering::Relaxed);
            }
            print_str(b"[thread-term] self-post tid=");
            print_u64(tid);
            print_str(b" reply-dropped=");
            print_u64(reply_dropped as u64);
            print_str(b" apc-owned=");
            print_u64(apc_owned_terminating_reply as u64);
            print_str(b" mechanism-deleted=");
            print_u64(mechanism_deleted as u64);
            print_str(b" -> recv without reply\n");
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            if trace_index < 8 {
                crate::win32k_glue::trace_hosted_tcb_debug_state(
                    b"thread-term-root-recv",
                    1,
                    new_reply,
                );
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        ExecPostAction::TerminateRemoteThread { tid } => {
            let _ =
                terminate_hosted_thread_mechanism(tid, &mut *delay_queue, &mut nt_handler);
        }
        ExecPostAction::TerminateProcess {
            process_index,
            current_tid,
            drop_reply,
        } => {
            if drop_reply {
                assert_eq!(tcb_suspend_r(event_runtime.tcb), 0,
                    "process self termination must stop before Reply cancellation");
            }
            let preserve_tid = if current_tid != 0 {
                Some(current_tid)
            } else {
                None
            };
            let reply_dropped = if drop_reply && !apc_owned_terminating_reply {
                drop_current_hosted_reply()
            } else {
                false
            };
            if let Some(pid) = nt_handler.pm_pid_for_pi(process_index as usize) {
                if nt_handler.pm.is_process_signaled(pid) {
                    if let Some(status) = nt_handler.pm.process(pid)
                        .and_then(|process| process.exit_status) {
                        let _ = nt_handler.observe_install_pipe_child_terminal(
                            process_index as usize, status,
                        );
                    }
                }
            }
            let reclaimed = terminate_hosted_process_mechanisms(
                process_index,
                preserve_tid,
                &mut *delay_queue,
                &mut nt_handler,
            );
            let current_deleted = if drop_reply && current_tid != 0 {
                terminate_hosted_thread_mechanism(
                    current_tid,
                    &mut *delay_queue,
                    &mut nt_handler,
                )
            } else {
                false
            };
            let final_process_teardown = drop_reply || current_tid == 0;
            if final_process_teardown {
                if let Some(pid) = nt_handler.pm_pid_for_pi(process_index as usize) {
                    let _ = nt_handler.try_delete_hosted_process_object(pid);
                }
            }
            nt_handler.refresh_process_manager_gates();
            if drop_reply && reply_dropped && current_deleted {
                PM_TERMINATE_PROCESS_NO_REPLY.fetch_add(1, Ordering::Relaxed);
                if process_index < 64 {
                    PM_TERMINATE_PROCESS_NO_REPLY_PIS
                        .fetch_or(1u64 << process_index, Ordering::Relaxed);
                }
            }
            print_str(b"[process-term] pi=");
            print_u64(process_index as u64);
            print_str(b" current_tid=");
            print_u64(current_tid);
            print_str(b" drop_reply=");
            print_u64(drop_reply as u64);
            print_str(b" reply-dropped=");
            print_u64(reply_dropped as u64);
            print_str(b" apc-owned=");
            print_u64(apc_owned_terminating_reply as u64);
            print_str(b" reclaimed=");
            print_u64(reclaimed as u64);
            print_str(b" current-deleted=");
            print_u64(current_deleted as u64);
            print_str(b" runtimes-pending=");
            print_u64(
                nt_handler
                    .thread_runtime
                    .has_process(process_index as usize)
                    as u64,
            );
            print_str(b"\n");
            if drop_reply {
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
        }
        ExecPostAction::CriticalTermination { code, object } => {
            assert_eq!(tcb_suspend_r(event_runtime.tcb), 0,
                "critical termination must stop before Reply cancellation");
            let reply_dropped = !apc_owned_terminating_reply
                && drop_current_hosted_reply();
            // A critical process can bugcheck while it is running a win32k user-mode
            // callback; unwind those continuations so win32k is idle (not stranded in its
            // callback receive loop) for the gate. No-op when it held none.
            let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
            print_str(b"[critical-termination] bugcheck=0x");
            print_hex(code);
            print_str(b" object=0x");
            print_hex((object >> 32) as u32);
            print_hex(object as u32);
            print_str(b" reply-dropped=");
            print_u64(reply_dropped as u64);
            print_str(b" -> fatal stop\n");
            lp.exit.stop = code as u64;
            lp.exit.record(b"fatal-stop");
            return ControlFlow::Break(Turn::Exit);
        }
        ExecPostAction::None => {}
    }
    let durable_status = finalize_service_loop_state(&mut nt_handler);
    if durable_status != nt_fs::STATUS_SUCCESS {
        sc.result = durable_status as u64;
    }
    // PROFILE FRONTIER (batch 58): once winlogon has resolved the profiles root, trace
    // every NATIVE syscall of its that FAILS, with the SSN and the NTSTATUS. `userenv`
    // only ever prints `GetLastError()`, and several distinct NTSTATUSes collapse onto
    // the same DOS error, so the frontier is unmeasurable without this.
    if pi == 2
        && lp.msg.m0 < 0x1000
        && sc.result != 0
        // STATUS_NO_MORE_FILES ends every legitimate `FindNextFileW` loop and
        // STATUS_INVALID_INFO_CLASS is a probe kernel32 makes and ignores; both flood
        // the window without being frontier information.
        && sc.result != 0x8000_0006
        && sc.result != 0xC000_0003
        && crate::writable_fs::PROFILE_USER_DIR_CREATED.load(Ordering::Relaxed) != 0
        // A SECOND budget opens once the user hive is loaded: the profile-copy phase
        // exhausts the first one long before winlogon's remaining `HandleLogon` steps
        // run, and those steps fail through `WARN`, which the binary does not print.
        && (PROFILE_FRONTIER_TRACED.fetch_add(1, Ordering::Relaxed) < 32
            || (post_profile_phase()
                && POST_PROFILE_FRONTIER_TRACED.fetch_add(1, Ordering::Relaxed) < 96))
    {
        print_str(b"[profile-frontier] winlogon SSN=");
        print_u64(lp.msg.m0);
        print_str(b" arg4=");
        print_u64(get_recv_mr(8));
        print_str(b" stack5=");
        print_u64(smss_stack_read(get_recv_mr(16) + 0x28));
        print_str(b" -> status=0x");
        print_hex(sc.result as u32);
        print_str(b"\n");
    }
    // Bump-heap pressure tripwire. Ownership-based frees can reuse lower addresses, but
    // the bump frontier still exposes growth of the allocator's mapped working set.
    let heap_watermark = allocator::mark();
    if heap_watermark
        >= HEAP_WATERMARK_REPORTED.load(Ordering::Relaxed) as usize + 0x2_0000
    {
        HEAP_WATERMARK_REPORTED.store(heap_watermark as u64, Ordering::Relaxed);
        print_str(b"[heap] executive bump high-water=");
        print_u64(heap_watermark as u64);
        print_str(b" cap=");
        print_u64(allocator::HEAP_FRAMES * 0x1000);
        print_str(b"\n");
    }
    // Thread creation is a cross-subsystem transaction. Mechanism admission, MM/Ps
    // commitment, ETHREAD activation, and handle publication all complete before any
    // success out-param is copied to the caller.
    if let Some(request) = nt_handler.thread_spawn_request.take() {
        if let Err(status) =
            spawn_requested_local_thread(&mut nt_handler, request, &*procs, fault_ep)
        {
            sc.result = u64::from(status);
        }
    }
    if let Some(request) = nt_handler.remote_thread_request.take() {
        if let Err(status) =
            spawn_requested_remote_thread(&mut nt_handler, request, fault_ep)
        {
            sc.result = u64::from(status);
        }
    }
    // Drain queued out-param writes (group B2): csrss out-ptrs may be arbitrary VAs that
    // need a persistent image-page alias; other hosted processes can also return values
    // to DLL globals. Use the handler's common cross-address-space writer for both.
    for k in 0..nt_handler.out_writes_n {
        let (ptr, val) = nt_handler.out_writes[k];
        if !nt_handler.xas_write_u64(ptr, val) {
            sc.result = 0xC000_0005;
            print_str(b"[copyout] failed pi=");
            print_u64(pi as u64);
            print_str(b" ptr=0x");
            print_hex((ptr >> 32) as u32);
            print_hex(ptr as u32);
            print_str(b"\n");
        }
    }
    // Checkpoint B: NtWaitForSingleObject on an unsignaled real event asked to PARK this
    // caller. Latch it for the reply site (the actual reply-cap steal happens there where
    // resume_ip/sp/flags are known).
    if nt_handler.wait_park_event >= 0 {
        sc.park_wait_event = nt_handler.wait_park_event;
        sc.park_wait_alertable = nt_handler.wait_alertable;
        sc.park_wait_deadline = nt_handler.wait_timeout.deadline();
    }
    if nt_handler.wait_park_count > 0 {
        sc.park_wait_set_n = nt_handler.wait_park_count;
        sc.park_wait_set_all = nt_handler.wait_park_all;
        sc.park_wait_alertable = nt_handler.wait_alertable;
        sc.park_wait_deadline = nt_handler.wait_timeout.deadline();
        sc.park_wait_set[..sc.park_wait_set_n]
            .copy_from_slice(&nt_handler.wait_park_objects[..sc.park_wait_set_n]);
        sc.park_wait_indices[..sc.park_wait_set_n]
            .copy_from_slice(&nt_handler.wait_park_result_indices[..sc.park_wait_set_n]);
    }
    if nt_handler.keyed_wait_key != u64::MAX {
        sc.park_keyed_wait_key = nt_handler.keyed_wait_key;
        sc.park_keyed_wait_deadline = nt_handler.keyed_wait_timeout.deadline();
    }
    if nt_handler.keyed_release_wait_key != u64::MAX {
        sc.park_keyed_release_wait_key = nt_handler.keyed_release_wait_key;
        sc.park_keyed_release_wait_deadline =
            nt_handler.keyed_release_wait_timeout.deadline();
    }
    if nt_handler.delay_requested {
        let now = nt_time_snapshot();
        let deadline = nt_delay_execution::due_time(
            nt_handler.delay_interval_100ns,
            now.monotonic_100ns,
            now.system_time_100ns,
        );
        if !deadline.is_due(now) {
            sc.park_delay_deadline = Some(deadline);
        }
    }
    sc.park_thread_alert_deadline = nt_handler.thread_alert_wait.take();
    thread_alert::redrive(&mut nt_handler);
    if nt_handler.io_completion_park_port >= 0 {
        sc.park_io_completion_port = nt_handler.io_completion_park_port;
        sc.park_io_completion_key_out = nt_handler.io_completion_key_out;
        sc.park_io_completion_apc_out = nt_handler.io_completion_apc_out;
        sc.park_io_completion_iosb_out = nt_handler.io_completion_iosb_out;
        sc.park_io_completion_deadline = nt_handler.io_completion_timeout.deadline();
    }
    let _ = unsafe { io_completion_deliver(&mut nt_handler) };
    if nt_handler.io_signal_event >= 0 {
        let _ = wait_wake_dispatcher_set(&mut nt_handler);
    }
    if let Some(transfer) = nt_handler.pending_driver_start_transfer.take() {
        sc.transfer_pending_driver_start = Some(transfer);
    }
    sc.transfer_native_directory_open = nt_handler.pending_native_directory_open_transfer.take();
    sc.transfer_native_file_target = nt_handler.pending_native_file_target_transfer.take();
    sc.transfer_native_directory_effect = nt_handler.pending_native_directory_effect_transfer.take();
    if let Some(transfer) = nt_handler.pending_pnp_operation_transfer.take() {
        sc.transfer_pending_pnp_operation = Some(transfer);
    }
    if let Some((pending, reservation)) = nt_handler.pending_file_irp_drain.take() {
        sc.transfer_file_irp_drain = Some((pending, reservation));
    }
    if let Some((file_id, reservation)) = nt_handler.pending_file_cleanup_wait.take() {
        let pending = nt_io_manager::PendingFileCleanupWait {
            file_id,
            pi: pi as u32,
            tid: nt_handler.current_tid,
            badge: lp.msg.badge,
            ..nt_io_manager::PendingFileCleanupWait::default()
        };
        sc.transfer_file_cleanup_wait = Some((pending, reservation));
    }
    if nt_handler.system_time_change.take().is_some() {
        publish_kuser_clocks();
        exec_handler::publish_time_zone(
            &nt_handler.time_zone_information,
            nt_system_time_100ns(),
        );
        let _ = delay_timer_rearm_and_drain_overdue(&mut *delay_queue, &mut nt_handler);
    } else if nt_handler.user_timer_rearm_requested
        || nt_handler.job_time_rearm_requested
    {
        delay_timer_rearm(&*delay_queue, &nt_handler);
    }
    sc.park_lpc_receive = nt_handler.lpc_receive_park.take();
    sc.park_lpc_connect = nt_handler.lpc_connect_park.take();
    sc.park_lpc_request = nt_handler.lpc_request_park.take();
    if nt_handler.dbgk_block_request {
        sc.park_dbgk_reporter = true;
    }
    redrive_global_post_syscall_work(&mut nt_handler);
    // The hosted-exe lane reserved a spawn after validating the owner-local file ->
    // section -> process transition in `exe_images`. The remaining per-image policy is
    // the address-space descriptor; handle publication and ProcessManager wiring are
    // common for csrss/winlogon and later Win32 children.
    if let Some(request) = nt_handler.exe_spawn_request {
        let new_process = nt_handler.exe_spawn_new_process;
        match hosted_spawn_uncertainty::prepare(&mut nt_handler, request) {
            Ok(prepared) => match publish_reserved_hosted_exe(request,
                &*exe_image_catalog, hosted_loaded_images_ptr, ntdll, fault_ep,
                procs, &mut nt_handler, exe_images)
            {
                Ok((process_handle, is_csrss)) => {
                    hosted_spawn_uncertainty::release_unentered(&mut nt_handler, prepared);
                    if is_csrss { lp.procs.csrss_process_handle = process_handle; }
                }
                Err(HostedExeSpawnError::Unentered(status)) => {
                    hosted_spawn_uncertainty::release_unentered(&mut nt_handler, prepared);
                    assert!(nt_handler.abort_unentered_hosted_exe(
                        request, new_process),
                        "unentered hosted spawn lost its exact reservation");
                    sc.result = u64::from(status);
                }
                Err(HostedExeSpawnError::Entered(status)) => {
                    hosted_spawn_uncertainty::retain_entered(prepared, status);
                }
                Err(HostedExeSpawnError::EnteredAbortable(status)) => {
                    hosted_spawn_uncertainty::retain_definite(
                        &nt_handler, prepared, status,
                    );
                }
            },
            Err(status) => {
                assert!(nt_handler.abort_unentered_hosted_exe(
                    request, new_process),
                    "preflighted hosted spawn lost its exact reservation");
                sc.result = u64::from(status);
            }
        }
    }
    ControlFlow::Continue(())
}
