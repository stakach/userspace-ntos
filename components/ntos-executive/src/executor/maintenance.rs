//! Between-event maintenance of the service loop (issue #382, loop hoist).
//!
//! Everything a turn does before it admits an event: the root-turn fences, restoration of a
//! retained receive boundary, queued-callback and AddDevice root turns, IRQ, timer and
//! redrive passes, the progress watchdog and durability. It yields the ingress binding the
//! turn admitted, if any, and the captured native request.
//!
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_flow::*;
use super::loop_receive::receive;
use super::*;
use crate::executor::local;

/// What maintenance hands to admission.
pub(super) type Maintained =
    (Option<HostedThreadRuntime>, Option<nt_syscall_abi::NativeSyscallRequest>);

// TCG device setup can spend more than 45 seconds between finite publication
// milestones. Keep this diagnostic window finite while the installer frontier
// is investigated; the outer boot harness bounds the whole run to one hour.
const STALL_BUDGET_100NS: u64 = 180 * 10_000_000;

#[inline(never)]
pub(super) unsafe fn maintain(
    lp: &mut LoopState<'_>,
) -> ControlFlow<Turn, Maintained> {
    let mut nt_handler = &mut *lp.handler;
    let nt_dispatcher = lp.dispatcher;
    let fault_ep = lp.ingress.fault_ep;
    let delay_queue = lp.ingress.delay_queue;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let exe_images = &mut *lp.images.exe_images;
    let exe_image_catalog = &mut *lp.images.exe_image_catalog;
    let hosted_loaded_images = &mut *lp.images.hosted_loaded_images;
    let hosted_loaded_images_ptr = lp.images.hosted_loaded_images_ptr;
    let reg = &mut *lp.images.reg;
    let ntdll = lp.images.ntdll;
    let queued_callback_fences_providers = root_queued_callback_exclusive_pending()
        || crate::driver_launch::unsettled_queued_callback();
    #[cfg(not(feature = "mup-provider-kernel-only"))]
    if !queued_callback_fences_providers {
        service_primary_alias_retry(&mut nt_handler, &mut lp.ingress.primary_alias_activation);
    }
    if !queued_callback_fences_providers {
        hosted_spawn_uncertainty::redrive(&mut *delay_queue, &mut nt_handler);
    }
    // The previous iteration's event locals and borrows have ended. Restore before any
    // new maintenance or admission; refusal retains the boundary and cannot be replayed.
    if let Some(boundary) = lp.ingress.receive_boundary.take() {
        if let Some(retained) = component_resume::run_receive(core::ptr::from_mut(&mut *nt_handler), boundary) {
            let _retained = retained;
            panic!("Receive restoration is retained; no replay or next ingress is permitted");
        }
        if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
            component_resume::run_outer(core::ptr::from_mut(&mut *nt_handler));
            if root_add_device_exclusive_pending() {
                if !prepare_parked_add_device_receive(&mut lp.ingress.root_add_device_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"restored-add-device-receive");
                    return ControlFlow::Break(Turn::Exit);
                }
            } else if root_queued_callback_exclusive_pending() {
                if !prepare_parked_queued_callback_receive(&mut lp.ingress.root_queued_callback_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"restored-queued-callback-receive");
                    return ControlFlow::Break(Turn::Exit);
                }
                if !transfer_selected_queued_callback_ingress(&mut lp.ingress.root_queued_callback_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"restored-queued-callback-child-transfer");
                    return ControlFlow::Break(Turn::Exit);
                }
            } else {
                if !prepare_service_receive(&mut *delay_queue, &mut nt_handler) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"restored-queued-work-poll");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
        }
        let received = crate::executive_ingress::receive(local().reply_main_slot.load(Ordering::Relaxed));
        let received = match received {
            crate::executive_ingress::ReceiveOutcome::Message(received) => received,
            crate::executive_ingress::ReceiveOutcome::RetainedFailure => {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"restored-ingress-retained");
                return ControlFlow::Break(Turn::Exit);
            }
            crate::executive_ingress::ReceiveOutcome::OuterBoundary(_) => {
                panic!("completed Receive cannot issue another settlement boundary")
            }
        };
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
    }
    // Receive ownership is captured before any deferred provider, timer, or driver work can
    // reuse the root TCB's IPC buffer. Fast MRs are already value locals; keep native tail
    // arguments as values too, instead of reading the live buffer after maintenance.
    let native_ingress_request = nt_syscall_abi::NativeSyscallRequest::capture(
        lp.msg.mi,
        [lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3],
        |index| unsafe { get_recv_mr(index) },
    );
    // A selected child is serviced before unrelated work can enter the held provider or
    // change its attachment. Its ordinary fault handler still performs fresh admission.
    let ingress;
    if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
    // The batch cursor owns an entered AddDevice Reply. Run only its selected child,
    // settle any inner CONNECT, then resume that same batch before general redrives.
    // The sealed child step is deposited before any subsequent batch borrow.
    let mut root_event_consumed = false;
    if root_queued_callback_exclusive_pending()
        && (badge_has_delay_timer(lp.msg.badge) || hosted_irq_lines_from_badge(lp.msg.badge) != 0)
    {
        let Some(turn) = lp.ingress.root_queued_callback_turn.last_mut() else {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"queued-callback-missing-turn");
            return ControlFlow::Break(Turn::Exit);
        };
        if service_parked_queued_callback_notification(lp.msg.badge).is_err() {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"queued-callback-notification");
            return ControlFlow::Break(Turn::Exit);
        }
        let arrival = if badge_has_delay_timer(lp.msg.badge) {
            nt_driver_start::RootArrival::Timer { now: monotonic_time_100ns() }
        } else { nt_driver_start::RootArrival::Irq };
        if turn.observe_arrival(turn.owner(), arrival).is_err() {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"queued-callback-arrival");
            return ControlFlow::Break(Turn::Exit);
        }
        root_event_consumed = true;
    } else if root_queued_callback_exclusive_pending() {
        // Keep original ingress order: a newer Call Y cannot overtake an older deferred
        // Call X if this callback happens to settle while Y is the current delivery.
        let reply = local().reply_main_slot.load(Ordering::Relaxed);
        let selected_child = crate::spawn_hosts::shared_ingress::owner::runtime::
            receive_child_pending()
            && hosted_ingress_binding(lp.msg.badge).is_some_and(|binding|
                crate::spawn_hosts::shared_ingress::owner::runtime::
                    receive_child_is_current(binding, reply));
        if !selected_child {
            let Some(permit) = ParkedRootQueuedCallbackPermit::retained() else {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"queued-callback-ingress-owner");
                return ControlFlow::Break(Turn::Exit);
            };
            if !retain_parked_queued_callback_ingress(
                &mut lp.ingress.root_queued_callback_turn, &permit, reply, lp.msg.badge)
            {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"queued-callback-ingress-defer");
                return ControlFlow::Break(Turn::Exit);
            }
            root_event_consumed = true;
        }
    }
    if let Some(turn) = lp.ingress.root_add_device_turn.as_mut() {
        if badge_has_delay_timer(lp.msg.badge) || hosted_irq_lines_from_badge(lp.msg.badge) != 0 {
            if let Err(status) = service_parked_add_device_notification(lp.msg.badge) {
                lp.exit.stop = status.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-notification");
                return ControlFlow::Break(Turn::Exit);
            }
            let arrival = if badge_has_delay_timer(lp.msg.badge) {
                nt_driver_start::RootArrival::Timer { now: monotonic_time_100ns() }
            } else {
                nt_driver_start::RootArrival::Irq
            };
            let _ = turn.observe_arrival(turn.owner(), arrival);
            root_event_consumed = true;
        }
    }
    'queued_callback_settlement: loop {
        // A callback reached by the preceding AddDevice child owns a nested physical
        // Reply. Settle it before running another AddDevice child or resuming the batch.
        // Passive work may enter a provider and retain a physical callback Reply. Only
        // this root boundary can hand that owner to the callback settlement below.
        if lp.ingress.root_add_device_turn.is_none()
            && lp.ingress.root_queued_callback_turn.is_empty()
            && !root_queued_callback_exclusive_pending()
        {
            let queued_admission = {
                let _message = crate::ipc_message::SavedMessageBuffer::capture();
                crate::driver_launch::drain_hosted_queued_callbacks_at_root()
            };
            if let Err(status) = queued_admission {
                lp.exit.stop = status as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"queued-callback-admission");
                return ControlFlow::Break(Turn::Exit);
            }
        }
        let callback_settlement = {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            settle_queued_callbacks()
        };
        match callback_settlement {
            ConnectPumpSettlement::Settled => {
                if !settle_parked_queued_callback_turn(&mut lp.ingress.root_queued_callback_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"queued-callback-settle");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
            ConnectPumpSettlement::AwaitingLocalChild => {
                if lp.ingress.root_add_device_turn.is_none() {
                    match park_queued_callback_root_receive(
                        &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, true,
                    ) {
                        QueuedCallbackPark::Retry => continue 'queued_callback_settlement,
                        QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                    };
                }
                if !prepare_parked_add_device_receive(&mut lp.ingress.root_add_device_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-child-receive");
                    return ControlFlow::Break(Turn::Exit);
                }
                let received = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                )?;
                (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
                return ControlFlow::Break(Turn::Next);
            }
            ConnectPumpSettlement::RetryableRestore => {
                match park_queued_callback_root_receive(
                    &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, true,
                ) {
                    QueuedCallbackPark::Retry => continue 'queued_callback_settlement,
                    QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                };
            }
            ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked => {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-connect-retained");
                return ControlFlow::Break(Turn::Exit);
            }
        }
        let selected = {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            match run_one_pending_add_device_child_step(nt_handler as *mut _) {
                Ok(selected) => selected,
                Err(()) => {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-child-step");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
        };
        let Some((reservation, ran_child)) = selected else {
            if let Some(turn) = lp.ingress.root_add_device_turn.take() {
                let owner = turn.owner();
                if !root_add_device_owner_exact_present(&nt_handler, owner)
                    || root_add_device_still_parked(&nt_handler, turn.owner())
                {
                    lp.ingress.root_add_device_turn = Some(turn);
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-owner-changed");
                    return ControlFlow::Break(Turn::Exit);
                }
                if turn.retained_ingress(owner).ok().flatten().is_some_and(|ticket|
                    !crate::spawn_hosts::shared_ingress::owner::runtime::deferred_parked_ingress_is_exact(ticket))
                {
                    lp.ingress.root_add_device_turn = Some(turn);
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-ingress-changed");
                    return ControlFlow::Break(Turn::Exit);
                }
                let retained = match turn.settle(owner) {
                    Ok(retained) => retained,
                    Err(turn) => {
                        lp.ingress.root_add_device_turn = Some(turn);
                        lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                        lp.exit.stop_ssn = 0;
                        lp.exit.record(b"add-device-settle");
                        return ControlFlow::Break(Turn::Exit);
                    }
                };
                ROOT_ADD_DEVICE_RETRY_DEADLINE.store(u64::MAX, Ordering::Release);
                ROOT_ADD_DEVICE_EXCLUSIVE.store(false, Ordering::Release);
                root_event_consumed |= retained.is_some();
                break;
            }
            // Ordinary redrives may reach Ready, but only this flat root phase may
            // enter AddDevice. Admit one exact row and recheck it before other work.
            let selection = ready_flat_root_add_device(&nt_handler);
            if lp.ingress.add_device_selection_evidence.report(selection) {
                trace_flat_root_add_device_selection(&nt_handler, selection);
            }
            // A row awaiting its bus PDO is not admitted or retried here: only another
            // row's relations can report that PDO.
            let nt_driver_start::AddDeviceSelection::Selected { owner: ready, .. } =
                selection else { break };
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            redrive_flat_root_add_device_selected(&mut nt_handler, ready);
            if root_add_device_still_parked(&nt_handler, ready) {
                lp.ingress.root_add_device_turn = Some(nt_driver_start::AddDeviceRootTurn::new(ready));
                ROOT_ADD_DEVICE_EXCLUSIVE.store(true, Ordering::Release);
                continue;
            }
            break;
        };
        if lp.ingress.root_add_device_turn.is_none() {
            lp.ingress.root_add_device_turn = Some(nt_driver_start::AddDeviceRootTurn::new(reservation));
            ROOT_ADD_DEVICE_EXCLUSIVE.store(true, Ordering::Release);
        }
        if lp.ingress.root_add_device_turn.as_ref().is_none_or(|turn| turn.owner() != reservation) {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"add-device-reservation-changed");
            return ControlFlow::Break(Turn::Exit);
        }
        let mut awaiting_connect_child = false;
        let still_parked = {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            match settle_queued_callbacks() {
                ConnectPumpSettlement::Settled => {}
                ConnectPumpSettlement::AwaitingLocalChild => {
                    awaiting_connect_child = true;
                }
                ConnectPumpSettlement::RetryableRestore => {
                    match park_queued_callback_root_receive(
                        &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, true,
                    ) {
                        QueuedCallbackPark::Retry => continue 'queued_callback_settlement,
                        QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                    };
                }
                ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked => {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-connect-retained");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
            match if awaiting_connect_child {
                ConnectPumpSettlement::AwaitingLocalChild
            } else {
                // The selected AddDevice may be waiting for a detached CONNECT whose
                // provider has just completed. Import that exact completion before
                // resuming the parent; this exclusive root path skips ordinary redrives.
                crate::driver_launch::redrive_entered_hosted_connect_completions();
                settle_suspended_connect_pumps()
            } {
                ConnectPumpSettlement::Settled => {
                    redrive_flat_root_add_device_selected(&mut nt_handler, reservation);
                    root_add_device_still_parked(&nt_handler, reservation)
                }
                ConnectPumpSettlement::AwaitingLocalChild => {
                    // The exact CONNECT pump has its sealed empty child observation.
                    // Keep both parents and their Replies parked until the root retry shot.
                    awaiting_connect_child = true;
                    true
                }
                ConnectPumpSettlement::RetryableRestore => {
                    match park_queued_callback_root_receive(
                        &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, true,
                    ) {
                        QueuedCallbackPark::Retry => continue 'queued_callback_settlement,
                        QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                    };
                }
                ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked => {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-connect-retained");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
        };
        trace_connect_add_device_boundary(3, u64::from(still_parked)
            | (u64::from(awaiting_connect_child) << 1)
            | (u64::from(ran_child) << 2));
        trace_connect_add_device_boundary(5,
            root_add_device_probe_bits(&nt_handler, reservation));
        trace_connect_add_device_boundary(6,
            crate::driver_launch::hosted_connect_root_probe_origin_bits());
        if !still_parked {
            if lp.ingress.root_add_device_turn.as_ref().and_then(|turn|
                turn.retained_ingress(reservation).ok().flatten())
                .is_some_and(|ticket|
                    !crate::spawn_hosts::shared_ingress::owner::runtime::deferred_parked_ingress_is_exact(ticket))
            {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-ingress-changed");
                return ControlFlow::Break(Turn::Exit);
            }
            let turn = lp.ingress.root_add_device_turn.take().expect("exact AddDevice turn");
            let retained = match turn.settle(reservation) {
                Ok(retained) => retained,
                Err(turn) => {
                    lp.ingress.root_add_device_turn = Some(turn);
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-settle");
                    return ControlFlow::Break(Turn::Exit);
                }
            };
            ROOT_ADD_DEVICE_RETRY_DEADLINE.store(u64::MAX, Ordering::Release);
            ROOT_ADD_DEVICE_EXCLUSIVE.store(false, Ordering::Release);
            break;
        }
        if !awaiting_connect_child && !ran_child
            && !root_add_device_retry_without_new_child(&nt_handler, reservation)
            && !root_add_device_needs_child_step(&nt_handler, reservation)
        {
            // The exact parent has an indeterminate or quarantined outcome. Its Reply
            // and banks remain held, and no unrelated provider can enter after this.
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"add-device-parent-retained");
            return ControlFlow::Break(Turn::Exit);
        }
        if ran_child && !awaiting_connect_child { continue }
        let turn = lp.ingress.root_add_device_turn.as_mut().expect("parked AddDevice turn");
        if !root_event_consumed && badge_has_delay_timer(lp.msg.badge)
            || !root_event_consumed && hosted_irq_lines_from_badge(lp.msg.badge) != 0
        {
            if let Err(status) = service_parked_add_device_notification(lp.msg.badge) {
                lp.exit.stop = status.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-notification");
                return ControlFlow::Break(Turn::Exit);
            }
            let arrival = if badge_has_delay_timer(lp.msg.badge) {
                nt_driver_start::RootArrival::Timer { now: monotonic_time_100ns() }
            } else {
                nt_driver_start::RootArrival::Irq
            };
            let _ = turn.observe_arrival(reservation, arrival);
            root_event_consumed = true;
            continue;
        }
        if !root_event_consumed && lp.msg.badge != DELAY_TIMER_BADGE
            && hosted_irq_lines_from_badge(lp.msg.badge) == 0
        {
            let Some(permit) = ParkedRootAddDevicePermit::for_exact(&nt_handler, reservation)
            else {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-permit");
                return ControlFlow::Break(Turn::Exit);
            };
            let reply = local().reply_main_slot.load(Ordering::Relaxed);
            let ticket = match crate::spawn_hosts::shared_ingress::owner::runtime::
                defer_hosted_delivery_for_add_device(reply, lp.msg.badge, &permit)
            {
                Ok(ticket) => ticket,
                Err(_) => {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"add-device-ingress-defer");
                    return ControlFlow::Break(Turn::Exit);
                }
            };
            if turn.retain_ingress(reservation, ticket).is_err() {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"add-device-ingress-retain");
                return ControlFlow::Break(Turn::Exit);
            }
            root_event_consumed = true;
        }
        let prepared = prepare_parked_add_device_receive(&mut lp.ingress.root_add_device_turn);
        trace_connect_add_device_boundary(4, u64::from(prepared));
        if !prepared {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"add-device-receive-prepare");
            return ControlFlow::Break(Turn::Exit);
        }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
        return ControlFlow::Break(Turn::Next);
    }
    // A nested provider can select a Receive child after the early guard was sampled.
    // Import that exact child before any ordinary provider redrive in this event.
    if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
        if root_event_consumed && !root_add_device_exclusive_pending()
            && !root_queued_callback_exclusive_pending()
            && !delay_timer_rearm(&*delay_queue, &nt_handler).owner_available()
        {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"receive-child-timer-owner");
            return ControlFlow::Break(Turn::Exit);
        }
        if badge_has_delay_timer(lp.msg.badge) || hosted_irq_lines_from_badge(lp.msg.badge) != 0 {
            if !root_event_consumed {
                let notification = if root_queued_callback_exclusive_pending() {
                    service_parked_queued_callback_notification(lp.msg.badge)
                } else {
                    service_parked_add_device_notification(lp.msg.badge)
                };
                if let Err(status) = notification {
                    lp.exit.stop = status.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"receive-child-notification");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
        } else if !root_event_consumed {
            let reply = local().reply_main_slot.load(Ordering::Relaxed);
            let selected_callback_child = root_queued_callback_exclusive_pending()
                && hosted_ingress_binding(lp.msg.badge).is_some_and(|binding|
                    crate::spawn_hosts::shared_ingress::owner::runtime::
                        receive_child_is_current(binding, reply));
            if selected_callback_child {
                let Some(permit) = ParkedRootQueuedCallbackPermit::retained() else {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"queued-callback-child-owner");
                    return ControlFlow::Break(Turn::Exit);
                };
                if crate::spawn_hosts::shared_ingress::owner::runtime::
                    defer_hosted_delivery_for_queued_callback(reply, lp.msg.badge, &permit).is_err()
                {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"queued-callback-child-defer");
                    return ControlFlow::Break(Turn::Exit);
                }
            } else {
                crate::spawn_hosts::shared_ingress::owner::runtime::defer_hosted_delivery(
                    reply, lp.msg.badge,
                ).expect("selected Receive child retains the unexecuted current Call");
            }
        }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
        return ControlFlow::Break(Turn::Next);
    }
    if root_event_consumed {
        // The parked ACK-only timer deliberately retained unrelated due owners. The
        // AddDevice bank has now settled, so restore their ordinary shared one-shot before
        // waiting for the next real ingress. A failed arm cannot be treated as an idle wait.
        if !delay_timer_rearm(&*delay_queue, &nt_handler).owner_available() {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"timer-rearm");
            return ControlFlow::Break(Turn::Exit);
        }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
        return ControlFlow::Break(Turn::Next);
    }
    // Bound notifications do not bind the offered Reply and use a separate badge namespace.
    crate::provider_bugcheck::stop_if_pending();
    // Retry outside registry/runtime borrows, including when the next ingress is excluded.
    // Failure retains the exact alias and all memory/backing-release exclusions.
    if let Err(status) = crate::temporary_frame_alias::drain() {
        print_str(b"[temporary-frame-alias] retained cleanup status=0x");
        print_hex(status);
        print_str(b"\n");
    }
    crate::client_frame_cleanup::retry_pending(&*nt_handler);
    crate::pagefile_retirement::retry_pending(&*nt_handler);
    // CM retries run only between hosted events, never inside a timer callback or nested pump.
    crate::cm_key_ownership::retry_cleanup(|| monotonic_time_100ns());
    crate::cm_snapshot_ownership::retry_cleanup(|| monotonic_time_100ns());
    let alpc_reply_committed;
    {
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        crate::native_alpc_create_work::redrive(&mut nt_handler);
        crate::native_alpc_close_work::redrive(&mut nt_handler);
        crate::native_alpc_connect_accept_work::redrive(&mut nt_handler);
        crate::native_srm_command_work::redrive(&mut nt_handler);
        alpc_reply_committed =
            crate::native_alpc_send_receive_work::redrive(&mut nt_handler);
        crate::registry_mutation_work::redrive(&mut nt_handler, &mut *delay_queue);
        crate::mutable_hive_mutation_work::redrive(&mut nt_handler, &mut *delay_queue);
        crate::section_metadata_work::redrive(&mut nt_handler, &mut *delay_queue);
        crate::process_image_snapshot_work::redrive(&mut nt_handler, &mut *delay_queue,
            ntdll, fault_ep, procs, exe_images, &*exe_image_catalog,
            hosted_loaded_images_ptr);
        crate::section_pagein_work::redrive(&mut nt_handler);
        crate::provider_section_map_work::redrive(&mut nt_handler);
        crate::native_image_pagein_work::redrive(&mut nt_handler, &nt_dispatcher);
        crate::vm_lock_pagein_work::redrive(&mut nt_handler);
        crate::vm_copy_work::redrive(&mut nt_handler);
        crate::provider_section_broker::redrive(nt_handler as *mut _);
        crate::gdi_routed_image_work::redrive(&mut nt_handler);
        crate::provider_directory_broker::redrive(nt_handler as *mut _);
        crate::provider_mm_section_objects::redrive(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_driver_io_create_file(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_query_path_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_internal_control_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_buffered_control_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_scsi_forward(nt_handler as *mut _);
        // Observe the retained source immediately after its first provider poll. Later
        // redrives can enter another provider before finalize_service_loop_state runs.
        if crate::driver_launch::hosted_scsi_receive_boundary_probe_due() {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            crate::driver_launch::trace_hosted_scsi_receive_boundary();
        }
        crate::driver_launch::redrive_hosted_write_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_read_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_flush_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_query_information_forward(nt_handler as *mut _);
        trace_connect_root_checkpoint(0, None);
        crate::driver_launch::redrive_hosted_connect_forward();
        trace_connect_root_checkpoint(1, None);
        // A port CONNECT may have yielded while its provider parent remained physically
        // parked. Its File frames have ended here. Run one selected child per flat pass,
        // then resume only that exact retained pump before another provider can enter.
        let connect_settlement = settle_suspended_connect_pumps();
        trace_connect_root_checkpoint(2, Some(&connect_settlement));
        if !matches!(connect_settlement, ConnectPumpSettlement::Settled) {
            // A nonretryable restore or a claimed, orphaned, or blocked port parent still
            // owns its Reply. No later provider may enter while that physical owner is held.
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"connect-pump-unsettled");
            return ControlFlow::Break(Turn::Exit);
        }
        // A work-queue callback can outlive its invoking provider frame. Reconcile
        // its exact Reply before a fresh Hook source may enter native code.
        let queue_settlement = settle_queued_callbacks();
        trace_connect_root_checkpoint(3, Some(&queue_settlement));
        match queue_settlement {
            ConnectPumpSettlement::Settled => {
                if !settle_parked_queued_callback_turn(&mut lp.ingress.root_queued_callback_turn) {
                    lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                    lp.exit.stop_ssn = 0;
                    lp.exit.record(b"queued-callback-settle");
                    return ControlFlow::Break(Turn::Exit);
                }
            }
            ConnectPumpSettlement::AwaitingLocalChild => {
                match park_queued_callback_root_receive(
                    &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, false,
                ) {
                    QueuedCallbackPark::Retry => unreachable!(),
                    QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                };
            }
            ConnectPumpSettlement::RetryableRestore => {
                match park_queued_callback_root_receive(
                    &mut lp.msg, &mut lp.ingress, nt_handler, &mut lp.exit, &mut root_event_consumed, false,
                ) {
                    QueuedCallbackPark::Retry => unreachable!(),
                    QueuedCallbackPark::Turn(turn) => return ControlFlow::Break(turn),
                };
            }
            ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked => {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"queued-callback-unsettled");
                return ControlFlow::Break(Turn::Exit);
            }
        }
        trace_connect_root_checkpoint(4, None);
        crate::driver_launch::redrive_hosted_hook_forward();
        trace_connect_root_checkpoint(5, None);
        if crate::driver_launch::hook_redrive_exit_probe() {
            trace_hook_root_boundary(0);
            crate::driver_launch::clear_hook_redrive_exit_probe();
        }
        if crate::driver_launch::hosted_hook_port_waiting() {
            trace_hook_root_boundary(1);
        }
        let hook_pump_settlement = {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            if crate::driver_launch::hosted_hook_port_waiting() {
                trace_hook_root_boundary(2);
            }
            settle_suspended_file_pumps()
        };
        if !matches!(hook_pump_settlement, ConnectPumpSettlement::Settled) {
            // The exact Hook File owner still holds a physical Reply. Do not enter the
            // next unrelated provider or publish a synthetic Hook completion.
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"file-pump-unsettled");
            return ControlFlow::Break(Turn::Exit);
        }
        crate::driver_launch::redrive_hosted_lower_pnp_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_lower_file_forward(nt_handler as *mut _);
        crate::driver_launch::redrive_accepted_pdo_provider_retirement();
        crate::driver_launch::redrive_hosted_driver_zw_fs_control_file(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_driver_zw_write_file(nt_handler as *mut _);
        crate::driver_launch::redrive_hosted_driver_zw_read_query_file(nt_handler as *mut _);
        crate::hosted_routed_file_close_work::redrive(&mut nt_handler);
        crate::driver_launch::hosted_consumer_file_objects::redrive();
        crate::driver_launch::win32k_file_owners::redrive();
        crate::provider_file_wait::redrive(&mut nt_handler);
        crate::current_apc::redrive(&mut nt_handler);
        crate::current_apc::redrive_terminated_runtimes(&mut nt_handler, &mut *delay_queue);
        crate::object_wait_reply::redrive(&mut nt_handler);
        crate::object_wait_reply::redrive_terminated_runtimes(&mut nt_handler, &mut *delay_queue);
        inline_file_retirement::redrive(&mut nt_handler);
        // A provider may clear the shared publication fence in this pass. Retry the
        // exact parked first-thread Reply after settlement, before receiving again.
        crate::exec_handler::initial_thread_creation::redrive_retry_no_effect(&mut nt_handler);
    }
    if alpc_reply_committed.is_some() {
        let _ = lpc_component_reply_commit_drain(&mut nt_handler);
    }
    if crate::writable_fs::registry_journal::owns_volume()
        && lp.msg.badge != DELAY_TIMER_BADGE
        && hosted_irq_lines_from_badge(lp.msg.badge) == 0
    {
        crate::spawn_hosts::shared_ingress::owner::runtime::defer_hosted_delivery(
            local().reply_main_slot.load(Ordering::Relaxed), lp.msg.badge,
        ).expect("unexecuted hosted delivery retains its physical ingress owner");
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        lp.msg.badge = received.0;
        lp.msg.mi = received.1;
        lp.msg.m0 = received.2;
        lp.msg.m1 = received.3;
        lp.msg.m2 = received.4;
        lp.msg.m3 = received.5;
        return ControlFlow::Break(Turn::Next);
    }
    if lp.msg.badge != DELAY_TIMER_BADGE
        && hosted_irq_lines_from_badge(lp.msg.badge) == 0
        && !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
        && crate::spawn_hosts::shared_ingress::owner::runtime::is_win32k_native_call(lp.msg.mi, lp.msg.m0)
        && component_shared_publication_is_busy()
    {
        // Maintenance above may have selected a returned Receive owner after this Call was
        // imported. Move the still-unexecuted original Call and Reply back to its ingress
        // row before fault-frame or win32k shared-page staging can overwrite either owner.
        crate::spawn_hosts::shared_ingress::owner::runtime::defer_hosted_delivery(
            local().reply_main_slot.load(Ordering::Relaxed), lp.msg.badge,
        ).expect("busy win32k Call retains its original physical ingress owner");
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
        return ControlFlow::Break(Turn::Next);
    }
    ingress = if lp.msg.badge == DELAY_TIMER_BADGE || hosted_irq_lines_from_badge(lp.msg.badge) != 0 {
        None
    } else {
        match nt_handler.admit_hosted_thread_ingress(lp.msg.badge) {
            Ok(runtime) => Some(runtime),
            Err(_) => return ControlFlow::Break(lp.reject_hosted_ingress()),
        }
    };
    // Deferred work between events writes canonical tables, never the previous event's
    // reusable scratch counters. Flush late completion fills before selecting another owner.
    nt_handler.loop_ctx = nt_handler.loop_ctx.map(|ctx| ctx.checkpoint_live());
    // Hardware IRQs share the root TCB's bound notification with the HPET timer. Component
    // pumps only latch these bits; the root loop is the sole dispatcher and therefore the sole
    // owner of ISR ordering and handler acknowledgement.
    let current_irq_lines = driver_launch::latch_hosted_irq_badge(lp.msg.badge);
    let serviced_irq_lines = driver_launch::drain_pending_hosted_irqs();
    if current_irq_lines != 0 || serviced_irq_lines != 0 {
        // A hosted SCSI terminal can arrive during the IRQ/DPC drain, after the
        // ordinary source poll. Service its retained owner even when a deferred
        // IRQ is drained on a later timer or ordinary ingress badge.
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _ = driver_launch::redrive_irq_ready_hosted_scsi(nt_handler as *mut _);
    }
    if current_irq_lines != 0 {
        let has_delay_timer = badge_has_delay_timer(lp.msg.badge);
        if !has_delay_timer {
            // IRQ-owned DPCs can publish the exact native IRP terminal. Observe and
            // ACK it before sleeping; otherwise each sector waits for a timer wakeup.
            if driver_launch::mounted_native_physical_irp_pending() {
                if service_mounted_native_blocks_and_redrive_backends() != 0 {
                    let _ = driver_launch::pump_hosted_io_completions();
                    let _ = pending_file_io_redrive_all(&mut nt_handler);
                    let _ = file_cleanup_redrive_all(&mut nt_handler);
                }
            }
        }
        if has_delay_timer {
            lp.msg.badge = DELAY_TIMER_BADGE;
        } else {
            let irq_durable_status = finalize_service_loop_state(&mut nt_handler);
            if irq_durable_status != nt_fs::STATUS_SUCCESS {
                print_str(b"[service-loop] IRQ checkpoint failure=0x");
                print_hex(irq_durable_status);
                print_str(b"\n");
                lp.exit.stop = irq_durable_status as u64;
                lp.exit.record(b"irq-checkpoint");
                return ControlFlow::Break(Turn::Exit);
            }
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
    }
    if pending_driver_start_redrive_needed(&nt_handler)
        || driver_launch::hosted_driver_dpc_activation_pending()
        || driver_launch::hosted_acpi_pci_route_recovery_ready()
    {
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
    }
    {
        let started = crate::disk_census_ticks();
        publish_kuser_clocks();
        crate::LOOP_KUSER_TICKS.fetch_add(
            crate::disk_census_ticks().wrapping_sub(started),
            Ordering::Relaxed,
        );
    }
    let overdue_timed_wakes = {
        let started = crate::disk_census_ticks();
        let drained = if lp.msg.badge == DELAY_TIMER_BADGE {
            0
        } else {
            delay_timer_drain_overdue_without_badge(&mut *delay_queue, &mut nt_handler)
        };
        crate::LOOP_DRAIN_TICKS.fetch_add(
            crate::disk_census_ticks().wrapping_sub(started),
            Ordering::Relaxed,
        );
        drained
    };
    if overdue_timed_wakes != 0 {
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
        // Timer drains are scheduler bookkeeping, not forward progress by themselves. The
        // resumed waiter records a boot milestone if it publishes a new image/page or crosses a
        // shell frontier; counting the wake itself can keep boot alive forever on timeout churn.
        if ingress.is_none() && crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) != 0 {
            if watchdog_defer_if_hosted_work_can_run(b"overdue-timer") {
                lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
            } else if crate::watchdog_confirm_trip() {
                print_str(b"[deadman] confirmed -> QUIESCE; run the gate\n");
                lp.exit.stop = lp.msg.m1;
                lp.exit.record(b"overdue-watchdog");
                return ControlFlow::Break(Turn::Exit);
            }
        }
    }
    // Progress-stall accounting: reset the wall-clock window on any epoch bump (real forward
    // progress); quiesce if no progress for STALL_BUDGET_100NS.
    {
        let quiesce_started = crate::disk_census_ticks();
        let ep = (lp.diag.progress_epoch)();
        let now = monotonic_time_100ns();
        {
            let slot = census_slot(lp.msg.badge);
            if lp.diag.census_prev_badge != usize::MAX {
                let elapsed = now.wrapping_sub(lp.diag.census_prev_t);
                BADGE_TIME_100NS[lp.diag.census_prev_badge].fetch_add(elapsed, Ordering::Relaxed);
            }
            BADGE_EVENTS[slot].fetch_add(1, Ordering::Relaxed);
            BADGE_LAST_T[slot].store(now, Ordering::Relaxed);
            lp.diag.census_prev_badge = slot;
            lp.diag.census_prev_t = now;
            crate::LOOP_QUIESCE_TICKS.fetch_add(
                crate::disk_census_ticks().wrapping_sub(quiesce_started),
                Ordering::Relaxed,
            );
            crate::sample_object_namespace_census(&nt_handler.obj_ns, now);
            census_tick_static(now);
            native_process_time_census::sample_after_census(&nt_handler);
            installer_child_span_census::maybe_sample_gap(&nt_handler, now);
            installer_child_span_census::print_census(&nt_handler);
            if CENSUS_LAST_DUMP.load(Ordering::Relaxed) == now {
            }
        }
        if ep != lp.diag.last_progress_epoch {
            lp.diag.last_progress_epoch = ep;
            lp.diag.last_progress_t = now;
            let _ = lp.diag.stall_deferrals.observe_progress(ep);
        } else if cfg!(not(feature = "mup-provider-kernel-only"))
            && ingress.is_none()
            && now.wrapping_sub(lp.diag.last_progress_t) >= STALL_BUDGET_100NS
        {
            let deferral =
                progress_stall_deferral_snapshot(&nt_handler, lp.parks.crash_parked, lp.parks.wait_parked);
            if deferral.is_some() && lp.diag.stall_deferrals.grant(ep, deferral.unwrap()) {
                let snapshot = deferral.unwrap();
                trace_progress_stall_deferral(snapshot, &nt_handler, lp.parks.crash_parked, lp.parks.wait_parked);
                lp.diag.last_progress_t = now;
            } else if nt_handler.grant_installer_inf_progress(ep, now, STALL_BUDGET_100NS) {
                print_str(b"[quiesce] deferring installer INF traversal grant=");
                print_u64(nt_handler.installer_inf_grants() as u64);
                print_str(b"/2\n");
                lp.diag.last_progress_t = now;
            } else {
                dump_lsa_readiness_quiesce(
                    &nt_handler,
                    &*hosted_loaded_images,
                    &reg,
                    ntdll,
                    procs,
                    pfilled,
                );
                dump_services_start_quiesce(
                    &nt_handler,
                    &*hosted_loaded_images,
                    &reg,
                    ntdll,
                    procs,
                    pfilled,
                );
                dump_interactive_shell_frontier_quiesce(
                    &nt_handler,
                    &*hosted_loaded_images,
                    &reg,
                    ntdll,
                    procs,
                    pfilled,
                );
                print_str(b"[quiesce] no boot milestone for ~180s wall-clock -> run gate\n");
                lp.exit.stop = lp.msg.m1;
                lp.exit.record(b"boot-milestone-stall");
                return ControlFlow::Break(Turn::Exit);
            }
        }
    }
    if ingress.is_none() && crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) != 0 {
        if watchdog_defer_if_hosted_work_can_run(b"service-loop-top") {
            lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
        } else if crate::watchdog_confirm_trip() {
            dump_lsa_readiness_quiesce(
                &nt_handler,
                &*hosted_loaded_images,
                &reg,
                ntdll,
                procs,
                pfilled,
            );
            dump_services_start_quiesce(
                &nt_handler,
                &*hosted_loaded_images,
                &reg,
                ntdll,
                procs,
                pfilled,
            );
            dump_interactive_shell_frontier_quiesce(
                &nt_handler,
                &*hosted_loaded_images,
                &reg,
                ntdll,
                procs,
                pfilled,
            );
            print_str(b"[deadman] nested receive confirmed watchdog -> run gate\n");
            lp.exit.stop = lp.msg.m1;
            lp.exit.record(b"nested-receive-watchdog");
            return ControlFlow::Break(Turn::Exit);
        }
    }
    // TAIL WATCH — sample every hosted process' TEB tail on EVERY service-loop event, so the
    // good→bad transition is attributed to the event that preceded it rather than to whichever
    // observer happened to look next.
    for watch_pi in 1..5usize {
        crate::teb_tail_watch(watch_pi, 0, lp.msg.m0, lp.msg.badge);
    }
    // Arm once the genuine dialog pump has drained painted messages or the later evidence/token
    // path shows the interactive boot is live. A true silence after that point reports itself
    // instead of hanging in recv; no synthetic framebuffer marker participates in this trigger.
    if crate::EXEC_DEADMAN_WATCHDOG
        && crate::WATCHDOG_ARMED.load(Ordering::Relaxed) == 0
        && ((WINLOGON_DIALOG_MODAL_DRAINED.load(Ordering::Relaxed) != 0
            && WINLOGON_DIALOG_MODAL_PAINTS.load(Ordering::Relaxed) != 0)
            || WINLOGON_DIALOG_FB_VERIFIED.load(Ordering::Relaxed) != 0
            || WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0)
    {
        crate::watchdog_arm(&mut *delay_queue, &nt_handler);
    }
    // ★ DRAIN timer ticks a COMPONENT PUMP absorbed. The HPET notification is bound to the root
    // TCB, so it can cancel ANY blocking recv the executive makes — including `pump_recv`'s,
    // which cannot service it (the delay queue lives here). The pump latches it instead; this
    // runs the same `delay_timer_interrupt` the badge arm below would have, one dispatch later.
    // Multiple pump receives can absorb ticks before this loop top; service the coalesced timer
    // state once, but account for every delivery the pump deferred.
    let pump_ticks = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::Relaxed);
    if pump_ticks != 0 {
        PUMP_TIMER_TICKS_DRAINED.fetch_add(pump_ticks, Ordering::Relaxed);
        delay_timer_interrupt(&mut *delay_queue, &mut nt_handler);
        #[cfg(not(feature = "mup-provider-kernel-only"))]
        service_primary_alias_retry(&mut nt_handler, &mut lp.ingress.primary_alias_activation);
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
    }
    if lp.msg.badge == DELAY_TIMER_BADGE {
        if (&*delay_queue).len() != 0 && (&*delay_queue).has_badge_other_than(lp.msg.badge) {
            let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
            if progress < 8 {
                print_str(
                    b"[delay] timer badge progressed while client waiter parked: queued=",
                );
                print_u64((&*delay_queue).len() as u64);
                print_str(b"\n");
            }
        }
        let timer_trace = DELAY_TIMER_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        if timer_trace < 8 {
            print_str(b"[delay] TIMER-NOTIFICATION msginfo_label=");
            print_u64(lp.msg.mi >> 12);
            print_str(b" raw_m0=0x");
            print_hex_u64(lp.msg.m0);
            print_str(b"\n");
        }
        delay_timer_interrupt(&mut *delay_queue, &mut nt_handler);
        #[cfg(not(feature = "mup-provider-kernel-only"))]
        service_primary_alias_retry(&mut nt_handler, &mut lp.ingress.primary_alias_activation);
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
        // ★ THE DEADMAN'S TEETH. `watchdog_on_tick` (inside `recv_full_r12`) has already
        // raised a candidate; this is where the boot confirms it against the hosted-thread
        // census, then quiesces and runs the gate. Long runnable user-mode stretches are
        // deferred and require another two fully silent periods before they can be considered
        // again.
        if crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) != 0 {
            if watchdog_defer_if_hosted_work_can_run(b"timer-badge") {
                lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
            } else if crate::watchdog_confirm_trip() {
                print_str(b"[deadman] confirmed -> QUIESCE; run the gate\n");
                lp.exit.stop = lp.msg.m1;
                lp.exit.record(b"timer-watchdog");
                return ControlFlow::Break(Turn::Exit);
            }
        }
        // Consume the delivered timer before scheduling can program the next shot.
        component_resume::run_outer(core::ptr::from_mut(&mut *nt_handler));
        let timer_durable_status = finalize_service_loop_state(&mut nt_handler);
        if timer_durable_status != nt_fs::STATUS_SUCCESS {
            print_str(b"[service-loop] timer checkpoint failure=0x");
            print_hex(timer_durable_status);
            print_str(b"\n");
            lp.exit.stop = timer_durable_status as u64;
            lp.exit.record(b"timer-checkpoint");
            return ControlFlow::Break(Turn::Exit);
        }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
        )?;
        lp.msg.badge = received.0;
        lp.msg.mi = received.1;
        lp.msg.m0 = received.2;
        lp.msg.m1 = received.3;
        lp.msg.m2 = received.4;
        lp.msg.m3 = received.5;
        return ControlFlow::Break(Turn::Next);
    }
    if (&*delay_queue).len() != 0 && (&*delay_queue).has_badge_other_than(lp.msg.badge) {
        let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
        if progress < 8 {
            print_str(b"[delay] unrelated badge progressed while waiter parked: badge=");
            print_u64(lp.msg.badge);
            print_str(b" queued=");
            print_u64((&*delay_queue).len() as u64);
            print_str(b"\n");
        }
    }
    // Complete durable publications and filesystem checkpoints before accepting the next
    // dispatch. Ordinary temporary ownership is reclaimed by Drop/free-list reuse, while
    // explicitly scoped scratch uses the allocator's independent transient lane.
    let durability_status = finalize_service_loop_state(&mut nt_handler);
    if durability_status != nt_fs::STATUS_SUCCESS {
        print_str(b"[service-loop] durability publication failed status=0x");
        print_hex(durability_status);
        print_str(b"\n");
        lp.exit.stop = durability_status as u64;
        lp.exit.record(b"durability-publication");
        return ControlFlow::Break(Turn::Exit);
    }
    // This delivery still owns its Reply and captured message. An outer resume can select
    // a different Receive child, so leave that work to a boundary without this ingress.
    } else {
        ingress = Some(nt_handler.admit_hosted_thread_ingress(lp.msg.badge)
            .expect("selected Receive child retains its current ingress binding"));
        assert!(crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_is_current(
            ingress.as_ref().unwrap().binding(), local().reply_main_slot.load(Ordering::Relaxed),
        ), "only the exact selected Receive child may run while its parent is held");
    }
    ControlFlow::Continue((ingress, native_ingress_request))
}
