//! The service loop's blocking receive (issue #382, loop hoist).
//!
//! These were the loop-local macros `component_receive_outcome!`, `component_recv!` and
//! `component_client_reply_recv!`. Where a macro left the service loop, the function returns
//! `Break`; the caller turns that back into `continue` or `break`. Every function is
//! `#[track_caller]`, so a recorded exit site is still the line of the outermost call.
//!
//! The reply arguments arrive as closures because the macros evaluated them after the
//! prepare step, and that step may run retained work.

use super::*;

/// The badge and message registers of one received event.
pub(super) type Received = (u64, u64, u64, u64, u64, u64);

/// Was `component_receive_outcome!`.
#[track_caller]
fn settle(
    ingress: &mut Ingress,
    exit: &mut LoopExit,
    outcome: crate::executive_ingress::ReceiveOutcome,
) -> ControlFlow<Turn, Received> {
    match outcome {
        crate::executive_ingress::ReceiveOutcome::Message(message) => ControlFlow::Continue(message),
        crate::executive_ingress::ReceiveOutcome::OuterBoundary(boundary) => {
            ingress.receive_boundary = Some(boundary);
            ControlFlow::Break(Turn::Next)
        }
        crate::executive_ingress::ReceiveOutcome::RetainedFailure => {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"ingress-retained");
            ControlFlow::Break(Turn::Exit)
        }
    }
}

/// Was `component_recv!`.
#[track_caller]
pub(super) unsafe fn receive(
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    exit: &mut LoopExit,
    ep: u64,
    reply: impl FnOnce() -> u64,
) -> ControlFlow<Turn, Received> {
    assert!(crate::executive_ingress::handles(ep));
    if root_add_device_exclusive_pending() {
        if !prepare_parked_add_device_receive(&mut ingress.root_add_device_turn) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"add-device-receive");
            return ControlFlow::Break(Turn::Exit);
        }
    } else if root_queued_callback_exclusive_pending() {
        if !prepare_parked_queued_callback_receive(&mut ingress.root_queued_callback_turn) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-callback-receive");
            return ControlFlow::Break(Turn::Exit);
        }
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
            && !transfer_selected_queued_callback_ingress(&mut ingress.root_queued_callback_turn)
        {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-callback-child-transfer");
            return ControlFlow::Break(Turn::Exit);
        }
    } else if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
        if !prepare_service_receive(&mut *ingress.delay_queue, nt_handler) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-work-receive-poll");
            return ControlFlow::Break(Turn::Exit);
        }
    }
    settle(ingress, exit, crate::executive_ingress::receive(reply()))
}

/// Was `component_client_reply_recv!`. `reply_message` yields the Reply slot, the message
/// length and the four reply registers.
#[track_caller]
pub(super) unsafe fn reply_receive(
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    exit: &mut LoopExit,
    ep: u64,
    reply_message: impl FnOnce() -> (u64, u64, u64, u64, u64, u64),
) -> ControlFlow<Turn, Received> {
    assert!(crate::executive_ingress::handles(ep));
    if root_add_device_exclusive_pending() {
        if !prepare_parked_add_device_receive(&mut ingress.root_add_device_turn) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"add-device-reply-receive");
            return ControlFlow::Break(Turn::Exit);
        }
    } else if root_queued_callback_exclusive_pending() {
        if !prepare_parked_queued_callback_receive(&mut ingress.root_queued_callback_turn) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-callback-reply-receive");
            return ControlFlow::Break(Turn::Exit);
        }
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
            && !transfer_selected_queued_callback_ingress(&mut ingress.root_queued_callback_turn)
        {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-callback-child-transfer");
            return ControlFlow::Break(Turn::Exit);
        }
    } else if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
        if !prepare_service_receive(&mut *ingress.delay_queue, nt_handler) {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-work-reply-poll");
            return ControlFlow::Break(Turn::Exit);
        }
    }
    let (reply, len, r0, r1, r2, r3) = reply_message();
    settle(ingress, exit, crate::executive_ingress::reply_receive(reply, len, r0, r1, r2, r3))
}
