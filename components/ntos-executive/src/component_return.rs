//! Hosted return-target retirement, independent of provider execution and terminal delivery.

use super::*;
use nt_user_host::hosted_return_target::{RetirementEffect, RetirementOutcome};

static RETIREMENT_FAILURES: AtomicU64 = AtomicU64::new(0);

fn report_retained(
    lane: nt_component_suspension::LaneHandle,
    cap: u64,
    effect: RetirementEffect,
    outcome: RetirementOutcome,
) {
    let (status, uncertain) = match outcome {
        RetirementOutcome::Acknowledged => return,
        RetirementOutcome::NoEffects(status) => (status, false),
        RetirementOutcome::Indeterminate(status) => (status, true),
    };
    if RETIREMENT_FAILURES.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    print_str(b"[component-return] retirement retained lane=");
    print_u64(lane.index as u64);
    print_str(b" cap=");
    print_u64(cap);
    print_str(b" effect=");
    print_str(match effect {
        RetirementEffect::Delete => b"delete",
        RetirementEffect::Retype => b"retype",
        RetirementEffect::ReleasePool => b"pool-release",
    });
    print_str(b" uncertain=");
    print_u64(uncertain as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

fn invocation_outcome(effect: RetirementEffect, status: u64) -> RetirementOutcome {
    match status {
        0 => RetirementOutcome::Acknowledged,
        // These exact Reply operations validate before mutation. Delete's MAX is the root's
        // pinned-slot refusal before entry; unknown transport results cannot authorize replay.
        1..=10 => RetirementOutcome::NoEffects(status as u32),
        u64::MAX if effect == RetirementEffect::Delete => {
            RetirementOutcome::NoEffects(nt_fs::STATUS_INVALID_HANDLE)
        }
        _ => RetirementOutcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32),
    }
}

unsafe fn invoke(effect: RetirementEffect, cap: u64) -> RetirementOutcome {
    let slot = match parked_reply::validate_saved(cap) {
        Ok(slot) => slot,
        Err(status) => return RetirementOutcome::NoEffects(status),
    };
    match effect {
        RetirementEffect::Delete => invocation_outcome(effect, cnode_delete_r(cap)),
        RetirementEffect::Retype => invocation_outcome(
            effect,
            untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, cap),
        ),
        RetirementEffect::ReleasePool => {
            // No callout separates this checked local publication from its frame receipt.
            wait_reply_pool_mut()[slot].used = false;
            RetirementOutcome::Acknowledged
        }
    }
}

pub(super) unsafe fn prepare_abandoned_replies(
    scope: nt_component_suspension::SuspensionScope,
) -> bool {
    // A terminal stage owns its reply through delivery ACK. It cannot be torn down here.
    if (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).has_terminal_in_scope(scope) {
        return false;
    }
    // Entered provider execution still uses its captured return target. Defer teardown until it
    // yields or returns rather than replacing that target underneath the running pump.
    if (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frames()
        .any(|(_, frame)| {
            scope.matches(frame.owner)
                && matches!(
                    frame.phase,
                    nt_component_suspension::SuspensionPhase::Resuming { .. }
                )
        })
    {
        return false;
    }
    // Publish sticky intent for the whole scope before the first fallible capability operation.
    loop {
        let target = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .frames()
            .find(|(_, frame)| {
                scope.matches(frame.owner) && frame.continuation.return_target.delivery().is_some()
            })
            .map(|(lane, frame)| (lane, frame.key));
        let Some((lane, key)) = target else { break };
        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .frame_mut(lane, key)
            .ok()
            .flatten()
            .expect("hosted return abandonment lost its frame")
            .continuation
            .return_target
            .request_abandonment();
    }
    loop {
        let target = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .frames()
            .find(|(_, frame)| {
                scope.matches(frame.owner) && !frame.continuation.return_target.is_abandoned()
            })
            .map(|(lane, frame)| (lane, frame.key, frame.owner));
        let Some((lane, key, owner)) = target else {
            return true;
        };
        let mut attempt = {
            let frame = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .frame_mut(lane, key)
                .ok()
                .flatten()
                .expect("hosted return retirement lost its frame");
            let Ok(attempt) = frame.continuation.return_target.begin_retirement() else {
                return false;
            };
            attempt
        };
        let outcome = invoke(attempt.effect(), attempt.reply_cap());
        let abandoned = {
            let frame = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .frame_mut(lane, key)
                .ok()
                .flatten()
                .expect("entered hosted return retirement lost its frame");
            assert_eq!(
                frame.owner, owner,
                "hosted return retirement changed caller"
            );
            frame
                .continuation
                .return_target
                .record_retirement(&mut attempt, outcome)
                .expect("hosted return retirement lost its exact effect receipt");
            frame.continuation.return_target.is_abandoned()
        };
        if abandoned {
            PROVIDER_WAIT_NATIVE_REPLIES_ABANDONED.fetch_add(1, Ordering::Relaxed);
        }
        if outcome != RetirementOutcome::Acknowledged {
            report_retained(lane, attempt.reply_cap(), attempt.effect(), outcome);
            return false;
        }
    }
}
