use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::provider_ps_retirement::PsRetirementTarget;
use crate::provider_kernel_pump::KernelProviderPumpFacts;
use crate::provider_kernel_wait::{KernelProviderWaitRecipient, KernelProviderWaitState};
use nt_provider_wait::{
    ProviderWaitMode, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitRequest,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
};

struct ThreadExitRecipient {
    target: PsRetirementTarget,
    wait: KernelProviderWaitState,
}

impl KernelProviderWaitRecipient for ThreadExitRecipient {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState {
        &mut self.wait
    }
}

fn terminated_target(pm: &mut ProcessManager) -> (ThreadLifetime, ProcessIdentity, u64, u64) {
    let pid = pm.create_process("gui.exe", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, true).unwrap();
    pm.set_thread_state(tid, ThreadState::Running).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let process = ProcessIdentity {
        pid,
        generation: ProcessGeneration::Hosted(7),
    };
    let eprocess = 0x3000;
    let ethread = 0x4000;
    assert!(pm.publish_kernel_object_pair(lifetime, eprocess, ethread));
    pm.set_thread_state(tid, ThreadState::Terminated).unwrap();
    (lifetime, process, eprocess, ethread)
}

/// Ps exit cleanup runs after the hosted requestor has become non-executable. The target is
/// still an exact Ps object owner, while the provider stack and its wait belong to a live root
/// caller. A contended provider wait must keep both identities until the original return.
#[test]
fn terminated_gui_target_parks_under_system_owned_provider_wait() {
    let mut pm = bootstrap().into_parts().pm;
    let (lifetime, process, eprocess, ethread) = terminated_target(&mut pm);
    let target = PsRetirementTarget::capture(&mut pm, process, lifetime, eprocess, ethread).unwrap();
    assert_eq!(target.validate(&pm, process), Ok(()));
    assert_eq!(references(&pm, lifetime), (1, 1));

    let system = pm.initial_system_identity().unwrap();
    let native = pm
        .capture_native_handle_caller(system.thread(), AccessMode::KernelMode)
        .unwrap();
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = ComponentSuspensionLanes::<KernelProviderWaitCapture, i32, u64>::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();

    let mut wait = KernelProviderWaitState::new(reply).unwrap();
    let mut attempt = wait.begin_initial().unwrap();
    wait.observe(
        &mut attempt,
        KernelProviderPumpFacts {
            observed_at: nt_kernel_exec::TimeSnapshot {
                monotonic_100ns: 10,
                system_time_100ns: 100,
                clock_generation: 0,
            },
            reply_cap: reply,
            completed: false,
            callback_suspended: false,
            provider_wait_suspended: true,
            lpc_wait_suspended: false,
            scheduler_yielded: false,
        },
        None,
    )
    .unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture_with_recipient(
            &mut pm,
            &catalog,
            &lanes,
            provider,
            lane,
            native,
            ThreadExitRecipient { target, wait },
        )
        .unwrap_or_else(|(status, _)| panic!("root capture failed: {status:x}"));
    assert_eq!(caller.thread(), system.thread());
    assert_eq!(caller.owner().caller, SuspensionCaller::Kernel { lane });
    assert_ne!(caller.thread(), lifetime);

    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: 71,
                owner: caller.owner(),
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Relative,
                timeout_100ns: -100_000,
            },
            &[ProviderWaitObject::new(ProviderWaitObjectType::Event, 81, 1)],
        )
        .unwrap();
    let capture = activations
        .capture_provider_wait(
            caller,
            &pm,
            &catalog,
            &lanes,
            reply,
            activations.recipient(caller).unwrap().wait.progress(),
            request,
        )
        .unwrap();
    activations
        .recipient_mut(caller)
        .unwrap()
        .wait
        .retain_provider_wait(request, Ok(capture))
        .unwrap();
    lanes
        .admit_running(lane, reply, capture.key(), 1, caller.owner(), capture)
        .unwrap();

    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(activations.retained_for_provider(catalog.identity().unwrap(), provider), 1);
    assert_eq!(activations.recipient(caller).unwrap().target.validate(&pm, process), Ok(()));
    assert_eq!(references(&pm, lifetime), (1, 1));
    assert_eq!(references(&pm, system.thread()), (2, 2));

    lanes.select(capture.key(), 0).unwrap();
    let resumed = activations
        .begin_wait_resume(caller, &pm, &catalog, &mut lanes, capture)
        .unwrap();
    assert_eq!(resumed.caller(), caller);
    assert_eq!(resumed.selection().completion, 0);
    assert_eq!(activations.recipient(caller).unwrap().target.validate(&pm, process), Ok(()));
    assert_eq!(references(&pm, lifetime), (1, 1));

    let (_, mut attempt, _) = resumed.into_parts();
    activations
        .recipient_mut(caller)
        .unwrap()
        .wait
        .observe(
            &mut attempt,
            KernelProviderPumpFacts {
                observed_at: nt_kernel_exec::TimeSnapshot {
                    monotonic_100ns: 11,
                    system_time_100ns: 101,
                    clock_generation: 0,
                },
                reply_cap: reply,
                completed: true,
                callback_suspended: false,
                provider_wait_suspended: false,
                lpc_wait_suspended: false,
                scheduler_yielded: false,
            },
            Some(0),
        )
        .unwrap();
    let terminal = activations
        .retain_terminal_completion(caller, &pm, &catalog, &mut lanes, capture.key(), 456, 0)
        .unwrap();
    let mut delivery = lanes
        .begin_terminal_stage(terminal, reply, TerminalStage::LocalDelivery)
        .unwrap();
    lanes
        .record_terminal_stage(&mut delivery, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    let (receipt, retired) = activations
        .finish_terminal_completion(caller, &pm, &mut lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 456);
    assert_eq!(references(&pm, lifetime), (1, 1));
    let (_, mut recipient) = activations
        .acknowledge_completion_with_recipient(receipt, &mut pm)
        .unwrap();
    assert_eq!(references(&pm, system.thread()), (1, 1));
    assert_eq!(recipient.target.validate(&pm, process), Ok(()));
    recipient.target.release(&mut pm).unwrap();
    assert_eq!(references(&pm, lifetime), (0, 0));
}

#[test]
fn ps_retirement_target_refuses_stale_generation_and_wrong_bodies_without_effect() {
    let mut pm = bootstrap().into_parts().pm;
    let (lifetime, process, eprocess, ethread) = terminated_target(&mut pm);
    let stale_process = ProcessIdentity {
        generation: ProcessGeneration::Hosted(8),
        ..process
    };
    assert!(PsRetirementTarget::capture(&mut pm, process, lifetime, ethread, eprocess).is_err());
    assert!(PsRetirementTarget::capture(&mut pm, process, lifetime, eprocess, ethread + 8)
        .is_err());
    assert_eq!(references(&pm, lifetime), (0, 0));

    let mut target = PsRetirementTarget::capture(&mut pm, process, lifetime, eprocess, ethread)
        .unwrap();
    assert!(target.validate(&pm, stale_process).is_err());
    assert_eq!(target.validate(&pm, process), Ok(()));
    assert_eq!(references(&pm, lifetime), (1, 1));
    target.release(&mut pm).unwrap();
    assert_eq!(references(&pm, lifetime), (0, 0));

    let activation = pm
        .prepare_thread_activation(lifetime.thread_id(), 0x6000, 0, false, 0x7000, 1, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert_ne!(pm.thread_lifetime(lifetime.thread_id()), Some(lifetime));
    assert!(PsRetirementTarget::capture(&mut pm, process, lifetime, eprocess, ethread).is_err());
    assert_eq!(references(&pm, pm.thread_lifetime(lifetime.thread_id()).unwrap()), (0, 0));
}
