//! Real timed kernel wait through the pre-runtime receiver; not a driver compatibility result.

use super::*;
use crate::shared_ingress_selftest as fixture;
use crate::spawn_hosts::shared_ingress::owner::runtime as ingress;
use nt_component_suspension::peer_registry::PeerRoute;
use nt_component_suspension::{TerminalStage, TerminalStageOutcome};
use nt_provider_wait::*;
use nt_user_host::provider_dispatcher_backend::ProviderDispatcherAccess;
use nt_user_host::provider_kernel_activation::*;
use nt_user_host::provider_kernel_pump::KernelProviderPumpFacts;
use nt_user_host::provider_kernel_wait::{KernelProviderWaitRecipient, KernelProviderWaitState};

struct Recipient(KernelProviderWaitState);

impl KernelProviderWaitRecipient for Recipient {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState {
        &mut self.0
    }
}

fn facts(reply_cap: u64, completed: bool) -> KernelProviderPumpFacts {
    KernelProviderPumpFacts {
        observed_at: nt_time_snapshot(),
        reply_cap,
        completed,
        callback_suspended: false,
        provider_wait_suspended: !completed,
        lpc_wait_suspended: false,
        scheduler_yielded: false,
    }
}

pub(crate) unsafe fn run(
    route: PeerRoute,
    unrelated: PeerRoute,
    catalog: &ProviderDomainCatalog,
) {
    print_str(b"[bootstrap-wait-native] begin\n");
    let ingress::PhysicalDomain::Provider { domain, .. } = ingress::physical_source(route).unwrap().domain
    else { panic!("fixture provider domain") };
    ingress::admit(route).expect("timed fixture dispatch");
    let initial_reply = ingress::current_reply(route).unwrap();
    let mut recipient = Recipient(KernelProviderWaitState::new(initial_reply).unwrap());
    let mut initial = recipient.0.begin_initial().unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = ps_bootstrap::with_process_manager(|pm| {
        let system = ps_bootstrap::initial_system_projection().unwrap().identity;
        let native = pm.capture_native_handle_caller(system.thread(), nt_types::AccessMode::KernelMode)?;
        activations.capture_with_recipient(
            pm, catalog, &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
            domain, route.identity().lane, native, recipient,
        ).map_err(|(status, _)| status)
    }).expect("timed fixture retained kernel caller");
    ingress::reply(route, initial_reply, &[1]).expect("timed fixture request ACK");
    fixture::receive(route);
    let (reply, message) = ingress::next_message(route).unwrap().unwrap();
    assert_eq!(message.info(), (0x7e1 << 12) | 4);
    assert_eq!(message.registers(), [17, 29, 43, 71]);
    ingress::adopt(route, reply).expect("timed fixture parked Call");
    let reply = ingress::current_reply(route).unwrap();
    activations.recipient_mut(caller).unwrap().0
        .observe_current(&mut initial, facts(reply, false), None, reply).unwrap();
    // The local identity is scoped to this real fixture provider and retired below.
    let local = route.identity().executor;
    let (event, _) = dispatcher_bootstrap::with_local_events(|state| {
        state.publish(domain, local, 1, false)
    }).expect("timed fixture canonical Event");
    let mut request = ProviderWaitRequest::empty();
    request.begin(ProviderWaitRequestMetadata {
        wait_id: 1,
        owner: caller.owner(),
        wait_type: ProviderWaitType::Any,
        wait_mode: ProviderWaitMode::Kernel,
        alertable: false,
        timeout_kind: ProviderWaitTimeoutKind::Relative,
        timeout_100ns: -10_000_000,
    }, &[ProviderWaitObject::new(
        ProviderWaitObjectType::Event, event.0.slot() + 1, event.0.generation().0.into(),
    )]).unwrap();
    let capture = ps_bootstrap::with_process_manager(|pm| {
        activations.capture_provider_wait(
            caller, pm, catalog, &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS), reply,
            activations.recipient(caller)?.0.progress(), request,
        )
    }).expect("timed fixture authenticated capture");
    activations.recipient_mut(caller).unwrap().0
        .retain_provider_wait(request, Ok(capture)).unwrap();
    ps_bootstrap::with_process_manager(|pm| {
        dispatcher_bootstrap::with_provider_objects(|mut objects| {
            objects.access = Some(ProviderDispatcherAccess::kernel_events(caller.owner()).unwrap());
            let (admission, replaced) = activations.publish_wait_work(
                caller, pm, catalog, &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS),
                &mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER), &mut objects,
                KernelProviderWaitWork::Initial(capture), next_dispatcher_wait_sequence(),
                nt_time_snapshot(), ComponentNativeContinuation::Kernel(capture),
                ComponentSuspensionCompletion::provider,
            ).unwrap_or_else(|_| panic!("timed fixture publication"));
            assert!(matches!(admission, ProviderDispatcherWaitAdmission::Parked { .. }));
            assert!(replaced.is_none());
        }).expect("bootstrap dispatcher owner");
        Ok(())
    }).unwrap();
    let ticks = DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed);
    let mut unrelated_done = false;
    let completed = crate::bootstrap_receive::drive(caller, || {
        if !unrelated_done {
            fixture::dispatch_once(unrelated);
            unrelated_done = true;
            return Ok(None);
        }
        let ready = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .next_resumable_if(|frame| matches!(frame.continuation,
                ComponentNativeContinuation::Kernel(found) if found == capture)).is_some();
        if !ready { return Ok(None); }
        assert!(DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed) > ticks,
            "timed fixture must observe a real hardware notification");
        let ticket = ps_bootstrap::with_process_manager(|pm| {
            activations.begin_wait_resume(caller, pm, catalog,
                &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS), capture)
                .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)
        })?;
        let (_, mut attempt, selected) = ticket.into_parts();
        assert_eq!(selected.completion.status, 0x102);
        let reply = ingress::current_reply(route).unwrap();
        ingress::reply(route, reply, &[0]).expect("timed fixture resume ACK");
        fixture::receive(route);
        let (_, returned) = ingress::next_message(route).unwrap().unwrap();
        assert_eq!(returned.info(), fixture::LABEL << 12);
        let reply = ingress::current_reply(route).unwrap();
        activations.recipient_mut(caller)?.0
            .observe_current(&mut attempt, facts(reply, true), Some(0), reply)
            .expect("timed fixture observed real return");
        let completion = ps_bootstrap::with_process_manager(|pm| {
            let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
            let terminal = activations.retain_terminal_completion(
                caller, pm, catalog, lanes, capture.key(),
                component_terminal::NativeTerminal::kernel_return(caller, 0), 0,
            ).map_err(|(status, _)| status)?;
            let mut delivery = lanes.begin_terminal_stage(terminal, reply, TerminalStage::LocalDelivery)
                .expect("timed fixture terminal delivery");
            activations.with_terminal_recipient(caller, pm, lanes, terminal, &delivery,
                |recipient, payload, status| {
                    assert_eq!(payload.kernel_result(), Some((caller, status)));
                    recipient.0.deliver_terminal_return(terminal, status)
                })??;
            lanes.record_terminal_stage(&mut delivery, reply, TerminalStageOutcome::Acknowledged)
                .expect("timed fixture local ACK");
            let (completion, _) = activations.finish_shared_terminal_completion(
                caller, pm, lanes, terminal, Ok(()),
            )?.expect("timed fixture semantic retirement");
            Ok(completion)
        })?;
        let result = ingress::complete(completion.route(), completion.dispatch(), completion.reply(), fixture::LABEL)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE);
        ps_bootstrap::with_process_manager(|pm| {
            let receipt = activations.record_shared_completion(completion, pm,
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS), result)?;
            let (status, _) = activations.acknowledge_completion_with_recipient(receipt, pm)?;
            assert_eq!(status, 0);
            Ok(())
        })?;
        Ok(Some(true))
    }).expect("timed fixture bootstrap receive");
    assert!(completed && unrelated_done);
    assert!(!component_execution_is_busy());
    dispatcher_bootstrap::with_local_events(|state| {
        let retired = state.retire(domain, local)?.expect("fixture Event has no retained leases");
        assert_eq!(retired, event);
        state.ack(domain, local, retired)
    }).unwrap();
    print_str(b"[bootstrap-wait-native] PASS timed-call=1 unrelated=1 hardware-wake=1 exact-ack=1\n");
}
