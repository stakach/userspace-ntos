use super::*;
use crate::ps_bootstrap::PsBootstrapState;
use nt_component_suspension::{SuspensionKey, TerminalStage, TerminalStageOutcome};
use nt_process::ThreadState;
use nt_provider_wait::{
    KernelProviderActivationDescriptor, ProviderStackActivationCatalog,
    ProviderStackActivationError,
};
use nt_types::AccessMode;

#[path = "provider_kernel_terminal_tests.rs"]
mod terminal_completion;

type Lanes = ComponentSuspensionLanes<u64, i32>;

fn bootstrap() -> PsBootstrapState {
    let mut bootstrap = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, _) = bootstrap.managers_mut();
    let system = pm.initial_system_identity().unwrap();
    assert!(pm.publish_process_kernel_object(system.process_id(), 0x1000));
    assert!(pm.publish_thread_kernel_object(system.thread_id(), 0x2000));
    bootstrap
}

fn requestor(pm: &mut ProcessManager, body: u64) -> NativeHandleCaller {
    let pid = pm.create_process("requestor", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, true).unwrap();
    pm.set_thread_state(tid, ThreadState::Running).unwrap();
    assert!(pm.publish_process_kernel_object(pid, body));
    assert!(pm.publish_thread_kernel_object(tid, body + 0x1000));
    pm.capture_native_handle_caller(pm.thread_lifetime(tid).unwrap(), AccessMode::KernelMode)
        .unwrap()
}

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: 100 + id,
        receive_endpoint: 200 + id,
        reply_object: 300 + id,
    }
}

fn references(pm: &ProcessManager, thread: ThreadLifetime) -> (u32, u32) {
    let blockers = pm
        .process_object_delete_blockers(thread.process_id())
        .unwrap();
    (
        blockers.process_kernel_pointer_references,
        blockers.thread_kernel_pointer_references,
    )
}

#[test]
fn capture_requires_exact_running_provider_and_duplicate_capture_is_atomic() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let other = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let mut activations = KernelProviderActivations::new();
    assert_eq!(
        activations.capture(&mut parts.pm, &catalog, &lanes, provider, lane, native),
        Err(STATUS_INVALID_HANDLE)
    );
    lanes.begin_dispatch(lane, reply).unwrap();
    let stale = ProviderDomainIdentity {
        generation: provider.generation + 1,
        ..provider
    };
    assert_eq!(
        activations.capture(&mut parts.pm, &catalog, &lanes, stale, lane, native),
        Err(STATUS_INVALID_HANDLE)
    );
    let caller = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    assert_eq!(caller.binding(), binding(1));
    assert_eq!(caller.owner().dispatch_id, dispatch.epoch());
    assert_eq!(caller.owner().caller, SuspensionCaller::Kernel { lane });
    assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
    for attempted_provider in [provider, other] {
        assert_eq!(
            activations.capture(
                &mut parts.pm,
                &catalog,
                &lanes,
                attempted_provider,
                lane,
                native
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
    }
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), provider),
        1
    );
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), other),
        0
    );
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Ok(())
    );

    let mut foreign_catalog = ProviderDomainCatalog::new();
    assert_eq!(foreign_catalog.register().unwrap(), provider);
    assert_eq!(
        activations.validate(caller, &parts.pm, &foreign_catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    let mut foreign_lanes = Lanes::new(1, 4);
    assert_eq!(foreign_lanes.allocate(binding(1)).unwrap(), lane);
    foreign_lanes.begin_dispatch(lane, reply).unwrap();
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &foreign_lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    foreign_lanes.finish_dispatch(lane, reply).unwrap();

    lanes.finish_dispatch(lane, reply).unwrap();
    activations.release(caller, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, caller.thread()), (0, 0));
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        activations.release(caller, &mut parts.pm),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn parked_and_reparked_jobs_retain_authority_but_cannot_execute() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    lanes.suspend_running(lane, reply, 55).unwrap();
    for iteration in 0..2 {
        assert_eq!(
            activations.validate(caller, &parts.pm, &catalog, &lanes),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
        assert_eq!(
            activations.retained_for_provider(catalog.identity().unwrap(), provider),
            1
        );
        lanes.resume_external(lane, reply, 55).unwrap();
        assert_eq!(
            activations.validate(caller, &parts.pm, &catalog, &lanes),
            Ok(())
        );
        if iteration == 0 {
            lanes.repark_external(lane, reply, 55).unwrap();
        }
    }
    lanes.complete_external(lane, reply, 55).unwrap();
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    lanes.begin_dispatch(lane, reply).unwrap();
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    let next = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    assert_ne!(next.owner().dispatch_id, caller.owner().dispatch_id);
    assert_eq!(references(&parts.pm, caller.thread()), (2, 2));
    activations.release(caller, &mut parts.pm).unwrap();
    assert_eq!(
        activations.validate(next, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    assert_eq!(references(&parts.pm, next.thread()), (1, 1));
    lanes.finish_dispatch(lane, reply).unwrap();
    activations.release(next, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, next.thread()), (0, 0));
}

#[test]
fn independent_lanes_retain_and_retire_their_original_threads() {
    let mut parts = bootstrap().into_parts();
    let first_native = requestor(&mut parts.pm, 0x3000);
    let second_native = requestor(&mut parts.pm, 0x5000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(2, 4);
    let first_lane = lanes.allocate(binding(1)).unwrap();
    let second_lane = lanes.allocate(binding(2)).unwrap();
    let mut activations = KernelProviderActivations::new();
    lanes
        .begin_dispatch(first_lane, binding(1).reply_object)
        .unwrap();
    let first = activations
        .capture(
            &mut parts.pm,
            &catalog,
            &lanes,
            provider,
            first_lane,
            first_native,
        )
        .unwrap();
    lanes
        .suspend_running(first_lane, binding(1).reply_object, 60)
        .unwrap();
    lanes
        .begin_dispatch(second_lane, binding(2).reply_object)
        .unwrap();
    let second = activations
        .capture(
            &mut parts.pm,
            &catalog,
            &lanes,
            provider,
            second_lane,
            second_native,
        )
        .unwrap();
    assert_ne!(first.thread(), second.thread());
    assert_ne!(first.owner(), second.owner());
    assert_eq!(references(&parts.pm, first.thread()), (1, 1));
    assert_eq!(references(&parts.pm, second.thread()), (1, 1));
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), provider),
        2
    );
    lanes
        .finish_dispatch(second_lane, binding(2).reply_object)
        .unwrap();
    activations.release(second, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, second.thread()), (0, 0));
    assert_eq!(references(&parts.pm, first.thread()), (1, 1));
    lanes
        .resume_external(first_lane, binding(1).reply_object, 60)
        .unwrap();
    assert_eq!(
        activations.validate(first, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    lanes
        .complete_external(first_lane, binding(1).reply_object, 60)
        .unwrap();
    activations.release(first, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, first.thread()), (0, 0));
}

#[test]
fn caller_exit_and_catalog_retirement_allow_exact_cleanup_after_wrong_manager_retry() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut foreign = bootstrap().into_parts();
    let foreign_native = requestor(&mut foreign.pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    assert_eq!(
        activations.capture(
            &mut parts.pm,
            &catalog,
            &lanes,
            provider,
            lane,
            foreign_native
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    let caller = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    assert_eq!(
        activations.validate(caller, &foreign.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    parts
        .pm
        .terminate_thread(caller.thread().thread_id(), 0)
        .unwrap();
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(!parts.pm.can_reclaim_thread(caller.thread().thread_id()));
    lanes.finish_dispatch(lane, reply).unwrap();
    lanes.begin_dispatch(lane, reply).unwrap();
    assert_eq!(
        activations.capture(&mut parts.pm, &catalog, &lanes, provider, lane, native),
        Err(STATUS_INVALID_HANDLE)
    );
    lanes.finish_dispatch(lane, reply).unwrap();
    assert!(activations.release(caller, &mut foreign.pm).is_err());
    assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
    let foreign_thread = foreign
        .pm
        .thread_lifetime(caller.thread().thread_id())
        .unwrap();
    assert_eq!(references(&foreign.pm, foreign_thread), (0, 0));
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), provider),
        1
    );
    // Simulate a retired provider after its execution ends; cleanup uses the retained Ps pair.
    catalog.retire(provider, 0).unwrap();
    activations.release(caller, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, caller.thread()), (0, 0));
    assert!(parts.pm.can_reclaim_thread(caller.thread().thread_id()));
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), provider),
        0
    );
}

#[test]
fn bootstrap_manager_move_preserves_initial_system_activation_and_reference_floor() {
    let mut bootstrap = bootstrap();
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let (pm, _) = bootstrap.managers_mut();
    let system = pm.initial_system_identity().unwrap();
    let baseline = references(pm, system.thread());
    let native = pm
        .capture_native_handle_caller(system.thread(), AccessMode::KernelMode)
        .unwrap();
    let caller = activations
        .capture(pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    assert_eq!(caller.thread(), system.thread());
    assert_eq!(
        references(pm, system.thread()),
        (baseline.0 + 1, baseline.1 + 1)
    );
    let mut parts = bootstrap.into_parts();
    assert_eq!(
        activations.validate(caller, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    lanes.finish_dispatch(lane, reply).unwrap();
    activations.release(caller, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, system.thread()), baseline);
    assert!(parts.pm.validate_initial_system_caller(system));
}

#[test]
fn foreign_table_copies_cannot_validate_or_release_an_identical_physical_job() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut first_table = KernelProviderActivations::new();
    let mut second_table = KernelProviderActivations::new();
    let first = first_table
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    let second = second_table
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    assert_eq!(first.owner(), second.owner());
    assert_eq!(first.thread(), second.thread());
    assert_eq!(first.binding(), second.binding());
    assert_ne!(first, second);
    assert_eq!(references(&parts.pm, first.thread()), (2, 2));
    assert_eq!(
        first_table.validate(second, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        second_table.validate(first, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        first_table.release(second, &mut parts.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        second_table.release(first, &mut parts.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&parts.pm, first.thread()), (2, 2));
    let identity = catalog.identity().unwrap();
    assert_eq!(first_table.retained_for_provider(identity, provider), 1);
    assert_eq!(second_table.retained_for_provider(identity, provider), 1);
    assert_eq!(
        first_table.validate(first, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    assert_eq!(
        second_table.validate(second, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    lanes.finish_dispatch(lane, reply).unwrap();
    first_table.release(first, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, second.thread()), (1, 1));
    assert_eq!(
        second_table.release(first, &mut parts.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    second_table.release(second, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, second.thread()), (0, 0));
}

#[test]
fn released_copy_cannot_alias_a_recapture_with_the_same_dispatch_epoch() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let old = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    // No native execution is started by this harness; retire the first capture before recapture.
    activations.release(old, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, old.thread()), (0, 0));
    let replacement = activations
        .capture(&mut parts.pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    assert_eq!(replacement.owner(), old.owner());
    assert_ne!(replacement, old);
    assert_eq!(
        activations.validate(old, &parts.pm, &catalog, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        activations.release(old, &mut parts.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&parts.pm, replacement.thread()), (1, 1));
    assert_eq!(
        activations.retained_for_provider(catalog.identity().unwrap(), provider),
        1
    );
    assert_eq!(
        activations.validate(replacement, &parts.pm, &catalog, &lanes),
        Ok(())
    );
    lanes.finish_dispatch(lane, reply).unwrap();
    activations.release(replacement, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, replacement.thread()), (0, 0));
}

#[test]
fn activation_counter_rejects_invalid_and_exhausted_values_without_wrapping() {
    for value in [0, u64::MAX] {
        let counter = AtomicU64::new(value);
        for _ in 0..2 {
            assert_eq!(
                next_activation(&counter),
                Err(STATUS_INSUFFICIENT_RESOURCES)
            );
            assert_eq!(counter.load(Ordering::Relaxed), value);
        }
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(next_activation(&counter), Ok(u64::MAX - 1));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(
        next_activation(&counter),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn root_descriptor_publication_preserves_identity_and_nested_local_irql_isolation() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut domains = ProviderDomainCatalog::new();
    let provider = domains.register().unwrap();
    let mut lanes = Lanes::new(2, 4);
    let _idle_lane = lanes.allocate(binding(1)).unwrap();
    let root_lane = lanes.allocate(binding(2)).unwrap();
    let reply = binding(2).reply_object;
    lanes.begin_dispatch(root_lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, root_lane, native)
        .unwrap();
    let descriptor = KernelProviderActivationDescriptor::new(caller.owner()).unwrap();
    assert_eq!(descriptor.validate(provider), Ok(caller.owner()));
    assert_eq!(
        activations.validate(caller, &parts.pm, &domains, &lanes),
        Ok(())
    );

    let mut stacks = ProviderStackActivationCatalog::new(1, 4).unwrap();
    let local_lane = stacks.register_lane(91, 0x8000, 0x1000).unwrap();
    assert_ne!(local_lane.slot(), root_lane.index);
    let outer = stacks
        .begin_kernel_for_stack_pointer(0x8800, provider, descriptor)
        .unwrap();
    assert_eq!(outer.lane, local_lane);
    assert_eq!(outer.lane_id, 91);
    assert_eq!(outer.dispatch_id, caller.owner().dispatch_id);
    assert_eq!(stacks.owner(outer), Ok(Some(caller.owner())));
    assert_eq!(
        stacks.raise_irql(outer, nt_kernel_exec::DISPATCH_LEVEL),
        Ok(0)
    );

    // This is local activation composition, not an invocation of native provider or IPC code.
    let nested = stacks.begin_for_stack_pointer(0x8700, 17).unwrap();
    assert_eq!(stacks.owner(nested), Ok(None));
    assert_eq!(
        stacks.current_irql(nested),
        Ok(nt_kernel_exec::PASSIVE_LEVEL)
    );
    assert_eq!(
        stacks.owner(outer),
        Err(ProviderStackActivationError::NotTop)
    );
    stacks
        .raise_irql(nested, nt_kernel_exec::APC_LEVEL)
        .unwrap();
    assert_eq!(stacks.current_irql(nested), Ok(nt_kernel_exec::APC_LEVEL));
    stacks
        .lower_irql(nested, nt_kernel_exec::PASSIVE_LEVEL)
        .unwrap();
    stacks.finish(nested).unwrap();
    assert_eq!(stacks.active(local_lane), Ok(outer));
    assert_eq!(stacks.owner(outer), Ok(Some(caller.owner())));
    assert_eq!(
        stacks.current_irql(outer),
        Ok(nt_kernel_exec::DISPATCH_LEVEL)
    );
    assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
    stacks
        .lower_irql(outer, nt_kernel_exec::PASSIVE_LEVEL)
        .unwrap();
    stacks.finish(outer).unwrap();
    assert_eq!(
        stacks.owner(outer),
        Err(ProviderStackActivationError::NotTop)
    );
    assert_eq!(
        activations.validate(caller, &parts.pm, &domains, &lanes),
        Ok(())
    );
    lanes.finish_dispatch(root_lane, reply).unwrap();
    assert_eq!(
        activations.validate(caller, &parts.pm, &domains, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    activations.release(caller, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, caller.thread()), (0, 0));
    assert_eq!(descriptor.validate(provider), Ok(caller.owner()));
    assert_eq!(
        activations.validate(caller, &parts.pm, &domains, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    stacks.unregister_lane(local_lane).unwrap();
}

#[test]
fn parseable_old_descriptor_cannot_authorize_a_new_root_job_or_released_capture() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut domains = ProviderDomainCatalog::new();
    let provider = domains.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let root_lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let mut activations = KernelProviderActivations::new();
    let mut stacks = ProviderStackActivationCatalog::new(1, 4).unwrap();
    let local_lane = stacks.register_lane(73, 0x8000, 0x1000).unwrap();
    lanes.begin_dispatch(root_lane, reply).unwrap();
    let old = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, root_lane, native)
        .unwrap();
    let old_descriptor = KernelProviderActivationDescriptor::new(old.owner()).unwrap();
    let first = stacks
        .begin_kernel_for_stack_pointer(0x8800, provider, old_descriptor)
        .unwrap();
    stacks.finish(first).unwrap();
    lanes.finish_dispatch(root_lane, reply).unwrap();
    lanes.begin_dispatch(root_lane, reply).unwrap();
    assert_eq!(old_descriptor.validate(provider), Ok(old.owner()));
    assert_eq!(
        activations.validate(old, &parts.pm, &domains, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        stacks.begin_kernel_for_stack_pointer(0x8800, provider, old_descriptor),
        Err(ProviderStackActivationError::StaleKernelDispatch)
    );

    let next = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, root_lane, native)
        .unwrap();
    let next_descriptor = KernelProviderActivationDescriptor::new(next.owner()).unwrap();
    assert!(next_descriptor.dispatch_epoch > old_descriptor.dispatch_epoch);
    assert_eq!(references(&parts.pm, next.thread()), (2, 2));
    activations.release(old, &mut parts.pm).unwrap();
    assert_eq!(references(&parts.pm, next.thread()), (1, 1));
    assert_eq!(old_descriptor.validate(provider), Ok(old.owner()));
    assert_eq!(
        activations.validate(old, &parts.pm, &domains, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        activations.validate(next, &parts.pm, &domains, &lanes),
        Ok(())
    );
    let second = stacks
        .begin_kernel_for_stack_pointer(0x8800, provider, next_descriptor)
        .unwrap();
    assert_eq!(stacks.owner(second), Ok(Some(next.owner())));
    assert_eq!(second.lane, local_lane);
    assert_eq!(second.lane_id, 73);
    assert_ne!(second.generation, first.generation);
    stacks.finish(second).unwrap();
    lanes.finish_dispatch(root_lane, reply).unwrap();
    activations.release(next, &mut parts.pm).unwrap();
    assert_eq!(next_descriptor.validate(provider), Ok(next.owner()));
    assert_eq!(
        activations.validate(next, &parts.pm, &domains, &lanes),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&parts.pm, next.thread()), (0, 0));
    assert_eq!(
        activations.retained_for_provider(domains.identity().unwrap(), provider),
        0
    );
}

#[test]
fn suspended_selected_cancelled_and_terminal_work_cannot_publish_a_return() {
    for cancel in [false, true] {
        let mut parts = bootstrap().into_parts();
        let native = requestor(&mut parts.pm, 0x3000);
        let mut domains = ProviderDomainCatalog::new();
        let provider = domains.register().unwrap();
        let mut lanes = Lanes::new(1, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        let reply = binding(1).reply_object;
        lanes.begin_dispatch(lane, reply).unwrap();
        let mut activations = KernelProviderActivations::new();
        let caller = activations
            .capture(&mut parts.pm, &domains, &lanes, provider, lane, native)
            .unwrap();
        assert!(activations.completion(caller).is_err());
        lanes.suspend_running(lane, reply, 70).unwrap();
        assert_eq!(
            activations.validate_retained(caller, &parts.pm, &domains, &lanes),
            Ok(())
        );
        assert!(activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
            .is_err());
        lanes.resume_external(lane, reply, 70).unwrap();
        let key = SuspensionKey::provider_wait(71);
        lanes
            .admit_running(lane, reply, key, 1, caller.owner(), 500)
            .unwrap();
        assert_eq!(
            activations.validate_retained(caller, &parts.pm, &domains, &lanes),
            Ok(())
        );
        assert!(activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
            .is_err());
        lanes.select(key, 0).unwrap();
        assert!(activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
            .is_err());
        if cancel {
            lanes.cancel(key, 0xc000_0120u32 as i32).unwrap();
            assert!(activations
                .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
                .is_err());
        }
        lanes.begin_resume(lane, reply, key).unwrap();
        assert!(activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
            .is_err());
        let terminal = lanes
            .retain_terminal_running(lane, reply, key, caller.owner(), ())
            .unwrap();
        assert!(activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
            .is_err());
        assert!(activations.completion(caller).is_err());
        assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
        for stage in [
            TerminalStage::Output,
            TerminalStage::Context,
            TerminalStage::Publication,
            TerminalStage::Reply,
        ] {
            let mut attempt = lanes.begin_terminal_stage(terminal, reply, stage).unwrap();
            lanes
                .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
                .unwrap();
        }
        lanes
            .finish_terminal(terminal, reply, Ok(()))
            .unwrap()
            .unwrap();
        lanes.resume_external(lane, reply, 70).unwrap();
        lanes.retire_external_running(lane, reply, 70).unwrap();
        let receipt = activations
            .record_completion(caller, &parts.pm, &domains, &mut lanes, 0xc000_0001)
            .unwrap();
        assert_eq!(receipt.caller(), caller);
        assert_eq!(receipt.status(), 0xc000_0001);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
        assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
        assert_eq!(activations.completion(caller), Ok(receipt));
        assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
        assert!(activations.release(caller, &mut parts.pm).is_err());
        assert_eq!(activations.completion(caller), Ok(receipt));
        assert_eq!(
            activations.acknowledge_completion(receipt, &mut parts.pm),
            Ok(0xc000_0001)
        );
        assert_eq!(references(&parts.pm, caller.thread()), (0, 0));
        assert!(activations.completion(caller).is_err());
    }
}

#[test]
fn caller_exit_allows_retained_return_and_failed_ack_survives_provider_retirement() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut foreign = bootstrap().into_parts();
    let _foreign_native = requestor(&mut foreign.pm, 0x3000);
    let mut domains = ProviderDomainCatalog::new();
    let provider = domains.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, lane, native)
        .unwrap();
    parts
        .pm
        .terminate_thread(caller.thread().thread_id(), 0)
        .unwrap();
    assert_eq!(
        activations.validate_retained(caller, &parts.pm, &domains, &lanes),
        Ok(())
    );
    assert!(activations
        .validate(caller, &parts.pm, &domains, &lanes)
        .is_err());
    assert!(activations
        .validate_retained(caller, &foreign.pm, &domains, &lanes)
        .is_err());
    let receipt = activations
        .record_completion(caller, &parts.pm, &domains, &mut lanes, 0)
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert!(!parts.pm.can_reclaim_thread(caller.thread().thread_id()));
    assert!(activations
        .acknowledge_completion(receipt, &mut foreign.pm)
        .is_err());
    assert_eq!(activations.completion(caller), Ok(receipt));
    assert_eq!(references(&parts.pm, caller.thread()), (1, 1));
    let foreign_thread = foreign
        .pm
        .thread_lifetime(caller.thread().thread_id())
        .unwrap();
    assert_eq!(references(&foreign.pm, foreign_thread), (0, 0));
    domains.retire(provider, 0).unwrap();
    assert_eq!(
        activations.acknowledge_completion(receipt, &mut parts.pm),
        Ok(0)
    );
    assert!(parts.pm.can_reclaim_thread(caller.thread().thread_id()));
    assert_eq!(references(&parts.pm, caller.thread()), (0, 0));
    assert!(activations
        .acknowledge_completion(receipt, &mut parts.pm)
        .is_err());
}

#[test]
fn completion_receipts_cannot_retire_foreign_tables_or_a_later_job() {
    let mut parts = bootstrap().into_parts();
    let native = requestor(&mut parts.pm, 0x3000);
    let mut domains = ProviderDomainCatalog::new();
    let provider = domains.register().unwrap();
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let mut foreign_table = KernelProviderActivations::new();
    let old = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, lane, native)
        .unwrap();
    let foreign = foreign_table
        .capture(&mut parts.pm, &domains, &lanes, provider, lane, native)
        .unwrap();
    let receipt = activations
        .record_completion(old, &parts.pm, &domains, &mut lanes, 0x4000_0001)
        .unwrap();
    let mut wrong_status = receipt;
    wrong_status.status = 0;
    assert!(activations
        .acknowledge_completion(wrong_status, &mut parts.pm)
        .is_err());
    assert_eq!(activations.completion(old), Ok(receipt));
    assert!(foreign_table
        .acknowledge_completion(receipt, &mut parts.pm)
        .is_err());
    assert_eq!(references(&parts.pm, old.thread()), (2, 2));
    foreign_table.release(foreign, &mut parts.pm).unwrap();
    lanes.begin_dispatch(lane, reply).unwrap();
    let next = activations
        .capture(&mut parts.pm, &domains, &lanes, provider, lane, native)
        .unwrap();
    assert_ne!(next.owner().dispatch_id, old.owner().dispatch_id);
    assert!(activations
        .record_completion(old, &parts.pm, &domains, &mut lanes, 0)
        .is_err());
    assert_eq!(
        activations.validate(next, &parts.pm, &domains, &lanes),
        Ok(())
    );
    assert_eq!(activations.completion(old), Ok(receipt));
    assert_eq!(
        activations.acknowledge_completion(receipt, &mut parts.pm),
        Ok(0x4000_0001)
    );
    assert!(activations
        .acknowledge_completion(receipt, &mut parts.pm)
        .is_err());
    assert_eq!(references(&parts.pm, next.thread()), (1, 1));
    assert_eq!(
        activations.validate(next, &parts.pm, &domains, &lanes),
        Ok(())
    );
    let next_receipt = activations
        .record_completion(next, &parts.pm, &domains, &mut lanes, 0)
        .unwrap();
    assert!(activations
        .acknowledge_completion(receipt, &mut parts.pm)
        .is_err());
    assert_eq!(activations.completion(next), Ok(next_receipt));
    assert_eq!(references(&parts.pm, next.thread()), (1, 1));
    assert_eq!(
        activations.acknowledge_completion(next_receipt, &mut parts.pm),
        Ok(0)
    );
    assert_eq!(references(&parts.pm, next.thread()), (0, 0));
}
