use super::*;
use crate::ps_bootstrap::PsBootstrapState;
use nt_process::ThreadState;
use nt_types::AccessMode;

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
