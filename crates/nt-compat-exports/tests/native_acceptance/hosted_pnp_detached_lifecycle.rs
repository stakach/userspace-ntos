//! Native lifecycle dispatch must release the I/O Manager borrow before provider entry.

const SOURCE: &str =
    include_str!("../../../../components/ntos-executive/src/driver_launch.rs");
const FILE_DISPATCH: &str =
    include_str!("../../../../components/ntos-executive/src/hosted_file_dispatch.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = source.split_once(start).expect("missing lifecycle boundary");
    tail.split_once(end).expect("missing lifecycle end boundary").0
}

#[test]
fn non_start_lifecycle_retains_exact_dispatch_owner_outside_manager_borrow() {
    let dispatch = between(
        SOURCE,
        "pub(crate) unsafe fn dispatch_hosted_pnp_lifecycle_canonical(",
        "/// Send a canonical `IRP_MN_START_DEVICE`",
    );
    assert!(!dispatch.contains("dispatch_prepared_external_pnp"));
    for required in [
        "DetachedDispatchInFlight",
        "begin_prepared_external_pnp(prepared)",
        "invocation.invoke(",
        "finish_external_pnp(returned)",
        "HostedDetachedPnpOwner::Retained(retained)",
        "HostedDetachedPnpOwner::DispatchReturned(rejection.into_owner())",
        "hosted_pnp_physical_provider(instance_index, projection.driver_id)",
        "acquire_hosted_provider_dependency_dispatch_lease(",
    ] {
        assert!(dispatch.contains(required), "missing detached lifecycle step: {required}");
    }
    assert!(
        dispatch.find("begin_prepared_external_pnp(prepared)").unwrap()
            < dispatch.find("invocation.invoke(").unwrap()
    );
    assert!(
        dispatch.find("invocation.invoke(").unwrap()
            < dispatch.find("finish_external_pnp(returned)").unwrap()
    );
}

#[test]
fn pending_lifecycle_acks_exact_provider_before_state_publication() {
    let drain = between(
        SOURCE,
        "unsafe fn drain_hosted_detached_lifecycle_completion(",
        "unsafe fn drain_hosted_pnp_completions()",
    );
    let ordered = [
        "owner.payload().is_empty()",
        "prepare_external_pnp_completion(owner)",
        "DetachedAckInFlight",
        "FSD_DISPATCH_ACK_COMPLETION",
        "finish_external_pnp_completion(returned)",
        "complete_hosted_pnp_lifecycle(irp_id, status)",
        "finish_hosted_pnp_publication(irp_id)",
    ];
    let mut previous = 0;
    for step in ordered {
        let index = drain.find(step).unwrap_or_else(|| panic!("missing lifecycle step: {step}"));
        assert!(index >= previous, "lifecycle step out of order: {step}");
        previous = index;
    }
    assert!(drain.contains("HostedDetachedPnpOwner::AckReturned(rejection.into_owner())"));
    assert!(drain.contains("completion.completion_origin == IrpCompletionOrigin::Driver"));
    assert!(drain.contains("hosted_pnp_physical_provider_current(provider)"));
    assert!(drain.contains("control_exact_storage("));
    assert!(!drain.contains("take_completed_external_pnp_receipt"));
    assert!(!drain.contains("acknowledge_completed_irp_strict"));
    let exact = between(FILE_DISPATCH, "pub(super) fn control_exact_storage(", "pub(super) fn execute(");
    assert!(!exact.contains("hosted_completion_storage_instance"));
    assert!(exact.contains("instance_domain_identity(inst) != Some(storage_domain)"));
    let poll = between(
        SOURCE,
        "unsafe fn poll_hosted_detached_pnp_completion(",
        "// --- host-side pool allocator",
    );
    assert!(poll.contains("poll_hosted_completion_at_storage(dependent_instance, provider.storage_instance)"));
    assert!(!poll.contains("io_manager_mut"));
}

#[test]
fn no_entry_ack_retry_keeps_exact_owner_and_provider_out_of_completion_drain() {
    let retry = between(
        SOURCE,
        "unsafe fn retry_hosted_detached_lifecycle_ack(",
        "unsafe fn drain_hosted_pnp_completions()",
    );
    for required in [
        "HostedDetachedPnpOwner::AckReturned(returned)",
        "CompletionAcknowledgement::NotEntered",
        "detached_provider_lease.is_some()",
        "hosted_pnp_physical_provider_current(provider)",
        "retry_external_pnp_completion(returned)",
        "DetachedAckInFlight",
        "control_exact_storage(",
        "finish_hosted_detached_lifecycle_ack(irp_id, returned)",
    ] {
        assert!(retry.contains(required), "missing checked ACK retry step: {required}");
    }
    let drain = between(
        SOURCE,
        "unsafe fn drain_hosted_pnp_completions()",
        "pub(crate) unsafe fn observe_hosted_pnp_start(",
    );
    assert!(!drain.contains("retry_hosted_detached_lifecycle_ack(irp_id)"));
    let observe = between(
        SOURCE,
        "pub(crate) unsafe fn observe_hosted_pnp_lifecycle(",
        "pub(crate) unsafe fn abandon_pending_irp(",
    );
    assert!(observe.contains("retry_hosted_detached_lifecycle_ack(irp_id)"));
}
