//! Source-level guard for the native boundary between Ps object lifetime and execution-slot life.

const EXECUTIVE: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const VM_RETIREMENT: &str = include_str!("../../../components/ntos-executive/src/process_vm_retirement.rs");
const PS_RETIREMENT: &str = include_str!("../../../components/ntos-executive/src/ps_object_retirement.rs");

#[test]
fn execution_retires_before_external_process_handles_close() {
    assert!(EXECUTIVE.contains("ProcessDeletionPhase::AwaitingExecutionQuiescence"));
    assert!(EXECUTIVE.contains("ProcessDeletionPhase::RetiringExecution"));
    assert!(EXECUTIVE.contains("process_execution_retirement_ready(pid)"));
    assert!(EXECUTIVE.contains("ProcessDeletionPhase::AwaitingReferences"));
    assert!(EXECUTIVE.contains("process_object_delete_ready(pid)"));
    assert!(VM_RETIREMENT.contains("ProcessObjectDeleteBlockers::execution_retirement_ready"));
    assert!(!VM_RETIREMENT.contains("ProcessObjectDeleteBlockers::delete_ready"));
    assert!(!VM_RETIREMENT.contains(".delete_ready)"));
}

#[test]
fn detached_object_cleanup_uses_exact_identity_and_saved_provider_metadata() {
    assert!(EXECUTIVE.contains("process_deletion_candidates.get_exact"));
    assert!(EXECUTIVE.contains("process_deletion_candidates.iter()"));
    assert!(EXECUTIVE.contains("provider_finalizer_context"));
}

#[test]
fn terminated_process_cannot_lose_its_deletion_owner_to_allocation_failure() {
    let register = EXECUTIVE
        .split("fn register_hosted_process_identity(")
        .nth(1)
        .unwrap()
        .split("fn register_hosted_pool_thread_identity(")
        .next()
        .unwrap();
    assert!(register.contains("process_deletion_candidates.try_reserve(MAX_PI)"));
    assert!(
        register.find("process_deletion_candidates.try_reserve(MAX_PI)").unwrap()
            < register.find("process_mechanisms").unwrap(),
        "retry-owner capacity must be reserved before a mechanism is published"
    );
    let deletion = EXECUTIVE
        .split("pub(crate) fn try_delete_hosted_process_object(")
        .nth(1)
        .unwrap()
        .split("fn trace_hosted_process_delete_blockers(")
        .next()
        .unwrap();
    assert!(deletion.contains("Err(nt_user_host::MechanismError::InsufficientResources)"));
    assert!(deletion.contains("return HostedProcessDeletionOutcome::Pending(candidate.phase)"));
    let drain = EXECUTIVE
        .split("pub(crate) fn drain_hosted_process_deletion_candidates(")
        .nth(1)
        .unwrap()
        .split("fn drain_failed_thread_constructions(")
        .next()
        .unwrap();
    assert!(drain.contains("for pi in 0..MAX_PI"));
    assert!(drain.contains("process_deletion_candidates.get_exact"));
    assert!(!EXECUTIVE.contains("let _ = handler.register_hosted_process_identity"));
    assert!(EXECUTIVE.contains("bootstrap process identity and deletion-owner capacity"));
}

#[test]
fn persistent_retirement_rows_allocate_from_durable_scope() {
    let register = EXECUTIVE
        .split("fn register_hosted_process_identity(")
        .nth(1).unwrap()
        .split("fn register_hosted_pool_thread_identity(")
        .next().unwrap();
    assert!(register.contains("let _durable = allocator::enter_durable();"));
    assert!(register.find("let _durable = allocator::enter_durable();").unwrap()
        < register.find("process_deletion_candidates.try_reserve(MAX_PI)").unwrap());
    let deletion = EXECUTIVE
        .split("pub(crate) fn try_delete_hosted_process_object(")
        .nth(1).unwrap()
        .split("fn trace_hosted_process_delete_blockers(")
        .next().unwrap();
    let queue = deletion.split("let queued = {").nth(1).unwrap().split("};").next().unwrap();
    assert!(queue.find("let _durable = allocator::enter_durable();").unwrap()
        < queue.find("self.process_deletion_candidates.queue(candidate)").unwrap());
    let prepare = PS_RETIREMENT
        .split("pub(crate) fn prepare_provider_context(")
        .nth(1).unwrap()
        .split("pub(crate) fn provider_finalizer_context(")
        .next().unwrap();
    assert!(prepare.find("let _durable = crate::allocator::enter_durable();").unwrap()
        < prepare.find("self.rows").unwrap());
}
