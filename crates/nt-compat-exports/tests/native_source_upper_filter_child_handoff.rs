//! A class UpperFilter AddDevice may request nested File work while its original Reply is held.

const UPPER: &str = include_str!("../../../components/ntos-executive/src/hosted_upper_filter_add_device.rs");
const PNP: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const ROLLBACK: &str = include_str!("../../../components/ntos-executive/src/hosted_add_device_rollback.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/hosted_add_device_continuation.rs");

#[test]
fn upper_filter_dispatch_uses_a_typed_retained_child_work_pump() {
    let entered = UPPER.split_once("unsafe fn drive(mut self)")
        .expect("entered upper-filter continuation").1;
    assert!(!entered.contains("dispatch_add_device_for_instance("),
        "the synchronous AddDevice pump cannot unwind a nested CONNECT to root");
    assert!(UPPER.contains("AddDevicePumpProgress")
        && UPPER.contains("dispatch_class_lower_alias_progress")
        && UPPER.contains("dispatch_add_device_for_instance_progress"),
        "both native filter phases must use the typed child-work pump");
    assert!(UPPER.contains("ChildWorkYield") && UPPER.contains("RetainedRefusal"),
        "a yielded or retryable parent cannot be flattened into NTSTATUS failure");
    assert!(UPPER.contains("UpperFilterAttachmentClaim")
        && UPPER.contains("record_child_step")
        && UPPER.contains("resume("),
        "the entered ledger claim must remain owned until the exact child step resumes it");
}

#[test]
fn deferred_rollback_keeps_the_class_page_until_its_terminal_drain() {
    assert!(UPPER.contains("transfer_to_rollback")
        && PUMP.contains("attach_bank_ticket")
        && UPPER.contains("commit_banked"),
        "the class page lease must move into rollback before native AddDevice enters");
    assert!(ROLLBACK.contains("bank_ticket.take()")
        && ROLLBACK.contains("retire_add_device_bank(ticket)"),
        "deferred rollback must retire its own exact page ticket at terminal cleanup");
}

#[test]
fn known_add_device_error_enters_ordered_cleanup_without_replaying_the_callback() {
    let terminal = UPPER.split_once("ActivePhase::AddDeviceTerminal(result) => {")
        .expect("typed AddDevice terminal").1
        .split_once("Ok(dispatch) => {")
        .expect("successful dispatch boundary").0;
    assert!(terminal.contains("Self::mark_terminal_failure(&mut active, status)"),
        "an authenticated error must drain rollback and its page instead of blocking forever");
}

#[test]
fn failed_filter_waits_for_its_exact_rollback_before_function_stack_teardown() {
    assert!(ROLLBACK.contains("struct AbortReceipt")
        && ROLLBACK.contains("enum AbortProgress")
        && ROLLBACK.contains("retry_abort_owned"),
        "deferred rollback must retain a generation-specific terminal receipt");
    assert!(UPPER.contains("ActivePhase::AbortPending")
        && UPPER.contains("AbortProgress::Retiring")
        && UPPER.contains("AbortProgress::Blocked"),
        "upper-filter failure must remain pending until its exact rollback has retired");
}

#[test]
fn attached_filter_is_retained_if_ledger_commit_refuses() {
    let failure = UPPER.split_once("unsafe fn mark_terminal_failure(")
        .expect("upper-filter terminal failure gate").1
        .split_once("unsafe fn block_unsettled(")
        .expect("uncertain result boundary").0;
    assert!(failure.contains("if active.transferred")
        && failure.contains("hosted_add_device_rollback::block(rollback, status)")
        && failure.contains("active.phase = ActivePhase::Blocked"),
        "an attached upper FDO must hold the class bank and PnP resource plan on ledger refusal");
}

#[test]
fn ordered_plan_failure_after_reservation_cannot_tear_down_prior_filter() {
    let admission = UPPER.split_once("if self.active.is_none() {")
        .expect("ordered upper-filter admission").1
        .split_once("let mut active = self.active.take()")
        .expect("entered filter boundary").0;
    assert!(!admission.contains("Err(status) => return UpperFilterAttachProgress::Completed(Err(status))"),
        "a failed later filter may leave a prior upper FDO attached");
    assert!(admission.contains("UpperFilterAttachProgress::RetainedRefusal(self)"),
        "the reserved plan must stay owned after an admission effect or ambiguous refusal");
}

#[test]
fn class_page_is_leased_before_alias_projection_can_write_it() {
    let prepare = UPPER.split_once("unsafe fn begin_next(&mut self)")
        .expect("filter preparation boundary").1
        .split_once("unsafe fn finish_dispatch(")
        .expect("post preparation boundary").0;
    assert!(prepare.contains("reserve_alias_owner(")
        && prepare.contains("AddDeviceBanks::claim("),
        "reserve projection identity and then lease its class page");
    assert!(!prepare.contains("hosted_upper_filter_projection::prepare("),
        "the old synchronous projection helper could write the class page before its lease");
    assert!(UPPER.contains("dispatch_pdo_projection_progress")
        && UPPER.contains("accept_alias_projection"),
        "each alias projection must use the typed retained pump and exact owner");
}

#[test]
fn alias_failure_keeps_the_bank_and_lower_stack_until_exact_retirement() {
    let failure = UPPER.split_once("unsafe fn mark_terminal_failure(")
        .expect("upper-filter failure gate").1
        .split_once("unsafe fn block_unsettled(")
        .expect("uncertain result boundary").0;
    assert!(failure.contains("if active.rollback.is_none()")
        && failure.contains("active.phase = ActivePhase::Blocked"),
        "an alias owner without rollback cannot release its page or function FDO on failure");
}

#[test]
fn pnp_batch_retains_upper_filter_after_function_add_device_without_replaying_it() {
    assert!(PNP.contains("pending_upper_filter"),
        "the batch must own the class filter continuation and resource plan across yield");
    assert!(PNP.contains("UpperFilterPending")
        && PNP.contains("record_upper_filter_child_step"),
        "a yielded filter must have its own typed pending phase and one-use child deposit");
    let finish = PNP.split_once("unsafe fn finish_add_device_for_devnode(")
        .expect("function AddDevice terminal tail").1
        .split_once("unsafe fn filter_attached_devnode(")
        .expect("FILTER tail boundary").0;
    assert!(finish.contains("attach_hosted_class_upper_filters_progress"),
        "function AddDevice terminal must hand a live filter continuation to the batch");
}

#[test]
fn root_selects_the_exact_upper_filter_child_before_other_provider_redrives() {
    let service = ROOT.split_once("'service_loop: loop {")
        .expect("flat root service loop").1;
    let child = service.find("run_one_pending_add_device_child_step(")
        .expect("root selects one retained AddDevice child step");
    let parent = service[child..].find("redrive_flat_root_add_device_selected(")
        .expect("root resumes the selected PnP batch") + child;
    let unrelated = service.find("redrive_hosted_driver_io_create_file(")
        .expect("later unrelated provider redrive");
    assert!(child < parent && parent < unrelated,
        "the upper-filter child and parent must settle before unrelated providers enter");
    let wait_stage = PNP.split_once("pub(crate) fn wait_stage(&self)")
        .expect("batch wait stage").1
        .split_once("pub(crate) fn").expect("following batch method").0;
    assert!(wait_stage.contains("pending_upper_filter.is_some()")
        && PNP.contains("self.record_upper_filter_child_step(step)"),
        "root's generic AddDevice selector must include the exact retained upper filter");
}
