//! A queued callback can await a local File child without an AddDevice parent.
//! The original callback selector and Reply stay parked while root handles the
//! current notification or retains an unrelated Call before another Receive.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const QUEUE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_work_queue_owner.rs");
const INGRESS: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing boundary: {end}"))
        .0
}

fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    between(source, signature, "\n}\n")
}

fn early_callback_wait() -> &'static str {
    SERVICE
        .split_once("// A callback reached by the preceding AddDevice child")
        .expect("early callback settlement")
        .1
        .split_once("ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked")
        .expect("end of retryable child branch")
        .0
}

#[test]
fn empty_queued_child_without_add_device_is_not_a_terminal_add_device_failure() {
    let early = early_callback_wait();
    assert!(early.contains("ConnectPumpSettlement::AwaitingLocalChild"));
    assert!(!early.contains("root_add_device_turn.is_none()\n                        || !prepare_parked_add_device_receive"),
        "a generic callback's empty child step cannot require an AddDevice turn");
    assert!(
        early.contains("if root_add_device_turn.is_none() {")
            && early.contains("park_queued_callback_root_receive!(root_event_consumed);")
            && early.contains("if !prepare_parked_add_device_receive(&mut root_add_device_turn)"),
        "a standalone callback must enter its wait before the AddDevice-only branch"
    );
}

#[test]
fn later_generic_settlement_keeps_retryable_child_absence_distinct_from_uncertainty() {
    let generic = SERVICE
        .split_once("let queue_settlement = settle_queued_callbacks();")
        .expect("generic callback settlement")
        .1
        .split_once("trace_connect_root_checkpoint(4, None)")
        .expect("later Hook boundary")
        .0;
    assert!(
        generic.contains("ConnectPumpSettlement::AwaitingLocalChild =>"),
        "a retained callback waiting for a child needs a bounded root wait before Hook redrive"
    );
    assert!(
        generic.contains("ConnectPumpSettlement::Retained")
            && generic.contains("ConnectPumpSettlement::Blocked"),
        "uncertain or blocked owners remain fail-closed with their exact Reply"
    );
}

#[test]
fn no_ready_child_keeps_the_exact_callback_selector_and_reply_parked() {
    let deposit = QUEUE
        .split_once("pub(crate) unsafe fn record_queued_callback_child_step(")
        .expect("exact queued callback child deposit")
        .1
        .split_once("pub(crate) unsafe fn unsettled_queued_callback()")
        .expect("end of exact child deposit")
        .0;
    let no_ready = deposit
        .split_once("if !step.ran_child() {")
        .expect("empty child observation")
        .1
        .split_once("row.child_step = Some(step);")
        .expect("recorded child effect boundary")
        .0;
    assert!(no_ready.contains("QueuedCallbackProgress::AwaitingLocalChild"));
    assert!(
        !no_ready.contains("row.pump.take()")
            && !no_ready.contains("row.claim.take()")
            && !no_ready.contains("reply"),
        "an empty observation cannot release or replay the callback's physical owner"
    );
}

#[test]
fn queued_wait_revalidates_the_newest_generation_and_physical_reply() {
    let selector = between(
        QUEUE,
        "unsafe fn exact_physical_identity(",
        "fn selector_for(",
    );
    assert!(
        selector.contains("runtime::dispatch(identity.route).ok() != Some(identity.dispatch)")
            && selector.contains(
                "runtime::current_reply(identity.route).ok() != Some(identity.reply_cap)"
            ),
        "the callback selector must authenticate the live physical dispatch and Reply"
    );
    let permit = between(
        SERVICE,
        "impl ParkedRootQueuedCallbackPermit {",
        "fn ready_flat_root_add_device(",
    );
    assert!(
        permit.contains("Action::NeedsChild(selector)")
            && permit.contains("Action::RetryRestore(selector)")
            && permit.contains("if selector == self.0")
            && permit.contains("queued_callback_root_action()")
            && permit.contains("queued_callback_file_floor(self.0)"),
        "a park permit must reselect the same live queue generation before any ingress effect"
    );
}

#[test]
fn queued_wait_retains_an_unrelated_call_and_its_original_reply() {
    let defer = between(
        INGRESS,
        "pub(crate) unsafe fn defer_hosted_delivery_for_queued_callback(",
        "unsafe fn defer_hosted_delivery_inner(",
    );
    assert!(
        defer.contains("ParkedRootParentProof::QueuedCallback(permit)"),
        "queued ingress must carry a typed callback permit"
    );
    let proof = between(
        INGRESS,
        "impl ParkedRootParentProof<'_> {",
        "pub(crate) unsafe fn defer_hosted_delivery_for_add_device(",
    );
    assert!(
        proof.contains("Self::QueuedCallback(permit) => permit.is_exact()"),
        "the typed proof must reselect the live callback before retaining a Call"
    );
    let owner = function_body(INGRESS, "unsafe fn defer_hosted_delivery_inner(");
    assert!(
        owner.contains("proof.is_exact()")
            && owner.contains("call.reply() == reply && call.can_park()")
            && owner.contains("query_component_reply_binding(binding.tcb, reply)")
            && owner.contains(".delivered = false"),
        "the unexecuted Call must return to its existing owner with its bound Reply"
    );
}

#[test]
fn queued_wait_acks_the_current_notification_and_arms_a_retry_before_receive() {
    let notify = function_body(
        SERVICE,
        "unsafe fn service_parked_queued_callback_notification(",
    );
    assert!(
        notify.contains("ack_parked_queued_callback_retry_timer()"),
        "the current timer badge must be ACKed before another blocking Receive"
    );
    let prepare = function_body(SERVICE, "unsafe fn prepare_parked_queued_callback_receive(");
    assert!(
        prepare.contains("delay_timer_program(")
            && prepare.contains("DELAY_TIMER_SOURCE_ROOT_QUEUED_CALLBACK_RETRY"),
        "an empty child observation needs its own bounded wake source"
    );
}

#[test]
fn both_root_settlement_sites_fence_providers_while_the_queued_reply_is_parked() {
    let early = early_callback_wait();
    assert!(
        early.contains("park_queued_callback_root_receive!(root_event_consumed)"),
        "the early site must enter the generic queued callback wait"
    );
    let later = between(
        SERVICE,
        "let queue_settlement = settle_queued_callbacks();",
        "trace_connect_root_checkpoint(4, None)",
    );
    assert!(
        later.contains("ConnectPumpSettlement::AwaitingLocalChild =>")
            && later.contains("park_queued_callback_root_receive!(root_event_consumed)"),
        "the later site must use the same exact queued callback wait before Hook redrive"
    );
    assert!(
        later.contains("ConnectPumpSettlement::Retained")
            && later.contains("ConnectPumpSettlement::Blocked")
            && later.contains("break 'service_loop"),
        "an uncertain callback continues to fence unrelated provider entry"
    );
}

#[test]
fn shared_queued_wait_settles_current_ingress_before_blocking() {
    let park = between(
        SERVICE,
        "macro_rules! park_queued_callback_root_receive",
        "// A callback reached by the preceding AddDevice child",
    );
    let notify = park
        .find("service_parked_queued_callback_notification(")
        .expect("ACK current queued callback notification");
    let defer = park
        .find("defer_hosted_delivery_for_queued_callback(")
        .expect("retain unexecuted Call and its original Reply");
    let receive = park
        .find("component_recv!(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed))")
        .expect("receive next root event");
    assert!(
        notify < receive && defer < receive,
        "notification ACK or Call deferral must precede Receive"
    );
    let receive_macro = between(
        SERVICE.split_once("'service_loop: loop {").expect("service loop").1,
        "macro_rules! component_recv {",
        "macro_rules! component_client_reply_recv {",
    );
    assert!(
        receive_macro.contains("root_queued_callback_exclusive_pending()")
            && receive_macro
                .contains("prepare_parked_queued_callback_receive(&mut root_queued_callback_turn)")
            && receive_macro
                .contains("component_receive_outcome!(crate::executive_ingress::receive($reply))"),
        "the exclusive callback must arm its one-shot immediately before Receive"
    );
}

#[test]
fn outer_io_pump_cannot_discard_a_suspended_callback_owner() {
    let pump = function_body(
        DRIVER,
        "pub(crate) fn pump_hosted_io_completions() -> usize {",
    );
    assert!(
        !pump.contains("drain_hosted_work_queues_at_passive_level")
            && !pump.contains("drain_hosted_queued_callbacks_at_root"),
        "ordinary I/O pumping may be ignored only when callback admission and its physical Reply are reserved for the root"
    );
}

#[test]
fn post_syscall_redrive_cannot_hide_a_suspended_callback_from_its_caller() {
    let post = function_body(
        SERVICE,
        "unsafe fn redrive_global_post_syscall_work(",
    );
    assert!(
        !post.contains("CallbackSuspended"),
        "returning from post-syscall redrive without reporting its retained callback leaves the current Reply and provider continuation without a root barrier"
    );
}

#[test]
fn root_receive_has_a_physical_queue_wake_after_an_empty_scan() {
    let receive = function_body(SERVICE, "unsafe fn prepare_service_receive(");
    assert!(
        receive.contains("delay_timer_arm_queued_work_receive_poll("),
        "an enqueue after the root's empty queue scan must still wake a blocking Receive"
    );
    let poll = function_body(MAIN, "unsafe fn delay_timer_arm_queued_work_receive_poll(");
    assert!(
        poll.contains("delay_timer_rearm(") && !poll.contains("peek_ready()"),
        "the physical receive poll must be armed regardless of observed queue readiness"
    );
    assert!(
        TIMER.contains("queued_work_receive_poll_deadline(), DELAY_TIMER_SOURCE_QUEUED_WORK_RECEIVE_POLL")
            && MAIN.contains("timer_deadline::queued_work_receive_poll_wake_due(now_100ns)"),
        "the poll needs one canonical timer selector and a due transition before root rescans the queue"
    );
}

#[test]
fn root_admits_queued_callbacks_before_other_provider_work() {
    let root = between(
        SERVICE,
        "        loop {\n            // A callback reached by the preceding AddDevice child",
        "            let callback_settlement =",
    );
    assert!(
        root.contains("drain_hosted_queued_callbacks_at_root()"),
        "root must admit passive queue work where it can immediately settle a retained callback owner"
    );
    assert!(
        root.contains("if root_add_device_turn.is_none()"),
        "queue admission must not enter an unrelated provider while AddDevice retains its parent"
    );
}

#[test]
fn root_retires_a_parked_callback_turn_before_admitting_another_provider() {
    let root = between(
        SERVICE,
        "        loop {\n            // A callback reached by the preceding AddDevice child",
        "            let callback_settlement =",
    );
    assert!(
        root.contains("root_queued_callback_turn.is_empty()")
            && root.contains("!root_queued_callback_exclusive_pending()"),
        "a callback ACK may remove its queue row before the root has retired its deferred ingress tickets"
    );
}

#[test]
fn productive_queue_budget_yields_without_disabling_its_provider() {
    let outer = function_body(
        DRIVER,
        "unsafe fn drain_hosted_work_queues_at_passive_level(",
    );
    assert!(
        outer.trim_end().ends_with("Ok(HostedWorkQueueDrainProgress::Drained(total))"),
        "a bounded productive sweep must yield to root, retaining later queue entries for the next turn"
    );
    let instance = function_body(
        DRIVER,
        "unsafe fn drain_hosted_work_queue_for_instance(",
    );
    assert!(
        !instance.contains("drops != 0 || (!io_only && hosted_work_queue_admission(shared).peek_ready().is_some())"),
        "a ready next item after a productive per-instance budget is not proof of an overflow or failed provider"
    );
}

#[test]
fn nested_callback_wait_uses_a_lifo_stack_of_exact_root_turns() {
    let root = SERVICE.split_once("fn ready_flat_root_add_device(")
        .expect("root callback ownership").0;
    assert!(
        root.contains("root_queued_callback_turn: Vec<RootQueuedCallbackTurn>"),
        "callback B may await a child while callback A retains its own Reply and ingress"
    );
    let park = function_body(SERVICE, "unsafe fn ensure_queued_callback_root_turn(");
    assert!(
        park.contains("current.push(turn)")
            && park.contains("current.last()")
            && park.contains("queued_callback_newer_root_child"),
        "only the newest exact callback may own the active root wait"
    );
    let settle = function_body(SERVICE, "unsafe fn settle_parked_queued_callback_turn(");
    assert!(
        settle.contains(".pop()") && settle.contains(".last()"),
        "settling B must reveal A without dropping A's retained ingress"
    );
}

#[test]
fn selected_receive_child_is_run_instead_of_being_deferred_as_an_unrelated_call() {
    let park = between(
        SERVICE,
        "macro_rules! park_queued_callback_root_receive",
        "// A callback reached by the preceding AddDevice child",
    );
    let selected = park
        .find("receive_child_pending()")
        .expect("a child selected during callback settlement must be observed");
    let defer = park
        .find("defer_hosted_delivery_for_queued_callback(")
        .expect("ordinary unexecuted Calls remain deferrable");
    assert!(
        selected < defer,
        "selected Receive child must enter its exact child barrier before generic deferral"
    );
}

#[test]
fn selected_child_transfer_requires_the_same_admission_key_as_import() {
    let transfer = function_body(INGRESS, "pub(crate) unsafe fn deferred_queued_ingress_selected(");
    assert!(transfer.contains("receive.barrier.admission_key() == call.admission_key()"),
        "a stale Receive barrier cannot release the callback's exact deferred Call ticket");
}

#[test]
fn deferred_call_ticket_is_attached_only_to_its_selected_callback() {
    let retain = function_body(SERVICE, "unsafe fn retain_parked_queued_callback_ingress(");
    assert!(retain.contains("turn.owner() != permit.0"),
        "a newly selected callback cannot put its Call ticket on an older stack turn");
}

#[test]
fn older_deferred_call_is_preserved_before_later_arrival_after_callback_settlement() {
    let prelude = between(
        SERVICE,
        "let mut root_event_consumed = false;",
        "let callback_settlement = {",
    );
    assert!(
        prelude.contains("retain_parked_queued_callback_ingress("),
        "current Call Y must be retained before the callback can settle and reimport older X"
    );
    let early = early_callback_wait();
    let later = between(
        SERVICE,
        "let queue_settlement = settle_queued_callbacks();",
        "trace_connect_root_checkpoint(4, None)",
    );
    assert!(
        early.contains("settle_parked_queued_callback_turn(")
            && later.contains("settle_parked_queued_callback_turn("),
        "both settlement sites must release only the exact callback stack top"
    );
    let root = between(
        SERVICE,
        "'service_loop: loop {",
        "fn ready_flat_root_add_device(",
    );
    assert!(root.contains("if root_event_consumed {")
        && root.contains("component_recv!(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed))"),
        "after retained ingress X/Y is released, root must receive those original Calls before ordinary admission");
}
