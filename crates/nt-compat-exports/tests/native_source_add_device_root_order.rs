//! A parked AddDevice parent is resumed at the flat root boundary before unrelated providers.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const PNP: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");

#[test]
fn selected_add_device_child_settles_inner_connect_and_exact_batch_before_other_redrives() {
    let root = SERVICE
        .split_once("'service_loop: loop {")
        .expect("flat service loop")
        .1;
    let child = root.find("run_one_pending_add_device_child_step(")
        .expect("root selects one retained AddDevice child");
    let inner = root.find("settle_suspended_connect_pumps(")
        .expect("inner CONNECT continuation settles at root");
    let parent = inner + root[inner..].find("redrive_flat_root_add_device_selected(")
        .expect("root resumes the selected AddDevice after its inner CONNECT settles");
    let unrelated = root.find("redrive_hosted_driver_io_create_file(")
        .expect("ordinary provider redrive");
    assert!(child < inner && inner < parent && parent < unrelated,
        "a held AddDevice must settle its child and parent before unrelated providers enter");
}

#[test]
fn retained_add_device_parent_fences_the_root_before_other_provider_redrives() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let parent = root.find("redrive_flat_root_add_device_selected(")
        .expect("exact AddDevice resume");
    let unrelated = root.find("redrive_hosted_driver_io_create_file(").unwrap();
    let gate = root[parent..unrelated].find("root_add_device_still_parked(")
        .expect("exact unsettled AddDevice owner must be checked before unrelated providers");
    assert!(root[parent + gate..unrelated].contains("break 'service_loop"),
        "blocked physical parent cannot admit another provider");
}

#[test]
fn ordinary_pnp_redrive_stops_before_add_device_and_flat_root_admits_exactly_one() {
    let ready = PNP.split_once("nt_driver_start::BatchPhase::Ready => {")
        .expect("Ready admission arm").1;
    let add_device = ready.find("start_one_devnode(").expect("native PnP admission");
    assert!(ready[..add_device].contains("flat_root_add_device_permit"),
        "ordinary completion redrive must return at Ready without parking a physical AddDevice parent");
    assert!(PNP.contains("drive_flat_root_add_device"),
        "only an explicit flat-root entry may cross the Ready admission gate");
    assert!(SERVICE.contains("pending_driver_start_redrive_flat_root_selected"),
        "root must select the exact reserved driver-start row for AddDevice admission");
    assert!(SERVICE.contains("pending_pnp_operation_redrive_flat_root_selected"),
        "rebalance restart must have the same exact root-only admission path");
}

#[test]
fn progressing_or_certified_retryable_add_device_gets_another_exclusive_root_turn() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let child = root.find("run_one_pending_add_device_child_step(")
        .expect("selected child root phase");
    let unrelated = root.find("redrive_hosted_driver_io_create_file(")
        .expect("later unrelated provider phase");
    let phase = &root[child..unrelated];
    assert!(!phase.contains("add_device_passes >= 16"),
        "successful child progress must not exhaust a fixed total pass budget");
    assert!(!phase.contains("consecutive_no_child_yields >= 2"),
        "a certified no-effects retry must not terminate the service loop after two turns");
    assert!(phase.contains("ROOT_ADD_DEVICE_RETRY_DEADLINE.store(deadline")
        && phase.contains("component_recv!(fault_ep"),
        "a retained retryable parent needs an armed one-shot and a fresh receive before unrelated work");
    assert!(!phase.contains("crate::yield_now()"),
        "yielding without receiving cannot deliver a bound timer or IRQ notification");
}

#[test]
fn blocked_boot_predecessor_cannot_starve_a_later_ready_add_device_owner() {
    let selection = SERVICE.split_once("fn ready_flat_root_add_device(")
        .expect("root Ready selector").1
        .split_once("fn root_add_device_still_parked(")
        .expect("Ready selector end").0;
    assert!(selection.contains("bootstrap_predecessors")
        && selection.contains("PendingDriverStartOwner::Boot")
        && selection.contains("continue;"),
        "root must skip a Ready row held behind a live bootstrap predecessor and select another exact owner");
    assert!(selection.contains("pending_pnp_operations"),
        "an eligible rebalance restart must remain selectable after a blocked boot row");
}
