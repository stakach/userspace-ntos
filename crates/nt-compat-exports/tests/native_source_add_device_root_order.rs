//! A parked AddDevice parent is resumed at the flat root boundary before unrelated providers.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

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
    let parent = root.find("pending_driver_start_redrive_selected(")
        .expect("root resumes only the selected AddDevice batch");
    let unrelated = root.find("redrive_hosted_driver_io_create_file(")
        .expect("ordinary provider redrive");
    assert!(child < inner && inner < parent && parent < unrelated,
        "a held AddDevice must settle its child and parent before unrelated providers enter");
}

#[test]
fn retained_add_device_parent_fences_the_root_before_other_provider_redrives() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let parent = root.find("pending_driver_start_redrive_selected(")
        .expect("exact AddDevice resume");
    let unrelated = root.find("redrive_hosted_driver_io_create_file(").unwrap();
    let gate = root[parent..unrelated].find("HostedPnpWaitStage::AddDevice")
        .expect("unsettled AddDevice owner must be checked before unrelated providers");
    assert!(root[parent + gate..unrelated].contains("break 'service_loop"),
        "blocked physical parent cannot admit another provider");
}
