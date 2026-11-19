//! Hosted MDLs carry real PFNs from owned frames (#321).
//!
//! The native adapter authenticated source and partial MDLs but left every PFN slot zero. PFN
//! layout, validation and partial windows are covered in `nt_mdl::pfn`.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PFN: &str = include_str!("../../../components/ntos-executive/src/hosted_mdl_pfn.rs");

fn arm(operation: &str) -> &'static str {
    let service = LAUNCH
        .split_once("unsafe fn service_hosted_driver_mdl_for_instance(")
        .unwrap()
        .1;
    service
        .split_once(&format!("        {operation} => {{"))
        .unwrap_or_else(|| panic!("{operation} arm"))
        .1
        .split_once("\n        HOSTED_MDL_OP_")
        .unwrap()
        .0
}

#[test]
fn locked_and_nonpaged_mdls_record_pfns_before_registry_publication() {
    let build = arm("HOSTED_MDL_OP_BUILD_NONPAGED");
    let header = build.find("!= address & !0xfff").unwrap();
    let populate = build.find("hosted_mdl_pfn::populate(instance_index, inst, mdl_exec, allocated)").unwrap();
    let publish = build.find(".build_for_nonpaged_key(key)").unwrap();
    assert!(header < populate && populate < publish);
}

#[test]
fn partial_mdl_copies_the_source_pfn_window_before_binding() {
    let partial = arm("HOSTED_MDL_OP_BIND_PARTIAL");
    let locked = partial.find("registry.is_locked(source_id)").unwrap();
    let copy = partial.find("hosted_mdl_pfn::copy_partial(").unwrap();
    let bind = partial.find("registry.bind_partial_key(").unwrap();
    assert!(locked < copy && copy < bind);
}

#[test]
fn pfns_come_from_owned_frame_capabilities_not_driver_metadata() {
    assert!(PFN.contains("get_frame_paddr_checked(cap_base.checked_add(index)?)"));
    assert!(PFN.contains("hosted_contiguous_ram_broker::instance_physical_address("));
    for driver_writable in ["hosted_component_physical_address", "FSD_DATA_PHYSICAL_MAP"] {
        assert!(!PFN.contains(driver_writable), "{driver_writable} is driver-writable metadata");
    }
}
