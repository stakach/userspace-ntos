//! A parked AddDevice parent is resumed at the flat root boundary before unrelated providers.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const PNP: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");

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

