//! A class PortDO forwards lifecycle IRPs to a separately hosted lower FDO.
//! The source IRP must stay owned until the real lower completion and ACK.

#[test]
fn cross_domain_lower_file_lifecycle_has_retained_route() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("extern \"win64\" fn s_iof_call_driver(").unwrap();
    let call = &source[start..source[start..].find("if major != IRP_MJ_PNP").unwrap() + start];
    for major in ["IRP_MJ_CREATE", "IRP_MJ_CLEANUP", "IRP_MJ_CLOSE"] {
        assert!(call.contains(major), "missing lower {major} forward");
    }
    assert!(call.contains("FSD_SERVICE_LOWER_FILE_FORWARD_LABEL"));
    assert!(source.contains("service_hosted_lower_file_forward"));
}
