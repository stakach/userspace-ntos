//! A nested CREATE runs on the authenticated class worker, whose request bank
//! differs from the primary bank held by the in-flight START IRP.

#[test]
fn create_subject_reads_the_authenticated_dispatch_bank() {
    let source = include_str!(
        "../../../components/ntos-executive/src/hosted_create_subject_registration.rs"
    );
    let service = &source[source.find("pub(super) unsafe fn service(").unwrap()..
        source.find("#[derive(Clone, Copy)]").unwrap()];
    assert!(service.contains("instance_for_pump_channel(channel, reply_cap)"));
    for field in ["SH_ACTIVE_IRP", "SH_REQ_CONTROL_ID", "SH_ACTIVE_IOSL"] {
        assert!(service.contains(&format!("channel.shared_va + {field}")));
        assert!(!service.contains(&format!("source.exec_shared_va + {field}")));
    }
}
