//! Wiring contract for the accepted disk PDO's pre-dispatch refusal receipt.
//! The native boot and a later semantic regression must establish why it was refused.

const OWNERS: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");

#[test]
fn pending_scsi_proof_reports_the_exact_pre_dispatch_boundary() {
    let start = OWNERS.find("fn dispatch_with_port_connect<Yield>(")
        .expect("production File IRP dispatcher");
    let end = OWNERS[start..].find("\nfn settle_returned_dispatch(")
        .map(|offset| start + offset).expect("dispatcher end");
    let dispatch = &OWNERS[start..end];
    syn::parse_str::<syn::ItemFn>(dispatch).expect("complete production dispatcher");
    for stage in ["reserve", "prepare", "bind-proof", "capture-route", "begin"] {
        assert!(dispatch.contains(&format!("trace_scsi_proof_refusal(b\"{stage}\"")),
            "missing exact pre-dispatch refusal stage: {stage}");
    }
    assert!(OWNERS.contains("pending_scsi_proof_slot()"),
        "only a scoped native disk proof may emit this receipt");
}
