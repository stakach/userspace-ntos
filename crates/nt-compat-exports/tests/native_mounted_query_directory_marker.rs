//! A native NtQueryDirectoryFile on the mounted volume reports a bounded serial completion
//! marker on both its inline and its retained Pending completion path.

const INGRESS: &str = include_str!("../../../components/ntos-executive/src/exec_file_directory_query.rs");
const DELIVERY: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const TRACE: &str =
    include_str!("../../../components/ntos-executive/src/mounted_query_directory_trace.rs");

fn first(source: &str, needle: &str) -> usize {
    source.find(needle).unwrap_or_else(|| panic!("missing {needle}"))
}

#[test]
fn inline_completion_reports_before_the_iosb_is_written() {
    let marker = first(INGRESS, "mounted_query_directory_trace::complete_inline(");
    let iosb = INGRESS.rfind("self.complete_terminal_file_io(").expect("inline IOSB publication");
    assert!(marker < iosb, "the inline marker observes the exact delivered status and bytes");
    let pending = first(INGRESS, "mounted_query_directory_trace::pending(");
    let parked = first(INGRESS, "return STATUS_PENDING;\n        }");
    assert!(pending < parked, "a pending query records its class with its exact IRP");
}

#[test]
fn pending_completion_reports_after_iosb_publication_and_before_backend_ack() {
    let iosb = first(DELIVERY, "let result = nt_handler.publish_file_io_status(");
    let marker = first(DELIVERY, "mounted_query_directory_trace::complete_pending(");
    let ack = first(DELIVERY, "_ if backend_ack_required => driver_launch::acknowledge_completed_irp(");
    assert!(iosb < marker && marker < ack,
        "the retained IRP output is still owned when its records are counted");
}

#[test]
fn marker_is_bounded_and_counts_records_through_the_shared_walker() {
    assert!(TRACE.contains("[mounted-query-directory] complete pi="));
    for field in [" class=", " entries=", " status=0x", " info="] {
        assert!(TRACE.contains(field), "marker field {field}");
    }
    assert!(TRACE.contains("directory_record_count("));
    assert!(TRACE.contains("MARKER_BUDGET"), "boot-visible but bounded");
    assert!(TRACE.contains("exec_volume_device()"), "only the mounted volume's Files are traced");
}
