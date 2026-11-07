//! A selected root READ route is classified without consuming a File or entering its provider.

const FILE: &str = include_str!("../../../components/ntos-executive/src/exec_file_capture.rs");
const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_ingress_owner.rs");

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).expect("native function");
    let body = &source[start..];
    let open = body.find('{').unwrap();
    let mut depth = 0usize;
    for (index, byte) in body.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 { return &body[..=index]; }
            }
            _ => {}
        }
    }
    panic!("unclosed native function")
}

#[test]
fn selected_read_preflight_uses_child_generation_and_canonical_read_route() {
    let preflight = function(FILE, "root_ingress_read_preflight");
    for required in ["child.pi", "child.process", "child.tid", "child.badge",
        "capture_thread_process_identity", "hosted_process_generation",
        "hosted_file_route_for_pid", "handle_access", "file_transfer_access_mask(false)",
        "registered_file_target", "IRP_MJ_READ", "RootIngressReadPreflight::Changed",
        "RootIngressReadPreflight::Unsupported"] {
        assert!(preflight.contains(required), "missing exact child route check: {required}");
    }
    for forbidden in ["self.pi", "hosted_file_capture::capture", "capture_hosted_file_transfer",
        "queue_hosted_file_read_exact", "dispatch_hosted_file_read_write_for",
        "prepare_transfer_event"] {
        assert!(!preflight.contains(forbidden), "preflight enters effects: {forbidden}");
    }
}

#[test]
fn ordinary_route_and_selected_preflight_share_one_process_local_lookup() {
    let ordinary = function(HANDLER, "hosted_file_route_for");
    let shared = function(HANDLER, "hosted_file_route_for_pid");
    assert!(ordinary.contains("hosted_file_route_for_pid"));
    assert!(shared.contains("self.pm.lookup_handle") || shared.contains(".lookup_handle"));
    assert!(shared.contains("driver_launch::hosted_file_route"));
    assert!(FILE.contains("self.hosted_file_route_for_pid"));
}

#[test]
fn selected_read_decode_precedes_route_and_keeps_both_owners_on_refusal() {
    let decode = function(HOSTED, "selected_root_read_request");
    for required in ["prepared_root_ingress_snapshot", "row.binding == snapshot.binding",
        "call.admission_key() == admission", "message.badge() != row.binding.badge",
        "message.info() != snapshot.info", "message.registers() != snapshot.registers",
        "SelectedRootReadRequest::parse"] {
        assert!(decode.contains(required), "missing selected Call proof: {required}");
    }
    let route = function(OWNER, "preflight_selected_read");
    assert!(route.contains("selected_root_read_request(child, table)"));
    assert!(route.contains("handler.root_ingress_read_preflight(request.binding, request.handle, None)"));
    assert!(route.contains("FileIoMode::Asynchronous"));
    for forbidden in ["bind_prepared(", "take_pending_root_ingress_dispatch(",
        "take_selected_root_hosted_with(", "queue_hosted_file_read_exact("] {
        assert!(!route.contains(forbidden), "preflight changed an owner: {forbidden}");
    }
}
