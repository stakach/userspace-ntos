//! The SMSS autochk search must expose its real attribute-query candidate and terminal result.
//! This is an observation contract; it must not choose a path or change File ownership.

const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const ATTR: &str = include_str!("../../../components/ntos-executive/src/exec_attribute_query.rs");
const DELIVERY: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const TRACE: &str = include_str!("../../../components/ntos-executive/src/exec_smss_attribute_probe_trace.rs");

#[path = "../../../components/ntos-executive/src/exec_smss_attribute_probe_sampling.rs"]
mod sampling;

#[test]
fn first_live_probe_and_bounded_generic_failure_samples_are_visible() {
    assert_eq!(sampling::NORMAL_SAMPLE_LIMIT, 16);
    assert_eq!(sampling::FAILURE_SAMPLE_LIMIT, 256);
    for ordinal in [0, 1, 15, 127, 255, 256, 512, 1024] {
        assert!(sampling::sample_failure(ordinal), "sample {ordinal} should remain visible");
    }
    for ordinal in [257, 258, 511, 513, 1023] {
        assert!(!sampling::sample_failure(ordinal), "sample {ordinal} should be suppressed");
    }
    assert!(TRACE.contains("normal_sample(&SMSS_ATTRIBUTE_PROBE_COUNT)"),
        "the first live pi=0 candidate must be emitted");
    assert!(TRACE.contains("SMSS_ATTRIBUTE_RESOLVE_FAILURE_COUNT")
        && TRACE.contains("SMSS_ATTRIBUTE_TARGET_FAILURE_COUNT")
        && TRACE.contains("SMSS_ATTRIBUTE_TERMINAL_FAILURE_COUNT"),
        "each failure phase needs its own bounded atomic budget");
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).unwrap_or_else(|| panic!("missing {start}"))
        .1.split_once(end).unwrap_or_else(|| panic!("missing {end} after {start}"))
        .0
}

#[test]
fn both_smss_attribute_services_observe_the_normalized_absolute_candidate() {
    for method in ["nt_query_attributes_file_service", "nt_query_full_attributes_file_service"] {
        let service = between(EXEC, &format!("unsafe fn {method}("),
            "if !matches!(parse_root, FileParseRoot::Absolute)");
        let normalized = service.find("self.normalize_object_directory_file_name(")
            .expect("candidate must follow name normalization");
        let observed = service.find("trace_smss_attribute_candidate(")
            .unwrap_or_else(|| panic!("RED: {method} must observe SMSS's captured candidate"));
        assert!(normalized < observed, "{method} must log the normalized, captured name");
        let call = &service[observed..service[observed..].find(");").unwrap() + observed];
        for field in ["self.pi", "self.current_tid", "name16"] {
            assert!(call.contains(field), "{method} candidate observation is missing {field}");
        }
    }
}

#[test]
fn mounted_target_observation_follows_exact_object_manager_resolution() {
    let resolve = between(ATTR, "unsafe fn query_native_mounted_attributes(",
        "unsafe fn query_mounted_attributes_on_target(");
    assert!(resolve.contains("resolve_kernel_directory_file_name")
        && resolve.contains("resolved_device != device_id"),
        "mounted target must retain exact Object Manager and physical device checks");
    assert!(resolve.contains("Err(status) => {")
        && resolve.contains("trace_smss_attribute_resolution("),
        "an early Object Manager failure must expose its actual status and candidate");

    let target = between(ATTR, "unsafe fn query_mounted_attributes_on_target(",
        "fn park_native_attribute_query(");
    let allocated = target.find("allocate_hosted_file(")
        .expect("mounted attribute query allocates its exact File");
    let observed = target[allocated..].find("trace_smss_attribute_target(")
        .map(|offset| allocated + offset)
        .expect("RED: log resolved device, relative FileName, and retained File identity");
    let call = &target[observed..target[observed..].find(");").unwrap() + observed];
    for field in ["self.pi", "self.current_tid", "device_id", "relative", "file_id"] {
        assert!(call.contains(field), "target observation is missing {field}");
    }
    assert!(target.contains("pending_irp.as_ref().map(|irp| irp.raw())"),
        "target observation must identify the dispatched IRP for terminal correlation");
    for stage in ["class", "output", "owner-capacity", "release-capacity", "caller",
        "name-capacity", "create-pending-owner", "query-pending-owner", "inline-terminal"] {
        assert!(target.contains(&format!("report_failure(b\"{stage}\"")),
            "negative synchronous {stage} result needs an uncapped target observation");
    }
}

#[test]
fn bounded_smss_samples_correlate_with_the_retained_attribute_terminal() {
    let delivery = between(DELIVERY, "let mut terminal_status =", "finish_owner_exact(identity, pending.irp_id)");
    let retained = delivery.find("PendingFileIoOperation::AttributeQuery(operation)")
        .expect("terminal path keeps the AttributeQuery owner");
    let observed = delivery.find("trace_smss_attribute_terminal(")
        .expect("RED: log the final retained AttributeQuery status, not STATUS_PENDING");
    assert!(retained < observed, "terminal observation must follow CREATE-to-QUERY handling");
    let call = &delivery[observed..delivery[observed..].find(");").unwrap() + observed];
    for field in ["pending.pi", "pending.tid", "hosted_file_id", "pending.irp_id", "terminal_status"] {
        assert!(call.contains(field), "terminal observation is missing {field}");
    }
    let owner = ATTR.split_once("fn park_native_attribute_query(")
        .expect("retained attribute-query owner").1;
    for field in ["route: PendingFileRoute::Hosted(file_id)", "pi: self.pi", "tid: self.current_tid"] {
        assert!(owner.contains(field), "retained AttributeQuery owner is missing {field}");
    }

    assert!(TRACE.contains("SMSS_ATTRIBUTE_PROBE_SAMPLE_LIMIT")
        && TRACE.contains("SMSS_ATTRIBUTE_PROBE_COUNT")
        && TRACE.contains("AtomicU64")
        && TRACE.contains("pi != 0")
        && TRACE.contains("normal_sample"),
        "SMSS candidate/target logging must have a bounded atomic sample budget");
    let terminal_trace = TRACE.split_once("fn trace_smss_attribute_terminal(").unwrap().1;
    assert!(!terminal_trace.contains("route_phase()")
        && !terminal_trace.contains("exec_fs_mount_identity"),
        "retained terminal logging cannot read root-owned mount state in a nested pump");
    assert!(TRACE.contains("sample_status(status, &SMSS_ATTRIBUTE_RESOLVE_COUNT")
        && TRACE.contains("sample_status(status, &SMSS_ATTRIBUTE_TARGET_COUNT")
        && TRACE.contains("sample_status(returned_status, &SMSS_ATTRIBUTE_TERMINAL_COUNT"),
        "normal and failure observations need separate bounded budgets");
    assert!(TRACE.contains("exec_block_route_kind"),
        "candidate/target/terminal observations must identify the Boot or Native route phase");
    assert!(delivery.contains("trace_smss_attribute_retarget("),
        "a CREATE-to-QUERY IRP retarget must bridge target and terminal identities");
}
