//! A native mounted lookup can park its caller after every unrelated IRQ has gone quiet.
//! Its next sector claim therefore needs its own timer source.

use syn::{visit::Visit, Expr, Item};

const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const BACKEND: &str = include_str!("../../../components/ntos-executive/src/mounted_volume_backend.rs");
const DIRECTORY: &str = include_str!("../../../components/ntos-executive/src/mounted_directory_query.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(name).unwrap_or_else(|| panic!("missing {name}"));
    let rest = &source[start..];
    &rest[..rest.find("\n}").unwrap_or_else(|| panic!("unterminated {name}"))]
}

#[test]
fn mounted_sector_wake_keeps_one_deadline_until_a_service_attempt() {
    let deadline = function_body(BLOCK, "pub(super) fn next_deadline(");
    let publication = function_body(SERVICE, "pub(crate) fn request_mounted_native_timer_rearm()");
    let timer = function_body(MAIN, "unsafe fn timer_retry_wake_due(");

    assert!(BLOCK.contains("nt_time::CoalescedRetryWake::new()"),
        "the mounted sector timer needs one retained wake per queue publication");
    assert!(deadline.contains("WAKE.next_deadline(")
        && !deadline.contains("now_100ns.saturating_add(100_000)"),
        "repeated scans of the same claim must not slide its deadline forward");
    assert!(publication.contains("publish_mounted_native_block_wake("),
        "committed CREATE, overlay, read, and directory work must publish before outer rearm");
    assert!(timer.contains("mounted_native_block_wake_due("),
        "the due timer must announce a mounted claim only once without claiming its IRP");
    assert!(BLOCK.contains("WAKE.begin_redrive(") && BLOCK.contains("retry_at("),
        "a service attempt must rearm only if unentered sector work remains");
}

#[test]
fn pending_settlement_preserves_the_retry_for_an_already_queued_sector() {
    let guard = &BLOCK[BLOCK.find("struct NativeServiceGuard")
        .expect("native service owner")..BLOCK.find("/// Complete bounded cached claims")
        .expect("native service entry")];
    assert!(guard.contains("WAKE.begin_redrive(monotonic_time_100ns(), queued_timer_work())"),
        "capture the publication before settling an in-flight command: a second queued sector \
         may become claimable without publishing another wake");
    assert!(guard.contains("if claimable_timer_work() && attempt.retry_at("),
        "rearm that same publication only after settlement leaves claimable queued work");
}

fn calls_in_function(source: &str, function: &str) -> Vec<String> {
    let file = syn::parse_file(source).expect("native source parses");
    let body = file.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == function => Some(&item.block),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {function}"));
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>().join("::"));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    calls.0
}

#[test]
fn claimable_mounted_work_has_a_timer_source_without_incidental_irq() {
    let service = calls_in_function(BLOCK, "next_sector_claim");
    for claim in ["claim_mounted_create_sector", "claim_mounted_overlay_sector",
        "claim_mounted_read_sectors", "claim_mounted_directory_sector"] {
        assert!(service.iter().any(|call| call.ends_with(claim)),
            "mounted native service must retain {claim} as an exact claim owner");
    }

    let timer = calls_in_function(TIMER, "next");
    assert!(timer.iter().any(|call| call.ends_with("driver_launch::mounted_native_block_next_deadline")),
        "a claimable mounted CREATE/READ/overlay/directory needs a finite autonomous wake; \
         otherwise an idle root Receive can wait forever for an unrelated IRQ");
}

#[test]
fn native_publication_requests_outer_rearm_before_parking() {
    let create = &BACKEND[BACKEND.find("    fn create(&mut self, irp: &IrpProjection)")
        .expect("mounted CREATE handler")..];
    let native = &create[create.find("if route_kind != nt_fs::BlockSourceKind::Boot || journal_owned")
        .expect("native mounted CREATE branch")..];
    let pending = native.find("return Ok(DispatchOutcome::Pending);")
        .expect("native CREATE parks its original IRP");
    let admission = &native[..pending];
    for capture in ["capture_deferred_boot(", "capture_resolved_root(", "capture("] {
        assert!(admission.contains(capture), "missing exact CREATE owner {capture}");
    }
    let last_capture = admission.rfind(".capture(").expect("path lookup capture");
    assert!(admission[last_capture..].contains("request_mounted_native_timer_rearm"),
        "the native CREATE must request a timer wake after publishing claimable work and before \
         returning Pending; the root's native-block pump may already have run this turn");
    assert!(!BACKEND.contains("rearm_registered_active_delay_timer("),
        "backend dispatch must not alias the live mutable handler through the global timer owner");
    assert!(DIRECTORY.contains("request_mounted_native_timer_rearm();"),
        "installed directory publication needs the same autonomous wake request");

    for boundary in ["fn finalize_service_loop_state", "fn pump_hosted_io_and_redrive_driver_starts"] {
        let body = &SERVICE[SERVICE.find(boundary).expect("outer service boundary")..];
        let next = body.find("\nfn ").unwrap_or(body.len());
        assert!(body[..next].contains("rearm_requested_mounted_native_timer(nt_handler)"),
            "{boundary} must consume mounted publication after backend borrows are released");
    }
    assert!(SERVICE.contains("rearm_registered_active_delay_timer_with_handler(handler);"),
        "outer rearm must use the existing handler reference");
}

#[test]
fn native_settlement_services_resolved_backend_before_receive() {
    let helper = &SERVICE[SERVICE.find("fn service_mounted_native_blocks_and_redrive_backends()")
        .expect("shared native settlement helper")..];
    let native = helper.find("driver_launch::service_mounted_native_blocks()")
        .expect("native physical settlement");
    let after_native = &helper[native..];
    let end = after_native.find("\n}").expect("bounded native helper end");
    assert!(after_native[..end].contains("driver_launch::service_pending_file_backends()"),
        "physical settlement must revisit resolved mounted backends once");

    let pump = &SERVICE[SERVICE.find("unsafe fn pump_hosted_io_and_redrive_driver_starts(")
        .expect("outer hosted I/O pump")..];
    let native = pump.find("let native_blocks = service_mounted_native_blocks_and_redrive_backends()")
        .expect("shared native settlement and backend pass");
    let after_native = &pump[native..];
    let completion = after_native.find("driver_launch::pump_hosted_io_completions()")
        .expect("hosted completion pump");
    assert!(completion > 0, "hosted completions must follow native settlement");
}

#[test]
fn irq_fast_path_delivers_native_backend_terminal_before_receive() {
    let irq = &SERVICE[SERVICE.find("if current_irq_lines != 0 {")
        .expect("root IRQ fast path")..];
    let receive = irq.find("let received = component_recv!")
        .expect("IRQ fast path parks root Receive");
    let before_receive = &irq[..receive];
    let settled = before_receive.find("service_mounted_native_blocks_and_redrive_backends()")
        .expect("IRQ terminal uses shared native block/backend ordering");
    let pumped = before_receive.find("driver_launch::pump_hosted_io_completions()")
        .expect("resolved terminal enters I/O Manager before Receive");
    let delivered = before_receive.find("pending_file_io_redrive_all(&mut nt_handler)")
        .expect("retained File reply redrives before Receive");
    assert!(settled < pumped && pumped < delivered,
        "IRQ path must settle native work, publish backend completion, then redrive File reply");
}
