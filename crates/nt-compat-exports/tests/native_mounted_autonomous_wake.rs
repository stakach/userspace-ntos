//! A native mounted lookup can park its caller after every unrelated IRQ has gone quiet.
//! Its next sector claim therefore needs its own timer source.

use syn::{visit::Visit, Expr, Item};

const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const BACKEND: &str = include_str!("../../../components/ntos-executive/src/mounted_volume_backend.rs");
const DIRECTORY: &str = include_str!("../../../components/ntos-executive/src/mounted_directory_query.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

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
