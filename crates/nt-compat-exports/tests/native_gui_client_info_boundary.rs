use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("focused GUI copyout function")
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn gui_copyout_authenticates_before_capture_and_revalidates_before_teb_writes() {
    let file = source("hosted_gui_client_info.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "service").block);
    let index = |name: &str| calls.0.iter().position(|call| call == name).unwrap();
    assert!(index("authenticate_win32k_service_request") < index("capture_provider_pool_packet"));
    assert!(index("capture_provider_pool_packet") < index("read_unaligned"));
    assert!(index("read_unaligned") < index("capture"));
    assert!(index("capture") < index("map_win32k_user_heap_into_client"));
    assert!(index("map_win32k_user_heap_into_client") < index("values_for"));
    assert!(index("values_for") < index("write_volatile"));
    let mapping = index("map_win32k_user_heap_into_client");
    let publication = index("write_volatile");
    for name in [
        "capture_process_identity",
        "thread_lifetime",
        "current_win32k_provider_domain",
        "current_provider_poll_owner",
        "hosted_gui_thread_teb_alias_for",
        "hosted_process_generation",
        "read_thread_win32",
    ] {
        assert!(
            calls.0[mapping + 1..publication]
                .iter()
                .any(|call| call == name),
            "revalidate {name} after mapping and before publication"
        );
    }
    let wrapper = source("service_sec_image.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&wrapper, "service_win32k_gui_client_info").block);
    assert_eq!(calls.0, ["service"]);
}

#[test]
fn rejection_diagnostics_only_read_captured_scalars_and_preserve_status() {
    let file = source("hosted_gui_client_info.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "rejected").block);
    assert!(calls.0.iter().all(|name| matches!(
        name.as_str(),
        "print_str"
            | "print_hex_u64"
            | "print_u64"
            | "from"
            | "pi"
            | "process"
            | "thread"
            | "thread_id"
            | "generation"
            | "badge"
    )));
    let last = function(&file, "rejected").block.stmts.last().unwrap();
    assert!(matches!(last, syn::Stmt::Expr(Expr::Cast(cast), None)
        if matches!(&*cast.expr, Expr::Path(path) if path.path.is_ident("status"))));
}

#[derive(Default)]
struct CanonicalThreadReads {
    events: Vec<&'static str>,
    exact_arguments: usize,
    deferred_mirror: bool,
}

impl<'ast> Visit<'ast> for CanonicalThreadReads {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            let names: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if names == ["ps_object_backing", "read_thread_win32"] {
                self.events.push("canonical-read");
                if call.args.len() == 2
                    && matches!(&call.args[0], Expr::Reference(reference)
                        if matches!(&*reference.expr, Expr::Field(field)
                            if matches!(&field.member, syn::Member::Named(name) if name == "pm")))
                    && matches!(&call.args[1], Expr::Path(path) if path.path.is_ident("thread"))
                {
                    self.exact_arguments += 1;
                }
            }
            if path.path.is_ident("reject")
                && matches!(call.args.first(), Some(Expr::Lit(literal))
                    if matches!(&literal.lit, syn::Lit::ByteStr(value)
                        if value.value() == b"packet-owner"))
            {
                self.events.push("packet-owner");
            }
            if names.last().is_some_and(|name| name == "write_volatile") {
                self.events.push("teb-store");
            }
            if names
                .last()
                .is_some_and(|name| name == "map_win32k_user_heap_into_client")
            {
                self.events.push("heap-map");
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "thread_win32" {
            self.deferred_mirror = true;
        }
        if call.method == "map_win32k_user_heap_into_client" {
            self.events.push("heap-map");
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn gui_copyout_reads_exact_canonical_thread_before_admission_and_after_mapping() {
    let file = source("hosted_gui_client_info.rs");
    let mut reads = CanonicalThreadReads::default();
    reads.visit_block(&function(&file, "service").block);
    assert!(
        !reads.deferred_mirror,
        "GUI copyout must not authenticate against the PM mirror imported after dispatch returns"
    );
    assert!(
        reads.exact_arguments >= 2,
        "read canonical PTI through exact PM and ThreadLifetime"
    );
    let admission = reads
        .events
        .iter()
        .position(|event| *event == "packet-owner")
        .unwrap();
    let mapping = reads
        .events
        .iter()
        .position(|event| *event == "heap-map")
        .unwrap();
    let store = reads
        .events
        .iter()
        .position(|event| *event == "teb-store")
        .unwrap();
    assert!(reads.events[..admission].contains(&"canonical-read"));
    assert!(reads.events[mapping + 1..store].contains(&"canonical-read"));
}

#[derive(Default)]
struct BodyChecks {
    calls: Calls,
    identifiers: Vec<String>,
}

impl<'ast> Visit<'ast> for BodyChecks {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.identifiers.push(ident.to_string());
    }
}

#[test]
fn canonical_thread_read_validates_current_published_executive_body_before_reading() {
    let file = source("ps_object_backing.rs");
    let helper = function(&file, "read_thread_win32");
    let mut checks = BodyChecks::default();
    checks.visit_block(&helper.block);
    checks.calls.visit_block(&helper.block);
    let index = |name: &str| {
        checks
            .calls
            .0
            .iter()
            .position(|call| call == name)
            .unwrap_or_else(|| panic!("canonical thread reader must call {name}"))
    };
    let read = index("read_volatile");
    for name in ["thread_lifetime", "thread_kernel_object", "live_alias"] {
        assert!(
            index(name) < read,
            "validate {name} before canonical body read"
        );
    }
    for name in [
        "current_thread_lifetime",
        "Published",
        "Executive",
        "KTHREAD_WIN32_THREAD",
    ] {
        assert!(
            checks.identifiers.iter().any(|ident| ident == name),
            "canonical thread reader must validate/use {name}"
        );
    }
}
