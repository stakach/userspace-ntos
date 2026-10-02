use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn, Pat};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing focused native mapping module: {}", path.display()));
    syn::parse_file(&text).unwrap()
}

fn function(file: &syn::File, name: &str) -> ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Wiring {
    calls: Vec<String>,
    paths: Vec<String>,
    literals: Vec<String>,
    methods: Vec<String>,
}

impl<'ast> Visit<'ast> for Wiring {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths
            .push(path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_path(self, path);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(
                path.path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
        self.literals
            .push(String::from_utf8(literal.value()).unwrap());
    }
}

fn wiring(function: &ItemFn) -> Wiring {
    let mut wiring = Wiring::default();
    wiring.visit_item_fn(function);
    wiring
}

#[test]
fn video_port_mapping_uses_focused_exact_grant_admission_not_flat_helper() {
    let file = source("driver_launch.rs");
    assert!(
        file.items.iter().any(|item| matches!(item,
        Item::Mod(module) if module.ident == "hosted_video_memory_mapping")),
        "declare the focused native caller-memory adapter"
    );
    assert!(
        !file.items.iter().any(|item| matches!(item,
        Item::Fn(function) if function.sig.ident == "hosted_video_memory_caller_va")),
        "remove superseded flat admission machinery"
    );
    let calls = wiring(&function(&file, "s_video_port_map_memory")).calls;
    assert!(
        calls
            .iter()
            .any(|call| call == "hosted_video_memory_mapping::caller_va"),
        "VideoPortMapMemory must use shared checked caller-memory admission"
    );
}

#[test]
fn caller_memory_uses_exact_tuple_and_rejects_without_fallback() {
    let file = source("hosted_video_memory_mapping.rs");
    let caller = function(&file, "caller_va");
    let facts = wiring(&caller);
    for field in [
        "SH_VIDEO_MEMORY_PHYS",
        "SH_VIDEO_MEMORY_LEN",
        "SH_VIDEO_MEMORY_CALLER_VA",
    ] {
        assert!(
            facts.paths.iter().any(|path| path == field),
            "capture exact {field}"
        );
    }
    assert!(facts
        .calls
        .iter()
        .any(|call| call.ends_with("hosted_memory_range_granted")));
    assert!(facts
        .calls
        .iter()
        .any(|call| call == "nt_video_miniport::caller_memory::admit_caller_memory"));
    struct Rejection {
        found: bool,
        accepted: bool,
    }
    impl<'ast> Visit<'ast> for Rejection {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, Pat::TupleStruct(pat)
                if pat.path.segments.last().unwrap().ident == "Err")
            {
                let mut body = Wiring::default();
                body.visit_expr(&arm.body);
                assert!(
                    body.paths.iter().any(|path| path == "None"),
                    "a rejected exact grant must remain unmapped"
                );
                assert!(
                    body.calls
                        .iter()
                        .any(|call| call.ends_with("report_rejection")),
                    "report only a genuine admission rejection"
                );
                assert!(
                    !body.paths.iter().any(|path| path == "Some"),
                    "no address fallback after failed admission"
                );
                self.found = true;
            }
            if matches!(&arm.pat, Pat::TupleStruct(pat)
                if pat.path.segments.last().unwrap().ident == "Ok")
            {
                let mut body = Wiring::default();
                body.visit_expr(&arm.body);
                assert!(
                    body.calls.iter().any(|call| call == "Some"),
                    "publish only the successfully admitted caller address"
                );
                assert!(
                    !body
                        .calls
                        .iter()
                        .any(|call| call.ends_with("report_rejection")),
                    "successful admissions must not log rejection receipts"
                );
                self.accepted = true;
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut rejection = Rejection {
        found: false,
        accepted: false,
    };
    rejection.visit_item_fn(&caller);
    assert!(
        rejection.found,
        "consume the typed admission Result explicitly"
    );
    assert!(
        rejection.accepted,
        "consume successful typed admission explicitly"
    );
    assert!(
        !facts
            .methods
            .iter()
            .any(|method| method.starts_with("unwrap_or")),
        "do not synthesize a default grant or address"
    );
}

#[test]
fn rejection_diagnostics_are_bounded_and_use_validated_resource_records() {
    let file = source("hosted_video_memory_mapping.rs");
    let diagnostic = function(&file, "report_rejection");
    let facts = wiring(&diagnostic);
    for field in [
        "SH_RESOURCE_PDO_OBJECT",
        "SH_VIDEO_MEMORY_PHYS",
        "SH_VIDEO_MEMORY_LEN",
        "SH_VIDEO_MEMORY_CALLER_VA",
        "SH_RESOURCE_ADDRESS_COUNT",
        "SH_RESOURCE_ADDRESS_CAPACITY",
    ] {
        assert!(
            facts.paths.iter().any(|path| path == field),
            "diagnose exact {field}"
        );
    }
    assert!(
        facts.methods.iter().any(|method| method == "fetch_add"),
        "bound failure-only output with an allocation-free counter"
    );
    assert!(
        facts
            .calls
            .iter()
            .any(|call| call.ends_with("shared_address_resource_count")),
        "validate shared count/capacity before walking records"
    );
    assert!(
        facts
            .calls
            .iter()
            .any(|call| call.ends_with("read_shared_address_resource")),
        "each diagnostic record must pass existing validation"
    );
    struct RecordWalk {
        validated_counts: Vec<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for RecordWalk {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let (Pat::TupleStruct(pattern), Some(initializer)) = (&local.pat, &local.init) {
                let mut value = Wiring::default();
                value.visit_expr(&initializer.expr);
                if pattern.path.segments.last().unwrap().ident == "Some"
                    && value
                        .calls
                        .iter()
                        .any(|call| call.ends_with("shared_address_resource_count"))
                {
                    if let Some(Pat::Ident(count)) = pattern.elems.first() {
                        self.validated_counts.push(count.ident.to_string());
                    }
                }
            }
            syn::visit::visit_local(self, local);
        }
        fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
            let mut range = Wiring::default();
            range.visit_expr(&expression.expr);
            let mut body = Wiring::default();
            body.visit_block(&expression.body);
            self.found |= range
                .paths
                .iter()
                .any(|path| self.validated_counts.contains(path))
                && body
                    .calls
                    .iter()
                    .any(|call| call.ends_with("read_shared_address_resource"));
            syn::visit::visit_expr_for_loop(self, expression);
        }
        fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
            let mut condition = Wiring::default();
            condition.visit_expr(&expression.cond);
            let mut body = Wiring::default();
            body.visit_block(&expression.body);
            self.found |= condition
                .paths
                .iter()
                .any(|path| self.validated_counts.contains(path))
                && body
                    .calls
                    .iter()
                    .any(|call| call.ends_with("read_shared_address_resource"));
            syn::visit::visit_expr_while(self, expression);
        }
    }
    let mut walk = RecordWalk {
        validated_counts: Vec::new(),
        found: false,
    };
    walk.visit_item_fn(&diagnostic);
    assert!(
        walk.found,
        "iterate only the validated Some(count), reading each record through validation"
    );
    assert!(
        !facts
            .calls
            .iter()
            .any(|call| call.ends_with("shared_address_resource_record")),
        "no raw record access in diagnostic iteration"
    );
    assert!(
        facts
            .literals
            .iter()
            .any(|literal| literal.contains("reject")),
        "print the actual typed rejection"
    );
}
