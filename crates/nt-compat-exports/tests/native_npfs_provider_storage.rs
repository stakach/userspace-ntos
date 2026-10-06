//! Provider-private NPFS queues are not executive-owned repairable storage.
//! These checks supplement real pipe/projection tests; they are not guest proof.
use syn::{visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(value) if value.sig.ident == name => Some(value),
            _ => None,
        })
        .expect("actual native function")
}

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        if call.method == "is_some_and" {
            if let Some(Expr::Path(predicate)) = call.args.first() {
                self.calls
                    .push(predicate.path.segments.last().unwrap().ident.to_string());
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn predicate_invocation_is_distinct_from_a_bare_function_reference() {
    let invoked: Expr = syn::parse_quote!(receipt.is_some_and(file_projection_identity_is_current));
    let referenced: Expr = syn::parse_quote!(file_projection_identity_is_current);
    let mut invocation = Effects::default();
    invocation.visit_expr(&invoked);
    let mut reference = Effects::default();
    reference.visit_expr(&referenced);
    assert!(invocation
        .calls
        .iter()
        .any(|name| name == "file_projection_identity_is_current"));
    assert!(!reference
        .calls
        .iter()
        .any(|name| name == "file_projection_identity_is_current"));
}

#[test]
fn actual_irp_dispatch_does_not_audit_or_repair_provider_private_queues() {
    let file = source("driver_launch.rs");
    let mut effects = Effects::default();
    effects.visit_block(&function(&file, "run_irp").block);
    for forbidden in ["audit_ccb", "audit_data_queue", "queue_dump"] {
        assert!(
            !effects.calls.iter().any(|name| name == forbidden),
            "dispatch cannot claim provider-private lifetime authority through {forbidden}"
        );
    }
    for required in ["fo_lookup", "fo_register", "fo_bind", "fo_release"] {
        assert!(
            effects.calls.iter().any(|name| name == required),
            "preserve canonical File projection ownership through {required}"
        );
    }
    assert!(effects.paths.iter().any(|name| name == "canonical_file_id"));
}

#[test]
fn obsolete_private_queue_repair_and_audit_only_counters_are_removed() {
    let file = source("driver_launch.rs");
    let names: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(value) => Some(value.sig.ident.to_string()),
            Item::Static(value) => Some(value.ident.to_string()),
            Item::Const(value) => Some(value.ident.to_string()),
            _ => None,
        })
        .collect();
    for forbidden in [
        "audit_ccb",
        "audit_data_queue",
        "queue_dump",
        "QUEUE_DUMP_COUNT",
        "NP_CCB_FILE_OBJECT",
        "NP_ENTRY_TYPE_MAX",
        "NP_QUEUE_WALK_MAX",
        "FSD_QUEUE_AUDITS",
        "FSD_QUEUE_REPAIRS",
        "FSD_FO_LIVE_CHECKS",
        "FSD_FO_DANGLING",
        "FSD_FO_CORRUPTED",
    ] {
        assert!(
            !names.iter().any(|name| name == forbidden),
            "delete unauthoritative audit machinery rather than leave {forbidden} dormant"
        );
    }
    for required in [
        "pipe_ccb_view",
        "pipe_ccb_view_in_pool",
        "trace_pipe_rw_result",
        "trace_pipe_transceive_result",
        "print_pipe_queue_heads_for_deadman",
        "FSD_FO_OPENS",
        "FSD_FO_REUSED",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "preserve independent diagnostics or real File events: {required}"
        );
    }
}

#[test]
fn native_pipe_acceptance_preserves_real_data_and_completion_ack_checks() {
    struct Gates(Vec<(String, Effects)>);
    impl<'ast> Visit<'ast> for Gates {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "check"))
            {
                if let Some(Expr::Lit(label)) = call.args.first() {
                    if let syn::Lit::ByteStr(label) = &label.lit {
                        let mut effects = Effects::default();
                        effects.visit_expr(call.args.iter().nth(1).expect("check condition"));
                        self.0
                            .push((String::from_utf8(label.value()).unwrap(), effects));
                    }
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let file = source("main.rs");
    let mut gates = Gates(Vec::new());
    gates.visit_file(&file);
    for (label, required) in [
        (
            "exec_npfs_concurrent_irp_read_and_write",
            &[
                "srv_read_pended",
                "response_ok",
                "pending_delivered",
                "stash_acked",
            ][..],
        ),
        (
            "exec_npfs_write_split_across_pending_read",
            &["hdr_pended", "hdr_ok", "hdr_stash_acked", "rest_ok"][..],
        ),
        (
            "exec_npfs_file_object_lifetime",
            &[
                "projection_before",
                "projection_pending",
                "projection_write",
                "projection_read",
                "projection_acked",
                "srv_read_pended",
                "response_ok",
                "pending_delivered",
                "stash_acked",
            ][..],
        ),
    ] {
        let matches: Vec<_> = gates.0.iter().filter(|(name, _)| name == label).collect();
        assert_eq!(matches.len(), 1, "retain the actual native gate {label}");
        let effects = &matches[0].1;
        for name in required {
            assert!(
                effects.paths.iter().any(|path| path == name),
                "{label} must still require real data/completion condition {name}"
            );
        }
        assert!(
            !effects.paths.iter().any(|name| name == "FSD_QUEUE_REPAIRS"),
            "a host repair counter is not a provider result or ownership acknowledgement"
        );
    }
    let mut effects = Effects::default();
    effects.visit_file(&file);
    for required in [
        "copy_completed_irp",
        "acknowledge_completed_irp",
        "capture_file_projection_identity",
        "file_projection_identity_is_current",
    ] {
        assert!(effects.calls.iter().any(|name| name == required));
    }
    for obsolete in [
        "FSD_FO_LIVE_CHECKS",
        "FSD_FO_DANGLING",
        "FSD_FO_CORRUPTED",
        "FSD_QUEUE_AUDITS",
        "FSD_QUEUE_REPAIRS",
    ] {
        assert!(
            !effects.paths.iter().any(|name| name == obsolete),
            "native evidence must not depend on deleted private-storage audit {obsolete}"
        );
    }
    let projection = source("hosted_file_objects.rs");
    for required in ["fo_lookup", "fo_register", "fo_bind", "fo_release"] {
        function(&projection, required);
    }
}

#[test]
fn projection_observations_use_exact_receipts_without_artificial_lifetime_pins() {
    let file = source("driver_launch.rs");
    for (name, required) in [
        ("capture_file_projection_identity", "hosted_file_identities"),
        (
            "file_projection_identity_is_current",
            "hosted_file_identity_at",
        ),
    ] {
        let mut effects = Effects::default();
        effects.visit_block(&function(&file, name).block);
        assert!(effects.calls.iter().any(|call| call == required));
        for forbidden in [
            "lease_hosted_file_identity",
            "retain_file",
            "read_volatile",
            "read_unaligned",
        ] {
            assert!(
                !effects.calls.iter().any(|call| call == forbidden),
                "projection observation must not read private memory or add lifetime authority"
            );
        }
    }
    let validate = function(&file, "file_projection_identity_is_current");
    struct ExactComparison(bool);
    impl<'ast> Visit<'ast> for ExactComparison {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Eq(_)) {
                let mut left = Effects::default();
                let mut right = Effects::default();
                left.visit_expr(&binary.left);
                right.visit_expr(&binary.right);
                self.0 |= left
                    .calls
                    .iter()
                    .any(|name| name == "hosted_file_identity_at")
                    && right.paths.iter().any(|name| name == "identity");
            }
            syn::visit::visit_expr_binary(self, binary);
        }
    }
    let mut exact = ExactComparison(false);
    exact.visit_block(&validate.block);
    assert!(
        exact.0,
        "revalidate the full saved binding generation, not only its address"
    );
    struct Observations(Vec<String>);
    impl<'ast> Visit<'ast> for Observations {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let syn::Pat::Ident(binding) = &local.pat {
                let name = binding.ident.to_string();
                let required = match name.as_str() {
                    "srv_projection" | "cli_projection" => Some("capture_file_projection_identity"),
                    "projection_before" | "projection_pending" | "projection_write"
                    | "projection_read" | "projection_acked" => Some("projection_is_current"),
                    _ => None,
                };
                if let Some(required) = required {
                    assert!(
                        binding.mutability.is_none(),
                        "keep saved evidence immutable"
                    );
                    let mut effects = Effects::default();
                    effects.visit_expr(&local.init.as_ref().expect("actual observation").expr);
                    assert!(
                        effects.calls.iter().any(|call| call == required),
                        "{name} must observe real projection authority, not a fabricated flag"
                    );
                    self.0.push(name);
                }
            }
            syn::visit::visit_local(self, local);
        }
    }
    let mut observations = Observations(Vec::new());
    observations.visit_file(&source("main.rs"));
    assert_eq!(
        observations.0,
        [
            "srv_projection",
            "cli_projection",
            "projection_before",
            "projection_pending",
            "projection_write",
            "projection_read",
            "projection_acked"
        ]
    );
}
