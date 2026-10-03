use syn::{visit::Visit, Expr, Item};

const KINDS: [&str; 3] = ["read", "flush", "query_information"];

fn source(kind: &str, suffix: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../components/ntos-executive/src/hosted_{kind}_{suffix}.rs"
    ));
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing exact hosted source boundary {name}"))
}

#[derive(Default)]
struct Calls(Vec<(String, Vec<Expr>)>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push((
                path.path.segments.last().unwrap().ident.to_string(),
                call.args.iter().cloned().collect(),
            ));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0
            .push((call.method.to_string(), call.args.iter().cloned().collect()));
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Calls {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls
}

#[derive(Default)]
struct Names(Vec<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.push(ident.to_string());
    }
}

#[test]
fn siblings_deduplicate_captured_generation_after_settling_exact_old_ack() {
    for kind in KINDS {
        let file = source(kind, "work");
        let calls = calls(&function(&file, "submit").block);
        let position = |name: &str| {
            calls
                .0
                .iter()
                .position(|(call, _)| call == name)
                .unwrap_or_else(|| panic!("{kind} submission must call {name}"))
        };
        assert!(
            position("reconcile_source_acks") < position("capture"),
            "{kind}"
        );
        assert!(position("capture") < position("source_identity"), "{kind}");
        assert!(
            position("source_identity") < position("source_work_index"),
            "{kind}"
        );
        let mut names = Names::default();
        for argument in &calls.0[position("source_work_index")].1 {
            names.visit_expr(argument);
        }
        assert!(
            !names.0.iter().any(|name| name == "source_irp_address"),
            "{kind}: reusable raw address cannot be duplicate-admission identity"
        );
    }
}

#[test]
fn siblings_executing_and_retained_owners_use_full_identity_and_owned_pin() {
    for kind in KINDS {
        let file = source(kind, "work");
        let executing = file
            .items
            .iter()
            .find_map(|item| match item {
                Item::Static(item) if item.ident == "EXECUTING" => Some(item),
                _ => None,
            })
            .unwrap();
        let mut names = Names::default();
        names.visit_type(&executing.ty);
        assert!(
            names
                .0
                .iter()
                .any(|name| name == "SourceIrpForwardIdentity"),
            "{kind}"
        );
        let helper = function(&file, "source_work_index");
        let calls = calls(&helper.block);
        assert!(
            calls.0.iter().any(|(name, _)| name == "duplicates_owned"),
            "{kind}"
        );
        assert!(
            calls.0.iter().any(|(name, _)| name == "source_pin_owned"),
            "{kind}: retained transport receipt is not source pin ownership"
        );
    }
}

#[test]
fn siblings_retire_only_acknowledged_physical_receipts_without_source_replay() {
    for kind in KINDS {
        let file = source(kind, "work");
        let calls = calls(&function(&file, "reconcile_source_acks").block);
        let reconcile = calls
            .0
            .iter()
            .position(|(name, _)| name == "reconcile_retained_service_reply")
            .unwrap_or_else(|| panic!("{kind}: old exact Reply must be acknowledged"));
        let retire = calls
            .0
            .iter()
            .position(|(name, _)| name == "retire_stopped_acknowledged_retained_service")
            .unwrap_or_else(|| panic!("{kind}: retain old receipt until physical acknowledgement"));
        assert!(reconcile < retire, "{kind}");
        for index in [reconcile, retire] {
            let mut names = Names::default();
            for argument in &calls.0[index].1 {
                names.visit_expr(argument);
            }
            for expected in ["ack", "route", "dispatch", "reply", "token"] {
                assert!(
                    names.0.iter().any(|name| name == expected),
                    "{kind}: retained {expected}"
                );
            }
        }
        assert!(
            !calls.0.iter().any(|(name, _)| matches!(
                name.as_str(),
                "release" | "unpin" | "s_io_free_irp" | "complete_hosted_irp"
            )),
            "{kind}"
        );
    }
}

#[test]
fn sibling_captures_report_full_observational_identity_and_actual_pin_state() {
    for kind in KINDS {
        let file = source(kind, "capture");
        let methods: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Impl(item) => Some(item.items.iter()),
                _ => None,
            })
            .flatten()
            .filter_map(|item| match item {
                syn::ImplItem::Fn(method) => Some(method),
                _ => None,
            })
            .collect();
        let identity = methods
            .iter()
            .find(|method| method.sig.ident == "source_identity")
            .unwrap_or_else(|| panic!("{kind}: capture must expose exact source identity"));
        let mut names = Names::default();
        names.visit_block(&identity.block);
        for expected in ["SourceIrpForwardIdentity", "source", "allocation"] {
            assert!(
                names.0.iter().any(|name| name == expected),
                "{kind}: {expected}"
            );
        }
        let pinned = methods
            .iter()
            .find(|method| method.sig.ident == "source_pin_owned")
            .unwrap_or_else(|| panic!("{kind}: capture must expose owned pin, not row existence"));
        let mut names = Names::default();
        names.visit_block(&pinned.block);
        assert!(names.0.iter().any(|name| name == "pinned"), "{kind}");
    }
}

#[test]
fn siblings_select_pending_arm_and_inline_hold_by_token_before_mutation() {
    for kind in KINDS {
        let file = source(kind, "work");
        for entry in ["arm_pending", "acknowledge_held"] {
            let calls = calls(&function(&file, entry).block);
            let selected = calls
                .0
                .iter()
                .find(|(name, arguments)| {
                    if name != "source_token_work_index" {
                        return false;
                    }
                    let mut names = Names::default();
                    for argument in arguments {
                        names.visit_expr(argument);
                    }
                    names.0.iter().any(|name| name == "token")
                        && names.0.iter().any(|name| name == "source_irp_address")
                })
                .unwrap_or_else(|| {
                    panic!("{kind}/{entry}: exact token must participate in candidate selection")
                });
            let mut names = Names::default();
            names.visit_block(&function(&file, &selected.0).block);
            for expected in ["origin", "token", "source_pin_owned"] {
                assert!(
                    names.0.iter().any(|name| name == expected),
                    "{kind}/{entry}: {expected}"
                );
            }
        }
    }
}

#[test]
fn siblings_ack_selection_excludes_released_sources_and_validates_retained_capture() {
    for kind in KINDS {
        let file = source(kind, "work");
        let ingress_calls = calls(&function(&file, "acknowledge").block);
        let selected = ingress_calls
            .0
            .iter()
            .find(|(name, _)| name == "source_ack_work_index")
            .unwrap_or_else(|| panic!("{kind}: ACK requires an exact eligible owner lookup"));
        let helper = function(&file, &selected.0);
        let calls = calls(&helper.block);
        assert!(
            calls.0.iter().any(|(name, _)| name == "source_pin_owned"),
            "{kind}: released transport-only row cannot capture another allocation's ACK"
        );
        assert!(
            calls.0.iter().any(|(name, _)| name == "validate_source"),
            "{kind}: validate existing retained allocation/ticket before choosing ACK owner"
        );
        assert!(
            !calls.0.iter().any(|(name, _)| name == "capture"),
            "{kind}: completed stack locations need not support fresh dispatch capture"
        );
    }
}
