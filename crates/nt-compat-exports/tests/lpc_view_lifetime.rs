//! A completed rendezvous does not retire either endpoint's mapped Section views.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct FailedAcceptBranches(Vec<syn::Block>);
impl<'ast> Visit<'ast> for FailedAcceptBranches {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let mut calls = Calls::default();
        calls.visit_expr(&expression.cond);
        if calls
            .0
            .iter()
            .any(|name| name == "accept_lpc_connection_views")
        {
            self.0.push(expression.then_branch.clone());
        }
        syn::visit::visit_expr_if(self, expression);
    }
}

#[test]
fn failed_accept_views_settle_the_exact_parked_connector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut branches = FailedAcceptBranches::default();
    branches.visit_file(&file);
    assert!(
        !branches.0.is_empty(),
        "actual native accept-view failure branches"
    );
    for branch in branches.0 {
        let mut calls = Calls::default();
        calls.visit_block(&branch);
        assert!(calls.0.iter().any(|name| name == "settle_lpc_accept_failure"),
            "closing a rejected server endpoint without exact retained connector settlement leaves NtSecureConnectPort parked forever");
    }
}

#[test]
fn completing_connection_keeps_view_owners_until_endpoint_retirement() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let mut found = None;
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
        for item in file.items {
            let syn::Item::Impl(implementation) = item else {
                continue;
            };
            for item in implementation.items {
                let syn::ImplItem::Fn(function) = item else {
                    continue;
                };
                if function.sig.ident == "complete_lpc_connection_views" {
                    found = Some(function);
                }
            }
        }
    }
    let function = found.expect("actual native LPC completion implementation");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    assert!(!calls.0.iter().any(|name| name == "swap_remove" || name == "remove"),
        "connection completion must retain exact mapped views for subsequent endpoint retirement; discarding the row leaks the server VAD across short-lived children");
}

#[test]
fn process_exit_and_retained_deletion_both_drain_broker_handles() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    for name in [
        "release_process_handles",
        "try_delete_hosted_process_object_exact",
    ] {
        let function = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(implementation) => Some(implementation),
                _ => None,
            })
            .flat_map(|implementation| implementation.items.iter())
            .find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
            .expect("actual process rundown implementation");
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        assert!(calls.0.iter().any(|call| call == "retire_lpc_process_handles"),
            "{name} must retain and drain the exiting process's broker-owned LPC handles, independently of executive handles and delayed object deletion");
    }
}

#[test]
fn provider_final_reference_release_publishes_retirement_progress() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/win32k_subsystem.rs");
    let source = std::fs::read_to_string(path).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "service_lpc_request" => {
                Some(function)
            }
            _ => None,
        })
        .expect("actual isolated provider LPC pump");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    assert!(
        calls
            .0
            .iter()
            .any(|call| call == "release_port_object_with_lifetime"),
        "provider-held LPC references must report final deletion to exact native view retirement"
    );
    assert!(
        !calls.0.iter().any(|call| call == "release_port_object"),
        "discarding final-reference deletion leaves event-driven view cleanup dormant"
    );
}

#[test]
fn aborted_preaccept_owner_requires_canonical_client_deletion() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/lpc_connection_views.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let function = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(implementation) => Some(implementation),
            _ => None,
        })
        .flat_map(|implementation| implementation.items.iter())
        .find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "abort_lpc_connection_views" => {
                Some(function)
            }
            _ => None,
        })
        .expect("actual preaccept LPC cancellation cleanup");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    let deletion = calls.0.iter().position(|call| call == "query_endpoint_lifetime")
        .expect("a cancelled Reply is not broker construction deletion: query the exact client endpoint before removing its native owner");
    let certificate = calls.0.iter().position(|call| call == "is_deleted").expect(
        "only the broker's monotonic endpoint deletion certificate authorizes owner retirement",
    );
    let withdrawal = calls
        .0
        .iter()
        .position(|call| call == "swap_remove")
        .expect("settled empty preaccept owner can be retired");
    assert!(
        deletion < certificate && certificate < withdrawal,
        "empty mapping slots alone cannot authorize retirement after uncertain broker refusal"
    );

    #[derive(Default)]
    struct ExactClientQuery {
        found: bool,
    }
    impl<'ast> Visit<'ast> for ExactClientQuery {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "query_endpoint_lifetime" {
                #[derive(Default)]
                struct Authority {
                    connection: bool,
                    client: bool,
                    owner: bool,
                }
                impl<'ast> Visit<'ast> for Authority {
                    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                        if let Some(segment) = path.path.segments.last() {
                            self.connection |= segment.ident == "connection_id";
                            self.client |= segment.ident == "CLIENT_COMM_PORT";
                        }
                        syn::visit::visit_expr_path(self, path);
                    }
                    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                        self.owner |= matches!(&field.member, syn::Member::Named(name) if name == "connector_broker_process");
                        self.connection |= matches!(&field.member, syn::Member::Named(name) if name == "connection_id");
                        syn::visit::visit_expr_field(self, field);
                    }
                }
                let mut authority = Authority::default();
                for argument in &call.args {
                    authority.visit_expr(argument);
                }
                self.found |= authority.connection && authority.client && authority.owner;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut exact = ExactClientQuery::default();
    exact.visit_block(&function.block);
    assert!(exact.found, "deletion query must use the actual connection, client endpoint kind, and captured broker owner, not the mapping PID");
}
