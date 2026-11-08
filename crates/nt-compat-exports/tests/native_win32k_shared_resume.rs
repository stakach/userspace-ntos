//! The win32k shared callback and selected-context cells are one physical publication.
//! A different lane may use that publication while Receive or an external service wait is
//! suspended, so continuation must restore the exact owner's cells before native execution.

use syn::{visit::Visit, Expr, Item};

#[path = "../../../components/ntos-executive/src/win32k_shared_request_owner.rs"]
mod shared_request_owner;

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn call_position(function: &syn::ItemFn, name: &str) -> Option<usize> {
    struct Calls<'a> {
        wanted: &'a str,
        next: usize,
        position: Option<usize>,
    }
    impl<'ast> Visit<'ast> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = call.func.as_ref() {
                if path.path.segments.last().is_some_and(|part| part.ident == self.wanted) {
                    self.position.get_or_insert(self.next);
                }
            }
            self.next += 1;
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls {
        wanted: name,
        next: 0,
        position: None,
    };
    calls.visit_block(&function.block);
    calls.position
}

fn has_field(fields: &syn::Fields, name: &str) -> bool {
    fields.iter().any(|field| field.ident.as_ref().is_some_and(|id| id == name))
}

#[test]
fn receive_yield_retains_shared_publication_before_nested_settlement() {
    let pending = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_pending_dispatch.rs"
    )).unwrap();
    let receive_yield = pending.items.iter().find_map(|item| match item {
        Item::Struct(record) if record.ident == "ReceiveYield" => Some(&record.fields),
        _ => None,
    }).expect("ReceiveYield declaration");
    assert!(has_field(receive_yield, "shared_resume"),
        "the authenticated yield must carry its exact shared publication across the park");

    let receive_source = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
    let receive = syn::parse_file(receive_source).unwrap();
    let prepare = function(&receive, "prepare_receive_yield");
    let parent = function(&receive, "finish_nested_yield_parent");
    assert!(call_position(parent, "capture_shared_resume_snapshot").is_some(),
        "the authenticated parent must capture its shared publication");
    let capture = call_position(prepare, "finish_nested_yield_parent")
        .expect("capture the dispatch publication at its authenticated yield boundary");
    let nested = call_position(prepare, "prepare_receive_settlement")
        .expect("receive settlement boundary");
    let park = call_position(prepare, "park_current").expect("parent park boundary");
    assert!(capture < nested && capture < park,
        "the shared page must be captured before nested settlement or parking can admit another dispatch");

    // Every initial and reparked receive continuation must take the publication carried by
    // that yield, rather than reading the one physical page after the pump has returned.
    struct PendingReceiveSites {
        found: usize,
    }
    impl<'ast> Visit<'ast> for PendingReceiveSites {
        fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
            if expr.path.segments.last().is_some_and(|segment| segment.ident == "PendingReceiveDispatch") {
                self.found += 1;
                let snapshot = expr.fields.iter()
                    .find(|field| matches!(&field.member, syn::Member::Named(name) if name == "snapshot"))
                    .expect("pending Receive owns one pump snapshot");
                let Expr::Struct(snapshot) = &snapshot.expr else {
                    panic!("pending receive site {} must retain one pump snapshot", self.found);
                };
                let shared = snapshot.fields.iter()
                    .find(|field| matches!(&field.member, syn::Member::Named(name) if name == "shared_resume"))
                    .unwrap_or_else(|| panic!("pending receive site {} lost its shared publication", self.found));
                let Expr::Field(from_yield) = &shared.expr else {
                    panic!("pending receive site {} must use the yield's retained publication", self.found);
                };
                assert!(matches!(from_yield.base.as_ref(), Expr::Path(path)
                    if path.path.is_ident("yielded")),
                    "pending receive site {} must use the yield's retained publication", self.found);
                assert!(matches!(&from_yield.member, syn::Member::Named(name) if name == "shared_resume"),
                    "pending receive site {} must use the yield's retained publication", self.found);
            }
            syn::visit::visit_expr_struct(self, expr);
        }
    }
    for file in [
        receive,
        syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_glue.rs")).unwrap(),
    ] {
        let mut sites = PendingReceiveSites { found: 0 };
        sites.visit_file(&file);
        assert!(sites.found > 0, "expected an initial or reparked receive continuation");
    }
}

#[test]
fn a_yielded_publication_survives_another_dispatch_on_the_same_page() {
    use nt_user_callback::{CallbackHeader, SharedCallbackPublication, SHARED_CALLBACK_REQUEST_WORDS};

    let a_header = CallbackHeader::idle(91, 7, 108, 729);
    let b_header = CallbackHeader::idle(92, 8, 112, 730);
    let mut a_request = [0xaaaa_u64; SHARED_CALLBACK_REQUEST_WORDS];
    a_request[7] = 0xfeed_cafe;
    let mut b_request = [0xbbbb_u64; SHARED_CALLBACK_REQUEST_WORDS];
    b_request[7] = 0xdead_beef;
    let a_context = [7, 108, 0xa3, 0xa4, 0xa5, 0xa6];
    let b_context = [8, 112, 0xb3, 0xb4, 0xb5, 0xb6];
    let mut page = (a_header, SharedCallbackPublication::new(a_request, a_context));

    let capture = |page: &(CallbackHeader, SharedCallbackPublication), expected: CallbackHeader| {
        if !page.0.matches_dispatch_identity(expected.dispatch_id, expected.client_pi,
            expected.client_tid, expected.client_badge) {
            return None;
        }
        let mut words = *page.1.request();
        shared_request_owner::canonicalize(&mut words, shared_request_owner::RequestOwner {
            ssn: 0x1002, pid: 0x50, pi: expected.client_pi as u64,
            tid: expected.client_tid, generation: 1, token_auth: 0x42,
            token_sid_len: 4, token_sid_ptr: 0x1000,
        });
        Some((page.0, SharedCallbackPublication::new(words, *page.1.context())))
    };

    let retained_a = capture(&page, a_header).expect("A owns the page before its yield");
    page = (b_header, SharedCallbackPublication::new(b_request, b_context));
    assert!(capture(&page, a_header).is_none(),
        "a late capture must reject B's physical header as A's ownership");
    let retained_b = capture(&page, b_header).expect("B owns the page while A is parked");
    assert_eq!(retained_a.0, a_header);
    assert_eq!(retained_a.1.request()[7], 0xfeed_cafe);
    assert_eq!(retained_a.1.context(), &a_context);
    assert_eq!(retained_b.1.request()[7], 0xdead_beef);
    assert_eq!(retained_b.1.context(), &b_context);
    page = retained_a;
    assert_eq!(page.0, a_header);
    assert_eq!(page.1.request()[7], 0xfeed_cafe);
    assert_eq!(page.1.context(), &a_context);
}

#[test]
fn receive_and_service_wait_restore_their_own_shared_publication_before_receiving() {
    let pending = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_pending_dispatch.rs"
    ))
    .unwrap();
    let snapshot_fields = pending.items.iter().find_map(|item| match item {
        Item::Struct(record) if record.ident == "SuspendedPumpSnapshot" => Some(&record.fields),
        _ => None,
    }).expect("shared pending pump snapshot");
    assert!(has_field(snapshot_fields, "shared_resume"),
        "the shared pump snapshot must retain its own callback publication");
    for name in ["PendingReceiveDispatch", "PendingServiceWaitDispatch"] {
        let fields = pending.items.iter().find_map(|item| match item {
            Item::Struct(record) if record.ident == name => Some(&record.fields),
            _ => None,
        }).unwrap_or_else(|| panic!("missing {name}"));
        assert!(has_field(fields, "snapshot"),
            "{name} must retain the common pump snapshot across a yield");
    }

    let bridge = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    ))
    .unwrap();
    let bridge_source = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    for name in ["PendingReceiveDispatch", "PendingServiceWaitDispatch"] {
        assert!(bridge_source.contains(&format!("{name} {{")));
    }
    assert!(bridge_source.contains("capture_shared_resume_snapshot"),
        "the initial yielded dispatch must retain its own shared publication");
    drop(bridge);

    let resume = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_receive.rs"
    ))
    .unwrap();
    let helper = function(&pending, "select_and_restore_shared_resume_snapshot");
    assert!(call_position(helper, "select_win32k_client_window").unwrap()
        < call_position(helper, "restore_shared_resume_snapshot").unwrap(),
        "the selected client must own the page before its publication is restored");
    for (name, continuation) in [
        ("resume_suspended_receive_component", "component_pump_continue_receive"),
        ("resume_suspended_service_wait_component", "component_pump_continue_service_wait"),
    ] {
        let function = function(&resume, name);
        let restore = call_position(function, "select_and_restore_shared_resume_snapshot")
            .unwrap_or_else(|| panic!("{name} must restore its exact shared publication"));
        let receive = call_position(function, continuation)
            .unwrap_or_else(|| panic!("{name} must continue the retained receive half"));
        assert!(restore < receive,
            "{name} must restore the callback header and selected context before native receive");
    }
}
