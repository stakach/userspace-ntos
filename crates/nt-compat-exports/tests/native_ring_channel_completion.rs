#[path = "../../../components/ntos-executive/src/ring_channel_completion.rs"]
mod ring_channel_completion;

use ring_channel_completion::CompletionInbox;
use syn::{visit::Visit, Item};

const EXECUTIVE: &str = include_str!("../../../components/ntos-executive/src/main.rs");

#[test]
fn owned_object_manager_request_returns_with_its_exact_completion_pending() {
    struct Calls { methods: Vec<String>, synchronous_raw: bool }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.methods.push(call.method.to_string());
            self.synchronous_raw |= call.method == "raw"
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("self"));
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let file = syn::parse_file(EXECUTIVE).expect("executive source parses");
    let body = file.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "submit_owned" => Some(&item.block),
            _ => None,
        }),
        _ => None,
    }).expect("owned SURT submission");
    let mut calls = Calls { methods: Vec::new(), synchronous_raw: false };
    calls.visit_block(body);
    assert!(!calls.synchronous_raw,
        "an owned directory request must not block its parent pump in the synchronous SURT wait");
    for method in ["begin_owned", "try_push", "notify_consumer"] {
        assert!(calls.methods.iter().any(|call| call == method),
            "owned submission must {method} before returning its exact pending identity");
    }
    assert!(EXECUTIVE.contains("self.0.submit_owned(opcode, in_buf)"),
        "the Object Manager adapter must use the nonblocking owned submit path");
}

#[test]
fn parked_outer_completion_survives_a_borrowed_frame() {
    let mut inbox = CompletionInbox::<[u8; 4]>::new();
    let outer = 41;
    let nested = 42;
    assert!(inbox.begin_owned(outer));
    assert_eq!(inbox.park_active_owned(outer, *b"OUTR"), Ok(()));
    assert!(inbox.begin(nested));
    assert_eq!(
        inbox.take_parked_owned(outer),
        Some(*b"OUTR"),
        "outer completion and payload must remain available to the outer request"
    );
    assert_eq!(inbox.active_request(), Some(nested));
}

#[test]
fn shared_request_frame_rejects_nested_submission_until_owner_finishes() {
    let mut inbox = CompletionInbox::<[u8; 4]>::new();
    assert!(inbox.begin(41));
    assert!(!inbox.begin(42), "nested request must not overwrite the outer request frame");
    inbox.finish(41);
    assert!(inbox.begin(42));
    inbox.finish(42);
}
