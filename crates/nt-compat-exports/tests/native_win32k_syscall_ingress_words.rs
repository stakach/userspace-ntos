//! A hosted win32k syscall owns the argument words captured when it was received.
//!
//! KVM boot 44038636280 walled the win32k component while it copied NtUserPeekMessage's fifth
//! argument from caller RSP 0x31. The win32k route ticked the periodic census
//! (`w32_census_enter`) before it read R10/R8/R9/RSP back out of the root IPC buffer, and the
//! census's `TCB::ReadDebugState` replies had overwritten those words: RSP was the last thread's
//! `target` word (49), R8/R9 were `none` (u64::MAX). These fixtures fail on that interleaving:
//! a route that rereads the buffer after a kernel query, or a diagnostic query that leaves its
//! reply in the buffer.

use syn::visit::Visit;
use syn::{Expr, Item};

const EXECUTIVE: &str = "../../components/ntos-executive/src";

fn parse(relative: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(EXECUTIVE).join(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    syn::parse_file(&source).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing fn {name}"))
}

/// Every call, method call and macro in source order, named by its full path.
fn events(function: &syn::ItemFn) -> Vec<String> {
    struct Events(Vec<String>);
    fn path_name(path: &syn::Path) -> String {
        path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>().join("::")
    }
    impl<'ast> Visit<'ast> for Events {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = call.func.as_ref() {
                self.0.push(path_name(&path.path));
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(format!(".{}", call.method));
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            self.0.push(format!("{}!", path_name(&mac.path)));
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut events = Events(Vec::new());
    events.visit_block(&function.block);
    events.0
}

fn position(events: &[String], wanted: impl Fn(&str) -> bool) -> Option<usize> {
    events.iter().position(|event| wanted(event))
}

#[test]
fn win32k_route_takes_its_arguments_from_the_ingress_capture() {
    let file = parse("executor/syscall_win32k.rs");
    let route = function(&file, "syscall_win32k_route");
    let events = events(route);
    let census = position(&events, |event| event.ends_with("w32_census_enter"))
        .expect("the route still ticks the dispatch census");
    let captured = position(&events, |event| event == ".register_args")
        .expect("R10/R8/R9 must come from the syscall's ingress capture");
    assert!(captured < census, "arguments must be owned before the census can run");
    assert!(
        !events.iter().any(|event| event.ends_with("get_recv_mr")),
        "the win32k route must not reread argument words from the shared root IPC buffer",
    );
}

#[test]
fn diagnostic_debug_state_reads_restore_the_received_message() {
    let file = parse("win32k_glue.rs");
    let read = function(&file, "tcb_read_debug_state");
    let events = events(read);
    let saved = position(&events, |event| event.ends_with("SavedMessageBuffer::capture"))
        .expect("TCB::ReadDebugState spills its reply into the root IPC buffer");
    let invoke = position(&events, |event| event.ends_with("asm!"))
        .expect("the debug-state invocation");
    assert!(saved < invoke, "the received message must be saved before the reply overwrites it");
}

#[test]
fn periodic_census_restores_the_message_it_interrupted() {
    let file = parse("main.rs");
    let census = function(&file, "census_tick_static");
    let events = events(census);
    let saved = position(&events, |event| event.ends_with("SavedMessageBuffer::capture"))
        .expect("the periodic dump runs inside a live root turn");
    let first_dump = position(&events, |event| event == "print_periodic_census_heartbeat")
        .expect("periodic census dump");
    assert!(saved < first_dump, "the message must be saved before the dump issues kernel queries");
}

#[test]
fn win32k_component_validates_the_caller_stack_tail_before_reading_it() {
    let file = parse("win32k_subsystem.rs");
    let dispatch = function(&file, "dispatch_ssn");
    let events = events(dispatch);
    let validate = position(&events, |event| event.ends_with("validate_user_stack_argument_tail"))
        .expect("a non-user caller stack must fail the call, not the component");
    let foreign_call = position(&events, |event| event == "call")
        .expect("the foreign SSDT handler call");
    assert!(validate < foreign_call);
    let request_argument = function(&file, "current_request_argument");
    assert!(events_contains(request_argument, "user_stack_argument_address"),
        "nested readers of the caller stack use the same user-range check");
}

fn events_contains(function: &syn::ItemFn, wanted: &str) -> bool {
    events(function).iter().any(|event| event.ends_with(wanted))
}
