use syn::{visit::Visit, Item};

const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");

fn function(source: &str, name: &str) -> syn::ItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

fn fragment<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).unwrap().1.split_once(end).unwrap().0
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn active_syscall_receive_is_copied_and_cleared_by_exact_scope() {
    let source = fragment(PUMP, "fn capture_active_syscall_snapshot", "pub(super) fn print_active_syscall_receive_census");
    for field in ["route_identity.domain_generation", "route_identity.lane.generation",
        "tcb", "reply", "ssn", "started_100ns"] {
        assert!(source.contains(field), "missing copied owner field {field}");
    }
    let scope = fragment(PUMP, "struct ReceiveCensusScope", "pub(super) fn receive_census");
    assert!(scope.contains("capture_active_syscall_snapshot"));
    assert!(scope.contains("syscall_snapshot"));
    let compact: String = scope.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact.contains("ACTIVE_SYSCALL_SNAPSHOTS[index].sequence.compare_exchange(sequence,0"),
        "scope Drop must clear only its own generation");
}

#[test]
fn nested_syscall_progress_excludes_timer_notifications() {
    let source = fragment(PUMP, "pub(super) unsafe fn receive(", "pub(super) unsafe fn autonomous");
    let hosted = source.find("Ok(runtime::Arrival::Hosted) =>").unwrap();
    let call = source.find("Ok(runtime::Arrival::Call { route: sender, reply }) =>").unwrap();
    let notification = source.find("Ok(runtime::Arrival::Notification(message)) =>").unwrap();
    assert!(hosted < notification && call < notification);
    let progress = "record_active_syscall_provider_arrival";
    assert!(source[hosted..notification].contains(progress),
        "only provider arrivals may advance the nested receive progress census");
    assert!(!source[notification..].contains(progress),
        "timer notifications cannot masquerade as provider progress");
}

#[test]
fn periodic_census_prints_only_copied_syscall_owner_fields() {
    let mut calls = Calls::default();
    calls.visit_item_fn(&function(PUMP, "print_active_syscall_receive_census"));
    for forbidden in ["current_reply", "physical_source", "receive_owner", "receive", "dispatch"] {
        assert!(!calls.0.iter().any(|call| call == forbidden),
            "census performed live owner operation {forbidden}");
    }
    assert!(calls.0.iter().any(|call| call == "print_u64"));
    let mut main_calls = Calls::default();
    main_calls.visit_item_fn(&function(MAIN, "census_tick_static"));
    assert!(main_calls.0.iter().any(|call| call == "print_active_syscall_receive_census"));
}
