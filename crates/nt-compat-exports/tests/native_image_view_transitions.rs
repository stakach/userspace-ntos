//! Observation must follow the real image-view ownership transitions, not authorize them.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);

impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(name: &str) -> Vec<String> {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_native_image_view.rs"
    ))
    .unwrap();
    let method = source
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
        })
        .expect("actual native image view entrypoint");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    calls.0
}

fn position(calls: &[String], name: &str) -> usize {
    calls
        .iter()
        .position(|call| call == name)
        .unwrap_or_else(|| panic!("missing actual image transition call {name}"))
}

#[test]
fn image_map_observation_follows_commit_before_late_user_copyout() {
    let calls = calls("map_native_image_section_view");
    let capture = position(&calls, "capture_image_view_transition");
    let publish = position(&calls, "publish_mapped_view");
    let emit = position(&calls, "emit_image_view_transition");
    let copyout = position(&calls, "process_memory_write_checked");
    assert!(capture < publish && publish < emit && emit < copyout,
        "copy exact owner metadata before effects; report committed view even if late copyout fails");
    assert_eq!(
        calls
            .iter()
            .filter(|call| *call == "emit_image_view_transition")
            .count(),
        1
    );
}

#[test]
fn image_unmap_observation_follows_exact_retirement_ack_and_owner_withdrawal() {
    let calls = calls("unmap_native_image_view");
    let capture = position(&calls, "capture_image_view_transition");
    let begin = position(&calls, "begin_mapped_view_retirement");
    let drain = position(&calls, "drain_view");
    let ack = position(&calls, "acknowledge_mapped_view_retirement");
    let remove = position(&calls, "swap_remove");
    let emit = position(&calls, "emit_image_view_transition");
    assert!(
        capture < begin && begin < drain && drain < ack && ack < remove && remove < emit,
        "an entered or uncertain unmap is not a retired view and must not emit a success record"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| *call == "emit_image_view_transition")
            .count(),
        1
    );
}
