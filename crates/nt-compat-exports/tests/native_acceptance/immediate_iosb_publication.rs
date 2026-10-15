//! NT5 iomgr/internal.c:1331-1358 publishes Information before the barrier and Status.
//! Completion polling must not observe terminal Status with stale Information.

use syn::{visit::Visit, Expr, ImplItem, Item};

fn function(source: &str, name: &str) -> syn::Block {
    let file = syn::parse_file(source).expect("native source parses");
    for item in file.items {
        match item {
            Item::Fn(function) if function.sig.ident == name => return *function.block,
            Item::Impl(item) => {
                for item in item.items {
                    if let ImplItem::Fn(function) = item {
                        if function.sig.ident == name { return function.block; }
                    }
                }
            }
            _ => {}
        }
    }
    panic!("missing native function {name}");
}

fn contains_name(expression: &Expr, name: &str) -> bool {
    struct Names<'a> { name: &'a str, found: bool }
    impl<'ast> Visit<'ast> for Names<'_> {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.found |= path.path.is_ident(self.name);
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut names = Names { name, found: false };
    names.visit_expr(expression);
    names.found
}

#[derive(Default)]
struct Publication {
    ordered: usize,
    raw_iosb: usize,
}

impl<'ast> Visit<'ast> for Publication {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if matches!(call.method.to_string().as_str(), "publish_file_io_status" | "write_current_iosb")
            && call.args.first().is_some_and(|argument| contains_name(argument, "iosb"))
        {
            self.ordered += 1;
        }
        if call.method == "xas_try_write_buf"
            && call.args.first().is_some_and(|argument| contains_name(argument, "iosb"))
        {
            self.raw_iosb += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            let name = &path.path.segments.last().unwrap().ident;
            if name == "publish_file_io_status_checked"
                && call.args.first().is_some_and(|argument| contains_name(argument, "iosb"))
            {
                self.ordered += 1;
            }
            if name == "write_unaligned"
                && call.args.first().is_some_and(|argument| contains_name(argument, "iosb"))
            {
                self.raw_iosb += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn publication(source: &str, name: &str) -> Publication {
    let mut publication = Publication::default();
    publication.visit_block(&function(source, name));
    publication
}

#[test]
fn immediate_iosb_wrapper_uses_information_before_terminal_status_publisher() {
    let publication = publication(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    ), "write_current_iosb");
    assert!(publication.ordered != 0, "immediate IOSB must use the authoritative ordered publisher");
    assert_eq!(publication.raw_iosb, 0, "Status-first direct stores bypass completion publication ordering");
}

#[test]
fn immediate_hosted_query_never_copies_status_first_iosb_blob() {
    let publication = publication(include_str!(
        "../../../../components/ntos-executive/src/exec_file_query.rs"
    ), "query_hosted_file_information");
    assert!(publication.ordered != 0, "hosted query must publish through the ordered IOSB boundary");
    assert_eq!(publication.raw_iosb, 0,
        "inline, pending-admission failure and immediate terminal query paths must not copy a Status-first IOSB blob");
}

#[test]
fn kernel_read_query_terminal_uses_same_ordered_publication_policy() {
    let publication = publication(include_str!(
        "../../../../components/ntos-executive/src/hosted_kernel_file_read_query.rs"
    ), "invoke");
    assert!(publication.ordered != 0, "kernel read/query must acknowledge ordered Information/Status publication");
    assert_eq!(publication.raw_iosb, 0, "kernel output publication must not store terminal Status before Information");
}
