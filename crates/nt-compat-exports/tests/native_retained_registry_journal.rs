use syn::{visit::Visit, Block, Expr, ImplItem, Item, Stmt};

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap()
}

fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .find_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == name => Some(method),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native registry method {name}"))
}

#[derive(Default)]
struct Facts {
    retained_query: bool,
    refused: bool,
    success: bool,
    continued: bool,
    zero_dirty: bool,
    methods: Vec<String>,
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.retained_query |= call.method == "retained_value_journal";
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if let Some(value) = &expression.expr {
            match &**value {
                Expr::Path(path) => {
                    let name = &path.path.segments.last().unwrap().ident;
                    self.refused |= name == "STATUS_UNSUCCESSFUL";
                    self.success |= name == "STATUS_SUCCESS";
                }
                Expr::Lit(literal) => {
                    if let syn::Lit::Int(value) = &literal.lit {
                        self.refused |= value
                            .base10_parse::<u32>()
                            .is_ok_and(|status| status & 0x8000_0000 != 0);
                    }
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_return(self, expression);
    }

    fn visit_expr_continue(&mut self, expression: &'ast syn::ExprContinue) {
        self.continued = true;
        syn::visit::visit_expr_continue(self, expression);
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        fn dirty_name(expression: &Expr) -> bool {
            matches!(expression, Expr::Path(path)
                if path.path.is_ident("dirty") || path.path.is_ident("dirty_cells"))
        }
        fn zero(expression: &Expr) -> bool {
            matches!(expression, Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(0))))
        }
        self.zero_dirty |= matches!(expression.op, syn::BinOp::Eq(_))
            && ((dirty_name(&expression.left) && zero(&expression.right))
                || (zero(&expression.left) && dirty_name(&expression.right)));
        syn::visit::visit_expr_binary(self, expression);
    }
}

fn facts(statement: &Stmt) -> Facts {
    let mut result = Facts::default();
    result.visit_stmt(statement);
    result
}

fn retained_refusal(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::If(guard), _) = statement else {
        return false;
    };
    let mut condition = Facts::default();
    condition.visit_expr(&guard.cond);
    let mut refusal = Facts::default();
    refusal.visit_block(&guard.then_branch);
    condition.retained_query && refusal.refused && !refusal.success
}

fn assert_zero_dirty_ack_guarded(name: &str, skip: bool) {
    let file = source();
    let method = method(&file, name);
    struct Audit<'a> {
        name: &'a str,
        skip: bool,
        found: usize,
    }
    impl<'ast> Visit<'ast> for Audit<'_> {
        fn visit_block(&mut self, block: &'ast Block) {
            for (index, statement) in block.stmts.iter().enumerate() {
                let Stmt::Expr(Expr::If(branch), _) = statement else {
                    continue;
                };
                let mut condition = Facts::default();
                condition.visit_expr(&branch.cond);
                let mut body = Facts::default();
                body.visit_block(&branch.then_branch);
                let early_ack = if self.skip {
                    body.continued
                } else {
                    body.success
                };
                if condition.zero_dirty && early_ack {
                    self.found += 1;
                    assert!(
                        block.stmts[..index].iter().any(retained_refusal),
                        "{} must refuse retained journal ownership before zero-dirty {}",
                        self.name,
                        if self.skip {
                            "checkpoint skipping"
                        } else {
                            "success"
                        },
                    );
                }
            }
            syn::visit::visit_block(self, block);
        }
    }
    let mut audit = Audit {
        name,
        skip,
        found: 0,
    };
    audit.visit_block(&method.block);
    assert!(
        audit.found != 0,
        "{name} must audit its real zero-dirty path"
    );
}

#[test]
fn dynamic_unload_retains_uncertain_journal_before_mount_and_slot_release() {
    let file = source();
    let unload = method(&file, "nt_unload_key_ex");
    let guard =
        unload.block.stmts.iter().position(retained_refusal).expect(
            "dynamic unload must refuse an uncertain entered journal before dropping its hive",
        );
    for effect in ["remove", "fetch_and", "unmount"] {
        let position = unload
            .block
            .stmts
            .iter()
            .position(|statement| {
                facts(statement)
                    .methods
                    .iter()
                    .any(|method| method == effect)
            })
            .unwrap_or_else(|| panic!("dynamic unload must audit its actual {effect} effect"));
        assert!(
            guard < position,
            "journal refusal must precede dynamic unload {effect}"
        );
    }
}

#[test]
fn boot_checkpoint_zero_dirty_success_retains_uncertain_journal() {
    assert_zero_dirty_ack_guarded("checkpoint_non_system_boot_mutable_hive", false);
}

#[test]
fn headroom_checkpoint_zero_dirty_success_retains_uncertain_journal() {
    assert_zero_dirty_ack_guarded(
        "checkpoint_non_system_boot_mutable_hive_preserving_headroom",
        false,
    );
}

#[test]
fn dynamic_checkpoint_zero_dirty_success_retains_uncertain_journal() {
    assert_zero_dirty_ack_guarded("checkpoint_dynamic_mutable_hive", false);
}

#[test]
fn boot_quiesce_zero_dirty_skip_retains_uncertain_journal() {
    assert_zero_dirty_ack_guarded(
        "checkpoint_dirty_boot_mutable_hives_preserving_headroom",
        true,
    );
}
