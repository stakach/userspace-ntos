use syn::{visit::Visit, Expr, Stmt};

fn parse(source: &str) -> syn::File {
    syn::parse_file(source).expect("native storage source parses")
}

fn path_ends(expression: &Expr, name: &str) -> bool {
    matches!(expression, Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

fn plain(expression: &Expr) -> &Expr {
    match expression {
        Expr::Cast(cast) => plain(&cast.expr),
        Expr::Paren(paren) => plain(&paren.expr),
        Expr::Group(group) => plain(&group.expr),
        _ => expression,
    }
}

fn integer(expression: &Expr, expected: u64) -> bool {
    matches!(plain(expression), Expr::Lit(literal)
        if matches!(&literal.lit, syn::Lit::Int(value)
            if matches!(value.base10_parse::<u64>(), Ok(actual) if actual == expected)))
}

fn failure_mask(expression: &Expr, result: &str) -> bool {
    let Expr::Binary(comparison) = plain(expression) else {
        return false;
    };
    if !matches!(comparison.op, syn::BinOp::Ne(_)) || !integer(&comparison.right, 0) {
        return false;
    }
    let Expr::Binary(mask) = plain(&comparison.left) else {
        return false;
    };
    matches!(mask.op, syn::BinOp::BitAnd(_))
        && path_ends(plain(&mask.left), result)
        && path_ends(plain(&mask.right), "TASK_FILE_FAILURE")
}

#[derive(Default)]
struct Facts {
    calls: Vec<String>,
    paths: Vec<String>,
    propagates: bool,
    census_gate: bool,
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.calls.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(segment) = path.path.segments.last() {
            self.paths.push(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        self.propagates = true;
        syn::visit::visit_expr_try(self, expression);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        self.propagates = true;
        syn::visit::visit_expr_return(self, expression);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "then"
            && matches!(&*call.receiver, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "census"))
            && call
                .args
                .iter()
                .any(|argument| path_ends(argument, "disk_census_ticks"))
        {
            self.census_gate = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn facts(statement: &Stmt) -> Facts {
    let mut facts = Facts::default();
    facts.visit_stmt(statement);
    facts
}

fn audit_commands(file: &syn::File, transport: &str, operation: &str, sectors: &str) {
    struct Audit<'a> {
        transport: &'a str,
        operation: &'a str,
        sectors: &'a str,
        found: usize,
    }
    impl<'ast> Visit<'ast> for Audit<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            for (index, statement) in block.stmts.iter().enumerate() {
                let command = facts(statement);
                if !command.calls.iter().any(|name| name == self.transport) {
                    continue;
                }
                // Nested blocks are audited independently, not as their enclosing statement.
                let Stmt::Local(local) = statement else {
                    continue;
                };
                let Some(initializer) = &local.init else {
                    continue;
                };
                let syn::Pat::Ident(result) = &local.pat else {
                    panic!("transport result must remain available for accounting")
                };
                let result = result.ident.to_string();
                let mut direct = Facts::default();
                direct.visit_expr(&initializer.expr);
                if !direct.calls.iter().any(|name| name == self.transport) {
                    continue;
                }
                struct Transport<'a> {
                    name: &'a str,
                    call: Option<syn::ExprCall>,
                }
                impl<'ast> Visit<'ast> for Transport<'_> {
                    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                        if path_ends(&call.func, self.name) {
                            assert!(self.call.is_none(), "one transport result per boundary");
                            self.call = Some(call.clone());
                        }
                        syn::visit::visit_expr_call(self, call);
                    }
                }
                let mut transport = Transport {
                    name: self.transport,
                    call: None,
                };
                transport.visit_expr(&initializer.expr);
                let request = transport.call.unwrap();
                if self.transport == "ahci_read_sectors" {
                    assert!(
                        path_ends(plain(&request.args[4]), self.sectors),
                        "read census count must match the actual transport request"
                    );
                } else if self.transport == "ahci_write_sectors" {
                    let mut payload = Facts::default();
                    payload.visit_expr(&request.args[4]);
                    assert!(payload.paths.iter().any(|name| name == "byte_end"));
                    assert!(block.stmts[..index].iter().any(|statement| {
                        let Stmt::Local(local) = statement else { return false };
                        matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "byte_end")
                            && facts(statement).paths.iter().any(|name| name == self.sectors)
                    }), "write payload extent must derive from the recorded chunk count");
                }
                self.found += 1;
                assert!(
                    !direct.propagates,
                    "{} propagates before census publication",
                    self.transport
                );
                let gated = block.stmts[..index]
                    .iter()
                    .find_map(|statement| {
                        let Stmt::Local(local) = statement else {
                            return None;
                        };
                        let syn::Pat::Ident(binding) = &local.pat else {
                            return None;
                        };
                        facts(statement)
                            .census_gate
                            .then(|| binding.ident.to_string())
                    })
                    .expect("command timing must be gated on Fat32.census");
                let mut recorded = false;
                for subsequent in &block.stmts[index + 1..] {
                    let observation = facts(subsequent);
                    if observation
                        .calls
                        .iter()
                        .any(|name| name == "disk_census_record")
                    {
                        let Stmt::Expr(Expr::Call(call), _) = subsequent else {
                            panic!("recording must precede propagation in the command block")
                        };
                        assert_eq!(call.args.len(), 4);
                        assert!(
                            path_ends(&call.args[0], self.operation),
                            "{} must record operation {}",
                            self.transport,
                            self.operation
                        );
                        assert!(path_ends(&call.args[1], &gated), "record gated timing only");
                        if self.operation == "Barrier" {
                            assert!(integer(&call.args[2], 0), "barrier has no sector payload");
                            assert!(
                                matches!(plain(&call.args[3]), Expr::MethodCall(outcome)
                                if outcome.method == "is_err" && outcome.args.is_empty()
                                    && path_ends(plain(&outcome.receiver), &result)),
                                "barrier failure must use its own transport result"
                            );
                        } else {
                            let expected = self.sectors.parse::<u64>();
                            assert!(
                                match expected {
                                    Ok(value) => integer(&call.args[2], value),
                                    Err(_) => path_ends(plain(&call.args[2]), self.sectors),
                                },
                                "record requested sector count {}",
                                self.sectors
                            );
                            assert!(
                                failure_mask(&call.args[3], &result),
                                "failure mask must use the same transport result"
                            );
                        }
                        recorded = true;
                        break;
                    }
                    assert!(
                        !observation.propagates,
                        "{} returns before recording completion/error",
                        self.transport
                    );
                }
                assert!(
                    recorded,
                    "{} has no command census publication",
                    self.transport
                );
            }
            syn::visit::visit_block(self, block);
        }
    }
    let mut audit = Audit {
        transport,
        operation,
        sectors,
        found: 0,
    };
    audit.visit_file(file);
    assert!(
        audit.found > 0,
        "missing actual {transport} command boundary"
    );
}

#[test]
fn snapshot_reads_record_read_operation_before_error_return() {
    let file = parse(include_str!(
        "../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs"
    ));
    audit_commands(&file, "ahci_read_sectors", "Read", "chunk_sectors");
}

#[test]
fn snapshot_writes_record_write_operation_before_error_return() {
    let file = parse(include_str!(
        "../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs"
    ));
    audit_commands(&file, "ahci_write_sectors", "Write", "chunk_sectors");
}

#[test]
fn cache_barrier_records_outcome_before_error_propagation() {
    let file = parse(include_str!(
        "../../../components/ntos-executive/src/ahci_maintenance.rs"
    ));
    audit_commands(&file, "flush_owned", "Barrier", "0");
    let snapshot = parse(include_str!(
        "../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs"
    ));
    struct Delegates(bool);
    impl<'ast> Visit<'ast> for Delegates {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0 |= path
                    .path
                    .segments
                    .iter()
                    .any(|segment| segment.ident == "ahci_maintenance")
                    && path_ends(&call.func, "flush");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut delegates = Delegates(false);
    delegates.visit_file(&snapshot);
    assert!(
        delegates.0,
        "snapshot barriers must use the censused maintenance adapter"
    );
}

#[test]
fn fat_reads_account_for_task_file_failures_not_only_timeouts() {
    let file = parse(include_str!(
        "../../../components/ntos-executive/src/fs_loader.rs"
    ));
    audit_commands(&file, "ahci_read_sector", "Read", "1");
    audit_commands(&file, "ahci_read_sectors", "Read", "count");
}

#[test]
fn disabled_census_returns_before_counter_mutation() {
    let file = parse(include_str!(
        "../../../components/ntos-executive/src/fs_loader.rs"
    ));
    let recorder = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "disk_census_record" => Some(function),
            _ => None,
        })
        .expect("native census recorder");
    let first = recorder.block.stmts.first().expect("census guard");
    let Stmt::Local(local) = first else {
        panic!("census must reject absent timing before mutation")
    };
    let initializer = local.init.as_ref().expect("census guard initializer");
    assert!(path_ends(&initializer.expr, "started"));
    let (_, divergence) = initializer
        .diverge
        .as_ref()
        .expect("absent timing must return");
    let mut guard = Facts::default();
    guard.visit_expr(divergence);
    assert!(guard.propagates);
    assert!(
        guard.calls.is_empty(),
        "disabled census must not mutate storage"
    );
}
