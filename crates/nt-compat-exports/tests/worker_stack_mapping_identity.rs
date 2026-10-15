//! Constructor-owned stacks must retain the target mapping separately from physical backing.
use syn::visit::Visit;

fn native_source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/main.rs");
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls<'a>(Vec<&'a syn::ExprCall>);

impl<'a> Visit<'a> for Calls<'a> {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        self.0.push(call);
        syn::visit::visit_expr_call(self, call);
    }
}

fn named_call(call: &syn::ExprCall, name: &str) -> bool {
    matches!(&*call.func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|part| part.ident == name))
}

fn is_name(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
}

fn indexed_field(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Index(index)
        if matches!(&*index.expr, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(member) if member == name)
                && is_name(&field.base, "resources"))
            && is_name(&index.index, "index"))
}

#[test]
fn native_worker_stack_registry_records_the_actual_target_mapping_and_separate_backing() {
    let file = native_source();
    let constructor = function(&file, "spawn_hosted_thread_mechanism");
    let mut calls = Calls::default();
    calls.visit_block(&constructor.block);
    let publication = calls.0.iter().copied().find(|call| {
        (named_call(call, "csrss_frame_put_at_cap_source_backing")
            || named_call(call, "csrss_frame_put_with_source"))
            && call.args.get(2).is_some_and(|arg| is_name(arg, "page"))
    });
    let publication = publication.expect(
        "worker stack publication must retain the mapped target cap separately from its owned backing; csrss_frame_put(..., f) makes resident retry map the owner cap",
    );
    assert!(is_name(&publication.args[3], "target_cap"));
    if named_call(publication, "csrss_frame_put_with_source") {
        assert_eq!(publication.args.len(), 5);
        assert!(is_name(&publication.args[4], "f"));
        let mut helper = Calls::default();
        helper.visit_block(&function(&file, "csrss_frame_put_with_source").block);
        let forwarding = helper
            .0
            .iter()
            .find(|call| named_call(call, "csrss_frame_put_at_cap_source_backing"))
            .expect("existing helper must retain the precise mapped-cap/backing split");
        assert!(is_name(&forwarding.args[3], "fr"));
        assert!(is_name(&forwarding.args[6], "source_cap"));
        assert!(matches!(&forwarding.args[7], syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Bool(value) if value.value)));
        assert!(is_name(&forwarding.args[8], "source_cap"));
    } else {
        assert_eq!(publication.args.len(), 9);
        assert!(is_name(&publication.args[6], "f"));
        assert!(matches!(&publication.args[7], syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Bool(value) if value.value)));
        assert!(is_name(&publication.args[8], "f"));
    }
    assert!(
        !calls.0.iter().any(|call| {
            named_call(call, "csrss_frame_put")
                && call.args.get(2).is_some_and(|arg| is_name(arg, "page"))
        }),
        "do not retain the old owner-as-mapping stack publication"
    );
}

#[test]
fn worker_stack_map_refusal_exits_before_resident_registry_publication() {
    let file = native_source();
    let constructor = function(&file, "spawn_hosted_thread_mechanism");
    struct StackLoop<'a>(Option<&'a syn::Block>);
    impl<'a> Visit<'a> for StackLoop<'a> {
        fn visit_expr_for_loop(&mut self, loop_: &'a syn::ExprForLoop) {
            let mut calls = Calls::default();
            calls.visit_block(&loop_.body);
            if calls.0.iter().any(|call| {
                named_call(call, "page_map_r")
                    && call
                        .args
                        .first()
                        .is_some_and(|arg| is_name(arg, "target_cap"))
            }) {
                self.0 = Some(&loop_.body);
            }
            syn::visit::visit_expr_for_loop(self, loop_);
        }
    }
    let mut stack = StackLoop(None);
    stack.visit_block(&constructor.block);
    let body = stack.0.expect("actual constructor-owned stack loop");
    let publication = body
        .stmts
        .iter()
        .position(|statement| {
            let mut calls = Calls::default();
            calls.visit_stmt(statement);
            calls.0.iter().any(|call| {
                [
                    "csrss_frame_put",
                    "csrss_frame_put_with_source",
                    "csrss_frame_put_at_cap_source_backing",
                ]
                .iter()
                .any(|name| named_call(call, name))
            })
        })
        .expect("actual stack registry publication");
    let checked = body.stmts[..publication].iter().any(|statement| {
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { return false; };
        let syn::Expr::Binary(condition) = &*branch.cond else { return false; };
        let refuses_target = matches!(condition.op, syn::BinOp::Ne(_))
            && is_name(&condition.left, "target_map")
            && matches!(&*condition.right, syn::Expr::Lit(value)
                if matches!(&value.lit, syn::Lit::Int(number) if matches!(number.base10_parse::<u64>(), Ok(0))));
        refuses_target && branch.then_branch.stmts.iter().any(|statement| {
            matches!(statement, syn::Stmt::Expr(syn::Expr::Return(_), _))
        })
    });
    assert!(checked, "failed target PageMap must retain construction ownership and return before recording a resident stack mapping");
}

#[test]
fn legacy_stack_release_removes_target_mapping_before_releasing_original_backing() {
    let file = native_source();
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "release_hosted_thread_resources").block);
    let position = |name: &str, field: &str, argument: usize| {
        calls
            .0
            .iter()
            .position(|call| {
                named_call(call, name)
                    && call
                        .args
                        .get(argument)
                        .is_some_and(|arg| indexed_field(arg, field))
            })
            .unwrap_or_else(|| panic!("missing {name} for exact {field}"))
    };
    let take = position("take_registered_thread_page", "stack_owner", 2);
    let target = position("recycle_mapped_cap", "stack_target", 0);
    let mirror = position("recycle_mapped_cap", "stack_mirror", 0);
    let backing = position("release_unmapped_owned_thread_frame", "stack_owner", 0);
    assert!(take < target && target < backing && mirror < backing);

    struct OwnerExclusion(bool);
    impl<'a> Visit<'a> for OwnerExclusion {
        fn visit_expr_if(&mut self, branch: &'a syn::ExprIf) {
            struct Different(bool);
            impl<'a> Visit<'a> for Different {
                fn visit_expr_binary(&mut self, expression: &'a syn::ExprBinary) {
                    self.0 |= matches!(expression.op, syn::BinOp::Ne(_))
                        && is_name(&expression.left, "source_cap")
                        && is_name(&expression.right, "owner");
                    syn::visit::visit_expr_binary(self, expression);
                }
            }
            let mut condition = Different(false);
            condition.visit_expr(&branch.cond);
            let mut body = Calls::default();
            body.visit_block(&branch.then_branch);
            self.0 |= condition.0
                && body.0.iter().any(|call| {
                    named_call(call, "recycle_plain_cap")
                        && call
                            .args
                            .first()
                            .is_some_and(|arg| is_name(arg, "source_cap"))
                });
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut exclusion = OwnerExclusion(false);
    exclusion.visit_block(&function(&file, "take_registered_thread_page").block);
    assert!(
        exclusion.0,
        "registry source==backing must not be deleted as an extra alias"
    );
}

#[test]
fn mapped_stack_registry_transfer_preserves_one_backing_owner_and_exact_row_comparison() {
    use nt_memory_manager::{
        ClientFrameRegistry, MemoryLifetime, ProcessGeneration, ProcessIdentity,
    };
    use nt_user_host::thread_registry::{ThreadRegistryError, ThreadRegistrySnapshot};
    use nt_user_host::thread_resources::{ThreadMemoryLayout, ThreadMemoryResources};
    use nt_user_host::thread_rollback::ThreadRollbackResourceKind;

    let layout = ThreadMemoryLayout::new(0x10000, 1, 0x12000, 0x13000, 0x16000).unwrap();
    let mut resources = ThreadMemoryResources::<1>::new(27, layout).unwrap();
    resources.stack_owner[0] = 10;
    resources.stack_target[0] = 11;
    resources.stack_mirror[0] = 12;
    let lifetime = MemoryLifetime::Process(ProcessIdentity {
        pid: 300,
        generation: ProcessGeneration::Hosted(19),
    });
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert_with_backing(27, lifetime, 0x10000, 11, 0, 0, 10, true, 10)
        .unwrap();
    let snapshot =
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[0x10000]).unwrap();
    let owners: Vec<_> = snapshot
        .rollback_resources()
        .iter()
        .filter(|resource| resource.kind == ThreadRollbackResourceKind::Frame)
        .map(|resource| resource.cap)
        .collect();
    let aliases: Vec<_> = snapshot
        .rollback_resources()
        .iter()
        .filter(|resource| resource.kind == ThreadRollbackResourceKind::Alias)
        .map(|resource| resource.cap)
        .collect();
    assert_eq!(owners, [10]);
    assert_eq!(aliases, [11, 12]);
    assert_eq!(snapshot.records()[0].frame, 11);
    assert_eq!(snapshot.records()[0].owned_backing_cap, 10);

    // A changed registry alias must invalidate cleanup even when PI/page/frame/backing match.
    registry
        .insert_with_backing(27, lifetime, 0x10000, 11, 0x20000, 13, 10, true, 10)
        .unwrap();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::StaleRecord { page: 0x10000 })
    ));
    let current = registry.get(27, 0x10000).unwrap();
    assert!(current.is_resident());
    assert_eq!(current.alias_cap, 13);

    let snapshot =
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[0x10000]).unwrap();
    let transfer = snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.get(27, 0x10000).is_none());
}
