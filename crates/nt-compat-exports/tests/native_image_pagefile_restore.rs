use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn retained_pagefile_image_restore_admits_exact_available_backing_before_generic_paging() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let method = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "restore_process_pagefile_page" =>
                {
                    Some(method)
                }
                _ => None,
            }),
            _ => None,
        })
        .expect("canonical retained pagefile restoration entry");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    let sequence = calls.0;
    assert!(
        !sequence.iter().any(|name| name == "vm_ensure_private_pt"),
        "an evicted private image page is not constrained to the historical heap VA window"
    );
    let paging = sequence
        .iter()
        .position(|name| name == "ensure_process_user_page_table")
        .expect("image restoration uses the exact process-owned generic parent/leaf hierarchy");
    for admission in [
        "capture_process_identity",
        "hosted_thread_memory_access",
        "lifetime",
        "page_for",
    ] {
        let admission = sequence
            .iter()
            .position(|name| name == admission)
            .unwrap_or_else(|| {
                panic!("restore must admit exact available pagefile backing via {admission}")
            });
        assert!(
            admission < paging,
            "retained lifetime and available backing precede paging allocation effects"
        );
    }
    let begin = sequence.iter().position(|name| name == "begin").unwrap();
    assert!(
        paging < begin,
        "pagefile authority remains retained until paging admission"
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/transition_page_restoration.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let begin = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "begin" => Some(function),
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&begin.block);
    let take = calls.0.iter().position(|name| name == "take_for").unwrap();
    let advance = calls.0.iter().position(|name| name == "advance").unwrap();
    assert!(
        take < advance,
        "real transition ownership transfers before native mapping"
    );
}

#[test]
fn transition_rollback_never_discards_mapping_or_alias_cleanup_acknowledgements() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/main.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let legacy = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "vm_restore_transition_mapping" => {
            Some(function)
        }
        _ => None,
    });
    if let Some(legacy) = legacy {
        struct Discarded(Vec<String>);
        impl<'ast> Visit<'ast> for Discarded {
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if matches!(local.pat, syn::Pat::Wild(_)) {
                    if let Some(init) = &local.init {
                        let mut calls = Calls::default();
                        calls.visit_expr(&init.expr);
                        self.0.extend(calls.0.into_iter().filter(|name| {
                            matches!(name.as_str(), "page_unmap_r" | "cnode_delete_recycle_r")
                        }));
                    }
                }
                syn::visit::visit_local(self, local);
            }
        }
        let mut discarded = Discarded(Vec::new());
        discarded.visit_block(&legacy.block);
        assert!(
            discarded.0.is_empty(),
            "transition backing cannot return Available after ignored cleanup effects: {:?}",
            discarded.0
        );
    } else {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/transition_page_restoration.rs");
        let file = syn::parse_file(
            &std::fs::read_to_string(path)
                .expect("removed rollback is replaced by a retained transition owner"),
        )
        .unwrap();
        struct Owners(bool);
        impl<'ast> Visit<'ast> for Owners {
            fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
                self.0 |= path
                    .path
                    .segments
                    .iter()
                    .any(|segment| segment.ident == "TransitionPageRestoration");
                syn::visit::visit_type_path(self, path);
            }
        }
        let mut owners = Owners(false);
        owners.visit_file(&file);
        assert!(
            owners.0,
            "restoration must retain its real transition backing through rollback"
        );
    }
}

#[test]
fn retained_restoration_blocks_ordinary_vm_access_but_exact_owner_can_resume() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let file =
        syn::parse_file(&std::fs::read_to_string(root.join("hosted_thread_runtime.rs")).unwrap())
            .unwrap();
    let access = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "hosted_thread_memory_retirement_access" =>
            {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    struct Fence(bool);
    impl<'ast> Visit<'ast> for Fence {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let parts: Vec<_> = path
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect();
                self.0 |= parts.ends_with(&[
                    "transition_page_restoration".into(),
                    "memory_available".into(),
                ]) && call.args.len() == 3;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut fence = Fence(false);
    fence.visit_block(&access.block);
    assert!(
        fence.0,
        "taken transition backing remains fenced from ordinary writes, reprotection and reclaim"
    );
    let file =
        syn::parse_file(&std::fs::read_to_string(root.join("exec_handler.rs")).unwrap()).unwrap();
    let restore = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "restore_process_pagefile_page" =>
                {
                    Some(method)
                }
                _ => None,
            }),
            _ => None,
        })
        .unwrap();
    let mut sequence = Calls::default();
    sequence.visit_block(&restore.block);
    let resume = sequence.0.iter().position(|name| name == "resume").unwrap();
    let ordinary = sequence
        .0
        .iter()
        .position(|name| name == "hosted_thread_memory_access")
        .unwrap();
    assert!(
        resume < ordinary,
        "only validated exact owner resumption bypasses its retained range fence"
    );
}
