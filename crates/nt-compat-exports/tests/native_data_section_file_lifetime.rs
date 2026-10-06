use std::path::PathBuf;
use syn::parse::Parser;
use syn::visit::Visit;

#[test]
fn local_data_section_creation_retains_admission_in_the_common_work_owner() {
    let file = source("section_metadata_work.rs");
    let body = function(&file, "submit_local_data");
    let mut calls = Calls::default();
    calls.visit_block(&body);
    assert!(calls.0.iter().any(|call| call == "retain_work"));
    for forbidden in ["reserve", "mount_id_for_live_device", "capture_native_section_source"] {
        assert!(!calls.0.iter().any(|call| call == forbidden), "local work must not fabricate provider admission via {forbidden}");
    }
    let work = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "Work" => Some(item),
        _ => None,
    }).unwrap();
    assert!(work.fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "data_admission")),
        "the Work owns captured Section subject and namespace refs across waits");
}

#[test]
fn committed_data_section_copyout_faults_do_not_abort_or_replay_publication() {
    let file = source("section_metadata_work.rs");
    let body = function(&file, "copy_data_section_output");
    let mut calls = Calls::default();
    calls.visit_block(&body);
    assert!(calls.0.iter().any(|call| call == "process_memory_write_checked"));
    for forbidden in ["publish", "abort", "close_native_table_handle"] {
        assert!(!calls.0.iter().any(|call| call == forbidden), "a committed DATA copy must not repeat or withdraw {forbidden}");
    }
    struct Policy { fault: bool, retry: bool, retained: bool }
    impl<'ast> Visit<'ast> for Policy {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            for segment in &path.path.segments {
                self.fault |= segment.ident == "UserFault";
                self.retry |= segment.ident == "Retry";
                self.retained |= segment.ident == "Indeterminate";
            }
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_path(&mut self, path: &'ast syn::Path) {
            for segment in &path.segments {
                self.fault |= segment.ident == "UserFault";
                self.retry |= segment.ident == "Retry";
            }
            syn::visit::visit_path(self, path);
        }
    }
    let mut policy = Policy { fault: false, retry: false, retained: false };
    policy.visit_block(&body);
    assert!(policy.fault && policy.retry && policy.retained);
}

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some((*item.block).clone()),
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item.block.clone()),
                _ => None,
            }),
            _ => None,
        })
        .expect("actual native implementation")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if let Ok(expressions) =
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(item.tokens.clone())
        {
            for expression in &expressions {
                let mut nested = Calls::default();
                nested.visit_expr(expression);
                self.0.extend(nested.0);
            }
        }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(
                path.path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls.0
}

#[test]
fn data_section_reservation_owns_a_durable_scope_before_retained_effects() {
    let block = function(
        &source("exec_section_create.rs"),
        "reserve_generic_data_section",
    );
    let guard = block
        .stmts
        .iter()
        .position(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            let syn::Pat::Ident(binding) = &local.pat else {
                return false;
            };
            if binding.ident != "_durable" {
                return false;
            }
            let Some(init) = &local.init else {
                return false;
            };
            let syn::Expr::Call(call) = &*init.expr else {
                return false;
            };
            let syn::Expr::Path(path) = &*call.func else {
                return false;
            };
            let name = path
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            matches!(
                name.as_str(),
                "allocator::enter_durable" | "crate::allocator::enter_durable"
            )
        })
        .expect("a function-owned durable scope must outlive all Section reservations");
    for (position, statement) in block.stmts.iter().enumerate() {
        let mut effects = Calls::default();
        effects.visit_stmt(statement);
        if effects.0.iter().any(|call| {
            call == "local_section_file::reserve_disk_source"
                || call == "crate::hosted_routed_section_capture::reserve"
                || call == "reserve_native_section_handle"
                || call == "create"
        }) {
            assert!(guard < position,
                "backing owners, invisible handles and persistent Section tables need durable storage");
        }
    }
}

#[test]
fn disk_data_section_reserves_a_real_file_pin_before_section_effects_and_binds_exactly() {
    let calls = calls(&function(
        &source("exec_section_create.rs"),
        "reserve_generic_data_section",
    ));
    let position = |name: &str| {
        calls
            .iter()
            .position(|call| call == name)
            .unwrap_or_else(|| panic!("missing actual {name} boundary"))
    };
    assert!(
        position("local_section_file::reserve_disk_source") < position("create"),
        "immutable FAT coordinates cannot substitute for retaining the opened File body"
    );
    assert!(position("section_identity") < position("local_section_file::bind"));
    assert!(
        position("local_section_file::bind") < position("bind_handle"),
        "the File owner must be attached to the exact Section incarnation before publication"
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "local_section_file::cancel_unbound"),
        "failed Section admission must explicitly settle its reserved File pin"
    );
}

#[test]
fn data_pagein_validates_the_retained_local_source_before_cached_or_new_frame_admission() {
    let calls = calls(&function(
        &source("service_section_pagein.rs"),
        "service_generic_section_frame",
    ));
    let validate = calls
        .iter()
        .position(|call| call == "local_section_file::validate_bound")
        .expect("local backing lease must match the exact Section identity");
    let cached = calls.iter().position(|call| call == "page_frame").unwrap();
    assert!(
        validate < cached,
        "a stale local source cannot acquire cached or fresh Section backing authority"
    );
}

#[test]
fn readonly_table_reset_refuses_to_discard_retained_data_sources() {
    let file = source("main.rs");
    let block = file
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            let syn::Type::Path(owner) = &*item.self_ty else {
                return None;
            };
            if !owner.path.is_ident("ExecReadOnlyFileOpens") {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "reset" => Some(&item.block),
                _ => None,
            })
        })
        .expect("actual readonly File table reset");
    let calls = calls(block);
    let fence = calls
        .iter()
        .position(|call| call.ends_with("local_section_file::data_sources_empty"))
        .expect("reset must refuse to overwrite retained DATA File generations");
    let clear = calls.iter().position(|call| call == "clear").unwrap();
    assert!(fence < clear);
}

#[test]
fn disk_backing_retirement_releases_the_bound_file_pin_instead_of_acknowledging_nothing() {
    let file = source("service_section_retirement.rs");
    let block = function(&file, "release_backing");
    struct DiskArm(bool);
    impl<'ast> Visit<'ast> for DiskArm {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            struct Disk(bool);
            impl<'ast> Visit<'ast> for Disk {
                fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
                    self.0 |= pattern.ident == "GENERIC_SECTION_BACKING_DISK";
                    syn::visit::visit_pat_ident(self, pattern);
                }
                fn visit_path(&mut self, path: &'ast syn::Path) {
                    self.0 |= path
                        .segments
                        .last()
                        .is_some_and(|part| part.ident == "GENERIC_SECTION_BACKING_DISK");
                    syn::visit::visit_path(self, path);
                }
            }
            let mut disk = Disk(false);
            disk.visit_pat(&arm.pat);
            if disk.0 {
                let mut actual = Calls::default();
                actual.visit_expr(&arm.body);
                assert!(
                    actual
                        .0
                        .iter()
                        .any(|call| call == "local_section_file::release_bound"),
                    "Disk retirement cannot ACK without releasing its exact retained File body"
                );
                self.0 = true;
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut disk = DiskArm(false);
    disk.visit_block(&block);
    assert!(
        disk.0,
        "actual Disk backing retirement branch must remain covered"
    );
}
