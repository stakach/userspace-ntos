//! Desktop acceptance must prove execution, not demand one implementation strategy.
//! ReactOS RegisterSystemControls installs class WndProcs (user32/controls/regcontrol.c),
//! InitFontSupport owns font discovery (ntgdi/freetype.c), and InstallLiveCD registers
//! components through syssetup. Private font injection, cache hits, particular CLSIDs and
//! later subclassing are not universal prerequisites for genuine Explorer painting.
//! These checks remove only acceptance assumptions, not the remaining operational scaffolds.

use std::collections::{BTreeMap, BTreeSet};
use syn::visit::{self, Visit};

const MAIN: &str = include_str!("../../../../components/ntos-executive/src/main.rs");

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing production gate {name}"))
}

#[derive(Default)]
struct Checks(BTreeMap<String, syn::Expr>);

impl<'ast> Visit<'ast> for Checks {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("check")) {
            if let Some(syn::Expr::Lit(literal)) = call.args.first() {
                if let syn::Lit::ByteStr(name) = &literal.lit {
                    let name = String::from_utf8(name.value()).unwrap();
                    let predicate = call.args.iter().nth(1).expect("check has a predicate");
                    assert!(
                        self.0.insert(name.clone(), predicate.clone()).is_none(),
                        "duplicate acceptance check {name}"
                    );
                }
            }
        }
        visit::visit_expr_call(self, call);
    }
}

#[derive(Default)]
struct Names(BTreeSet<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, name: &'ast syn::Ident) {
        self.0.insert(name.to_string());
    }
}

fn names(expression: &syn::Expr) -> BTreeSet<String> {
    let mut names = Names::default();
    names.visit_expr(expression);
    names.0
}

fn dependencies(function: &syn::ItemFn, predicate: &syn::Expr) -> BTreeSet<String> {
    let locals: BTreeMap<_, _> = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let syn::Pat::Ident(binding) = &local.pat else {
                return None;
            };
            Some((binding.ident.to_string(), &*local.init.as_ref()?.expr))
        })
        .collect();
    let mut result = names(predicate);
    loop {
        let mut expanded = result.clone();
        for name in &result {
            if let Some(expression) = locals.get(name) {
                expanded.extend(names(expression));
            }
        }
        if expanded == result {
            return result;
        }
        result = expanded;
    }
}

fn inspect(name: &str) -> (syn::ItemFn, Checks) {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let function = function(&file, name);
    let mut checks = Checks::default();
    checks.visit_item_fn(&function);
    (function, checks)
}

fn require(checks: &Checks, function: &syn::ItemFn, name: &str, required: &[&str]) {
    let predicate = checks
        .0
        .get(name)
        .unwrap_or_else(|| panic!("retain genuine check {name}"));
    assert!(
        !matches!(predicate, syn::Expr::Lit(literal)
        if matches!(literal.lit, syn::Lit::Bool(_))),
        "{name} must consume evidence"
    );
    let dependencies = dependencies(function, predicate);
    for required in required {
        assert!(
            dependencies.contains(*required),
            "{name} must depend on {required}"
        );
    }
}

#[test]
fn userinit_acceptance_does_not_require_private_fonts_or_session_cache_hits() {
    let (_, checks) = inspect("userinit_image_pipeline_spec");
    for forbidden in [
        "exec_userinit_system_font_seeded",
        "exec_userinit_global_cursor_reused",
        "exec_userinit_builtin_classes_reused",
    ] {
        assert!(
            !checks.0.contains_key(forbidden),
            "{forbidden} is not a genuine launch prerequisite; retain totals only as diagnostics"
        );
    }
}

#[test]
fn explorer_acceptance_does_not_require_seeded_fonts_com_class_lists_or_subclassing() {
    let (_, checks) = inspect("explorer_image_pipeline_spec");
    for forbidden in [
        "exec_userinit_explorer_system_fonts_seeded",
        "exec_explorer_shell_com_classes_served",
        "exec_explorer_wndproc_installed_by_client",
    ] {
        assert!(
            !checks.0.contains_key(forbidden),
            "{forbidden} is not universal desktop evidence; class-registered WndProcs are valid"
        );
    }
}

#[test]
fn userinit_acceptance_keeps_exact_launch_parent_and_gdi_receipts() {
    let (function, checks) = inspect("userinit_image_pipeline_spec");
    require(
        &checks,
        &function,
        "exec_userinit_process_spawned",
        &["report", "userinit", "fully_published", "main"],
    );
    require(
        &checks,
        &function,
        "exec_userinit_shell_image_attempted",
        &["report", "coherent_shell_chain"],
    );
    require(
        &checks,
        &function,
        "exec_userinit_gdi_shared_table_mapped",
        &["report", "GdiMapped"],
    );
}

#[test]
fn explorer_acceptance_keeps_exact_shell_callbacks_paint_and_framebuffer_evidence() {
    let (function, checks) = inspect("explorer_image_pipeline_spec");
    require(
        &checks,
        &function,
        "exec_explorer_process_spawned",
        &[
            "report",
            "explorer",
            "coherent_shell_chain",
            "fully_published",
            "main",
            "live",
        ],
    );
    require(
        &checks,
        &function,
        "exec_explorer_create_window_strings_captured",
        &["report", "WindowCreated"],
    );
    require(
        &checks,
        &function,
        "exec_explorer_register_window_messages_captured",
        &["report", "MessageRegistered"],
    );
    require(
        &checks,
        &function,
        "exec_explorer_user_callbacks_redirected",
        &[
            "report",
            "coherent_shell_chain",
            "CallbackCompleted",
            "CallbackFailed",
            "live",
        ],
    );
    require(
        &checks,
        &function,
        "exec_explorer_shell_chrome_painted",
        &[
            "report",
            "coherent_shell_chain",
            "BeginPaint",
            "EndPaint",
            "DirectDraw",
            "BatchFlush",
            "BatchRecords",
            "live",
            "available",
            "non_bg",
            "unique_non_bg",
        ],
    );
}
