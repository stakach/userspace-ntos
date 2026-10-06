//! Winlogon's setup policy belongs to the mounted media, not to the kernel.
//! ReactOS base/system/winlogon/setup.c RunSetup consumes SYSTEM\Setup\CmdLine;
//! dll/win32/syssetup/install.c InstallLiveCD launches userinit through normal process APIs.
//! NT5 base/ntos/config implements registry queries, not caller-specific setup-state replies.

use syn::visit::Visit;

const MAIN: &str = include_str!("../../../../components/ntos-executive/src/main.rs");
const EXEC: &str = include_str!("../../../../components/ntos-executive/src/exec_handler.rs");
const GENERATOR: &str = include_str!("../../../nt-hive-core/src/bin/gen_hive.rs");

#[derive(Default)]
struct Evidence {
    calls: Vec<String>,
    strings: Vec<String>,
    value_writes: Vec<String>,
    boot_commands: Vec<String>,
}

impl<'ast> Visit<'ast> for Evidence {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        if matches!(call.method.to_string().as_str(), "set_value" | "set_dword") {
            if let Some(syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(name), ..
            })) = call.args.iter().nth(1) {
                self.value_writes.push(name.value());
                if name.value().eq_ignore_ascii_case("BootExecute") {
                    if let Some(data) = call.args.iter().nth(3) {
                        let mut value = Evidence::default();
                        value.visit_expr(data);
                        self.boot_commands.extend(value.strings);
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.strings.push(literal.value());
    }
}

fn native_evidence(source: &str) -> Evidence {
    let file = syn::parse_file(source).expect("actual production Rust must parse");
    let mut evidence = Evidence::default();
    // Top-level production functions and implementation methods only; test modules cannot
    // satisfy a guard by merely mentioning the forbidden production call in an assertion.
    for item in &file.items {
        match item {
            syn::Item::Fn(function) => evidence.visit_block(&function.block),
            syn::Item::Impl(implementation) => evidence.visit_item_impl(implementation),
            _ => {}
        }
    }
    evidence
}

#[test]
fn native_boot_does_not_convert_livecd_setup_to_installed_state() {
    let main = native_evidence(MAIN);
    assert!(
        !main.calls.iter().any(|call| call == "provision_reactos_installed_boot_state"),
        "boot must preserve the media's SetupType/SystemSetupInProgress/CmdLine; \
         forcing installed state bypasses real winlogon -> setup -mini -> userinit"
    );
    let executive = native_evidence(EXEC);
    assert!(
        !executive.calls.iter().any(|call|
            call == "seed_reactos_installed_boot_state_into_target"),
        "remove the obsolete kernel-owned installed-state mutation, not only its boot call"
    );
}

#[test]
fn registry_query_does_not_fabricate_a_setup_phase_for_lsass() {
    let executive = native_evidence(EXEC);
    assert!(
        !executive.calls.iter().any(|call| call == "should_expose_sam_setup_phase"),
        "NtQueryValueKey must return the mounted SetupType value, not a per-caller DWORD 1"
    );
    let file = syn::parse_file(EXEC).unwrap();
    for item in &file.items {
        let syn::Item::Impl(implementation) = item else { continue };
        for item in &implementation.items {
            let syn::ImplItem::Fn(function) = item else { continue };
            let mut evidence = Evidence::default();
            evidence.visit_block(&function.block);
            assert!(
                !(evidence.strings.iter().any(|value| value.eq_ignore_ascii_case("SetupType"))
                    && evidence.calls.iter().any(|call| call == "current_process_is_lsass")),
                "{} still couples media setup state to a caller's executable role",
                function.sig.ident
            );
        }
    }
}

#[test]
fn acceptance_profiles_do_not_replace_real_setup_or_shell_configuration() {
    let file = syn::parse_file(GENERATOR).unwrap();
    let builder = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "build_hive_with_configuration" => {
            Some(function)
        }
        _ => None,
    }).expect("actual hive profile builder");
    let mut evidence = Evidence::default();
    evidence.visit_block(&builder.block);
    for forbidden in ["SetupType", "SystemSetupInProgress", "CmdLine", "Shell", "Userinit"] {
        assert!(
            !evidence.value_writes.iter().any(|name| name.eq_ignore_ascii_case(forbidden)),
            "acceptance profiles must not replace media startup value {forbidden}"
        );
    }
    assert!(evidence.value_writes.iter().any(|name| name == "BootExecute"));
    for command in ["file_acceptance", "font_run_setup"] {
        assert!(evidence.boot_commands.iter().any(|value| value == command),
            "the native acceptance command {command} must remain a BootExecute fixture");
    }
}
