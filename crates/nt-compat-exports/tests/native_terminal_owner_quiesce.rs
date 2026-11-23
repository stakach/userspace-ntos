//! A process-local terminal fault must not end the shared service loop while another
//! hosted process can still make progress. The LSA readiness signal says nothing about
//! the runnable state of those other owners (#432).

use std::collections::BTreeMap;
use syn::visit::{self, Visit};

const SOURCES: &[&str] = &[
    include_str!("../../../components/ntos-executive/src/executor/flow.rs"),
    include_str!("../../../components/ntos-executive/src/executor/syscall_tail.rs"),
    include_str!("../../../components/ntos-executive/src/executor/exceptions.rs"),
    include_str!("../../../components/ntos-executive/src/executor/vm_fault.rs"),
];

const TERMINAL_REASONS: &[&str] = &[
    "crash-all-live-parked",
    "all-live-waiting",
    "callback-bad-resume",
    "winlogon-post-logon-fault",
    "winlogon-post-logon-syscall",
];

fn direct_exit_reason(body: &syn::Block) -> Option<String> {
    body.stmts.iter().find_map(|stmt| {
        let syn::Stmt::Expr(syn::Expr::MethodCall(call), _) = stmt else {
            return None;
        };
        if call.method != "record" {
            return None;
        }
        let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::ByteStr(reason),
            ..
        })) = call.args.first()
        else {
            return None;
        };
        String::from_utf8(reason.value()).ok()
    })
}

#[derive(Default)]
struct Names(Vec<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.0
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        visit::visit_expr_path(self, path);
    }
}

#[derive(Default)]
struct TerminalExits(BTreeMap<String, usize>);

impl<'ast> Visit<'ast> for TerminalExits {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        if let Some(reason) = direct_exit_reason(&branch.then_branch) {
            assert_ne!(
                reason, "winlogon-main-crash",
                "a winlogon fault must be contained before the shared loop can quiesce"
            );
            if TERMINAL_REASONS.contains(&reason.as_str()) {
                let mut condition = Names::default();
                condition.visit_expr(&branch.cond);
                assert!(
                    condition.0.iter().any(|name| name == "live_top_badges"),
                    "{reason}: terminal exit needs the live owner census"
                );
                assert!(
                    !condition
                        .0
                        .iter()
                        .any(|name| name == "LSA_RPC_SERVER_ACTIVE_SIGNALLED"),
                    "{reason}: LSA readiness does not retire another runnable process"
                );
                *self.0.entry(reason).or_default() += 1;
            }
        }
        visit::visit_expr_if(self, branch);
    }
}

#[test]
fn terminal_faults_quiesce_only_after_the_live_owner_census_is_empty() {
    let mut exits = TerminalExits::default();
    for source in SOURCES {
        exits.visit_file(&syn::parse_file(source).expect("native executor source parses"));
    }
    for reason in TERMINAL_REASONS {
        assert_eq!(
            exits.0.get(*reason),
            Some(&1),
            "missing terminal path {reason}"
        );
    }
}
