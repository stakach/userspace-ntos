//! Selected root import may reopen only after native proved a fully rolled-back Reply effect.

const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const EXECUTIVE: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");

fn body<'a>(source: &'a str, name: &str) -> &'a str {
    source.split_once(name).expect("function is present").1
        .split_once("\n}").expect("function ends").0
}

#[test]
fn selected_import_aborts_only_after_exact_no_effect_and_identity_checks() {
    let adapter = body(EXECUTIVE, "unsafe fn import_selected_root_child(");
    assert!(adapter.contains("HostedReplyImport::RefusedNoEffect")
        && adapter.contains("SelectedRootImportOutcome::RefusedNoEffect")
        && adapter.contains("HostedReplyImport::Retained"));

    let selected = body(HOSTED, "unsafe fn take_selected_root_hosted_with(");
    let begin = selected.find("root.pass.begin_import(").unwrap();
    let outcome = selected.find("match import(reply, &message)").unwrap();
    let proof = selected.find("attempt.after_no_effect_native_refusal()").unwrap();
    let abort = selected.find("root.pass.abort_import_before_effect(").unwrap();
    let deliver = selected.find("root.pass.deliver(").unwrap();
    assert!(begin < outcome && outcome < proof && proof < abort && abort < deliver);
    let refusal = &selected[outcome..proof];
    assert!(refusal.contains("SelectedRootImportOutcome::Retained => return Err"));
    let checks = &selected[proof..abort];
    assert!(checks.contains("root_ingress_parent_is_held(parent, admission)")
        && checks.contains("query_component_reply_binding(row.binding.tcb, reply)")
        && checks.contains("call.admission_key() != admission"));
    let reconcile = body(HOSTED, "unsafe fn reconcile_root_ingress_import_no_effect(");
    assert!(reconcile.contains("root.import_no_effect.take()")
        && reconcile.contains("root_ingress_parent_is_held(parent, admission)")
        && reconcile.contains("root.import_no_effect = Some(no_effect)"));
}
