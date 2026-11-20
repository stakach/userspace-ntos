//! The root shadow-table arm must own the shared win32k page and ARG bank before
//! staging a hosted Call. Nested prelude work must complete before that reservation.

const ROOT: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_win32k.rs");

fn ordinary_win32k_arm() -> String {
    let start = ROOT.find("pub(super) unsafe fn syscall_win32k_route(")
        .expect("ordinary hosted win32k ingress arm exists");
    let end = ROOT[start..].find("let mut handoff = admit_pending_win32k_dispatch(")
        .map(|offset| start + offset)
        .expect("pending win32k handoff follows dispatch");
    ROOT[start..end].chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn root_reserves_exact_call_before_first_shared_arg_stage() {
    let arm = ordinary_win32k_arm();
    let first_arg = arm.find("letarg=win32k_subsystem::WIN32K_ARG_VADDR;")
        .expect("root arm stages its first shared ARG buffer");
    let ticket = arm.find("mint_hosted_win32k_preentry_ticket(")
        .expect("root arm authenticates the original retained Call and Reply");
    let reserve = arm.find("win32k_shared_page_authority::reserve(")
        .expect("root arm reserves the singleton page before ARG staging");
    assert!(ticket < reserve && reserve < first_arg,
        "a Busy refusal must leave the original Call/Reply and ARG bank untouched");
}

#[test]
fn nested_prelude_and_effective_identity_precede_root_reservation() {
    let arm = ordinary_win32k_arm();
    let credential = arm.find("winlogon_credential_injection_route(")
        .expect("real credential posting can enter win32k recursively");
    let client = arm.find("letdispatch_client=win32k_client_context_for_thread(")
        .expect("root computes the exact hosted client identity");
    let effective_ssn = arm.find("SSN_WIN32_JOB_USER_HANDLE")
        .expect("handle-grant calls use their effective provider SSN");
    let revalidate = arm.find("revalidate_hosted_win32k_preentry_ticket(")
        .expect("nested prelude can change the delivered Call and must be revalidated");
    let reserve = arm.find("win32k_shared_page_authority::reserve(")
        .expect("root reserves the physical page for the effective dispatch identity");
    assert!(credential < revalidate
        && client < revalidate && effective_ssn < revalidate && revalidate < reserve,
        "nested credential calls, effective SSN and exact client must settle before page ownership");
}
