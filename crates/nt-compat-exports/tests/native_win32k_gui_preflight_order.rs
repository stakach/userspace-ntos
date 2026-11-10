//! A native GUI Call must resolve its dispatch identity before touching the shared ARG frame.

const SERVICE: &str = include_str!(
    "../../../components/ntos-executive/src/service_sec_image.rs"
);

#[test]
fn gui_dispatch_identity_is_preflighted_after_nested_credentials_and_before_arg_staging() {
    let gui = SERVICE
        .split_once("} else if m0 >= win32k_subsystem::WIN32K_SERVICE_BASE")
        .expect("root GUI arm")
        .1
        .split_once("// SSNs absent from the registered native table")
        .expect("end of root GUI arm")
        .0;
    let credentials = gui.find("winlogon_credential_injection_route(")
        .expect("nested credential prelude");
    let peb = gui.find("let Some(dispatch_peb_mirror) = hosted_peb_mirror_for_pi(pi)")
        .expect("dispatch PEB mirror preflight");
    let client = gui.find("let dispatch_client = win32k_client_context_for_thread(")
        .expect("exact dispatch client");
    let arg = gui.find("let arg = win32k_subsystem::WIN32K_ARG_VADDR;")
        .expect("first shared ARG write");
    assert!(credentials < peb && peb < client && client < arg,
        "a missing dispatch identity must reject before shared ARG staging");
    assert!(gui[peb..client].contains("reject_hosted_ingress!()"),
        "a missing PEB mirror must retain the rejection path before ARG staging");
    assert_eq!(gui.matches("let Some(dispatch_peb_mirror) = hosted_peb_mirror_for_pi(pi)").count(), 1);
    assert_eq!(gui.matches("let dispatch_client = win32k_client_context_for_thread(").count(), 1);
}
