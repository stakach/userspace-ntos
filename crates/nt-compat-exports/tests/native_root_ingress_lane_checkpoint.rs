//! A retained selected root Call must enter its own lane and park the original root Reply.

const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_ingress_owner.rs");
const CONTINUATION: &str = include_str!("../../../components/ntos-executive/src/component_continuation.rs");
const RESUME: &str = include_str!("../../../components/ntos-executive/src/component_resume.rs");

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).expect("native function");
    let body = &source[start..];
    let open = body.find('{').unwrap();
    let mut depth = 0usize;
    for (index, byte) in body.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { return &body[..=index] } }
            _ => {}
        }
    }
    panic!("unclosed function")
}

#[test]
fn bound_root_child_admits_once_and_park_retries_without_readmission() {
    assert!(CONTINUATION.contains("RootIngress(nt_user_host::root_ingress_handoff::RootIngressHandoffTicket)"));
    let admit = function(OWNER, "admit_bound_root_ingress");
    for required in ["with_bound_root_ingress_scope", "admit_root_ingress_owned",
        "ComponentNativeContinuation::RootIngress(ticket)", "AdmittedUnparked"] {
        assert!(admit.contains(required), "missing lane step: {required}");
    }
    let park = function(OWNER, "park_admitted_root_reply");
    for required in ["root_reply_authority_is_live", "prepare_exact_hosted",
        "try_commit", "Bundle::Parked"] {
        assert!(park.contains(required), "missing exact park step: {required}");
    }
    assert!(!park.contains("admit_root_ingress_owned"));
    assert!(function(RESUME, "eligible").contains("ComponentNativeContinuation::RootIngress(_) => false"));
}
