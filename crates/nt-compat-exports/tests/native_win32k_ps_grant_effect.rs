//! Ps body grants may have retained mapping effects before returning an error.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");

#[test]
fn ps_grant_reports_no_effect_only_before_the_first_mapping_attempt() {
    let body = SOURCE
        .split("unsafe fn grant_win32k_client_ps_bodies(")
        .nth(1)
        .expect("the shared-page Ps grant boundary")
        .split("fn win32k_dispatch_client_identity(")
        .next()
        .unwrap();
    let mapping = body.find("grant_published_body(").expect("the retained Ps mapping attempt");
    let preflight = &body[..mapping];
    let uncertain = body.find("effect = SharedPageReservationEffect::Uncertain")
        .expect("the mapping attempt must make failure uncertain");
    let applied = body.find("effect = SharedPageReservationEffect::Applied")
        .expect("a successful grant must be reported as applied");

    assert!(preflight.contains("SharedPageReservationEffect::NoEffect"),
        "a failed authentication before mapping must certify no page effect");
    assert!(uncertain < mapping && mapping < applied,
        "failed process or thread mapping must be uncertain until success is acknowledged");
    assert!(preflight.contains("PublishedBody::Process, PublishedBody::Thread"),
        "the process body must be granted before its dependent thread body");
}
