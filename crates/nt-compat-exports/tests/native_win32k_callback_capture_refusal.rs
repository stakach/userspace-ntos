//! A refused labelled provider Call during NtCallbackReturn keeps its exact callback and Reply.

const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");

#[test]
fn callback_resume_retains_refused_pump_before_classifying_return() {
    let resume = GLUE
        .split_once("unsafe fn resume_suspended_user_callback_component(")
        .and_then(|(_, body)| body.split_once("\n}\n").map(|(body, _)| body))
        .expect("callback resume implementation");
    let pump = resume.find("component_pump_resume_user_callback(&channel)")
        .expect("native callback pump");
    let refusal = resume.find("provider_wait_capture_refusal.is_some()")
        .expect("typed capture refusal checked immediately on return");
    let classify = resume.find("capture_win32k_dispatch_return(")
        .expect("normal callback classification");
    assert!(pump < refusal && refusal < classify,
        "a refused Call must be retained before callback completion effects");
    assert!(resume.contains("retain_callback_resume_refusal("),
        "the callback frame, channel and returned pump need durable ownership");
    assert!(!resume.contains("panic!(\"callback resume violated execution-lane ownership\")"),
        "refused capture must not freeze the whole executive");

    assert!(GLUE.contains("CallbackResumeBank<")
        && GLUE.contains("reserve_callback_resume(active_frame)")
        && GLUE.contains("reserve_callback_resume(frame)")
        && GLUE.contains("transfer_popped_callback_resume(claim, completed_frame)")
        && GLUE.contains("transfer_popped_callback_resume(claim, cancelled_frame)")
        && GLUE.contains("transfer_popped_callback_resume(claim, popped)")
        && GLUE.contains("CompletedUserCallback::CaptureRefused"),
        "the active callback must reserve ownership, then transfer its popped frame and typed refusal");
    assert!(GLUE.contains("CALLBACK_RESUME_OFFERED")
        && GLUE.contains("current_reply_cap")
        && GLUE.contains("provider_reply_cap")
        && GLUE.contains("retain_callback_outer_reply("),
        "a refused pure row must still retain the observed pump and both Reply lifetimes");
}
