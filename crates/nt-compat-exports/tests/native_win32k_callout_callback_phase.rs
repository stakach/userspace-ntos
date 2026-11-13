//! A native user callback can suspend process or thread initialization before Win32k
//! publishes its process and thread objects. The resume must retain that exact phase.

#[test]
fn callback_resume_retains_exact_initialization_phase() {
    let native = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    assert!(native.contains("enum Win32kCalloutPhase"));
    assert!(native.contains("ProcessInitialize") && native.contains("ThreadInitialize"));
    assert!(native.contains("struct Win32kCalloutPhaseRecord"));
    assert!(native.contains("activation: ProviderStackEventActivation"));
    assert!(native.contains("callout_phase: Option<Win32kCalloutPhaseRecord>"));
    assert!(native.contains("active_provider_stack_event_activation() == Some(phase.activation)"));
    assert!(native.contains("process_ctx_generation(process_index) != context.generation"));
    assert!(native.contains("thread_ctx_generation(thread_index) != context.generation"));
    assert!(native.contains("if w32thread != 0 {\n        write_volatile(w32thread as *mut u64, ethread);"));
    assert!(native.contains("Win32kCalloutPhase::ProcessInitialize"));
    assert!(native.contains("Win32kCalloutPhase::ThreadInitialize"));
}
