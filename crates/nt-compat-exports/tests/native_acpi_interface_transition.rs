//! Retained ACPI interface registration must keep a progressing CM mutation schedulable.

#[test]
fn retained_provider_mutation_reschedules_after_a_progressing_bounded_sweep() {
    let work = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let pump = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");

    assert!(work.contains("pub(crate) unsafe fn redrive_provider() -> bool"));
    assert!(work.contains("let previous_phase = phase_progress_fingerprint(&work.phase)"));
    assert!(work.contains("immediate_progress = previous_phase != phase_progress_fingerprint(&work.phase)"));
    assert!(work.contains("if !completed && immediate_progress"));
    assert!(pump.contains("let progressed = crate::registry_mutation_work::redrive_provider()"));
    assert!(pump.contains("if progressed && crate::registry_mutation_work::wake_due("));
    assert!(pump.contains("continue;"));
}

#[test]
fn same_phase_cm_exchange_progress_cannot_park_a_retained_provider() {
    let work = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    assert!(work.contains("fn phase_progress_fingerprint(phase: &Phase) -> PhaseProgressFingerprint"));
    assert!(work.contains("attempt.server_nonce()"));
    assert!(work.contains("attempt.outcome_status()"));
    assert!(work.contains("attempt.is_acknowledged()"));
    assert!(work.contains("preparation.uploaded_len()"));
    assert!(work.contains("preparation.collected_len()"));
    assert!(work.contains("let previous_phase = phase_progress_fingerprint(&work.phase)"));
    assert!(work.contains("immediate_progress = previous_phase != phase_progress_fingerprint(&work.phase)"));
}
