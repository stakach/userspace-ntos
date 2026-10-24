//! ReactOS PsChangeQuantumTable selection from the admitted registry DWORD.

use nt_process::ProcessPriorityQuantumPolicy;

#[test]
fn raw_priority_separation_selects_variable_fixed_short_long_tables() {
    let cases = [
        (0x04, false, [6, 12, 18], false),
        (0x08, false, [18, 18, 18], false),
        (0x14, false, [12, 24, 36], false),
        (0x18, false, [36, 36, 36], true),
        (0x24, false, [6, 12, 18], false),
        (0x28, false, [18, 18, 18], false),
        (0x00, false, [6, 12, 18], false),
        (0x00, true, [36, 36, 36], true),
        (0x10, true, [36, 36, 36], true),
    ];
    for (raw, nt_as_system, quantums, job_classes) in cases {
        let actual = ProcessPriorityQuantumPolicy::from_priority_separation(raw, nt_as_system);
        assert_eq!(actual.foreground_quantums, quantums, "raw={raw:#x}");
        assert_eq!(actual.use_job_scheduling_classes, job_classes, "raw={raw:#x}");
    }
}

#[test]
fn separation_value_three_normalizes_to_two() {
    let actual = ProcessPriorityQuantumPolicy::from_priority_separation(0x1b, false);
    assert_eq!(actual.priority_separation, 2);
    assert_eq!(actual.foreground_quantums, [36, 36, 36]);
    assert!(actual.use_job_scheduling_classes);
}
