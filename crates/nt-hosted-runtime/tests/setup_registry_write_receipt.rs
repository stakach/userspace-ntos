use nt_hosted_runtime::{
    AckedSetupWrite, BatchDurableRange, SetupOwnerIdentity, SetupValueName,
    SetupWriteCandidate, SetupWriteStorage,
};

const SETUP: SetupOwnerIdentity = SetupOwnerIdentity {
    process_index: 13,
    pid: 228,
    generation: 8,
};
const OTHER: SetupOwnerIdentity = SetupOwnerIdentity {
    process_index: 14,
    pid: 236,
    generation: 9,
};
const PATH: &str = r"\registry\machine\system\setup";

fn candidate(owner: SetupOwnerIdentity, name: &str, value: &[u8]) -> Option<SetupWriteCandidate> {
    SetupWriteCandidate::capture(SETUP, owner, PATH, name, 4, value)
}

#[test]
fn captures_only_exact_setup_child_system_setup_dwords() {
    let zero = 0u32.to_le_bytes();
    let progress = candidate(SETUP, "SystemSetupInProgress", &zero).unwrap();
    assert_eq!(progress.name(), SetupValueName::SystemSetupInProgress);
    assert_eq!(progress.value(), 0);
    assert_eq!(progress.owner(), SETUP);
    assert_eq!(candidate(OTHER, "SetupType", &zero), None);
    assert_eq!(SetupWriteCandidate::capture(
        SETUP, SETUP, r"\registry\machine\system\setup\child", "SetupType", 4, &zero,
    ), None);
    assert_eq!(SetupWriteCandidate::capture(
        SETUP, SETUP, r"\registry\machine\software\setup", "SetupType", 4, &zero,
    ), None);
    assert_eq!(SetupWriteCandidate::capture(
        SETUP, SETUP, PATH, "SetupType", 1, &zero,
    ), None);
    assert_eq!(candidate(SETUP, "SetupType", &zero[..3]), None);
    assert_eq!(candidate(SETUP, "Unrelated", &zero), None);
    assert_eq!(candidate(SETUP, "setuptype", &zero).unwrap().name(), SetupValueName::SetupType);
}

#[test]
fn cm_ack_is_not_a_durable_batch_receipt() {
    let zero = 0u32.to_le_bytes();
    let candidate = candidate(SETUP, "SetupType", &zero).unwrap();
    let acked = AckedSetupWrite::new(candidate, 6529, SetupWriteStorage::Batch {
        epoch: 7,
        cm_mount: 42,
    });
    assert!(!acked.covered_by_batch(BatchDurableRange {
        epoch: 7, cm_mount: 42, previous: 6528, target: 6528,
    }));
    assert!(!acked.covered_by_batch(BatchDurableRange {
        epoch: 8, cm_mount: 42, previous: 6528, target: 6530,
    }));
    assert!(!acked.covered_by_batch(BatchDurableRange {
        epoch: 7, cm_mount: 43, previous: 6528, target: 6530,
    }));
    assert!(acked.covered_by_batch(BatchDurableRange {
        epoch: 7, cm_mount: 42, previous: 6528, target: 6530,
    }));
    assert!(!AckedSetupWrite::new(candidate, 6529, SetupWriteStorage::PerRow)
        .covered_by_batch(BatchDurableRange {
            epoch: 7, cm_mount: 42, previous: 6528, target: 6530,
        }));
}

#[test]
fn unrelated_writes_skip_the_live_setup_selector() {
    use core::cell::Cell;
    let calls = Cell::new(0);
    let select = || { calls.set(calls.get() + 1); Some(SETUP) };
    let zero = 0u32.to_le_bytes();
    assert_eq!(SetupWriteCandidate::capture_lazy(
        SETUP, r"\registry\machine\system\other", "SetupType", 4, &zero, select,
    ), None);
    assert_eq!(SetupWriteCandidate::capture_lazy(
        SETUP, PATH, "Other", 4, &zero, select,
    ), None);
    assert_eq!(SetupWriteCandidate::capture_lazy(
        SETUP, PATH, "SetupType", 1, &zero, select,
    ), None);
    assert_eq!(SetupWriteCandidate::capture_lazy(
        SETUP, PATH, "SetupType", 4, &zero[..3], select,
    ), None);
    assert_eq!(calls.get(), 0);
    assert!(SetupWriteCandidate::capture_lazy(
        SETUP, PATH, "SetupType", 4, &zero, select,
    ).is_some());
    assert_eq!(calls.get(), 1);
}
