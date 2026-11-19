//! A completed callback's wait admission keeps every outcome instead of asserting (#336).

extern crate alloc;

#[path = "../../../components/ntos-executive/src/retained_admissions.rs"]
mod retained_admissions;

use retained_admissions::{Disposition, RetainedAdmissions, RetainedWaitAdmission as A};

#[test]
fn every_admission_outcome_is_retained() {
    let mut owner = RetainedAdmissions::new();
    assert_eq!(owner.retain(1u32, A::Accepted), Ok(Disposition::Admitted));
    assert_eq!(owner.retain(2, A::RefusedNoEffect), Ok(Disposition::RetryLater));
    assert_eq!(owner.retain(3, A::Indeterminate), Ok(Disposition::Quarantined));
    assert_eq!((owner.retrying(), owner.quarantined()), (1, 1));
}

#[test]
fn a_no_effect_refusal_is_retried_and_an_indeterminate_one_never_is() {
    let mut owner = RetainedAdmissions::new();
    owner.retain(10u32, A::RefusedNoEffect).unwrap();
    owner.retain(11, A::RefusedNoEffect).unwrap();
    owner.retain(12, A::Indeterminate).unwrap();
    let mut seen = Vec::new();
    let admitted = owner.retry(|item| {
        seen.push(*item);
        match item {
            10 => A::Accepted,
            11 => A::Indeterminate,
            _ => unreachable!("a quarantined admission is never retried"),
        }
    });
    assert_eq!(admitted, 1);
    seen.sort();
    assert_eq!(seen, [10, 11]);
    assert_eq!((owner.retrying(), owner.quarantined()), (0, 2));
    assert_eq!(owner.retry(|_| unreachable!()), 0);
}

#[test]
fn callback_wait_admissions_no_longer_assert_accepted() {
    for (file, source) in [
        ("service_sec_image.rs", include_str!("../../../components/ntos-executive/src/service_sec_image.rs")),
        ("executor/syscall.rs", include_str!("../../../components/ntos-executive/src/executor/syscall.rs")),
    ] {
        for admission in ["provider_wait_admit", "lpc_wait_admit", "receive_admit", "service_wait_admit"] {
            assert!(
                !source.contains(&format!("assert!({admission}")),
                "{file} asserts the outcome of {admission}"
            );
        }
    }
}

#[test]
fn lpc_reservation_releases_keep_the_effect_distinction() {
    for (file, source) in [
        ("service_sec_image.rs", include_str!("../../../components/ntos-executive/src/service_sec_image.rs")),
        ("component_resume_maintenance.rs", include_str!("../../../components/ntos-executive/src/component_resume_maintenance.rs")),
        ("component_resume_execute.rs", include_str!("../../../components/ntos-executive/src/component_resume_execute.rs")),
    ] {
        assert!(
            !source.contains("LPC_COMPONENT_WAITS)).cancel(reservation)"),
            "{file} discards an LPC reservation cancel result"
        );
    }
}
