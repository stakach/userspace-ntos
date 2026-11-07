use alloc::vec::Vec;

use super::{
    parse_small_irq, reconcile_reported_interrupt, InterruptResource, InterruptSource, LegacyIrqOverride,
    ReportedInterruptError, ReportedInterruptResource, ResolvedInterruptResource,
};

#[test]
fn small_irq_accepts_independent_trigger_and_polarity_bits() {
    for (flags, level_sensitive, active_low) in [(0x09, false, true), (0x00, true, false)] {
        let mut resources = Vec::new();
        parse_small_irq(&[0x10, 0x00, flags], 0, &mut resources).unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].interrupt, InterruptSource::LegacyIrq(4));
        assert_eq!(resources[0].level_sensitive, level_sensitive);
        assert_eq!(resources[0].active_low, active_low);
    }
}

const REPORTED: ReportedInterruptResource = ReportedInterruptResource {
    line: 4,
    level_sensitive: true,
    shared: true,
};

const LEGACY: InterruptResource = InterruptResource {
    descriptor_index: 1,
    interrupt: InterruptSource::LegacyIrq(4),
    level_sensitive: true,
    active_low: true,
    shared: true,
};

#[test]
fn exact_legacy_irq_retains_crs_electrical_mode_without_override() {
    assert_eq!(
        reconcile_reported_interrupt(&[LEGACY], REPORTED, &[]),
        Ok(ResolvedInterruptResource {
            gsi: 4,
            level_sensitive: true,
            active_low: true,
            shared: true,
        })
    );
}

#[test]
fn direct_gsi_keeps_its_own_polarity() {
    let direct = InterruptResource {
        interrupt: InterruptSource::GlobalSystemInterrupt(4),
        active_low: false,
        ..LEGACY
    };
    assert_eq!(
        reconcile_reported_interrupt(&[direct], REPORTED, &[]),
        Ok(ResolvedInterruptResource {
            gsi: 4,
            level_sensitive: true,
            active_low: false,
            shared: true,
        })
    );
}

#[test]
fn cm_trigger_sharing_and_line_must_match_exact_crs() {
    for reported in [
        ReportedInterruptResource {
            level_sensitive: false,
            ..REPORTED
        },
        ReportedInterruptResource {
            shared: false,
            ..REPORTED
        },
    ] {
        assert_eq!(
            reconcile_reported_interrupt(&[LEGACY], reported, &[]),
            Err(ReportedInterruptError::Mismatch)
        );
    }
    assert_eq!(
        reconcile_reported_interrupt(
            &[LEGACY],
            ReportedInterruptResource {
                line: 5,
                ..REPORTED
            },
            &[]
        ),
        Err(ReportedInterruptError::Missing)
    );
}

#[test]
fn duplicate_line_and_conflicting_override_fail_closed() {
    assert_eq!(
        reconcile_reported_interrupt(&[LEGACY, LEGACY], REPORTED, &[]),
        Err(ReportedInterruptError::Ambiguous)
    );
    assert_eq!(
        reconcile_reported_interrupt(
            &[LEGACY],
            REPORTED,
            &[LegacyIrqOverride {
                irq: 4,
                gsi: 20,
                level_sensitive: Some(false),
                active_low: Some(false),
            }]
        ),
        Err(ReportedInterruptError::InvalidRoute)
    );
}
