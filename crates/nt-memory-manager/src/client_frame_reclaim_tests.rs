const MEMORY_PROCESS: crate::MemoryLifetime =
    crate::MemoryLifetime::Process(crate::ProcessIdentity {
        pid: 1,
        generation: crate::ProcessGeneration::Hosted(1),
    });
use super::*;
use alloc::{vec, vec::Vec};

#[test]
fn indexed_cleanup_retains_every_acknowledgement_and_terminal_failure() {
    for owned in [false, true] {
        let (mut baseline, initial) = fixture(owned);
        let start = baseline
            .begin_reclaim_at_exact(0, initial, RELEASE)
            .unwrap();
        let mut successful = Io::default();
        baseline
            .cleanup_reclaim_at_exact(0, start, RELEASE, &mut successful)
            .unwrap();
        for (position, failure) in successful.calls.iter().copied().enumerate() {
            let (mut registry, initial) = fixture(owned);
            let start = registry
                .begin_reclaim_at_exact(0, initial, RELEASE)
                .unwrap();
            let mut io = Io {
                failure: Some(failure),
                ..Io::default()
            };
            registry.lookup_steps.set(0);
            assert_eq!(
                registry.cleanup_reclaim_at_exact(0, start, RELEASE, &mut io),
                Err(ClientFrameReclaimError::Backend(77))
            );
            assert_eq!(io.calls, successful.calls[..=position]);
            let retained = registry.record_at(0).unwrap();
            assert!(!retained.is_resident());
            io.calls.clear();
            let ready = registry
                .cleanup_reclaim_at_exact(0, retained, RELEASE, &mut io)
                .unwrap();
            assert_eq!(io.calls, successful.calls[position..]);
            assert_eq!(
                registry.commit_reclaim_at_exact(0, ready, RELEASE, |_| Err(19)),
                Err(ClientFrameReclaimError::Backend(19))
            );
            assert_eq!(registry.record_at(0), Some(ready));
            io.calls.clear();
            assert_eq!(
                registry.cleanup_reclaim_at_exact(0, ready, RELEASE, &mut io),
                Ok(ready)
            );
            assert!(io.calls.is_empty());
            registry
                .commit_reclaim_at_exact(0, ready, RELEASE, |_| Ok(()))
                .unwrap();
            assert_eq!(registry.lookup_steps.get(), 0);
            assert_eq!(registry.reclaiming_count(), 0);
        }
    }
}

#[test]
fn indexed_equal_caps_and_pageout_conversion_preserve_progress() {
    for owned in [false, true] {
        let mut registry = ClientFrameRegistry::new();
        registry
            .insert(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 11, 11, owned)
            .unwrap();
        let initial = registry.record_at(0).unwrap();
        let intent = if owned { PAGEOUT } else { RELEASE };
        let start = registry.begin_reclaim_at_exact(0, initial, intent).unwrap();
        let failure = if owned {
            Call::Revoke(11)
        } else {
            Call::Recycle(11)
        };
        let mut io = Io {
            failure: Some(failure),
            ..Io::default()
        };
        assert!(registry
            .cleanup_reclaim_at_exact(0, start, intent, &mut io)
            .is_err());
        let retained = registry.record_at(0).unwrap();
        let retained = if owned {
            registry
                .cancel_pageout_to_release_at_exact(0, retained)
                .unwrap()
        } else {
            retained
        };
        io.calls.clear();
        let ready = registry
            .cleanup_reclaim_at_exact(0, retained, RELEASE, &mut io)
            .unwrap();
        assert_eq!(io.calls, vec![failure]);
        assert_eq!(
            registry.cancel_pageout_to_release_at_exact(0, ready),
            Err(ClientFrameReclaimError::InvalidState)
        );
        assert_eq!(
            registry.commit_reclaim_at_exact(0, ready, PAGEOUT, |_| panic!("wrong intent")),
            Err(ClientFrameReclaimError::InvalidState)
        );
        registry
            .commit_reclaim_at_exact(0, ready, RELEASE, |_| Ok(()))
            .unwrap();
    }
}

fn assert_indexed_refusal(
    registry: &mut ClientFrameRegistry,
    index: usize,
    expected: ClientFrameRecord,
    error: ClientFrameReclaimError,
) {
    let mut io = Io::default();
    registry.lookup_steps.set(0);
    assert_eq!(
        registry.begin_reclaim_at_exact(index, expected, RELEASE),
        Err(error)
    );
    assert_eq!(
        registry.cleanup_reclaim_at_exact(index, expected, RELEASE, &mut io),
        Err(error)
    );
    assert_eq!(
        registry.cancel_pageout_to_release_at_exact(index, expected),
        Err(error)
    );
    assert_eq!(
        registry.commit_reclaim_at_exact(index, expected, RELEASE, |_| panic!("invalid witness")),
        Err(error)
    );
    assert!(io.calls.is_empty());
    assert_eq!(registry.lookup_steps.get(), 0);
}

fn retire_indexed_owner(
    registry: &mut ClientFrameRegistry,
    pi: u64,
    lifetime: crate::MemoryLifetime,
    io: &mut Io,
) -> Result<usize, ClientFrameReclaimError> {
    let mut index = 0;
    let mut removed = 0;
    while let Some(mut row) = registry.record_at(index) {
        if row.pi != pi {
            index += 1;
            continue;
        }
        if row.lifetime != lifetime {
            return Err(ClientFrameReclaimError::StaleRecord);
        }
        if row
            .reclaim_intent()
            .is_some_and(|intent| matches!(intent, ClientFrameReclaimIntent::Pageout { .. }))
        {
            row = registry.cancel_pageout_to_release_at_exact(index, row)?;
        }
        row = registry.begin_reclaim_at_exact(index, row, RELEASE)?;
        row = registry.cleanup_reclaim_at_exact(index, row, RELEASE, io)?;
        registry.commit_reclaim_at_exact(index, row, RELEASE, |_| Ok(()))?;
        removed += 1;
    }
    Ok(removed)
}

#[test]
fn mixed_owner_indexed_walk_rechecks_swap_ins_and_retains_transferred_row() {
    let mut registry = ClientFrameRegistry::new();
    for (pi, page, cap, owned) in [
        (8, 0x1000, 10, false),
        (7, 0x2000, 20, false),
        (9, 0x3000, 30, true),
        (7, 0x4000, 40, true),
        (7, 0x5000, 50, true),
        (7, 0x6000, 60, true),
    ] {
        registry
            .insert(pi, MEMORY_PROCESS, page, cap, 0, 0, 0, owned)
            .unwrap();
    }
    let unrelated = [
        registry.record_at(0).unwrap(),
        registry.record_at(2).unwrap(),
    ];
    let pending = registry.record_at(3).unwrap();
    let pending = registry
        .begin_reclaim_at_exact(3, pending, PAGEOUT)
        .unwrap();
    let mut setup = Io {
        failure: Some(Call::Revoke(40)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_at_exact(3, pending, PAGEOUT, &mut setup)
        .is_err());
    let pending = registry.record_at(3).unwrap();
    let transferred = registry.record_at(4).unwrap();
    let transfer = registry.prepare_transfer_exact(&[transferred]).unwrap();
    let held = transfer.records()[0];
    registry.lookup_steps.set(0);
    let mut io = Io::default();
    assert_eq!(
        retire_indexed_owner(&mut registry, 7, MEMORY_PROCESS, &mut io),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert_eq!(registry.lookup_steps.get(), 0);
    let remaining: Vec<_> = registry.records().copied().collect();
    assert_eq!(remaining.len(), 4);
    assert!(unrelated.iter().all(|row| remaining.contains(row)));
    assert!(remaining.contains(&held));
    assert!(remaining.contains(&pending));
    assert!(!io.calls.iter().any(|call| matches!(
        call,
        Call::Unmap(10 | 30 | 50) | Call::Delete(10 | 30 | 50) | Call::Revoke(30 | 50)
    )));
    assert_eq!(
        io.calls
            .iter()
            .filter(|call| **call == Call::Unmap(40))
            .count(),
        0
    );
    assert_eq!(
        io.calls
            .iter()
            .filter(|call| **call == Call::Revoke(40))
            .count(),
        0
    );
    registry.finish_transfer(transfer).unwrap();
    io.calls.clear();
    registry.lookup_steps.set(0);
    assert_eq!(
        retire_indexed_owner(&mut registry, 7, MEMORY_PROCESS, &mut io),
        Ok(1)
    );
    assert_eq!(registry.lookup_steps.get(), 0);
    assert_eq!(io.calls, vec![Call::Revoke(40)]);
    assert_eq!(registry.len(), 2);
    assert!(unrelated
        .iter()
        .all(|row| registry.records().any(|current| current == row)));
}

#[test]
fn mixed_owner_indexed_walk_failure_retains_exact_progress_and_stale_lifetime() {
    let (mut registry, initial) = fixture(false);
    registry
        .insert(8, MEMORY_PROCESS, 0x3000, 21, 0, 0, 0, true)
        .unwrap();
    let unrelated = registry.record_at(1).unwrap();
    let mut io = Io {
        failure: Some(Call::Recycle(11)),
        ..Io::default()
    };
    assert_eq!(
        retire_indexed_owner(&mut registry, 7, MEMORY_PROCESS, &mut io),
        Err(ClientFrameReclaimError::Backend(77))
    );
    let retained = registry.record_at(0).unwrap();
    assert_eq!(retained.record_id, initial.record_id);
    assert_eq!(registry.record_at(1), Some(unrelated));
    assert!(!retained.is_resident());
    io.calls.clear();
    assert_eq!(
        retire_indexed_owner(&mut registry, 7, MEMORY_PROCESS, &mut io),
        Ok(1)
    );
    assert_eq!(io.calls.first(), Some(&Call::Recycle(11)));
    assert_eq!(registry.record_at(0), Some(unrelated));
    let stale = crate::MemoryLifetime::Process(crate::ProcessIdentity {
        pid: 1,
        generation: crate::ProcessGeneration::Hosted(2),
    });
    registry
        .insert(7, stale, 0x4000, 31, 0, 0, 0, true)
        .unwrap();
    let row = registry.record_at(1).unwrap();
    io.calls.clear();
    assert_eq!(
        retire_indexed_owner(&mut registry, 7, MEMORY_PROCESS, &mut io),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert!(io.calls.is_empty());
    assert_eq!(registry.record_at(1), Some(row));
    assert_eq!(registry.record_at(0), Some(unrelated));
}

#[test]
fn indexed_witnesses_reject_stale_moved_reused_and_transferred_records() {
    let (mut registry, initial) = fixture(true);
    assert_indexed_refusal(
        &mut registry,
        usize::MAX,
        initial,
        ClientFrameReclaimError::StaleRecord,
    );
    registry
        .insert(8, MEMORY_PROCESS, 0x3000, 21, 0, 0, 0, true)
        .unwrap();
    let moved = registry.record_at(1).unwrap();
    registry.take_exact(initial).unwrap();
    assert_indexed_refusal(
        &mut registry,
        1,
        moved,
        ClientFrameReclaimError::StaleRecord,
    );
    assert_indexed_refusal(
        &mut registry,
        0,
        initial,
        ClientFrameReclaimError::StaleRecord,
    );
    assert_eq!(registry.record_at(0), Some(moved));
    registry.take_exact(moved).unwrap();
    registry
        .insert_at_age(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 13, true, 40)
        .unwrap();
    assert_indexed_refusal(
        &mut registry,
        0,
        initial,
        ClientFrameReclaimError::StaleRecord,
    );
    let current = registry.record_at(0).unwrap();
    let start = registry
        .begin_reclaim_at_exact(0, current, PAGEOUT)
        .unwrap();
    assert_indexed_refusal(
        &mut registry,
        0,
        current,
        ClientFrameReclaimError::StaleRecord,
    );
    let ready = registry
        .cleanup_reclaim_at_exact(0, start, PAGEOUT, &mut Io::default())
        .unwrap();
    registry
        .commit_reclaim_at_exact(0, ready, PAGEOUT, |_| Ok(()))
        .unwrap();
    registry
        .insert(7, MEMORY_PROCESS, 0x1000, 11, 0, 0, 0, true)
        .unwrap();
    let current = registry.record_at(0).unwrap();
    let transfer = registry.prepare_transfer_exact(&[current]).unwrap();
    let held = transfer.records()[0];
    assert_indexed_refusal(
        &mut registry,
        0,
        held,
        ClientFrameReclaimError::InvalidState,
    );
    assert_eq!(registry.record_at(0), Some(held));
    registry.finish_transfer(transfer).unwrap();
}

const RELEASE: ClientFrameReclaimIntent = ClientFrameReclaimIntent::Release;
const PAGEOUT: ClientFrameReclaimIntent = ClientFrameReclaimIntent::Pageout { protection: 4 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Unmap(u64),
    Delete(u64),
    Recycle(u64),
    Revoke(u64),
}

#[derive(Default)]
struct Io {
    calls: Vec<Call>,
    failure: Option<Call>,
}
impl Io {
    fn call(&mut self, call: Call) -> Result<(), u32> {
        self.calls.push(call);
        if self.failure == Some(call) {
            self.failure = None;
            Err(77)
        } else {
            Ok(())
        }
    }
}
impl ClientFrameReclaimIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.call(Call::Unmap(cap))
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.call(Call::Delete(cap))
    }
    fn recycle_empty(&mut self, cap: u64) -> Result<(), u32> {
        self.call(Call::Recycle(cap))
    }
    fn revoke(&mut self, cap: u64) -> Result<(), u32> {
        self.call(Call::Revoke(cap))
    }
}
fn fixture(owned: bool) -> (ClientFrameRegistry, ClientFrameRecord) {
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert_at_age(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 13, owned, 40)
        .unwrap();
    let row = registry.get(7, 0x1000).unwrap();
    (registry, row)
}

#[test]
fn each_failed_unmap_delete_or_recycle_retains_exact_progress_for_retry() {
    let expected = [
        Call::Unmap(11),
        Call::Delete(11),
        Call::Recycle(11),
        Call::Unmap(12),
        Call::Delete(12),
        Call::Recycle(12),
        Call::Unmap(13),
        Call::Delete(13),
        Call::Recycle(13),
    ];
    for (index, failed) in expected.iter().copied().enumerate() {
        let (mut registry, initial) = fixture(false);
        let start = registry.begin_reclaim_exact(initial, RELEASE).unwrap();
        let mut io = Io {
            failure: Some(failed),
            ..Io::default()
        };
        assert_eq!(
            registry.cleanup_reclaim_exact(start, RELEASE, &mut io),
            Err(ClientFrameReclaimError::Backend(77))
        );
        assert_eq!(io.calls, expected[..=index]);
        let retained = registry.get(7, 0x1000).unwrap();
        assert!(retained.is_reclaiming());
        assert!(!retained.is_resident());
        assert_eq!(registry.take_exact(retained), None);
        assert_eq!(registry.take(7, 0x1000), None);
        io.calls.clear();
        let ready = registry
            .cleanup_reclaim_exact(retained, RELEASE, &mut io)
            .unwrap();
        assert_eq!(io.calls, expected[index..]);
        assert!(ready.cleanup_complete());
        assert_eq!((ready.frame, ready.alias_cap, ready.source_cap), (0, 0, 0));
        io.calls.clear();
        assert_eq!(
            registry.cleanup_reclaim_exact(ready, RELEASE, &mut io),
            Ok(ready)
        );
        assert!(io.calls.is_empty());
        registry
            .commit_reclaim_exact(ready, RELEASE, |_| Ok(()))
            .unwrap();
        assert!(registry.is_process_empty(7));
        assert_eq!(registry.reclaiming_count(), 0);
    }
}

#[test]
fn deleted_caps_stay_named_until_checked_recycling_succeeds() {
    let (mut registry, initial) = fixture(false);
    let start = registry.begin_reclaim_exact(initial, RELEASE).unwrap();
    let mut io = Io {
        failure: Some(Call::Recycle(11)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_exact(start, RELEASE, &mut io)
        .is_err());
    let retained = registry.get(7, 0x1000).unwrap();
    assert_eq!(retained.frame, 11);
    assert_eq!(retained.alias_cap, 12);
    assert_eq!(retained.source_cap, 13);
    assert_eq!(retained.clone_source_cap(), None);
    assert_eq!(retained.mapped_alias(), None);
    assert!(!registry.memory_available(7, 0x1000, 1));
    io.calls.clear();
    io.failure = Some(Call::Recycle(11));
    assert!(registry
        .cleanup_reclaim_exact(retained, RELEASE, &mut io)
        .is_err());
    assert_eq!(io.calls, vec![Call::Recycle(11)]);
    assert_eq!(registry.get(7, 0x1000), Some(retained));
}

#[test]
fn equal_cap_roles_are_normalized_and_canonical_owned_frame_is_never_deleted() {
    for owns in [false, true] {
        for alias in [0, 11, 12] {
            for source in [0, 11, 12, 13] {
                let mut registry = ClientFrameRegistry::new();
                registry
                    .insert(
                        7,
                        MEMORY_PROCESS,
                        0x1000,
                        11,
                        if alias == 0 { 0 } else { 0x2000 },
                        alias,
                        source,
                        owns,
                    )
                    .unwrap();
                let start = registry
                    .begin_reclaim_exact(registry.get(7, 0x1000).unwrap(), RELEASE)
                    .unwrap();
                let mut io = Io::default();
                let ready = registry
                    .cleanup_reclaim_exact(start, RELEASE, &mut io)
                    .unwrap();
                let mut expected = Vec::new();
                let mut seen = Vec::new();
                for cap in [11, alias, source] {
                    if cap == 0 || seen.contains(&cap) {
                        continue;
                    }
                    seen.push(cap);
                    expected.push(Call::Unmap(cap));
                    if !owns || cap != 11 {
                        expected.push(Call::Delete(cap));
                        expected.push(Call::Recycle(cap));
                    }
                }
                if owns {
                    expected.push(Call::Revoke(11));
                }
                assert_eq!(
                    io.calls, expected,
                    "owns={owns} alias={alias} source={source}"
                );
                assert_eq!(ready.frame, if owns { 11 } else { 0 });
                assert_eq!(
                    (ready.alias_cap, ready.source_cap),
                    (
                        if owns && alias == 11 { 11 } else { 0 },
                        if owns && source == 11 { 11 } else { 0 }
                    )
                );
                assert!(ready.cleanup_complete());
            }
        }
    }
}

#[test]
fn equal_deleted_roles_remain_grouped_through_recycle_failure() {
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 11, 11, false)
        .unwrap();
    let start = registry
        .begin_reclaim_exact(registry.get(7, 0x1000).unwrap(), RELEASE)
        .unwrap();
    let mut io = Io {
        failure: Some(Call::Recycle(11)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_exact(start, RELEASE, &mut io)
        .is_err());
    let retained = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        (retained.frame, retained.alias_cap, retained.source_cap),
        (11, 11, 11)
    );
    io.calls.clear();
    let ready = registry
        .cleanup_reclaim_exact(retained, RELEASE, &mut io)
        .unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(11)]);
    assert_eq!((ready.frame, ready.alias_cap, ready.source_cap), (0, 0, 0));
}

#[test]
fn canonical_revoke_follows_explicit_alias_cleanup_and_is_retained_across_failure() {
    let (mut registry, initial) = fixture(true);
    let start = registry.begin_reclaim_exact(initial, RELEASE).unwrap();
    let mut io = Io {
        failure: Some(Call::Revoke(11)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_exact(start, RELEASE, &mut io)
        .is_err());
    assert_eq!(
        io.calls,
        vec![
            Call::Unmap(11),
            Call::Unmap(12),
            Call::Delete(12),
            Call::Recycle(12),
            Call::Unmap(13),
            Call::Delete(13),
            Call::Recycle(13),
            Call::Revoke(11)
        ]
    );
    let retained = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        (retained.frame, retained.alias_cap, retained.source_cap),
        (11, 0, 0)
    );
    assert!(!retained.cleanup_complete());
    io.calls.clear();
    let ready = registry
        .cleanup_reclaim_exact(retained, RELEASE, &mut io)
        .unwrap();
    assert_eq!(io.calls, vec![Call::Revoke(11)]);
    assert_eq!(
        registry.commit_reclaim_exact(ready, RELEASE, |_| Err(19)),
        Err(ClientFrameReclaimError::Backend(19))
    );
    io.calls.clear();
    registry
        .cleanup_reclaim_exact(ready, RELEASE, &mut io)
        .unwrap();
    assert!(io.calls.is_empty());
    registry
        .commit_reclaim_exact(ready, RELEASE, |record| {
            assert_eq!(record.frame, 11);
            Ok(())
        })
        .unwrap();
}

#[test]
fn incomplete_or_opposite_intent_commit_never_calls_terminal_backend() {
    let (mut registry, initial) = fixture(true);
    for row in [
        initial,
        registry.begin_reclaim_exact(initial, PAGEOUT).unwrap(),
    ] {
        assert!(registry
            .commit_reclaim_exact(row, PAGEOUT, |_| panic!("not ready"))
            .is_err());
    }
    let start = registry.get(7, 0x1000).unwrap();
    let mut io = Io::default();
    assert_eq!(
        registry.cleanup_reclaim_exact(start, RELEASE, &mut io),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert!(io.calls.is_empty());
    let ready = registry
        .cleanup_reclaim_exact(start, PAGEOUT, &mut io)
        .unwrap();
    assert_eq!(
        registry.commit_reclaim_exact(ready, RELEASE, |_| panic!("wrong intent")),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert_eq!(
        registry.commit_reclaim_exact(
            ready,
            ClientFrameReclaimIntent::Pageout { protection: 8 },
            |_| panic!("wrong protection")
        ),
        Err(ClientFrameReclaimError::InvalidState)
    );
    registry
        .commit_reclaim_exact(ready, PAGEOUT, |_| Ok(()))
        .unwrap();
}

#[test]
fn terminal_failure_preserves_ready_row_and_publication_retries_exactly() {
    let (mut registry, initial) = fixture(true);
    let mut io = Io::default();
    let start = registry.begin_reclaim_exact(initial, PAGEOUT).unwrap();
    let ready = registry
        .cleanup_reclaim_exact(start, PAGEOUT, &mut io)
        .unwrap();
    assert_eq!(
        registry.commit_reclaim_exact(ready, PAGEOUT, |_| Err(41)),
        Err(ClientFrameReclaimError::Backend(41))
    );
    assert_eq!(registry.get(7, 0x1000), Some(ready));
    assert_eq!(registry.reclaiming_count(), 1);
    assert!(!registry.memory_available(7, 0x1000, 1));
    assert_eq!(registry.take(7, 0x1000), None);
    assert_eq!(registry.take_exact(ready), None);
    io.calls.clear();
    assert_eq!(
        registry.cleanup_reclaim_exact(ready, PAGEOUT, &mut io),
        Ok(ready)
    );
    assert!(io.calls.is_empty());
    assert_eq!(
        registry.commit_reclaim_exact(ready, PAGEOUT, |row| {
            assert_eq!(row.frame, 11);
            assert_eq!(row.reclaim_intent(), Some(PAGEOUT));
            Ok(())
        }),
        Ok(ready)
    );
    assert!(registry.memory_available(7, 0x1000, 1));
    assert_eq!(registry.reclaiming_count(), 0);
    assert_eq!(
        registry.commit_reclaim_exact(ready, PAGEOUT, |_| panic!("stale completion")),
        Err(ClientFrameReclaimError::StaleRecord)
    );
}

#[test]
fn opposite_intents_are_refused_before_changing_rows_or_access_exclusions() {
    for (initial_intent, other) in [
        (RELEASE, PAGEOUT),
        (PAGEOUT, RELEASE),
        (PAGEOUT, ClientFrameReclaimIntent::Pageout { protection: 8 }),
    ] {
        let (mut registry, initial) = fixture(true);
        let start = registry
            .begin_reclaim_exact(initial, initial_intent)
            .unwrap();
        assert_eq!(
            registry.begin_reclaim_exact(start, initial_intent),
            Ok(start)
        );
        assert_eq!(
            registry.begin_reclaim_exact(start, other),
            Err(ClientFrameReclaimError::InvalidState)
        );
        assert_eq!(registry.get(7, 0x1000), Some(start));
        assert_eq!(registry.reclaiming_count(), 1);
        assert!(!registry.touch(7, 0x1000));
        assert!(!start.is_resident());
    }
}

#[test]
fn pageout_requires_a_canonical_owned_frame_without_starting_reclamation() {
    let (mut registry, initial) = fixture(false);
    assert_eq!(
        registry.begin_reclaim_exact(initial, PAGEOUT),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert_eq!(registry.get(7, 0x1000), Some(initial));
    assert_eq!(registry.reclaiming_count(), 0);
    assert!(registry.memory_available(7, 0x1000, 4096));
}

#[test]
fn terminal_teardown_conversion_preserves_every_completed_cleanup_phase() {
    let (mut registry, initial) = fixture(true);
    let start = registry.begin_reclaim_exact(initial, PAGEOUT).unwrap();
    let mut io = Io {
        failure: Some(Call::Recycle(12)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_exact(start, PAGEOUT, &mut io)
        .is_err());
    let retained = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        registry.begin_reclaim_exact(retained, RELEASE),
        Err(ClientFrameReclaimError::InvalidState)
    );
    let release = registry.cancel_pageout_to_release_exact(retained).unwrap();
    assert_eq!(release.reclaim_intent(), Some(RELEASE));
    assert_eq!(registry.reclaiming_count(), 1);
    assert!(!registry.memory_available(7, 0x1000, 4096));
    io.calls.clear();
    let ready = registry
        .cleanup_reclaim_exact(release, RELEASE, &mut io)
        .unwrap();
    assert_eq!(
        io.calls,
        vec![
            Call::Recycle(12),
            Call::Unmap(13),
            Call::Delete(13),
            Call::Recycle(13),
            Call::Revoke(11)
        ]
    );
    registry
        .commit_reclaim_exact(ready, RELEASE, |_| Ok(()))
        .unwrap();
    assert!(registry.memory_available(7, 0x1000, 4096));
}

#[test]
fn completed_pageout_can_convert_to_release_without_replaying_cleanup() {
    let (mut registry, initial) = fixture(true);
    let mut io = Io::default();
    assert_eq!(
        registry.cancel_pageout_to_release_exact(initial),
        Err(ClientFrameReclaimError::InvalidState)
    );
    let start = registry.begin_reclaim_exact(initial, PAGEOUT).unwrap();
    let ready = registry
        .cleanup_reclaim_exact(start, PAGEOUT, &mut io)
        .unwrap();
    let release = registry.cancel_pageout_to_release_exact(ready).unwrap();
    assert!(release.cleanup_complete());
    io.calls.clear();
    assert_eq!(
        registry.cleanup_reclaim_exact(release, RELEASE, &mut io),
        Ok(release)
    );
    assert!(io.calls.is_empty());
    assert_eq!(
        registry.cancel_pageout_to_release_exact(release),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert_eq!(
        registry.commit_reclaim_exact(release, PAGEOUT, |_| panic!("cancelled pageout")),
        Err(ClientFrameReclaimError::InvalidState)
    );
    registry
        .commit_reclaim_exact(release, RELEASE, |_| Ok(()))
        .unwrap();
}

#[test]
fn stale_rows_cannot_cleanup_convert_or_publish_replacement_owners() {
    let (mut registry, old) = fixture(true);
    registry.take_exact(old).unwrap();
    registry
        .insert_at_age(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 13, true, 40)
        .unwrap();
    let current = registry.get(7, 0x1000).unwrap();
    let mut io = Io::default();
    assert_eq!(
        registry.begin_reclaim_exact(old, RELEASE),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert_eq!(
        registry.cleanup_reclaim_exact(old, RELEASE, &mut io),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert_eq!(
        registry.cancel_pageout_to_release_exact(old),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert_eq!(
        registry.commit_reclaim_exact(old, RELEASE, |_| panic!("stale owner")),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert!(io.calls.is_empty());
    assert_eq!(registry.get(7, 0x1000), Some(current));
}

#[test]
fn snapshots_from_other_registries_have_no_cleanup_authority() {
    let (_, foreign) = fixture(true);
    let (mut registry, own) = fixture(true);
    let mut io = Io::default();
    assert_eq!(
        registry.begin_reclaim_exact(foreign, RELEASE),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert_eq!(
        registry.cleanup_reclaim_exact(foreign, RELEASE, &mut io),
        Err(ClientFrameReclaimError::StaleRecord)
    );
    assert_eq!(registry.get(7, 0x1000), Some(own));
    assert!(io.calls.is_empty());
}

#[test]
fn transferred_rows_refuse_both_intents_cleanup_conversion_and_publication() {
    let (mut registry, initial) = fixture(true);
    let mut io = Io::default();
    let transfer = registry.prepare_transfer_exact(&[initial]).unwrap();
    let held = transfer.records()[0];
    for intent in [RELEASE, PAGEOUT] {
        assert_eq!(
            registry.begin_reclaim_exact(held, intent),
            Err(ClientFrameReclaimError::InvalidState)
        );
        assert_eq!(
            registry.cleanup_reclaim_exact(held, intent, &mut io),
            Err(ClientFrameReclaimError::InvalidState)
        );
        assert_eq!(
            registry.commit_reclaim_exact(held, intent, |_| panic!("transferred owner")),
            Err(ClientFrameReclaimError::InvalidState)
        );
    }
    assert_eq!(
        registry.cancel_pageout_to_release_exact(held),
        Err(ClientFrameReclaimError::InvalidState)
    );
    assert!(io.calls.is_empty());
    assert_eq!(registry.reclaiming_count(), 1);
    assert!(!registry.memory_available(7, 0x1000, 1));
    registry.finish_transfer(transfer).unwrap();
    assert_eq!(registry.reclaiming_count(), 0);
    assert!(registry.memory_available(7, 0x1000, 1));
}

#[test]
fn terminal_memory_exclusions_are_half_open_process_exact_and_overflow_safe() {
    let (mut registry, initial) = fixture(true);
    assert_eq!(registry.reclaiming_count(), 0);
    assert!(!registry.memory_available(7, u64::MAX, 1));
    assert!(registry.memory_available(7, u64::MAX, 0));
    let start = registry.begin_reclaim_exact(initial, RELEASE).unwrap();
    for (base, size) in [
        (0x1000, 1),
        (0x1fff, 1),
        (0xfff, 2),
        (0, 0x3000),
        (0x1001, 0xfff),
    ] {
        assert!(!registry.memory_available(7, base, size));
        assert!(registry.memory_available(8, base, size));
    }
    for (base, size) in [(0, 0x1000), (0x2000, 4096), (0x1000, 0), (u64::MAX, 0)] {
        assert!(registry.memory_available(7, base, size));
    }
    let ready = registry
        .cleanup_reclaim_exact(start, RELEASE, &mut Io::default())
        .unwrap();
    assert!(!registry.memory_available(7, 0x1000, 1));
    registry
        .commit_reclaim_exact(ready, RELEASE, |_| Ok(()))
        .unwrap();
    assert!(registry.memory_available(7, 0x1000, 4096));
}

#[test]
fn mixed_transfer_and_reclaim_counts_survive_partial_row_removal() {
    let (mut registry, initial) = fixture(true);
    registry
        .insert(7, MEMORY_PROCESS, 0x3000, 21, 0, 0, 0, true)
        .unwrap();
    let other = registry.get(7, 0x3000).unwrap();
    let transfer = registry.prepare_transfer_exact(&[other]).unwrap();
    let start = registry.begin_reclaim_exact(initial, RELEASE).unwrap();
    assert_eq!(registry.reclaiming_count(), 2);
    assert_eq!(registry.stats().reclaiming_records, 2);
    assert!(!registry.memory_available(7, 0x1000, 1));
    assert!(!registry.memory_available(7, 0x3000, 1));
    let ready = registry
        .cleanup_reclaim_exact(start, RELEASE, &mut Io::default())
        .unwrap();
    registry
        .commit_reclaim_exact(ready, RELEASE, |_| Ok(()))
        .unwrap();
    assert_eq!(registry.reclaiming_count(), 1);
    assert!(registry.memory_available(7, 0x1000, 1));
    assert!(!registry.memory_available(7, 0x3000, 1));
    registry.finish_transfer(transfer).unwrap();
    assert_eq!(registry.reclaiming_count(), 0);
}

#[test]
fn malformed_terminal_page_bounds_fail_closed_for_the_owning_process() {
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert(7, MEMORY_PROCESS, u64::MAX, 11, 0, 0, 0, true)
        .unwrap();
    let row = registry.get(7, u64::MAX).unwrap();
    registry.begin_reclaim_exact(row, RELEASE).unwrap();
    assert!(!registry.memory_available(7, 0x1000, 1));
    assert!(registry.memory_available(8, 0x1000, 1));
}

#[test]
fn explicit_backing_can_be_frame_alias_or_source_without_deleting_the_canonical_owner() {
    for backing in [11, 12, 13] {
        let mut registry = ClientFrameRegistry::new();
        registry
            .insert_with_backing(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 13, true, backing)
            .unwrap();
        let start = registry
            .begin_reclaim_exact(registry.get(7, 0x1000).unwrap(), PAGEOUT)
            .unwrap();
        let mut io = Io::default();
        let ready = registry
            .cleanup_reclaim_exact(start, PAGEOUT, &mut io)
            .unwrap();
        let mut expected = Vec::new();
        for cap in [11, 12, 13] {
            expected.push(Call::Unmap(cap));
            if cap != backing {
                expected.push(Call::Delete(cap));
                expected.push(Call::Recycle(cap));
            }
        }
        expected.push(Call::Revoke(backing));
        assert_eq!(io.calls, expected);
        assert_eq!(ready.owned_backing_cap, backing);
        assert_eq!(ready.frame, if backing == 11 { 11 } else { 0 });
        assert_eq!(ready.alias_cap, if backing == 12 { 12 } else { 0 });
        assert_eq!(ready.source_cap, if backing == 13 { 13 } else { 0 });
        registry
            .commit_reclaim_exact(ready, PAGEOUT, |record| {
                assert_eq!(record.owned_backing_cap, backing);
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn source_alias_backing_is_kept_through_copied_frame_delete_and_recycle_failure() {
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert_with_backing(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 12, true, 12)
        .unwrap();
    let start = registry
        .begin_reclaim_exact(registry.get(7, 0x1000).unwrap(), RELEASE)
        .unwrap();
    let mut io = Io {
        failure: Some(Call::Recycle(11)),
        ..Io::default()
    };
    assert!(registry
        .cleanup_reclaim_exact(start, RELEASE, &mut io)
        .is_err());
    let retained = registry.get(7, 0x1000).unwrap();
    assert_eq!(retained.owned_backing_cap, 12);
    assert_eq!(retained.frame, 11);
    io.calls.clear();
    let ready = registry
        .cleanup_reclaim_exact(retained, RELEASE, &mut io)
        .unwrap();
    assert_eq!(
        io.calls,
        vec![Call::Recycle(11), Call::Unmap(12), Call::Revoke(12)]
    );
    assert_eq!(
        (
            ready.frame,
            ready.alias_cap,
            ready.source_cap,
            ready.owned_backing_cap
        ),
        (0, 12, 12, 12)
    );
}

#[test]
fn invalid_or_conflicting_backing_provenance_cannot_partially_publish_a_record() {
    let mut registry = ClientFrameRegistry::new();
    for (owns, backing) in [(true, 0), (false, 12), (true, 14)] {
        assert_eq!(
            registry.insert_with_backing(
                7,
                MEMORY_PROCESS,
                0x1000,
                11,
                0x2000,
                12,
                13,
                owns,
                backing
            ),
            Err(crate::ClientFrameInsertError::InvalidRecord)
        );
        assert!(registry.is_empty());
    }
    registry
        .insert_at_age_with_backing(7, MEMORY_PROCESS, 0x1000, 11, 0x2000, 12, 13, true, 40, 12)
        .unwrap();
    let before = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        registry.insert_at_age_with_backing(7, MEMORY_PROCESS, 0x1000, 11, 0, 0, 0, true, 999, 11),
        Err(crate::ClientFrameInsertError::ConflictingOwnership)
    );
    assert_eq!(registry.get(7, 0x1000), Some(before));
    assert_eq!(
        registry.insert_at_age_with_backing(7, MEMORY_PROCESS, 0x1000, 11, 0, 0, 0, true, 40, 12),
        Ok(crate::ClientFrameInsert::Updated)
    );
    assert_eq!(registry.get(7, 0x1000), Some(before));
}
