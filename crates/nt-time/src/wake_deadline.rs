/// Select a wake deadline and its source together. Input order breaks ties; missing deadlines
/// do not participate. This only observes candidates, never advances time or consumes demand.
pub fn earliest_deadline<S: Copy>(
    candidates: impl IntoIterator<Item = (Option<u64>, S)>,
) -> Option<(u64, S)> {
    candidates
        .into_iter()
        .filter_map(|(deadline, source)| deadline.map(|deadline| (deadline, source)))
        .min_by_key(|(deadline, _)| *deadline)
}

/// Select the first due owner in input order and return the clock reading used to decide.
/// Missing deadlines are not eligible owners and do not read the clock.
pub fn first_due<S>(
    candidates: impl IntoIterator<Item = (Option<u64>, S)>,
    clock: impl FnOnce() -> u64,
) -> Option<(S, u64)> {
    let mut eligible = candidates
        .into_iter()
        .filter_map(|(deadline, source)| deadline.map(|deadline| (deadline, source)))
        .peekable();
    eligible.peek()?;
    let now = clock();
    eligible.find(|(deadline, _)| *deadline <= now).map(|(_, source)| (source, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Deadline, TimeSnapshot};

    #[test]
    fn empty_and_missing_sources_do_not_invent_a_wake() {
        assert_eq!(earliest_deadline::<u8>([]), None);
        assert_eq!(earliest_deadline([(None, 7), (None, 2)]), None);
    }

    #[test]
    fn absent_retained_retry_owners_do_not_read_the_clock() {
        let mut reads = 0;
        assert_eq!(first_due::<u8>([], || { reads += 1; 100 }), None);
        assert_eq!(first_due([(None, 4), (None, 9)], || { reads += 1; 100 }), None);
        assert_eq!(reads, 0, "no eligible owner may cause an HPET read");
    }

    #[test]
    fn retained_retry_uses_one_fresh_clock_and_first_due_owner() {
        let candidates = [(None, 0), (Some(150), 1), (Some(100), 7),
            (Some(100), 3), (Some(200), 9)];
        let mut reads = 0;
        let mut now = || { reads += 1; 100 };
        assert_eq!(first_due(candidates, &mut now), Some((7, 100)));
        assert_eq!(reads, 1);
        assert_eq!(first_due(candidates, || 99), None);
        assert_eq!(first_due(candidates, || 150), Some((1, 150)));
        assert_eq!(first_due([(Some(0), 2), (Some(0), 1)], || 0), Some((2, 0)));
    }

    #[test]
    fn selects_deadline_and_identity_in_one_pass() {
        assert_eq!(
            earliest_deadline([(Some(50), 9), (None, 0), (Some(10), 8), (Some(30), 1)]),
            Some((10, 8))
        );
        assert_eq!(
            earliest_deadline([(Some(u64::MAX), 1)]),
            Some((u64::MAX, 1))
        );
        assert_eq!(
            earliest_deadline([(Some(0), 2), (Some(10), 1)]),
            Some((0, 2))
        );
    }

    #[test]
    fn ties_preserve_declared_precedence_not_source_numeric_order() {
        for count in 1..=18 {
            let candidates = (0..count).map(|index| (Some(100), 99 - index));
            assert_eq!(earliest_deadline(candidates), Some((100, 99)));
        }
        assert_eq!(
            earliest_deadline([(None, 100), (Some(10), 9), (Some(10), 1)]),
            Some((10, 9))
        );
    }

    #[test]
    fn section_retry_owner_ties_keep_existing_candidate_order() {
        // The four section retry owners will have separate census IDs. Equal deadlines
        // must retain their current order rather than choosing by numeric source ID.
        let candidates = [(Some(100), 28), (Some(100), 21),
            (Some(100), 27), (Some(100), 26)];
        assert_eq!(earliest_deadline(candidates), Some((100, 28)));
        assert_eq!(earliest_deadline(candidates.into_iter().skip(1)), Some((100, 21)));
    }

    #[test]
    fn absolute_and_relative_candidates_use_the_same_snapshot_without_consumption() {
        let relative = Deadline::Relative {
            monotonic_100ns: 150,
        };
        let absolute = Deadline::Absolute {
            system_time_100ns: 1_100,
        };
        let before = TimeSnapshot {
            monotonic_100ns: 100,
            system_time_100ns: 1_000,
            clock_generation: 0,
        };
        let after = TimeSnapshot {
            monotonic_100ns: 110,
            system_time_100ns: 1_200,
            clock_generation: 1,
        };
        let select = |now| {
            earliest_deadline([
                (relative.monotonic_target(now), "relative"),
                (absolute.monotonic_target(now), "absolute"),
                (Deadline::Infinite.monotonic_target(now), "infinite"),
            ])
        };
        assert_eq!(select(before), Some((150, "relative")));
        assert_eq!(select(before), Some((150, "relative")));
        assert_eq!(select(after), Some((110, "absolute")));
        assert!(!relative.is_due(after));
    }
}
