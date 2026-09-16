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
