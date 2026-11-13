//! Read-only selection among independently retained component work lanes.

/// A native owner must authenticate its row and primary source before reporting readiness.
/// This observation never grants authority to enter or replay the retained callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingLaneReadiness {
    Absent,
    Blocked,
    Ready,
}

/// Select one ready pending row after the last visited index, wrapping once. The caller owns
/// the cursor and must revalidate the row's exact physical identity before entering it.
pub fn next_ready_pending_lane(
    count: usize,
    after: Option<usize>,
    mut observe: impl FnMut(usize) -> PendingLaneReadiness,
) -> Option<usize> {
    if count == 0 { return None; }
    let mut index = after.map_or(0, |last| {
        let last = last % count;
        if last + 1 == count { 0 } else { last + 1 }
    });
    for _ in 0..count {
        if observe(index) == PendingLaneReadiness::Ready {
            return Some(index);
        }
        index = if index + 1 == count { 0 } else { index + 1 };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_first_owner_cannot_hide_another_ready_delete() {
        let rows = [
            PendingLaneReadiness::Blocked,
            PendingLaneReadiness::Ready,
            PendingLaneReadiness::Ready,
        ];
        assert_eq!(next_ready_pending_lane(rows.len(), None, |index| rows[index]), Some(1));
        assert_eq!(next_ready_pending_lane(rows.len(), Some(1), |index| rows[index]), Some(2));
        assert_eq!(next_ready_pending_lane(rows.len(), Some(2), |index| rows[index]), Some(1));
    }

    #[test]
    fn absent_and_empty_rows_never_create_work() {
        assert_eq!(next_ready_pending_lane(0, None, |_| PendingLaneReadiness::Ready), None);
        assert_eq!(next_ready_pending_lane(2, Some(1), |_| PendingLaneReadiness::Absent), None);
    }
}
