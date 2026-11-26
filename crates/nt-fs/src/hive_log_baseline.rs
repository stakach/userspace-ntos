//! Live authority for reusing an exact non-SYSTEM hive log baseline.

use crate::SnapshotPublicationState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveLogBaselineAuthority {
    Unpublished,
    AnchoredSuffix,
    FoldedSnapshot { epoch: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiveLogBaselineMismatch;

impl HiveLogBaselineAuthority {
    pub fn after_durable_fold(self, epoch: u64, prior_clean_epoch: Option<u64>,
        exact_file_and_length: bool) -> Self {
        match self {
            Self::AnchoredSuffix if exact_file_and_length => Self::FoldedSnapshot { epoch },
            Self::FoldedSnapshot { epoch: old } if exact_file_and_length
                && prior_clean_epoch == Some(old) => Self::FoldedSnapshot { epoch },
            _ => Self::Unpublished,
        }
    }

    pub fn needs_checkpoint(
        self,
        exact_file_id: bool,
        observed_len: Option<u64>,
        expected_len: u64,
        publication: &SnapshotPublicationState,
    ) -> Result<bool, HiveLogBaselineMismatch> {
        match self {
            Self::Unpublished => Ok(true),
            Self::AnchoredSuffix => {
                if !exact_file_id || observed_len.is_none_or(|len| len < expected_len) {
                    Err(HiveLogBaselineMismatch)
                } else {
                    Ok(observed_len != Some(expected_len))
                }
            }
            Self::FoldedSnapshot { epoch } => {
                // The fold made this exact sidecar part of the paired snapshot. A later
                // generic mutation or another capture removes that evidence, even if the
                // sidecar still happens to have the same length.
                Ok(!exact_file_id || observed_len != Some(expected_len)
                    || publication.is_dirty() || publication.epochs() != (epoch, epoch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folded_named_log_reuses_exact_clean_published_epoch_for_next_record() {
        let publication = SnapshotPublicationState::new();
        let a = HiveLogBaselineAuthority::AnchoredSuffix;
        let capture = publication.begin_fold_capture().unwrap();
        let epoch = capture.epoch();
        let prior = capture.prior_clean_published_epoch();
        capture.publish().unwrap();
        let b = a.after_durable_fold(epoch, prior, true);
        assert_eq!(b.needs_checkpoint(true, Some(18), 18, &publication), Ok(false),
            "record N+1 can append against durable fold B without another checkpoint");
    }

    #[test]
    fn dirty_or_crossed_fold_epoch_refuses_reuse() {
        let publication = SnapshotPublicationState::new();
        let capture = publication.begin_fold_capture().unwrap();
        let epoch = capture.epoch();
        capture.publish().unwrap();
        let baseline = HiveLogBaselineAuthority::AnchoredSuffix.after_durable_fold(epoch, Some(0), true);
        publication.mark_dirty();
        assert_eq!(baseline.needs_checkpoint(true, Some(18), 18, &publication), Ok(true));
        let next = publication.begin_dirty_capture().unwrap().unwrap();
        next.publish().unwrap();
        assert_eq!(baseline.needs_checkpoint(true, Some(18), 18, &publication), Ok(true));
    }

    #[test]
    fn wrong_identity_same_length_or_edited_length_rebaseline() {
        let publication = SnapshotPublicationState::new();
        let capture = publication.begin_fold_capture().unwrap();
        let epoch = capture.epoch();
        capture.publish().unwrap();
        let baseline = HiveLogBaselineAuthority::AnchoredSuffix.after_durable_fold(epoch, Some(0), true);
        assert_eq!(baseline.needs_checkpoint(false, Some(18), 18, &publication), Ok(true));
        assert_eq!(baseline.needs_checkpoint(true, Some(19), 18, &publication), Ok(true));
        assert_eq!(baseline.needs_checkpoint(true, Some(17), 18, &publication), Ok(true));
    }

    #[test]
    fn old_wal_suffix_keeps_identity_fail_closed() {
        let publication = SnapshotPublicationState::new();
        let baseline = HiveLogBaselineAuthority::AnchoredSuffix;
        assert_eq!(baseline.needs_checkpoint(false, Some(18), 18, &publication),
            Err(HiveLogBaselineMismatch));
        assert_eq!(baseline.needs_checkpoint(true, Some(17), 18, &publication),
            Err(HiveLogBaselineMismatch));
    }

    #[test]
    fn consecutive_clean_folds_advance_the_same_log_baseline_without_checkpoint() {
        let publication = SnapshotPublicationState::new();
        let first = publication.begin_fold_capture().unwrap();
        let epoch_a = first.epoch();
        first.publish().unwrap();
        let baseline = HiveLogBaselineAuthority::AnchoredSuffix
            .after_durable_fold(epoch_a, Some(0), true);
        let second = publication.begin_fold_capture().unwrap();
        assert_eq!(second.prior_clean_published_epoch(), Some(epoch_a));
        let epoch_b = second.epoch();
        let prior = second.prior_clean_published_epoch();
        second.publish().unwrap();
        let baseline = baseline.after_durable_fold(epoch_b, prior, true);
        assert_eq!(baseline.needs_checkpoint(true, Some(18), 18, &publication), Ok(false));
    }

    #[test]
    fn dirty_or_replaced_log_cannot_carry_across_a_later_fold() {
        let publication = SnapshotPublicationState::new();
        let first = publication.begin_fold_capture().unwrap();
        let epoch_a = first.epoch();
        first.publish().unwrap();
        let baseline = HiveLogBaselineAuthority::AnchoredSuffix
            .after_durable_fold(epoch_a, Some(0), true);
        publication.mark_dirty();
        let second = publication.begin_fold_capture().unwrap();
        assert_eq!(second.prior_clean_published_epoch(), None);
        let epoch_b = second.epoch();
        let prior = second.prior_clean_published_epoch();
        second.publish().unwrap();
        assert_eq!(baseline.after_durable_fold(epoch_b, prior, true),
            HiveLogBaselineAuthority::Unpublished);
        assert_eq!(baseline.after_durable_fold(epoch_b, Some(epoch_a), false),
            HiveLogBaselineAuthority::Unpublished);
    }
}
