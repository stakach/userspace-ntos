//! Select paging bookkeeping without confusing a nested recipient with the live event owner.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyBookkeeping {
    Current,
    Live,
    Stored,
}

pub fn copy_bookkeeping(
    current_pi: usize,
    live_pi: Option<usize>,
    target_pi: usize,
    process_count: usize,
) -> Option<CopyBookkeeping> {
    if current_pi >= process_count
        || target_pi >= process_count
        || live_pi.is_some_and(|pi| pi >= process_count)
    {
        return None;
    }
    Some(if target_pi == current_pi {
        CopyBookkeeping::Current
    } else if Some(target_pi) == live_pi {
        CopyBookkeeping::Live
    } else {
        CopyBookkeeping::Stored
    })
}

pub fn live_checkpoint_matches(
    current_pi: usize,
    live_pi: usize,
    live_pml4: u64,
    stored_pml4: u64,
    live_generation: u64,
    stored_generation: Option<u64>,
) -> bool {
    current_pi == live_pi
        && live_pml4 != 0
        && live_pml4 == stored_pml4
        && stored_generation == Some(live_generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_owner_uses_current_locals() {
        assert_eq!(
            copy_bookkeeping(2, Some(2), 2, 8),
            Some(CopyBookkeeping::Current)
        );
        assert_eq!(
            copy_bookkeeping(2, Some(2), 4, 8),
            Some(CopyBookkeeping::Stored)
        );
    }

    #[test]
    fn nested_completion_returns_to_original_live_owner() {
        assert_eq!(
            copy_bookkeeping(4, Some(2), 4, 8),
            Some(CopyBookkeeping::Current)
        );
        assert_eq!(
            copy_bookkeeping(4, Some(2), 2, 8),
            Some(CopyBookkeeping::Live)
        );
        assert_eq!(
            copy_bookkeeping(4, Some(2), 6, 8),
            Some(CopyBookkeeping::Stored)
        );
        assert_eq!(
            copy_bookkeeping(6, Some(2), 2, 8),
            Some(CopyBookkeeping::Live)
        );
    }

    #[test]
    fn checkpointed_epoch_never_selects_old_live_locals() {
        assert_eq!(
            copy_bookkeeping(4, None, 2, 8),
            Some(CopyBookkeeping::Stored)
        );
        assert_eq!(
            copy_bookkeeping(2, None, 2, 8),
            Some(CopyBookkeeping::Current)
        );
        assert_eq!(
            copy_bookkeeping(2, Some(4), 4, 8),
            Some(CopyBookkeeping::Live)
        );
    }

    #[test]
    fn invalid_process_indices_are_rejected() {
        assert_eq!(copy_bookkeeping(0, None, 0, 0), None);
        assert_eq!(copy_bookkeeping(8, None, 2, 8), None);
        assert_eq!(copy_bookkeeping(2, None, 8, 8), None);
        assert_eq!(copy_bookkeeping(2, Some(8), 2, 8), None);
    }

    #[test]
    fn checkpoint_requires_restored_owner_and_same_address_space() {
        assert!(live_checkpoint_matches(2, 2, 100, 100, 1, Some(1)));
        assert!(!live_checkpoint_matches(4, 2, 100, 100, 1, Some(1)));
        assert!(!live_checkpoint_matches(2, 2, 100, 200, 1, Some(1)));
        assert!(!live_checkpoint_matches(2, 2, 100, 0, 1, Some(1)));
        assert!(!live_checkpoint_matches(2, 2, 0, 0, 1, Some(1)));
    }

    #[test]
    fn recycled_capability_does_not_revive_retired_generation() {
        assert!(!live_checkpoint_matches(2, 2, 100, 100, 1, Some(2)));
        assert!(!live_checkpoint_matches(2, 2, 100, 100, 1, None));
    }
}
