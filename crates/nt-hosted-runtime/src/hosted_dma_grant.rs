//! Select the DMA grant evidence retained for a hosted device across shared-bank refreshes.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaGrantEvidence {
    pub va: u64,
    pub len: u64,
    pub logical: u64,
}

/// `retained` is supplied only for the same physical device with a recorded root-owned PnP grant.
/// The caller authenticates that identity and continues to validate the exact PnP window before
/// admitting a SCSI reservation.
pub fn dma_grant_after_bank_refresh(
    retained: Option<DmaGrantEvidence>,
    shared: DmaGrantEvidence,
) -> DmaGrantEvidence {
    retained.unwrap_or(shared)
}

/// Select the canonical evidence when the first adapter request publishes an authenticated
/// PnP window. This keeps publication policy beside the later shared-bank refresh policy.
pub fn dma_grant_after_adapter_acquire(
    _previous: DmaGrantEvidence,
    authenticated_window: DmaGrantEvidence,
) -> DmaGrantEvidence {
    authenticated_window
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_GRANT: DmaGrantEvidence = DmaGrantEvidence {
        va: 0x4000,
        len: 0x2000,
        logical: 0x8000,
    };

    #[test]
    fn root_owned_grant_survives_a_cleared_or_foreign_lane_bank() {
        let foreign = DmaGrantEvidence {
            va: 0x9000,
            len: 0x1000,
            logical: 0xa000,
        };
        assert_eq!(
            dma_grant_after_bank_refresh(Some(ROOT_GRANT), DmaGrantEvidence::default()),
            ROOT_GRANT
        );
        assert_eq!(
            dma_grant_after_bank_refresh(Some(ROOT_GRANT), foreign),
            ROOT_GRANT
        );
    }

    #[test]
    fn initial_and_revoked_grants_take_the_current_bank_value() {
        assert_eq!(dma_grant_after_bank_refresh(None, ROOT_GRANT), ROOT_GRANT);
        assert_eq!(
            dma_grant_after_bank_refresh(None, DmaGrantEvidence::default()),
            DmaGrantEvidence::default()
        );
    }

    #[test]
    fn first_adapter_request_publishes_the_exact_window_before_later_bank_refresh() {
        let initial = DmaGrantEvidence::default();
        let published = dma_grant_after_adapter_acquire(initial, ROOT_GRANT);
        let foreign_bank = DmaGrantEvidence {
            va: 0x9000,
            len: 0x1000,
            logical: 0xa000,
        };
        let retained = dma_grant_after_bank_refresh(Some(published), foreign_bank);
        assert_eq!(retained, ROOT_GRANT);
    }
}
