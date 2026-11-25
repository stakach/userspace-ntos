//! Select the DMA grant evidence retained for a hosted device across shared-bank refreshes.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaGrantEvidence {
    pub va: u64,
    pub len: u64,
    pub logical: u64,
}

/// `retained` is supplied only for the same physical device and a live, root-owned PnP grant.
/// The caller authenticates that identity and continues to validate the exact PnP window before
/// admitting a SCSI reservation.
pub fn dma_grant_after_bank_refresh(
    _retained: Option<DmaGrantEvidence>,
    shared: DmaGrantEvidence,
) -> DmaGrantEvidence {
    shared
}
