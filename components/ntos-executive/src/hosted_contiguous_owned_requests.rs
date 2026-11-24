//! Per-call receipts for a contiguous source mapping returned at its existing provider VA.
//! The broker holds its allocation lock while calling this state machine. No PageMap effect is
//! made by these calls, so an acknowledged unmap retires only the request, not the allocation.

use nt_hosted_runtime::{
    ContiguousRamOwner, ContiguousRamPublishedMapping, MmioRequest, MmioRequestBacking,
    MmioRequestError, MmioRequestLedger, MmioRequestOwner,
};

pub(super) struct HostedContiguousOwnedRequests {
    ledger: MmioRequestLedger,
}

impl HostedContiguousOwnedRequests {
    pub(super) const fn new() -> Self {
        Self {
            ledger: MmioRequestLedger::new(),
        }
    }

    pub(super) fn map(
        &mut self,
        owner: ContiguousRamOwner,
        child: u64,
        published: ContiguousRamPublishedMapping,
        physical: u64,
        length: u64,
        cache: u32,
    ) -> Result<u64, MmioRequestError> {
        let (request, address) = MmioRequest::from_contiguous_published(
            owner, child, published, physical, length, cache,
        )
        .ok_or(MmioRequestError::InvalidRequest)?;
        let receipt = self.ledger.prepare(request)?;
        if let Err(error) = self.ledger.complete(
            receipt,
            address,
            MmioRequestBacking::ContiguousOwned { child },
        ) {
            // No native effect occurred. The prepared row is safe to discard.
            let _ = self.ledger.cancel_prepared(receipt);
            return Err(error);
        }
        Ok(address)
    }

    pub(super) fn unmap(
        &mut self,
        owner: ContiguousRamOwner,
        child: u64,
        address: u64,
        length: u64,
    ) -> Result<(), MmioRequestError> {
        let authority = MmioRequestOwner::contiguous_owned(owner, child);
        let (receipt, backing) = self.ledger.begin_unmap(authority, address, length)?;
        if backing != (MmioRequestBacking::ContiguousOwned { child }) {
            let _ = self.ledger.mark_unmap_uncertain(receipt);
            return Err(MmioRequestError::InvalidReceipt);
        }
        self.ledger.acknowledge_unmap(receipt)
    }

    pub(super) fn has_source_rows(&self, owner: ContiguousRamOwner, child: u64) -> bool {
        self.ledger.has_contiguous_source_rows(owner, child)
    }
}
