//! Retained integration for provider mappings of a protected pending thread.
use super::*;
use nt_user_host::provider_alias_bank::thread_journal::ThreadProviderAliasJournal;
use nt_user_host::thread_resources::ThreadMemoryLayout;
use nt_user_host::thread_rollback::ThreadRollbackId;

#[derive(Debug)]
pub(crate) struct ThreadProviderAliasCleanup {
    journal: ThreadProviderAliasJournal,
    layout: ThreadMemoryLayout,
}

fn error_status(error: BankError) -> u32 {
    match error {
        BankError::InsufficientResources => nt_address_space::STATUS_INSUFFICIENT_RESOURCES,
        BankError::Backend(status) => status,
        _ => nt_address_space::STATUS_INVALID_PARAMETER,
    }
}

impl ThreadProviderAliasCleanup {
    pub(crate) unsafe fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
    ) -> Result<Self, u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let _durable = allocator::enter_durable();
        let slot = &mut *core::ptr::addr_of_mut!(BANK);
        if slot.is_none() {
            *slot = Some(ProviderAliasBank::new(SEGMENT_SLOTS, SEGMENTS).map_err(error_status)?);
        }
        ThreadProviderAliasJournal::prepare(id, layout, slot.as_ref().unwrap())
            .map(|journal| Self { journal, layout })
            .map_err(error_status)
    }

    /// Immutable preclaim provenance, not current ownership after retirement begins.
    pub(crate) fn root_capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.journal.original_root_caps()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.journal.is_complete()
    }

    /// Conservative execution-gate requirement, not current cap ownership. A successfully
    /// mapped bank row normally owns only a child cap after its root scratch slot is recycled.
    /// Keep requiring quiescence through partial cleanup, even if that original cap is now gone.
    pub(crate) fn needs_quiescence(&self) -> bool {
        !self.is_complete() && self.journal.original_capabilities().next().is_some()
    }

    pub(crate) unsafe fn revalidate(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let bank = (&*core::ptr::addr_of!(BANK))
            .as_ref()
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        self.revalidate_bank(id, bank)
    }

    /// Borrow must be held. The journal first validates exact claims and remaining coverage;
    /// recycled original cap numbers are provenance, so only current rows are checked below.
    unsafe fn revalidate_bank(
        &self,
        id: ThreadRollbackId,
        bank: &ProviderAliasBank,
    ) -> Result<(), u32> {
        self.journal.revalidate(id, bank).map_err(error_status)?;
        for capability in bank.snapshots()
            .filter(|row| row.request.pi == id.identity().pi
                && self.layout.overlaps(row.request.page, 4096))
            .flat_map(|row| row.owned_capabilities())
        {
            use nt_user_host::provider_alias_bank::ProviderAliasCapability;
            match capability {
                ProviderAliasCapability::Root(cap) if segment_owns_root_cap(cap) => {
                    return Err(nt_address_space::STATUS_INVALID_PARAMETER)
                }
                ProviderAliasCapability::Child(child) if !segment_owns_child(child) => {
                    return Err(nt_address_space::STATUS_INVALID_PARAMETER)
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// All disjoint journal validation precedes this allocation-free claim.
    pub(crate) unsafe fn claim(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let bank = (&mut *core::ptr::addr_of_mut!(BANK))
            .as_mut()
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        self.journal.claim(id, bank).map_err(error_status)
    }

    /// The caller retains disjoint claims, pending-range exclusion, and the exact client VSpace
    /// owner. All execution/copy users of the selected client mappings must be quiescent; one
    /// deleted client TCB does not prove provider or sibling-thread quiescence. No component IPC
    /// or reentry is permitted. Only leaf copies retire: provider backing and permanent segment
    /// CNodes remain owned, including across failures and retries.
    pub(crate) unsafe fn retire(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let bank = (&mut *core::ptr::addr_of_mut!(BANK))
            .as_mut()
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        self.revalidate_bank(id, bank)?;
        self.journal.retire(id, bank, &mut Io).map_err(error_status)
    }
}
