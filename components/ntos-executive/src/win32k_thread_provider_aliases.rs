//! Claim-only integration for provider mappings of a protected pending thread.
use super::*;
use nt_user_host::provider_alias_bank::thread_journal::ThreadProviderAliasJournal;
use nt_user_host::thread_resources::ThreadMemoryLayout;
use nt_user_host::thread_rollback::ThreadRollbackId;

#[derive(Debug)]
pub(crate) struct ThreadProviderAliasCleanup {
    journal: ThreadProviderAliasJournal,
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
            .map(|journal| Self { journal })
            .map_err(error_status)
    }

    pub(crate) fn root_capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.journal.original_root_caps()
    }

    pub(crate) unsafe fn revalidate(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let bank = (&*core::ptr::addr_of!(BANK))
            .as_ref()
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        self.journal.revalidate(id, bank).map_err(error_status)?;
        for capability in self.journal.original_capabilities() {
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

    /// All disjoint journal validation precedes this allocation-free claim. Native destructive
    /// retirement is intentionally absent until complete backing/temporary ownership is retained.
    pub(crate) unsafe fn claim(&self, id: ThreadRollbackId) -> Result<(), u32> {
        let _borrow = Borrow::acquire().map_err(error_status)?;
        let bank = (&mut *core::ptr::addr_of_mut!(BANK))
            .as_mut()
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        self.journal.claim(id, bank).map_err(error_status)
    }
}
