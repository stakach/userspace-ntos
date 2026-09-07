//! Read-only external alias coverage for a protected thread construction.
use super::*;
use nt_memory_manager::alias_transition::AliasTransitionSnapshot;
use nt_user_host::thread_resources::ThreadMemoryLayout;

#[derive(Debug)]
pub(crate) struct ThreadAliasSnapshot {
    pi: u64,
    layout: ThreadMemoryLayout,
    entries: Vec<(u64, AliasTransitionSnapshot)>,
}

impl ThreadAliasSnapshot {
    /// Pending access exclusions must already prevent alias admission for this geometry.
    /// Actual alias ownership stays in MAPPINGS; this snapshot never authorizes independent delete.
    pub(crate) unsafe fn capture(pi: u64, layout: ThreadMemoryLayout) -> Result<Self, u32> {
        let mut entries = Vec::new();
        if W32_ATTACHED_PI.load(Ordering::Acquire) == pi {
            let mappings = &*core::ptr::addr_of!(MAPPINGS);
            let selected = mappings
                .iter()
                .filter(|mapping| layout.overlaps(mapping.page, 4096));
            entries
                .try_reserve(selected.clone().count())
                .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
            for mapping in selected {
                if entries.iter().any(|(page, _)| *page == mapping.page) {
                    return Err(nt_process::STATUS_INVALID_PARAMETER);
                }
                entries.push((mapping.page, mapping.alias.snapshot()));
            }
        }
        Ok(Self {
            pi,
            layout,
            entries,
        })
    }

    pub(crate) fn capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .flat_map(|(_, snapshot)| snapshot.capabilities())
    }

    /// No allocation, repair, remap, detach or replacement of the original snapshot.
    pub(crate) unsafe fn revalidate(&self) -> Result<(), u32> {
        let attached = W32_ATTACHED_PI.load(Ordering::Acquire) == self.pi;
        let mappings = &*core::ptr::addr_of!(MAPPINGS);
        let selected = mappings
            .iter()
            .filter(|mapping| attached && self.layout.overlaps(mapping.page, 4096));
        if selected.clone().count() != self.entries.len()
            || self.entries.iter().any(|(page, snapshot)| {
                selected
                    .clone()
                    .filter(|mapping| {
                        *page == mapping.page && *snapshot == mapping.alias.snapshot()
                    })
                    .count()
                    != 1
            })
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        // A selected capability must not also be owned by another mapping, even outside this
        // thread's geometry. Candidate and retiring slots participate in this check too.
        for cap in self.capabilities() {
            let occurrences = mappings
                .iter()
                .flat_map(|mapping| mapping.alias.snapshot().capabilities())
                .filter(|&other| other == cap)
                .count();
            if occurrences != 1 {
                return Err(nt_process::STATUS_INVALID_PARAMETER);
            }
        }
        Ok(())
    }
}
