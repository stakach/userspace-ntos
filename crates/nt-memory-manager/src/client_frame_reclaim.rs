//! Allocation-free exact registry reclamation, shared by physical release and pageout.
use super::{ClientFrameRecord, ClientFrameRegistry};

const FRAME: u8 = 1;
const ALIAS: u8 = 2;
const SOURCE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameReclaimIntent {
    Release,
    Pageout { protection: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameReclaimError {
    StaleRecord,
    InvalidState,
    Backend(u32),
}

pub trait ClientFrameReclaimIo {
    fn unmap(&mut self, cap: u64) -> Result<(), u32>;
    /// Delete only. An empty slot remains exclusively owned until checked recycling succeeds.
    fn delete(&mut self, cap: u64) -> Result<(), u32>;
    fn recycle_empty(&mut self, cap: u64) -> Result<(), u32>;
    /// Revoke remaining descendants only after explicit aliases are retired. Never applied to a
    /// borrowed canonical frame; external journals must already have acknowledged their aliases.
    fn revoke(&mut self, cap: u64) -> Result<(), u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReclaimState {
    intent: ClientFrameReclaimIntent,
    unmapped: u8,
    deleted: u8,
    revoked: bool,
    complete: bool,
}

impl ClientFrameRecord {
    pub fn reclaim_intent(self) -> Option<ClientFrameReclaimIntent> {
        self.cleanup.map(|state| state.intent)
    }

    pub fn cleanup_complete(self) -> bool {
        self.cleanup.is_some_and(|state| state.complete)
    }

    fn roles(self, cap: u64) -> u8 {
        if cap == 0 {
            return 0;
        }
        u8::from(self.frame == cap) * FRAME
            | u8::from(self.alias_cap == cap) * ALIAS
            | u8::from(self.source_cap == cap) * SOURCE
    }

    fn clear_roles(&mut self, cap: u64) {
        let mut cleared = 0;
        if self.frame == cap {
            self.frame = 0;
            cleared |= FRAME;
        }
        if self.alias_cap == cap {
            self.alias_cap = 0;
            self.alias = 0;
            cleared |= ALIAS;
        }
        if self.source_cap == cap {
            self.source_cap = 0;
            cleared |= SOURCE;
        }
        let state = self.cleanup.as_mut().expect("reclamation owns progress");
        state.unmapped &= !cleared;
        state.deleted &= !cleared;
    }
}

impl ClientFrameRegistry {
    fn reclaim_index(&self, expected: ClientFrameRecord) -> Result<usize, ClientFrameReclaimError> {
        let index = self
            .index_for(expected.pi, expected.page)
            .ok_or(ClientFrameReclaimError::StaleRecord)?;
        if self.records[index] != expected {
            return Err(ClientFrameReclaimError::StaleRecord);
        }
        if expected.transfer_id.is_some() {
            return Err(ClientFrameReclaimError::InvalidState);
        }
        Ok(index)
    }

    /// Close resident access before the first backend operation. The existing record identity and
    /// complete snapshot, rather than a reusable key/cap tuple, authorize every subsequent step.
    pub fn begin_reclaim_exact(
        &mut self,
        expected: ClientFrameRecord,
        intent: ClientFrameReclaimIntent,
    ) -> Result<ClientFrameRecord, ClientFrameReclaimError> {
        let index = self.reclaim_index(expected)?;
        let row = &mut self.records[index];
        if let Some(state) = row.cleanup {
            if state.intent != intent {
                return Err(ClientFrameReclaimError::InvalidState);
            }
        } else {
            if matches!(intent, ClientFrameReclaimIntent::Pageout { .. }) && !row.owns_frame {
                return Err(ClientFrameReclaimError::InvalidState);
            }
            row.cleanup = Some(ReclaimState {
                intent,
                unmapped: 0,
                deleted: 0,
                revoked: false,
                complete: false,
            });
            self.reclaiming += 1;
        }
        Ok(*row)
    }

    /// Normalize equal role caps while retaining each successful unmap/delete acknowledgement.
    /// Source/alias role numbers survive deletion until strict recycling succeeds. The canonical
    /// owned frame is unmapped but never deleted or published by this helper, even when other roles
    /// name that same cap. The backend may not reenter or mutate this registry.
    pub fn cleanup_reclaim_exact(
        &mut self,
        expected: ClientFrameRecord,
        intent: ClientFrameReclaimIntent,
        io: &mut impl ClientFrameReclaimIo,
    ) -> Result<ClientFrameRecord, ClientFrameReclaimError> {
        let index = self.reclaim_index(expected)?;
        let row = &mut self.records[index];
        let state = row.cleanup.ok_or(ClientFrameReclaimError::InvalidState)?;
        if state.intent != intent {
            return Err(ClientFrameReclaimError::InvalidState);
        }
        if state.complete {
            return Ok(*row);
        }
        for cap in [row.frame, row.alias_cap, row.source_cap] {
            let mask = row.roles(cap);
            if mask == 0 {
                continue;
            }
            if row.cleanup.as_ref().unwrap().unmapped & mask != mask {
                io.unmap(cap).map_err(ClientFrameReclaimError::Backend)?;
                row.cleanup.as_mut().unwrap().unmapped |= mask;
            }
            if row.owned_backing_cap == cap {
                continue;
            }
            if row.cleanup.as_ref().unwrap().deleted & mask != mask {
                io.delete(cap).map_err(ClientFrameReclaimError::Backend)?;
                row.cleanup.as_mut().unwrap().deleted |= mask;
            }
            io.recycle_empty(cap)
                .map_err(ClientFrameReclaimError::Backend)?;
            row.clear_roles(cap);
        }
        if row.owned_backing_cap != 0 && !row.cleanup.as_ref().unwrap().revoked {
            io.revoke(row.owned_backing_cap)
                .map_err(ClientFrameReclaimError::Backend)?;
            row.cleanup.as_mut().unwrap().revoked = true;
        }
        row.cleanup.as_mut().unwrap().complete = true;
        Ok(*row)
    }

    /// Validate readiness before publishing a frame or committing an already-prepared pagefile
    /// transition. The callback must be failure-atomic and may not yield/reenter this registry.
    /// Success removes the exact row immediately, with no allocation or fallible step in between.
    pub fn commit_reclaim_exact(
        &mut self,
        expected: ClientFrameRecord,
        intent: ClientFrameReclaimIntent,
        terminal: impl FnOnce(ClientFrameRecord) -> Result<(), u32>,
    ) -> Result<ClientFrameRecord, ClientFrameReclaimError> {
        let index = self.reclaim_index(expected)?;
        let state = expected
            .cleanup
            .ok_or(ClientFrameReclaimError::InvalidState)?;
        if state.intent != intent || !state.complete {
            return Err(ClientFrameReclaimError::InvalidState);
        }
        terminal(expected).map_err(ClientFrameReclaimError::Backend)?;
        self.reclaiming -= 1;
        Ok(self.records.swap_remove(index))
    }

    /// Explicit terminal-VM teardown conversion, never ordinary working-set policy. The caller
    /// must cancel any prepared pagefile publication before this operation and prevent future
    /// faults/refaults. Successful cleanup acknowledgements are preserved; nothing becomes live.
    pub fn cancel_pageout_to_release_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Result<ClientFrameRecord, ClientFrameReclaimError> {
        let index = self.reclaim_index(expected)?;
        let row = &mut self.records[index];
        let state = row
            .cleanup
            .as_mut()
            .ok_or(ClientFrameReclaimError::InvalidState)?;
        if !matches!(state.intent, ClientFrameReclaimIntent::Pageout { .. }) {
            return Err(ClientFrameReclaimError::InvalidState);
        }
        state.intent = ClientFrameReclaimIntent::Release;
        Ok(*row)
    }
}

#[cfg(test)]
#[path = "client_frame_reclaim_tests.rs"]
mod tests;
