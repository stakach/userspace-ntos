//! Exclusive temporary access to a canonical frame through an owned copied capability.

pub trait SectionScratchIo {
    /// Copy a frame capability. Failure must leave no caller-owned slot behind.
    fn copy_frame(&mut self, frame: u64) -> Result<u64, u32>;
    fn map_alias(&mut self, alias: u64) -> Result<(), u32>;
    /// Delete the copied capability and its mapping, then recycle only its capability slot.
    /// An already-revoked (empty) slot still needs successful ownership acknowledgement.
    fn delete_alias(&mut self, alias: u64) -> Result<(), u32>;
}

/// One serialized scratch mapping permits only one outstanding alias. Cleanup failure retains
/// that exact capability and blocks further acquisitions; no failure-path allocation is needed.
pub struct SectionScratch {
    pending_alias: Option<u64>,
}

impl SectionScratch {
    pub const fn new() -> Self {
        Self {
            pending_alias: None,
        }
    }

    pub fn drain(&mut self, io: &mut impl SectionScratchIo) -> Result<(), u32> {
        if let Some(alias) = self.pending_alias {
            io.delete_alias(alias)?;
            self.pending_alias = None;
        }
        Ok(())
    }

    /// Run the transfer only after mapping succeeds, and finish capability cleanup before success.
    /// Preserve accepted byte progress and the original I/O error when cleanup also fails.
    pub fn with_frame<I: SectionScratchIo>(
        &mut self,
        frame: u64,
        io: &mut I,
        transfer: impl FnOnce(&mut I) -> (u32, usize),
    ) -> (u32, usize) {
        if frame == 0 {
            return (crate::STATUS_INVALID_HANDLE, 0);
        }
        if let Err(status) = self.drain(io) {
            return (status, 0);
        }
        let alias = match io.copy_frame(frame) {
            Ok(0) => return (crate::STATUS_INVALID_HANDLE, 0),
            Ok(alias) => alias,
            Err(status) => return (status, 0),
        };
        self.pending_alias = Some(alias);
        let result = match io.map_alias(alias) {
            Ok(()) => transfer(io),
            Err(status) => (status, 0),
        };
        match (result, self.drain(io)) {
            ((0, bytes), Err(status)) => (status, bytes),
            (result, _) => result,
        }
    }
}

impl Default for SectionScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "section_scratch_tests.rs"]
mod tests;
