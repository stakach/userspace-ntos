extern crate alloc;

use alloc::vec::Vec;

/// Owned bytes for a hosted IRP's bank callbacks. Neither bank borrows the dispatch caller.
pub(super) struct HostedIrpBanks {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl HostedIrpBanks {
    pub(super) fn new(input: &[u8], output: &[u8]) -> Option<Self> {
        let mut owned_input = Vec::new();
        owned_input.try_reserve_exact(input.len()).ok()?;
        owned_input.extend_from_slice(input);
        let mut owned_output = Vec::new();
        owned_output.try_reserve_exact(output.len()).ok()?;
        owned_output.extend_from_slice(output);
        Some(Self {
            input: owned_input,
            output: owned_output,
        })
    }

    pub(super) fn input(&self) -> &[u8] {
        &self.input
    }

    pub(super) fn output(&self) -> &[u8] {
        &self.output
    }

    pub(super) fn output_mut(&mut self) -> &mut [u8] {
        &mut self.output
    }

    pub(super) fn copy_output_to(&self, destination: &mut [u8]) {
        destination.copy_from_slice(&self.output);
    }
}
