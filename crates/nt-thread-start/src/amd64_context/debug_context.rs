use super::{CapturedAmd64Context, CodecError, CONTEXT_AMD64};
use crate::{captured_u64, plan_amd64_debug_registers, Amd64DebugRegisterError};

pub(super) const DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
const DEBUG_OFFSET: usize = 0x48;
const NT5_DR7_MASK: u64 = 0xffff_0155;

impl CapturedAmd64Context {
    /// NT5 KeContextToKframes SET policy: sanitize all addresses, clear DR6, and mask DR7.
    /// Keep disabled slot fields rather than resynthesizing a lossy breakpoint-slot image.
    pub fn extract_legacy_debug_registers(
        &self,
        highest_user_address: u64,
    ) -> Result<Option<[u64; 6]>, CodecError> {
        self.validate_native_groups()?;
        if self.flags() & DEBUG_REGISTERS != DEBUG_REGISTERS {
            return Ok(None);
        }
        let mut debug = [0; 6];
        for (index, address) in debug[..4].iter_mut().enumerate() {
            let supplied = captured_u64(&self.bytes, (DEBUG_OFFSET + index * 8) as u64);
            *address = if supplied > highest_user_address {
                0
            } else {
                supplied
            };
        }
        debug[5] = captured_u64(&self.bytes, (DEBUG_OFFSET + 5 * 8) as u64) & NT5_DR7_MASK;
        for slot in 0..4 {
            let kind = (debug[5] >> (16 + slot * 4)) & 3;
            let length = (debug[5] >> (18 + slot * 4)) & 3;
            // The raw native debug backend does not implement CR4.DE I/O breakpoints,
            // including disabled I/O descriptors. Do not discard them as stale metadata.
            if kind == 2 {
                return Err(CodecError::UnsupportedDebugRegisters);
            }
            if debug[5] & (1 << (slot * 2)) != 0 && kind == 0 && length != 0 {
                return Err(CodecError::InvalidDebugRegisters);
            }
        }
        plan_amd64_debug_registers(
            debug[..4].try_into().unwrap(),
            debug[5],
            highest_user_address,
        )
        .map_err(|error| match error {
            Amd64DebugRegisterError::UnsupportedIoBreakpoint
            | Amd64DebugRegisterError::UnsupportedControlBits => {
                CodecError::UnsupportedDebugRegisters
            }
            _ => CodecError::InvalidDebugRegisters,
        })?;
        Ok(Some(debug))
    }

    /// Publish the requested raw hardware debug image without applying SET masks, clamping
    /// addresses, clearing DR6, or overwriting an unrequested context field.
    pub fn publish_legacy_debug_registers(&mut self, debug: &[u64; 6]) -> Result<bool, CodecError> {
        self.validate_native_groups()?;
        if self.flags() & DEBUG_REGISTERS != DEBUG_REGISTERS {
            return Ok(false);
        }
        for (index, value) in debug.iter().enumerate() {
            let offset = DEBUG_OFFSET + index * 8;
            self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
