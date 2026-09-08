use super::{
    continue_context::{CONTROL, INTEGER, INTEGER_OFFSETS},
    CapturedAmd64Context, CodecError, CONTEXT_AMD64, NT_NATIVE_CODE_SELECTOR,
};

impl CapturedAmd64Context {
    /// Publish requested legacy GPR/control/segment groups from UserContext ordering.
    /// CS/SS use the NT native ABI namespace, not the microkernel's physical GDT numbering.
    /// SEGMENTS reports NT's fixed DS/ES/FS/GS selectors; it never exposes or replaces FS/GS
    /// bases. Raw flags and all unrequested bytes, including ContextFlags, are preserved.
    pub fn publish_legacy_registers(&mut self, registers: &[u64; 20]) -> Result<bool, CodecError> {
        self.validate_native_groups()?;
        let flags = self.flags();
        if flags & CONTROL == CONTROL {
            self.bytes[0xf8..0x100].copy_from_slice(&registers[0].to_le_bytes());
            self.bytes[0x98..0xa0].copy_from_slice(&registers[1].to_le_bytes());
            self.bytes[0x44..0x48].copy_from_slice(&(registers[2] as u32).to_le_bytes());
            self.bytes[0x38..0x3a].copy_from_slice(&NT_NATIVE_CODE_SELECTOR.to_le_bytes());
            self.bytes[0x42..0x44].copy_from_slice(&0x2bu16.to_le_bytes());
        }
        if flags & (CONTEXT_AMD64 | 4) == (CONTEXT_AMD64 | 4) {
            for (offset, selector) in [(0x3a, 0x2bu16), (0x3c, 0x2b), (0x3e, 0x53), (0x40, 0x2b)] {
                self.bytes[offset..offset + 2].copy_from_slice(&selector.to_le_bytes());
            }
        }
        if flags & INTEGER == INTEGER {
            for (offset, value) in INTEGER_OFFSETS.into_iter().zip(&registers[3..18]) {
                let offset = offset as usize;
                self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(flags & 7 != 0)
    }
}
