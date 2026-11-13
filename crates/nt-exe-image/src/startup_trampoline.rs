//! Machine-code startup boundary for a hosted AMD64 executable.
//!
//! The executive owns mappings and capabilities. This module only emits the
//! Windows x64 calling sequence for loader initialization and the image entry.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupTrampolineError {
    MissingLoader,
    MissingThreadExit,
    AddressOverflow,
}

pub struct StartupTrampoline {
    bytes: [u8; 96],
    len: usize,
}

impl StartupTrampoline {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn emit(
        context: u64,
        peb: u64,
        ntdll_base: u64,
        image_base: u64,
        image_entry: u64,
        loader_rva: u64,
        thread_exit_rva: u64,
    ) -> Result<Self, StartupTrampolineError> {
        if loader_rva == 0 {
            return Err(StartupTrampolineError::MissingLoader);
        }
        if thread_exit_rva == 0 {
            return Err(StartupTrampolineError::MissingThreadExit);
        }
        let loader = ntdll_base
            .checked_add(loader_rva)
            .ok_or(StartupTrampolineError::AddressOverflow)?;
        let thread_exit = ntdll_base
            .checked_add(thread_exit_rva)
            .ok_or(StartupTrampolineError::AddressOverflow)?;
        let mut out = Self {
            bytes: [0; 96],
            len: 0,
        };
        out.push(&[0x48, 0x83, 0xEC, 0x20]); // shadow space, preserve 16-byte alignment
        out.movabs(0xB9, context); // rcx = initial CONTEXT
        out.movabs(0xBA, ntdll_base); // rdx = ntdll base
        out.push(&[0x49, 0xB8]); // r8 = image base
        out.push(&image_base.to_le_bytes());
        out.movabs(0xB8, loader);
        out.push(&[0xFF, 0xD0]); // call loader
        out.movabs(0xB9, peb); // rcx = PEB for native image entry
        out.movabs(0xB8, image_entry);
        out.push(&[0xFF, 0xD0]); // call image entry
        out.push(&[0x89, 0xC1]); // ecx = eax: preserve returned status
        out.movabs(0xB8, thread_exit);
        out.push(&[0xFF, 0xD0]); // call RtlExitUserThread(status)
        out.push(&[0x0F, 0x0B]); // impossible-return guard
        Ok(out)
    }

    fn movabs(&mut self, opcode: u8, imm: u64) {
        self.push(&[0x48, opcode]);
        self.push(&imm.to_le_bytes());
    }

    fn push(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_entry_passes_its_status_to_resolved_thread_exit() {
        let code =
            StartupTrampoline::emit(0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x60, 0x70).unwrap();
        let bytes = code.bytes();
        assert!(bytes.ends_with(&[
            0x89, 0xC1, 0x48, 0xB8, 0x70, 0x30, 0, 0, 0, 0, 0, 0, 0xFF, 0xD0, 0x0F, 0x0B
        ]));
        assert!(!bytes.windows(2).any(|window| window == [0xEB, 0xFE]));
    }

    #[test]
    fn missing_export_is_rejected_before_emission() {
        assert!(matches!(
            StartupTrampoline::emit(1, 2, 3, 4, 5, 6, 0),
            Err(StartupTrampolineError::MissingThreadExit)
        ));
        assert!(matches!(
            StartupTrampoline::emit(1, 2, 3, 4, 5, 0, 6),
            Err(StartupTrampolineError::MissingLoader)
        ));
        assert!(matches!(
            StartupTrampoline::emit(1, 2, u64::MAX, 4, 5, 6, 7),
            Err(StartupTrampolineError::AddressOverflow)
        ));
    }
}
