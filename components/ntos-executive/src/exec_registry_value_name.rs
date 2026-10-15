use super::*;

impl ExecNtHandler {
    /// Capture the complete caller string before querying; failure is never a default value name.
    pub(super) unsafe fn capture_registry_value_name(
        &mut self,
        address: u64,
    ) -> Result<alloc::vec::Vec<u16>, u32> {
        let pi = self.pi;
        let process = self.capture_process_identity(pi).ok_or(STATUS_INVALID_HANDLE)?;
        let mut descriptor = [0u8; 16];
        self.process_memory_read_status(pi, address, &mut descriptor)?;
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let length = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
        let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        bytes.resize(length, 0);
        if length != 0 {
            self.process_memory_read_status(pi, buffer, &mut bytes)?;
            if self.capture_process_identity(pi) != Some(process) {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        // ReactOS captures first, rejects odd Length, then removes trailing NULs. Length zero is
        // the genuine default value and does not require a valid Buffer.
        if length & 1 != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut name = alloc::vec::Vec::new();
        name.try_reserve_exact(length / 2).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        name.extend(bytes.chunks_exact(2).map(|word| u16::from_le_bytes([word[0], word[1]])));
        while name.last() == Some(&0) {
            name.pop();
        }
        Ok(name)
    }
}
