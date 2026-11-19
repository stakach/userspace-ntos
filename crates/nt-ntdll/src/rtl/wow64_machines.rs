//! Reading the kernel's `SystemSupportedProcessorArchitectures` list
//! (`SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION`, zero-terminated).

const NATIVE: u32 = 1 << 18;

/// Whether `machine` is a supported non-native (WOW64 guest) architecture in `entries`, as
/// Wine's `RtlWow64IsWowGuestMachineSupported` decides it.
pub fn guest_machine_supported(entries: &[u32], machine: u16) -> bool {
    entries
        .iter()
        .take_while(|&&entry| entry & 0xffff != 0)
        .any(|&entry| entry & NATIVE == 0 && entry as u16 == machine)
}

#[cfg(test)]
mod tests {
    use super::*;

    const I386: u16 = 0x014c;
    const AMD64: u16 = 0x8664;

    #[test]
    fn only_a_non_native_listed_machine_is_a_guest() {
        // This kernel: native AMD64 only.
        let native_only = [0x000f_8664, 0];
        assert!(!guest_machine_supported(&native_only, I386));
        assert!(!guest_machine_supported(&native_only, AMD64));
        // A kernel with a WOW64 i386 layer.
        let with_wow64 = [0x000f_8664, 0x0002_014c, 0];
        assert!(guest_machine_supported(&with_wow64, I386));
        // Entries after the terminator are not read.
        assert!(!guest_machine_supported(&[0x000f_8664, 0, 0x0002_014c], I386));
    }
}
