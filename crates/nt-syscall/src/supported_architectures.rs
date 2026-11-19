//! `NtQuerySystemInformationEx(SystemSupportedProcessorArchitectures)`.
//!
//! The input is a process handle (or 0 for the system). The output is an array of
//! `SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION` (one `ULONG` each: `Machine:16`,
//! `KernelMode:1`, `UserMode:1`, `Native:1`, `Process:1`, `WoW64Container:1`) ending with a zero
//! entry, as Wine's `dlls/ntdll/unix/system.c` produces it. This kernel personality runs
//! AMD64 code only: there is no WOW64 layer, so the native machine is the only entry.

pub const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES: u32 = 0xb5;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

const KERNEL_MODE: u32 = 1 << 16;
const USER_MODE: u32 = 1 << 17;
const NATIVE: u32 = 1 << 18;
const PROCESS: u32 = 1 << 19;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc000_0004;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

/// The entries, terminator included, for a query about a process running `process_machine`
/// (`None` for a system query with a zero handle).
pub fn supported_architectures(process_machine: Option<u16>) -> [u32; 2] {
    let process = if process_machine == Some(IMAGE_FILE_MACHINE_AMD64) { PROCESS } else { 0 };
    [u32::from(IMAGE_FILE_MACHINE_AMD64) | KERNEL_MODE | USER_MODE | NATIVE | process, 0]
}

/// The bytes to copy and the length to report, or the failure status with the length needed.
pub fn encode(
    input_length: usize,
    output_length: usize,
    process_machine: Option<u16>,
) -> Result<([u8; 8], u32), (u32, u32)> {
    if input_length != 8 {
        return Err((STATUS_INVALID_PARAMETER, 0));
    }
    let entries = supported_architectures(process_machine);
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&entries[0].to_le_bytes());
    if output_length < bytes.len() {
        let status = if output_length == 0 { STATUS_INFO_LENGTH_MISMATCH } else { STATUS_BUFFER_TOO_SMALL };
        return Err((status, bytes.len() as u32));
    }
    Ok((bytes, bytes.len() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_native_amd64_machine_is_the_only_entry() {
        let (bytes, length) = encode(8, 64, Some(IMAGE_FILE_MACHINE_AMD64)).unwrap();
        assert_eq!(length, 8);
        let first = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(first & 0xffff, 0x8664);
        assert_eq!(first >> 16, 0b1111);
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
        // A system query does not mark the process bit.
        assert_eq!(supported_architectures(None)[0] >> 16, 0b0111);
    }

    #[test]
    fn rejects_a_wrong_input_and_reports_the_size_needed() {
        assert_eq!(encode(4, 64, None), Err((STATUS_INVALID_PARAMETER, 0)));
        assert_eq!(encode(8, 4, None), Err((STATUS_BUFFER_TOO_SMALL, 8)));
        assert_eq!(encode(8, 0, None), Err((STATUS_INFO_LENGTH_MISMATCH, 8)));
    }
}
