//! Owned native arguments for a future checked `NtAlpcCreatePort` dispatch.
//!
//! This crate only captures caller memory. A security descriptor pointer and
//! RootDirectory handle still require policy validation before submission.
//! Submission must retain the original Reply and request across an uncertain
//! SURT completion before it can be enabled.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const MAX_NAME_BYTES: usize = 2048;

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedCreatePort {
    pub output: u64,
    pub root_directory: u64,
    pub object_flags: u32,
    pub security_descriptor: u64,
    pub name: Vec<u16>,
    pub attributes: [u8; 72],
}

/// Capture the three native arguments into executive-owned storage, with no
/// port-service effect. `read` and `probe_output` must be bound to the same
/// authenticated process address space by the caller.
pub fn capture(
    args: [u64; 3],
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    mut probe_output: impl FnMut(u64, usize) -> bool,
) -> Result<CapturedCreatePort, u32> {
    let [output, object_attributes, port_attributes] = args;
    if output == 0 || !probe_output(output, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut captured = CapturedCreatePort {
        output,
        root_directory: 0,
        object_flags: 0,
        security_descriptor: 0,
        name: Vec::new(),
        attributes: [0; 72],
    };
    if object_attributes != 0 {
        let mut oa = [0u8; 48];
        if !read(object_attributes, &mut oa) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        if u32::from_le_bytes(oa[0..4].try_into().unwrap()) < oa.len() as u32 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        captured.root_directory = u64::from_le_bytes(oa[8..16].try_into().unwrap());
        captured.object_flags = u32::from_le_bytes(oa[24..28].try_into().unwrap());
        captured.security_descriptor = u64::from_le_bytes(oa[32..40].try_into().unwrap());
        let name_pointer = u64::from_le_bytes(oa[16..24].try_into().unwrap());
        if name_pointer != 0 {
            let mut unicode = [0u8; 16];
            if !read(name_pointer, &mut unicode) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            let length = u16::from_le_bytes(unicode[0..2].try_into().unwrap()) as usize;
            let maximum = u16::from_le_bytes(unicode[2..4].try_into().unwrap()) as usize;
            let buffer = u64::from_le_bytes(unicode[8..16].try_into().unwrap());
            if length & 1 != 0 || length > maximum || length > MAX_NAME_BYTES
                || (length != 0 && buffer == 0)
            {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            let mut bytes = [0u8; MAX_NAME_BYTES];
            if length != 0 && !read(buffer, &mut bytes[..length]) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            captured.name.try_reserve_exact(length / 2)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            for pair in bytes[..length].chunks_exact(2) {
                captured.name.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
        }
    }
    if port_attributes != 0 && !read(port_attributes, &mut captured.attributes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(captured)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> [u8; 512] {
        let mut memory = [0u8; 512];
        memory[64..68].copy_from_slice(&48u32.to_le_bytes());
        memory[80..88].copy_from_slice(&128u64.to_le_bytes());
        memory[128..130].copy_from_slice(&20u16.to_le_bytes());
        memory[130..132].copy_from_slice(&22u16.to_le_bytes());
        memory[136..144].copy_from_slice(&160u64.to_le_bytes());
        for (index, unit) in "\\SmApiPort".encode_utf16().enumerate() {
            memory[160 + index * 2..162 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        memory[256 + 24..256 + 32].copy_from_slice(&328u64.to_le_bytes());
        memory
    }

    #[test]
    fn captures_name_and_attributes_without_retaining_caller_pointers() {
        let mut memory = image();
        let captured = capture([16, 64, 256], |address, out| {
            let start = address as usize;
            let Some(bytes) = memory.get(start..start + out.len()) else { return false };
            out.copy_from_slice(bytes);
            true
        }, |address, size| address == 16 && size == 8).unwrap();
        assert_eq!(captured.name, "\\SmApiPort".encode_utf16().collect::<Vec<_>>());
        assert_eq!(u64::from_le_bytes(captured.attributes[24..32].try_into().unwrap()), 328);
        memory[160] = 0;
        assert_eq!(memory[160], 0);
        assert_eq!(captured.name[0], b'\\' as u16);
    }

    #[test]
    fn rejects_invalid_output_and_truncated_name() {
        let memory = image();
        let read = |address: u64, out: &mut [u8]| {
            let start = address as usize;
            let Some(bytes) = memory.get(start..start + out.len()) else { return false };
            out.copy_from_slice(bytes);
            true
        };
        assert_eq!(capture([16, 64, 256], read, |_, _| false), Err(STATUS_ACCESS_VIOLATION));
        let mut truncated = image();
        truncated[128..130].copy_from_slice(&23u16.to_le_bytes());
        assert_eq!(capture([16, 64, 256], |address, out| {
            let start = address as usize;
            let Some(bytes) = truncated.get(start..start + out.len()) else { return false };
            out.copy_from_slice(bytes);
            true
        }, |_, _| true), Err(STATUS_OBJECT_NAME_INVALID));
    }

    #[test]
    fn null_optional_attributes_make_an_unnamed_port_request() {
        let captured = capture([16, 0, 0], |_, _| panic!("no input pointer to read"),
            |address, size| address == 16 && size == 8).unwrap();
        assert!(captured.name.is_empty());
        assert_eq!(captured.root_directory, 0);
        assert_eq!(captured.attributes, [0; 72]);
    }
}
