//! Owned native arguments for a checked `NtAlpcCreatePort` dispatch.
//!
//! Capture and wire encoding have no port-service effect. Submission must retain
//! the original Reply and request across an uncertain SURT completion.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use nt_alpc_abi::{AlpcCreatePortCheckedRequest, AlpcCreatePortOwnedRequest,
    AlpcCreatePortRequest, AlpcPortAttributes};

mod retained_create;
pub use retained_create::{CreateOwner, RetainedCreate, RetainedCreateError, TerminalCreate};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
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

impl CapturedCreatePort {
    pub fn port_flags(&self) -> u32 {
        u32::from_le_bytes(self.attributes[0..4].try_into().unwrap())
    }

    pub fn max_message_length(&self) -> u64 {
        u64::from_le_bytes(self.attributes[16..24].try_into().unwrap())
    }

    pub fn max_pool_usage(&self) -> u64 {
        u64::from_le_bytes(self.attributes[32..40].try_into().unwrap())
    }

    /// Encode only the policy this port service can honor. A RootDirectory or
    /// SecurityDescriptor must be resolved/checked by the executive before it
    /// can be passed to the service; silently dropping either grants authority.
    pub fn checked_wire(
        &self,
        owner: CreateOwner,
        token: (u64, u64),
    ) -> Result<Vec<u8>, u32> {
        if owner.process_id == 0 || owner.thread_id == 0 || owner.process_generation == 0
            || token == (0, 0)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.root_directory != 0 || self.security_descriptor != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        // OBJ_CASE_INSENSITIVE is already the port core's name comparison rule.
        // Other object flags need namespace/handle policy not represented here.
        if self.object_flags & !0x40 != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        if self.name.len() > MAX_NAME_BYTES / 2 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let attributes: AlpcPortAttributes = bytemuck::pod_read_unaligned(&self.attributes);
        if attributes.flags != 0 || attributes.max_message_length > u32::MAX as u64
            || attributes.max_pool_usage > u32::MAX as u64
            || attributes.memory_bandwidth != 0 || attributes.max_section_size != 0
            || attributes.max_view_size != 0 || attributes.max_total_section_size != 0
            || attributes.dup_object_types != 0 || attributes.reserved != 0
        {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let qos = attributes.security_qos;
        if (qos.length != 0 && qos.length != 12)
            || (qos.length == 0 && (qos.impersonation_level != 0
                || qos.context_tracking_mode != 0 || qos.effective_only != 0))
            || qos.impersonation_level > 3 || qos.context_tracking_mode > 1
            || qos.effective_only > 1 || qos._pad != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<AlpcCreatePortOwnedRequest>();
        let name_len_bytes = self.name.len() * 2;
        let mut wire = Vec::new();
        wire.try_reserve_exact(header_size + name_len_bytes)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let request = AlpcCreatePortOwnedRequest {
            checked: AlpcCreatePortCheckedRequest {
                create: AlpcCreatePortRequest {
                    abi_size: header_size as u16,
                    port_flags: attributes.flags,
                    max_message_length: attributes.max_message_length as u32,
                    name_offset: header_size as u32,
                    name_len_bytes: name_len_bytes as u32,
                    ..Default::default()
                },
                owner_process: owner.process_id,
                owner_thread: owner.thread_id,
                owner_generation: owner.process_generation,
                invocation_hi: token.0,
                invocation_lo: token.1,
            },
            attributes,
        };
        wire.extend_from_slice(bytemuck::bytes_of(&request));
        for unit in &self.name {
            wire.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(wire)
    }
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
        memory[256 + 16..256 + 24].copy_from_slice(&328u64.to_le_bytes());
        memory[256 + 32..256 + 40].copy_from_slice(&8192u64.to_le_bytes());
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
        assert_eq!(u64::from_le_bytes(captured.attributes[16..24].try_into().unwrap()), 328);
        assert_eq!(captured.max_message_length(), 328);
        assert_eq!(captured.max_pool_usage(), 8192);
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

    #[test]
    fn checked_wire_keeps_exact_owner_token_limits_and_name() {
        let memory = image();
        let captured = capture([16, 64, 256], |address, out| {
            out.copy_from_slice(&memory[address as usize..address as usize + out.len()]);
            true
        }, |_, _| true).unwrap();
        let owner = CreateOwner { process_id: 41, thread_id: 51, process_generation: 61 };
        let wire = captured.checked_wire(owner, (71, 81)).unwrap();
        let size = core::mem::size_of::<AlpcCreatePortOwnedRequest>();
        let request: AlpcCreatePortOwnedRequest = bytemuck::pod_read_unaligned(&wire[..size]);
        assert_eq!(request.checked.create.abi_size as usize, size);
        assert_eq!(request.checked.create.name_offset as usize, size);
        assert_eq!(request.checked.create.name_len_bytes, 20);
        assert_eq!((request.checked.owner_process, request.checked.owner_thread,
            request.checked.owner_generation), (41, 51, 61));
        assert_eq!((request.checked.invocation_hi, request.checked.invocation_lo), (71, 81));
        assert_eq!(request.attributes.max_message_length, 328);
        assert_eq!(request.attributes.max_pool_usage, 8192);
        assert_eq!(&wire[size..], &memory[160..180]);
    }

    #[test]
    fn unsupported_authority_and_limits_have_no_wire() {
        let mut captured = capture([16, 0, 0], |_, _| unreachable!(), |_, _| true).unwrap();
        let owner = CreateOwner { process_id: 1, thread_id: 2, process_generation: 3 };
        captured.root_directory = 9;
        assert_eq!(captured.checked_wire(owner, (4, 5)), Err(STATUS_NOT_SUPPORTED));
        captured.root_directory = 0;
        captured.security_descriptor = 9;
        assert_eq!(captured.checked_wire(owner, (4, 5)), Err(STATUS_NOT_SUPPORTED));
        captured.security_descriptor = 0;
        captured.object_flags = 0x10;
        assert_eq!(captured.checked_wire(owner, (4, 5)), Err(STATUS_NOT_SUPPORTED));
        captured.object_flags = 0x40;
        captured.attributes[48..56].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(captured.checked_wire(owner, (4, 5)), Err(STATUS_NOT_SUPPORTED));
        captured.attributes[48..56].fill(0);
        assert_eq!(captured.checked_wire(owner, (0, 0)), Err(STATUS_INVALID_PARAMETER));
    }
}
