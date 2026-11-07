//! Bounded process-query bytes selected from an authenticated caller handle and image record.

extern crate alloc;

use alloc::vec::Vec;
use nt_exe_image::{HostedImageRoot, HostedProcessImageRef};
use nt_process::{ProcessId, ProcessManager, PROCESS_QUERY_INFORMATION};

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const IMAGE_INFORMATION_SIZE: usize = 0x40;
const UNICODE_STRING_SIZE: usize = 0x10;

/// The caller must select this from the exact live process/image mapping, including its
/// generation, after resolving the query handle. The captured PE bytes are never fabricated.
#[derive(Clone, Copy)]
pub struct ProcessImageEvidence<'a> {
    pub process_id: ProcessId,
    pub image: HostedProcessImageRef<'a>,
    pub image_information: [u8; IMAGE_INFORMATION_SIZE],
}

/// Data to copy through a bounded native broker packet. `return_length` is also valid on a
/// short-buffer result, matching the two-call `win32k` query pattern.
pub struct CapturedProcessInformation {
    pub status: u32,
    pub return_length: u32,
    pub bytes: Vec<u8>,
}

impl CapturedProcessInformation {
    fn error(status: u32) -> Self {
        Self {
            status,
            return_length: 0,
            bytes: Vec::new(),
        }
    }

    fn short(required: usize) -> Self {
        Self {
            status: nt_process::STATUS_INFO_LENGTH_MISMATCH,
            return_length: required as u32,
            bytes: Vec::new(),
        }
    }
}

/// Capture only the two classes used by the pinned LiberNT `win32k.sys` image probe. The caller
/// supplies a verified PE image-information block and an exact process/image mapping; this
/// contract handles NT access checks, lengths, and the resulting bytes.
pub fn capture_process_information<'a>(
    processes: &ProcessManager,
    caller: ProcessId,
    handle: u64,
    class: u32,
    output_address: u64,
    output_length: u32,
    dos_root: &[u8],
    image_for_process: impl FnOnce(ProcessId) -> Option<ProcessImageEvidence<'a>>,
) -> CapturedProcessInformation {
    if class != 37 && class != 43 {
        return CapturedProcessInformation::error(STATUS_INVALID_INFO_CLASS);
    }
    let target = match processes.resolve_process_handle(caller, handle, PROCESS_QUERY_INFORMATION) {
        Ok(pid) => pid,
        Err(status) => return CapturedProcessInformation::error(status),
    };
    let Some(evidence) = image_for_process(target) else {
        return CapturedProcessInformation::error(nt_process::STATUS_INVALID_HANDLE);
    };
    let Some(process) = processes.process(target) else {
        return CapturedProcessInformation::error(nt_process::STATUS_INVALID_HANDLE);
    };
    if evidence.process_id != target
        || evidence.image.generation == 0
        || evidence.image.top_badge == 0
        || !evidence
            .image
            .leaf
            .eq_ignore_ascii_case(process.image_file_name.as_bytes())
    {
        return CapturedProcessInformation::error(nt_process::STATUS_INVALID_HANDLE);
    }

    let mut bytes = Vec::new();
    let required = if class == 37 {
        IMAGE_INFORMATION_SIZE
    } else {
        let mut path = Vec::new();
        let extra = usize::from(evidence.image.image_root == HostedImageRoot::System32) * 9;
        let Some(capacity) = dos_root
            .len()
            .checked_add(extra + 1 + evidence.image.leaf.len())
        else {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        };
        if path.try_reserve_exact(capacity).is_err() {
            return CapturedProcessInformation::error(STATUS_INSUFFICIENT_RESOURCES);
        }
        path.extend_from_slice(dos_root);
        path.extend_from_slice(if evidence.image.image_root == HostedImageRoot::System32 {
            b"\\System32\\"
        } else {
            b"\\"
        });
        path.extend_from_slice(evidence.image.leaf);
        let Some(byte_length) = path.len().checked_mul(2) else {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        };
        let Some(maximum_length) = byte_length.checked_add(2) else {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        };
        if maximum_length > u16::MAX as usize {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        }
        let Some(required) = UNICODE_STRING_SIZE.checked_add(maximum_length) else {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        };
        if required > u32::MAX as usize {
            return CapturedProcessInformation::error(nt_process::STATUS_INVALID_PARAMETER);
        }
        if output_length as usize >= required {
            if bytes.try_reserve_exact(required).is_err() {
                return CapturedProcessInformation::error(STATUS_INSUFFICIENT_RESOURCES);
            }
            bytes.resize(required, 0);
            bytes[0..2].copy_from_slice(&(byte_length as u16).to_le_bytes());
            bytes[2..4].copy_from_slice(&(maximum_length as u16).to_le_bytes());
            let Some(buffer_address) = output_address.checked_add(UNICODE_STRING_SIZE as u64)
            else {
                return CapturedProcessInformation::error(STATUS_ACCESS_VIOLATION);
            };
            bytes[8..16].copy_from_slice(&buffer_address.to_le_bytes());
            for (index, &byte) in path.iter().enumerate() {
                let offset = UNICODE_STRING_SIZE + index * 2;
                bytes[offset..offset + 2].copy_from_slice(&(byte as u16).to_le_bytes());
            }
        }
        required
    };
    if (output_length as usize) < required {
        return CapturedProcessInformation::short(required);
    }
    if output_address == 0 {
        return CapturedProcessInformation::error(STATUS_ACCESS_VIOLATION);
    }
    if output_address & if class == 43 { 1 } else { 3 } != 0 {
        return CapturedProcessInformation::error(STATUS_DATATYPE_MISALIGNMENT);
    }
    if class == 37 {
        if bytes.try_reserve_exact(IMAGE_INFORMATION_SIZE).is_err() {
            return CapturedProcessInformation::error(STATUS_INSUFFICIENT_RESOURCES);
        }
        bytes.extend_from_slice(&evidence.image_information);
    }
    CapturedProcessInformation {
        status: STATUS_SUCCESS,
        return_length: required as u32,
        bytes,
    }
}
