use crate::{
    ClientFrameRecord, ClientFrameRegistry, MemoryLifetime, ProcessIdentity, STATUS_INVALID_HANDLE,
};

/// Distinguish a nonresident page from a frame retained by another process generation.
pub fn admit_resident_reprotect(
    pi: u64,
    process: ProcessIdentity,
    page: u64,
    frames: &ClientFrameRegistry,
) -> Result<Option<ClientFrameRecord>, u32> {
    if !process.is_valid() {
        return Err(STATUS_INVALID_HANDLE);
    }
    match frames.get(pi, page) {
        Some(record) if record.lifetime != MemoryLifetime::Process(process) => {
            Err(STATUS_INVALID_HANDLE)
        }
        record => Ok(record),
    }
}
