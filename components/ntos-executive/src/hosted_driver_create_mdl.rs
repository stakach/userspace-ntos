//! Native `MmCreateMdl` header allocation and initialization.

use super::*;

const PAGE: u64 = 4096;

/// `PMDL MmCreateMdl(PMDL, PVOID, SIZE_T)` allocates only the MDL and PFN-array
/// capacity. PFNs remain unset until a later page-lock/physical-page operation.
/// The caller releases a newly allocated header with ExFreePool.
pub(super) extern "win64" fn mm_create_mdl(mdl: u64, base: u64, length: u64) -> u64 {
    let Some(bytes) = nt_mdl::create_mdl::mdl_size_for_range(base, length) else { return 0; };
    let bytes = bytes as u64;
    let offset = base & (PAGE - 1);
    unsafe {
        let allocated = mdl == 0;
        let mdl = if allocated { pool_alloc(bytes) } else { mdl };
        if mdl == 0 { return 0; }
        if component_pool_allocation_capacity(mdl).is_none_or(|capacity| capacity < bytes) {
            if allocated { pool_free(mdl); }
            return 0;
        }
        core::ptr::write_bytes(mdl as *mut u8, 0, bytes as usize);
        write_unaligned((mdl + nt_mdl::MDL_OFF_SIZE) as *mut i16, bytes as i16);
        write_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *mut u64, base & !(PAGE - 1));
        write_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, length as u32);
        write_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32, offset as u32);
        mdl
    }
}
