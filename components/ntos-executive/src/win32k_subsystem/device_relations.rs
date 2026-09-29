//! Native win32k PDO relation invalidation through the retained executive PnP action.

use super::*;

pub(super) extern "win64" fn synchronous_invalidate(
    device_object: u64,
    relation_type: u32,
) -> i32 {
    let (words, raw, out1, out2, out3) = unsafe {
        crate::driver_launch::call_on4_raw(
            (W32_REGISTRY_LABEL << 12) | 4,
            WIN32K_REGISTRY_OP_SYNC_INVALIDATE_RELATIONS,
            device_object,
            relation_type as u64,
            0,
        )
    };
    if words != 4
        || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
        || out1 != 0
        || out2 != 0
        || out3 != 0
    {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [W32_REGISTRY_LABEL, WIN32K_REGISTRY_OP_SYNC_INVALIDATE_RELATIONS, words, raw],
            );
        }
    }
    raw as u32 as i32
}
