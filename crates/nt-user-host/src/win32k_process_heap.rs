//! Address contract for the pinned LiberNT `PROCESSINFO.HeapMappings` member.

// Pinned LiberNT win32k.sys IntMapDesktopView: RVA 0x5e33d adds 0x360 to PROCESSINFO,
// then walks W32HEAP_USER_MAPPING.Next at RVA 0x5e350.
const HEAP_MAPPINGS_OFF: u64 = 0x360;

pub fn heap_mappings_head(processinfo: u64) -> Option<u64> {
    processinfo.checked_add(HEAP_MAPPINGS_OFF)
}
