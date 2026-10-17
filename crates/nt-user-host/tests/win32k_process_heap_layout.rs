use nt_user_host::win32k_process_heap::heap_mappings_head;

#[test]
fn released_libernt_processinfo_heap_mapping_head_skips_adjacent_self_linked_list() {
    // The pinned win32k.sys IntMapDesktopView at RVA 0x5e33d adds 0x360 to PROCESSINFO before
    // walking W32HEAP_USER_MAPPING.Next. At +0x340 Winlogon's adjacent LIST_ENTRY points to
    // itself, which makes a mapping walker spin until its scan limit.
    let processinfo = 0x1000_a01b_660;
    let wrong_adjacent_list = processinfo + 0x340;
    let head = heap_mappings_head(processinfo).unwrap();
    assert_eq!(head, processinfo + 0x360);
    assert_ne!(head, wrong_adjacent_list);
    assert_eq!(heap_mappings_head(u64::MAX - 0x100), None);
}
