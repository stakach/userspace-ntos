//! ReactOS updates SharedUserData->LastSystemRITEventTickCount at +0x2e4 on real input.
//! Its kernel Win32k alias must accept that write while process user aliases remain read only.

#[test]
fn win32k_kernel_kuser_alias_is_writable_and_client_alias_is_read_only() {
    let executive = include_str!("../../../components/ntos-executive/src/main.rs");
    let high = executive
        .split_once("let kuser_map = page_map_r(")
        .expect("Win32k high KUSER alias mapping")
        .1
        .split_once(");")
        .expect("complete high alias map call")
        .0;
    assert!(high.contains("WIN32K_KUSER_SHARED_DATA_VA"));
    assert!(high.contains("RW_NX"), "Win32k writes the high alias during input");

    let spawn = include_str!("../../../components/ntos-executive/src/img_spawn.rs");
    let low = spawn
        .split_once("let kuser_client = checked_spawn_copy_cap(kuser_f")
        .expect("process KUSER alias allocation")
        .1
        .split_once("if !kuser_page_alias_put")
        .expect("process KUSER alias ownership")
        .0;
    assert!(low.contains("KUSER_VA,\n            2 | PAGE_EXECUTE_NEVER"));
}
