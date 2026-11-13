//! Pinned LiberNT native IAT data exports preserve an address-of-cell, then the live value.

#[test]
fn new_win32k_data_exports_have_canonical_live_values() {
    let win32k = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let catalog = include_str!("../src/win32k_resolve.rs");
    let section = nt_object_manager::object_type::section_object_type_addr();
    let job = nt_object_manager::object_type::job_object_type_addr();
    assert_ne!(section, 0);
    assert_ne!(job, 0);
    assert_ne!(section, job, "section and job require distinct canonical OBJECT_TYPE identities");

    for name in ["MmSectionObjectType", "PsJobType", "MmWriteableSharedUserData"] {
        assert!(catalog.contains(&format!("\"{name}\",")), "data-export catalog omits {name}");
        assert!(win32k.contains(&format!("(\"{name}\",")), "native cell allocation omits {name}");
    }
    assert!(win32k.contains("\"MmSectionObjectType\" => ot::section_object_type_addr()"));
    assert!(win32k.contains("\"PsJobType\" => ot::job_object_type_addr()"));
    assert!(win32k.contains("(\"MmWriteableSharedUserData\", WIN32K_KUSER_SHARED_DATA_VA)"));
    let names: Vec<_> = win32k
        .split_once("const DATA_EXPORTS: &[(&str, u64)] = &[")
        .expect("native data-cell table")
        .1
        .split_once("];\n")
        .expect("end of native data-cell table")
        .0
        .lines()
        .filter_map(|line| line.split_once('"').and_then(|(_, rest)| rest.split_once('"').map(|(name, _)| name)))
        .collect();
    let indices: Vec<_> = ["MmSectionObjectType", "PsJobType", "MmWriteableSharedUserData"]
        .into_iter()
        .map(|name| names.iter().position(|entry| *entry == name).expect("distinct data cell"))
        .collect();
    assert_ne!(indices[0], indices[1]);
    assert_ne!(indices[0], indices[2]);
    assert_ne!(indices[1], indices[2]);
    assert!(win32k.contains("pub const WIN32K_KUSER_SHARED_DATA_VA: u64 = nt_ntdll_layout::kuser::KERNEL_ALIAS_VA"));
    assert!(win32k.contains("pub const WIN32K_KUSER_SCRATCH_VA: u64 = WIN32K_AUX_PT_VADDR"));
    assert!(win32k.contains("WIN32K_DATA_VADDR + 0x1000 + di as u64 * 8"));
    assert!(win32k.contains("object_type_cell_value(name).unwrap_or(*value)"));
    assert!(main.contains("let kuser_map_cap = copy_cap(kuser_frame);"));
    assert!(main.contains("win32k_subsystem::WIN32K_KUSER_SHARED_DATA_VA,\n                    RW_NX,\n                    sc.pml4,"));
    assert!(main.contains("if kuser_map != 0"));
}
