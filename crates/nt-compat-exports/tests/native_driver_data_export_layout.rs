//! Hosted driver DATA imports must have distinct writable cells across components.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PROCESS: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_process_state.rs");
const SAFE_BOOT: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_safe_boot.rs");
const DEVICE: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_object_reference.rs");
const NLS: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_nls_exports.rs");

fn hex_offset(source: &str, name: &str) -> usize {
    let needle = format!("{name}: u64 = 0x");
    let tail = source.split_once(&needle).unwrap_or_else(|| panic!("missing {name}")).1;
    let digits: String = tail.chars().take_while(|c| c.is_ascii_hexdigit() || *c == '_')
        .filter(|c| *c != '_').collect();
    usize::from_str_radix(&digits, 16).unwrap()
}

#[test]
fn imported_driver_data_cells_are_disjoint_and_keep_device_type_after_initialization() {
    let cells = [
        ("KeNumberProcessors", hex_offset(LAUNCH, "FSD_DATA_KE_NUMBER_PROCESSORS_OFF"), 1),
        ("KdComPortInUse", hex_offset(LAUNCH, "FSD_DATA_KD_COM_PORT_IN_USE_OFF"), 8),
        ("IoDeviceObjectType", hex_offset(DEVICE, "DEVICE_OBJECT_TYPE_CELL_OFFSET"), 8),
        ("PsInitialSystemProcess", hex_offset(PROCESS, "INITIAL_SYSTEM_PROCESS_CELL_OFF"), 8),
        ("PsProcessType", hex_offset(PROCESS, "PROCESS_TYPE_CELL_OFF"), 8),
        ("PsThreadType", hex_offset(PROCESS, "THREAD_TYPE_CELL_OFF"), 8),
        ("InitSafeBootMode", hex_offset(SAFE_BOOT, "SAFE_BOOT_MODE_OFFSET"), 4),
    ];
    for (i, (name, start, length)) in cells.iter().enumerate() {
        for (other, other_start, other_length) in cells.iter().skip(i + 1) {
            assert!(*start + *length <= *other_start || *other_start + *other_length <= *start,
                "{name} overlaps {other}");
        }
    }

    let nls_end = hex_offset(NLS, "FSD_NLS_STATE_OFFSET") + 8;
    let hal_start = hex_offset(LAUNCH, "FSD_DATA_HAL_PRIVATE_DISPATCH_OFF");
    for (name, start, length) in cells.iter().skip(3) {
        if *start >= nls_end {
            assert!(*start + *length <= hal_start, "{name} overlaps HAL private dispatch");
        }
    }

    // Reproduce the native initializer order: device type, safe boot, then Ps data exports.
    let mut data = [0u8; 0xc00];
    let device_cell = cells[2].1;
    let expected_device_type = (hex_offset(LAUNCH, "FSD_DATA_VADDR")
        + hex_offset(DEVICE, "DEVICE_OBJECT_TYPE_BODY_OFFSET")) as u64;
    data[device_cell..device_cell + 8].copy_from_slice(&expected_device_type.to_le_bytes());
    data[cells[6].1..cells[6].1 + 4].fill(0);
    for (index, value) in [(3, 0x1000_e801_000u64), (4, 0x1000_eec0_100), (5, 0x1000_eec1_80)] {
        let start = cells[index].1;
        data[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    assert_eq!(u64::from_le_bytes(data[device_cell..device_cell + 8].try_into().unwrap()),
        expected_device_type);
}
