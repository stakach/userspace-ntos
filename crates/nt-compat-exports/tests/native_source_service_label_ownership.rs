fn label(source: &str, name: &str) -> u64 {
    let marker = format!("const {name}: u64 = 0x");
    let tail = source.split_once(&marker).expect("service label declaration").1;
    let hex: String = tail.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    u64::from_str_radix(&hex, 16).expect("hexadecimal service label")
}

#[test]
fn pci_and_dynamic_object_services_have_distinct_labels() {
    let pci_root = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_root.rs");
    let pci_route = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_route_query.rs");
    let dynamic = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_object.rs");
    let delete = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_delete.rs");
    let labels = [
        label(pci_root, "LABEL"),
        label(pci_route, "LABEL"),
        label(dynamic, "LABEL"),
        label(dynamic, "INSERT_LABEL"),
        label(dynamic, "REFERENCE_LABEL"),
        label(delete, "DEREFERENCE_LABEL"),
    ];
    for (index, &left) in labels.iter().enumerate() {
        assert!(!labels[index + 1..].contains(&left), "duplicate service label {left:#x}");
    }
}

#[test]
fn seh_transport_and_win32k_services_have_distinct_labels() {
    let seh = include_str!("../../nt-unwind/src/seh_transport.rs");
    let win32k = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let seh_labels = [
        "RAISE_LABEL",
        "PREPARE_LABEL",
        "HANDLER_RESULT_LABEL",
        "PREPARE_COMMAND_LABEL",
        "INVOKE_COMMAND_LABEL",
        "RESTORE_COMMAND_LABEL",
        "SECOND_CHANCE_COMMAND_LABEL",
        "UNWIND_REQUEST_LABEL",
        "BEGIN_UNWIND_LABEL",
        "FAULT_BEGIN_LABEL",
    ];
    let win32k_labels: Vec<(&str, u64)> = win32k
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("pub const W32_")?;
            let (name, value) = rest.split_once(": u64 = 0x")?;
            if !name.ends_with("_LABEL") {
                return None;
            }
            let hex: String = value.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            Some((name, u64::from_str_radix(&hex, 16).unwrap()))
        })
        .collect();
    assert!(!win32k_labels.is_empty());
    for name in seh_labels {
        let value = label(seh, name);
        assert!(
            !win32k_labels.iter().any(|(_, other)| *other == value),
            "SEH {name} collides with Win32k service label {value:#x}"
        );
    }
}
