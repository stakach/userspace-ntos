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
