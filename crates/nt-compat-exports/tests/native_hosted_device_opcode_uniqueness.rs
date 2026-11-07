//! Hosted device RPC opcodes are one protocol, even when handlers live in separate modules.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const REFERENCE: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_object_reference.rs");

fn numeric_constant(source: &str, name: &str) -> Option<u64> {
    let line = source.lines().find(|line| {
        line.trim_start().starts_with(&format!("const {name}: u64 = "))
            || line.trim_start().starts_with(&format!("pub(crate) const {name}: u64 = "))
            || line.trim_start().starts_with(&format!("pub(super) const {name}: u64 = "))
    })?;
    let value = line.split_once(": u64 = ")?.1.trim_end_matches(';');
    value.parse().ok()
}

#[test]
fn hosted_device_rpc_opcodes_are_unique_and_have_one_numeric_authority() {
    let block = LAUNCH
        .split_once("const HOSTED_DEVICE_OP_QUERY_PROPERTY_BEGIN: u64 = ")
        .expect("hosted device protocol start")
        .1
        .split_once("const HOSTED_DEVICE_INTERFACE_ARG_LINK_LEN:")
        .expect("hosted device protocol end")
        .0;
    let mut operations = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        let Some((declaration, value)) = line.split_once(": u64 = ") else { continue };
        let Some(name) = declaration.split_whitespace().last() else { continue };
        if !name.starts_with("HOSTED_DEVICE_OP_") { continue }
        let value = value.trim_end_matches(';');
        let number = if let Ok(number) = value.parse::<u64>() {
            number
        } else if value == "hosted_driver_object_reference::OP_REFERENCE_BY_POINTER" {
            numeric_constant(REFERENCE, "OP_REFERENCE_BY_POINTER")
                .expect("external reference opcode must be numeric")
        } else {
            panic!("unexpected nonnumeric hosted device opcode {name} = {value}")
        };
        if let Some((other_name, _)) = operations.iter().find(|(_, other_number)| *other_number == number) {
            panic!("hosted device RPC opcode {number} aliases {other_name} and {name}");
        }
        operations.push((name, number));
    }
    assert!(operations.len() >= 35, "hosted device opcode inventory is incomplete");
    assert!(numeric_constant(LAUNCH, "HOSTED_DEVICE_OP_REFERENCE_BY_POINTER").is_some(),
        "reference opcode must be defined numerically beside the other device operations");
    assert!(numeric_constant(REFERENCE, "OP_REFERENCE_BY_POINTER").is_none(),
        "device reference must not retain a second numeric opcode authority");
}
