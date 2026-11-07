//! Native hosted registry requests share one broker lane. Duplicate operation numbers route
//! a caller to the wrong service, even when each operation is defined in a separate module.

use std::collections::BTreeMap;

const OPCODES: &str =
    include_str!("../../../components/ntos-executive/src/hosted_registry_opcodes.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const QUERY_KEY: &str = include_str!("../../../components/ntos-executive/src/hosted_zw_query_key.rs");
const ENUMERATE_VALUE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_zw_enumerate_value_key.rs");
const DEFERRED_VALUE: &str =
    include_str!("../../../components/ntos-executive/src/driver_registry_deferred_value.rs");

#[test]
fn hosted_registry_broker_operations_have_distinct_numbers() {
    let mut by_number = BTreeMap::<u64, &str>::new();
    for line in OPCODES.lines() {
        let Some((declaration, number)) = line.trim().split_once(": u64 = ") else {
            continue;
        };
        let Some(name) = declaration.split_whitespace().last() else {
            continue;
        };
        if !name.starts_with("HOSTED_REGISTRY_OP_") {
            continue;
        }
        let number: u64 = number
            .trim_end_matches(';')
            .parse()
            .expect("hosted registry operation number must be a literal");
        if let Some(previous) = by_number.insert(number, name) {
            panic!("hosted registry operation {number} is shared by {previous} and {name}");
        }
    }
    assert_eq!(by_number.len(), 19, "all hosted registry operations must be covered");
    for name in by_number.values() {
        assert!(
            [BROKER, QUERY_KEY, ENUMERATE_VALUE, DEFERRED_VALUE]
                .iter()
                .any(|source| source.contains(*name)),
            "{name} must be routed by the broker or used by a caller"
        );
    }
    for (name, source) in [
        ("HOSTED_REGISTRY_OP_QUERY_KEY", QUERY_KEY),
        ("HOSTED_REGISTRY_OP_ENUMERATE_VALUE", ENUMERATE_VALUE),
        ("HOSTED_REGISTRY_OP_QUERY_KEY", BROKER),
        ("HOSTED_REGISTRY_OP_ENUMERATE_VALUE", BROKER),
        ("HOSTED_REGISTRY_OP_REGISTER_INTERFACE", BROKER),
        ("HOSTED_REGISTRY_OP_OPEN_INTERFACE_KEY", BROKER),
    ] {
        assert!(source.contains(name), "{name} must reach its caller or broker branch");
    }
    for source in [BROKER, QUERY_KEY, ENUMERATE_VALUE, DEFERRED_VALUE] {
        assert!(!source.lines().any(|line| line.contains("const HOSTED_REGISTRY_OP_")),
            "hosted registry operation numbers must be allocated in one module");
    }
}
