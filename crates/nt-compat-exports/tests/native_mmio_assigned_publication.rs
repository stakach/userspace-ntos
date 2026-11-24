//! Execute the production StartDevice MMIO policy with an assigned descriptor whose projection
//! fields are empty. The assignment itself still requires a per-binding map receipt.

const SH_RESOURCE_ADDRESS_KIND_MEMORY: u8 = 1;

#[derive(Clone, Copy)]
struct SharedAddressResource {
    kind: u8,
    resource_index: u8,
    va: u64,
    map_len: u64,
}

#[path = "../../../components/ntos-executive/src/hosted_mmio_publication_policy.rs"]
mod hosted_mmio_publication_policy;

#[test]
fn assigned_memory_requires_receipt_even_before_projection_fields_are_filled() {
    for (va, map_len) in [(0, 0), (0, 0x1000), (0x7000_0000, 0)] {
        let resources = [SharedAddressResource {
            kind: SH_RESOURCE_ADDRESS_KIND_MEMORY,
            resource_index: 0,
            va,
            map_len,
        }];
        assert!(
            hosted_mmio_publication_policy::assigned_memory_requires_receipt(&resources),
            "an assigned memory grant cannot publish StartDevice without its own receipt"
        );
    }
}

#[test]
fn devices_without_assigned_memory_do_not_require_an_mmio_receipt() {
    let resources = [SharedAddressResource {
        kind: 2,
        resource_index: 0,
        va: 0,
        map_len: 0,
    }];
    assert!(!hosted_mmio_publication_policy::assigned_memory_requires_receipt(&resources));
}
