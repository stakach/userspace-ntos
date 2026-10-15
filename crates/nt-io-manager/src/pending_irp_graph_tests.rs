use super::*;
use alloc::vec::Vec;

fn distinct() -> PendingIrpGraphPointers {
    PendingIrpGraphPointers {
        reclaim: 1,
        mdl: 2,
        aux_data: 3,
        data: 4,
        create_parameters: 5,
        create_access_state: 6,
        create_security_context: 7,
        pnp_resource_list: 8,
        irp: 9,
        file_object: 10,
        owns_file: true,
    }
}

#[test]
fn all_ten_candidates_preserve_native_release_order() {
    let graph = PendingIrpAllocationGraph::new(distinct());
    assert_eq!(graph.allocations().len(), 10);
    for (index, allocation) in graph.allocations().iter().enumerate() {
        assert_eq!(allocation.pointer, index as u64 + 1);
        assert_eq!(
            allocation.release_kind,
            if index == 9 {
                GraphReleaseKind::FileStorage
            } else {
                GraphReleaseKind::Pool
            }
        );
        assert!(graph.contains_pointer(allocation.pointer));
    }
    assert!(!graph.contains_pointer(0));
    assert!(!graph.contains_pointer(11));
}

#[test]
fn absent_candidates_do_not_manufacture_allocations() {
    let graph = PendingIrpAllocationGraph::new(PendingIrpGraphPointers::default());
    assert!(graph.allocations().is_empty());
    assert!(!graph.contains_pointer(0));
}

#[test]
fn every_collision_pair_releases_once_at_first_position() {
    for later in 1..10 {
        for earlier in 0..later {
            let mut pointers = distinct();
            let mut values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            values[later] = values[earlier];
            pointers.reclaim = values[0];
            pointers.mdl = values[1];
            pointers.aux_data = values[2];
            pointers.data = values[3];
            pointers.create_parameters = values[4];
            pointers.create_access_state = values[5];
            pointers.create_security_context = values[6];
            pointers.pnp_resource_list = values[7];
            pointers.irp = values[8];
            pointers.file_object = values[9];
            let graph = PendingIrpAllocationGraph::new(pointers);
            let expected: Vec<_> = values
                .iter()
                .enumerate()
                .filter(|(index, value)| !values[..*index].contains(value))
                .map(|(_, value)| *value)
                .collect();
            assert_eq!(
                graph
                    .allocations()
                    .iter()
                    .map(|row| row.pointer)
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(graph.allocations().len(), 9);
            let file = graph
                .allocations()
                .iter()
                .find(|row| row.pointer == pointers.file_object)
                .unwrap();
            assert_eq!(file.release_kind, GraphReleaseKind::FileStorage);
        }
    }
}

#[test]
fn borrowed_file_is_not_a_candidate_or_a_file_storage_release() {
    let mut pointers = distinct();
    pointers.owns_file = false;
    let graph = PendingIrpAllocationGraph::new(pointers);
    assert_eq!(graph.allocations().len(), 9);
    assert!(!graph.contains_pointer(10));
    assert!(graph
        .allocations()
        .iter()
        .all(|row| row.release_kind == GraphReleaseKind::Pool));
    pointers.file_object = pointers.data;
    let graph = PendingIrpAllocationGraph::new(pointers);
    assert!(graph.contains_pointer(pointers.data));
    assert!(graph
        .allocations()
        .iter()
        .all(|row| row.release_kind == GraphReleaseKind::Pool));
}

#[test]
fn aux_data_alias_and_reclaim_alias_are_deduplicated() {
    let mut pointers = distinct();
    pointers.aux_data = pointers.data;
    pointers.reclaim = pointers.data;
    let graph = PendingIrpAllocationGraph::new(pointers);
    assert_eq!(graph.allocations().len(), 8);
    assert_eq!(graph.allocations()[0].pointer, pointers.data);
    assert_eq!(
        graph
            .allocations()
            .iter()
            .filter(|row| row.pointer == pointers.data)
            .count(),
        1
    );
}
