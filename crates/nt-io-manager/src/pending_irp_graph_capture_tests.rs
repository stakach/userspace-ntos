//! Contract tests for captured graph metadata, not native allocator authority.
//!
//! The adapter must authenticate the source and physical arena, exclude other owners, and
//! retain its actual resources. Settling a terminal plan here confirms bookkeeping only:
//! it does not prove driver completion, destination adoption, or a physical free.

use crate::pending_irp_graph::captured::{
    CapturedGraph, GraphRoles, PreparedInventory, TerminalChanges,
};
use crate::pending_irp_graph::PendingIrpGraphPointers;
use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner};
use crate::{HostedDomainId, HostedDomainIdentity};

fn allocation(address: u64, generation: u64) -> SourcePoolAllocationIdentity {
    SourcePoolAllocationIdentity {
        component_address: address,
        capacity: 0x80,
        pool_generation: generation,
    }
}

fn source() -> SourceIrpForwardIdentity {
    let domain = HostedDomainIdentity {
        domain_id: HostedDomainId(7),
        cookie: 9,
    };
    SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(domain, 13, 17).unwrap(),
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedCaller(2),
            domain,
            component_address: 0x9000,
            bytes: 0x60,
            stack_count: 1,
            pool_generation: 29,
        },
    )
    .unwrap()
}

fn pointers() -> PendingIrpGraphPointers {
    PendingIrpGraphPointers {
        mdl: 0x1000,
        aux_data: 0x2000,
        data: 0x3000,
        irp: 0x9000,
        ..PendingIrpGraphPointers::default()
    }
}

fn members() -> [SourcePoolAllocationIdentity; 4] {
    [
        allocation(0x1000, 11),
        allocation(0x2000, 12),
        allocation(0x3000, 13),
        allocation(0x9000, 29),
    ]
}

fn graph() -> CapturedGraph {
    CapturedGraph::capture(source(), pointers(), 0, &members()).unwrap()
}

fn unchanged() -> TerminalChanges {
    TerminalChanges {
        reclaim: None,
        transfer_data: None,
    }
}

#[test]
fn capture_preserves_exact_source_identities_roles_and_release_order() {
    let graph = graph();
    assert_eq!(graph.source(), source());
    let captured = graph.initial_members();
    assert_eq!(captured.len(), 4);
    for (row, expected) in captured.iter().zip(members()) {
        assert_eq!(row.allocation, expected);
    }
    assert_eq!(captured[0].roles, GraphRoles::MDL);
    assert_eq!(captured[1].roles, GraphRoles::AUX_DATA);
    assert_eq!(captured[2].roles, GraphRoles::DATA);
    assert_eq!(captured[3].roles, GraphRoles::IRP);
}

#[test]
fn exact_aliases_merge_roles_but_conflicting_alias_identities_are_rejected() {
    let mut pointers = pointers();
    pointers.aux_data = pointers.data;
    let identities = [members()[0], members()[2], members()[3]];
    let graph = CapturedGraph::capture(source(), pointers, 0, &identities).unwrap();
    assert_eq!(graph.initial_members().len(), 3);
    assert_eq!(graph.initial_members()[1].allocation, members()[2]);
    assert_eq!(
        graph.initial_members()[1].roles,
        GraphRoles::AUX_DATA | GraphRoles::DATA
    );

    for contradictory in [
        allocation(pointers.data, 99),
        SourcePoolAllocationIdentity {
            capacity: 0x40,
            ..members()[2]
        },
    ] {
        let supplied = [identities[0], identities[1], identities[2], contradictory];
        assert!(CapturedGraph::capture(source(), pointers, 0, &supplied).is_err());
    }
}

#[test]
fn capture_rejects_missing_extra_invalid_overlapping_and_stale_packet_members() {
    assert!(CapturedGraph::capture(source(), pointers(), 0, &members()[..3]).is_err());
    let mut extra = members().to_vec();
    extra.push(allocation(0xa000, 31));
    assert!(CapturedGraph::capture(source(), pointers(), 0, &extra).is_err());

    for replacement in [
        allocation(0x3000, 0),
        SourcePoolAllocationIdentity {
            capacity: 0,
            ..members()[2]
        },
        SourcePoolAllocationIdentity {
            capacity: u64::MAX,
            ..members()[2]
        },
    ] {
        let mut supplied = members();
        supplied[2] = replacement;
        assert!(CapturedGraph::capture(source(), pointers(), 0, &supplied).is_err());
    }

    let mut overlapping = pointers();
    overlapping.aux_data = overlapping.mdl + 0x40;
    let mut supplied = members();
    supplied[1] = allocation(overlapping.aux_data, 12);
    assert!(CapturedGraph::capture(source(), overlapping, 0, &supplied).is_err());

    for replacement in [
        allocation(0x9000, 30),
        SourcePoolAllocationIdentity {
            capacity: 0x40,
            ..members()[3]
        },
    ] {
        let mut supplied = members();
        supplied[3] = replacement;
        assert!(CapturedGraph::capture(source(), pointers(), 0, &supplied).is_err());
    }
}

#[test]
fn initial_capture_does_not_adopt_a_terminal_reclaim_or_a_borrowed_file_name() {
    let mut premature = pointers();
    premature.reclaim = premature.data;
    assert!(CapturedGraph::capture(source(), premature, 0, &members()).is_err());

    let mut borrowed = pointers();
    borrowed.file_object = 0xa000;
    let mut supplied = members().to_vec();
    supplied.push(allocation(0xb000, 41));
    assert!(CapturedGraph::capture(source(), borrowed, 0xb000, &supplied).is_err());
    let graph = CapturedGraph::capture(source(), borrowed, 0, &members()).unwrap();
    assert_eq!(graph.initial_members().len(), 4);
}

#[test]
fn captured_owned_file_name_survives_later_descriptor_changes() {
    let mut pointers = pointers();
    pointers.file_object = 0xa000;
    pointers.owns_file = true;
    let mut file_name_buffer = 0xb000;
    let mut supplied = members().to_vec();
    supplied.push(allocation(pointers.file_object, 40));
    supplied.push(allocation(file_name_buffer, 41));
    let graph = CapturedGraph::capture(source(), pointers, file_name_buffer, &supplied).unwrap();
    let before = graph.initial_members().to_vec();
    let file = before
        .iter()
        .find(|row| row.roles.contains(GraphRoles::FILE_OBJECT))
        .unwrap();
    let name = before
        .iter()
        .find(|row| row.roles.contains(GraphRoles::FILE_NAME))
        .unwrap();
    assert_eq!(file.allocation, allocation(0xa000, 40));
    assert_eq!(name.allocation, allocation(0xb000, 41));
    assert!(before.iter().position(|row| row == name) < before.iter().position(|row| row == file));

    file_name_buffer = 0xc000;
    assert_ne!(file_name_buffer, name.allocation.component_address);
    let settled = graph
        .prepare_terminal(unchanged())
        .unwrap()
        .enter()
        .settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.retained_members(), before);
}

#[test]
fn distinct_replacement_reclaim_is_adopted_without_replacing_initial_buffer() {
    let graph = graph();
    let before = graph.initial_members().to_vec();
    let replacement = allocation(0xc000, 51);
    let changes = TerminalChanges {
        reclaim: Some(replacement),
        transfer_data: None,
    };
    let entered = graph.prepare_terminal(changes).unwrap().enter();
    assert_eq!(entered.source(), source());
    assert_eq!(entered.initial_members(), before);
    assert_eq!(entered.changes(), changes);

    // Keeping this non-Copy entered value is the uncertain-effect path. Only explicit
    // settlement below advances bookkeeping; there is no abort or prepare-again operation.
    let entered = Some(entered);
    assert_eq!(entered.as_ref().unwrap().initial_members(), before);
    let settled = entered.unwrap().settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.retained_members()[0].allocation, replacement);
    assert_eq!(settled.retained_members()[0].roles, GraphRoles::RECLAIM);
    assert_eq!(&settled.retained_members()[1..], before);
    assert!(settled.transferred_members().is_empty());
}

#[test]
fn reclaim_alias_releases_once_and_does_not_rewrite_initial_roles() {
    let graph = graph();
    let before = graph.initial_members().to_vec();
    let settled = graph
        .prepare_terminal(TerminalChanges {
            reclaim: Some(members()[2]),
            transfer_data: None,
        })
        .unwrap()
        .enter()
        .settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.retained_members().len(), before.len());
    assert_eq!(settled.retained_members()[0].allocation, members()[2]);
    assert_eq!(
        settled.retained_members()[0].roles,
        GraphRoles::DATA | GraphRoles::RECLAIM
    );
}

#[test]
fn filter_result_transfer_removes_only_exact_data_from_terminal_retirement() {
    let graph = graph();
    let before = graph.initial_members().to_vec();
    let changes = TerminalChanges {
        reclaim: None,
        transfer_data: Some(members()[2]),
    };
    let settled = graph.prepare_terminal(changes).unwrap().enter().settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.transferred_members(), &before[2..3]);
    assert_eq!(
        settled.retained_members(),
        [before[0], before[1], before[3]]
    );
}

#[test]
fn rejected_terminal_changes_return_the_original_graph_for_every_refusal() {
    for changes in [
        TerminalChanges {
            reclaim: Some(allocation(0xc000, 0)),
            transfer_data: None,
        },
        TerminalChanges {
            reclaim: Some(SourcePoolAllocationIdentity {
                capacity: u64::MAX,
                ..allocation(0xc000, 51)
            }),
            transfer_data: None,
        },
        TerminalChanges {
            reclaim: Some(allocation(0x3000, 99)),
            transfer_data: None,
        },
        TerminalChanges {
            reclaim: Some(allocation(0x3040, 99)),
            transfer_data: None,
        },
        TerminalChanges {
            reclaim: Some(SourcePoolAllocationIdentity {
                capacity: 0x40,
                ..members()[2]
            }),
            transfer_data: None,
        },
        TerminalChanges {
            reclaim: None,
            transfer_data: Some(allocation(0x3000, 99)),
        },
        TerminalChanges {
            reclaim: None,
            transfer_data: Some(members()[0]),
        },
        TerminalChanges {
            reclaim: None,
            transfer_data: Some(allocation(0xc000, 51)),
        },
        TerminalChanges {
            reclaim: Some(members()[2]),
            transfer_data: Some(members()[2]),
        },
    ] {
        let original = graph();
        let before = original.initial_members().to_vec();
        let rejected = original.prepare_terminal(changes).unwrap_err();
        assert_eq!(rejected.changes(), changes);
        let recovered = rejected.into_graph();
        assert_eq!(recovered.source(), source());
        assert_eq!(recovered.initial_members(), before);
        let settled = recovered
            .prepare_terminal(unchanged())
            .unwrap()
            .enter()
            .settle();
        assert_eq!(settled.retained_members(), before);
    }
}

#[test]
fn structural_data_alias_cannot_transfer_the_packet_mdl_file_or_name_owner() {
    for structural in [pointers().irp, pointers().mdl, 0xa000, 0xb000] {
        let mut pointers = pointers();
        pointers.data = structural;
        pointers.file_object = 0xa000;
        pointers.owns_file = true;
        let supplied = [
            members()[0],
            members()[1],
            members()[3],
            allocation(0xa000, 40),
            allocation(0xb000, 41),
        ];
        let graph = CapturedGraph::capture(source(), pointers, 0xb000, &supplied).unwrap();
        let before = graph.initial_members().to_vec();
        let transfer = before
            .iter()
            .find(|row| row.allocation.component_address == structural)
            .unwrap()
            .allocation;
        let rejected = graph
            .prepare_terminal(TerminalChanges {
                reclaim: None,
                transfer_data: Some(transfer),
            })
            .unwrap_err();
        assert_eq!(rejected.into_graph().initial_members(), before);
    }
}

#[test]
fn prepared_abort_restores_capture_and_does_not_apply_proposed_handoffs() {
    let original = graph();
    let before = original.initial_members().to_vec();
    let proposed = TerminalChanges {
        reclaim: Some(allocation(0xc000, 51)),
        transfer_data: Some(members()[2]),
    };
    let prepared = original.prepare_terminal(proposed).unwrap();
    let recovered = prepared.abort();
    assert_eq!(recovered.initial_members(), before);
    let settled = recovered
        .prepare_terminal(unchanged())
        .unwrap()
        .enter()
        .settle();
    assert_eq!(settled.retained_members(), before);
    assert!(settled.transferred_members().is_empty());
}

#[test]
fn aliased_data_and_auxiliary_buffer_transfer_as_one_exact_member() {
    let mut pointers = pointers();
    pointers.aux_data = pointers.data;
    let supplied = [members()[0], members()[2], members()[3]];
    let graph = CapturedGraph::capture(source(), pointers, 0, &supplied).unwrap();
    let before = graph.initial_members().to_vec();
    let settled = graph
        .prepare_terminal(TerminalChanges {
            reclaim: Some(allocation(0xc000, 51)),
            transfer_data: Some(members()[2]),
        })
        .unwrap()
        .enter()
        .settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.transferred_members(), &before[1..2]);
    assert_eq!(settled.retained_members().len(), 3);
    assert_eq!(settled.retained_members()[1..], [before[0], before[2]]);
}

#[test]
fn full_initial_inventory_has_room_for_file_name_and_terminal_replacement() {
    let pointers = PendingIrpGraphPointers {
        mdl: 0x1000,
        aux_data: 0x2000,
        data: 0x3000,
        create_parameters: 0x4000,
        create_access_state: 0x5000,
        create_security_context: 0x6000,
        pnp_resource_list: 0x7000,
        irp: 0x9000,
        file_object: 0xa000,
        owns_file: true,
        reclaim: 0,
    };
    let supplied = [
        allocation(0x1000, 11),
        allocation(0x2000, 12),
        allocation(0x3000, 13),
        allocation(0x4000, 14),
        allocation(0x5000, 15),
        allocation(0x6000, 16),
        allocation(0x7000, 17),
        allocation(0x9000, 29),
        allocation(0xa000, 40),
        allocation(0xb000, 41),
    ];
    let graph = CapturedGraph::capture(source(), pointers, 0xb000, &supplied).unwrap();
    let before = graph.initial_members().to_vec();
    assert_eq!(before.len(), 10);
    let replacement = allocation(0xc000, 51);
    let settled = graph
        .prepare_terminal(TerminalChanges {
            reclaim: Some(replacement),
            transfer_data: None,
        })
        .unwrap()
        .enter()
        .settle();
    assert_eq!(settled.initial_members(), before);
    assert_eq!(settled.retained_members().len(), 11);
    assert_eq!(settled.retained_members()[0].allocation, replacement);
    assert_eq!(settled.retained_members()[1..], before);
}

#[test]
fn inventory_prevalidation_needs_real_allocation_but_no_source_ticket() {
    let allocation = source().allocation();
    let inventory = PreparedInventory::prepare(allocation, pointers(), 0, &members()).unwrap();
    assert_eq!(inventory.source_allocation(), allocation);
    assert_eq!(inventory.initial_members(), graph().initial_members());

    let mut stale = members();
    stale[3].pool_generation += 1;
    assert!(PreparedInventory::prepare(allocation, pointers(), 0, &stale).is_err());
    assert!(PreparedInventory::prepare(allocation, pointers(), 0, &members()[..3]).is_err());
    let mut invalid = allocation;
    invalid.stack_count = 0;
    assert!(PreparedInventory::prepare(invalid, pointers(), 0, &members()).is_err());
}

#[test]
fn binding_actual_registered_source_preserves_prevalidated_inventory() {
    let allocation = source().allocation();
    let inventory = PreparedInventory::prepare(allocation, pointers(), 0, &members()).unwrap();
    let before = inventory.initial_members().to_vec();
    let mut ledger = crate::source_irp_ledger::SourceIrpLedger::new();
    let ticket = ledger.register(allocation).unwrap();
    let registered = SourceIrpForwardIdentity::new(ticket, allocation).unwrap();
    let graph = inventory.bind(registered).unwrap();
    assert_eq!(graph.source(), registered);
    assert_eq!(graph.initial_members(), before);
    assert_eq!(
        ledger.registered(
            allocation.owner,
            allocation.domain,
            allocation.component_address
        ),
        Some((ticket, allocation))
    );
}

#[test]
fn wrong_source_binding_returns_the_same_inventory_without_losing_registration() {
    let original = source().allocation();
    for changed in [
        SourceIrpAllocation {
            pool_generation: 30,
            ..original
        },
        SourceIrpAllocation {
            component_address: 0xa000,
            ..original
        },
        SourceIrpAllocation {
            bytes: 0x61,
            ..original
        },
        SourceIrpAllocation {
            stack_count: 2,
            ..original
        },
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedCaller(3),
            ..original
        },
        SourceIrpAllocation {
            domain: HostedDomainIdentity {
                cookie: original.domain.cookie + 1,
                ..original.domain
            },
            ..original
        },
    ] {
        let inventory = PreparedInventory::prepare(original, pointers(), 0, &members()).unwrap();
        let before = inventory.initial_members().to_vec();
        let mut ledger = crate::source_irp_ledger::SourceIrpLedger::new();
        let wrong_ticket = ledger.register(changed).unwrap();
        let wrong = SourceIrpForwardIdentity::new(wrong_ticket, changed).unwrap();
        let rejected = inventory.bind(wrong).unwrap_err();
        assert_eq!(rejected.source(), wrong);
        let inventory = rejected.into_inventory();
        assert_eq!(inventory.source_allocation(), original);
        assert_eq!(inventory.initial_members(), before);
        assert_eq!(
            ledger.registered(changed.owner, changed.domain, changed.component_address),
            Some((wrong_ticket, changed))
        );

        let mut exact_ledger = crate::source_irp_ledger::SourceIrpLedger::new();
        let ticket = exact_ledger.register(original).unwrap();
        let exact = SourceIrpForwardIdentity::new(ticket, original).unwrap();
        let graph = inventory.bind(exact).unwrap();
        assert_eq!(graph.source(), exact);
        assert_eq!(graph.initial_members(), before);
    }
}
