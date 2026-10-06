//! Contract tests only: native receipt/free/unload hooks and source-graph transfer are separate.
//! Request scalars correlate an already-retained source; they do not manufacture an IRP pin.
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::source_irp_ledger::{SourceIrpLedger, SourceIrpOwner};
use nt_pnp_manager::returned_pnp_buffer::{
    BufferOrigin, BufferPhase, PhysicalPoolArena, ReleaseResult, ReturnedAllocation,
    ReturnedPnpBufferCatalog, ReturnedPnpBufferError, ReturnedPnpQuery, ReturnedPnpRequest,
    TerminalOutcome,
};
use std::sync::atomic::Ordering;

#[path = "returned_pnp_buffer/fixture.rs"]
mod fixture;
use fixture::{
    allocation, domain, other_request, request, source, TargetFixture, ALLOCATION_CHILD,
    NOT_SUPPORTED, PENDING, REFUSE, REQUESTS, SUCCESS,
};

#[test]
fn identical_inflight_request_cannot_gain_second_publication_or_release_authority() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let returned = allocation();
    let ticket = catalog.prepare(request).unwrap();
    let prepared = catalog.snapshot(ticket).unwrap();
    assert!(catalog.prepare(request).is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), prepared);
    assert!(catalog.blocks_arena_teardown(request.source_arena));
    assert!(catalog.blocks_arena_teardown(request.expected_allocator));
    catalog
        .publish_terminal(
            ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned),
        )
        .unwrap();
    let published = catalog.snapshot(ticket).unwrap();
    assert!(catalog.prepare(request).is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), published);
    assert!(!catalog.blocks_arena_teardown(request.source_arena));
    assert!(catalog.blocks_arena_teardown(request.expected_allocator));
    let release = catalog.begin_release(ticket, returned).unwrap();
    catalog
        .observe_release(release, ReleaseResult::Uncertain)
        .unwrap();
    let retained = catalog.snapshot(ticket).unwrap();
    assert!(catalog.prepare(request).is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), retained);
    assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    assert!(!catalog.blocks_arena_teardown(request.source_arena));
    assert!(catalog.blocks_arena_teardown(request.expected_allocator));
}

#[test]
fn distinct_irps_cannot_adopt_same_or_overlapping_retained_physical_allocation() {
    let original = allocation();
    let mut conflicting = Vec::new();
    conflicting.push(original);
    conflicting.push(ReturnedAllocation {
        pool: SourcePoolAllocationIdentity {
            pool_generation: 22,
            ..original.pool
        },
        ..original
    });
    conflicting.push(ReturnedAllocation {
        pool: SourcePoolAllocationIdentity {
            capacity: 128,
            ..original.pool
        },
        ..original
    });
    for base in [
        original.pool.component_address - 32,
        original.pool.component_address + 32,
    ] {
        conflicting.push(ReturnedAllocation {
            pool: SourcePoolAllocationIdentity {
                component_address: base,
                ..original.pool
            },
            ..original
        });
    }
    for releasing in [false, true] {
        for conflict in &conflicting {
            let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
            let first_request = request();
            let second_request = other_request();
            let first_ticket = catalog.prepare(first_request).unwrap();
            let second_ticket = catalog.prepare(second_request).unwrap();
            catalog
                .publish_terminal(
                    first_ticket,
                    first_request,
                    SUCCESS,
                    original.pool.component_address,
                    Some(original),
                )
                .unwrap();
            if releasing {
                let release = catalog.begin_release(first_ticket, original).unwrap();
                catalog
                    .observe_release(release, ReleaseResult::Uncertain)
                    .unwrap();
            }
            let first_before = catalog.snapshot(first_ticket).unwrap();
            let second_before = catalog.snapshot(second_ticket).unwrap();
            assert!(catalog
                .publish_terminal(
                    second_ticket,
                    second_request,
                    SUCCESS,
                    conflict.pool.component_address,
                    Some(*conflict)
                )
                .is_err());
            assert_eq!(catalog.snapshot(first_ticket).unwrap(), first_before);
            assert_eq!(catalog.snapshot(second_ticket).unwrap(), second_before);
            assert_eq!(second_before.phase, BufferPhase::Prepared);
            assert!(catalog.blocks_pool_free(original.arena, original.pool.component_address));
            assert!(catalog.blocks_arena_teardown(first_request.source_arena));
            assert!(catalog.blocks_arena_teardown(second_request.source_arena));
            assert!(catalog.blocks_arena_teardown(second_request.expected_allocator));
        }
    }
}

#[test]
fn same_numeric_buffer_address_is_independent_in_distinct_physical_arenas() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let first_request = request();
    let first = allocation();
    let second_arena = PhysicalPoolArena {
        domain: domain(10, 100),
        pml4: 0x3000,
        pool_frame_base: 0x4000,
        exec_pool_va: 0x200000,
    };
    let second_request = ReturnedPnpRequest {
        expected_allocator: second_arena,
        ..other_request()
    };
    let second = ReturnedAllocation {
        arena: second_arena,
        ..first
    };
    let first_ticket = catalog.prepare(first_request).unwrap();
    let second_ticket = catalog.prepare(second_request).unwrap();
    for (ticket, request, returned) in [
        (first_ticket, first_request, first),
        (second_ticket, second_request, second),
    ] {
        assert_eq!(
            catalog
                .publish_terminal(
                    ticket,
                    request,
                    SUCCESS,
                    returned.pool.component_address,
                    Some(returned)
                )
                .unwrap(),
            TerminalOutcome::Published(ticket)
        );
        assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    }
    let first_release = catalog.begin_release(first_ticket, first).unwrap();
    catalog
        .observe_release(first_release, ReleaseResult::Acknowledged)
        .unwrap();
    assert!(!catalog.blocks_pool_free(first.arena, first.pool.component_address));
    assert!(catalog.blocks_pool_free(second.arena, second.pool.component_address));
    assert_eq!(
        catalog.snapshot(second_ticket).unwrap().allocation,
        Some(second)
    );
}

#[test]
fn prepared_refusal_retains_exact_request_and_both_physical_arena_fences() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let ticket = catalog.prepare(request).unwrap();
    let before = catalog.snapshot(ticket).unwrap();
    assert_eq!(before.phase, BufferPhase::Prepared);
    assert_eq!(before.request, request);
    assert!(catalog.blocks_arena_teardown(request.source_arena));
    assert!(catalog.blocks_arena_teardown(request.expected_allocator));
    // Source provenance is physical; a returned buffer may use a different allocator.
    assert_eq!(request.source.domain, request.source_arena.domain);
    assert_ne!(request.source.domain, request.expected_allocator.domain);
    let mut wrong = request;
    wrong.canonical_irp_id += 1;
    assert!(catalog
        .publish_terminal(
            ticket,
            wrong,
            SUCCESS,
            allocation().pool.component_address,
            Some(allocation())
        )
        .is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), before);
    assert!(catalog
        .publish_terminal(
            ticket,
            request,
            PENDING,
            allocation().pool.component_address,
            Some(allocation())
        )
        .is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), before);
    assert!(catalog.retire_no_buffer(ticket).is_err());
    assert_eq!(catalog.snapshot(ticket).unwrap(), before);
}

#[test]
fn every_request_identity_dimension_must_match_before_terminal_publication() {
    let original = request();
    let mut variants = Vec::new();
    let mut changed = original;
    changed.source_ticket = SourceIrpTicket::new(original.source.domain, 17, 8).unwrap();
    variants.push(changed);
    let mut changed = original;
    changed.source.pool_generation += 1;
    variants.push(changed);
    let mut changed = original;
    changed.source.owner = SourceIrpOwner::HostedDriver(4);
    variants.push(changed);
    let mut changed = original;
    changed.source.domain.cookie += 1;
    variants.push(changed);
    let mut changed = original;
    changed.source.component_address += 1;
    variants.push(changed);
    let mut changed = original;
    changed.source.bytes += 1;
    variants.push(changed);
    let mut changed = original;
    changed.source.stack_count += 1;
    variants.push(changed);
    let mut changed = original;
    changed.source_arena.pml4 += 1;
    variants.push(changed);
    let mut changed = original;
    changed.expected_allocator.exec_pool_va += 1;
    variants.push(changed);
    let mut changed = original;
    changed.parent_devnode += 1;
    variants.push(changed);
    let mut changed = original;
    changed.parent_generation += 1;
    variants.push(changed);
    let mut changed = original;
    changed.query = ReturnedPnpQuery::QueryId { id_type: 0 };
    variants.push(changed);
    for wrong in variants {
        let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
        let ticket = catalog.prepare(original).unwrap();
        let before = catalog.snapshot(ticket).unwrap();
        assert!(catalog
            .publish_terminal(
                ticket,
                wrong,
                SUCCESS,
                allocation().pool.component_address,
                Some(allocation())
            )
            .is_err());
        assert_eq!(catalog.snapshot(ticket).unwrap(), before);
    }
}

#[test]
fn terminal_publication_checks_entire_minted_target_registration_not_public_getters_only() {
    let mut fixture = TargetFixture::new();
    let foreign_manager = TargetFixture::new();
    let original = ReturnedPnpRequest {
        target: fixture.target,
        ..request()
    };
    let foreign = foreign_manager.target;
    assert_eq!(foreign.domain(), original.target.domain());
    assert_eq!(foreign.address(), original.target.address());
    assert_eq!(foreign.device_id(), original.target.device_id());
    assert_eq!(foreign.generation(), original.target.generation());
    assert_ne!(
        foreign, original.target,
        "manager-local registration is not a tuple of public getters"
    );
    let mut variants = vec![foreign];
    let domain = original.target.domain();
    variants.push(fixture.another_device(domain, original.target.address() + 0x1000));
    let other_domain = fixture.io.register_hosted_domain();
    variants.push(
        fixture
            .io
            .bind_hosted_device_pointer(
                other_domain,
                original.target.address(),
                original.target.device_id(),
            )
            .unwrap(),
    );

    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let ticket = catalog.prepare(original).unwrap();
    let before = catalog.snapshot(ticket).unwrap();
    // Model a stale observed target and a newly minted registration at its numeric PDO address.
    // Native needs its active IRP/projection retirement fence or registered caller reference,
    // plus source/device owners and whole live-registration validation before effects. A detached
    // DeviceReference alone does not prevent this; the copied observation adds no owner or pin.
    fixture
        .io
        .retire_hosted_device_pointer(original.target)
        .unwrap();
    let replacement = fixture
        .io
        .bind_hosted_device_pointer(
            domain,
            original.target.address(),
            original.target.device_id(),
        )
        .unwrap();
    assert_eq!(replacement.domain(), original.target.domain());
    assert_eq!(replacement.address(), original.target.address());
    assert_eq!(replacement.device_id(), original.target.device_id());
    assert_ne!(replacement.generation(), original.target.generation());
    variants.push(replacement);
    fixture.io.retire_hosted_device_pointer(replacement).unwrap();
    variants.push(
        fixture
            .io
            .bind_hosted_device_pointer(
                domain,
                original.target.address() + 0x2000,
                original.target.device_id(),
            )
            .unwrap(),
    );
    for target in variants {
        let wrong = ReturnedPnpRequest { target, ..original };
        assert!(catalog
            .publish_terminal(
                ticket,
                wrong,
                SUCCESS,
                allocation().pool.component_address,
                Some(allocation())
            )
            .is_err());
        assert_eq!(catalog.snapshot(ticket).unwrap(), before);
        assert!(catalog.blocks_arena_teardown(original.source_arena));
        assert!(catalog.blocks_arena_teardown(original.expected_allocator));
    }
    assert_ne!(
        original.target.domain(),
        original.expected_allocator.domain,
        "a PDO projection does not identify the physical result allocator"
    );
}

#[test]
fn invalid_prepare_never_publishes_an_arena_fence() {
    let original = request();
    let mut variants = Vec::new();
    let mut changed = original;
    changed.source.domain.cookie = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source.domain = domain(8, 80);
    variants.push(changed);
    let mut changed = original;
    changed.source_arena.domain = domain(8, 80);
    variants.push(changed);
    let mut changed = original;
    changed.source.component_address = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source.bytes = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source.pool_generation = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source.stack_count = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source.component_address = u64::MAX;
    variants.push(changed);
    let mut changed = original;
    changed.parent_devnode = 0;
    variants.push(changed);
    let mut changed = original;
    changed.parent_generation = 0;
    variants.push(changed);
    let mut changed = original;
    changed.canonical_irp_id = 0;
    variants.push(changed);
    let mut changed = original;
    changed.expected_allocator.domain.cookie = 0;
    variants.push(changed);
    let mut changed = original;
    changed.expected_allocator.pml4 = 0;
    variants.push(changed);
    let mut changed = original;
    changed.expected_allocator.pool_frame_base = 0;
    variants.push(changed);
    let mut changed = original;
    changed.expected_allocator.exec_pool_va = 0;
    variants.push(changed);
    let mut changed = original;
    changed.source_arena.pml4 = 0;
    variants.push(changed);
    for invalid in variants {
        let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
        assert!(catalog.prepare(invalid).is_err());
        assert!(!catalog.blocks_arena_teardown(original.source_arena));
        assert!(!catalog.blocks_arena_teardown(original.expected_allocator));
    }
}

#[test]
fn adoption_requires_exact_base_extent_generation_and_expected_physical_arena() {
    let valid = allocation();
    let mut variants = Vec::new();
    let mut changed = valid;
    changed.pool.component_address = 0;
    variants.push(changed);
    let mut changed = valid;
    changed.pool.capacity = 0;
    variants.push(changed);
    let mut changed = valid;
    changed.pool.pool_generation = 0;
    variants.push(changed);
    let mut changed = valid;
    changed.pool.component_address = u64::MAX;
    variants.push(changed);
    let mut changed = valid;
    changed.arena.domain = domain(9, 91);
    variants.push(changed);
    let mut changed = valid;
    changed.arena.pml4 += 1;
    variants.push(changed);
    let mut changed = valid;
    changed.arena.pool_frame_base += 1;
    variants.push(changed);
    let mut changed = valid;
    changed.arena.exec_pool_va += 1;
    variants.push(changed);
    for invalid in variants {
        let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
        let request = request();
        let ticket = catalog.prepare(request).unwrap();
        let before = catalog.snapshot(ticket).unwrap();
        assert!(catalog
            .publish_terminal(
                ticket,
                request,
                SUCCESS,
                invalid.pool.component_address,
                Some(invalid)
            )
            .is_err());
        assert_eq!(catalog.snapshot(ticket).unwrap(), before);
    }
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let ticket = catalog.prepare(request).unwrap();
    for information in [valid.pool.component_address + 2, 0] {
        assert!(catalog
            .publish_terminal(ticket, request, SUCCESS, information, Some(valid))
            .is_err());
        assert_eq!(
            catalog.snapshot(ticket).unwrap().phase,
            BufferPhase::Prepared
        );
    }
    assert!(catalog
        .publish_terminal(ticket, request, SUCCESS, valid.pool.component_address, None)
        .is_err());
    assert_eq!(
        catalog.snapshot(ticket).unwrap().phase,
        BufferPhase::Prepared
    );
}

#[test]
fn null_and_error_are_nonreplayable_terminals_until_explicit_no_buffer_retirement() {
    for status in [SUCCESS, NOT_SUPPORTED] {
        let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
        let request = request();
        let ticket = catalog.prepare(request).unwrap();
        let information = if status == SUCCESS { 0 } else { u64::MAX };
        let observed = if status == SUCCESS {
            None
        } else {
            Some(allocation())
        };
        let result = catalog
            .publish_terminal(ticket, request, status, information, observed)
            .unwrap();
        assert_eq!(
            result,
            if status == SUCCESS {
                TerminalOutcome::NoBuffer
            } else {
                TerminalOutcome::Failed(status)
            }
        );
        let terminal = catalog.snapshot(ticket).unwrap();
        assert_eq!(terminal.phase, BufferPhase::TerminalNoBuffer { status });
        assert_eq!(
            terminal.allocation, None,
            "failure Information is never adopted"
        );
        assert!(catalog
            .publish_terminal(
                ticket,
                request,
                SUCCESS,
                allocation().pool.component_address,
                Some(allocation())
            )
            .is_err());
        assert_eq!(catalog.snapshot(ticket).unwrap(), terminal);
        assert!(catalog.begin_release(ticket, allocation()).is_err());
        assert!(!catalog.blocks_pool_free(allocation().arena, allocation().pool.component_address));
        catalog.retire_no_buffer(ticket).unwrap();
        assert!(catalog.snapshot(ticket).is_err());
        assert!(!catalog.blocks_arena_teardown(request.source_arena));
        assert!(!catalog.blocks_arena_teardown(request.expected_allocator));
        assert!(catalog.retire_no_buffer(ticket).is_err());
    }
}

#[test]
fn nonnull_empty_buffer_still_owns_exact_storage_until_release_ack() {
    // Capacity for a single WCHAR NUL remains a pool allocation; content decoding is separate.
    let returned = ReturnedAllocation {
        pool: SourcePoolAllocationIdentity {
            capacity: 2,
            ..allocation().pool
        },
        ..allocation()
    };
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let ticket = catalog.prepare(request).unwrap();
    assert_eq!(
        catalog
            .publish_terminal(
                ticket,
                request,
                SUCCESS,
                returned.pool.component_address,
                Some(returned)
            )
            .unwrap(),
        TerminalOutcome::Published(ticket)
    );
    let published = catalog.snapshot(ticket).unwrap();
    assert_eq!(published.phase, BufferPhase::Published);
    assert_eq!(published.allocation, Some(returned));
    assert!(catalog.retire_no_buffer(ticket).is_err());
    assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    let release = catalog.begin_release(ticket, returned).unwrap();
    assert_eq!(
        catalog.snapshot(ticket).unwrap().phase,
        BufferPhase::Releasing
    );
    assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    catalog
        .observe_release(release, ReleaseResult::Acknowledged)
        .unwrap();
    assert!(catalog.snapshot(ticket).is_err());
    assert!(!catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    assert!(catalog
        .observe_release(release, ReleaseResult::Acknowledged)
        .is_err());
}

#[test]
fn copied_source_provenance_does_not_require_the_packet_to_survive_buffer_ownership() {
    let mut source_ledger = SourceIrpLedger::new();
    let source = source();
    let source_ticket = source_ledger.register(source).unwrap();
    let request = ReturnedPnpRequest {
        source_ticket,
        source,
        ..request()
    };
    let returned = allocation();
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let ticket = catalog.prepare(request).unwrap();
    catalog
        .publish_terminal(
            ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned),
        )
        .unwrap();
    assert!(
        !catalog.blocks_arena_teardown(request.source_arena),
        "captured packet provenance is not an owning source-arena pin"
    );
    assert!(catalog.blocks_arena_teardown(returned.arena));
    // Model packet teardown ACK, not provider completion inferred from a transport Reply.
    source_ledger.retire(source_ticket, source).unwrap();
    assert_eq!(source_ledger.live_for_owner(source.owner, source.domain), 0);
    assert_eq!(catalog.snapshot(ticket).unwrap().request, request);
    assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
    let release = catalog.begin_release(ticket, returned).unwrap();
    catalog
        .observe_release(release, ReleaseResult::Acknowledged)
        .unwrap();
}

#[test]
fn uncertain_or_refused_release_retains_exact_owner_and_never_permits_replay() {
    for result in [ReleaseResult::Uncertain, ReleaseResult::Refused] {
        let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
        let request = request();
        let returned = allocation();
        let ticket = catalog.prepare(request).unwrap();
        catalog
            .publish_terminal(
                ticket,
                request,
                SUCCESS,
                returned.pool.component_address,
                Some(returned),
            )
            .unwrap();
        let release = catalog.begin_release(ticket, returned).unwrap();
        catalog.observe_release(release, result).unwrap();
        let retained = catalog.snapshot(ticket).unwrap();
        assert_eq!(retained.phase, BufferPhase::Releasing);
        assert_eq!(retained.allocation, Some(returned));
        assert!(catalog.begin_release(ticket, returned).is_err());
        assert!(catalog.retire_no_buffer(ticket).is_err());
        assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
        assert!(catalog.blocks_arena_teardown(returned.arena));
        assert_eq!(catalog.snapshot(ticket).unwrap(), retained);
        // A late real ACK for the same attempt may finish; it is not a new native free attempt.
        catalog
            .observe_release(release, ReleaseResult::Acknowledged)
            .unwrap();
    }
}

#[test]
fn tickets_and_release_tokens_are_catalog_local_even_for_identical_first_rows() {
    let mut first = ReturnedPnpBufferCatalog::new().unwrap();
    let mut second = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let returned = allocation();
    let first_ticket = first.prepare(request).unwrap();
    let second_ticket = second.prepare(request).unwrap();
    assert_ne!(first_ticket, second_ticket);
    assert!(second
        .publish_terminal(
            first_ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned)
        )
        .is_err());
    assert_eq!(
        second.snapshot(second_ticket).unwrap().phase,
        BufferPhase::Prepared
    );
    for (catalog, ticket) in [(&mut first, first_ticket), (&mut second, second_ticket)] {
        catalog
            .publish_terminal(
                ticket,
                request,
                SUCCESS,
                returned.pool.component_address,
                Some(returned),
            )
            .unwrap();
    }
    let first_release = first.begin_release(first_ticket, returned).unwrap();
    let second_release = second.begin_release(second_ticket, returned).unwrap();
    assert!(second
        .observe_release(first_release, ReleaseResult::Acknowledged)
        .is_err());
    assert!(first
        .observe_release(second_release, ReleaseResult::Acknowledged)
        .is_err());
    assert!(first.blocks_pool_free(returned.arena, returned.pool.component_address));
    assert!(second.blocks_pool_free(returned.arena, returned.pool.component_address));
    first
        .observe_release(first_release, ReleaseResult::Acknowledged)
        .unwrap();
    second
        .observe_release(second_release, ReleaseResult::Acknowledged)
        .unwrap();
}

#[test]
fn wrong_release_snapshot_and_stale_ticket_cannot_release_reused_numeric_storage() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let returned = allocation();
    let first_ticket = catalog.prepare(request).unwrap();
    catalog
        .publish_terminal(
            first_ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned),
        )
        .unwrap();
    let mut variants = Vec::new();
    let mut changed = returned;
    changed.pool.pool_generation += 1;
    variants.push(changed);
    let mut changed = returned;
    changed.pool.capacity += 1;
    variants.push(changed);
    let mut changed = returned;
    changed.arena.domain.cookie += 1;
    variants.push(changed);
    let mut changed = returned;
    changed.arena.pml4 += 1;
    variants.push(changed);
    let mut changed = returned;
    changed.arena.pool_frame_base += 1;
    variants.push(changed);
    let mut changed = returned;
    changed.arena.exec_pool_va += 1;
    variants.push(changed);
    let before = catalog.snapshot(first_ticket).unwrap();
    for wrong in variants {
        assert!(catalog.begin_release(first_ticket, wrong).is_err());
        assert_eq!(catalog.snapshot(first_ticket).unwrap(), before);
    }
    let stale_release = catalog.begin_release(first_ticket, returned).unwrap();
    catalog
        .observe_release(stale_release, ReleaseResult::Acknowledged)
        .unwrap();
    let reused = ReturnedAllocation {
        pool: SourcePoolAllocationIdentity {
            pool_generation: 22,
            ..returned.pool
        },
        ..returned
    };
    let second_ticket = catalog.prepare(request).unwrap();
    assert_ne!(first_ticket, second_ticket);
    catalog
        .publish_terminal(
            second_ticket,
            request,
            SUCCESS,
            reused.pool.component_address,
            Some(reused),
        )
        .unwrap();
    let before = catalog.snapshot(second_ticket).unwrap();
    assert!(catalog
        .observe_release(stale_release, ReleaseResult::Acknowledged)
        .is_err());
    assert!(catalog.begin_release(first_ticket, returned).is_err());
    assert_eq!(catalog.snapshot(second_ticket).unwrap(), before);
    assert!(catalog.blocks_pool_free(reused.arena, reused.pool.component_address));
}

#[test]
fn physical_arena_fences_do_not_confuse_equal_addresses_in_other_arenas() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let returned = allocation();
    let ticket = catalog.prepare(request).unwrap();
    catalog
        .publish_terminal(
            ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned),
        )
        .unwrap();
    let mut variants = Vec::new();
    let mut changed = returned.arena;
    changed.domain.cookie += 1;
    variants.push(changed);
    let mut changed = returned.arena;
    changed.pml4 += 1;
    variants.push(changed);
    let mut changed = returned.arena;
    changed.pool_frame_base += 1;
    variants.push(changed);
    let mut changed = returned.arena;
    changed.exec_pool_va += 1;
    variants.push(changed);
    for foreign in variants {
        assert!(!catalog.blocks_pool_free(foreign, returned.pool.component_address));
        assert!(!catalog.blocks_arena_teardown(foreign));
    }
    assert!(catalog.blocks_pool_free(returned.arena, returned.pool.component_address));
}

#[test]
fn source_graph_origin_requires_real_transfer_without_discarding_prepared_ownership() {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let request = request();
    let ticket = catalog.prepare(request).unwrap();
    let returned = ReturnedAllocation {
        origin: BufferOrigin::SourceGraphChild {
            source_ticket: request.source_ticket,
        },
        ..allocation()
    };
    assert_eq!(
        catalog.publish_terminal(
            ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned)
        ),
        Err(ReturnedPnpBufferError::RequiresSourceTransfer)
    );
    assert_eq!(
        catalog.snapshot(ticket).unwrap().phase,
        BufferPhase::Prepared
    );
    assert!(catalog.blocks_arena_teardown(request.source_arena));
    assert!(catalog.blocks_arena_teardown(request.expected_allocator));
    // The adapter must retain its graph owner and refuse graph retirement on this result.
    // This standalone catalog has not implemented, authorized, or simulated child transfer.
    // Origin is a trusted adapter classification under the authenticated graph owner, not a
    // provider-supplied tag. Known graph storage cannot be relabeled IndependentPool to bypass it.
}

#[test]
fn allocation_refusal_is_preentry_and_terminal_capture_needs_no_allocation() {
    if std::env::var_os(ALLOCATION_CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "allocation_refusal_is_preentry_and_terminal_capture_needs_no_allocation",
                "--nocapture",
            ])
            .env(ALLOCATION_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated owner allocation contract failed: {output:?}"
        );
        return;
    }
    let request = request();
    let returned = allocation();
    let mut empty = ReturnedPnpBufferCatalog::new().unwrap();
    REQUESTS.store(0, Ordering::Relaxed);
    REFUSE.store(true, Ordering::Relaxed);
    let refused = empty.prepare(request);
    REFUSE.store(false, Ordering::Relaxed);
    assert_eq!(refused, Err(ReturnedPnpBufferError::NoCapacity));
    assert!(
        REQUESTS.load(Ordering::Relaxed) > 0,
        "actual allocation refusal, not a fake row cap"
    );
    assert!(!empty.blocks_arena_teardown(request.source_arena));
    assert!(!empty.blocks_arena_teardown(request.expected_allocator));

    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let ticket = catalog.prepare(request).unwrap();
    REQUESTS.store(0, Ordering::Relaxed);
    REFUSE.store(true, Ordering::Relaxed);
    let captured = catalog.publish_terminal(
        ticket,
        request,
        SUCCESS,
        returned.pool.component_address,
        Some(returned),
    );
    let snapshot = catalog.snapshot(ticket);
    let release = catalog.begin_release(ticket, returned);
    let acknowledged =
        release.and_then(|token| catalog.observe_release(token, ReleaseResult::Acknowledged));
    REFUSE.store(false, Ordering::Relaxed);
    assert_eq!(
        REQUESTS.load(Ordering::Relaxed),
        0,
        "prepared terminal capture, exact snapshot, release intent and ACK must not allocate"
    );
    assert_eq!(captured, Ok(TerminalOutcome::Published(ticket)));
    assert_eq!(snapshot.unwrap().allocation, Some(returned));
    acknowledged.unwrap();
    assert!(catalog.snapshot(ticket).is_err());
}
