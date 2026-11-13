use nt_io_abi::{
    select_scsi_coherent_controller, ScsiControllerAuthority, ScsiControllerCandidate,
};

fn accepted_relation() -> ScsiControllerAuthority {
    ScsiControllerAuthority {
        child_pdo: 0x1200,
        relation_generation: 7,
        parent_pdo: 0x2300,
        parent_generation: 11,
        provider_domain_id: 3,
        provider_cookie: 0x45,
    }
}

fn controller() -> ScsiControllerCandidate {
    let relation = accepted_relation();
    ScsiControllerCandidate {
        controller_device_id: 0x3400,
        child_pdo: relation.child_pdo,
        relation_generation: relation.relation_generation,
        parent_pdo: relation.parent_pdo,
        parent_generation: relation.parent_generation,
        provider_domain_id: relation.provider_domain_id,
        provider_cookie: relation.provider_cookie,
        window_lease_id: 0x56,
        window_generation: relation.parent_generation,
        grant_va: 0x100_000,
        broker_va: 0x200_000,
        grant_length: 0x20_000,
        grant_logical: 0x80_000,
        live: true,
    }
}

#[test]
fn accepted_child_selects_only_its_exact_live_controller_and_window() {
    let exact = controller();
    let candidates = [
        ScsiControllerCandidate { child_pdo: 0x1201, ..exact },
        ScsiControllerCandidate { parent_pdo: 0x2301, ..exact },
        ScsiControllerCandidate { provider_cookie: 0x46, ..exact },
        ScsiControllerCandidate { window_lease_id: 0, ..exact },
        exact,
    ];
    assert_eq!(
        select_scsi_coherent_controller(accepted_relation(), &candidates),
        Some(exact)
    );
}

#[test]
fn stale_or_ambiguous_parent_authority_never_selects_a_dma_window() {
    let relation = accepted_relation();
    let exact = controller();
    for stale in [
        ScsiControllerAuthority { child_pdo: 0x1201, ..relation },
        ScsiControllerAuthority { relation_generation: 8, ..relation },
        ScsiControllerAuthority { parent_pdo: 0x2301, ..relation },
        ScsiControllerAuthority { parent_generation: 12, ..relation },
        ScsiControllerAuthority { provider_domain_id: 4, ..relation },
        ScsiControllerAuthority { provider_cookie: 0x46, ..relation },
    ] {
        assert_eq!(select_scsi_coherent_controller(stale, &[exact]), None);
    }
    for unavailable in [
        ScsiControllerCandidate { live: false, ..exact },
        ScsiControllerCandidate { controller_device_id: 0, ..exact },
        ScsiControllerCandidate { window_lease_id: 0, ..exact },
        ScsiControllerCandidate { window_generation: 12, ..exact },
        ScsiControllerCandidate { grant_va: 0, ..exact },
        ScsiControllerCandidate { broker_va: 0, ..exact },
        ScsiControllerCandidate { grant_length: 0, ..exact },
        ScsiControllerCandidate { grant_logical: u64::MAX, ..exact },
    ] {
        assert_eq!(select_scsi_coherent_controller(relation, &[unavailable]), None);
    }
    assert_eq!(select_scsi_coherent_controller(relation, &[exact, exact]), None);
}
