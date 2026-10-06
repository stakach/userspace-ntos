use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpLedger, SourceIrpLedgerError, SourceIrpOwner,
    SourceIrpRetirement, SourcePoolFreeAdmission,
};
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

fn allocation(owner: SourceIrpOwner) -> SourceIrpAllocation {
    SourceIrpAllocation {
        owner,
        domain: HostedDomainIdentity {
            domain_id: HostedDomainId(7),
            cookie: 11,
        },
        component_address: 0x2000,
        bytes: 0x128,
        stack_count: 2,
        pool_generation: 1,
    }
}

#[test]
fn caller_storage_stays_protected_through_pin_and_uncertain_retirement() {
    let mut ledger = SourceIrpLedger::new();
    let caller = allocation(SourceIrpOwner::HostedCaller(3));
    let ticket = ledger.register(caller).unwrap();
    let check = |ledger: &SourceIrpLedger| {
        assert_eq!(
            ledger.pool_free_admission(3, caller.domain, caller.component_address),
            Ok(SourcePoolFreeAdmission::Protected(caller))
        );
        assert!(ledger.matches(caller.owner, caller, ticket));
        assert_eq!(ledger.live_for_owner(caller.owner, caller.domain), 1);
    };
    check(&ledger);
    assert_eq!(
        ledger.pin(caller.owner, caller.domain, caller.component_address),
        Ok((ticket, caller))
    );
    check(&ledger);
    assert_eq!(
        ledger.begin_hosted_caller_retirement(ticket, caller),
        Err(SourceIrpLedgerError::Pinned)
    );
    check(&ledger);
    ledger.unpin(ticket).unwrap();
    ledger
        .begin_hosted_caller_retirement(ticket, caller)
        .unwrap();
    // Op7 closes new pins; it does not acknowledge physical teardown or authorize pool free.
    check(&ledger);
    assert_eq!(
        ledger.pin(caller.owner, caller.domain, caller.component_address),
        Err(SourceIrpLedgerError::RetirementStarted)
    );
    check(&ledger);
    ledger
        .finish_hosted_caller_retirement(ticket, caller)
        .unwrap();
    assert_eq!(
        ledger.pool_free_admission(3, caller.domain, caller.component_address),
        Ok(SourcePoolFreeAdmission::Unregistered)
    );
}

#[test]
fn only_exact_driver_instance_gets_driver_retirement_authority() {
    let mut ledger = SourceIrpLedger::new();
    let driver = allocation(SourceIrpOwner::HostedDriver(3));
    let ticket = ledger.register(driver).unwrap();
    assert_eq!(
        ledger.pool_free_admission(4, driver.domain, driver.component_address),
        Ok(SourcePoolFreeAdmission::Protected(driver))
    );
    assert_eq!(
        ledger.prepare_driver_free(4, driver.domain, driver.component_address),
        Err(SourceIrpLedgerError::NotFound)
    );
    assert!(ledger.matches(driver.owner, driver, ticket));
    assert_eq!(
        ledger.pool_free_admission(3, driver.domain, driver.component_address),
        Ok(SourcePoolFreeAdmission::DriverOwned(driver))
    );
    ledger
        .pin(driver.owner, driver.domain, driver.component_address)
        .unwrap();
    assert_eq!(
        ledger.pool_free_admission(3, driver.domain, driver.component_address),
        Ok(SourcePoolFreeAdmission::DriverOwned(driver))
    );
    assert_eq!(
        ledger.prepare_driver_free(3, driver.domain, driver.component_address),
        Err(SourceIrpLedgerError::Pinned)
    );
    assert!(ledger.matches(driver.owner, driver, ticket));
    ledger.unpin(ticket).unwrap();
    assert_eq!(
        ledger.prepare_driver_free(3, driver.domain, driver.component_address),
        Ok(SourceIrpRetirement::Retired(ticket))
    );
    assert_eq!(
        ledger.pool_free_admission(3, driver.domain, driver.component_address),
        Ok(SourcePoolFreeAdmission::DriverOwned(driver))
    );
    ledger.retire(ticket, driver).unwrap();
    assert_eq!(
        ledger.pool_free_admission(3, driver.domain, driver.component_address),
        Ok(SourcePoolFreeAdmission::Unregistered)
    );
}

#[test]
fn unrelated_physical_domain_or_address_is_unregistered_without_mutating_owner() {
    let mut ledger = SourceIrpLedger::new();
    let owned = allocation(SourceIrpOwner::Win32k);
    let ticket = ledger.register(owned).unwrap();
    for domain in [
        HostedDomainIdentity {
            cookie: owned.domain.cookie + 1,
            ..owned.domain
        },
        HostedDomainIdentity {
            domain_id: HostedDomainId(8),
            ..owned.domain
        },
    ] {
        assert_eq!(
            ledger.pool_free_admission(3, domain, owned.component_address),
            Ok(SourcePoolFreeAdmission::Unregistered)
        );
    }
    assert_eq!(
        ledger.pool_free_admission(3, owned.domain, owned.component_address + 0x1000),
        Ok(SourcePoolFreeAdmission::Unregistered)
    );
    assert_eq!(
        ledger.pool_free_admission(3, owned.domain, owned.component_address),
        Ok(SourcePoolFreeAdmission::Protected(owned))
    );
    assert!(ledger.matches(owned.owner, owned, ticket));
    assert_eq!(ledger.live_for_owner(owned.owner, owned.domain), 1);
}

#[test]
fn ambiguous_physical_address_never_grants_either_owner_free_authority() {
    for other_owner in [
        SourceIrpOwner::HostedCaller(3),
        SourceIrpOwner::HostedDriver(4),
        SourceIrpOwner::Win32k,
    ] {
        let mut ledger = SourceIrpLedger::new();
        let driver = allocation(SourceIrpOwner::HostedDriver(3));
        let other = SourceIrpAllocation {
            owner: other_owner,
            pool_generation: 2,
            ..driver
        };
        let first = ledger.register(driver).unwrap();
        // Existing registration keys include owner: admission must inspect all physical matches.
        let second = ledger.register(other).unwrap();
        for instance in [3, 4, 9] {
            assert_eq!(
                ledger.pool_free_admission(instance, driver.domain, driver.component_address),
                Err(SourceIrpLedgerError::WrongIdentity)
            );
            assert!(ledger.matches(driver.owner, driver, first));
            assert!(ledger.matches(other.owner, other, second));
            assert_eq!(ledger.live_for_owner(driver.owner, driver.domain), 1);
            assert_eq!(ledger.live_for_owner(other.owner, other.domain), 1);
        }
    }
}

#[test]
fn deferred_driver_free_state_is_not_changed_by_admission_observation() {
    let mut ledger = SourceIrpLedger::new();
    let driver = allocation(SourceIrpOwner::HostedDriver(3));
    let ticket = ledger.register(driver).unwrap();
    ledger
        .pin(driver.owner, driver.domain, driver.component_address)
        .unwrap();
    ledger.arm_deferred_free(ticket).unwrap();
    assert_eq!(
        ledger.prepare_driver_free(3, driver.domain, driver.component_address),
        Ok(SourceIrpRetirement::Deferred(ticket))
    );
    assert!(ledger.deferred_free_requested(ticket));
    for _ in 0..2 {
        assert_eq!(
            ledger.pool_free_admission(3, driver.domain, driver.component_address),
            Ok(SourcePoolFreeAdmission::DriverOwned(driver))
        );
        assert_eq!(
            ledger.pool_free_admission(4, driver.domain, driver.component_address),
            Ok(SourcePoolFreeAdmission::Protected(driver))
        );
        assert!(ledger.deferred_free_requested(ticket));
        assert!(ledger.matches(driver.owner, driver, ticket));
    }
    assert_eq!(
        ledger.prepare_driver_free(3, driver.domain, driver.component_address),
        Err(SourceIrpLedgerError::AlreadyDeferred)
    );
}
