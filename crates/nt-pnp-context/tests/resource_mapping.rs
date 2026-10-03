use nt_pnp_context::{
    resource_mapping::{
        Admission, MappingDomain, MappingError, MappingKey, MappingOwner, MappingPhase,
        ReleaseAction, ResourceMappingTable,
    },
    ContextRegistry,
};

fn owners() -> [MappingOwner; 2] {
    let mut registry = ContextRegistry::new();
    registry.publish((), ()).unwrap();
    let a = registry.acquire_active().unwrap().into_identity();
    let b = registry.acquire_active().unwrap().into_identity();
    [
        MappingOwner {
            instance: 1,
            device_id: 10,
            context_lease: a,
        },
        MappingOwner {
            instance: 1,
            device_id: 11,
            context_lease: b,
        },
    ]
}

fn key() -> MappingKey {
    MappingKey {
        domain: MappingDomain { id: 1, cookie: 8 },
        pml4: 40,
        virtual_page: 0x1000,
        physical_page: 0x8106_2000,
        source_cap: 50,
        rights: 3,
        attributes: 0,
    }
}

fn new(
    table: &mut ResourceMappingTable,
    key: MappingKey,
    owner: MappingOwner,
) -> nt_pnp_context::resource_mapping::OwnerReceipt {
    match table.prepare(key, owner).unwrap() {
        Admission::New(receipt) => receipt,
        Admission::Joined(_) => panic!("fresh mapping must require a native effect"),
    }
}

fn map(
    table: &mut ResourceMappingTable,
    owner: nt_pnp_context::resource_mapping::OwnerReceipt,
) -> nt_pnp_context::resource_mapping::MapEffectReceipt {
    let (_, effect) = table.begin_map(owner).unwrap();
    table.acknowledge_map(effect).unwrap();
    effect
}

#[test]
fn second_device_rollback_never_deletes_first_devices_leaf() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let first = new(&mut table, key(), a);
    table.attach_cap(first, 70).unwrap();
    map(&mut table, first);
    let second = match table.prepare(key(), b).unwrap() {
        Admission::Joined(receipt) => receipt,
        Admission::New(_) => panic!("equivalent second owner must not PageMap another cap"),
    };
    assert_ne!(first, second);
    assert_eq!(
        table.begin_release(second),
        Ok(ReleaseAction::OwnerReleased)
    );
    assert_eq!(table.begin_release(second), Err(MappingError::UnknownOwner));
    let row = table.iter().next().unwrap();
    assert_eq!(row.cap(), Some(70));
    assert_eq!(row.phase(), MappingPhase::Mapped);
    assert_eq!(row.owners().collect::<Vec<_>>(), vec![(first, a)]);
    assert_eq!(table.begin_release(first), Ok(ReleaseAction::DeleteCap(70)));
    assert_eq!(table.iter().next().unwrap().phase(), MappingPhase::Retiring);
    assert_eq!(table.prepare(key(), b), Err(MappingError::Unavailable));
    table.acknowledge_delete(first).unwrap();
    assert!(table.iter().next().is_none());
    assert_eq!(
        table.acknowledge_delete(first),
        Err(MappingError::UnknownOwner)
    );
    let replacement = new(&mut table, key(), a);
    assert_ne!(replacement, first);
    assert_eq!(table.attach_cap(first, 71), Err(MappingError::UnknownOwner));
}

#[test]
fn pending_and_uncertain_maps_cannot_be_joined_or_replayed() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let receipt = new(&mut table, key(), a);
    assert_eq!(table.prepare(key(), b), Err(MappingError::Unavailable));
    assert_eq!(table.begin_map(receipt), Err(MappingError::InvalidPhase));
    table.attach_cap(receipt, 70).unwrap();
    assert_eq!(
        table.attach_cap(receipt, 71),
        Err(MappingError::InvalidPhase)
    );
    let (_, effect) = table.begin_map(receipt).unwrap();
    assert_eq!(table.begin_release(receipt), Err(MappingError::Unavailable));
    table.mark_map_uncertain(effect).unwrap();
    assert_eq!(
        table.iter().next().unwrap().phase(),
        MappingPhase::Uncertain
    );
    assert_eq!(table.iter().next().unwrap().cap(), Some(70));
    assert_eq!(table.prepare(key(), a), Err(MappingError::Unavailable));
    assert_eq!(
        table.acknowledge_map(effect),
        Err(MappingError::InvalidPhase)
    );
    assert_eq!(table.begin_release(receipt), Err(MappingError::Unavailable));
    assert_eq!(
        table.acknowledge_delete(receipt),
        Err(MappingError::InvalidPhase)
    );
}

#[test]
fn last_owner_is_retained_until_exact_delete_acknowledgement() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let receipt = new(&mut table, key(), a);
    table.attach_cap(receipt, 70).unwrap();
    map(&mut table, receipt);
    assert_eq!(
        table.acknowledge_delete(receipt),
        Err(MappingError::InvalidPhase)
    );
    assert_eq!(
        table.begin_release(receipt),
        Ok(ReleaseAction::DeleteCap(70))
    );
    assert_eq!(table.begin_release(receipt), Err(MappingError::Unavailable));
    assert_eq!(
        table.iter().next().unwrap().owners().collect::<Vec<_>>(),
        vec![(receipt, a)]
    );
    table.mark_delete_uncertain(receipt).unwrap();
    assert_eq!(table.prepare(key(), b), Err(MappingError::Unavailable));
    assert_eq!(
        table.acknowledge_delete(receipt),
        Err(MappingError::InvalidPhase)
    );
}

#[test]
fn different_backing_or_rights_cannot_replace_a_live_leaf() {
    for change in 0..3 {
        let mut table = ResourceMappingTable::new();
        let [a, b] = owners();
        let original = key();
        let receipt = new(&mut table, original, a);
        table.attach_cap(receipt, 70).unwrap();
        map(&mut table, receipt);
        let mut other = original;
        match change {
            0 => other.physical_page += 0x1000,
            1 => other.rights = 1,
            _ => other.attributes = 1,
        }
        assert_eq!(table.prepare(other, b), Err(MappingError::Conflict));
        assert_eq!(table.iter().count(), 1);
        assert_eq!(table.iter().next().unwrap().key(), original);
    }
}

#[test]
fn verified_cap_alias_joins_without_changing_original_backing() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let receipt = new(&mut table, key(), a);
    table.attach_cap(receipt, 70).unwrap();
    map(&mut table, receipt);
    let mut alias = key();
    alias.source_cap = 51;
    assert!(matches!(table.prepare(alias, b), Ok(Admission::Joined(_))));
    assert_eq!(table.iter().next().unwrap().key(), key());
    assert_eq!(table.iter().next().unwrap().cap(), Some(70));
}

#[test]
fn surviving_second_owner_repairs_original_cap_after_first_owner_retires() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let first = new(&mut table, key(), a);
    table.attach_cap(first, 70).unwrap();
    map(&mut table, first);
    let mut second_key = key();
    second_key.source_cap = 51;
    let second = match table.prepare(second_key, b).unwrap() {
        Admission::Joined(receipt) => receipt,
        Admission::New(_) => panic!("second owner shares the original retained cap"),
    };
    assert_eq!(table.begin_release(first), Ok(ReleaseAction::OwnerReleased));
    assert_eq!(table.begin_remap(first), Err(MappingError::UnknownOwner));
    let row = table.iter().next().unwrap();
    assert_eq!(row.key(), key());
    assert_eq!(row.owners().collect::<Vec<_>>(), vec![(second, b)]);
    let (cap, effect) = table.begin_remap(second).unwrap();
    assert_eq!(cap, 70);
    assert_eq!(table.begin_release(second), Err(MappingError::Unavailable));
    table.acknowledge_map(effect).unwrap();
    assert_eq!(
        table.begin_release(second),
        Ok(ReleaseAction::DeleteCap(70))
    );
    assert_eq!(table.begin_release(second), Err(MappingError::Unavailable));
    assert_eq!(table.iter().next().unwrap().cap(), Some(70));
    table.acknowledge_delete(second).unwrap();
    assert!(table.iter().next().is_none());
    assert_eq!(
        table.acknowledge_delete(second),
        Err(MappingError::UnknownOwner)
    );
    assert_eq!(table.begin_release(first), Err(MappingError::UnknownOwner));
}

#[test]
fn another_table_or_stale_domain_cannot_reuse_receipts_or_replace_live_leaf() {
    let mut table = ResourceMappingTable::new();
    let mut other_table = ResourceMappingTable::new();
    let [a, b] = owners();
    let receipt = new(&mut table, key(), a);
    let other = new(&mut other_table, key(), a);
    assert_ne!(receipt, other);
    assert_eq!(table.attach_cap(other, 70), Err(MappingError::UnknownOwner));
    assert_eq!(
        other_table.begin_release(receipt),
        Err(MappingError::UnknownOwner)
    );
    let mut stale = key();
    stale.domain.cookie += 1;
    assert_eq!(table.prepare(stale, b), Err(MappingError::Conflict));
    assert_eq!(table.iter().count(), 1);
}

#[test]
fn repeated_exact_owner_admission_is_idempotent_only_after_map_ack() {
    let mut table = ResourceMappingTable::new();
    let a = owners()[0];
    let receipt = new(&mut table, key(), a);
    assert_eq!(table.prepare(key(), a), Err(MappingError::Unavailable));
    table.attach_cap(receipt, 70).unwrap();
    map(&mut table, receipt);
    assert_eq!(table.prepare(key(), a), Ok(Admission::Joined(receipt)));
    assert_eq!(table.iter().next().unwrap().owners().count(), 1);
}

#[test]
fn map_ack_requires_current_exact_effect_from_this_table() {
    let mut table = ResourceMappingTable::new();
    let mut other_table = ResourceMappingTable::new();
    let [a, b] = owners();
    let first = new(&mut table, key(), a);
    let mut other_key = key();
    other_key.virtual_page += 0x1000;
    let second = new(&mut table, other_key, b);
    let foreign = new(&mut other_table, key(), a);
    table.attach_cap(first, 70).unwrap();
    table.attach_cap(second, 71).unwrap();
    other_table.attach_cap(foreign, 72).unwrap();
    let (_, first_effect) = table.begin_map(first).unwrap();
    let (_, second_effect) = table.begin_map(second).unwrap();
    let (_, foreign_effect) = other_table.begin_map(foreign).unwrap();
    assert_eq!(
        table.acknowledge_map(foreign_effect),
        Err(MappingError::UnknownOwner)
    );
    assert_eq!(
        table.mark_map_uncertain(foreign_effect),
        Err(MappingError::UnknownOwner)
    );
    assert_eq!(table.begin_map(first), Err(MappingError::InvalidPhase));
    assert_eq!(table.begin_release(first), Err(MappingError::Unavailable));
    table.acknowledge_map(second_effect).unwrap();
    assert_eq!(table.iter().next().unwrap().phase(), MappingPhase::Mapping);
    table.acknowledge_map(first_effect).unwrap();
    assert_eq!(
        table.acknowledge_map(first_effect),
        Err(MappingError::InvalidPhase)
    );
    assert_eq!(
        table.mark_map_uncertain(first_effect),
        Err(MappingError::InvalidPhase)
    );
}

#[test]
fn remap_retains_original_cap_and_all_owners_before_effect() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let first = new(&mut table, key(), a);
    table.attach_cap(first, 70).unwrap();
    let initial_effect = map(&mut table, first);
    let second = match table.prepare(key(), b).unwrap() {
        Admission::Joined(receipt) => receipt,
        _ => panic!("shared acknowledged mapping"),
    };
    let (cap, effect) = table.begin_remap(first).unwrap();
    assert_eq!(cap, 70);
    assert_eq!(table.begin_remap(second), Err(MappingError::InvalidPhase));
    assert_eq!(table.begin_release(first), Err(MappingError::Unavailable));
    assert_eq!(table.begin_release(second), Err(MappingError::Unavailable));
    assert_eq!(
        table.acknowledge_map(initial_effect),
        Err(MappingError::InvalidPhase)
    );
    assert_eq!(table.iter().next().unwrap().owners().count(), 2);
    table.acknowledge_map(effect).unwrap();
    assert_eq!(
        table.acknowledge_map(effect),
        Err(MappingError::InvalidPhase)
    );
    assert_eq!(table.iter().next().unwrap().cap(), Some(70));
    assert_eq!(
        table.begin_release(second),
        Ok(ReleaseAction::OwnerReleased)
    );
    let (cap, next_effect) = table.begin_remap(first).unwrap();
    assert_eq!(cap, 70);
    assert_ne!(effect, next_effect);
    assert_eq!(
        table.acknowledge_map(effect),
        Err(MappingError::InvalidPhase)
    );
    table.mark_map_uncertain(next_effect).unwrap();
    assert_eq!(table.begin_remap(first), Err(MappingError::InvalidPhase));
}

#[test]
fn exact_domain_generation_and_vspace_separate_mapping_authority() {
    let mut table = ResourceMappingTable::new();
    let [a, b] = owners();
    let first = new(&mut table, key(), a);
    let mut fresh = key();
    fresh.domain.cookie += 1;
    fresh.pml4 += 1;
    let second = new(&mut table, fresh, b);
    assert_eq!(table.attach_cap(second, 71), Ok(()));
    assert_eq!(table.begin_map(first), Err(MappingError::InvalidPhase));
    map(&mut table, second);
    assert_eq!(table.iter().count(), 2);
}

#[test]
fn known_nonentered_admission_can_release_without_native_delete() {
    let mut table = ResourceMappingTable::new();
    let a = owners()[0];
    let receipt = new(&mut table, key(), a);
    assert_eq!(
        table.begin_release(receipt),
        Ok(ReleaseAction::UnmappedReleased)
    );
    assert!(table.iter().next().is_none());
    let receipt = new(&mut table, key(), a);
    table.attach_cap(receipt, 70).unwrap();
    assert_eq!(
        table.begin_release(receipt),
        Ok(ReleaseAction::DeleteCap(70))
    );
    table.acknowledge_delete(receipt).unwrap();
    assert!(table.iter().next().is_none());
}

#[test]
fn invalid_page_or_cap_admission_never_creates_an_owner() {
    for change in 0..7 {
        let mut table = ResourceMappingTable::new();
        let mut invalid = key();
        match change {
            0 => invalid.domain.id = 0,
            1 => invalid.domain.cookie = 0,
            2 => invalid.pml4 = 0,
            3 => invalid.virtual_page += 1,
            4 => invalid.physical_page += 1,
            5 => invalid.source_cap = 0,
            _ => invalid.rights = 0,
        }
        assert_eq!(
            table.prepare(invalid, owners()[0]),
            Err(MappingError::InvalidKey)
        );
        assert!(table.iter().next().is_none());
    }
}
