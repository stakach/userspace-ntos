use super::*;
use crate::{DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort};
use alloc::boxed::Box;
use nt_types::NtPath;

fn fixture() -> (IoManager<MockObjectPort>, ReverseClassAliasIdentity) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\ReverseClass").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let port_fdo = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let class_port_fdo = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let class_main = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    io.attach_device_to_stack(class_port_fdo, port_fdo).unwrap();
    let class_domain = io.register_hosted_domain();
    let port_domain = io.register_hosted_domain();
    let source_port_fdo = io
        .bind_hosted_device_pointer(class_domain, 0x5000, class_port_fdo)
        .unwrap();
    let source_main = io
        .bind_hosted_device_pointer(class_domain, 0x6000, class_main)
        .unwrap();
    let alias_port_fdo = io
        .bind_hosted_device_pointer(port_domain, 0x7000, class_port_fdo)
        .unwrap();
    let alias_main = io
        .bind_hosted_device_pointer(port_domain, 0x8000, class_main)
        .unwrap();
    (
        io,
        ReverseClassAliasIdentity {
            source_port_fdo,
            source_main,
            alias_port_fdo,
            alias_main,
        },
    )
}

#[test]
fn distinct_reverse_aliases_publish_once_and_hold_exact_sources() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    assert_eq!(owner.stage(&io, identity), Ok(()));
    assert_eq!(owner.begin_publication(&mut io, identity), Ok(()));
    assert_eq!(
        owner.begin_publication(&mut io, identity),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(owner.complete_publication(&io, identity), Ok(()));
    assert_eq!(owner.published_identity_without_manager(), Some(identity));
    assert_eq!(
        owner.alias_for_attached_traversal(&io),
        Ok(identity.alias_port_fdo)
    );
    assert_eq!(
        owner.alias_for_callback_first_argument(&io),
        Ok(identity.alias_main)
    );
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_port_fdo),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_main),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        io.retire_hosted_device_pointer(identity.alias_main),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(owner.begin_retirement(), Ok(()));
    assert_eq!(owner.published_identity_without_manager(), None);
    assert_eq!(
        owner.alias_for_attached_traversal(&io),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(owner.finish_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    assert_eq!(owner.release_aliases_for_retirement(&mut io), Ok(()));
    io.retire_hosted_device_pointer(identity.alias_port_fdo)
        .unwrap();
    io.retire_hosted_device_pointer(identity.alias_main)
        .unwrap();
    assert_eq!(owner.finish_retirement(&mut io), Ok(()));
    io.retire_hosted_device_pointer(identity.source_port_fdo)
        .unwrap();
    io.retire_hosted_device_pointer(identity.source_main)
        .unwrap();
}

#[test]
fn swapped_cross_domain_and_reused_generation_cannot_publish() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    let swapped = ReverseClassAliasIdentity {
        alias_port_fdo: identity.alias_main,
        alias_main: identity.alias_port_fdo,
        ..identity
    };
    assert_eq!(owner.stage(&io, swapped), Err(NtStatus::INVALID_HANDLE));
    let same_alias = ReverseClassAliasIdentity {
        alias_main: identity.alias_port_fdo,
        ..identity
    };
    assert_eq!(owner.stage(&io, same_alias), Err(NtStatus::INVALID_HANDLE));
    let wrong_domain = ReverseClassAliasIdentity {
        alias_main: identity.source_main,
        ..identity
    };
    assert_eq!(
        owner.stage(&io, wrong_domain),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(owner.stage(&io, identity), Ok(()));
    io.retire_hosted_device_pointer(identity.alias_main)
        .unwrap();
    let replacement = io
        .bind_hosted_device_pointer(
            identity.alias_main.domain(),
            identity.alias_main.address(),
            identity.alias_main.device_id(),
        )
        .unwrap();
    assert_ne!(replacement, identity.alias_main);
    assert_eq!(
        owner.begin_publication(&mut io, identity),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        owner.begin_publication(
            &mut io,
            ReverseClassAliasIdentity {
                alias_main: replacement,
                ..identity
            }
        ),
        Err(NtStatus::INVALID_HANDLE)
    );
}

#[test]
fn uncertain_native_publication_blocks_replay_and_retirement() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    owner.stage(&io, identity).unwrap();
    owner.begin_publication(&mut io, identity).unwrap();
    owner.block_uncertain().unwrap();
    assert_eq!(owner.published_identity_without_manager(), None);
    assert_eq!(
        io.retire_hosted_device_pointer(identity.alias_main),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        owner.complete_publication(&io, identity),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        owner.begin_publication(&mut io, identity),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        owner.alias_for_attached_traversal(&io),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(owner.begin_retirement(), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_port_fdo),
        Err(NtStatus::DEVICE_BUSY)
    );
}

#[test]
fn uncertain_alias_allocation_before_stage_retains_sources_and_blocks_retry() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    owner.block_prepublication().unwrap();
    assert_eq!(owner.phase(), ReverseClassAliasPhase::Uncertain);
    assert_eq!(owner.stage(&io, identity), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(owner.begin_retirement(), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_port_fdo),
        Err(NtStatus::DEVICE_BUSY)
    );
}

#[test]
fn uncertain_alias_reply_after_stage_blocks_provider_entry() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    owner.stage(&io, identity).unwrap();
    owner.block_prepublication().unwrap();
    assert_eq!(
        owner.begin_publication(&mut io, identity),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        owner.alias_for_attached_traversal(&io),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_main),
        Err(NtStatus::DEVICE_BUSY)
    );
}

#[test]
fn failed_physical_revalidation_after_ack_closes_published_aliases() {
    let (mut io, identity) = fixture();
    let mut owner =
        ReverseClassAliasProjection::new(&mut io, identity.source_port_fdo, identity.source_main)
            .unwrap();
    owner.stage(&io, identity).unwrap();
    owner.begin_publication(&mut io, identity).unwrap();
    owner.complete_publication(&io, identity).unwrap();
    owner.block_uncertain().unwrap();
    assert_eq!(owner.published_identity_without_manager(), None);
    assert_eq!(
        owner.alias_for_callback_first_argument(&io),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(owner.begin_retirement(), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(
        io.retire_hosted_device_pointer(identity.source_main),
        Err(NtStatus::DEVICE_BUSY)
    );
}
