//! RED contract for execution roles transferred by a real foreign initial-thread caller.
//!
//! The image catalog's role and `SpawnTarget` stay immutable. Historical image observations
//! provide provenance, while this separate ledger owns generation-bound execution authority.

use nt_exe_image::{
    execution_role::{
        ExecutionRoleLedger, ForeignInitialThreadLineageEvidence, ForeignInitialThreadRoleEvidence,
    },
    HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog, OwnedHostedProcessImage,
    ProcessImageSourceEvidence,
    SpawnTarget,
};
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, SectionFileIdentity, SectionMountIds};

fn process(pid: u32, generation: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        generation: ProcessGeneration::Hosted(generation),
    }
}

#[test]
fn registered_file_alias_cannot_override_the_actual_creator_policy() {
    use nt_exe_image::execution_role::ExecutionRoleError;
    let mut mounts = SectionMountIds::new();
    let physical_mount = mounts.allocate().unwrap();
    let routed_mount = mounts.allocate().unwrap();
    let root_file = SectionFileIdentity { mount: physical_mount, file_id: 10 };
    let service_file = SectionFileIdentity { mount: physical_mount, file_id: 12 };
    let routed_file = SectionFileIdentity { mount: routed_mount, file_id: 12 };
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss = registered(&mut catalog, 0, 0, b"smss.exe",
        HostedProcessRole::NativeSession, HostedProcessRole::NativeSession, root_file);
    let service = registered(&mut catalog, 3, 6, b"services.exe",
        HostedProcessRole::ServiceControlManager, HostedProcessRole::InteractiveLogon, service_file);
    let observation = catalog.capture_image_observation(service).unwrap();
    let child = child(&mut catalog, b"services.exe", Some(observation));
    let source = ProcessImageSourceEvidence::capture_with_registered_file(
        catalog.get_by_pi(child.pi).unwrap(), routed_file, Some(service_file), Some(observation)).unwrap();
    let caller_process = process(12, 1);
    let child_process = process(120, 2);
    let mut roles = ExecutionRoleLedger::<16>::new();
    roles.seed_bootstrap_root(&catalog, smss, caller_process, root_file).unwrap();
    let candidate = source.registered_target_for_role(&catalog).unwrap();
    assert_eq!(roles.reserve_foreign_initial_thread_role(&catalog,
        evidence(caller_process, child_process, child, candidate,
            source.registered_file().unwrap(), None)), Err(ExecutionRoleError::UnauthorizedCreator));
    assert_eq!(roles.role(child, child_process), None);
    let token = roles.reserve_foreign_initial_thread_lineage(&catalog,
        lineage(caller_process, child_process, child, source.file(), None)).unwrap();
    roles.commit_foreign_initial_thread(&catalog, token, child, child_process).unwrap();
    assert_eq!(roles.role(child, child_process), Some(HostedProcessRole::Application));
}

fn registered(
    catalog: &mut OwnedHostedImageCatalog<16>,
    pi: usize,
    badge: u64,
    leaf: &'static [u8],
    role: HostedProcessRole,
    creator: HostedProcessRole,
    backing: SectionFileIdentity,
) -> SpawnTarget {
    let image = OwnedHostedProcessImage::new(
        pi,
        badge,
        1,
        leaf,
        leaf,
        role,
        leaf,
        leaf,
        HostedImageRoot::System32,
        leaf,
    )
    .unwrap();
    catalog.register(image).unwrap();
    let target = SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap());
    catalog.bind_registered_backing(target, backing).unwrap();
    // This is bootstrap-owned policy metadata, installed once alongside the exact backing.
    catalog
        .bind_registered_launch_policy(target, creator)
        .unwrap();
    target
}

fn child(
    catalog: &mut OwnedHostedImageCatalog<16>,
    leaf: &'static [u8],
    observation: Option<nt_exe_image::CapturedImageObservation>,
) -> SpawnTarget {
    let pi = catalog
        .admit_dynamic_executable_observed(
            leaf,
            HostedProcessRole::Application,
            leaf,
            leaf,
            HostedImageRoot::System32,
            observation,
            32,
        )
        .unwrap();
    SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap())
}

fn evidence(
    caller: ProcessIdentity,
    child: ProcessIdentity,
    child_target: SpawnTarget,
    registered_target: SpawnTarget,
    section_image: SectionFileIdentity,
    parent_handle_hint: Option<ProcessIdentity>,
) -> ForeignInitialThreadRoleEvidence {
    ForeignInitialThreadRoleEvidence {
        caller,
        child,
        child_target,
        registered_target,
        section_image,
        parent_handle_hint,
    }
}

fn lineage(
    caller: ProcessIdentity,
    child: ProcessIdentity,
    child_target: SpawnTarget,
    section_image: SectionFileIdentity,
    parent_handle_hint: Option<ProcessIdentity>,
) -> ForeignInitialThreadLineageEvidence {
    ForeignInitialThreadLineageEvidence {
        caller,
        child,
        child_target,
        section_image,
        parent_handle_hint,
    }
}

#[test]
fn bootstrap_root_requires_the_actual_mounted_file() {
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let other_mount = mounts.allocate().unwrap();
    let registered_file = SectionFileIdentity { mount, file_id: 10 };
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss = registered(&mut catalog, 0, 0, b"smss.exe",
        HostedProcessRole::NativeSession, HostedProcessRole::NativeSession,
        registered_file);
    let process = process(12, 1);
    let mut roles = ExecutionRoleLedger::<16>::new();
    assert_eq!(roles.seed_bootstrap_root(&catalog, smss, process,
        SectionFileIdentity { mount: other_mount, file_id: registered_file.file_id }),
        Err(nt_exe_image::execution_role::ExecutionRoleError::InvalidBacking));
    assert_eq!(roles.role(smss, process), None);
    assert_eq!(roles.seed_bootstrap_root(&catalog, smss, process, registered_file), Ok(()));
    assert_eq!(roles.role(smss, process), Some(HostedProcessRole::NativeSession));
}

#[test]
fn exact_live_creator_transfers_role_without_mutating_spawn_identity() {
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss_file = SectionFileIdentity { mount, file_id: 10 };
    let smss = registered(
        &mut catalog,
        0,
        0,
        b"smss.exe",
        HostedProcessRole::NativeSession,
        HostedProcessRole::NativeSession,
        smss_file,
    );
    let winlogon_file = SectionFileIdentity { mount, file_id: 11 };
    let winlogon = registered(
        &mut catalog,
        2,
        4,
        b"winlogon.exe",
        HostedProcessRole::InteractiveLogon,
        HostedProcessRole::NativeSession,
        winlogon_file,
    );
    let services_file = SectionFileIdentity { mount, file_id: 12 };
    let services = registered(
        &mut catalog,
        3,
        6,
        b"services.exe",
        HostedProcessRole::ServiceControlManager,
        HostedProcessRole::InteractiveLogon,
        services_file,
    );
    let winlogon_observation = catalog.capture_image_observation(winlogon).unwrap();
    let services_observation = catalog.capture_image_observation(services).unwrap();
    let dynamic_winlogon = child(&mut catalog, b"winlogon.exe", Some(winlogon_observation));
    let dynamic_services = child(&mut catalog, b"services.exe", Some(services_observation));
    let smss_identity = process(12, 1);
    let winlogon_identity = process(96, 3);
    let services_identity = process(120, 4);
    let mut roles = ExecutionRoleLedger::<16>::new();
    roles
        .seed_bootstrap_root(&catalog, smss, smss_identity, smss_file)
        .unwrap();

    // An exact image observation by itself cannot turn the dynamic Application into SCM.
    assert_eq!(
        catalog
            .get_by_pi(dynamic_services.pi)
            .unwrap()
            .observation_role(),
        HostedProcessRole::ServiceControlManager
    );
    assert!(!roles.can_own_installer_service_work(dynamic_services, services_identity));
    assert!(!catalog
        .get_by_pi(dynamic_services.pi)
        .unwrap()
        .can_own_installer_service_work());

    roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                smss_identity,
                winlogon_identity,
                dynamic_winlogon,
                winlogon,
                winlogon_file,
                Some(smss_identity),
            ),
        )
        .unwrap();
    assert_eq!(
        roles.role(dynamic_winlogon, winlogon_identity),
        Some(HostedProcessRole::InteractiveLogon)
    );
    roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                winlogon_identity,
                services_identity,
                dynamic_services,
                services,
                services_file,
                Some(winlogon_identity),
            ),
        )
        .unwrap();
    assert_eq!(
        roles.role(dynamic_services, services_identity),
        Some(HostedProcessRole::ServiceControlManager)
    );
    assert_eq!(
        roles.creator_of(dynamic_winlogon, winlogon_identity),
        Some(smss_identity)
    );
    assert_eq!(
        roles.creator_of(dynamic_services, services_identity),
        Some(winlogon_identity)
    );
    assert!(roles.can_own_installer_service_work(dynamic_services, services_identity));
    assert_eq!(
        SpawnTarget::from_image(catalog.get_by_pi(dynamic_services.pi).unwrap()),
        dynamic_services,
        "role transfer must not rewrite process-image identity"
    );
}

#[test]
fn forged_parent_wrong_backing_stale_generation_and_repeat_cannot_transfer_role() {
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let other_mount = mounts.allocate().unwrap();
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss_file = SectionFileIdentity { mount, file_id: 10 };
    let smss = registered(
        &mut catalog,
        0,
        0,
        b"smss.exe",
        HostedProcessRole::NativeSession,
        HostedProcessRole::NativeSession,
        smss_file,
    );
    let winlogon_file = SectionFileIdentity { mount, file_id: 11 };
    let registered_winlogon = registered(
        &mut catalog,
        2,
        4,
        b"winlogon.exe",
        HostedProcessRole::InteractiveLogon,
        HostedProcessRole::NativeSession,
        winlogon_file,
    );
    let services_file = SectionFileIdentity { mount, file_id: 12 };
    let registered_services = registered(
        &mut catalog,
        3,
        6,
        b"services.exe",
        HostedProcessRole::ServiceControlManager,
        HostedProcessRole::InteractiveLogon,
        services_file,
    );
    let winlogon_observation = catalog.capture_image_observation(registered_winlogon);
    let services_observation = catalog.capture_image_observation(registered_services);
    let dynamic_winlogon = child(&mut catalog, b"winlogon.exe", winlogon_observation);
    let dynamic_services = child(&mut catalog, b"services.exe", services_observation);
    let smss_identity = process(12, 1);
    let winlogon_identity = process(96, 3);
    let services_identity = process(120, 4);
    let application_identity = process(200, 7);
    let mut roles = ExecutionRoleLedger::<16>::new();
    roles
        .seed_bootstrap_root(&catalog, smss, smss_identity, smss_file)
        .unwrap();
    roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                smss_identity,
                winlogon_identity,
                dynamic_winlogon,
                registered_winlogon,
                winlogon_file,
                None,
            ),
        )
        .unwrap();

    assert!(roles
        .record_foreign_initial_thread(
            &catalog,
            lineage(
                winlogon_identity,
                services_identity,
                registered_services,
                services_file,
                None,
            ),
        )
        .is_err(), "ordinary lineage cannot grant a registered service role");

    assert!(
        roles
            .admit_foreign_initial_thread(
                &catalog,
                evidence(
                    application_identity,
                    services_identity,
                    dynamic_services,
                    registered_services,
                    services_file,
                    Some(winlogon_identity),
                )
            )
            .is_err(),
        "a caller-supplied parent handle is not the actual thread caller"
    );
    assert!(roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                winlogon_identity,
                services_identity,
                dynamic_services,
                registered_services,
                SectionFileIdentity {
                    file_id: 13,
                    ..services_file
                },
                None,
            )
        )
        .is_err());
    assert!(roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                winlogon_identity,
                services_identity,
                dynamic_services,
                registered_services,
                SectionFileIdentity {
                    mount: other_mount,
                    ..services_file
                },
                None,
            )
        )
        .is_err());
    assert!(roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                process(96, 2),
                services_identity,
                dynamic_services,
                registered_services,
                services_file,
                None,
            )
        )
        .is_err());
    assert!(roles
        .admit_foreign_initial_thread(
            &catalog,
            evidence(
                winlogon_identity,
                services_identity,
                SpawnTarget {
                    generation: dynamic_services.generation + 1,
                    ..dynamic_services
                },
                registered_services,
                services_file,
                None,
            )
        )
        .is_err());
    assert!(!roles.can_own_installer_service_work(dynamic_services, services_identity));

    let valid = evidence(
        winlogon_identity,
        services_identity,
        dynamic_services,
        registered_services,
        services_file,
        None,
    );
    roles.admit_foreign_initial_thread(&catalog, valid).unwrap();
    assert_eq!(
        roles.creator_of(dynamic_services, services_identity),
        Some(winlogon_identity)
    );
    assert!(
        roles.admit_foreign_initial_thread(&catalog, valid).is_err(),
        "the role transfer is one-shot even if repeated identically"
    );
    assert!(
        roles
            .admit_foreign_initial_thread(
                &catalog,
                evidence(
                    winlogon_identity,
                    services_identity,
                    dynamic_services,
                    registered_winlogon,
                    winlogon_file,
                    None,
                )
            )
            .is_err(),
        "conflicting registered identity cannot overwrite authority"
    );

    // PM's parent can be selected through the caller-supplied process handle. Preserve the
    // actual initial-thread creator for generic children too, then walk only that chain.
    let application = child(&mut catalog, b"application.exe", None);
    let application_file = SectionFileIdentity { mount, file_id: 14 };
    roles
        .record_foreign_initial_thread(
            &catalog,
            lineage(
                winlogon_identity,
                application_identity,
                application,
                application_file,
                Some(winlogon_identity),
            ),
        )
        .unwrap();
    let forged_worker = child(&mut catalog, b"forged-worker.exe", None);
    let forged_worker_identity = process(204, 8);
    roles
        .record_foreign_initial_thread(
            &catalog,
            lineage(
                application_identity,
                forged_worker_identity,
                forged_worker,
                SectionFileIdentity { mount, file_id: 15 },
                Some(services_identity),
            ),
        )
        .unwrap();
    assert_eq!(
        roles.creator_of(forged_worker, forged_worker_identity),
        Some(application_identity)
    );
    assert_eq!(
        roles.installer_service_ancestor(forged_worker, forged_worker_identity),
        None,
        "forged PM parent must not turn an Application child into installer service work"
    );

    let genuine_worker = child(&mut catalog, b"genuine-worker.exe", None);
    let genuine_worker_identity = process(208, 9);
    roles
        .record_foreign_initial_thread(
            &catalog,
            lineage(
                services_identity,
                genuine_worker_identity,
                genuine_worker,
                SectionFileIdentity { mount, file_id: 16 },
                Some(application_identity),
            ),
        )
        .unwrap();
    assert_eq!(
        roles.installer_service_ancestor(genuine_worker, genuine_worker_identity),
        Some(services_identity),
        "actual creator chain controls installer ancestry"
    );

    roles
        .retire_exact(dynamic_services, services_identity)
        .unwrap();
    assert_eq!(roles.creator_of(dynamic_services, services_identity), None);
    assert_eq!(
        roles.installer_service_ancestor(genuine_worker, genuine_worker_identity),
        None,
        "retiring the service generation invalidates descendant authority"
    );
    catalog.retire_dynamic_target(dynamic_services).unwrap();
    let replacement = child(&mut catalog, b"services.exe", None);
    assert_eq!(replacement.pi, dynamic_services.pi);
    assert_ne!(replacement.generation, dynamic_services.generation);
    assert_eq!(roles.role(dynamic_services, services_identity), None);
    assert_eq!(roles.role(replacement, process(124, 5)), None);
    assert!(!roles.can_own_installer_service_work(replacement, process(124, 5)));
    assert!(roles
        .retire_exact(dynamic_services, services_identity)
        .is_err());
}

#[test]
fn pending_initial_thread_has_no_authority_until_exact_one_shot_commit() {
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss_file = SectionFileIdentity { mount, file_id: 10 };
    let smss = registered(&mut catalog, 0, 0, b"smss.exe",
        HostedProcessRole::NativeSession, HostedProcessRole::NativeSession,
        smss_file);
    let winlogon_file = SectionFileIdentity { mount, file_id: 11 };
    let winlogon = registered(&mut catalog, 2, 4, b"winlogon.exe",
        HostedProcessRole::InteractiveLogon, HostedProcessRole::NativeSession, winlogon_file);
    let services_file = SectionFileIdentity { mount, file_id: 12 };
    let services = registered(&mut catalog, 3, 6, b"services.exe",
        HostedProcessRole::ServiceControlManager, HostedProcessRole::InteractiveLogon,
        services_file);
    let winlogon_observation = catalog.capture_image_observation(winlogon).unwrap();
    let services_observation = catalog.capture_image_observation(services).unwrap();
    let dynamic_winlogon = child(&mut catalog, b"winlogon.exe", Some(winlogon_observation));
    let dynamic_services = child(&mut catalog, b"services.exe", Some(services_observation));
    let worker = child(&mut catalog, b"worker.exe", None);
    let smss_identity = process(12, 1);
    let winlogon_identity = process(96, 3);
    let services_identity = process(120, 4);
    let worker_identity = process(124, 5);
    let mut roles = ExecutionRoleLedger::<16>::new();
    roles.seed_bootstrap_root(&catalog, smss, smss_identity, smss_file).unwrap();

    let winlogon_evidence = evidence(smss_identity, winlogon_identity, dynamic_winlogon,
        winlogon, winlogon_file, Some(smss_identity));
    let winlogon_token = roles.reserve_foreign_initial_thread_role(&catalog, winlogon_evidence)
        .unwrap();
    assert_eq!(roles.role(dynamic_winlogon, winlogon_identity), None);
    assert_eq!(roles.creator_of(dynamic_winlogon, winlogon_identity), None);
    assert!(roles.reserve_foreign_initial_thread_role(&catalog, winlogon_evidence).is_err());
    roles.commit_foreign_initial_thread(&catalog, winlogon_token, dynamic_winlogon,
        winlogon_identity).unwrap();
    assert_eq!(roles.role(dynamic_winlogon, winlogon_identity),
        Some(HostedProcessRole::InteractiveLogon));
    assert!(roles.commit_foreign_initial_thread(&catalog, winlogon_token,
        dynamic_winlogon, winlogon_identity).is_err());
    assert!(roles.cancel_foreign_initial_thread(winlogon_token, dynamic_winlogon,
        winlogon_identity).is_err());

    let services_evidence = evidence(winlogon_identity, services_identity, dynamic_services,
        services, services_file, Some(winlogon_identity));
    let services_token = roles.reserve_foreign_initial_thread_role(&catalog, services_evidence)
        .unwrap();
    assert!(!roles.can_own_installer_service_work(dynamic_services, services_identity));
    assert_eq!(roles.installer_service_ancestor(dynamic_services, services_identity), None);
    assert!(roles.commit_foreign_initial_thread(&catalog, services_token,
        dynamic_services, process(120, 3)).is_err());
    assert!(!roles.can_own_installer_service_work(dynamic_services, services_identity));
    roles.cancel_foreign_initial_thread(services_token, dynamic_services,
        services_identity).unwrap();
    assert!(roles.commit_foreign_initial_thread(&catalog, services_token,
        dynamic_services, services_identity).is_err());

    let replacement_token = roles.reserve_foreign_initial_thread_role(&catalog, services_evidence)
        .unwrap();
    assert_ne!(replacement_token, services_token);
    assert!(roles.commit_foreign_initial_thread(&catalog, services_token,
        dynamic_services, services_identity).is_err());
    roles.commit_foreign_initial_thread(&catalog, replacement_token,
        dynamic_services, services_identity).unwrap();
    assert!(roles.can_own_installer_service_work(dynamic_services, services_identity));

    let worker_evidence = lineage(services_identity, worker_identity, worker,
        SectionFileIdentity { mount, file_id: 13 }, Some(smss_identity));
    let worker_token = roles.reserve_foreign_initial_thread_lineage(&catalog, worker_evidence)
        .unwrap();
    assert_eq!(roles.installer_service_ancestor(worker, worker_identity), None);
    roles.commit_foreign_initial_thread(&catalog, worker_token, worker, worker_identity)
        .unwrap();
    assert_eq!(roles.installer_service_ancestor(worker, worker_identity), Some(services_identity));

    // A pending child can complete after its verified caller exits. The reserved caller
    // identity survives, but a retired service can no longer supply ancestry authority.
    let late_worker = child(&mut catalog, b"late-worker.exe", None);
    let late_worker_identity = process(128, 6);
    let late_evidence = lineage(services_identity, late_worker_identity, late_worker,
        SectionFileIdentity { mount, file_id: 14 }, None);
    let late_token = roles.reserve_foreign_initial_thread_lineage(&catalog, late_evidence)
        .unwrap();
    roles.retire_exact(dynamic_services, services_identity).unwrap();
    roles.commit_foreign_initial_thread(&catalog, late_token, late_worker,
        late_worker_identity).unwrap();
    assert_eq!(roles.creator_of(late_worker, late_worker_identity), Some(services_identity));
    assert_eq!(roles.installer_service_ancestor(late_worker, late_worker_identity), None);
    assert!(roles.reserve_foreign_initial_thread_lineage(&catalog, late_evidence).is_err());
    let forged_after = child(&mut catalog, b"forged-after.exe", None);
    assert!(roles.reserve_foreign_initial_thread_lineage(&catalog,
        lineage(services_identity, process(130, 8), forged_after,
            SectionFileIdentity { mount, file_id: 16 }, None)).is_err(),
        "retired caller cannot authorize a new reservation");

    let abandoned = child(&mut catalog, b"abandoned.exe", None);
    let abandoned_identity = process(132, 7);
    let abandoned_evidence = lineage(winlogon_identity, abandoned_identity, abandoned,
        SectionFileIdentity { mount, file_id: 15 }, None);
    let abandoned_token = roles.reserve_foreign_initial_thread_lineage(&catalog,
        abandoned_evidence).unwrap();
    roles.retire_exact(abandoned, abandoned_identity).unwrap();
    assert!(roles.commit_foreign_initial_thread(&catalog, abandoned_token,
        abandoned, abandoned_identity).is_err(), "exact retirement invalidates pending token");
}
