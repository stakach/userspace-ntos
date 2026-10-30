//! RED contract for execution roles transferred by a real foreign initial-thread caller.
//!
//! The image catalog's role and `SpawnTarget` stay immutable. Historical image observations
//! provide provenance, while this separate ledger owns generation-bound execution authority.

use nt_exe_image::{
    execution_role::{
        ExecutionRoleLedger, ForeignInitialThreadLineageEvidence, ForeignInitialThreadRoleEvidence,
    },
    HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog, OwnedHostedProcessImage,
    SpawnTarget,
};
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, SectionFileIdentity, SectionMountIds};

fn process(pid: u32, generation: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        generation: ProcessGeneration::Hosted(generation),
    }
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
fn exact_live_creator_transfers_role_without_mutating_spawn_identity() {
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let mut catalog = OwnedHostedImageCatalog::<16>::new();
    let smss = registered(
        &mut catalog,
        0,
        0,
        b"smss.exe",
        HostedProcessRole::NativeSession,
        HostedProcessRole::NativeSession,
        SectionFileIdentity { mount, file_id: 10 },
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
        .seed_bootstrap_root(&catalog, smss, smss_identity)
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
    let smss = registered(
        &mut catalog,
        0,
        0,
        b"smss.exe",
        HostedProcessRole::NativeSession,
        HostedProcessRole::NativeSession,
        SectionFileIdentity { mount, file_id: 10 },
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
        .seed_bootstrap_root(&catalog, smss, smss_identity)
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
