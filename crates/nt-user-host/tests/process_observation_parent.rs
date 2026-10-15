use nt_process::ProcessManager;
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::process_observation::{
    ObservationError, ObservationKey, ObservationLimits, ProcessObservations, PublicationFact,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_user_host::thread_binding::ThreadBinding;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Userinit,
    Explorer,
}

fn process(
    pm: &mut ProcessManager,
    name: &str,
    parent: Option<u32>,
    pi: usize,
    generation: u64,
) -> (ObservationKey, ProviderLogicalCaller) {
    let pid = pm.create_process(name, parent, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let key = ObservationKey {
        pi,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(generation),
        },
    };
    let caller = ProviderLogicalCaller::capture(
        ThreadBinding {
            pi,
            process: key.process,
            tid: u64::from(tid),
            badge: 100 + u64::from(tid),
            tcb: 200 + u64::from(tid),
            role: (),
            reservations: None,
        },
        pm.thread_lifetime(tid).unwrap(),
    )
    .unwrap();
    (key, caller)
}

#[test]
fn exact_live_explorer_selects_its_historical_parent_not_unrelated_userinit_history() {
    let mut pm = ProcessManager::new();
    let mut observations =
        ProcessObservations::<Role, Option<ObservationKey>, ()>::new(ObservationLimits {
            processes: 8,
            workers_per_process: 0,
            gui_kinds_per_process: 0,
        });
    let (old, old_main) = process(&mut pm, "userinit.exe", None, 6, 1);
    let (parent, parent_main) = process(&mut pm, "userinit.exe", None, 7, 2);
    let (child, child_main) = process(&mut pm, "explorer.exe", Some(parent.process.pid), 8, 3);
    for (key, caller, role, image_parent) in [
        (old, old_main, Role::Userinit, None),
        (parent, parent_main, Role::Userinit, None),
        (child, child_main, Role::Explorer, Some(parent)),
    ] {
        observations.register(key, role, image_parent).unwrap();
        observations
            .record_publication(key, PublicationFact::ProcessCatalog)
            .unwrap();
        observations
            .record_publication(key, PublicationFact::VSpace)
            .unwrap();
        observations
            .record_main_publication(key, caller, caller.thread())
            .unwrap();
    }
    for key in [old, parent] {
        pm.terminate_process(key.process.pid, 0).unwrap();
        observations
            .record_terminal(
                key,
                pm.process(key.process.pid).unwrap().exit_status.unwrap(),
            )
            .unwrap();
        observations.retire(key).unwrap();
    }
    let explorer = observations
        .live_for_role(Role::Explorer, &[child])
        .unwrap()
        .unwrap();
    let exact_parent = observations
        .historical_snapshot(explorer.image().unwrap())
        .unwrap();
    assert_eq!(exact_parent.key(), parent);
    assert!(
        exact_parent.role() == Role::Userinit
            && exact_parent.fully_published()
            && exact_parent.is_retired()
    );
    assert!(observations.historical_snapshot(old).unwrap().is_retired());
    let wrong = ObservationKey {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(99),
            ..parent.process
        },
        ..parent
    };
    assert!(observations.historical_snapshot(wrong).is_none());
    let (other, _) = process(&mut pm, "explorer.exe", Some(parent.process.pid), 9, 4);
    observations
        .register(other, Role::Explorer, Some(parent))
        .unwrap();
    assert!(matches!(
        observations.live_for_role(Role::Explorer, &[child, other]),
        Err(ObservationError::AmbiguousRole)
    ));
}
