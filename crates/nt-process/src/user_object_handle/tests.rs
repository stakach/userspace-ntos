use super::*;
use crate::native_handle::{NativeHandleInformation, KERNEL_HANDLE_TAG, OBJ_KERNEL_HANDLE};

const WINDOW_STATION_TYPE: u64 = 0x5100;
const DESKTOP_TYPE: u64 = 0x5200;

fn target(body: u64, generation: u64) -> UserObjectTarget {
    UserObjectTarget { domain: 7, object_type: DESKTOP_TYPE, body, generation }
}

struct Fixture {
    pm: ProcessManager,
    first: NativeHandleCaller,
    second: NativeHandleCaller,
    first_kernel: NativeHandleCaller,
}

fn caller(pm: &mut ProcessManager, name: &str, mode: AccessMode) -> NativeHandleCaller {
    let pid = pm.create_process(name, None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    pm.capture_native_handle_caller(pm.thread_lifetime(tid).unwrap(), mode).unwrap()
}

fn fixture() -> Fixture {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("system", None, None);
    let initial = pm.create_thread(system, 0, 0, true).unwrap();
    pm.designate_initial_system(system, initial).unwrap();
    let first = caller(&mut pm, "first", AccessMode::UserMode);
    let second = caller(&mut pm, "second", AccessMode::UserMode);
    let first_kernel = pm
        .capture_native_handle_caller(
            pm.thread_lifetime(first.original_thread().thread_id()).unwrap(),
            AccessMode::KernelMode,
        )
        .unwrap();
    Fixture { pm, first, second, first_kernel }
}

fn lookup(
    pm: &ProcessManager,
    caller: NativeHandleCaller,
    value: u64,
    access: u32,
    expected: Option<u64>,
) -> Result<UserObjectTarget, u32> {
    pm.lookup_native_user_object_handle(caller, value, access, expected).map(|(target, _)| target)
}

fn publish(pm: &mut ProcessManager, caller: NativeHandleCaller, target: UserObjectTarget, grant: u32) -> u64 {
    let mut publication = pm.reserve_native_user_object_handle(caller, 0).unwrap();
    publication.bind(pm, target, grant).unwrap();
    publication.publish(pm).unwrap()
}

#[test]
fn equal_handle_values_in_two_processes_name_their_own_user_objects() {
    let mut f = fixture();
    let a = publish(&mut f.pm, f.first, target(0x1000, 1), 0x1ff);
    let b = publish(&mut f.pm, f.second, target(0x2000, 1), 0x1ff);
    assert_eq!(a, b, "both processes allocate the same first slot");
    assert_eq!(
        lookup(&f.pm, f.first, a, 0, Some(DESKTOP_TYPE)),
        Ok(target(0x1000, 1))
    );
    assert_eq!(
        lookup(&f.pm, f.second, b, 0, Some(DESKTOP_TYPE)),
        Ok(target(0x2000, 1))
    );
    // Closing one process's handle leaves the other's equal value intact.
    assert_eq!(f.pm.close_native_user_object_handle(f.first, a), Ok(target(0x1000, 1)));
    assert_eq!(
        lookup(&f.pm, f.first, a, 0, None),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        lookup(&f.pm, f.second, b, 0, None),
        Ok(target(0x2000, 1))
    );
}

#[test]
fn reserved_and_bound_user_handles_are_invisible_until_published() {
    let mut f = fixture();
    let mut publication = f.pm.reserve_native_user_object_handle(f.first, 0).unwrap();
    let value = publication.value();
    assert_eq!(
        lookup(&f.pm, f.first, value, 0, None),
        Err(STATUS_INVALID_HANDLE)
    );
    publication.bind(&mut f.pm, target(0x3000, 2), 1).unwrap();
    assert_eq!(
        lookup(&f.pm, f.first, value, 0, None),
        Err(STATUS_INVALID_HANDLE)
    );
    let caller_pid = f.first.effective_process();
    assert_eq!(f.pm.find_native_user_object_handle(f.first_kernel, caller_pid, None, None, None), Ok(None));
    assert_eq!(publication.abort(&mut f.pm), Ok(Some(target(0x3000, 2))));
}

#[test]
fn user_lookup_enforces_type_generation_and_user_mode_access() {
    let mut f = fixture();
    let value = publish(&mut f.pm, f.first, target(0x4000, 3), 0x1);
    assert_eq!(
        lookup(&f.pm, f.first, value, 0, Some(WINDOW_STATION_TYPE)),
        Err(STATUS_OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(
        lookup(&f.pm, f.first, value, 0x2, None),
        Err(crate::STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        lookup(&f.pm, f.first_kernel, value, 0x2, None),
        Ok(target(0x4000, 3))
    );
    let other = f.pm.insert_handle(f.first.effective_process(), HandleObject::Opaque(9), 0).unwrap();
    assert_eq!(
        lookup(&f.pm, f.first, u64::from(other), 0, None),
        Err(STATUS_OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(
        f.pm.close_native_user_object_handle(f.first, u64::from(other)),
        Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH))
    );
}

#[test]
fn kernel_user_handles_live_in_the_system_table() {
    let mut f = fixture();
    let mut publication = f
        .pm
        .reserve_native_user_object_handle(f.first_kernel, OBJ_KERNEL_HANDLE)
        .unwrap();
    publication.bind(&mut f.pm, target(0x5000, 1), 0x1ff).unwrap();
    let value = publication.publish(&mut f.pm).unwrap();
    assert_ne!(value & KERNEL_HANDLE_TAG, 0);
    assert!(f.pm.reserve_native_user_object_handle(f.first, OBJ_KERNEL_HANDLE).is_err());
    assert_eq!(
        lookup(&f.pm, f.first_kernel, value, 0, None),
        Ok(target(0x5000, 1))
    );
    assert_eq!(
        lookup(&f.pm, f.first, value, 0, None),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn find_searches_only_the_named_process_and_honours_every_filter() {
    let mut f = fixture();
    let first_pid = f.first.effective_process();
    let second_pid = f.second.effective_process();
    let desktop = target(0x6000, 1);
    let station = UserObjectTarget { object_type: WINDOW_STATION_TYPE, ..target(0x7000, 1) };
    let in_second = publish(&mut f.pm, f.second, desktop, 0x10);
    let counts = (f.pm.handle_count(first_pid), f.pm.handle_count(second_pid));
    let search = |pm: &ProcessManager, pid, object, object_type, info| {
        pm.find_native_user_object_handle(f.first_kernel, pid, object, object_type, info)
    };
    assert_eq!(search(&f.pm, first_pid, Some(desktop.body), None, None), Ok(None));
    assert_eq!(
        search(&f.pm, second_pid, Some(desktop.body), Some(DESKTOP_TYPE), None),
        Ok(Some(in_second as u32))
    );
    // NULL Object and NULL ObjectType are wildcards.
    assert_eq!(search(&f.pm, second_pid, None, None, None), Ok(Some(in_second as u32)));
    assert_eq!(search(&f.pm, second_pid, None, Some(WINDOW_STATION_TYPE), None), Ok(None));
    let exact = NativeHandleInformation { attributes: 0, granted_access: Some(0x10) };
    let other = NativeHandleInformation { attributes: 0, granted_access: Some(0x11) };
    assert_eq!(search(&f.pm, second_pid, None, None, Some(exact)), Ok(Some(in_second as u32)));
    assert_eq!(search(&f.pm, second_pid, None, None, Some(other)), Ok(None));
    let _ = publish(&mut f.pm, f.first, station, 0x1);
    assert_eq!(
        search(&f.pm, first_pid, None, Some(DESKTOP_TYPE), None),
        Ok(None),
        "a WindowStation handle never satisfies a Desktop filter"
    );
    assert_eq!(f.pm.handle_count(second_pid), counts.1, "search acquires no reference");
    assert_eq!(
        f.pm.find_native_user_object_handle(f.first, second_pid, None, None, None),
        Err(crate::STATUS_ACCESS_DENIED),
        "ObFindHandleForObject is a kernel-mode search"
    );
}

#[test]
fn a_kernel_caller_restricted_to_user_mode_gets_user_mode_checks_only() {
    let mut f = fixture();
    let handle = publish(&mut f.pm, f.first_kernel, target(0x1000, 1), 0x1);
    let user = f.first_kernel.restricted_to(AccessMode::UserMode);
    assert_eq!(user.mode(), AccessMode::UserMode);
    assert_eq!(user.effective_process(), f.first_kernel.effective_process());
    assert_eq!(
        lookup(&f.pm, user, handle, 0x2, None),
        Err(crate::STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        lookup(&f.pm, f.first_kernel, handle, 0x2, None),
        Ok(target(0x1000, 1))
    );
    assert_eq!(f.first.restricted_to(AccessMode::KernelMode).mode(), AccessMode::UserMode,
        "restriction never gains kernel mode");
}

#[test]
fn lookup_reports_the_exact_handle_information() {
    let mut f = fixture();
    let mut publication = f.pm.reserve_native_user_object_handle(f.first, 2).unwrap();
    publication.bind(&mut f.pm, target(0x1000, 1), 0x1ff).unwrap();
    let handle = publication.publish(&mut f.pm).unwrap();
    assert_eq!(
        f.pm.lookup_native_user_object_handle(f.first, handle, 0, None),
        Ok((
            target(0x1000, 1),
            NativeHandleInformation { attributes: 2, granted_access: Some(0x1ff) }
        ))
    );
}
