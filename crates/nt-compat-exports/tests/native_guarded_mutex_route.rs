//! A guarded mutex must use exact thread state and a retained gate continuation.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const BRIDGE: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_guarded_mutex.rs");
const POOL: &str = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");

#[test]
fn exports_and_pump_dispatch_use_root_owned_guarded_mutex_service() {
    for (export, thunk) in [
        ("KeInitializeGuardedMutex", "initialize"),
        ("KeAcquireGuardedMutex", "acquire"),
        ("KeReleaseGuardedMutex", "release"),
    ] {
        assert!(LAUNCH.contains(&format!("\"{export}\",\n        hosted_driver_guarded_mutex::{thunk}")));
    }
    assert!(LAUNCH.contains("FSD_SERVICE_GUARDED_MUTEX_LABEL: u64 = hosted_driver_guarded_mutex::LABEL"));
    assert!(PUMP.contains("label == crate::driver_launch::FSD_SERVICE_GUARDED_MUTEX_LABEL"));
    assert!(PUMP.contains("service_hosted_driver_guarded_mutex("));
    assert!(PUMP.contains("HostedDriverWaitServiceResult::SharedParked { .. }"));
}

#[test]
fn contention_parks_exact_ticket_and_cancellation_balances_guarded_region() {
    for required in [
        "instance_for_pump_channel(ch, reply)",
        "hosted_driver_caller(instance, inst, badge)",
        "instance_domain_identity(inst)",
        "pool_range_identity_unlocked(inst, component, MUTEX_BYTES)",
        "hosted_driver_kmutex::owner_body(ch, inst)",
        "store().begin_wait(exec as *mut u8, thread_body,",
        "GuardedMutexWaitAdmission::Queued(ticket)",
        "park_hosted_driver_wait(instance, caller.thread_handle, caller.route,",
        "nt_kernel_exec::Deadline::Infinite",
        "store().granted(row.exec as *mut u8, row.thread_body, row.ticket)",
        "store().complete_wait(row.exec as *mut u8, row.thread_body, row.ticket)",
        "store().cancel_wait(row.exec as *mut u8, row.thread_body,",
        "store().release(row.exec as *mut u8, row.thread_body, row.thread_body as *mut u8)",
    ] {
        assert!(BRIDGE.contains(required), "missing retained guarded mutex contract: {required}");
    }
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::ready(object, thread)"));
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::consume(object, thread)"));
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::cancel_pending(instance, thread_handle, reply)"));
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::acknowledged(instance, thread_handle, reply, cancelled)"));
    assert!(POOL.contains("hosted_driver_guarded_mutex::pool_free_admission(domain, pool)"));
    assert!(POOL.contains("hosted_driver_guarded_mutex::pool_freed(domain, pool)"));
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::quiesced(domain)"));
    assert!(LAUNCH.contains("hosted_driver_guarded_mutex::retire_domain(domain)"));
    assert!(!BRIDGE.contains("spin_loop"));
}
