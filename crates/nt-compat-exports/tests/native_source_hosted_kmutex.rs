//! The first dxgmms2 registration mutex must be a real signaled mutant.

#[test]
fn hosted_mutex_wait_and_release_are_root_owned() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let broker = include_str!("../../../components/ntos-executive/src/hosted_driver_kmutex.rs");
    assert!(launch.contains("\"KeInitializeMutex\",\n        hosted_driver_kmutex::initialize"));
    assert!(launch.contains("\"KeReleaseMutex\",\n        hosted_driver_kmutex::release"));
    for contract in [
        "hosted_driver_caller", "instance_for_pump_channel", "HostedKmutexManager",
        "wake_hosted_driver_waiters_for_instance", "retire_domain", "pool_free_admission",
    ] {
        assert!(broker.contains(contract), "missing mutex contract {contract}");
    }
}
