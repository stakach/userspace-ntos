//! The user-mode performance counter must report the same clock and frequency as the
//! executive's monotonic timing authority, even when the guest TSC is not invariant.

const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

#[test]
fn native_performance_counter_uses_monotonic_snapshot_and_preserves_optional_frequency() {
    let body = EXEC
        .split("NativeService::NtQueryPerformanceCounter => {")
        .nth(1)
        .and_then(|body| body.split("NativeService::NtQueryVolumeInformationFile =>").next())
        .expect("native performance counter service");

    assert!(body.contains("nt_time_snapshot().performance_counter()"));
    assert!(!body.contains("_rdtsc"), "raw TSC has no coherent 1 GHz guest contract");
    assert!(body.contains("self.queue_write(ctr_ptr, now)"));
    assert!(body.contains("if freq_ptr != 0") && body.contains("self.queue_write(freq_ptr, freq)"));
}
