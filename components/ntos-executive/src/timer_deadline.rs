//! Value-only owner deadlines combined with canonical global sources at one clock snapshot.

use super::*;

pub(super) struct OwnerDeadlines {
    pub dispatcher: nt_user_host::dispatcher_deadlines::DispatcherDeadlines,
    pub user_timer: Option<u64>,
    pub job_time: Option<u64>,
    pub component_resume: Option<u64>,
}

/// Retry owners may reconcile retained demand at this snapshot. No notification acknowledgment,
/// wait selection, hardware rearm or provider execution occurs here.
/// Candidate order preserves the established equal-deadline source precedence.
pub(super) unsafe fn next(now: nt_time::TimeSnapshot, owner: OwnerDeadlines) -> Option<(u64, u64)> {
    nt_time::earliest_deadline([
        (owner.dispatcher.delay, DELAY_TIMER_SOURCE_DELAY_QUEUE),
        (
            object_waiter_next_deadline(now),
            DELAY_TIMER_SOURCE_EVENT_WAIT,
        ),
        (
            (&*core::ptr::addr_of!(KEYED_WAITERS)).next_deadline(now),
            DELAY_TIMER_SOURCE_KEYED_WAIT,
        ),
        (
            (&*core::ptr::addr_of!(KEYED_RELEASE_WAITERS)).next_deadline(now),
            DELAY_TIMER_SOURCE_KEYED_RELEASE,
        ),
        (
            (&*core::ptr::addr_of!(IO_COMPLETION_WAITERS)).next_deadline(now),
            DELAY_TIMER_SOURCE_IO_COMPLETION,
        ),
        (owner.user_timer, DELAY_TIMER_SOURCE_USER_TIMER),
        (
            service_sec_image::provider_wait_next_deadline(now),
            DELAY_TIMER_SOURCE_PROVIDER_WAIT,
        ),
        (
            owner.dispatcher.provider_timer,
            DELAY_TIMER_SOURCE_PROVIDER_TIMER,
        ),
        (
            driver_launch::hosted_driver_timer_next_deadline(now),
            DELAY_TIMER_SOURCE_HOSTED_KERNEL_TIMER,
        ),
        (
            driver_launch::hosted_driver_wait_next_deadline(now),
            DELAY_TIMER_SOURCE_HOSTED_DRIVER,
        ),
        (
            driver_launch::hosted_acpi_pci_route_recovery_next_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_ACPI_PCI_ROUTE_RECOVERY,
        ),
        (owner.job_time, DELAY_TIMER_SOURCE_JOB_TIME),
        (
            driver_launch::driver_registry_close_retry_deadline(),
            DELAY_TIMER_SOURCE_REGISTRY_CLOSE,
        ),
        (
            cm_key_ownership::next_deadline(),
            DELAY_TIMER_SOURCE_CM_KEY_CLEANUP,
        ),
        (
            cm_snapshot_ownership::next_deadline(),
            DELAY_TIMER_SOURCE_CM_SNAPSHOT_CLEANUP,
        ),
        (
            driver_launch::hosted_file_retry_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_HOSTED_FILE_RETRY,
        ),
        (owner.component_resume, DELAY_TIMER_SOURCE_COMPONENT_RESUME),
        (watchdog_deadline(), DELAY_TIMER_SOURCE_WATCHDOG),
        (
            driver_launch::hosted_dpc_next_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_HOSTED_DPC,
        ),
    ])
}
