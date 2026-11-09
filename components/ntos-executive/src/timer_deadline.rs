//! Value-only owner deadlines combined with canonical global sources at one clock snapshot.

use super::*;

pub(super) struct OwnerDeadlines {
    pub dispatcher: nt_user_host::dispatcher_deadlines::DispatcherDeadlines,
    pub user_timer: Option<u64>,
    pub job_time: Option<u64>,
    pub component_resume: Option<u64>,
    pub root_add_device: Option<u64>,
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
        (thread_alert::next_deadline(now), DELAY_TIMER_SOURCE_THREAD_ALERT),
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
            driver_launch::hosted_driver_dynamic_delete::next_deadline(),
            DELAY_TIMER_SOURCE_HOSTED_DYNAMIC_DELETE,
        ),
        (
            driver_launch::hosted_provider_export_lane::next_deadline(),
            DELAY_TIMER_SOURCE_HOSTED_PROVIDER_STARTUP_RESTORE,
        ),
        (
            spawn_hosts::shared_ingress::owner::runtime::nested::next_abort_deadline(),
            DELAY_TIMER_SOURCE_NESTED_ACQUIRE_ABORT,
        ),
        (
            win32k_glue::win32k_startup_restore_next_deadline(),
            DELAY_TIMER_SOURCE_WIN32K_STARTUP_RESTORE,
        ),
        (
            driver_launch::hosted_acpi_pci_route_recovery_next_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_ACPI_PCI_ROUTE_RECOVERY,
        ),
        (owner.job_time, DELAY_TIMER_SOURCE_JOB_TIME),
        (
            cm_key_ownership::next_deadline(),
            DELAY_TIMER_SOURCE_CM_KEY_CLEANUP,
        ),
        (
            cm_snapshot_ownership::next_deadline(),
            DELAY_TIMER_SOURCE_CM_SNAPSHOT_CLEANUP,
        ),
        (
            registry_mutation_work::next_deadline(),
            DELAY_TIMER_SOURCE_REGISTRY_MUTATION,
        ),
        (section_metadata_work::next_deadline(), DELAY_TIMER_SOURCE_SECTION_METADATA),
        (process_image_snapshot_work::next_deadline(),
            DELAY_TIMER_SOURCE_PROCESS_IMAGE_SNAPSHOT),
        (provider_section_broker::next_deadline(), DELAY_TIMER_SOURCE_PROVIDER_SECTION),
        (gdi_routed_image_work::next_deadline(), DELAY_TIMER_SOURCE_GDI_ROUTED_IMAGE),
        (
            provider_directory_broker::next_deadline(),
            DELAY_TIMER_SOURCE_PROVIDER_DIRECTORY,
        ),
        (
            driver_launch::hosted_file_retry_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_HOSTED_FILE_RETRY,
        ),
        (
            driver_launch::mounted_native_block_next_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_MOUNTED_NATIVE_BLOCK,
        ),
        (owner.component_resume, DELAY_TIMER_SOURCE_COMPONENT_RESUME),
        (owner.root_add_device, DELAY_TIMER_SOURCE_ROOT_ADD_DEVICE_RETRY),
        (
            service_sec_image::system_wal_fold_next_deadline(),
            DELAY_TIMER_SOURCE_SYSTEM_WAL_FOLD,
        ),
        (watchdog_deadline(), DELAY_TIMER_SOURCE_WATCHDOG),
        (
            driver_launch::hosted_dpc_next_deadline(now.monotonic_100ns),
            DELAY_TIMER_SOURCE_HOSTED_DPC,
        ),
        (
            driver_launch::hosted_irq_retry_next_deadline(),
            DELAY_TIMER_SOURCE_HOSTED_IRQ_RETRY,
        ),
    ])
}
