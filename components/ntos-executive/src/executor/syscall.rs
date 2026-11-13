//! The syscall arm of the service loop (issue #382, loop hoist).

use super::*;

/// What one syscall decides: its result, whether the NT or win32k route handled it, and the
/// park or transfer it asks the reply-or-park tail to perform. These were the mutable locals
/// the syscall prelude declared and the tail consumed.
pub(super) struct SyscallOutcome {
    pub(super) result: u64,
    pub(super) handled: bool,
    // Set by an accepted interactive milestone that parks the caller instead of replying.
    pub(super) wl_milestone_park: bool,
    // A blocking GetMessage park must not end the boot; the service loop keeps running.
    // (Phase 3: the `routed_win32k` / `routed_lpc` / `routed_csr` flags that used to live
    // here are GONE. They existed solely to steer this syscall's reply away from the legacy
    // `reply_to` — which a nested win32k / SM-loop / CSR-thread fault had clobbered — and
    // onto the caller's bound `REPLY_MAIN`. Every reply takes the bound object now, so there
    // is nothing left to steer. See the reply tail at the bottom of the syscall arm.)
    pub(super) redirected_user_callback: bool,
    pub(super) component_suspension_park_request: bool,
    pub(super) component_root_maintenance_ticket: Option<root_maintenance_owner::RootMaintenanceTicket>,
    pub(super) component_suspension_admitted_dispatch_id: u64,
    pub(super) current_apc_handoff: Option<nt_user_host::current_apc::CurrentApcIdentity>,
    pub(super) redirected_context_continue: bool,
    pub(super) active_callback_bad_resume: bool,
    // Checkpoint B: -1 = no wait-park; >=0 = NtWaitForSingleObject asked to park this caller on
    // the encoded WaitObject in nt_handler.wait_park_event after dispatch.
    pub(super) park_wait_event: i64,
    // Array-wait park: the typed dispatcher/process/thread/File set + WaitAll flag.
    // count 0 = no array-park. Consumed next to park_wait_event in the reply block.
    pub(super) park_wait_set: &'static mut [WaitObject; 64],
    pub(super) park_wait_indices: &'static mut [u8; 64],
    pub(super) park_wait_set_n: usize,
    pub(super) park_wait_set_all: bool,
    pub(super) park_wait_alertable: bool,
    pub(super) park_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_keyed_wait_key: u64,
    pub(super) park_keyed_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_keyed_release_wait_key: u64,
    pub(super) park_keyed_release_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_delay_deadline: Option<nt_delay_execution::Deadline>,
    pub(super) park_thread_alert_deadline: Option<nt_delay_execution::Deadline>,
    pub(super) park_io_completion_port: i64,
    pub(super) park_io_completion_key_out: u64,
    pub(super) park_io_completion_apc_out: u64,
    pub(super) park_io_completion_iosb_out: u64,
    pub(super) park_io_completion_deadline: nt_delay_execution::Deadline,
    pub(super) published_file_io: Option<file_dispatch_handoff::PublishedFileIo>,
    pub(super) transfer_pending_driver_start: Option<PendingDriverStartTransfer>,
    pub(super) transfer_native_directory_open: Option<crate::native_directory_open_work::PendingNativeDirectoryOpen>,
    pub(super) transfer_native_file_target: Option<crate::native_file_target_open_work::PendingNativeFileTargetOpen>,
    pub(super) transfer_native_directory_effect: Option<crate::native_directory_effect_work::PendingNativeDirectoryEffect>,
    pub(super) transfer_pending_pnp_operation: Option<PendingPnpOperationTransfer>,
    pub(super) transfer_file_irp_drain: Option<(nt_io_manager::PendingFileIrpDrain, nt_io_manager::PendingFileIrpDrainReservation)>,
    pub(super) transfer_file_cleanup_wait: Option<(nt_io_manager::PendingFileCleanupWait, nt_io_manager::PendingFileCleanupWaitReservation)>,
    pub(super) synchronous_file_wait_parked: bool,
    pub(super) park_lpc_receive: Option<PendingLpcReceivePark>,
    pub(super) park_lpc_connect: Option<PendingLpcConnectPark>,
    pub(super) park_lpc_request: Option<PendingLpcRequestPark>,
    // ★ Dbgk TARGET-SIDE BLOCK request (syscall flavour) latched out of the handler:
    // a debug event was posted from THIS syscall arm and NT blocks the reporting thread on
    // the debugger's continue. Consumed at the reply site (the reply-cap steal needs
    // resume_ip/sp/flags, known only there). Always false with no debugger attached.
    pub(super) park_dbgk_reporter: bool,
}

impl SyscallOutcome {
    pub(super) unsafe fn new() -> Self {
        Self {
            result: 0,
            handled: true,
            wl_milestone_park: false,
            redirected_user_callback: false,
            component_suspension_park_request: false,
            component_root_maintenance_ticket: None,
            component_suspension_admitted_dispatch_id: 0,
            current_apc_handoff: None,
            redirected_context_continue: false,
            active_callback_bad_resume: false,
            park_wait_event: -1,
            park_wait_set: &mut *core::ptr::addr_of_mut!(PARK_WAIT_SET_WORK),
            park_wait_indices: &mut *core::ptr::addr_of_mut!(PARK_WAIT_INDEX_WORK),
            park_wait_set_n: 0,
            park_wait_set_all: false,
            park_wait_alertable: false,
            park_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_keyed_wait_key: u64::MAX,
            park_keyed_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_keyed_release_wait_key: u64::MAX,
            park_keyed_release_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_delay_deadline: None,
            park_thread_alert_deadline: None,
            park_io_completion_port: -1,
            park_io_completion_key_out: 0,
            park_io_completion_apc_out: 0,
            park_io_completion_iosb_out: 0,
            park_io_completion_deadline: nt_delay_execution::Deadline::Infinite,
            published_file_io: None,
            transfer_pending_driver_start: None,
            transfer_native_directory_open: None,
            transfer_native_file_target: None,
            transfer_native_directory_effect: None,
            transfer_pending_pnp_operation: None,
            transfer_file_irp_drain: None,
            transfer_file_cleanup_wait: None,
            synchronous_file_wait_parked: false,
            park_lpc_receive: None,
            park_lpc_connect: None,
            park_lpc_request: None,
            park_dbgk_reporter: false,
        }
    }
}
