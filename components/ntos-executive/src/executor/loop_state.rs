//! State of the hosted service loop (issue #382, loop hoist).
//!
//! The loop in `service_sec_image()` kept its state in function locals captured by local
//! macros. Those locals become the fields of `LoopState`, grouped by concern; each group is
//! also a borrow unit, so a helper takes the groups it needs while its caller still holds a
//! reference into another group.
//!
//! This file is declared from `service_sec_image.rs`: the loop still reaches that module's
//! private helpers, so the hoisted files stay its children until those helpers are ported.

use super::*;

/// How a helper that ends the current turn leaves it: `Next` was `continue 'service_loop`,
/// `Exit` was `break 'service_loop`.
pub(super) enum Turn {
    Next,
    Exit,
}

/// The verdict the service loop returns to `_start`, and the working fault counters of the
/// process whose event is being served.
pub(super) struct LoopExit {
    /// Working copies of `procs[pi].{faults, first, ntfaults}`: loaded at event admission
    /// and saved back before each receive.
    pub(super) faults: u64,
    pub(super) first: u64,
    pub(super) ntfaults: u64,
    pub(super) stop: u64,
    pub(super) stop_ssn: u64,
    /// A single terminal receipt identifies which safety gate ended the serialized loop.
    /// The source location is recorded at the branch, before any quiesce checkpoint can fail.
    pub(super) service_loop_exit_site: u32,
    pub(super) service_loop_exit_reason: &'static [u8],
    pub(super) iters: u64,
    pub(super) dbgsvc: u64,
}

impl LoopExit {
    pub(super) fn new() -> Self {
        Self {
            faults: 0,
            first: 0,
            ntfaults: 0,
            stop: 0,
            stop_ssn: 0,
            service_loop_exit_site: 0,
            service_loop_exit_reason: b"unrecorded",
            iters: 0,
            dbgsvc: 0,
        }
    }

    /// Record the branch that ends the loop. The site is the line of the outermost call, as
    /// `line!()` reported it while this was a local macro.
    #[track_caller]
    pub(super) fn record(&mut self, reason: &'static [u8]) {
        self.service_loop_exit_site = core::panic::Location::caller().line();
        self.service_loop_exit_reason = reason;
    }
}

/// Per-process park masks. See the park and quiesce contract in `service_sec_image()`.
pub(super) struct Parks {
    /// Top-level process badges that have hit an unrecoverable crash.
    pub(super) crash_parked: u64,
    /// Which THREAD badges have already logged a `[parked]` fault line (see `park_and_log!`).
    pub(super) crash_logged: u64,
    /// Cooperative-wait owner mask, derived from THREAD_WAIT_PARKED. Each deadline-less park
    /// records the actual hosted thread badge; completion paths clear that badge when they
    /// resume the stolen reply cap. A process contributes to this mask only when every live
    /// hosted thread with a real TCB is parked, so ordinary worker churn no longer clears or
    /// sets process liveness as a side effect.
    pub(super) wait_parked: u64,
}

/// Diagnostic rings, the forward-progress watchdog and the wall-clock census.
pub(super) struct Diag {
    /// Ring of the last serviced SSNs and the badge that issued each.
    pub(super) ssn_ring: &'static mut [u16; 32],
    pub(super) ssn_ring_badge: &'static mut [u8; 32],
    /// winlogon-main-only ring (badge==WINLOGON_BADGE), isolating winlogon's sequence from
    /// the services noise that dominates the shared ring.
    pub(super) wl_ring: &'static mut [u16; 48],
    pub(super) wl_ri: usize,
    pub(super) ssn_ri: usize,
    /// Boot-milestone watchdog state is wall-clock based: `last_progress_t` is the monotonic
    /// time (100ns units) at the last epoch bump. An expired milestone window requests
    /// bounded stall validation, not proof of a deadlock.
    pub(super) progress_epoch: fn() -> u64,
    pub(super) last_progress_epoch: u64,
    pub(super) last_progress_t: u64,
    pub(super) stall_deferrals: nt_hosted_runtime::ProgressDeferralBudget<super::StallDeferralSnapshot>,
    /// FORWARD-PROGRESS CENSUS (see `print_progress_census`): attribute the wall-clock
    /// between two consecutive loop tops to the badge that was serviced in between.
    pub(super) census_prev_t: u64,
    pub(super) census_prev_badge: usize,
    /// Print budgets of the ALPC create and send ingress traces.
    pub(super) alpc_create_ingress_trace: AtomicU64,
    pub(super) alpc_send_ingress_trace: AtomicU64,
}

/// The event being served: the badge and message registers of the last receive.
pub(super) struct Message {
    pub(super) badge: u64,
    pub(super) mi: u64,
    pub(super) m0: u64,
    pub(super) m1: u64,
    pub(super) m2: u64,
    pub(super) m3: u64,
}

/// Receive state. The two root-turn fields are deleted by the later turn conversion.
pub(super) struct Ingress {
    pub(super) fault_ep: u64,
    /// Bootstrap and runtime retain one queue at the same address; only the stable owner
    /// address is kept across nested driver dispatch.
    pub(super) delay_queue: *mut nt_delay_execution::Queue,
    pub(super) receive_boundary: Option<crate::spawn_hosts::shared_ingress::owner::runtime::ReceiveSettlementBoundary>,
    pub(super) root_add_device_turn: Option<RootAddDeviceTurn>,
    pub(super) add_device_selection_evidence: nt_driver_start::AddDeviceSelectionEvidence<RootAddDeviceOwner>,
    pub(super) root_queued_callback_turn: Vec<RootQueuedCallbackTurn>,
    #[cfg(not(feature = "mup-provider-kernel-only"))]
    pub(super) primary_alias_activation: nt_hosted_runtime::PrimaryAliasActivation,
}

/// Per-hosted-process tables, indexed by process index.
pub(super) struct Procs {
    pub(super) procs: &'static mut [ProcExec],
    /// Per-process demand-fill bookkeeping, saved from and loaded into `filled_pages`.
    pub(super) pfilled: &'static mut [[u64; 512]],
    /// Working buffer for the current process's demand-filled page VAs.
    pub(super) filled_pages: &'static mut [u64; 512],
    pub(super) primary_pi: usize,
    pub(super) csrss_process_handle: u64,
}

/// Image and DLL tables. `reg`, `pe` and `ntdll` borrow objects owned by the setup frame of
/// `service_sec_image()`, whose addresses the handler's loop context already records.
pub(super) struct Images<'a> {
    pub(super) exe_images: &'static mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
    pub(super) exe_image_catalog:
        &'static mut nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    pub(super) generic_sections: *mut GenericSectionTable,
    pub(super) hosted_loaded_images: &'static mut HostedLoadedImageTable,
    pub(super) hosted_loaded_images_ptr: *mut HostedLoadedImageTable,
    pub(super) dll_pe_store: &'static mut DllPeStore,
    pub(super) reg: &'a mut nt_dll_registry::Registry,
    /// The primary image and the shared ntdll.
    pub(super) pe: &'a nt_pe_loader::PeFile<'a>,
    pub(super) ntdll: (u64, &'a nt_pe_loader::PeFile<'a>),
    pub(super) nt_base: u64,
}

pub(super) struct LoopState<'a> {
    pub(super) exit: LoopExit,
    pub(super) parks: Parks,
    pub(super) diag: Diag,
    pub(super) msg: Message,
    pub(super) ingress: Ingress,
    pub(super) procs: Procs,
    pub(super) images: Images<'a>,
    /// The primary process's loop context, as setup published it. Admission derives each
    /// event's context from it.
    pub(super) memory_context: ExecLoopCtx,
    pub(super) handler: &'static mut ExecNtHandler,
    pub(super) dispatcher: &'a NativeSyscallDispatcher,
}
