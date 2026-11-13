//! Event admission of the service loop (issue #382, loop hoist).

use super::*;

/// The admitted event of one turn: who sent it, which roles that thread has and the
/// geometry of its process. Admission builds it once; the arms read it.
pub(super) struct Event<'e> {
    pub(super) event_runtime: HostedThreadRuntime,
    pub(super) is_svc_listener: bool,
    pub(super) is_lsass_listener: bool,
    pub(super) is_lsass_listener2: bool,
    pub(super) is_lsass_listener3: bool,
    pub(super) is_tp_worker: bool,
    pub(super) is_scm_worker: bool,
    pub(super) is_lsa_worker: bool,
    pub(super) is_lsa_auth_server: bool,
    pub(super) is_wl_worker: bool,
    pub(super) pi: usize,
    pub(super) native_ingress_request: Option<nt_syscall_abi::NativeSyscallRequest>,
    pub(super) scratch_base: u64,
    pub(super) pml4: u64,
    pub(super) hosted_thread_role: Option<HostedThreadRole>,
    /// The executable of the event's process. A raw pointer, because the reference it comes
    /// from borrows the loaded-image table that the arms also reach through `LoopState`. The
    /// event's image read scope keeps the parsed image alive for the turn.
    pub(super) pe: *const nt_pe_loader::PeFile<'e>,
    pub(super) img_end: u64,
    pub(super) img_base: u64,
}
