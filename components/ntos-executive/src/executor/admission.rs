//! Event admission of the service loop (issue #382, loop hoist).

use super::*;

/// The admitted event of one turn: who sent it, which roles that thread has and the
/// geometry of its process. Admission builds it once; the arms read it.
pub(super) struct Event {
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
}
