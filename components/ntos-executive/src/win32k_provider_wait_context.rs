//! Preserve the caller kind across a provider wait without inventing a hosted requestor.

use super::*;
use nt_kernel_exec::win32k_lane_context::{PsProviderWaitIdentity, PsProviderWaitTarget};
use nt_provider_wait::{ProviderWaitOwner, ProviderWaitRequest, SuspensionCaller};

static HOSTED_WAIT_CONTEXT_REJECT_TRACE_N: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum KernelWaitTarget {
    InitialSystem,
    Ps(PsProviderWaitTarget),
}

/// Resolve the suspended Ps target through the retained process incarnation and, when present,
/// its exact thread record. A process-exit callout may have no GUI thread record; its canonical
/// ETHREAD fields and TEB still have to match the retained target.
unsafe fn live_ps_wait_identity(target: PsProviderWaitTarget) -> Option<PsProviderWaitIdentity> {
    let process_index = process_context_index_for_pid(target.process_id)?;
    if process_ctx_pi(process_index) != target.client_pi
        || process_ctx_generation(process_index) != target.process_generation
        || process_ctx_eprocess(process_index) != target.eprocess
    {
        return None;
    }
    provider_ps_lifecycle::validate_ps_provider_execution_thread(
        target.process_id,
        target.thread_id,
        target.eprocess,
        target.ethread,
    )
    .ok()?;
    let thread_index = thread_context_index_for_tid(target.thread_id);
    if thread_index.is_some() != target.thread_recorded {
        return None;
    }
    if let Some(index) = thread_index {
        if thread_ctx_pid(index) != target.process_id
            || thread_ctx_pi(index) != target.client_pi
            || thread_ctx_generation(index) != target.process_generation
            || thread_ctx_ethread(index) != target.ethread
        {
            return None;
        }
        let recorded_teb = thread_ctx_teb(index);
        let callout_teb = thread_ctx_callout_teb(index);
        if target.teb != recorded_teb
            && target.teb != callout_teb
            && provider_ps_lifecycle::read_ps_provider_execution_teb(target.ethread, target.teb)
                .is_err()
        {
            return None;
        }
    } else {
        provider_ps_lifecycle::read_ps_provider_execution_teb(target.ethread, target.teb).ok()?;
    }
    Some(PsProviderWaitIdentity {
        client_pi: process_ctx_pi(process_index),
        process_id: process_ctx_pid(process_index),
        thread_id: target.thread_id,
        process_generation: process_ctx_generation(process_index),
        eprocess: process_ctx_eprocess(process_index),
        ethread: target.ethread,
    })
}

unsafe fn ps_wait_projection_is_live(target: PsProviderWaitTarget) -> bool {
    let Some(process_index) = process_context_index_for_pid(target.process_id) else {
        return false;
    };
    target.selected_process == process_attach::selected_process(target.ethread, target.eprocess)
        && target.w32process
            == process_attach::selected_win32process(
                target.ethread,
                target.eprocess,
                process_ctx_w32process(process_index),
            )
        && target.w32thread
            == read_volatile((target.ethread + KTHREAD_WIN32THREAD_OFF) as *const u64)
}

unsafe fn capture_kernel_wait_target() -> Option<KernelWaitTarget> {
    let pi = current_lane_ids().client_pi.load(Ordering::Relaxed);
    let pid = current_lane_ids().process_id.load(Ordering::Relaxed);
    let tid = current_lane_ids().thread_id.load(Ordering::Relaxed);
    if pi == MAX_PI as u64 {
        let system = crate::ps_bootstrap::initial_system_projection()?;
        return (pid == u64::from(system.identity.process_id())
            && tid == u64::from(system.identity.thread_id())
            && current_eprocess() == system.process_body
            && current_ethread() == system.thread_body)
            .then_some(KernelWaitTarget::InitialSystem);
    }
    checked_client_index(pi)?;
    let process_index = process_context_index_for_pid(pid)?;
    let eprocess = process_ctx_eprocess(process_index);
    let ethread = current_ethread();
    let target = PsProviderWaitTarget {
        client_pi: pi,
        process_id: pid,
        thread_id: tid,
        process_generation: process_ctx_generation(process_index),
        eprocess,
        ethread,
        teb: read_volatile((current_kpcr_va() + 0x30) as *const u64),
        selected_process: current_eprocess(),
        w32process: read_volatile(current_w32process_slot() as *const u64),
        w32thread: read_volatile(current_w32thread_slot() as *const u64),
        thread_recorded: thread_context_index_for_tid(tid).is_some(),
    };
    let live = live_ps_wait_identity(target)?;
    if !ps_wait_projection_is_live(target) {
        return None;
    }
    Some(KernelWaitTarget::Ps(target.capture(live)?))
}

unsafe fn restore_kernel_wait_target(target: KernelWaitTarget) -> bool {
    let KernelWaitTarget::Ps(target) = target else {
        return select_initial_system_context();
    };
    let Some(live) = live_ps_wait_identity(target) else {
        return false;
    };
    if !target.permits_restore(live) || !ps_wait_projection_is_live(target) {
        return false;
    }
    let process_index = match process_context_index_for_pid(target.process_id) {
        Some(index) => index,
        None => return false,
    };
    current_lane_ids()
        .client_pi
        .store(target.client_pi, Ordering::Relaxed);
    current_lane_ids()
        .process_id
        .store(target.process_id, Ordering::Relaxed);
    current_lane_ids()
        .thread_id
        .store(target.thread_id, Ordering::Relaxed);
    write_volatile((current_kpcr_va() + 0x30) as *mut u64, target.teb);
    write_volatile(
        (current_kpcr_va() + 0x60) as *mut u64,
        target.selected_process,
    );
    write_volatile((current_kpcr_va() + 0x188) as *mut u64, target.ethread);
    write_volatile(current_w32process_slot() as *mut u64, target.w32process);
    write_volatile(current_w32thread_slot() as *mut u64, target.w32thread);
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_PROCESS_ID) as *mut u64,
        target.process_id,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_THREAD_ID) as *mut u64,
        target.thread_id,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_EPROCESS) as *mut u64,
        target.eprocess,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_ETHREAD) as *mut u64,
        target.ethread,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_W32PROCESS) as *mut u64,
        process_ctx_w32process(process_index),
    );
    let w32thread = thread_context_index_for_tid(target.thread_id)
        .map(|index| thread_ctx_w32thread(index))
        .unwrap_or(0);
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_W32THREAD) as *mut u64,
        w32thread,
    );
    true
}

fn trace_hosted_wait_context_reject(
    stage: &[u8],
    owner: ProviderWaitOwner,
    header: &nt_user_callback::CallbackHeader,
) {
    if HOSTED_WAIT_CONTEXT_REJECT_TRACE_N.fetch_add(1, Ordering::Relaxed) >= 12 {
        return;
    }
    let SuspensionCaller::Hosted(client) = owner.caller else {
        return;
    };
    print_str(b"[win32k-provider-wait-context-reject] stage=");
    print_str(stage);
    print_str(b" owner=");
    print_u64(owner.dispatch_id);
    print_str(b"/");
    print_u64(client.client_pi as u64);
    print_str(b"/");
    print_u64(client.client_tid);
    print_str(b"/");
    print_u64(client.client_badge);
    print_str(b" header=");
    print_u64(header.dispatch_id);
    print_str(b"/");
    print_u64(header.client_pi as u64);
    print_str(b"/");
    print_u64(header.client_tid);
    print_str(b"/");
    print_u64(header.client_badge);
    print_str(b"\n");
}

#[derive(Clone, Copy)]
pub(super) enum ProviderWaitContext {
    Hosted(Win32kCallbackRequestContext),
    Kernel {
        activation: ProviderStackEventActivation,
        owner: ProviderWaitOwner,
        target: KernelWaitTarget,
    },
}

impl ProviderWaitContext {
    pub(super) unsafe fn capture(request: &ProviderWaitRequest) -> Result<Self, u32> {
        let request = request.validate().map_err(|_| 0xC000_000Du32)?;
        match request.owner.caller {
            SuspensionCaller::Hosted(_) => {
                let frame = (WIN32K_SHARED_VADDR + SH_USER_CALLBACK)
                    as *const nt_user_callback::CallbackFrame;
                let shared = read_volatile(core::ptr::addr_of!((*frame).header));
                let header = if hosted_wait_header_matches_owner(&shared, request.owner) {
                    shared
                } else {
                    let activation =
                        active_provider_stack_event_activation().ok_or(0xC000_000Du32)?;
                    if current_provider_wait_owner() != Some(request.owner) {
                        trace_hosted_wait_context_reject(
                            b"activation-owner",
                            request.owner,
                            &shared,
                        );
                        return Err(0xC000_000D);
                    }
                    let Some(retained) = retained_hosted_wait_header(activation, request.owner)
                        .filter(|header| hosted_wait_header_matches_owner(header, request.owner))
                    else {
                        trace_hosted_wait_context_reject(
                            b"header-mismatch",
                            request.owner,
                            &shared,
                        );
                        return Err(0xC000_000D);
                    };
                    retained
                };
                match callback_request_context_for_request(&header) {
                    Some(context) => Ok(Self::Hosted(context)),
                    None => {
                        trace_hosted_wait_context_reject(b"client-context", request.owner, &header);
                        Err(0xC000_000D)
                    }
                }
            }
            SuspensionCaller::Kernel { .. } => {
                let activation = active_provider_stack_event_activation().ok_or(0xC000_000Du32)?;
                if current_provider_wait_owner() != Some(request.owner) {
                    return Err(0xC000_000D);
                }
                let target = capture_kernel_wait_target().ok_or(0xC000_000Du32)?;
                Ok(Self::Kernel {
                    activation,
                    owner: request.owner,
                    target,
                })
            }
        }
    }

    pub(super) unsafe fn restore(self) -> bool {
        match self {
            Self::Hosted(context) => restore_user_callback_request_context(context),
            Self::Kernel {
                activation,
                owner,
                target,
            } => {
                // Nested dispatch guards retire their own activation before returning here.
                // Validate the original stack-local owner before restoring this lane's
                // kernel caller; never republish a shared descriptor.
                let activation_is_current =
                    active_provider_stack_event_activation() == Some(activation);
                let owner_is_current = current_provider_wait_owner() == Some(owner);
                activation_is_current && owner_is_current && restore_kernel_wait_target(target)
            }
        }
    }
}
