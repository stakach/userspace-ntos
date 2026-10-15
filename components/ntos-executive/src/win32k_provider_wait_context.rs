//! Preserve the caller kind across a provider wait without inventing a hosted requestor.

use super::*;
use nt_provider_wait::{ProviderWaitOwner, ProviderWaitRequest, SuspensionCaller};

static HOSTED_WAIT_CONTEXT_REJECT_TRACE_N: AtomicU64 = AtomicU64::new(0);

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
                    let activation = active_provider_stack_event_activation()
                        .ok_or(0xC000_000Du32)?;
                    if current_provider_wait_owner() != Some(request.owner) {
                        trace_hosted_wait_context_reject(b"activation-owner", request.owner, &shared);
                        return Err(0xC000_000D);
                    }
                    let Some(retained) = retained_hosted_wait_header(activation, request.owner)
                        .filter(|header| hosted_wait_header_matches_owner(header, request.owner))
                    else {
                        trace_hosted_wait_context_reject(b"header-mismatch", request.owner, &shared);
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
                Ok(Self::Kernel {
                    activation,
                    owner: request.owner,
                })
            }
        }
    }

    pub(super) unsafe fn restore(self) -> bool {
        match self {
            Self::Hosted(context) => restore_user_callback_request_context(context),
            Self::Kernel { activation, owner } => {
                // Nested dispatch guards retire their own activation before returning here.
                // Validate the original stack-local owner; never republish a shared descriptor.
                active_provider_stack_event_activation() == Some(activation)
                    && current_provider_wait_owner() == Some(owner)
            }
        }
    }
}
