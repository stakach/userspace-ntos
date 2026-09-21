//! Preserve the caller kind across a provider wait without inventing a hosted requestor.

use super::*;
use nt_provider_wait::{ProviderWaitOwner, ProviderWaitRequest, SuspensionCaller};

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
            SuspensionCaller::Hosted(client) => {
                let frame = (WIN32K_SHARED_VADDR + SH_USER_CALLBACK)
                    as *const nt_user_callback::CallbackFrame;
                let header = read_volatile(core::ptr::addr_of!((*frame).header));
                if header.dispatch_id != request.owner.dispatch_id
                    || header.client_pi != client.client_pi
                    || header.client_tid != client.client_tid
                    || header.client_badge != client.client_badge
                {
                    return Err(0xC000_000D);
                }
                callback_request_context_for_request(&header)
                    .map(Self::Hosted)
                    .ok_or(0xC000_000D)
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
