//! Caller-aware, memory-local publication before the dispatcher arbiter consumes readiness.

use super::*;
use nt_component_suspension::{LaneHandle, SuspensionCaller};
use nt_provider_wait::ProviderDispatcherWaitCompletion;
use nt_user_host::provider_wait_selection::{select_provider_wait, ProviderWaitSelectionError};

pub(super) unsafe fn publish(
    completion: ProviderDispatcherWaitCompletion,
) -> Result<LaneHandle, ProviderWaitSelectionError<u32>> {
    select_provider_wait(
        &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS),
        completion,
        |lane, continuation, completion| {
            const INVALID_HANDLE: u32 = 0xC000_0008;
            match (completion.owner.caller, continuation) {
                (SuspensionCaller::Hosted(client), ComponentNativeContinuation::Hosted(hosted)) => {
                    let PendingComponentDispatch::Provider(pending) = &hosted.pending else {
                        return Err(INVALID_HANDLE);
                    };
                    let request = pending.request.validate().map_err(|_| INVALID_HANDLE)?;
                    if request.owner != completion.owner
                        || request.wait_id != completion.wait_id
                        || pending.dispatch.lane != lane
                        || pending.dispatch.dispatch_id != completion.owner.dispatch_id
                        || pending.client.pi != client.client_pi
                        || pending.client.generation != client.client_generation
                        || pending.client.tid != client.client_tid
                        || pending.client.badge != client.client_badge
                    {
                        return Err(INVALID_HANDLE);
                    }
                }
                (
                    SuspensionCaller::Kernel { lane: owner_lane },
                    ComponentNativeContinuation::Kernel(capture),
                ) => {
                    if owner_lane != lane
                        || capture.caller().owner() != completion.owner
                        || capture.key() != provider_wait_key(completion.wait_id)
                    {
                        return Err(INVALID_HANDLE);
                    }
                }
                _ => return Err(INVALID_HANDLE),
            }
            // Provider status is caller-neutral. The retained typed continuation, not a
            // fabricated hosted return target, determines the eventual execution/delivery path.
            Ok(ComponentSuspensionCompletion::provider(completion.status))
        },
    )
}
