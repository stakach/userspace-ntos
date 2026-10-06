//! Captured component continuation and completion payloads.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum PendingComponentDispatch {
    Provider(win32k_glue::PendingProviderWaitDispatch),
    Lpc(win32k_glue::PendingLpcWaitDispatch),
    Receive(win32k_glue::PendingReceiveDispatch),
}

impl PendingComponentDispatch {
    pub(super) fn client(self) -> win32k_glue::Win32kClientContext {
        match self {
            Self::Provider(pending) => pending.client,
            Self::Lpc(pending) => pending.client,
            Self::Receive(pending) => pending.client,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ComponentSuspensionCompletion {
    pub(super) status: i32,
    pub(super) lpc_message_id: u32,
    pub(super) lpc_reply_len: u32,
    pub(super) lpc_reply: [u8; nt_lpc_abi::PORT_MESSAGE_MAX_LEN],
}

impl ComponentSuspensionCompletion {
    /// Internal receive readiness, never supplied as a provider wait result or user Reply.
    pub(super) const fn receive_ready() -> Self {
        Self::provider(0)
    }
    pub(super) const fn provider(status: i32) -> Self {
        Self {
            status,
            lpc_message_id: 0,
            lpc_reply_len: 0,
            lpc_reply: [0; nt_lpc_abi::PORT_MESSAGE_MAX_LEN],
        }
    }

    pub(super) fn lpc(status: i32, message_id: u32, reply: &[u8]) -> Option<Self> {
        if reply.len() > nt_lpc_abi::PORT_MESSAGE_MAX_LEN {
            return None;
        }
        let mut completion = Self {
            status,
            lpc_message_id: message_id,
            lpc_reply_len: reply.len() as u32,
            lpc_reply: [0; nt_lpc_abi::PORT_MESSAGE_MAX_LEN],
        };
        completion.lpc_reply[..reply.len()].copy_from_slice(reply);
        Some(completion)
    }

    pub(super) fn lpc_reply(&self) -> &[u8] {
        &self.lpc_reply[..self.lpc_reply_len as usize]
    }
}

#[derive(Clone, Copy)]
pub(super) struct HostedNativeContinuation {
    pub(super) pending: PendingComponentDispatch,
    pub(super) return_target: HostedReturnTarget<win32k_glue::StagedUserCallbackContext>,
}

#[derive(Clone, Copy)]
pub(crate) enum ComponentNativeContinuation {
    Hosted(HostedNativeContinuation),
    // Native blocking admission still requires the stopped-job scheduler and receive ownership.
    Kernel(nt_user_host::provider_kernel_activation::KernelProviderWaitCapture),
}

impl nt_user_host::provider_kernel_wait::KernelProviderWaitContinuation for ComponentNativeContinuation {
    fn kernel_wait_capture(&self) -> Option<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture> {
        match self {
            Self::Kernel(capture) => Some(*capture),
            Self::Hosted(_) => None,
        }
    }
}

impl ComponentNativeContinuation {
    pub(super) fn hosted(&self) -> Option<&HostedNativeContinuation> {
        match self {
            Self::Hosted(hosted) => Some(hosted),
            Self::Kernel(_) => None,
        }
    }

    pub(super) fn hosted_mut(&mut self) -> Option<&mut HostedNativeContinuation> {
        match self {
            Self::Hosted(hosted) => Some(hosted),
            Self::Kernel(_) => None,
        }
    }
}
