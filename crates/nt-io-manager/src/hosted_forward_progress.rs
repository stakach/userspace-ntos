//! Dispatch-return policy for legacy hosted source IRPs, separate from terminal ownership.
//!
//! A disposition records a provider result; it neither authenticates a source ticket nor
//! releases its retained File, device, IRP, completion cursor, or reply owner.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedForwardDispatchReply {
    Rejected(i32),
    InlineTerminal(i32),
    Pending,
}

impl HostedForwardDispatchReply {
    /// Status and disposition share the existing service reply's two scalar words.
    pub const fn words(self) -> Option<(i32, u64)> {
        let pending = nt_status::NtStatus::PENDING.raw();
        match self {
            Self::Rejected(status) if status != pending => Some((status, 0)),
            Self::InlineTerminal(status) if status != pending => Some((status, 1)),
            Self::Pending => Some((pending, 2)),
            _ => None,
        }
    }

    pub const fn decode(status: i32, disposition: u64) -> Option<Self> {
        let pending = nt_status::NtStatus::PENDING.raw();
        match disposition {
            0 if status != pending => Some(Self::Rejected(status)),
            1 if status != pending => Some(Self::InlineTerminal(status)),
            2 if status == pending => Some(Self::Pending),
            _ => None,
        }
    }
}

/// Source output publication is distinct from the provider's dispatch return.
/// A genuine Pending dispatch returns before completion without publishing source output.
pub const fn hosted_forward_dispatch_reply_ready(
    reply: HostedForwardDispatchReply,
    source_terminal_published: bool,
) -> bool {
    match reply {
        HostedForwardDispatchReply::Rejected(_) | HostedForwardDispatchReply::Pending => true,
        HostedForwardDispatchReply::InlineTerminal(_) => source_terminal_published,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_and_inline_terminal_keep_their_existing_publication_boundaries() {
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::Rejected(-1), false));
        assert!(!hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::InlineTerminal(0), false));
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::InlineTerminal(0), true));
    }

    #[test]
    fn dispatch_disposition_roundtrip_rejects_pending_status_mismatch() {
        for reply in [
            HostedForwardDispatchReply::Rejected(nt_status::NtStatus::INVALID_HANDLE.raw()),
            HostedForwardDispatchReply::InlineTerminal(0),
            HostedForwardDispatchReply::InlineTerminal(nt_status::NtStatus::INVALID_PARAMETER.raw()),
            HostedForwardDispatchReply::Pending,
        ] {
            let (status, disposition) = reply.words().unwrap();
            assert_eq!(HostedForwardDispatchReply::decode(status, disposition), Some(reply));
        }
        let pending = nt_status::NtStatus::PENDING.raw();
        assert_eq!(HostedForwardDispatchReply::Rejected(pending).words(), None);
        assert_eq!(HostedForwardDispatchReply::InlineTerminal(pending).words(), None);
        for (status, disposition) in [(pending, 0), (pending, 1), (0, 2), (0, 3), (pending, u64::MAX)] {
            assert_eq!(HostedForwardDispatchReply::decode(status, disposition), None);
        }
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::Pending, true));
    }
}
