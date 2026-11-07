//! Exact notification boundary for a checked ALPC reply-and-receive call.
//!
//! The reply send can commit while the receive half remains pending. A completed
//! receive has a separate service-record ACK before its owner may be retired.

use nt_alpc_abi::send_flag;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyCommitGate {
    token: (u64, u64),
    reply_message: bool,
    awaiting_ack: bool,
    notified: bool,
}

impl ReplyCommitGate {
    pub fn new(flags: u32, token: (u64, u64)) -> Self {
        Self { token, reply_message: flags & send_flag::REPLY_MESSAGE != 0,
            awaiting_ack: false, notified: false }
    }

    /// An exact PENDING means the reply send committed and only the receive
    /// half remains parked. A terminal SUCCESS waits for the record ACK.
    pub fn service_exact(&mut self, status: i32) -> Option<(u64, u64)> {
        if !self.reply_message || self.notified { return None; }
        match status as u32 {
            0x0000_0103 => {
                self.notified = true;
                Some(self.token)
            }
            0 => {
                self.awaiting_ack = true;
                None
            }
            _ => None,
        }
    }

    pub fn ack_exact(&mut self, status: i32) -> Option<(u64, u64)> {
        if !self.awaiting_ack || self.notified || status != 0 { return None; }
        self.notified = true;
        Some(self.token)
    }
}
