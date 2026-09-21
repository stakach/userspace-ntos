//! Startup VM faults use retained one-way replies, never the private ReplyRecv pump.

use super::super::ReceiveError;
use super::*;

impl NativeSharedIngress {
    /// Authenticate the physical worker/domain and the channel's VSpace, image ownership and
    /// attached-client generation before entering this nonreentrant operation. Mapping can
    /// perform kernel IPC but must not dispatch root work or borrow this
    /// owner again. Failure after entering mapping retains the attempt, even if no reply occurred.
    pub(crate) unsafe fn service_startup_fault<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        route: PeerRoute,
        fault_reply: u64,
        channel: &crate::spawn_hosts::PumpChannel,
        faults: u64,
        demand: u64,
        resolve_caller: impl FnOnce(PeerRoute) -> Option<u64>,
    ) -> Result<nt_component_suspension::IngressReplyObservation, ReceiveError> {
        if !self.ready || self.pending_reply.is_some() {
            return Err(ReceiveError::PendingReplyRecovery);
        }
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        if resolve_caller(route) != Some(route.identity().executor)
            || channel.tcb != route.identity().executor
            || channel.fault_ep != route.endpoint()
            || lanes.binding(route.identity().lane).map(|b| b.reply_object) != Ok(channel.reply_cap)
        {
            return Err(ReceiveError::StartupFault(
                nt_component_suspension::StartupFaultError::WrongOwner,
            ));
        }
        self.receiver
            .as_mut()
            .expect("initialized receiver")
            .service_startup_fault(
                route,
                fault_reply,
                lanes,
                self.peers.as_ref().expect("initialized registry"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
                |reply, words| {
                    if !crate::spawn_hosts::pump_service_vm_fault(
                        channel, 6, words[0], words[1], words[3], faults, demand,
                    ) {
                        return nt_component_suspension::IngressReplyObservation::Indeterminate;
                    }
                    if crate::reply_on(reply, 0, 0, 0, 0, 0) == 0 {
                        nt_component_suspension::IngressReplyObservation::Acknowledged
                    } else {
                        nt_component_suspension::IngressReplyObservation::Indeterminate
                    }
                },
            )
            .map_err(ReceiveError::StartupFault)
    }

    /// Finish an acknowledged interim fault only after independent physical lifetime validation.
    /// Publish recovered Reply ownership before insertion can issue kernel binding queries.
    pub(crate) unsafe fn finish_startup_fault<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        route: PeerRoute,
        fault_reply: u64,
        probe_tcb: u64,
        resolve_caller: impl FnOnce(PeerRoute) -> Option<u64>,
    ) -> Result<(), ReceiveError> {
        if !self.ready || self.pending_reply.is_some() {
            return Err(ReceiveError::PendingReplyRecovery);
        }
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        if resolve_caller(route) != Some(route.identity().executor) {
            return Err(ReceiveError::StartupFault(
                nt_component_suspension::StartupFaultError::WrongOwner,
            ));
        }
        let (reply, _message) = self
            .receiver
            .as_mut()
            .expect("initialized receiver")
            .finish_startup_fault(
                route,
                fault_reply,
                lanes,
                self.peers.as_mut().expect("initialized registry"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            )
            .map_err(ReceiveError::StartupFault)?;
        self.pending_reply = Some(reply);
        self.recycle_pending_reply(lanes, probe_tcb)
    }

    /// Retry only pool admission, never fault service or reply. The live probe TCB and all
    /// external Reply exclusions remain the caller's responsibility, as during initialization.
    pub(crate) unsafe fn recycle_pending_reply<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        probe_tcb: u64,
    ) -> Result<(), ReceiveError> {
        if !self.ready {
            return Err(ReceiveError::PendingReplyRecovery);
        }
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        self.replacements
            .as_mut()
            .expect("initialized replacement pool")
            .insert_pending(
                &mut self.pending_reply,
                self.receiver.as_ref().expect("initialized receiver"),
                lanes,
                |reply| crate::spawn_hosts::query_component_reply_binding(probe_tcb, reply),
            )
            .map_err(ReceiveError::Retain)
    }
}
