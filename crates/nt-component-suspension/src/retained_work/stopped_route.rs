//! Private store side of the exact stopped-peer cancellation transaction.

use super::*;
use crate::{CancelledStoppedCall, StoppedRouteError};

impl<M> RetainedWork<M> {
    pub(crate) fn stopped_route_count<E>(
        &self,
        route: PeerRoute,
    ) -> Result<usize, StoppedRouteError<E>> {
        let mut count = 0;
        for slot in &self.slots {
            match slot {
                Slot::Stored { call, .. } if call.route() == route => count += 1,
                Slot::CheckedOut { route: owner, .. } if *owner == route => {
                    return Err(StoppedRouteError::Busy)
                }
                Slot::Reserved { .. } => return Err(StoppedRouteError::Busy),
                _ => {}
            }
        }
        Ok(count)
    }

    pub(crate) fn stopped_route_replies(&self, route: PeerRoute) -> impl Iterator<Item = u64> + '_ {
        self.slots.iter().filter_map(move |slot| match slot {
            Slot::Stored { call, .. } if call.route() == route => Some(call.reply()),
            _ => None,
        })
    }

    pub(crate) fn drain_stopped_route(
        &mut self,
        route: PeerRoute,
        canonical: u64,
        peers: &mut PeerRegistry,
        output: &mut Vec<CancelledStoppedCall<M>>,
    ) {
        for slot in &mut self.slots {
            if !matches!(slot, Slot::Stored { call, .. } if call.route() == route) {
                continue;
            }
            let Slot::Stored { call, .. } = core::mem::replace(slot, Slot::Vacant) else {
                unreachable!()
            };
            let (reply, message) = call.cancel_stopped(peers);
            // Canonical ownership remains in the lane; only displaced/queued Replies escape.
            let reply = if reply.reply() == canonical {
                None
            } else {
                Some(reply)
            };
            output.push(CancelledStoppedCall { reply, message });
        }
    }
}
