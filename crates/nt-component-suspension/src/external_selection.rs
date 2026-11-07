//! Memory-only selection among independently authenticated, eligible hosted Calls.

use crate::ExternalIngress;

/// Return an eligible queue index without mutating a Call, checking native capabilities, or
/// transferring its retained Reply. The caller supplies only eligible entries. The admission
/// ordinal determines fairness, not authority to dispatch the selected Call.
pub fn oldest_external_ingress<'a, M: 'a>(
    calls: impl IntoIterator<Item = (usize, &'a ExternalIngress<M>)>,
) -> Option<usize> {
    calls
        .into_iter()
        .min_by_key(|(_, call)| call.admission_sequence())
        .map(|(index, _)| index)
}

/// Native row observations needed to admit a retained Call as a Receive child. These flags
/// describe the row only; the Call itself remains the authority for Reply and Stop state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalReceiveState {
    pub delivered: bool,
    pub released: bool,
    pub settlement_prepared: bool,
}

/// Select the oldest Call that can still become a Receive child. Inspection never consumes a
/// Reply, changes Stop state, or moves the Call out of its native owner row.
pub fn oldest_receive_external_ingress<'a, M: 'a>(
    calls: impl IntoIterator<Item = (usize, &'a ExternalIngress<M>, ExternalReceiveState)>,
) -> Option<usize> {
    oldest_receive_external_ingress_matching(calls, |_| true)
}

/// Apply an additional read-only caller predicate before ordinal selection. A rejected Call
/// remains retained for its own delivery path; this does not consume or reprioritize it.
pub fn oldest_receive_external_ingress_matching<'a, M: 'a>(
    calls: impl IntoIterator<Item = (usize, &'a ExternalIngress<M>, ExternalReceiveState)>,
    mut matches: impl FnMut(&ExternalIngress<M>) -> bool,
) -> Option<usize> {
    oldest_external_ingress(calls.into_iter().filter_map(|(index, call, state)| {
        (!state.delivered && !state.released && !state.settlement_prepared
            && call.can_park() && matches(call))
        .then_some((index, call))
    }))
}

#[cfg(test)]
mod tests;
