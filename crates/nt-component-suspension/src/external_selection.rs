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

#[cfg(test)]
mod tests;
