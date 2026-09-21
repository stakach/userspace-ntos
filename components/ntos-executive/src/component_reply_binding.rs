//! Exact microkernel Reply binding observations.

use nt_component_suspension::ReplyBindingObservation;

pub(crate) unsafe fn query(
    tcb: u64,
    reply: u64,
) -> Result<ReplyBindingObservation, sel4_rt::reply_binding::Error> {
    use sel4_rt::reply_binding::Binding;
    sel4_rt::reply_binding::query(tcb, reply).map(|binding| match binding {
        Binding::Free => ReplyBindingObservation::Free,
        Binding::Offered => ReplyBindingObservation::Offered,
        Binding::BoundToTarget => ReplyBindingObservation::BoundToTarget,
        Binding::BoundElsewhere => ReplyBindingObservation::BoundElsewhere,
    })
}
