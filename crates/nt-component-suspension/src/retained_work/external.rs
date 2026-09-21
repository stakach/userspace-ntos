use super::*;

impl<M> RetainedWork<M> {
    pub(crate) fn mark_external(&mut self, reservation: &RetainedWorkReservation) {
        assert!(
            self.owns_reservation(reservation),
            "preflight external reservation"
        );
        self.slots[reservation.slot] = Slot::External {
            identity: reservation.identity,
            reply: reservation.reply,
        };
    }
    pub(crate) fn owns_external(&self, reservation: &RetainedWorkReservation) -> bool {
        reservation.identity != 0
            && matches!(self.slots.get(reservation.slot),
            Some(Slot::External { identity, reply }) if *identity == reservation.identity && *reply == reservation.reply)
    }
    pub(crate) fn release_external(&mut self, reservation: &mut RetainedWorkReservation) {
        assert!(
            self.owns_external(reservation),
            "preflight external release"
        );
        self.slots[reservation.slot] = Slot::Vacant;
        reservation.identity = 0;
    }
}
