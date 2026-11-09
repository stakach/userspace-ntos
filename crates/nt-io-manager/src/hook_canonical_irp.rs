//! Exact canonical File IRP retirement across a returned HOOK pump and source ACK.

use crate::IrpId;

/// The returned File pump and the source ACK are alternative owners of one retirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HookCanonicalIrp {
    #[default]
    None,
    Pending(IrpId),
    Retired(IrpId),
}

impl HookCanonicalIrp {
    pub fn record_pending(&mut self, irp: IrpId) -> bool {
        if !matches!(self, Self::None) || irp.raw() == 0 { return false; }
        *self = Self::Pending(irp);
        true
    }

    pub fn matches_completion(self, irp: Option<IrpId>) -> bool {
        match (self, irp) {
            (Self::Pending(expected), Some(actual)) => expected == actual,
            (Self::None, None) => true,
            _ => false,
        }
    }

    pub fn record_returned_retirement(&mut self, irp: IrpId) -> bool {
        self.retire_exact(irp)
    }

    pub fn ack_target(self) -> Option<IrpId> {
        match self { Self::Pending(irp) => Some(irp), _ => None }
    }

    pub fn record_strict_ack(&mut self, irp: IrpId) -> bool {
        self.retire_exact(irp)
    }

    fn retire_exact(&mut self, irp: IrpId) -> bool {
        if *self != Self::Pending(irp) { return false; }
        *self = Self::Retired(irp);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::HookCanonicalIrp;
    use crate::IrpId;

    #[test]
    fn returned_file_retirement_consumes_the_later_source_ack_claim() {
        let irp = IrpId::new(12, 1);
        let mut owner = HookCanonicalIrp::default();
        assert!(owner.record_pending(irp));
        assert!(owner.matches_completion(Some(irp)));
        assert!(owner.record_returned_retirement(irp));
        assert_eq!(owner.ack_target(), None);
        assert!(!owner.record_returned_retirement(irp));
    }

    #[test]
    fn ordinary_pending_hook_keeps_exact_strict_ack_until_it_succeeds() {
        let irp = IrpId::new(12, 1);
        let other = IrpId::new(12, 2);
        let mut owner = HookCanonicalIrp::default();
        assert!(owner.record_pending(irp));
        assert!(!owner.matches_completion(Some(other)));
        assert!(!owner.record_returned_retirement(other));
        assert_eq!(owner.ack_target(), Some(irp));
        assert!(!owner.record_strict_ack(other));
        assert_eq!(owner.ack_target(), Some(irp));
        assert!(owner.record_strict_ack(irp));
        assert_eq!(owner.ack_target(), None);
    }
}
