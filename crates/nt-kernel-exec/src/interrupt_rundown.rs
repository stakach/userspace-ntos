//! Exact interrupt-delivery leases and disconnect rundown barriers.
//!
//! A physical interrupt line is disabled by the kernel from notification delivery until the
//! handler capability is acknowledged. That gives one root delivery at a time, but it does not
//! protect a copied ISR chain from a re-entrant disconnect while a hosted callback is parked.
//! These allocation-free records make that lifetime explicit. Connection teardown waits for its
//! exact delivery lease; line teardown additionally requires an exact hardware-mask confirmation.

/// Immutable identity of one generation of a connected interrupt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptConnectionIdentity {
    pub owner_domain: u64,
    pub owner_cookie: u64,
    pub connection_id: u64,
    pub grant_generation: u64,
}

impl InterruptConnectionIdentity {
    pub const fn new(
        owner_domain: u64,
        owner_cookie: u64,
        connection_id: u64,
        grant_generation: u64,
    ) -> Option<Self> {
        if owner_domain == 0 || owner_cookie == 0 || connection_id == 0 || grant_generation == 0 {
            None
        } else {
            Some(Self {
                owner_domain,
                owner_cookie,
                connection_id,
                grant_generation,
            })
        }
    }
}

/// Exact proof that one ISR-chain snapshot retains a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptConnectionLease {
    pub identity: InterruptConnectionIdentity,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptConnectionDisposition {
    Active,
    Retiring,
    Quarantined,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptRundownState {
    Active,
    Draining,
    Ready,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptConnectionLeaseError {
    NotActive,
    DeliveryInFlight,
    SequenceExhausted,
    StaleLease,
    ReleaseNotReady,
}

/// Per-connection admission and rundown state.
///
/// One physical line delivery can hold at most one lease on a connection. The line remains masked
/// until the complete shared ISR scan is acknowledged, so admitting a second lease would indicate
/// a transport bug rather than useful parallelism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptConnectionRundown {
    identity: InterruptConnectionIdentity,
    disposition: InterruptConnectionDisposition,
    next_sequence: u64,
    active_sequence: Option<u64>,
}

impl InterruptConnectionRundown {
    pub const fn new(identity: InterruptConnectionIdentity) -> Self {
        Self {
            identity,
            disposition: InterruptConnectionDisposition::Active,
            next_sequence: 1,
            active_sequence: None,
        }
    }

    pub const fn identity(self) -> InterruptConnectionIdentity {
        self.identity
    }

    pub const fn disposition(self) -> InterruptConnectionDisposition {
        self.disposition
    }

    pub const fn has_delivery_lease(self) -> bool {
        self.active_sequence.is_some()
    }

    pub const fn rundown_state(self) -> InterruptRundownState {
        match self.disposition {
            InterruptConnectionDisposition::Active => InterruptRundownState::Active,
            InterruptConnectionDisposition::Retiring
            | InterruptConnectionDisposition::Quarantined => {
                if self.active_sequence.is_some() {
                    InterruptRundownState::Draining
                } else {
                    InterruptRundownState::Ready
                }
            }
            InterruptConnectionDisposition::Released => InterruptRundownState::Released,
        }
    }

    pub fn acquire_delivery(
        &mut self,
    ) -> Result<InterruptConnectionLease, InterruptConnectionLeaseError> {
        if self.disposition != InterruptConnectionDisposition::Active {
            return Err(InterruptConnectionLeaseError::NotActive);
        }
        if self.active_sequence.is_some() {
            return Err(InterruptConnectionLeaseError::DeliveryInFlight);
        }
        let sequence = self.next_sequence;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.disposition = InterruptConnectionDisposition::Quarantined;
            return Err(InterruptConnectionLeaseError::SequenceExhausted);
        };
        self.next_sequence = next_sequence;
        self.active_sequence = Some(sequence);
        Ok(InterruptConnectionLease {
            identity: self.identity,
            sequence,
        })
    }

    pub fn complete_delivery(
        &mut self,
        lease: InterruptConnectionLease,
    ) -> Result<InterruptRundownState, InterruptConnectionLeaseError> {
        if lease.identity != self.identity || self.active_sequence != Some(lease.sequence) {
            return Err(InterruptConnectionLeaseError::StaleLease);
        }
        self.active_sequence = None;
        Ok(self.rundown_state())
    }

    pub fn begin_retirement(&mut self) -> InterruptRundownState {
        if self.disposition == InterruptConnectionDisposition::Active {
            self.disposition = InterruptConnectionDisposition::Retiring;
        }
        self.rundown_state()
    }

    pub fn quarantine(&mut self) -> InterruptRundownState {
        if self.disposition != InterruptConnectionDisposition::Released {
            self.disposition = InterruptConnectionDisposition::Quarantined;
        }
        self.rundown_state()
    }

    pub fn release(&mut self) -> Result<(), InterruptConnectionLeaseError> {
        if self.rundown_state() != InterruptRundownState::Ready {
            return Err(InterruptConnectionLeaseError::ReleaseNotReady);
        }
        self.disposition = InterruptConnectionDisposition::Released;
        Ok(())
    }

    #[cfg(test)]
    fn set_next_sequence_for_test(&mut self, sequence: u64) {
        self.next_sequence = sequence;
    }
}

/// Immutable identity of one installed physical-line generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptLineIdentity {
    pub controller_ordinal: u16,
    pub local_pin: u16,
    pub generation: u64,
}

impl InterruptLineIdentity {
    pub const fn new(controller_ordinal: u16, local_pin: u16, generation: u64) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self {
                controller_ordinal,
                local_pin,
                generation,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptLineDelivery {
    pub identity: InterruptLineIdentity,
    pub sequence: u64,
}

/// Exact authorization to confirm that the physical route was permanently masked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptLineMask {
    pub identity: InterruptLineIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLineDisposition {
    Active,
    Retiring,
    Quarantined,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLineDeliveryPhase {
    Idle,
    Scanning(u64),
    AwaitingAcknowledgement(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLineScanCompletion {
    Acknowledge(InterruptLineDelivery),
    Mask(InterruptLineMask),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLineError {
    NotActive,
    DeliveryInFlight,
    SequenceExhausted,
    StaleDelivery,
    StaleMask,
    ScanNotComplete,
    AcknowledgementForbidden,
    MaskNotConfirmed,
    ReleaseNotReady,
}

/// Per-line delivery, acknowledgement, quarantine, and hardware-mask state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptLineRundown {
    identity: InterruptLineIdentity,
    disposition: InterruptLineDisposition,
    phase: InterruptLineDeliveryPhase,
    next_sequence: u64,
    hardware_masked: bool,
}

impl InterruptLineRundown {
    pub const fn new(identity: InterruptLineIdentity) -> Self {
        Self {
            identity,
            disposition: InterruptLineDisposition::Active,
            phase: InterruptLineDeliveryPhase::Idle,
            next_sequence: 1,
            hardware_masked: false,
        }
    }

    pub const fn identity(self) -> InterruptLineIdentity {
        self.identity
    }

    pub const fn disposition(self) -> InterruptLineDisposition {
        self.disposition
    }

    pub const fn phase(self) -> InterruptLineDeliveryPhase {
        self.phase
    }

    pub const fn hardware_masked(self) -> bool {
        self.hardware_masked
    }

    pub const fn rundown_state(self) -> InterruptRundownState {
        match self.disposition {
            InterruptLineDisposition::Active => InterruptRundownState::Active,
            InterruptLineDisposition::Retiring | InterruptLineDisposition::Quarantined => {
                if self.hardware_masked && matches!(self.phase, InterruptLineDeliveryPhase::Idle) {
                    InterruptRundownState::Ready
                } else {
                    InterruptRundownState::Draining
                }
            }
            InterruptLineDisposition::Released => InterruptRundownState::Released,
        }
    }

    pub fn begin_delivery(&mut self) -> Result<InterruptLineDelivery, InterruptLineError> {
        if self.disposition != InterruptLineDisposition::Active || self.hardware_masked {
            return Err(InterruptLineError::NotActive);
        }
        if self.phase != InterruptLineDeliveryPhase::Idle {
            return Err(InterruptLineError::DeliveryInFlight);
        }
        let sequence = self.next_sequence;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.disposition = InterruptLineDisposition::Quarantined;
            return Err(InterruptLineError::SequenceExhausted);
        };
        self.next_sequence = next_sequence;
        self.phase = InterruptLineDeliveryPhase::Scanning(sequence);
        Ok(InterruptLineDelivery {
            identity: self.identity,
            sequence,
        })
    }

    pub fn defer_delivery(
        &mut self,
        delivery: InterruptLineDelivery,
    ) -> Result<(), InterruptLineError> {
        self.require_phase(
            delivery,
            InterruptLineDeliveryPhase::Scanning(delivery.sequence),
        )?;
        if self.disposition != InterruptLineDisposition::Active {
            return Err(InterruptLineError::NotActive);
        }
        self.phase = InterruptLineDeliveryPhase::Idle;
        Ok(())
    }

    pub fn complete_scan(
        &mut self,
        delivery: InterruptLineDelivery,
    ) -> Result<InterruptLineScanCompletion, InterruptLineError> {
        self.require_phase(
            delivery,
            InterruptLineDeliveryPhase::Scanning(delivery.sequence),
        )?;
        if self.disposition == InterruptLineDisposition::Active {
            self.phase = InterruptLineDeliveryPhase::AwaitingAcknowledgement(delivery.sequence);
            Ok(InterruptLineScanCompletion::Acknowledge(delivery))
        } else {
            Ok(InterruptLineScanCompletion::Mask(InterruptLineMask {
                identity: self.identity,
            }))
        }
    }

    pub fn confirm_acknowledgement(
        &mut self,
        delivery: InterruptLineDelivery,
    ) -> Result<(), InterruptLineError> {
        self.require_phase(
            delivery,
            InterruptLineDeliveryPhase::AwaitingAcknowledgement(delivery.sequence),
        )?;
        if self.disposition != InterruptLineDisposition::Active || self.hardware_masked {
            return Err(InterruptLineError::AcknowledgementForbidden);
        }
        self.phase = InterruptLineDeliveryPhase::Idle;
        Ok(())
    }

    pub fn begin_retirement(&mut self) -> Result<InterruptLineMask, InterruptLineError> {
        match self.disposition {
            InterruptLineDisposition::Active => {
                self.disposition = InterruptLineDisposition::Retiring;
            }
            InterruptLineDisposition::Retiring | InterruptLineDisposition::Quarantined => {}
            InterruptLineDisposition::Released => return Err(InterruptLineError::ReleaseNotReady),
        }
        Ok(InterruptLineMask {
            identity: self.identity,
        })
    }

    pub fn quarantine(&mut self) -> Result<InterruptLineMask, InterruptLineError> {
        if self.disposition == InterruptLineDisposition::Released {
            return Err(InterruptLineError::ReleaseNotReady);
        }
        self.disposition = InterruptLineDisposition::Quarantined;
        Ok(InterruptLineMask {
            identity: self.identity,
        })
    }

    pub fn confirm_mask(&mut self, mask: InterruptLineMask) -> Result<(), InterruptLineError> {
        if mask.identity != self.identity
            || !matches!(
                self.disposition,
                InterruptLineDisposition::Retiring | InterruptLineDisposition::Quarantined
            )
        {
            return Err(InterruptLineError::StaleMask);
        }
        self.hardware_masked = true;
        Ok(())
    }

    /// Finish an unacknowledged delivery after the permanent hardware mask is confirmed.
    pub fn abort_delivery(
        &mut self,
        delivery: InterruptLineDelivery,
    ) -> Result<InterruptRundownState, InterruptLineError> {
        if delivery.identity != self.identity {
            return Err(InterruptLineError::StaleDelivery);
        }
        if !self.hardware_masked {
            return Err(InterruptLineError::MaskNotConfirmed);
        }
        if !matches!(
            self.phase,
            InterruptLineDeliveryPhase::Scanning(sequence)
                | InterruptLineDeliveryPhase::AwaitingAcknowledgement(sequence)
                if sequence == delivery.sequence
        ) {
            return Err(InterruptLineError::StaleDelivery);
        }
        self.phase = InterruptLineDeliveryPhase::Idle;
        Ok(self.rundown_state())
    }

    pub fn release(&mut self) -> Result<(), InterruptLineError> {
        if self.rundown_state() != InterruptRundownState::Ready {
            return Err(InterruptLineError::ReleaseNotReady);
        }
        self.disposition = InterruptLineDisposition::Released;
        Ok(())
    }

    fn require_phase(
        self,
        delivery: InterruptLineDelivery,
        phase: InterruptLineDeliveryPhase,
    ) -> Result<(), InterruptLineError> {
        if delivery.identity != self.identity || self.phase != phase {
            Err(InterruptLineError::StaleDelivery)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn set_next_sequence_for_test(&mut self, sequence: u64) {
        self.next_sequence = sequence;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn connection_identity(generation: u64) -> InterruptConnectionIdentity {
        InterruptConnectionIdentity::new(1, 2, 3, generation).unwrap()
    }

    fn line_identity(generation: u64) -> InterruptLineIdentity {
        InterruptLineIdentity::new(0, 9, generation).unwrap()
    }

    #[test]
    fn identities_reject_zero_generation_or_owner_fields() {
        assert!(InterruptConnectionIdentity::new(0, 2, 3, 4).is_none());
        assert!(InterruptConnectionIdentity::new(1, 0, 3, 4).is_none());
        assert!(InterruptConnectionIdentity::new(1, 2, 0, 4).is_none());
        assert!(InterruptConnectionIdentity::new(1, 2, 3, 0).is_none());
        assert!(InterruptLineIdentity::new(0, 0, 0).is_none());
    }

    #[test]
    fn connection_lease_is_exact_and_single_in_flight() {
        let mut rundown = InterruptConnectionRundown::new(connection_identity(4));
        let lease = rundown.acquire_delivery().unwrap();
        assert_eq!(
            rundown.acquire_delivery(),
            Err(InterruptConnectionLeaseError::DeliveryInFlight)
        );
        let stale = InterruptConnectionLease {
            identity: connection_identity(5),
            sequence: lease.sequence,
        };
        assert_eq!(
            rundown.complete_delivery(stale),
            Err(InterruptConnectionLeaseError::StaleLease)
        );
        assert_eq!(
            rundown.complete_delivery(lease),
            Ok(InterruptRundownState::Active)
        );
        assert_eq!(
            rundown.complete_delivery(lease),
            Err(InterruptConnectionLeaseError::StaleLease)
        );
    }

    #[test]
    fn retirement_blocks_admission_and_waits_for_exact_lease() {
        let mut rundown = InterruptConnectionRundown::new(connection_identity(4));
        let lease = rundown.acquire_delivery().unwrap();
        assert_eq!(rundown.begin_retirement(), InterruptRundownState::Draining);
        assert_eq!(
            rundown.acquire_delivery(),
            Err(InterruptConnectionLeaseError::NotActive)
        );
        assert_eq!(
            rundown.release(),
            Err(InterruptConnectionLeaseError::ReleaseNotReady)
        );
        assert_eq!(
            rundown.complete_delivery(lease),
            Ok(InterruptRundownState::Ready)
        );
        rundown.release().unwrap();
        assert_eq!(rundown.rundown_state(), InterruptRundownState::Released);
    }

    #[test]
    fn connection_sequence_exhaustion_quarantines_without_publishing() {
        let mut rundown = InterruptConnectionRundown::new(connection_identity(4));
        rundown.set_next_sequence_for_test(u64::MAX);
        assert_eq!(
            rundown.acquire_delivery(),
            Err(InterruptConnectionLeaseError::SequenceExhausted)
        );
        assert!(!rundown.has_delivery_lease());
        assert_eq!(
            rundown.disposition(),
            InterruptConnectionDisposition::Quarantined
        );
        assert_eq!(rundown.rundown_state(), InterruptRundownState::Ready);
    }

    #[test]
    fn normal_line_delivery_requires_scan_then_exact_ack() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        let delivery = line.begin_delivery().unwrap();
        assert_eq!(
            line.confirm_acknowledgement(delivery),
            Err(InterruptLineError::StaleDelivery)
        );
        assert_eq!(
            line.complete_scan(delivery),
            Ok(InterruptLineScanCompletion::Acknowledge(delivery))
        );
        let stale = InterruptLineDelivery {
            identity: line_identity(2),
            sequence: delivery.sequence,
        };
        assert_eq!(
            line.confirm_acknowledgement(stale),
            Err(InterruptLineError::StaleDelivery)
        );
        line.confirm_acknowledgement(delivery).unwrap();
        assert_eq!(line.phase(), InterruptLineDeliveryPhase::Idle);
    }

    #[test]
    fn deferred_delivery_can_retry_without_acknowledgement() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        let first = line.begin_delivery().unwrap();
        line.defer_delivery(first).unwrap();
        let second = line.begin_delivery().unwrap();
        assert!(second.sequence > first.sequence);
    }

    #[test]
    fn idle_retirement_requires_exact_mask_before_release() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        let mask = line.begin_retirement().unwrap();
        assert_eq!(line.rundown_state(), InterruptRundownState::Draining);
        assert_eq!(line.release(), Err(InterruptLineError::ReleaseNotReady));
        assert_eq!(
            line.confirm_mask(InterruptLineMask {
                identity: line_identity(2)
            }),
            Err(InterruptLineError::StaleMask)
        );
        line.confirm_mask(mask).unwrap();
        assert_eq!(line.rundown_state(), InterruptRundownState::Ready);
        line.release().unwrap();
    }

    #[test]
    fn retirement_during_scan_forbids_ack_and_drains_after_mask() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        let delivery = line.begin_delivery().unwrap();
        let mask = line.begin_retirement().unwrap();
        assert_eq!(
            line.complete_scan(delivery),
            Ok(InterruptLineScanCompletion::Mask(mask))
        );
        assert_eq!(
            line.confirm_acknowledgement(delivery),
            Err(InterruptLineError::StaleDelivery)
        );
        assert_eq!(
            line.abort_delivery(delivery),
            Err(InterruptLineError::MaskNotConfirmed)
        );
        line.confirm_mask(mask).unwrap();
        assert_eq!(
            line.abort_delivery(delivery),
            Ok(InterruptRundownState::Ready)
        );
    }

    #[test]
    fn quarantine_never_allows_acknowledgement() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        let delivery = line.begin_delivery().unwrap();
        line.complete_scan(delivery).unwrap();
        let mask = line.quarantine().unwrap();
        assert_eq!(
            line.confirm_acknowledgement(delivery),
            Err(InterruptLineError::AcknowledgementForbidden)
        );
        line.confirm_mask(mask).unwrap();
        line.abort_delivery(delivery).unwrap();
        assert_eq!(line.rundown_state(), InterruptRundownState::Ready);
    }

    #[test]
    fn line_sequence_exhaustion_quarantines_without_delivery() {
        let mut line = InterruptLineRundown::new(line_identity(1));
        line.set_next_sequence_for_test(u64::MAX);
        assert_eq!(
            line.begin_delivery(),
            Err(InterruptLineError::SequenceExhausted)
        );
        assert_eq!(line.phase(), InterruptLineDeliveryPhase::Idle);
        assert_eq!(line.disposition(), InterruptLineDisposition::Quarantined);
    }
}
