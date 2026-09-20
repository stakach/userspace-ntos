//! Disjoint endpoint and bound-notification namespaces for executive ingress.
//!
//! These validate root capability construction, not receive provenance. Copying a capability
//! preserves its badge and therefore requires a separately established source identity.

pub const TIMER_BADGE: u64 = 1 << 62;
pub const IRQ_BADGE: u64 = 1 << 61;
pub const IRQ_SLOT_COUNT: u8 = 61;
pub const ENDPOINT_BADGE_MAX: u64 = IRQ_BADGE - 1;

/// Zero is a valid unbadged endpoint. Bits 61 and above are never endpoint identities.
pub const fn valid_endpoint_badge(badge: u64) -> bool {
    badge <= ENDPOINT_BADGE_MAX
}

/// Validate timer/IRQ notification badges, including OR-coalesced deliveries. An IRQ marker
/// requires at least one slot; payload bits without the IRQ marker are not a notification.
pub const fn valid_notification_badge(badge: u64) -> bool {
    if badge == 0 || badge & (1 << 63) != 0 {
        return false;
    }
    let slots = badge & ENDPOINT_BADGE_MAX;
    if badge & IRQ_BADGE != 0 {
        slots != 0
    } else {
        badge == TIMER_BADGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_range_is_disjoint_from_every_notification_bit() {
        for badge in [0, 1, 526, ENDPOINT_BADGE_MAX] {
            assert!(valid_endpoint_badge(badge));
            assert!(!valid_notification_badge(badge));
            for marker in [IRQ_BADGE, TIMER_BADGE, 1 << 63] {
                assert!(!valid_endpoint_badge(badge | marker));
            }
        }
        assert!(!valid_endpoint_badge(u64::MAX));
    }

    #[test]
    fn dynamic_irq_slots_and_coalesced_timer_notifications_are_valid() {
        for first in 0..IRQ_SLOT_COUNT {
            for second in 0..IRQ_SLOT_COUNT {
                let irq = IRQ_BADGE | (1 << first) | (1 << second);
                assert!(valid_notification_badge(irq));
                assert!(valid_notification_badge(irq | TIMER_BADGE));
                assert!(!valid_endpoint_badge(irq));
            }
        }
        assert!(valid_notification_badge(TIMER_BADGE));
        assert!(valid_notification_badge(IRQ_BADGE | ENDPOINT_BADGE_MAX));
    }

    #[test]
    fn malformed_notification_badges_are_rejected() {
        for badge in [0, IRQ_BADGE, IRQ_BADGE | TIMER_BADGE, u64::MAX] {
            assert!(!valid_notification_badge(badge));
        }
        for bit in 0..IRQ_SLOT_COUNT {
            assert!(!valid_notification_badge(1 << bit));
            assert!(!valid_notification_badge(TIMER_BADGE | (1 << bit)));
            assert!(!valid_notification_badge(
                IRQ_BADGE | (1 << bit) | (1 << 63)
            ));
        }
    }
}
