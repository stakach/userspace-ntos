//! The firmware HPET read window retained for a component clock alias.

use crate::{PhysicalRange, ACPI_PAGE_SIZE, HPET_REGISTER_BLOCK_LEN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpetReadOnlyAlias {
    frame_base: u64,
    pages: u64,
}

impl HpetReadOnlyAlias {
    pub fn for_firmware_range(
        hpet: PhysicalRange,
        grant: PhysicalRange,
        frame_base: u64,
        pages: u64,
        writable: bool,
    ) -> Option<Self> {
        if writable
            || frame_base == 0
            || hpet != grant
            || hpet.length != HPET_REGISTER_BLOCK_LEN
            || hpet.start % ACPI_PAGE_SIZE != 0
            || hpet.start.checked_add(hpet.length).is_none()
        {
            return None;
        }
        let required_pages = hpet.length.div_ceil(ACPI_PAGE_SIZE);
        (pages == required_pages && frame_base.checked_add(pages).is_some())
            .then_some(Self { frame_base, pages })
    }

    pub const fn frame_base(self) -> u64 { self.frame_base }
    pub const fn pages(self) -> u64 { self.pages }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HPET: PhysicalRange = PhysicalRange { start: 0xfed0_0000, length: 1024 };

    #[test]
    fn exact_read_only_firmware_frame_is_projectable() {
        let alias = HpetReadOnlyAlias::for_firmware_range(
            HPET, HPET, 500, 1, false,
        ).expect("retained read-only HPET frame");
        assert_eq!(alias.frame_base(), 500);
        assert_eq!(alias.pages(), 1);
    }

    #[test]
    fn writable_misaligned_or_mismatched_grants_are_rejected() {
        assert!(HpetReadOnlyAlias::for_firmware_range(HPET, HPET, 500, 1, true).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(HPET, HPET, 0, 1, false).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(HPET, HPET, 500, 0, false).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(HPET, HPET, 500, 2, false).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(HPET, HPET, u64::MAX, 1, false).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(
            HPET, PhysicalRange { start: HPET.start + ACPI_PAGE_SIZE, length: HPET.length },
            500, 1, false,
        ).is_none());
        assert!(HpetReadOnlyAlias::for_firmware_range(
            PhysicalRange { start: HPET.start + 1, length: HPET.length },
            PhysicalRange { start: HPET.start + 1, length: HPET.length },
            500, 1, false,
        ).is_none());
    }
}
