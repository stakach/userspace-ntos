//! Native CONTEXT uses FXSAVE's 32-bit offset/selector layout. The microkernel retains
//! FXSAVE64's 64-bit instruction/data pointers. Selectors have no addressing role in long mode.

use super::LEGACY_FLOATING_POINT_BYTES;

pub(super) fn wire_to_hardware(image: &mut [u8; LEGACY_FLOATING_POINT_BYTES]) {
    // Zero-extend each 32-bit offset; selector/reserved words are not high pointer bits.
    image[12..16].fill(0);
    image[20..24].fill(0);
}

pub(super) fn hardware_to_wire(image: &mut [u8; LEGACY_FLOATING_POINT_BYTES]) {
    // XMM_SAVE_AREA32 cannot represent the high pointer bits. Native long-mode selectors
    // are zero in this legacy save format; preserve all control and register payload bytes.
    image[12..16].fill(0);
    image[20..24].fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_cannot_become_high_hardware_pointer_bits() {
        let mut image = [0xa5; LEGACY_FLOATING_POINT_BYTES];
        image[8..12].copy_from_slice(&0x8123_4567u32.to_le_bytes());
        image[16..20].copy_from_slice(&0xfedc_ba98u32.to_le_bytes());
        let original = image;
        wire_to_hardware(&mut image);
        assert_eq!(u64::from_le_bytes(image[8..16].try_into().unwrap()), 0x8123_4567);
        assert_eq!(u64::from_le_bytes(image[16..24].try_into().unwrap()), 0xfedc_ba98);
        assert_eq!(image[..8], original[..8]);
        assert_eq!(image[24..], original[24..]);
    }

    #[test]
    fn high_hardware_pointer_bits_are_not_published_as_nt_selectors() {
        let mut image = [0x5a; LEGACY_FLOATING_POINT_BYTES];
        image[8..16].copy_from_slice(&0x0000_0100_1234_5678u64.to_le_bytes());
        image[16..24].copy_from_slice(&0x0000_0200_abcd_ef01u64.to_le_bytes());
        let original = image;
        hardware_to_wire(&mut image);
        assert_eq!(&image[8..12], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&image[16..20], &0xabcd_ef01u32.to_le_bytes());
        assert_eq!(&image[12..16], &[0; 4]);
        assert_eq!(&image[20..24], &[0; 4]);
        assert_eq!(image[..8], original[..8]);
        assert_eq!(image[24..], original[24..]);
    }
}
