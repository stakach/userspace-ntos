//! The WDDM bridge interface that dxgkrnl returns to win32k for
//! `IOCTL_WDDM_BRIDGE_QUERY_INTERFACE` (win32ss/drivers/wddm/wddm_bridge.c).
//!
//! The 0x270-byte output is a version/size header followed by 77 function pointers into the
//! completing provider's image. Those addresses exist only in that provider's address space, so
//! they must never reach a caller in another domain. Each slot is replaced with a target the
//! caller can execute: the IOCTL slot with a routine that declines the direct call (wddm_bridge.c
//! then sends the same IOCTL through IRP dispatch), every other slot with a fail-fast target that
//! names the slot. win32k validates that the slots are non-NULL, so NULL is not an option.

/// CTL_CODE(FILE_DEVICE_VIDEO, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS).
pub const IOCTL_WDDM_BRIDGE_QUERY_INTERFACE: u32 = 0x0023_0800;
pub const WDDM_BRIDGE_INTERFACE_LEN: usize = 0x270;
/// First function-pointer slot after the 8-byte header.
pub const WDDM_BRIDGE_FIRST_SLOT: usize = 0x8;
/// The version-8 `SendIoctl` slot WddmBridgeSendIoctl prefers over IRP dispatch.
pub const WDDM_BRIDGE_SEND_IOCTL_SLOT: usize = 0x268;
pub const WDDM_BRIDGE_SLOT_COUNT: usize =
    (WDDM_BRIDGE_INTERFACE_LEN - WDDM_BRIDGE_FIRST_SLOT) / 8;

#[derive(Debug, PartialEq, Eq)]
pub enum BridgeProjectionError {
    Length,
}

/// Rewrite every non-NULL slot of a completed bridge interface for the calling domain. NULL slots
/// (absent at the negotiated version) stay NULL. Returns how many slots were projected.
pub fn project_bridge_interface(
    output: &mut [u8],
    decline_send_ioctl: u64,
    mut fail_fast: impl FnMut(usize) -> u64,
) -> Result<usize, BridgeProjectionError> {
    if output.len() != WDDM_BRIDGE_INTERFACE_LEN {
        return Err(BridgeProjectionError::Length);
    }
    let mut projected = 0;
    for offset in (WDDM_BRIDGE_FIRST_SLOT..WDDM_BRIDGE_INTERFACE_LEN).step_by(8) {
        let slot = &mut output[offset..offset + 8];
        if u64::from_le_bytes(slot.try_into().unwrap()) == 0 {
            continue;
        }
        let target = if offset == WDDM_BRIDGE_SEND_IOCTL_SLOT {
            decline_send_ioctl
        } else {
            fail_fast((offset - WDDM_BRIDGE_FIRST_SLOT) / 8)
        };
        slot.copy_from_slice(&target.to_le_bytes());
        projected += 1;
    }
    Ok(projected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Boot 44510687412: win32k called dxgkrnl+0xa8060 (slot 0x268) directly from its own lane.
    #[test]
    fn no_provider_code_address_survives_projection() {
        let provider = 0x0000_0100_0e00_0000u64;
        let mut output = [0u8; WDDM_BRIDGE_INTERFACE_LEN];
        output[..8].copy_from_slice(&0x0000_0270_0000_0008u64.to_le_bytes());
        for offset in (WDDM_BRIDGE_FIRST_SLOT..WDDM_BRIDGE_INTERFACE_LEN).step_by(8) {
            let target = if offset == 0x230 { 0 } else { provider + offset as u64 * 0x10 };
            output[offset..offset + 8].copy_from_slice(&target.to_le_bytes());
        }
        let projected =
            project_bridge_interface(&mut output, 0xdec1, |slot| 0xf000 + slot as u64).unwrap();
        assert_eq!(projected, WDDM_BRIDGE_SLOT_COUNT - 1);
        assert_eq!(&output[..8], &0x0000_0270_0000_0008u64.to_le_bytes());
        let word = |offset: usize| u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap());
        assert_eq!(word(WDDM_BRIDGE_SEND_IOCTL_SLOT), 0xdec1);
        assert_eq!(word(0x8), 0xf000);
        assert_eq!(word(0x230), 0, "a slot absent at this version stays absent");
        assert_eq!(word(0x260), 0xf000 + (0x260 - 8) / 8);
        for offset in (WDDM_BRIDGE_FIRST_SLOT..WDDM_BRIDGE_INTERFACE_LEN).step_by(8) {
            assert!(!(provider..provider + 0x10_0000).contains(&word(offset)));
        }
    }

    #[test]
    fn only_the_exact_interface_length_is_projected() {
        let mut short = [0u8; WDDM_BRIDGE_INTERFACE_LEN - 8];
        assert_eq!(
            project_bridge_interface(&mut short, 1, |_| 2),
            Err(BridgeProjectionError::Length)
        );
    }
}
