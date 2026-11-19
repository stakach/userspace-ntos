//! Bounded serial evidence for provider CREATEs completed by the mounted volume.
//!
//! Reported after the provider's File handle is published, so each line proves a canonical
//! CREATE on the live mounted-volume Device returned a valid handle (for win32k, e.g. a
//! `\SystemRoot\Fonts\...` open). Observation only; it never influences the CREATE.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{mounted_volume, print_hex_u64, print_str};

const MARKER_BUDGET: u32 = 64;
static MARKERS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateOrigin {
    HostedDriver,
    Win32k,
}

pub(crate) fn opened(
    origin: CreateOrigin, device_id: u64, file_id: u64, handle: u64, pending: bool, name: &[u16],
) {
    if mounted_volume::exec_volume_device() != Some(device_id) { return; }
    if MARKERS.fetch_add(1, Ordering::Relaxed) >= MARKER_BUDGET { return; }
    print_str(b"[mounted-provider-open] origin=");
    print_str(match origin {
        CreateOrigin::HostedDriver => b"driver",
        CreateOrigin::Win32k => b"win32k",
    });
    print_str(b" file=0x");
    print_hex_u64(file_id);
    print_str(b" handle=0x");
    print_hex_u64(handle);
    print_str(b" pending=");
    print_str(if pending { b"1" } else { b"0" });
    print_str(b" name=");
    // Serial output is ASCII; any other UTF-16 unit is shown as '?'.
    let mut ascii = [0u8; 96];
    let shown = name.len().min(ascii.len());
    for (byte, unit) in ascii.iter_mut().zip(&name[..shown]) {
        *byte = if (0x20..0x7f).contains(unit) { *unit as u8 } else { b'?' };
    }
    print_str(&ascii[..shown]);
    if shown < name.len() { print_str(b"..."); }
    print_str(b"\n");
}
