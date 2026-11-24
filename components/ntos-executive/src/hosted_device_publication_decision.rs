//! Decide whether delayed device publication may use the instance's mutable resource bank.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartPublication {
    Installed,
    NoInterrupt,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InstalledInterrupt {
    pub object: u64,
    pub interrupt_id: u64,
    pub grant_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveInterruptProjection {
    pub object: u64,
    pub pool_generation: u64,
    pub connection: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MmioPublication {
    NoMap,
    Unresolved,
}

/// Assigned memory requires a per-binding map receipt; the shared bank is never that receipt.
pub(crate) fn mmio_publication(has_assigned_memory: bool) -> MmioPublication {
    if has_assigned_memory {
        MmioPublication::Unresolved
    } else {
        MmioPublication::NoMap
    }
}

/// The exact installed connection belongs to a device binding; the shared bank is per instance.
/// IoConnectInterrupt settles the canonical connect synchronously. A delayed StartDevice
/// publication may observe that result or an exact unresolved projection, never replay a
/// different device's shared bytes.
pub(crate) fn start_publication(
    installed_interrupt: Option<InstalledInterrupt>,
    live_projection_for_binding: Option<LiveInterruptProjection>,
) -> StartPublication {
    match (installed_interrupt, live_projection_for_binding) {
        (Some(installed), Some(live))
            if live.pool_generation != 0
                && installed.object == live.object
                && live.connection
                    == Some((installed.interrupt_id, installed.grant_generation)) =>
        {
            StartPublication::Installed
        }
        (None, None) => StartPublication::NoInterrupt,
        _ => StartPublication::Unresolved,
    }
}

pub(crate) fn should_clear_shared_after_disconnect(
    pointer: u64,
    shared_interrupt_object: u64,
) -> bool {
    pointer != 0 && pointer == shared_interrupt_object
}

/// Select the sole retained canonical interrupt by pointer. The caller must still authenticate
/// its binding, physical projection allocation and grant before changing root-owned state.
pub(crate) fn disconnect_binding<Binding: Copy>(
    pointer: u64,
    connections: impl IntoIterator<Item = (Binding, u64)>,
) -> Option<Binding> {
    if pointer == 0 {
        return None;
    }
    let mut selected = None;
    for (binding, object) in connections {
        if object == pointer {
            if selected.is_some() {
                return None;
            }
            selected = Some(binding);
        }
    }
    selected
}
