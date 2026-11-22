//! A driver instance's I/O-port capability slots after a nested IRQ-lane dispatch (#430).
//!
//! The instance's CNode holds one device's port capabilities at a time. An IRQ-lane dispatch
//! installs its own device's capabilities, so an ordinary dispatch of a different device that it
//! interrupted would resume with the wrong ports. After the nested dispatch, the outer binding is
//! restored from its current canonical state. A binding that is no longer published gets no
//! capabilities: it never runs with another device's ports.

/// What the instance's port-capability slots must become after the nested dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedPortCapRestore {
    /// No ordinary dispatch was bound, or it was the nested dispatch's own device.
    Keep,
    /// Reinstall the outer device's capabilities from its canonical resource state.
    Restore,
    /// The outer binding was revoked meanwhile; leave the slots empty.
    Clear,
}

/// `outer` is the device of the ordinary dispatch bound when the nested dispatch began;
/// `outer_published` whether that exact binding is still the device's current publication.
pub fn port_caps_after_nested_dispatch(
    outer: Option<u64>,
    nested: u64,
    outer_published: bool,
) -> NestedPortCapRestore {
    match outer {
        None => NestedPortCapRestore::Keep,
        Some(device) if device == nested => NestedPortCapRestore::Keep,
        Some(_) if outer_published => NestedPortCapRestore::Restore,
        Some(_) => NestedPortCapRestore::Clear,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_different_outer_device_gets_its_own_ports_back() {
        assert_eq!(port_caps_after_nested_dispatch(Some(7), 9, true), NestedPortCapRestore::Restore);
    }

    #[test]
    fn a_revoked_outer_binding_never_inherits_the_irq_devices_ports() {
        assert_eq!(port_caps_after_nested_dispatch(Some(7), 9, false), NestedPortCapRestore::Clear);
    }

    #[test]
    fn the_same_device_or_no_outer_dispatch_keeps_the_slots() {
        assert_eq!(port_caps_after_nested_dispatch(Some(9), 9, true), NestedPortCapRestore::Keep);
        assert_eq!(port_caps_after_nested_dispatch(Some(9), 9, false), NestedPortCapRestore::Keep);
        assert_eq!(port_caps_after_nested_dispatch(None, 9, false), NestedPortCapRestore::Keep);
    }
}
