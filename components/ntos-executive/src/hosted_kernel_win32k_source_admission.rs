//! One exact source-IRP admission across win32k IOCTL, PnP, and READ/WRITE routes.

use super::*;

type Route = nt_component_suspension::peer_registry::PeerRoute;

#[derive(Clone, Copy, Eq, PartialEq)]
struct SourceIdentity {
    route: Route,
    address: u64,
    ticket: u64,
    native_generation: u64,
}

static mut ACTIVE: Vec<SourceIdentity> = Vec::new();

pub(super) unsafe fn contains(address: u64) -> bool {
    (&*core::ptr::addr_of!(ACTIVE)).iter().any(|row| row.address == address)
}

pub(super) unsafe fn register(
    route: Route,
    address: u64,
    ticket: u64,
    native_generation: u64,
) -> bool {
    if address == 0 || ticket == 0 || native_generation == 0 || contains(address)
        || (&mut *core::ptr::addr_of_mut!(ACTIVE)).try_reserve(1).is_err()
    {
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(ACTIVE)).push(SourceIdentity {
        route, address, ticket, native_generation,
    });
    true
}

pub(super) unsafe fn retire(
    route: Route,
    address: u64,
    ticket: u64,
    native_generation: u64,
) {
    let identity = SourceIdentity { route, address, ticket, native_generation };
    let index = (&*core::ptr::addr_of!(ACTIVE)).iter().position(|row| *row == identity)
        .expect("exact win32k source admission retirement");
    (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
}
