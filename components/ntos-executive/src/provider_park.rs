//! Root owner of provider lanes parked at a fail-closed site (#394). Policy: nt_kernel_exec.
//!
//! A parked lane is blocked in an unreplied labelled Call, so it uses no processor and its
//! Reply is owned here. The pump walls instead of being confined in a receive that never
//! arrives. Retiring the provider's VSpace tears its parked lanes down.

use super::*;
use nt_kernel_exec::provider_park::{ParkSite, ParkedLanes, ProviderChannel};

// Only the serialized executive receiver accesses this table.
static mut PARKED: ParkedLanes<64> = ParkedLanes::new();

/// Record an authenticated park. Any refusal leaves the Call unreplied; the pump walls either
/// way, so a refused or malformed park never makes the lane runnable again.
pub(crate) unsafe fn accept(
    channel: &spawn_hosts::PumpChannel,
    reply_object: u64,
    badge: u64,
    message_info: u64,
    words: [u64; 2],
) {
    let recorded = (|| {
        let route = spawn_hosts::shared_ingress::owner::runtime::channel_route(channel)
            .ok().flatten()
            .ok_or(nt_kernel_exec::provider_park::ParkError::InvalidChannel)?;
        let provider = ProviderChannel {
            endpoint: channel.fault_ep, tcb: channel.tcb, vspace: channel.pml4,
            reply_object, expected_badge: route.badge(),
        };
        let site = ParkSite::decode(provider, badge, message_info, words)?;
        (&mut *core::ptr::addr_of_mut!(PARKED)).record(provider, site)
    })();
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[provider-park] n=");
    print_u64(n);
    print_str(b" tcb=");
    print_u64(channel.tcb);
    match recorded {
        Ok(lane) => {
            print_str(b" line=");
            print_u64(u64::from(lane.site.line));
            print_str(b" file=0x");
            print_hex_u64(lane.site.file);
            print_str(b" generation=");
            print_u64(lane.generation);
            print_str(b" parked=");
            print_u64((&*core::ptr::addr_of!(PARKED)).len() as u64);
        }
        Err(_) => print_str(b" rejected"),
    }
    print_str(b"\n");
}

/// A retired provider VSpace takes its parked lanes with it: each is suspended in its Call.
pub(crate) unsafe fn tear_down_vspace(vspace: u64) {
    for lane in (&mut *core::ptr::addr_of_mut!(PARKED)).tear_down_vspace(vspace) {
        let error = tcb_suspend_r(lane.channel.tcb);
        print_str(b"[provider-park] torn down tcb=");
        print_u64(lane.channel.tcb);
        print_str(b" suspend=");
        print_u64(error);
        print_str(b"\n");
    }
}
