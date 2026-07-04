//! The isolated PnP Manager child: owns the canonical devnode table + v0.1 state
//! machine + fixture resources, served over SURT. It validates every state
//! transition the Driver Host reports and never touches driver code (spec §7.5).
//! Each lifecycle opcode drives the internal transitions for that phase; an
//! out-of-order request fails the transition validation.

use nt_pnp_abi::{
    DeviceState, PNP_OP_CALL_ADD_DEVICE, PNP_OP_CREATE_DEVNODE, PNP_OP_LOAD_DRIVER,
    PNP_OP_QUERY_DEVNODE, PNP_OP_REMOVE_DEVICE, PNP_OP_START_DEVICE,
};
use nt_pnp_manager::PnpManager;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    yield_now, COMP_RING_VADDR, CT_N_COMP, CT_N_SUB, ENV, REP_DATA_VADDR, RING_LEN, STATE_VADDR,
    SUB_RING_VADDR,
};

fn pnp() -> &'static mut PnpManager {
    // SAFETY: single-threaded child; the state page holds an initialised PnpManager.
    unsafe { &mut *(STATE_VADDR as *mut PnpManager) }
}

/// Apply an ordered chain of transitions; the first invalid one fails the request.
fn transition_chain(id: u64, states: &[DeviceState]) -> (i32, u64) {
    let fail = 0xC000_0001u32 as i32;
    for &s in states {
        if pnp().transition(id, s).is_err() {
            return (fail, 0);
        }
    }
    let state = pnp().state(id).map(|s| s as u32 as u64).unwrap_or(0);
    (0, state)
}

/// Dispatch one PnP request; returns `(status, detail0)`.
unsafe fn serve(sqe: &SurtSqe) -> (i32, u64) {
    let fail = 0xC000_0001u32 as i32;
    match sqe.opcode {
        x if x == PNP_OP_CREATE_DEVNODE => {
            let id = pnp().create_mmio_fixture_devnode(sqe.arg0);
            (0, id)
        }
        x if x == PNP_OP_QUERY_DEVNODE => match pnp().resources(sqe.arg0) {
            Some(res) => {
                // Write the resource assignment into the shared payload frame.
                let p = REP_DATA_VADDR as *mut u8;
                core::ptr::write_unaligned(p as *mut u64, res.mem_start);
                core::ptr::write_unaligned(p.add(8) as *mut u32, res.mem_length);
                core::ptr::write_unaligned(p.add(12) as *mut u32, res.int_vector);
                core::ptr::write_unaligned(p.add(16) as *mut u32, res.int_level);
                core::ptr::write_unaligned(p.add(20) as *mut u64, res.int_affinity);
                core::ptr::write_volatile(p.add(28), res.int_latched as u8);
                let state = pnp().state(sqe.arg0).map(|s| s as u32 as u64).unwrap_or(0);
                (0, state)
            }
            None => (fail, 0),
        },
        x if x == PNP_OP_LOAD_DRIVER => transition_chain(sqe.arg0, &[DeviceState::DriverLoaded]),
        x if x == PNP_OP_CALL_ADD_DEVICE => transition_chain(
            sqe.arg0,
            &[DeviceState::AddDeviceCalled, DeviceState::DeviceStackBuilt],
        ),
        x if x == PNP_OP_START_DEVICE => transition_chain(
            sqe.arg0,
            &[
                DeviceState::ResourcesAssigned,
                DeviceState::StartIrpSent,
                DeviceState::Started,
            ],
        ),
        x if x == PNP_OP_REMOVE_DEVICE => {
            transition_chain(sqe.arg0, &[DeviceState::RemovePending, DeviceState::Removed])
        }
        _ => (fail, 0),
    }
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.pnp_manager_entry"]
pub unsafe extern "C" fn pnp_manager_entry() -> ! {
    core::ptr::write(STATE_VADDR as *mut PnpManager, PnpManager::new());

    let mut submissions = match Consumer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut completions = match Producer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let wait_requests = Sel4Notify::new(&ENV, CT_N_SUB);
    let signal_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        let (status, detail0) = serve(sqe);
        let cqe = SurtCqe {
            request_id: sqe.request_id,
            status,
            detail0,
            ..Default::default()
        };
        while completions.try_push(cqe).is_err() {
            yield_now();
        }
        let _ = completions.notify_consumer(&signal_completion);
        true
    });
    park()
}
