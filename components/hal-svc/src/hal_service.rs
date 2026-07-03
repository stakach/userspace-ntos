//! The isolated HAL service child: hosts the canonical Resource Manager, owns the
//! shared MMIO register bank, and serves HAL requests over SURT. It validates every
//! map/connect against a static fixture and **never calls driver code** — on
//! injection it asserts the device's interrupt line in the shared frame and returns
//! the Driver Host's opaque ISR tokens for the Driver Host to run locally (spec
//! §11.1, §16.3).

use nt_hal_abi::{
    HAL_OP_CONNECT_INTERRUPT, HAL_OP_DISCONNECT_INTERRUPT, HAL_OP_INJECT_INTERRUPT,
    HAL_OP_MAP_IO_SPACE, HAL_OP_UNMAP_IO_SPACE,
};
use nt_resource_manager::{ResourceManager, ResourceOwner};
use nt_sim_device::{ID_VALUE, REG_ID, REG_STATUS, STATUS_INTERRUPT_PENDING};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    yield_now, COMP_RING_VADDR, CT_N_COMP, CT_N_SUB, DEVICE_OBJECT_ID, DRIVER_HOST_ID, ENV,
    HAL_MMIO_VADDR, RING_LEN, STATE_VADDR, SUB_RING_VADDR,
};

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
}

/// The canonical Resource Manager, stored on the RW state page (the child's `.bss`
/// is mapped read-only; its `Vec`s allocate from the child's heap).
fn rm() -> &'static mut ResourceManager {
    // SAFETY: single-threaded child; the state page holds an initialised RM.
    unsafe { &mut *(STATE_VADDR as *mut ResourceManager) }
}

/// Read/write the shared MMIO register bank directly (the same physical frame the
/// Driver Host maps + the driver dereferences).
unsafe fn mmio_write(offset: u64, value: u32) {
    core::ptr::write_volatile((HAL_MMIO_VADDR + offset) as *mut u32, value);
}
unsafe fn mmio_read(offset: u64) -> u32 {
    core::ptr::read_volatile((HAL_MMIO_VADDR + offset) as *const u32)
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

/// Dispatch one HAL request; returns `(status, detail0, detail1)`.
unsafe fn serve(sqe: &SurtSqe) -> (i32, u64, u64) {
    let ok = 0i32;
    let fail = 0xC000_0001u32 as i32; // STATUS_UNSUCCESSFUL
    match sqe.opcode {
        x if x == HAL_OP_MAP_IO_SPACE => {
            match rm().map_io_space(owner(), sqe.arg0, sqe.arg1, sqe.arg2 as u32) {
                Ok(g) => (ok, g.mapping_id, 0),
                Err(_) => (fail, 0, 0),
            }
        }
        x if x == HAL_OP_UNMAP_IO_SPACE => match rm().unmap_io_space(owner(), sqe.arg0) {
            Ok(()) => (ok, 0, 0),
            Err(_) => (fail, 0, 0),
        },
        x if x == HAL_OP_CONNECT_INTERRUPT => {
            // arg0 = resource_id, arg1 = routine_token, arg2 = context_token.
            match rm().connect_interrupt(owner(), sqe.arg0, sqe.arg1, sqe.arg2) {
                Ok(interrupt_id) => (ok, interrupt_id, 0),
                Err(_) => (fail, 0, 0),
            }
        }
        x if x == HAL_OP_DISCONNECT_INTERRUPT => {
            match rm().disconnect_interrupt(owner(), sqe.arg0) {
                Ok(()) => (ok, 0, 0),
                Err(_) => (fail, 0, 0),
            }
        }
        x if x == HAL_OP_INJECT_INTERRUPT => {
            // Assert the device interrupt line in the shared frame, then return the
            // connected ISR's opaque tokens for the Driver Host to run locally.
            match rm().inject_interrupt(sqe.arg0) {
                Some(t) => {
                    let s = mmio_read(REG_STATUS);
                    mmio_write(REG_STATUS, s | STATUS_INTERRUPT_PENDING);
                    (ok, t.service_routine_token, t.service_context_token)
                }
                None => (fail, 0, 0),
            }
        }
        _ => (fail, 0, 0),
    }
}

#[no_mangle]
#[link_section = ".text.hal_service_entry"]
pub unsafe extern "C" fn hal_service_entry() -> ! {
    // Initialise the canonical Resource Manager on the state page + seed the shared
    // register bank's ID register.
    core::ptr::write(
        STATE_VADDR as *mut ResourceManager,
        ResourceManager::with_mmio_test_fixture(owner()),
    );
    mmio_write(REG_ID, ID_VALUE);

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
        let (status, detail0, detail1) = serve(sqe);
        let cqe = SurtCqe {
            request_id: sqe.request_id,
            status,
            detail0,
            detail1,
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
