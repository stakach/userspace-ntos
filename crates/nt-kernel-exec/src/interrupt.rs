//! Simulated interrupt bridge (spec §11). A `KINTERRUPT` is opaque driver storage;
//! the runtime keeps its ISR registration keyed by the driver's pointer. There is
//! no real hardware interrupt in this milestone — a test harness (later, a real
//! seL4 IRQ notification) injects an interrupt by vector, the runtime raises to the
//! ISR's synthetic DIRQL, the driver's `KSERVICE_ROUTINE` runs (typically queuing a
//! DPC bottom-half), then the IRQL lowers and the DPC queue drains.

use alloc::vec::Vec;

/// The synthetic Device IRQL an injected ISR runs at — above `DISPATCH_LEVEL`
/// (real DIRQL values are platform interrupt-controller specific, spec §6.1).
pub const SYNTHETIC_DIRQL: u8 = 5;

struct Interrupt {
    ptr: u64,
    service_routine: u64,
    service_context: u64,
    vector: u32,
    dirql: u8,
    connected: bool,
}

/// The Driver Host's connected interrupts (spec §11).
#[derive(Default)]
pub struct InterruptTable {
    interrupts: Vec<Interrupt>,
}

impl InterruptTable {
    pub fn new() -> Self {
        Self {
            interrupts: Vec::new(),
        }
    }

    fn slot(&mut self, ptr: u64) -> &mut Interrupt {
        if let Some(i) = self.interrupts.iter().position(|x| x.ptr == ptr) {
            return &mut self.interrupts[i];
        }
        self.interrupts.push(Interrupt {
            ptr,
            service_routine: 0,
            service_context: 0,
            vector: 0,
            dirql: SYNTHETIC_DIRQL,
            connected: false,
        });
        self.interrupts.last_mut().unwrap()
    }

    /// `IoConnectInterrupt[Ex]` — register an ISR (`KSERVICE_ROUTINE`) for a vector.
    pub fn connect(
        &mut self,
        ptr: u64,
        service_routine: u64,
        service_context: u64,
        vector: u32,
        dirql: u8,
    ) {
        let x = self.slot(ptr);
        x.service_routine = service_routine;
        x.service_context = service_context;
        x.vector = vector;
        x.dirql = dirql;
        x.connected = true;
    }

    /// `IoDisconnectInterrupt[Ex]`.
    pub fn disconnect(&mut self, ptr: u64) {
        if let Some(x) = self.interrupts.iter_mut().find(|x| x.ptr == ptr) {
            x.connected = false;
        }
    }

    pub fn is_connected(&self, ptr: u64) -> bool {
        self.interrupts.iter().any(|x| x.ptr == ptr && x.connected)
    }

    /// The connected ISR bound to `vector`: `(service_routine, interrupt, service_context, dirql)`.
    pub fn find_vector(&self, vector: u32) -> Option<(u64, u64, u64, u8)> {
        self.interrupts
            .iter()
            .find(|x| x.connected && x.vector == vector)
            .map(|x| (x.service_routine, x.ptr, x.service_context, x.dirql))
    }
}

/// An ISR ready to run, from [`crate::KernelExecRuntime::inject_interrupt`]. The
/// caller invokes `KSERVICE_ROUTINE(Interrupt, ServiceContext) -> BOOLEAN` with no
/// runtime borrow held (spec §17), then calls `finish_isr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReadyIsr {
    pub service_routine: u64,
    pub interrupt: u64,
    pub service_context: u64,
    pub dirql: u8,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn connect_find_disconnect() {
        let mut t = InterruptTable::new();
        assert!(t.find_vector(0x30).is_none());
        t.connect(0x1000, 0x15E, 0xC7, 0x30, SYNTHETIC_DIRQL);
        assert!(t.is_connected(0x1000));
        assert_eq!(
            t.find_vector(0x30),
            Some((0x15E, 0x1000, 0xC7, SYNTHETIC_DIRQL))
        );
        t.disconnect(0x1000);
        assert!(!t.is_connected(0x1000));
        assert!(t.find_vector(0x30).is_none());
    }
}
