//! Handle attributes requested through `OBJECT_ATTRIBUTES` when a handle is created.
//!
//! NT gives a new handle the `OBJ_INHERIT` attribute of the request that created it
//! (`ObpCreateHandle`), so `GetHandleInformation` reports `HANDLE_FLAG_INHERIT` and
//! `ObInitProcess` copies it into a child created with inheritance.

use crate::{HandleFlags, HandleReservation, ProcessId, ProcessManager};

const OBJ_INHERIT: u32 = 0x2;

impl ProcessManager {
    /// Reserve a handle slot for an object opened with `attributes`
    /// (`OBJECT_ATTRIBUTES.Attributes`). The handle bound into the reservation carries the
    /// attributes' handle flags.
    pub fn try_reserve_handle_slot_for_attributes(
        &mut self,
        pid: ProcessId,
        attributes: u32,
    ) -> Result<HandleReservation, u32> {
        self.try_reserve_handle_slot_with_flags(pid, HandleFlags {
            inherit: attributes & OBJ_INHERIT != 0,
            protect_from_close: false,
        })
    }
}
