//! Canonical dispatcher storage created before providers and moved once into the live handler.

use super::*;

pub(crate) struct DispatcherBootstrapSeed {
    pub obj_ns: Vec<ObjEntry>,
    pub anon_event_seq: u32,
    pub dispatcher: nt_user_host::dispatcher_state::DispatcherState,
}

enum BootstrapPhase {
    Uninitialized,
    Owned(DispatcherBootstrapSeed),
    Transferred,
}

static mut BOOTSTRAP: BootstrapPhase = BootstrapPhase::Uninitialized;

pub(crate) unsafe fn initialize() -> Result<(), u32> {
    if !matches!(
        &*core::ptr::addr_of!(BOOTSTRAP),
        BootstrapPhase::Uninitialized
    ) {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let _durable = allocator::enter_durable();
    let seed = DispatcherBootstrapSeed {
        obj_ns: exec_handler::build_initial_object_namespace(),
        anon_event_seq: 0,
        dispatcher: nt_user_host::dispatcher_state::DispatcherState::new(192, 192),
    };
    core::ptr::addr_of_mut!(BOOTSTRAP).write(BootstrapPhase::Owned(seed));
    Ok(())
}

pub(crate) unsafe fn take() -> DispatcherBootstrapSeed {
    match core::mem::replace(
        &mut *core::ptr::addr_of_mut!(BOOTSTRAP),
        BootstrapPhase::Transferred,
    ) {
        BootstrapPhase::Owned(seed) => seed,
        BootstrapPhase::Uninitialized => {
            panic!("dispatcher bootstrap must precede handler initialization")
        }
        BootstrapPhase::Transferred => {
            panic!("dispatcher bootstrap storage was already transferred")
        }
    }
}
