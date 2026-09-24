//! Native handle publication for a canonical routed FILE_OBJECT.

use crate::native_handle::{
    NativeHandleCaller, NativeHandleScope, NativePsCloseError, KERNEL_HANDLE_TAG,
    OBJ_KERNEL_HANDLE, STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::{
    HandleFlags, HandleObject, HandleReservation, HandleSlot, ProcessId, ProcessManager,
    ProcessState, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_PROCESS_IS_TERMINATING,
};
use core::sync::atomic::{AtomicU64, Ordering};
use nt_types::AccessMode;

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);
const OBJ_INHERIT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Bound {
        file_id: u64,
        device_id: u64,
        access: u32,
    },
    Published,
    Aborted,
}

/// An invisible table reference retained until caller output is committed or rolled back.
/// Provider File ownership is independent; the executive must release the returned identity.
#[must_use = "routed File publication must be published or aborted"]
pub struct RoutedFileHandlePublication {
    manager: u64,
    reservation: HandleReservation,
    value: u64,
    flags: HandleFlags,
    phase: Phase,
}

fn admit_owner(pm: &ProcessManager, pid: ProcessId) -> Result<(), u32> {
    let process = pm.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
    if matches!(
        process.state,
        ProcessState::Exiting | ProcessState::Terminated
    ) {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    Ok(())
}

impl ProcessManager {
    pub fn reserve_native_routed_file_handle(
        &mut self,
        caller: NativeHandleCaller,
        attributes: u32,
    ) -> Result<RoutedFileHandlePublication, u32> {
        self.validate_native_handle_caller(caller)?;
        let kernel = attributes & OBJ_KERNEL_HANDLE != 0;
        if attributes & !(OBJ_KERNEL_HANDLE | OBJ_INHERIT) != 0
            || (kernel && caller.mode() != AccessMode::KernelMode)
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        let owner = if kernel {
            self.initial_system_identity()
                .ok_or(STATUS_INVALID_HANDLE)?
                .process_id()
        } else {
            caller.effective_process()
        };
        admit_owner(self, owner)?;
        if self.routed_file_publication_identity == 0 {
            self.routed_file_publication_identity = NEXT_IDENTITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| crate::STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let reservation = self.try_reserve_handle_slot(owner)?;
        if reservation.handle > 0x7fff_fffc {
            self.cancel_reserved_handle(reservation)?;
            return Err(crate::STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(RoutedFileHandlePublication {
            manager: self.routed_file_publication_identity,
            reservation,
            value: u64::from(reservation.handle) | if kernel { KERNEL_HANDLE_TAG } else { 0 },
            flags: HandleFlags {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            phase: Phase::Reserved,
        })
    }

    /// This is a typed lookup, not a File pointer reference. The I/O Manager must separately
    /// retain the exact File and project a FILE_OBJECT before publishing a pointer to a driver.
    pub fn lookup_native_routed_file_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
        desired_access: u32,
    ) -> Result<(u64, u64), u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let HandleObject::RoutedFile { file_id, device_id } = self
            .lookup_handle(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let granted = self
            .handle_access(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if caller.mode() == AccessMode::UserMode && desired_access & !granted != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok((file_id, device_id))
    }

    /// Removes only the table reference. The executive must schedule canonical File cleanup.
    pub fn close_native_routed_file_handle(
        &mut self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<(u64, u64), NativePsCloseError> {
        let target = self
            .inspect_native_close_target(caller, value)
            .map_err(NativePsCloseError::Status)?;
        let HandleObject::RoutedFile { file_id, device_id } = target.object() else {
            return Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH));
        };
        let removed = self.close_native_handle(caller, value)?;
        debug_assert_eq!(removed.into_object(), target.object());
        Ok((file_id, device_id))
    }
}

impl RoutedFileHandlePublication {
    fn validate_manager(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.manager == 0 || self.manager != pm.routed_file_publication_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    pub const fn value(&self) -> u64 {
        self.value
    }
    pub const fn process_id(&self) -> ProcessId {
        self.reservation.process_id
    }

    pub fn bind(
        &mut self,
        pm: &mut ProcessManager,
        file_id: u64,
        device_id: u64,
        access: u32,
    ) -> Result<(), u32> {
        self.validate_manager(pm)?;
        if self.phase != Phase::Reserved {
            return Err(STATUS_INVALID_HANDLE);
        }
        admit_owner(pm, self.reservation.process_id)?;
        pm.bind_reserved_handle(
            self.reservation,
            HandleObject::RoutedFile { file_id, device_id },
            access,
        )?;
        let slot = crate::handle_to_slot(self.reservation.handle).expect("reserved File handle");
        let HandleSlot::Bound { entry, .. } = &mut pm
            .processes
            .get_mut(&self.reservation.process_id)
            .expect("reserved File owner")
            .handles[slot]
        else {
            unreachable!("new File binding remains bound")
        };
        entry.flags = self.flags;
        self.phase = Phase::Bound {
            file_id,
            device_id,
            access,
        };
        Ok(())
    }

    fn validate_bound(&self, pm: &ProcessManager) -> Result<(u64, u64), u32> {
        self.validate_manager(pm)?;
        let Phase::Bound {
            file_id,
            device_id,
            access,
        } = self.phase
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let process = pm
            .process(self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = crate::handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        match process.handles.get(slot) {
            Some(HandleSlot::Bound { generation, entry })
                if *generation == self.reservation.generation
                    && entry.object == HandleObject::RoutedFile { file_id, device_id }
                    && entry.granted_access == access
                    && entry.flags == self.flags =>
            {
                Ok((file_id, device_id))
            }
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    pub fn publish(&mut self, pm: &mut ProcessManager) -> Result<u64, u32> {
        self.validate_bound(pm)?;
        admit_owner(pm, self.reservation.process_id)?;
        pm.publish_reserved_handle(self.reservation)?;
        self.phase = Phase::Published;
        Ok(self.value)
    }

    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<Option<(u64, u64)>, u32> {
        self.validate_manager(pm)?;
        let file = match self.phase {
            Phase::Reserved => {
                pm.cancel_reserved_handle(self.reservation)?;
                None
            }
            Phase::Bound { .. } => {
                let file = self.validate_bound(pm)?;
                pm.cancel_bound_handle(self.reservation)?;
                Some(file)
            }
            Phase::Published | Phase::Aborted => return Err(STATUS_INVALID_HANDLE),
        };
        self.phase = Phase::Aborted;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_handle::{KERNEL_HANDLE_TAG, OBJ_KERNEL_HANDLE};
    use crate::{HandleFlags, HandleObject, STATUS_ACCESS_DENIED};
    use nt_types::AccessMode;

    fn fixture() -> (ProcessManager, NativeHandleCaller, NativeHandleCaller) {
        let mut pm = ProcessManager::new();
        let system = pm.create_process("system", None, None);
        let initial = pm.create_thread(system, 0, 0, true).unwrap();
        pm.designate_initial_system(system, initial).unwrap();
        let client = pm.create_process("client", None, None);
        let thread = pm.create_thread(client, 0, 0, false).unwrap();
        let lifetime = pm.thread_lifetime(thread).unwrap();
        let user = pm
            .capture_native_handle_caller(lifetime, AccessMode::UserMode)
            .unwrap();
        let kernel = pm
            .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
            .unwrap();
        (pm, user, kernel)
    }

    #[test]
    fn kernel_file_handle_is_invisible_until_publication_and_typed_on_close() {
        let (mut pm, user, kernel) = fixture();
        let mut publication = pm
            .reserve_native_routed_file_handle(kernel, OBJ_KERNEL_HANDLE)
            .unwrap();
        assert_eq!(publication.value() & KERNEL_HANDLE_TAG, KERNEL_HANDLE_TAG);
        publication.bind(&mut pm, 41, 17, 0x3).unwrap();
        assert_eq!(
            pm.lookup_native_routed_file_handle(kernel, publication.value(), 0),
            Err(STATUS_INVALID_HANDLE)
        );
        publication.publish(&mut pm).unwrap();
        assert_eq!(
            pm.lookup_native_routed_file_handle(user, publication.value(), 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            pm.lookup_native_routed_file_handle(kernel, publication.value(), 0x3),
            Ok((41, 17))
        );
        assert_eq!(
            pm.close_native_routed_file_handle(kernel, publication.value())
                .unwrap(),
            (41, 17)
        );
        assert_eq!(
            pm.lookup_native_routed_file_handle(kernel, publication.value(), 0),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn abort_preserves_exact_file_identity_and_reused_generation() {
        let (mut pm, _, kernel) = fixture();
        let mut first = pm
            .reserve_native_routed_file_handle(kernel, OBJ_KERNEL_HANDLE)
            .unwrap();
        first.bind(&mut pm, 51, 19, 1).unwrap();
        assert_eq!(first.abort(&mut pm), Ok(Some((51, 19))));
        let mut second = pm
            .reserve_native_routed_file_handle(kernel, OBJ_KERNEL_HANDLE)
            .unwrap();
        second.bind(&mut pm, 52, 19, 1).unwrap();
        assert_eq!(first.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
        second.publish(&mut pm).unwrap();
        assert_eq!(
            pm.lookup_native_routed_file_handle(kernel, second.value(), 1),
            Ok((52, 19))
        );
    }

    #[test]
    fn scope_access_and_type_are_checked_before_reference_or_close() {
        let (mut pm, user, kernel) = fixture();
        assert!(matches!(
            pm.reserve_native_routed_file_handle(user, OBJ_KERNEL_HANDLE),
            Err(crate::STATUS_INVALID_PARAMETER)
        ));
        let mut file = pm.reserve_native_routed_file_handle(user, 0).unwrap();
        file.bind(&mut pm, 61, 23, 1).unwrap();
        file.publish(&mut pm).unwrap();
        assert_eq!(
            pm.lookup_native_routed_file_handle(user, file.value(), 2),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            pm.lookup_native_routed_file_handle(kernel, file.value(), 2),
            Ok((61, 23))
        );
        let other = pm
            .insert_handle(user.effective_process(), HandleObject::Opaque(7), 0)
            .unwrap();
        assert!(pm
            .close_native_routed_file_handle(user, other as u64)
            .is_err());
        assert_eq!(
            pm.lookup_handle(user.effective_process(), other),
            Some(HandleObject::Opaque(7))
        );
    }

    #[test]
    fn protected_close_does_not_release_the_file_reference() {
        let (mut pm, user, _) = fixture();
        let mut file = pm.reserve_native_routed_file_handle(user, 0).unwrap();
        file.bind(&mut pm, 71, 29, 1).unwrap();
        file.publish(&mut pm).unwrap();
        pm.set_handle_flags(
            user.effective_process(),
            file.value() as u32,
            HandleFlags {
                inherit: false,
                protect_from_close: true,
            },
        )
        .unwrap();
        assert!(pm
            .close_native_routed_file_handle(user, file.value())
            .is_err());
        assert_eq!(
            pm.lookup_native_routed_file_handle(user, file.value(), 1),
            Ok((71, 29))
        );
    }
}
