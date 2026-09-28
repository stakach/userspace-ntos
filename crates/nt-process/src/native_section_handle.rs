//! Native-scope lookup for a section handle's identity and access grant.

use crate::native_handle::{
    NativeHandleCaller, NativeHandleScope, KERNEL_HANDLE_TAG, OBJ_KERNEL_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::{
    HandleFlags, HandleObject, HandleReservation, HandleSlot, ProcessId, ProcessManager,
    ProcessState, SectionId, STATUS_INVALID_HANDLE, STATUS_PROCESS_IS_TERMINATING,
};
use core::sync::atomic::{AtomicU64, Ordering};
use nt_types::AccessMode;

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);
const OBJ_INHERIT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Bound { section: SectionId, access: u32 },
    Published,
    Aborted,
}

/// An invisible Section reference until its handle value is delivered to the caller.
#[must_use = "Section handle publication must be published or aborted"]
pub struct NativeSectionHandlePublication {
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

/// A table lookup, not a retained section reference. Callers must not carry this snapshot across
/// callbacks or other operations that can close and reuse the handle slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSectionHandle {
    owner: ProcessId,
    section: SectionId,
    granted_access: u32,
}

impl NativeSectionHandle {
    pub const fn owner(self) -> ProcessId {
        self.owner
    }

    pub const fn section(self) -> SectionId {
        self.section
    }

    pub const fn granted_access(self) -> u32 {
        self.granted_access
    }
}

impl ProcessManager {
    pub fn reserve_native_section_handle(
        &mut self,
        caller: NativeHandleCaller,
        attributes: u32,
    ) -> Result<NativeSectionHandlePublication, u32> {
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
        if self.section_publication_identity == 0 {
            self.section_publication_identity = NEXT_IDENTITY
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
        Ok(NativeSectionHandlePublication {
            manager: self.section_publication_identity,
            reservation,
            value: u64::from(reservation.handle) | if kernel { KERNEL_HANDLE_TAG } else { 0 },
            flags: HandleFlags {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            phase: Phase::Reserved,
        })
    }

    /// Resolve a section handle in the native caller's exact user or System table. The full
    /// native width and caller mode are checked before the table slot is inspected.
    pub fn lookup_native_section_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<NativeSectionHandle, u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let section = match self
            .lookup_handle(owner, handle)
            .ok_or(STATUS_INVALID_HANDLE)?
        {
            HandleObject::Section(section) => section,
            _ => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        Ok(NativeSectionHandle {
            owner,
            section,
            granted_access: self
                .handle_access(owner, handle)
                .ok_or(STATUS_INVALID_HANDLE)?,
        })
    }
}

impl NativeSectionHandlePublication {
    fn validate_manager(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.manager == 0 || self.manager != pm.section_publication_identity {
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
        section: SectionId,
        access: u32,
    ) -> Result<(), u32> {
        self.validate_manager(pm)?;
        if self.phase != Phase::Reserved {
            return Err(STATUS_INVALID_HANDLE);
        }
        admit_owner(pm, self.reservation.process_id)?;
        pm.bind_reserved_handle(self.reservation, HandleObject::Section(section), access)?;
        let slot = crate::handle_to_slot(self.reservation.handle).expect("reserved Section handle");
        let HandleSlot::Bound { entry, .. } = &mut pm
            .processes
            .get_mut(&self.reservation.process_id)
            .expect("reserved Section owner")
            .handles[slot]
        else {
            unreachable!("new Section binding remains bound")
        };
        entry.flags = self.flags;
        self.phase = Phase::Bound { section, access };
        Ok(())
    }

    fn validate_bound(&self, pm: &ProcessManager) -> Result<SectionId, u32> {
        self.validate_manager(pm)?;
        let Phase::Bound { section, access } = self.phase else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let process = pm
            .process(self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = crate::handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        match process.handles.get(slot) {
            Some(HandleSlot::Bound { generation, entry })
                if *generation == self.reservation.generation
                    && entry.object == HandleObject::Section(section)
                    && entry.granted_access == access
                    && entry.flags == self.flags =>
            {
                Ok(section)
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

    /// Return a bound Section to the caller for control-area retirement.
    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<Option<SectionId>, u32> {
        self.validate_manager(pm)?;
        let section = match self.phase {
            Phase::Reserved => {
                pm.cancel_reserved_handle(self.reservation)?;
                None
            }
            Phase::Bound { .. } => {
                let section = self.validate_bound(pm)?;
                pm.cancel_bound_handle(self.reservation)?;
                Some(section)
            }
            Phase::Published | Phase::Aborted => return Err(STATUS_INVALID_HANDLE),
        };
        self.phase = Phase::Aborted;
        Ok(section)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_handle::KERNEL_HANDLE_TAG;
    use nt_types::AccessMode;

    fn fixture() -> (
        ProcessManager,
        NativeHandleCaller,
        NativeHandleCaller,
        ProcessId,
    ) {
        let mut pm = ProcessManager::new();
        let system = pm.create_process("kernel", None, None);
        let system_thread = pm.create_thread(system, 0, 0, true).unwrap();
        pm.designate_initial_system(system, system_thread).unwrap();
        let client = pm.create_process("client", None, None);
        let thread = pm.create_thread(client, 0, 0, false).unwrap();
        let lifetime = pm.thread_lifetime(thread).unwrap();
        let user = pm
            .capture_native_handle_caller(lifetime, AccessMode::UserMode)
            .unwrap();
        let kernel = pm
            .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
            .unwrap();
        (pm, user, kernel, client)
    }

    #[test]
    fn tagged_kernel_handle_uses_system_table_not_colliding_client_slot() {
        let (mut pm, user, kernel, client) = fixture();
        let system = pm.initial_system_identity().unwrap().process_id();
        let local = pm
            .insert_handle(client, HandleObject::Section(11), 0x0004)
            .unwrap();
        let global = pm
            .insert_handle(system, HandleObject::Section(29), 0x0002)
            .unwrap();
        assert_eq!(local, global);
        assert_eq!(
            pm.lookup_native_section_handle(user, u64::from(local)),
            Ok(NativeSectionHandle {
                owner: client,
                section: 11,
                granted_access: 0x0004,
            })
        );
        assert_eq!(
            pm.lookup_native_section_handle(kernel, u64::from(local)),
            Ok(NativeSectionHandle {
                owner: client,
                section: 11,
                granted_access: 0x0004,
            })
        );
        assert_eq!(
            pm.lookup_native_section_handle(kernel, KERNEL_HANDLE_TAG | u64::from(global)),
            Ok(NativeSectionHandle {
                owner: system,
                section: 29,
                granted_access: 0x0002,
            })
        );
        assert_eq!(
            pm.lookup_native_section_handle(user, KERNEL_HANDLE_TAG | u64::from(global)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn rejects_foreign_pseudo_nonsection_and_invalid_width() {
        let (mut pm, user, kernel, client) = fixture();
        let local = pm
            .insert_handle(client, HandleObject::Section(11), 0x0004)
            .unwrap();
        let other = pm.create_process("other", None, None);
        let other_thread = pm.create_thread(other, 0, 0, false).unwrap();
        let other_caller = pm
            .capture_native_handle_caller(
                pm.thread_lifetime(other_thread).unwrap(),
                AccessMode::KernelMode,
            )
            .unwrap();
        assert_eq!(
            pm.lookup_native_section_handle(other_caller, u64::from(local)),
            Err(STATUS_INVALID_HANDLE)
        );
        let file = pm.insert_handle(client, HandleObject::File(7), 0).unwrap();
        assert_eq!(
            pm.lookup_native_section_handle(user, u64::from(file)),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        for value in [u64::MAX, u64::MAX - 1, 0x1_0000_0000 | u64::from(local)] {
            assert_eq!(
                pm.lookup_native_section_handle(kernel, value),
                Err(STATUS_INVALID_HANDLE),
            );
        }
    }

    #[test]
    fn section_publication_is_invisible_until_delivery_and_uses_exact_scope() {
        let (mut pm, user, kernel, client) = fixture();
        let system = pm.initial_system_identity().unwrap().process_id();
        assert_eq!(
            pm.reserve_native_section_handle(user, OBJ_KERNEL_HANDLE)
                .err(),
            Some(crate::STATUS_INVALID_PARAMETER)
        );
        let mut local = pm.reserve_native_section_handle(user, OBJ_INHERIT).unwrap();
        let mut global = pm
            .reserve_native_section_handle(kernel, OBJ_KERNEL_HANDLE)
            .unwrap();
        assert_eq!(local.process_id(), client);
        assert_eq!(global.process_id(), system);
        assert_eq!(global.value() & KERNEL_HANDLE_TAG, KERNEL_HANDLE_TAG);
        local.bind(&mut pm, 17, 0x4).unwrap();
        global.bind(&mut pm, 19, 0x2).unwrap();
        assert_eq!(
            pm.lookup_native_section_handle(user, local.value()),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            pm.lookup_native_section_handle(kernel, global.value()),
            Err(STATUS_INVALID_HANDLE)
        );
        let local_value = local.publish(&mut pm).unwrap();
        let global_value = global.publish(&mut pm).unwrap();
        assert_eq!(
            pm.lookup_native_section_handle(user, local_value)
                .unwrap()
                .section(),
            17
        );
        assert_eq!(
            pm.lookup_native_section_handle(kernel, global_value)
                .unwrap()
                .section(),
            19
        );
        assert_eq!(
            pm.lookup_native_section_handle(user, global_value),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            pm.handle_flags(client, local_value as u32).unwrap().inherit,
            true
        );
    }

    #[test]
    fn abort_returns_only_the_exact_bound_section_and_reuses_slot_safely() {
        let (mut pm, user, _, _) = fixture();
        let mut first = pm.reserve_native_section_handle(user, 0).unwrap();
        let value = first.value();
        first.bind(&mut pm, 23, 0x4).unwrap();
        assert_eq!(first.abort(&mut pm), Ok(Some(23)));
        assert_eq!(first.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            pm.lookup_native_section_handle(user, value),
            Err(STATUS_INVALID_HANDLE)
        );
        let mut second = pm.reserve_native_section_handle(user, 0).unwrap();
        second.bind(&mut pm, 29, 0x2).unwrap();
        second.publish(&mut pm).unwrap();
        assert_eq!(
            pm.lookup_native_section_handle(user, second.value())
                .unwrap()
                .section(),
            29
        );
    }
}
