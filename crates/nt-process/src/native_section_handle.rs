//! Native-scope lookup for a section handle's identity and access grant.

use crate::native_handle::{NativeHandleCaller, NativeHandleScope, STATUS_OBJECT_TYPE_MISMATCH};
use crate::{HandleObject, ProcessId, ProcessManager, SectionId, STATUS_INVALID_HANDLE};

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
}
