//! Native-scope lookup for file handles eligible to back data sections.

use crate::native_handle::{NativeHandleCaller, NativeHandleScope, STATUS_OBJECT_TYPE_MISMATCH};
use crate::{HandleObject, ProcessId, ProcessManager, STATUS_INVALID_HANDLE};

/// A table lookup, not a retained File reference. The section owner must separately retain its
/// backing before dispatching I/O or publishing a section handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSectionFileSource {
    owner: ProcessId,
    object: HandleObject,
    granted_access: u32,
}

impl NativeSectionFileSource {
    pub const fn owner(self) -> ProcessId {
        self.owner
    }

    pub const fn object(self) -> HandleObject {
        self.object
    }

    pub const fn granted_access(self) -> u32 {
        self.granted_access
    }
}

impl ProcessManager {
    /// Resolve the caller's exact user or kernel handle table and admit only file objects that
    /// the data-section path can retain. Pseudo handles and other object types are not files.
    pub fn lookup_native_section_file_source(
        &self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<NativeSectionFileSource, u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let object = self.lookup_handle(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(
            object,
            HandleObject::DiskFile { .. }
                | HandleObject::OverlayFile(_)
                | HandleObject::RoutedFile { .. }
        ) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        Ok(NativeSectionFileSource {
            owner,
            object,
            granted_access: self.handle_access(owner, handle).ok_or(STATUS_INVALID_HANDLE)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_handle::KERNEL_HANDLE_TAG;
    use crate::STATUS_INVALID_HANDLE;
    use nt_types::AccessMode;

    fn fixture() -> (ProcessManager, NativeHandleCaller, NativeHandleCaller, ProcessId) {
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
    fn exact_table_scope_and_granted_access() {
        let (mut pm, user, kernel, client) = fixture();
        let system = pm.initial_system_identity().unwrap().process_id();
        let local_object = HandleObject::DiskFile {
            first_cluster: 7,
            size: 8192,
            object_id: 3,
        };
        let global_object = HandleObject::RoutedFile {
            file_id: 41,
            device_id: 17,
        };
        let local = pm.insert_handle(client, local_object, 0x0004).unwrap();
        let global = pm.insert_handle(system, global_object, 0x0002).unwrap();
        assert_eq!(local, global);
        assert_eq!(
            pm.lookup_native_section_file_source(user, u64::from(local)).unwrap(),
            NativeSectionFileSource {
                owner: client,
                object: local_object,
                granted_access: 0x0004,
            }
        );
        assert_eq!(
            pm.lookup_native_section_file_source(kernel, KERNEL_HANDLE_TAG | u64::from(global))
                .unwrap(),
            NativeSectionFileSource {
                owner: system,
                object: global_object,
                granted_access: 0x0002,
            }
        );
        assert_eq!(
            pm.lookup_native_section_file_source(kernel, u64::from(local))
                .unwrap()
                .object(),
            local_object
        );
        assert_eq!(
            pm.lookup_native_section_file_source(user, KERNEL_HANDLE_TAG | u64::from(global)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn wrong_caller_and_non_file_handles_are_rejected() {
        let (mut pm, user, kernel, client) = fixture();
        let overlay = pm
            .insert_handle(client, HandleObject::OverlayFile(18), 0x0004)
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
            pm.lookup_native_section_file_source(other_caller, u64::from(overlay)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            pm.lookup_native_section_file_source(user, u64::from(overlay))
                .unwrap()
                .object(),
            HandleObject::OverlayFile(18)
        );
        for object in [HandleObject::File(18), HandleObject::Section(2)] {
            let handle = pm.insert_handle(client, object, 0).unwrap();
            assert_eq!(
                pm.lookup_native_section_file_source(kernel, u64::from(handle)),
                Err(STATUS_OBJECT_TYPE_MISMATCH)
            );
        }
        assert_eq!(
            pm.lookup_native_section_file_source(kernel, u64::MAX),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}
