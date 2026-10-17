use crate::native_handle::{NativeHandleCaller, NativeHandleScope};
use crate::{HandleFlags, ProcessManager, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE};

impl ProcessManager {
    /// `ZwQueryObject(ObjectHandleFlagInformation)` for one entry in the authenticated
    /// caller's exact table. Pseudo handles have no mutable per-handle flags.
    pub fn query_native_object_handle_flag_information(
        &self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<[u8; 2], u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let flags = self.handle_flags(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
        Ok([flags.inherit.into(), flags.protect_from_close.into()])
    }

    /// `ZwSetInformationObject(ObjectHandleFlagInformation)` after the native adapter has
    /// captured exactly two bytes from its kernel buffer. Handle decoding authenticates the
    /// caller's table, including the System table for tagged kernel handles.
    pub fn set_native_object_handle_flag_information(
        &mut self,
        caller: NativeHandleCaller,
        handle: u64,
        encoded: &[u8],
    ) -> Result<(), u32> {
        let [inherit, protect_from_close] = encoded else {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        };
        self.set_native_handle_flags(
            caller,
            handle,
            HandleFlags {
                inherit: *inherit != 0,
                protect_from_close: *protect_from_close != 0,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::native_handle::KERNEL_HANDLE_TAG;
    use crate::{HandleFlags, HandleObject, ProcessManager, STATUS_INVALID_HANDLE};
    use nt_types::AccessMode;

    fn fixture() -> (
        ProcessManager,
        crate::native_handle::NativeHandleCaller,
        crate::native_handle::NativeHandleCaller,
        crate::ProcessId,
        crate::ProcessId,
    ) {
        let mut manager = ProcessManager::new();
        let system = manager.create_process("System", None, None);
        let system_thread = manager.create_thread(system, 0, 0, true).unwrap();
        manager.designate_initial_system(system, system_thread).unwrap();
        let client = manager.create_process("client.exe", None, None);
        let client_thread = manager.create_thread(client, 0, 0, false).unwrap();
        let lifetime = manager.thread_lifetime(client_thread).unwrap();
        let user = manager
            .capture_native_handle_caller(lifetime, AccessMode::UserMode)
            .unwrap();
        let kernel = manager
            .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
            .unwrap();
        (manager, user, kernel, system, client)
    }

    #[test]
    fn native_object_handle_flag_information_decodes_two_bytes_into_exact_owner() {
        let (mut manager, user, kernel, system, client) = fixture();
        let user_handle = manager
            .insert_handle(client, HandleObject::Opaque(0x101), 0)
            .unwrap();
        let kernel_handle = manager
            .insert_handle(system, HandleObject::Opaque(0x202), 0)
            .unwrap();
        assert_eq!(user_handle, kernel_handle);

        assert_eq!(
            manager.set_native_object_handle_flag_information(
                user,
                u64::from(user_handle) | 1,
                &[1, 0],
            ),
            Ok(())
        );
        assert_eq!(
            manager.handle_flags(client, user_handle),
            Some(HandleFlags {
                inherit: true,
                protect_from_close: false,
            })
        );
        assert_eq!(manager.handle_flags(system, kernel_handle), Some(HandleFlags::default()));

        assert_eq!(
            manager.set_native_object_handle_flag_information(
                kernel,
                KERNEL_HANDLE_TAG | u64::from(kernel_handle) | 2,
                &[0, 7],
            ),
            Ok(())
        );
        assert_eq!(
            manager.handle_flags(system, kernel_handle),
            Some(HandleFlags {
                inherit: false,
                protect_from_close: true,
            })
        );
    }

    #[test]
    fn native_object_handle_flag_information_rejects_bad_length_and_pseudo_handles() {
        let (mut manager, user, kernel, system, client) = fixture();
        let user_handle = manager
            .insert_handle(client, HandleObject::Opaque(0x101), 0)
            .unwrap();
        let system_handle = manager
            .insert_handle(system, HandleObject::Opaque(0x202), 0)
            .unwrap();
        for bad in [&[][..], &[1][..], &[1, 0, 0][..]] {
            assert_eq!(
                manager.set_native_object_handle_flag_information(
                    user,
                    u64::from(user_handle),
                    bad,
                ),
                Err(crate::STATUS_INFO_LENGTH_MISMATCH)
            );
        }
        assert_eq!(
            manager.set_native_object_handle_flag_information(kernel, u64::MAX, &[1, 1]),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.set_native_object_handle_flag_information(
                user,
                KERNEL_HANDLE_TAG | u64::from(system_handle),
                &[1, 1],
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.handle_flags(client, user_handle), Some(HandleFlags::default()));
        assert_eq!(manager.handle_flags(system, system_handle), Some(HandleFlags::default()));
    }

    #[test]
    fn native_object_handle_flag_query_uses_exact_decoded_owner() {
        let (mut manager, user, kernel, system, client) = fixture();
        let user_handle = manager
            .insert_handle(client, HandleObject::Opaque(0x101), 0)
            .unwrap();
        let system_handle = manager
            .insert_handle(system, HandleObject::Opaque(0x202), 0)
            .unwrap();
        assert_eq!(user_handle, system_handle);
        assert_eq!(
            manager.query_native_object_handle_flag_information(user, u64::from(user_handle)),
            Ok([0, 0])
        );
        manager
            .set_native_object_handle_flag_information(user, u64::from(user_handle), &[1, 0])
            .unwrap();
        assert_eq!(
            manager.query_native_object_handle_flag_information(user, u64::from(user_handle)),
            Ok([1, 0])
        );
        assert_eq!(
            manager.query_native_object_handle_flag_information(
                kernel,
                KERNEL_HANDLE_TAG | u64::from(system_handle),
            ),
            Ok([0, 0])
        );
        assert_eq!(
            manager.query_native_object_handle_flag_information(user, u64::MAX),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}
