//! Named Event publication from an authenticated kernel provider.
use super::*;
use nt_user_host::provider_named_event::NamedEventCreate;

impl ExecNtHandler {
    pub(crate) fn provider_create_named_event<O: Copy + Eq>(
        &mut self,
        target_pi: usize,
        caller: nt_process::native_handle::NativeHandleCaller,
        capture: &NamedEventCreate<O>,
    ) -> Result<(u32, u64), u32> {
        const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
        const BAD_NAME: u32 = 0xC000_0033;
        const COLLISION: u32 = 0xC000_0035;
        const TYPE_MISMATCH: u32 = 0xC000_0024;
        self.pm.validate_native_handle_caller(caller)?;
        let target_pid = self.pm_pid_for_pi(target_pi).ok_or(INVALID)?;
        if capture.security_descriptor.is_empty() {
            return Err(0xC000_00BB);
        }
        nt_security::security_descriptor_bytes_for_access(&capture.security_descriptor)?;
        let mut owned_sd = Vec::new();
        owned_sd.try_reserve_exact(capture.security_descriptor.len())
            .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
        owned_sd.extend_from_slice(&capture.security_descriptor);
        let mut name = [0u8; OBJ_NAME_CAP];
        if capture.name.len() > name.len() { return Err(BAD_NAME); }
        for (index, &unit) in capture.name.iter().enumerate() {
            let byte = u8::try_from(unit).map_err(|_| BAD_NAME)?;
            if !byte.is_ascii() { return Err(BAD_NAME); }
            name[index] = byte.to_ascii_lowercase();
        }
        let name = &name[..capture.name.len()];
        let (root, name) = self.native_directory_root_and_path(
            caller, capture.root_directory, name,
        )?;
        // The rooted directory handle is owned by the same authenticated provider call.
        if capture.root_directory != 0 {
            self.pm.lookup_native_object_directory_handle(
                caller, capture.root_directory, DIRECTORY_CREATE_OBJECT_ACCESS,
            )?;
        }
        let existing = self.obj_resolve(name, root);
        if let Some(index) = existing {
            if self.obj_ns[index].kind != OBJ_KIND_EVENT { return Err(TYPE_MISMATCH); }
            if capture.attributes & 0x80 == 0 { return Err(COLLISION); }
            let handle = self.mint_event_handle_for_pi(target_pi, index, capture.desired_access)
                .ok_or(nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
            return Ok((0x4000_0000, handle));
        }
        self.named_event_security.try_reserve(1)
            .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
        self.obj_ns.try_reserve(1)
            .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
        let index = self.obj_create(name, root, OBJ_KIND_EVENT, &[],
            capture.attributes & OBJ_PERMANENT != 0).ok_or(BAD_NAME)?;
        self.events.initialize(index as u64,
            if capture.event_type == 1 { EventKind::Synchronization } else { EventKind::Notification },
            capture.initial_state);
        let identity = self.obj_ns[index].identity;
        self.named_event_security.push((identity, owned_sd));
        let handle = match self.mint_event_handle_for_pi(target_pi, index, capture.desired_access) {
            Some(handle) => handle,
            None => {
                self.named_event_security.retain(|(owned, _)| *owned != identity);
                self.rollback_new_event(index);
                return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        assert_eq!(self.pm_pid_for_pi(target_pi), Some(target_pid));
        Ok((0, handle))
    }
}
