//! Hosted native Key admission: captured subject, real namespace, exact grant and reserved output.

use super::*;
use nt_process::RegistryKeyHandlePublication;
use nt_user_host::registry_subject::RegistrySubject;

/// Owned across CM work; no token/PM/namespace borrow survives an IPC boundary.
pub(crate) struct HostedRegistryPublication {
    pub subject: RegistrySubject,
    pub publication: RegistryKeyHandlePublication,
    pub path: alloc::string::String,
    pub output: u64,
    pub disposition_output: u64,
    pub desired: u32,
    pub bound_target: Option<KeyRef>,
    root: Option<(KeyRef, RegistryKeyHandlePublication)>,
    relative: Option<alloc::string::String>,
}

impl ExecNtHandler {
    pub(super) unsafe fn read_registry_name_checked(
        &mut self,
        address: u64,
    ) -> Result<alloc::string::String, u32> {
        let mut header = [0u8; 16];
        self.process_memory_read_status(self.pi, address, &mut header)?;
        let length = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
        let maximum = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
        if length & 1 != 0 || length > maximum {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let pointer = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let mut bytes = alloc::vec![0u8; length];
        if length != 0 {
            self.process_memory_read_status(self.pi, pointer, &mut bytes)?;
        }
        let units: alloc::vec::Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name =
            alloc::string::String::from_utf16(&units).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
        if name.contains('\0') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(name)
    }

    unsafe fn capture_hosted_registry_publication(
        &mut self,
        args: &[u64],
        create: bool,
    ) -> Result<(HostedRegistryPublication, u64), u32> {
        if args[0] == 0
            || !self.probe_user_output(args[0], 8)
            || (create && args[6] != 0 && !self.probe_user_output(args[6], 4))
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let mut attributes = [0u8; 48];
        if args[2] == 0 || !self.xas_read(args[2], &mut attributes) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        if u32::from_le_bytes(attributes[..4].try_into().unwrap()) != 48 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let flags = u32::from_le_bytes(attributes[24..28].try_into().unwrap());
        if flags & !(0x2 | 0x40 | 0x80 | 0x200 | 0x400) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let lifetime = self
            .pm
            .thread_lifetime(self.current_tid as u32)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let caller = self
            .pm
            .capture_native_handle_caller(lifetime, nt_types::AccessMode::UserMode)?;
        let root = u64::from_le_bytes(attributes[8..16].try_into().unwrap());
        let name = self.read_registry_name_checked(u64::from_le_bytes(
            attributes[16..24].try_into().unwrap(),
        ))?;
        let full = if root == 0 {
            if !name.starts_with('\\') {
                return Err(0xC000_003B);
            }
            name.clone()
        } else {
            if name.starts_with('\\') {
                return Err(0xC000_003B);
            }
            let target = self.pm.lookup_native_registry_key_handle(caller, root, 0)?;
            let mut full = self
                .registry_target_path(target)
                .ok_or(STATUS_INVALID_HANDLE)?;
            if !name.is_empty() {
                full.push('\\');
                full.push_str(&name);
            }
            full
        };
        let mut subject = RegistrySubject::capture(&self.pm, &mut self.token_store, caller)?;
        let mut publication = match self
            .pm
            .reserve_native_registry_key_handle(caller, flags & (0x2 | 0x200))
        {
            Ok(publication) => publication,
            Err(status) => {
                subject
                    .release(&mut self.token_store)
                    .expect("registry subject ownership");
                return Err(status);
            }
        };
        let mut retained_root = None;
        let path_result = (|| {
            if root != 0 {
                let target = self.pm.lookup_native_registry_key_handle(caller, root, 0)?;
                let mut owner = self.pm.reserve_native_registry_key_handle(caller, 0)?;
                if let Err(status) = owner.bind(&mut self.pm, target, 0) {
                    owner.abort(&mut self.pm).expect("unbound root reservation");
                    return Err(status);
                }
                retained_root = Some((target, owner));
            }
            self.registry_storage_canon(&full)
        })();
        let path = match path_result {
            Ok(path) => path,
            Err(status) => {
                publication
                    .abort(&mut self.pm)
                    .expect("unbound registry reservation");
                if let Some((_, mut owner)) = retained_root.take() {
                    if let Some(target) = owner.abort(&mut self.pm).expect("root reservation") {
                        self.release_registry_key_target(target);
                    }
                }
                subject
                    .release(&mut self.token_store)
                    .expect("registry subject ownership");
                return Err(status);
            }
        };
        Ok((
            HostedRegistryPublication {
                subject,
                publication,
                path,
                output: args[0],
                disposition_output: if create { args[6] } else { 0 },
                desired: nt_ulong_arg(args[1]),
                bound_target: None,
                root: retained_root,
                relative: (root != 0).then_some(name),
            },
            u64::from_le_bytes(attributes[32..40].try_into().unwrap()),
        ))
    }

    pub(crate) fn abort_hosted_registry_publication(
        &mut self,
        state: &mut HostedRegistryPublication,
    ) {
        if let Some(target) = state
            .publication
            .abort(&mut self.pm)
            .expect("registry PM reservation")
        {
            self.release_registry_key_target(target);
        }
        self.release_hosted_registry_root(state);
        state
            .subject
            .release(&mut self.token_store)
            .expect("registry subject ownership");
    }

    fn release_hosted_registry_root(&mut self, state: &mut HostedRegistryPublication) {
        if let Some((_, mut owner)) = state.root.take() {
            if let Some(target) = owner.abort(&mut self.pm).expect("retained registry root") {
                self.release_registry_key_target(target);
            }
        }
    }

    unsafe fn acquire_hosted_registry_target(
        &mut self,
        state: &HostedRegistryPublication,
    ) -> Result<KeyRef, u32> {
        match &state.root {
            Some((root, _)) => self.acquire_relative_registry_target(
                *root,
                state.relative.as_deref().expect("relative registry name"),
            ),
            None => self.acquire_registry_target(&state.path),
        }
    }

    /// The caller retains a canonical reference to root across the target service exchange.
    pub(crate) unsafe fn acquire_relative_registry_target(
        &mut self,
        root: KeyRef,
        name: &str,
    ) -> Result<KeyRef, u32> {
        if name.starts_with('\\') || name.contains('\0') {
            return Err(0xC000_003B);
        }
        if let Some(target) = self.cm_system_key_target(root) {
            let opened = crate::config_manager_open_relative_system_hive_key(target.lease, name)
                .map_err(|status| status as u32)?;
            return match self.install_cm_system_key_target(CmSystemKeyTarget {
                lease: opened.lease,
                physical_path: nt_hive_core::canon_path(&opened.physical_path),
            }) {
                Ok(target) => Ok(target),
                Err(status) => {
                    let _ = crate::config_manager_retire_system_hive_key(opened.lease);
                    Err(status)
                }
            };
        }
        if let Some(target) = crate::registry_key_targets::runtime(root) {
            let (reply, _) = crate::config_manager_runtime_key_operation(
                target.key,
                nt_config_abi::runtime_key_op::OPEN_RELATIVE,
                0,
                name,
                0,
                &[],
            )
            .map_err(|status| status as u32)?;
            let mut path = target.path;
            if !name.is_empty() {
                path.push('\\');
                path.push_str(name);
            }
            return self
                .install_cm_runtime_key_target(nt_hive_core::canon_path(&path), reply.detail0);
        }
        // Local hive and overlay resolution has no IPC between validation and lookup. Virtual
        // namespace roots cannot be deleted and may cross into a separately owned CM mount.
        self.registry_key_stats(root)?;
        let mut path = self
            .registry_target_path(root)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !name.is_empty() {
            path.push('\\');
            path.push_str(name);
        }
        self.acquire_registry_target(&path)
    }

    fn bind_hosted_registry_target(
        &mut self,
        state: &mut HostedRegistryPublication,
        target: KeyRef,
    ) -> Result<(), u32> {
        if let Some(bound) = state.bound_target {
            return if bound == target {
                Ok(())
            } else {
                Err(STATUS_INVALID_HANDLE)
            };
        }
        if let Err(status) = state.publication.bind(&mut self.pm, target, 0) {
            self.release_registry_key_target(target);
            return Err(status);
        }
        state.bound_target = Some(target);
        Ok(())
    }

    pub(crate) unsafe fn acquire_registry_target(&mut self, path: &str) -> Result<KeyRef, u32> {
        if let Some(target) = Self::virtual_registry_root_target_from_canon(path) {
            return Ok(target);
        }
        if let Some(index) = self.registry_overlay_index_for_canon_path(path) {
            return Ok(OVERLAY_KEY_TAG | index as u32);
        }
        if is_cm_runtime_registry_path(path) {
            let key = crate::config_manager_open_key_id(path).map_err(|status| status as u32)?;
            return self.install_cm_runtime_key_target(path.into(), key);
        }
        if is_system_registry_path(path) {
            let opened =
                crate::config_manager_open_system_hive_key(path).map_err(|status| status as u32)?;
            return match self.install_cm_system_key_target(CmSystemKeyTarget {
                lease: opened.lease,
                physical_path: nt_hive_core::canon_path(&opened.physical_path),
            }) {
                Ok(target) => Ok(target),
                Err(status) => {
                    let _ = crate::config_manager_retire_system_hive_key(opened.lease);
                    Err(status)
                }
            };
        }
        if let Some(key) = self.mutable_registry_key_by_path(path) {
            return self.install_mutable_registry_key_target(key);
        }
        if self.mutable_hive_owns_path(path) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        self.resolve_key(path).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    fn registry_open_grant(
        &self,
        state: &HostedRegistryPublication,
        target: KeyRef,
        backup: bool,
    ) -> Result<u32, u32> {
        if backup {
            let subject = state.subject.resolve(&self.token_store)?;
            let audit = nt_security::authorize_key_backup_restore(&subject, state.subject.mode());
            crate::registry_security_audit::backup(audit);
            return if audit.status == 0 {
                Ok(audit.granted_access)
            } else {
                Err(audit.status)
            };
        }
        let descriptor = self
            .registry_key_security_descriptor(target)?
            .ok_or(0xC000_0079u32)?;
        let subject = state.subject.resolve(&self.token_store)?;
        let access = nt_security::authorize_key_open(
            &subject,
            &descriptor,
            state.desired,
            state.subject.mode(),
        )?;
        crate::registry_security_audit::access(&access);
        if access.status == 0 {
            Ok(access.granted_access)
        } else {
            Err(access.status)
        }
    }

    pub(crate) unsafe fn finish_hosted_registry_publication(
        &mut self,
        state: &mut HostedRegistryPublication,
        target: KeyRef,
        granted: u32,
        created: bool,
    ) -> Result<(), u32> {
        if let Err(status) = self
            .pm
            .validate_native_handle_caller(state.subject.caller())
        {
            if state.bound_target != Some(target) {
                self.release_registry_key_target(target);
            }
            return Err(status);
        }
        self.bind_hosted_registry_target(state, target)?;
        state
            .publication
            .authorize_bound_grant(&mut self.pm, granted)?;
        let disposition = if created {
            REG_CREATED_NEW_KEY
        } else {
            REG_OPENED_EXISTING_KEY
        };
        if state.disposition_output != 0 {
            self.process_memory_write_status(
                self.pi,
                state.disposition_output,
                &disposition.to_le_bytes(),
            )?;
        }
        self.process_memory_write_status(
            self.pi,
            state.output,
            &state.publication.value().to_le_bytes(),
        )?;
        state.publication.publish(&mut self.pm)?;
        self.release_hosted_registry_root(state);
        if target == USER_ROOT_KEY {
            USER_ROOT_OPENED.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(key) = self.mutable_registry_key(target) {
            self.note_mutable_registry_key_open(key, &state.path);
        } else if self.cm_system_key_target(target).is_some() {
            self.note_system_registry_key_open(&state.path);
        } else if self.base_hive(target).is_some() {
            self.note_base_registry_key_open(target, &state.path);
        }
        let class_bit = explorer_shell_com_class_bit_for_path(&state.path);
        if class_bit != 0 {
            EXPLORER_SHELL_COM_CLASS_OPEN_MASK.fetch_or(class_bit, Ordering::Relaxed);
        }
        state
            .subject
            .release(&mut self.token_store)
            .expect("registry subject ownership");
        Ok(())
    }

    pub(super) unsafe fn nt_open_key_admitted(&mut self, args: &[u64]) -> u32 {
        let _durable = allocator::enter_durable();
        let (mut state, _) = match self.capture_hosted_registry_publication(args, false) {
            Ok(state) => state,
            Err(status) => return status,
        };
        let result = (|| {
            let target = self.acquire_hosted_registry_target(&state)?;
            self.bind_hosted_registry_target(&mut state, target)?;
            let granted = match self.registry_open_grant(&state, target, false) {
                Ok(granted) => granted,
                Err(status) => return Err(status),
            };
            self.finish_hosted_registry_publication(&mut state, target, granted, false)
        })();
        match result {
            Ok(()) => 0,
            Err(status) => {
                if status == STATUS_OBJECT_NAME_NOT_FOUND {
                    self.note_registry_open_miss(&state.path);
                }
                self.abort_hosted_registry_publication(&mut state);
                status
            }
        }
    }

    pub(super) unsafe fn nt_create_key_admitted(&mut self, args: &[u64]) -> u32 {
        let _durable = allocator::enter_durable();
        let options = nt_ulong_arg(args[5]);
        if options & !(1 | 4) != 0 {
            return STATUS_NOT_SUPPORTED;
        }
        let backup = options & 4 != 0;
        let volatile = options & 1 != 0;
        let expected_generation =
            crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
        let (mut state, creator_pointer) =
            match self.capture_hosted_registry_publication(args, true) {
                Ok(state) => state,
                Err(status) => return status,
            };
        let mut parent_retention = None;
        let mut durable_create = None;
        let result = (|| {
            match self.acquire_hosted_registry_target(&state) {
                Ok(target) => {
                    self.bind_hosted_registry_target(&mut state, target)?;
                    let granted = match self.registry_open_grant(&state, target, backup) {
                        Ok(granted) => granted,
                        Err(status) => return Err(status),
                    };
                    return self
                        .finish_hosted_registry_publication(&mut state, target, granted, false);
                }
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => {}
                Err(status) => return Err(status),
            }
            let (parent_path, leaf) = state.path.rsplit_once('\\').ok_or(0xC000_003Bu32)?;
            if parent_path.is_empty() || leaf.is_empty() {
                return Err(0xC000_003B);
            }
            let mut parent_owner = self
                .pm
                .reserve_native_registry_key_handle(state.subject.caller(), 0)?;
            let parent_result = match &state.root {
                Some((root, _)) => {
                    let relative = state.relative.as_deref().expect("relative registry name");
                    let relative_parent = relative.rsplit_once('\\').map_or("", |(path, _)| path);
                    self.acquire_relative_registry_target(*root, relative_parent)
                }
                None => self.acquire_registry_target(parent_path),
            };
            let parent = match parent_result {
                Ok(parent) => parent,
                Err(status) => {
                    parent_owner
                        .abort(&mut self.pm)
                        .expect("parent reservation");
                    return Err(status);
                }
            };
            if let Err(status) = parent_owner.bind(&mut self.pm, parent, 0) {
                parent_owner
                    .abort(&mut self.pm)
                    .expect("parent reservation");
                self.release_registry_key_target(parent);
                return Err(status);
            }
            parent_retention = Some(parent_owner);
            let runtime_parent = if is_cm_runtime_registry_path(&state.path) {
                let runtime = self
                    .cm_runtime_key_target(parent)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                Some(
                    crate::config_manager_runtime_key_operation(
                        runtime.key,
                        nt_config_abi::runtime_key_op::SECURITY,
                        0,
                        "",
                        0,
                        &[],
                    )
                    .map(
                        |(reply, descriptor)| nt_config_client::RuntimeKeySecuritySnapshot {
                            key: runtime.key,
                            generation: reply.detail1 as u32,
                            descriptor,
                        },
                    )
                    .map_err(|status| status as u32),
                )
            } else {
                None
            };
            let parent_security = match &runtime_parent {
                Some(Ok(snapshot)) => Ok(Some(snapshot.descriptor.clone())),
                Some(Err(status)) => Err(*status),
                None => self.registry_key_security_descriptor(parent),
            };
            let parent_security = parent_security?.ok_or(0xC000_0079u32)?;
            let creator = if creator_pointer == 0 {
                None
            } else {
                Some(nt_security::capture_security_descriptor_bytes(
                    &ExecClientMemory { handler: self },
                    creator_pointer,
                )?)
            };
            let class = if args[4] == 0 {
                None
            } else {
                Some(self.read_registry_name_checked(args[4])?)
            };
            let prepared = {
                let subject = state.subject.resolve(&self.token_store)?;
                if backup {
                    let mut audit = nt_security::KeyBackupRestoreCreationAudit::default();
                    let result = nt_security::prepare_key_backup_restore_creation_security(
                        &subject,
                        &parent_security,
                        creator.as_deref(),
                        state.subject.mode(),
                        &mut audit,
                    );
                    if let Some(privileges) = audit.privileges {
                        crate::registry_security_audit::backup(privileges);
                    }
                    crate::registry_security_audit::assignment(audit.assignment);
                    result?
                } else {
                    let mut audit = nt_security::KeyCreationAudit::default();
                    let result = nt_security::prepare_key_creation_security(
                        &subject,
                        &parent_security,
                        creator.as_deref(),
                        state.desired,
                        state.subject.mode(),
                        &mut audit,
                    );
                    crate::registry_security_audit::creation(&audit);
                    result?
                }
            };
            if is_cm_runtime_registry_path(&state.path) {
                let parent_snapshot = runtime_parent.expect("runtime parent captured")?;
                let (key, created) = crate::config_manager_create_secured_key_checked_with_class(
                    &state.path,
                    &prepared.descriptor,
                    volatile,
                    parent_snapshot.key,
                    parent_snapshot.generation,
                    class.as_deref(),
                )
                .map_err(|status| status as u32)?;
                // A concurrent creation is an existing-target open, never a parent-create grant.
                let target = self.install_cm_runtime_key_target(state.path.clone(), key)?;
                self.bind_hosted_registry_target(&mut state, target)?;
                let granted = if created {
                    prepared.granted_access
                } else {
                    match self.registry_open_grant(&state, target, backup) {
                        Ok(granted) => granted,
                        Err(status) => return Err(status),
                    }
                };
                return self
                    .finish_hosted_registry_publication(&mut state, target, granted, created);
            }
            if is_system_registry_path(&state.path) {
                let parent_lease = self.cm_system_key_target(parent)
                    .ok_or(STATUS_INVALID_HANDLE)?.lease;
                durable_create = Some((parent, parent_lease, alloc::string::String::from(leaf), class, prepared));
                return Ok(());
            }
            let (target, created) = self.create_secured_registry_child(
                parent,
                &state.path,
                &prepared.descriptor,
                class.as_deref(),
                volatile,
            )?;
            self.bind_hosted_registry_target(&mut state, target)?;
            let granted = if created {
                prepared.granted_access
            } else {
                self.registry_open_grant(&state, target, backup)?
            };
            self.finish_hosted_registry_publication(&mut state, target, granted, created)
        })();
        if let Some((parent, lease, leaf, class, prepared)) = durable_create {
            let owner = parent_retention.take().expect("SYSTEM create parent reservation");
            let mutation = nt_config_client::SystemHiveMutation::CreateChildRelative {
                parent: lease,
                name: &leaf,
                class_name: class.as_deref(),
                descriptor: &prepared.descriptor,
                volatile,
            };
            match crate::registry_mutation_work::submit_hosted(
                self, state, owner, parent, leaf.clone(), prepared.granted_access,
                expected_generation, mutation,
            ) {
                Ok(()) => return 0x103,
                Err((status, mut state, mut owner)) => {
                    if let Some(target) = owner.abort(&mut self.pm).expect("unsubmitted parent") {
                        self.release_registry_key_target(target);
                    }
                    self.abort_hosted_registry_publication(&mut state);
                    return status;
                }
            }
        }
        if let Some(mut parent_owner) = parent_retention {
            if let Some(target) = parent_owner
                .abort(&mut self.pm)
                .expect("retained parent reservation")
            {
                self.release_registry_key_target(target);
            }
        }
        match result {
            Ok(()) => 0,
            Err(status) => {
                self.abort_hosted_registry_publication(&mut state);
                status
            }
        }
    }

    /// CM-backed parents use their generation-checked broker; this is the exact hosted-Key path.
    /// The caller retains an invisible/visible PM reference to `parent` across this operation.
    pub(crate) fn create_secured_registry_child(
        &mut self,
        parent: KeyRef,
        path: &str,
        descriptor: &[u8],
        class: Option<&str>,
        volatile: bool,
    ) -> Result<(KeyRef, bool), u32> {
        let (parent_path, name) = path.rsplit_once('\\').ok_or(STATUS_OBJECT_NAME_INVALID)?;
        if name.is_empty() || self.registry_target_path(parent).as_deref() != Some(parent_path) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if self.cm_runtime_key_target(parent).is_some()
            || self.cm_system_key_target(parent).is_some()
        {
            return Err(STATUS_NOT_SUPPORTED);
        }
        if let Some(index) = self.registry_overlay_index_for_canon_path(path) {
            return Ok((OVERLAY_KEY_TAG | index as u32, false));
        }
        if let Some(mutable) = self.mutable_key_handle(parent) {
            if let Some(key) = self
                .mutable_hives
                .hive(mutable.hive)
                .and_then(|hive| hive.open_subkey(mutable.key, name))
            {
                return self
                    .install_mutable_registry_key_target(ResolvedHiveKey {
                        hive: mutable.hive,
                        key,
                    })
                    .map(|target| (target, false));
            }
            if !volatile {
                let key =
                    self.journal_create_secured_mutable_subkey(mutable, name, class, descriptor)?;
                return self
                    .install_mutable_registry_key_target(key)
                    .map(|target| (target, true));
            }
        } else if !volatile && overlay_key_idx(parent).is_none() {
            return Err(0xC000_00A2);
        }
        if self.overlay.len() >= OVERLAY_KEY_MAX as usize {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let index = self.overlay.create_secured_owned(
            path.into(),
            volatile,
            class.map(Into::into),
            descriptor.to_vec(),
        )?;
        Ok((OVERLAY_KEY_TAG | index as u32, true))
    }

    fn journal_create_secured_mutable_subkey(
        &mut self,
        parent: ResolvedHiveKey,
        name: &str,
        class: Option<&str>,
        descriptor: &[u8],
    ) -> Result<ResolvedHiveKey, u32> {
        let parent_path = self
            .mutable_key_relative_path(parent)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let checkpoint = self
            .mutable_hive_checkpoint_path_owned(parent.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let key = {
            let hive = self
                .mutable_hives
                .hive_mut(parent.hive)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let provider = crate::writable_fs::WritableHiveIoProvider::new(&checkpoint);
            let mut manager = nt_hive_core::HiveManager::for_live_hive(provider, hive);
            manager
                .mutate_with_live_apply(
                    hive,
                    nt_hive_core::HiveLogOp::CreateChild {
                        parent: &parent_path,
                        name,
                        class_name: class,
                        descriptor,
                    },
                    |hive| {
                        let mut transaction = hive.begin_transaction();
                        if transaction
                            .try_create_child(
                                parent.key,
                                name.into(),
                                class.map(Into::into),
                                descriptor.to_vec(),
                            )
                            .is_err()
                        {
                            return false;
                        }
                        transaction.commit();
                        true
                    },
                )
                .map_err(Self::mutable_hive_journal_status)?;
            hive.open_subkey(parent.key, name)
                .ok_or(STATUS_INVALID_HANDLE)?
        };
        self.note_mutable_hive_journal_record(parent.hive);
        Ok(ResolvedHiveKey {
            hive: parent.hive,
            key,
        })
    }
}
