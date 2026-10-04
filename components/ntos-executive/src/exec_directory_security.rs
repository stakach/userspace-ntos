//! Captured directory admission and exact namespace security ownership.

use super::*;

pub(crate) struct DirectorySecurityRecord {
    identity: u64,
    descriptor: Vec<u8>,
    references: u32,
}

impl DirectorySecurityRecord {
    pub(super) fn identity(&self) -> u64 {
        self.identity
    }
}

pub(crate) struct DirectorySecurityAdmission {
    subject: nt_user_host::native_caller_subject::NativeCallerSubject,
    parent: usize,
    parent_identity: u64,
    leaf: Vec<u8>,
    references: Vec<(usize, u64)>,
    existing: Option<(usize, u64)>,
    descriptor: Option<Vec<u8>>,
    pub(super) handle_attributes: u32,
    pub(super) granted_access: u32,
    pub(super) opened_existing: bool,
    permanent: bool,
    released: bool,
}

impl DirectorySecurityAdmission {
    pub(super) fn caller(&self) -> nt_process::native_handle::NativeHandleCaller {
        self.subject.caller()
    }
}

static ACCESS_CHECKS: AtomicU64 = AtomicU64::new(0);
static ACCESS_DENIALS: AtomicU64 = AtomicU64::new(0);
static PRIVILEGES_USED: AtomicU64 = AtomicU64::new(0);
static PRIVILEGE_DENIALS: AtomicU64 = AtomicU64::new(0);

fn access_audit(result: &nt_security::AccessCheckResult) {
    ACCESS_CHECKS.fetch_add(1, Ordering::Relaxed);
    ACCESS_DENIALS.fetch_add(u64::from(result.status != 0), Ordering::Relaxed);
    PRIVILEGES_USED.fetch_add(result.privileges_used.len() as u64, Ordering::Relaxed);
}

fn privilege(
    subject: &nt_security::CapturedSubjectTokens<'_>,
    mode: nt_security::ProcessorMode,
    luid: u32,
) -> bool {
    let mut required = [nt_security::PrivilegeAdjustment {
        luid: nt_security::Luid::new(luid),
        attributes: 0,
    }];
    let granted = subject.check_privileges(&mut required, true, mode);
    PRIVILEGES_USED.fetch_add(
        u64::from(required[0].attributes & nt_security::SE_PRIVILEGE_USED_FOR_ACCESS != 0),
        Ordering::Relaxed,
    );
    PRIVILEGE_DENIALS.fetch_add(u64::from(!granted), Ordering::Relaxed);
    granted
}

fn assignment_audit(audit: nt_security::SecurityAssignmentAudit) {
    for decision in [audit.security, audit.restore].into_iter().flatten() {
        let granted = decision == nt_security::SecurityAssignmentPrivilegeOutcome::Granted;
        PRIVILEGES_USED.fetch_add(u64::from(granted), Ordering::Relaxed);
        PRIVILEGE_DENIALS.fetch_add(u64::from(!granted), Ordering::Relaxed);
    }
}

pub(super) fn capture_boot_protection_mode(bytes: &[u8]) -> Result<u32, u32> {
    let hive = RegfHive::new(bytes).ok_or(0xC000_014Cu32)?;
    let control_set = hive
        .current_control_set_name()
        .map_err(|_| 0xC000_014Cu32)?;
    let path = alloc::format!("{}\\Control\\Session Manager", control_set);
    let Some(key) = hive.open_key(&path) else {
        return Ok(0);
    };
    // ObpProtectionMode starts at zero; only a genuinely absent value uses that NT default.
    match hive.value_with(key, "ProtectionMode", |kind, bytes| {
        if kind != 4 || bytes.len() != 4 {
            Err(0xC000_0024)
        } else {
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
        }
    }) {
        Some(value) => value,
        None if !hive.value_exists(key, "ProtectionMode") => Ok(0),
        None => Err(0xC000_014C),
    }
}

pub(super) fn prepare_boot_directory_security(
    pm: &nt_process::ProcessManager,
    tokens: &mut nt_security::TokenStore,
    namespace: &[ObjEntry],
    protection_mode: u32,
) -> Result<Vec<DirectorySecurityRecord>, u32> {
    let _durable = allocator::enter_durable();
    let identity = pm.initial_system_identity().ok_or(0xC000_0008u32)?;
    if !pm.validate_initial_system_caller(identity) {
        return Err(0xC000_0008);
    }
    let primary = pm
        .process_primary_token(identity.process_id())
        .ok_or(0xC000_007Cu32)?;
    let client = pm
        .thread_impersonation(identity.thread_id())
        .map(|context| nt_security::SubjectClientIdentity {
            token: context.token,
            level: context.level,
        });
    let mut captured = nt_security::CapturedSubjectContext::capture(
        tokens,
        primary,
        client,
        u64::from(identity.process_id()),
    )?;
    let result = (|| {
        let subject = captured.resolve(tokens)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(namespace.len())
            .map_err(|_| 0xC000_009Au32)?;
        for entry in namespace
            .iter()
            .filter(|entry| entry.kind == OBJ_KIND_DIRECTORY)
        {
            let mut audit = nt_security::SecurityAssignmentAudit::default();
            let assigned = if entry.parent == OBJ_PARENT_ROOT || entry.name() == b"device" {
                nt_security::assign_object_directory_root_security(&subject, &mut audit)
            } else if matches!(entry.name(), b"??" | b"global??") {
                nt_security::assign_dos_devices_directory_security(
                    &subject,
                    protection_mode,
                    &mut audit,
                )
            } else if entry.name() == b"security" {
                nt_security::assign_security_directory_security(&subject, &mut audit)
            } else if matches!(entry.name(), b"objecttypes" | b"driver" | b"filesystem") {
                nt_security::assign_directory_security(
                    &subject,
                    None,
                    None,
                    nt_security::ProcessorMode::KernelMode,
                    &mut audit,
                )
            } else {
                return Err(0xC000_00BB);
            };
            assignment_audit(audit);
            records.push(DirectorySecurityRecord {
                identity: entry.identity,
                descriptor: assigned?,
                references: 0,
            });
        }
        Ok(records)
    })();
    captured.release(tokens)?;
    result
}

impl ExecNtHandler {
    pub(super) fn capture_named_creator_security_descriptor(
        &mut self,
        address: u64,
    ) -> Result<Vec<u8>, u32> {
        let _durable = allocator::enter_durable();
        struct Memory<'a> {
            handler: core::cell::RefCell<&'a mut ExecNtHandler>,
            fault: core::cell::Cell<Option<u32>>,
        }
        impl nt_security::ClientMemory for Memory<'_> {
            fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
                if self.fault.get().is_some() {
                    return false;
                }
                let mut handler = self.handler.borrow_mut();
                let pi = handler.pi;
                match unsafe { handler.process_memory_read_status(pi, address, bytes) } {
                    Ok(()) => true,
                    Err(status) => {
                        self.fault.set(Some(status));
                        false
                    }
                }
            }
        }
        let memory = Memory {
            handler: core::cell::RefCell::new(self),
            fault: core::cell::Cell::new(None),
        };
        let result = nt_security::capture_security_descriptor_bytes(&memory, address);
        match memory.fault.get() {
            Some(status) => Err(status),
            None => result,
        }
    }

    fn directory_security_descriptor(&self, index: usize) -> Result<&[u8], u32> {
        let entry = self.obj_ns.get(index).ok_or(0xC000_0008u32)?;
        if !entry.is_live() || entry.kind != OBJ_KIND_DIRECTORY {
            return Err(0xC000_0024);
        }
        self.directory_security
            .iter()
            .find(|record| record.identity == entry.identity)
            .map(|record| record.descriptor.as_slice())
            .ok_or(0xC000_0022)
    }

    pub(super) fn prepare_directory_object_security(
        &mut self,
        captured: &CapturedNamedObjectAttributes,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<DirectorySecurityAdmission, u32> {
        let _durable = allocator::enter_durable();
        let attributes = nt_object_manager::directory::admit_directory_object_attributes(
            captured.attributes,
            caller.mode(),
        )
        .map_err(|status| status.0 as u32)?;
        let handle_attributes = attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2);
        let mut subject = nt_user_host::native_caller_subject::NativeCallerSubject::capture(
            &self.pm,
            &mut self.token_store,
            caller,
        )?;
        let result = (|| {
            let creator = if captured.security_descriptor != 0 {
                Some(self.capture_named_creator_security_descriptor(captured.security_descriptor)?)
            } else {
                None
            };
            let tokens = subject.resolve(&self.token_store)?;
            let mode = subject.mode();
            let access_mode = if captured.attributes & 0x400 != 0 {
                nt_security::ProcessorMode::UserMode
            } else {
                mode
            };
            let permanent = captured.attributes & OBJ_PERMANENT != 0;
            if create && permanent && !privilege(&tokens, mode, 16) {
                return Err(0xC000_0061);
            }
            let traverse_bypass = privilege(&tokens, access_mode, 23); // SeChangeNotifyPrivilege
            let path = captured.path().ok_or(0xC000_0033u32)?;
            let (root, path) = self.native_directory_root_and_path(caller, captured.root, path)?;
            let (parent_path, leaf) = match path.iter().rposition(|&byte| byte == b'\\') {
                Some(position) => (&path[..position], &path[position + 1..]),
                None => (&[][..], path),
            };
            let check = |index| {
                let descriptor = self.directory_security_descriptor(index)?;
                if traverse_bypass {
                    return Ok(());
                }
                let result = nt_security::authorize_directory_open(
                    &tokens,
                    descriptor,
                    DIRECTORY_TRAVERSE_ACCESS,
                    access_mode,
                )?;
                access_audit(&result);
                if result.status != 0 {
                    Err(result.status)
                } else {
                    Ok(())
                }
            };
            let parent = if parent_path.iter().all(|&byte| byte == b'\\') {
                if path.first() == Some(&b'\\') {
                    0
                } else {
                    root
                }
            } else {
                self.obj_resolve_authorized(parent_path, root, true, check)?
                    .ok_or(0xC000_003Au32)?
            };
            check(parent)?;
            let parent_descriptor = self.directory_security_descriptor(parent)?;
            let existing = self.obj_resolve_authorized(path, root, true, check)?;
            let (descriptor, granted_access, opened_existing) = if let Some(index) = existing {
                if create && captured.attributes & 0x80 == 0 {
                    return Err(0xC000_0035);
                }
                let descriptor = self.directory_security_descriptor(index)?;
                let result = nt_security::authorize_directory_open(
                    &tokens,
                    descriptor,
                    desired_access,
                    access_mode,
                )?;
                access_audit(&result);
                if result.status != 0 {
                    return Err(result.status);
                }
                (
                    None,
                    result.granted_access
                        & (nt_security::DIRECTORY_GENERIC_MAPPING.generic_all
                            | nt_security::ACCESS_SYSTEM_SECURITY),
                    create,
                )
            } else {
                if !create {
                    return Err(0xC000_0034);
                }
                let result = nt_security::authorize_directory_open(
                    &tokens,
                    parent_descriptor,
                    DIRECTORY_CREATE_SUBDIRECTORY_ACCESS,
                    access_mode,
                )?;
                access_audit(&result);
                if result.status != 0 {
                    return Err(result.status);
                }
                let mut audit = nt_security::SecurityAssignmentAudit::default();
                let assigned = nt_security::assign_directory_security(
                    &tokens,
                    creator.as_deref(),
                    Some(parent_descriptor),
                    mode,
                    &mut audit,
                );
                assignment_audit(audit);
                let descriptor = assigned?;
                let granted = nt_security::DIRECTORY_GENERIC_MAPPING.map(
                    (desired_access & !0x0200_0000)
                        | if desired_access & 0x0200_0000 != 0 {
                            0x1000_0000
                        } else {
                            0
                        },
                ) & (nt_security::DIRECTORY_GENERIC_MAPPING.generic_all
                    | nt_security::ACCESS_SYSTEM_SECURITY);
                if granted & nt_security::ACCESS_SYSTEM_SECURITY != 0
                    && !privilege(&tokens, mode, 8)
                {
                    return Err(0xC000_0061);
                }
                (Some(descriptor), granted, false)
            };
            let mut owned_leaf = Vec::new();
            owned_leaf
                .try_reserve_exact(leaf.len())
                .map_err(|_| 0xC000_009Au32)?;
            owned_leaf.extend_from_slice(leaf);
            let mut references = Vec::new();
            references
                .try_reserve_exact(3)
                .map_err(|_| 0xC000_009Au32)?;
            for index in [Some(root), Some(parent), existing].into_iter().flatten() {
                if references.iter().any(|&(owned, _)| owned == index) {
                    continue;
                }
                let identity = self.obj_ns[index].identity;
                let record = self
                    .directory_security
                    .iter()
                    .find(|record| record.identity == identity)
                    .ok_or(0xC000_0022u32)?;
                record.references.checked_add(1).ok_or(0xC000_009Au32)?;
                references.push((index, identity));
            }
            if descriptor.is_some() {
                self.directory_security
                    .try_reserve(1)
                    .map_err(|_| 0xC000_009Au32)?;
                self.obj_ns.try_reserve(1).map_err(|_| 0xC000_009Au32)?;
            }
            Ok((
                parent,
                self.obj_ns[parent].identity,
                owned_leaf,
                references,
                existing.map(|index| (index, self.obj_ns[index].identity)),
                descriptor,
                granted_access,
                opened_existing,
                permanent,
            ))
        })();
        match result {
            Ok((
                parent,
                parent_identity,
                leaf,
                references,
                existing,
                descriptor,
                granted_access,
                opened_existing,
                permanent,
            )) => {
                for &(_, identity) in &references {
                    self.directory_security
                        .iter_mut()
                        .find(|record| record.identity == identity)
                        .expect("prevalidated directory body reference")
                        .references += 1;
                }
                Ok(DirectorySecurityAdmission {
                    handle_attributes,
                    subject,
                    parent,
                    parent_identity,
                    leaf,
                    references,
                    existing,
                    descriptor,
                    granted_access,
                    opened_existing,
                    permanent,
                    released: false,
                })
            }
            Err(status) => {
                subject
                    .release(&mut self.token_store)
                    .expect("directory admission retains exact subject until release");
                Err(status)
            }
        }
    }

    pub(super) fn commit_directory_object_security(
        &mut self,
        admission: &mut DirectorySecurityAdmission,
    ) -> Result<(usize, bool), u32> {
        let _durable = allocator::enter_durable();
        if admission.released {
            return Err(0xC000_0008);
        }
        self.pm
            .validate_native_handle_caller(admission.subject.caller())?;
        let parent = self.obj_ns.get(admission.parent).ok_or(0xC000_0008u32)?;
        if !parent.is_live()
            || parent.kind != OBJ_KIND_DIRECTORY
            || parent.identity != admission.parent_identity
        {
            return Err(0xC000_0008);
        }
        let current = if admission.leaf.is_empty() {
            Some(admission.parent)
        } else {
            self.obj_child(admission.parent, &admission.leaf)
        };
        if let Some((index, identity)) = admission.existing {
            if !self.obj_ns[index].is_live()
                || self.obj_ns[index].kind != OBJ_KIND_DIRECTORY
                || self.obj_ns[index].identity != identity
            {
                return Err(0xC000_0008);
            }
            self.directory_security_descriptor(index)?;
            return Ok((index, false));
        }
        if current.is_some() {
            return Err(0xC000_0035);
        }
        self.directory_security
            .try_reserve(1)
            .map_err(|_| 0xC000_009Au32)?;
        self.obj_ns.try_reserve(1).map_err(|_| 0xC000_009Au32)?;
        let descriptor = admission.descriptor.take().ok_or(0xC000_0008u32)?;
        let Some(index) = self.obj_insert(
            admission.parent,
            &admission.leaf,
            OBJ_KIND_DIRECTORY,
            &[],
            admission.permanent,
        ) else {
            admission.descriptor = Some(descriptor);
            return Err(0xC000_009A);
        };
        self.directory_security.push(DirectorySecurityRecord {
            identity: self.obj_ns[index].identity,
            descriptor,
            references: 0,
        });
        Ok((index, true))
    }

    pub(super) fn release_directory_object_security(
        &mut self,
        admission: &mut DirectorySecurityAdmission,
    ) {
        if !admission.released {
            admission
                .subject
                .release(&mut self.token_store)
                .expect("directory terminal owns exact captured token references");
            admission.released = true;
            for &(index, identity) in &admission.references {
                let record = self
                    .directory_security
                    .iter_mut()
                    .find(|record| record.identity == identity)
                    .expect("retained exact directory body and descriptor");
                record.references = record
                    .references
                    .checked_sub(1)
                    .expect("one directory admission reference release");
                self.release_directory_namespace_reference(identity);
                self.retire_directory_security_body(index, identity);
            }
        }
    }

    pub(super) fn retire_directory_security_body(&mut self, index: usize, identity: u64) {
        let Some(entry) = self.obj_ns.get(index) else {
            return;
        };
        if entry.identity != identity || entry.kind != OBJ_KIND_DIRECTORY || entry.permanent
            || entry.parent != OBJ_PARENT_ANONYMOUS || entry.wait_references != 0
            // Live child names own their containing directory in the append-only namespace.
            || self.obj_ns.iter().any(|child| child.is_live() && child.parent == index)
            || self.pm.handle_object_count(nt_process::HandleObject::ObjectDirectory(identity)) != 0
        {
            return;
        }
        let Some(record) = self
            .directory_security
            .iter()
            .find(|record| record.identity == identity)
        else {
            return;
        };
        if record.references != 0 {
            return;
        }
        self.directory_security
            .retain(|record| record.identity != identity);
        self.obj_ns[index].unlink();
    }

    pub(crate) fn sweep_directory_security_bodies(&mut self) {
        // Other backing owners can withdraw child names without entering Directory services.
        // The serialized loop converges only proved detached bodies, never uncertain admissions.
        for _ in 0..self.obj_ns.len() {
            let before = self.directory_security.len();
            for index in 0..self.obj_ns.len() {
                let identity = self.obj_ns[index].identity;
                self.retire_directory_security_body(index, identity);
            }
            if before == self.directory_security.len() {
                break;
            }
        }
    }

    pub(super) fn unlink_directory_security_name(&mut self, index: usize) {
        let identity = self.obj_ns[index].identity;
        let parent = self.obj_ns[index].parent;
        let parent_identity = self.obj_ns.get(parent).map(|entry| entry.identity);
        self.obj_ns[index].name = [0; OBJ_NAME_CAP];
        self.obj_ns[index].name_len = 0;
        self.obj_ns[index].parent = OBJ_PARENT_ANONYMOUS;
        self.retire_directory_security_body(index, identity);
        if let Some(identity) = parent_identity {
            self.retire_directory_security_body(parent, identity)
        }
    }
}
