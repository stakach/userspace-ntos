//! Captured DATA Section admission, namespace leases, and checked handle publication.

use super::*;
use nt_memory_manager::{SectionIdentity, SectionReference};

pub(crate) struct DataSectionSecurity {
    identity: SectionIdentity,
    descriptor: Vec<u8>,
}

pub(crate) struct DataSectionName {
    object_identity: u64,
    section: SectionIdentity,
    reference: SectionReference,
}

pub(crate) struct DataSectionAdmission {
    subject: nt_user_host::native_caller_subject::NativeCallerSubject,
    references: Vec<(usize, u64)>,
    parent: Option<(usize, u64)>,
    leaf: Vec<u8>,
    existing: Option<SectionReference>,
    descriptor: Option<Vec<u8>>,
    pub(crate) granted_access: u32,
    pub(crate) handle_attributes: u32,
    pub(crate) status: u32,
    requested_access: u32,
    access_mode: nt_security::ProcessorMode,
    open_if: bool,
    permanent: bool,
    released: bool,
}

impl DataSectionAdmission {
    pub(crate) fn existing(&self) -> Option<SectionReference> {
        self.existing
    }
    pub(crate) fn caller(&self) -> nt_process::native_handle::NativeHandleCaller {
        self.subject.caller()
    }
}

static SECTION_PRIVILEGES_USED: AtomicU64 = AtomicU64::new(0);
static SECTION_PRIVILEGE_DENIALS: AtomicU64 = AtomicU64::new(0);
static SECTION_ACCESS_CHECKS: AtomicU64 = AtomicU64::new(0);
static SECTION_ACCESS_DENIALS: AtomicU64 = AtomicU64::new(0);

fn record_access(result: &nt_security::AccessCheckResult) {
    SECTION_ACCESS_CHECKS.fetch_add(1, Ordering::Relaxed);
    SECTION_ACCESS_DENIALS.fetch_add(u64::from(result.status != 0), Ordering::Relaxed);
    SECTION_PRIVILEGES_USED.fetch_add(result.privileges_used.len() as u64, Ordering::Relaxed);
}

impl ExecNtHandler {
    pub(crate) unsafe fn create_admitted_data_section(
        &mut self,
        caller: nt_process::native_handle::NativeHandleCaller,
        output: u64,
        maxsize: u64,
        page_protection: u32,
        allocation_attrs: u32,
        file_handle: u64,
        admission: DataSectionAdmission,
    ) -> u32 {
        let _durable = allocator::enter_durable();
        let desired_access = admission.granted_access;
        let attributes = admission.handle_attributes;
        let mut admission = Some(admission);
        let mut reserved = None;
        let result = (|| {
            if admission.as_ref().unwrap().existing().is_none() {
                if file_handle != 0 {
                    let source = self
                        .pm
                        .lookup_native_section_file_source(caller, file_handle)?;
                    if matches!(source.object(), nt_process::HandleObject::RoutedFile { .. }) {
                        return crate::section_metadata_work::submit_hosted_data(
                            self,
                            caller,
                            source,
                            output,
                            desired_access,
                            attributes,
                            maxsize,
                            page_protection,
                            allocation_attrs,
                            file_handle,
                            &mut admission,
                        );
                    }
                }
                reserved = Some(self.reserve_generic_data_section(
                    caller,
                    self.pi,
                    desired_access,
                    attributes,
                    maxsize,
                    page_protection,
                    allocation_attrs,
                    file_handle,
                    None,
                )?);
            }
            crate::section_metadata_work::submit_local_data(
                self,
                caller,
                output,
                file_handle,
                &mut reserved,
                &mut admission,
            )
        })();
        match result {
            Ok(()) => 0x0000_0103,
            Err(status) => {
                if let Some(mut section) = reserved {
                    section.abort(self);
                }
                self.release_data_section_admission(
                    admission
                        .as_mut()
                        .expect("failed Section submission retains admission"),
                );
                status
            }
        }
    }

    pub(super) fn prepare_data_section_name(
        &mut self,
        captured: &CapturedNamedObjectAttributes,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<DataSectionAdmission, u32> {
        let _durable = allocator::enter_durable();
        let attributes = nt_object_manager::directory::admit_named_object_attributes(
            captured.attributes,
            caller.mode(),
            0x100,
        )
        .map_err(|status| status.0 as u32)?;
        let mut subject = nt_user_host::native_caller_subject::NativeCallerSubject::capture(
            &self.pm,
            &mut self.token_store,
            caller,
        )?;
        let result = (|| {
            // Capture even for Open/OPENIF; existing-object authorization never uses this SD.
            let creator = if captured.security_descriptor != 0 {
                Some(self.capture_named_creator_security_descriptor(captured.security_descriptor)?)
            } else {
                None
            };
            let desired_access = desired_access
                | if creator.as_ref().is_some_and(|bytes| {
                    bytes.get(2..4).is_some_and(|control| {
                        u16::from_le_bytes([control[0], control[1]]) & 0x10 != 0
                    })
                }) {
                    nt_security::ACCESS_SYSTEM_SECURITY
                } else {
                    0
                };
            let tokens = subject.resolve(&self.token_store)?;
            let mode = subject.mode();
            let access_mode = if attributes & 0x400 != 0 {
                nt_security::ProcessorMode::UserMode
            } else {
                mode
            };
            let permanent = attributes & OBJ_PERMANENT != 0;
            if create && permanent {
                let mut required = [nt_security::PrivilegeAdjustment {
                    luid: nt_security::Luid::new(16),
                    attributes: 0,
                }];
                let granted = tokens.check_privileges(&mut required, true, mode);
                SECTION_PRIVILEGES_USED.fetch_add(
                    u64::from(
                        required[0].attributes & nt_security::SE_PRIVILEGE_USED_FOR_ACCESS != 0,
                    ),
                    Ordering::Relaxed,
                );
                SECTION_PRIVILEGE_DENIALS.fetch_add(u64::from(!granted), Ordering::Relaxed);
                if !granted {
                    return Err(0xC000_0061);
                }
            }
            let mut parent = None;
            let mut root = None;
            let mut existing_index = None;
            let mut leaf = Vec::new();
            if let Some(path) = captured.path() {
                let (root_index, path) =
                    self.native_directory_root_and_path(caller, captured.root, path)?;
                root = Some(root_index);
                let mut required = [nt_security::PrivilegeAdjustment {
                    luid: nt_security::Luid::new(23),
                    attributes: 0,
                }];
                let bypass = tokens.check_privileges(&mut required, true, access_mode);
                SECTION_PRIVILEGES_USED.fetch_add(
                    u64::from(
                        required[0].attributes & nt_security::SE_PRIVILEGE_USED_FOR_ACCESS != 0,
                    ),
                    Ordering::Relaxed,
                );
                SECTION_PRIVILEGE_DENIALS.fetch_add(u64::from(!bypass), Ordering::Relaxed);
                let check = |index| {
                    let descriptor = self.directory_security_descriptor(index)?;
                    if bypass {
                        return Ok(());
                    }
                    let result = nt_security::authorize_directory_open(
                        &tokens,
                        descriptor,
                        DIRECTORY_TRAVERSE_ACCESS,
                        access_mode,
                    )?;
                    record_access(&result);
                    if result.status == 0 {
                        Ok(())
                    } else {
                        Err(result.status)
                    }
                };
                let (parent_path, name) = match path.iter().rposition(|&byte| byte == b'\\') {
                    Some(position) => (&path[..position], &path[position + 1..]),
                    None => (&[][..], path),
                };
                let parent_index = if parent_path.iter().all(|&byte| byte == b'\\') {
                    if path.first() == Some(&b'\\') {
                        0
                    } else {
                        root_index
                    }
                } else {
                    self.obj_resolve_authorized(parent_path, root_index, true, check)?
                        .ok_or(0xC000_003Au32)?
                };
                check(parent_index)?;
                parent = Some((parent_index, self.obj_ns[parent_index].identity));
                existing_index = self.obj_resolve_authorized(path, root_index, true, check)?;
                leaf.try_reserve_exact(name.len())
                    .map_err(|_| 0xC000_009Au32)?;
                leaf.extend_from_slice(name);
            } else if !create {
                return Err(0xC000_0033);
            }
            let mut existing = None;
            let (descriptor, granted_access, status) = if let Some(index) = existing_index {
                if create && attributes & 0x80 == 0 {
                    return Err(0xC000_0035);
                }
                let entry = &self.obj_ns[index];
                if entry.kind != OBJ_KIND_SECTION {
                    return Err(0xC000_0024);
                }
                let name = self
                    .data_section_names
                    .iter()
                    .find(|name| name.object_identity == entry.identity)
                    .ok_or(0xC000_0024u32)?;
                let section = name.section;
                let descriptor = self
                    .data_section_security
                    .iter()
                    .find(|record| record.identity == section)
                    .ok_or(0xC000_0022u32)?;
                let access = nt_security::authorize_section_open(
                    &tokens,
                    &descriptor.descriptor,
                    desired_access,
                    access_mode,
                )?;
                record_access(&access);
                if access.status != 0 {
                    return Err(access.status);
                }
                let table = unsafe { &mut *self.loop_ctx.ok_or(0xC000_00A3u32)?.generic_sections };
                if table.section_identity(section.index()) != Some(section) {
                    return Err(0xC000_0008);
                }
                existing = Some(
                    table
                        .retain_section_reference(name.reference)
                        .ok_or(0xC000_009Au32)?,
                );
                (
                    None,
                    access.granted_access
                        & (nt_security::SECTION_GENERIC_MAPPING.generic_all
                            | nt_security::ACCESS_SYSTEM_SECURITY),
                    if create { 0x4000_0000 } else { 0 },
                )
            } else {
                if !create {
                    return Err(0xC000_0034);
                }
                let parent_descriptor = match parent {
                    Some((index, _)) => {
                        let descriptor = self.directory_security_descriptor(index)?;
                        let access = nt_security::authorize_directory_open(
                            &tokens,
                            descriptor,
                            DIRECTORY_CREATE_OBJECT_ACCESS,
                            access_mode,
                        )?;
                        record_access(&access);
                        if access.status != 0 {
                            return Err(access.status);
                        }
                        Some(descriptor)
                    }
                    None => None,
                };
                let mut audit = nt_security::SecurityAssignmentAudit::default();
                let assigned = nt_security::assign_section_security(
                    &tokens,
                    creator.as_deref(),
                    parent_descriptor,
                    mode,
                    &mut audit,
                );
                for decision in [audit.security, audit.restore].into_iter().flatten() {
                    let granted =
                        decision == nt_security::SecurityAssignmentPrivilegeOutcome::Granted;
                    SECTION_PRIVILEGES_USED.fetch_add(u64::from(granted), Ordering::Relaxed);
                    SECTION_PRIVILEGE_DENIALS.fetch_add(u64::from(!granted), Ordering::Relaxed);
                }
                let descriptor = assigned?;
                let mut audit = None;
                let grant = nt_security::prepare_object_creation_grant(
                    &tokens,
                    desired_access,
                    &nt_security::SECTION_GENERIC_MAPPING,
                    mode,
                    &mut audit,
                );
                if let Some(audit) = audit {
                    SECTION_PRIVILEGES_USED.fetch_add(
                        u64::from(
                            audit.attributes & nt_security::SE_PRIVILEGE_USED_FOR_ACCESS != 0,
                        ),
                        Ordering::Relaxed,
                    );
                    SECTION_PRIVILEGE_DENIALS
                        .fetch_add(u64::from(!audit.granted), Ordering::Relaxed);
                }
                (Some(descriptor), grant?, 0)
            };
            // All fallible preparation precedes either retained Section or Directory pin transfer.
            let references = match self.prepare_namespace_directory_references([
                root,
                parent.map(|value| value.0),
                None,
            ]) {
                Ok(references) => references,
                Err(status) => {
                    if let Some(reference) = existing {
                        assert!(unsafe {
                            (&mut *self.loop_ctx.unwrap().generic_sections)
                                .release_section_reference(reference)
                        });
                    }
                    return Err(status);
                }
            };
            if descriptor.is_some() {
                if self.data_section_security.try_reserve(1).is_err()
                    || (parent.is_some()
                        && (self.data_section_names.try_reserve(1).is_err()
                            || self.obj_ns.try_reserve(1).is_err()))
                {
                    return Err(0xC000_009A);
                }
            }
            Ok((
                references,
                parent,
                leaf,
                existing,
                descriptor,
                granted_access,
                status,
                permanent,
                desired_access,
                access_mode,
            ))
        })();
        match result {
            Ok((
                references,
                parent,
                leaf,
                existing,
                descriptor,
                granted_access,
                status,
                permanent,
                requested_access,
                access_mode,
            )) => {
                self.retain_namespace_directory_references(&references);
                Ok(DataSectionAdmission {
                    subject,
                    references,
                    parent,
                    leaf,
                    existing,
                    descriptor,
                    granted_access,
                    handle_attributes: attributes
                        & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2),
                    status,
                    requested_access,
                    access_mode,
                    open_if: attributes & 0x80 != 0,
                    permanent,
                    released: false,
                })
            }
            Err(status) => {
                subject
                    .release(&mut self.token_store)
                    .expect("failed Section admission releases exact subject");
                Err(status)
            }
        }
    }

    pub(crate) fn reconcile_data_section_name(
        &mut self,
        admission: &mut DataSectionAdmission,
    ) -> Result<(), u32> {
        let _durable = allocator::enter_durable();
        if admission.released {
            return Err(0xC000_0008);
        }
        self.pm
            .validate_native_handle_caller(admission.subject.caller())?;
        // An already admitted object remains authoritative even if its name was unlinked.
        if admission.existing.is_some() {
            return Ok(());
        }
        let Some((parent, parent_identity)) = admission.parent else {
            return Ok(());
        };
        let entry = self.obj_ns.get(parent).ok_or(0xC000_0008u32)?;
        if entry.identity != parent_identity || entry.kind != OBJ_KIND_DIRECTORY || !entry.is_live()
        {
            return Err(0xC000_0008);
        }
        let Some(index) = self.obj_child(parent, &admission.leaf) else {
            return Ok(());
        };
        if !admission.open_if {
            return Err(0xC000_0035);
        }
        let entry = &self.obj_ns[index];
        if entry.kind != OBJ_KIND_SECTION {
            return Err(0xC000_0024);
        }
        let name = self
            .data_section_names
            .iter()
            .find(|name| name.object_identity == entry.identity)
            .ok_or(0xC000_0024u32)?;
        let identity = name.section;
        let descriptor = self
            .data_section_security
            .iter()
            .find(|record| record.identity == identity)
            .ok_or(0xC000_0022u32)?;
        let tokens = admission.subject.resolve(&self.token_store)?;
        let access = nt_security::authorize_section_open(
            &tokens,
            &descriptor.descriptor,
            admission.requested_access,
            admission.access_mode,
        )?;
        record_access(&access);
        if access.status != 0 {
            return Err(access.status);
        }
        let table = unsafe { &mut *self.loop_ctx.ok_or(0xC000_00A3u32)?.generic_sections };
        if table.section_identity(identity.index()) != Some(identity) {
            return Err(0xC000_0008);
        }
        let reference = table
            .retain_section_reference(name.reference)
            .ok_or(0xC000_009Au32)?;
        admission.existing = Some(reference);
        admission.granted_access = access.granted_access
            & (nt_security::SECTION_GENERIC_MAPPING.generic_all
                | nt_security::ACCESS_SYSTEM_SECURITY);
        admission.status = 0x4000_0000;
        admission.descriptor = None;
        Ok(())
    }

    pub(crate) fn release_data_section_admission(&mut self, admission: &mut DataSectionAdmission) {
        if admission.released {
            return;
        }
        if let Some(reference) = admission.existing.take() {
            assert!(unsafe {
                (&mut *self.loop_ctx.unwrap().generic_sections).release_section_reference(reference)
            });
        }
        admission
            .subject
            .release(&mut self.token_store)
            .expect("Section terminal owns exact subject references");
        self.release_namespace_directory_references(&admission.references);
        admission.released = true;
    }

    pub(crate) fn attach_data_section_name(
        &mut self,
        admission: &mut DataSectionAdmission,
        identity: SectionIdentity,
    ) -> Result<(), u32> {
        let _durable = allocator::enter_durable();
        if admission.released || admission.existing.is_some() {
            return Err(0xC000_0008);
        }
        self.pm
            .validate_native_handle_caller(admission.subject.caller())?;
        if let Some((parent, parent_identity)) = admission.parent {
            let entry = self.obj_ns.get(parent).ok_or(0xC000_0008u32)?;
            if entry.identity != parent_identity
                || entry.kind != OBJ_KIND_DIRECTORY
                || !entry.is_live()
            {
                return Err(0xC000_0008);
            }
            if self.obj_child(parent, &admission.leaf).is_some() {
                return Err(0xC000_0035);
            }
            self.obj_ns.try_reserve(1).map_err(|_| 0xC000_009Au32)?;
            self.data_section_names
                .try_reserve(1)
                .map_err(|_| 0xC000_009Au32)?;
        }
        self.data_section_security
            .try_reserve(1)
            .map_err(|_| 0xC000_009Au32)?;
        let sections = self.loop_ctx.ok_or(0xC000_00A3u32)?.generic_sections;
        if unsafe { (&*sections).section_identity(identity.index()) } != Some(identity) {
            return Err(0xC000_0008);
        }
        if let Some((parent, _)) = admission.parent {
            let reference =
                unsafe { (&mut *sections).retain_section(identity) }.ok_or(0xC000_009Au32)?;
            let Some(index) = self.obj_insert(
                parent,
                &admission.leaf,
                OBJ_KIND_SECTION,
                &[],
                admission.permanent,
            ) else {
                assert!(unsafe { (&mut *sections).release_section_reference(reference) });
                return Err(0xC000_009A);
            };
            self.obj_ns[index].payload = identity.index() as u64;
            self.data_section_names.push(DataSectionName {
                object_identity: self.obj_ns[index].identity,
                section: identity,
                reference,
            });
        }
        self.data_section_security.push(DataSectionSecurity {
            identity,
            descriptor: admission
                .descriptor
                .take()
                .expect("new DATA Section owns assigned descriptor"),
        });
        Ok(())
    }

    pub(crate) fn withdraw_data_section_name(&mut self, identity: SectionIdentity) {
        if let Some(position) = self
            .data_section_names
            .iter()
            .position(|name| name.section == identity)
        {
            let name = self.data_section_names.remove(position);
            if let Some(index) = self.obj_ns.iter().position(|entry| {
                entry.identity == name.object_identity && entry.kind == OBJ_KIND_SECTION
            }) {
                let parent = self.obj_ns[index].parent;
                self.obj_ns[index].unlink();
                if let Some(entry) = self.obj_ns.get(parent) {
                    self.retire_directory_security_body(parent, entry.identity);
                }
            }
            assert!(unsafe {
                (&mut *self.loop_ctx.unwrap().generic_sections)
                    .release_section_reference(name.reference)
            });
        }
    }

    pub(crate) fn data_section_last_handle_closed(&mut self, index: usize) {
        let Some(ctx) = self.loop_ctx else {
            return;
        };
        let Some(identity) = (unsafe { (&*ctx.generic_sections).section_identity(index) }) else {
            return;
        };
        let temporary = self
            .data_section_names
            .iter()
            .find(|name| name.section == identity)
            .and_then(|name| {
                self.obj_ns
                    .iter()
                    .find(|entry| entry.identity == name.object_identity)
            })
            .is_some_and(|entry| !entry.permanent);
        if temporary {
            self.withdraw_data_section_name(identity);
        }
        assert!(unsafe { (&mut *ctx.generic_sections).release_handle(index) });
        self.sweep_data_section_security();
    }

    pub(crate) fn sweep_data_section_security(&mut self) {
        let Some(ctx) = self.loop_ctx else {
            return;
        };
        let table = unsafe { &*ctx.generic_sections };
        self.data_section_security.retain(|record| {
            table.section_identity(record.identity.index()) == Some(record.identity)
        });
    }

    pub(crate) fn publish_existing_data_section(
        &mut self,
        admission: &mut DataSectionAdmission,
        publication: &mut nt_process::NativeSectionHandlePublication,
    ) -> Result<u64, u32> {
        let _durable = allocator::enter_durable();
        let reference = admission.existing.ok_or(0xC000_0008u32)?;
        let identity = reference.identity();
        self.pm
            .validate_native_handle_caller(admission.subject.caller())?;
        let had_handle = self
            .pm
            .handle_object_count(nt_process::HandleObject::Section(
                identity.index() as nt_process::SectionId
            ))
            != 0;
        let table = unsafe { &mut *self.loop_ctx.ok_or(0xC000_00A3u32)?.generic_sections };
        if table.section_identity(identity.index()) != Some(identity) {
            return Err(0xC000_0008);
        }
        publication.bind(
            &mut self.pm,
            identity.index() as nt_process::SectionId,
            admission.granted_access,
        )?;
        if !had_handle && !table.bind_section_reference_handle(reference, publication.value()) {
            return Err(0xC000_0008);
        }
        match publication.publish(&mut self.pm) {
            Ok(handle) => Ok(handle),
            Err(status) => {
                if !had_handle {
                    assert!(table.release_handle(identity.index()));
                }
                Err(status)
            }
        }
    }
}
