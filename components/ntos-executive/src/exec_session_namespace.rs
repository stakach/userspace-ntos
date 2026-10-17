//! Exact numbered Object Manager parents owned by a successful MM session creation.

use super::*;

impl ExecNtHandler {
    pub(super) fn publish_session_namespace(
        &mut self,
        session_id: u32,
        previous_mode: nt_syscall::ProcessorMode,
    ) -> Result<(), u32> {
        if nt_object_manager::session_namespace_ownership(session_id)
            == nt_object_manager::SessionNamespaceOwnership::Bootstrap
        {
            return Ok(());
        }
        let _durable = allocator::enter_durable();
        let parent = self.obj_resolve(b"\\sessions", 0).ok_or(0xC000_003Au32)?;
        self.directory_security_descriptor(parent)?;
        let name = alloc::format!("{session_id}");
        if name.len() > OBJ_NAME_CAP || self.obj_child(parent, name.as_bytes()).is_some() {
            return Err(0xC000_0035);
        }

        let caller = self.native_handle_caller(previous_mode)?;
        let mut subject = nt_user_host::native_caller_subject::NativeCallerSubject::capture(
            &self.pm,
            &mut self.token_store,
            caller,
        )?;
        let descriptors = (|| {
            let tokens = subject.resolve(&self.token_store)?;
            let parent_descriptor = self.directory_security_descriptor(parent)?;
            let mut audit = nt_security::SecurityAssignmentAudit::default();
            let session = nt_security::assign_directory_security(
                &tokens,
                None,
                Some(parent_descriptor),
                subject.mode(),
                &mut audit,
            )?;
            let mut audit = nt_security::SecurityAssignmentAudit::default();
            let windows = nt_security::assign_directory_security(
                &tokens,
                None,
                Some(&session),
                subject.mode(),
                &mut audit,
            )?;
            let mut audit = nt_security::SecurityAssignmentAudit::default();
            let bno = nt_security::assign_directory_security(
                &tokens, None, Some(&session), subject.mode(), &mut audit,
            )?;
            Ok::<_, u32>((session, windows, bno))
        })();
        subject.release(&mut self.token_store)?;
        let (session_descriptor, windows_descriptor, bno_descriptor) = descriptors?;
        self.obj_ns.try_reserve(3).map_err(|_| 0xC000_009Au32)?;
        self.directory_security.try_reserve(3).map_err(|_| 0xC000_009Au32)?;

        // The canonical server owns the paths; the executive mirror carries its exact IDs.
        // All fallible allocations and security assignments precede this native effect.
        let canonical = unsafe { crate::object_manager_create_session_namespace(session_id) }
            .map_err(|status| status.0 as u32)?;
        let session = ObjEntry::push_dir(&mut self.obj_ns, name.as_bytes(), parent, true)
            .expect("preflighted namespace capacity and monotonically allocated identity");
        self.obj_ns[session].payload = canonical.session.0;
        let windows = ObjEntry::push_dir(&mut self.obj_ns, b"windows", session, true)
            .expect("preflighted Windows child capacity and identity");
        self.obj_ns[windows].payload = canonical.windows.0;
        let bno = ObjEntry::push_dir(&mut self.obj_ns, b"basenamedobjects", session, true)
            .expect("preflighted BaseNamedObjects child capacity and identity");
        self.obj_ns[bno].payload = canonical.base_named_objects.0;
        self.directory_security.push(directory_security::DirectorySecurityRecord {
            identity: self.obj_ns[session].identity,
            descriptor: session_descriptor,
            references: 0,
        });
        self.directory_security.push(directory_security::DirectorySecurityRecord {
            identity: self.obj_ns[windows].identity,
            descriptor: windows_descriptor,
            references: 0,
        });
        self.directory_security.push(directory_security::DirectorySecurityRecord {
            identity: self.obj_ns[bno].identity,
            descriptor: bno_descriptor,
            references: 0,
        });
        Ok(())
    }

    /// Retire only a proven empty namespace. A live child, handle, or failed canonical retirement
    /// leaves the namespace intact; monotonically allocated session IDs are never reused.
    pub(super) fn retire_session_namespace_if_empty(&mut self, session_id: u32) {
        if nt_object_manager::session_namespace_ownership(session_id)
            == nt_object_manager::SessionNamespaceOwnership::Bootstrap
        {
            return;
        }
        let Some(parent) = self.obj_resolve(b"\\sessions", 0) else { return };
        let name = alloc::format!("{session_id}");
        let Some(session) = self.obj_child(parent, name.as_bytes()) else { return };
        let Some(windows) = self.obj_child(session, b"windows") else { return };
        let Some(bno) = self.obj_child(session, b"basenamedobjects") else { return };
        let session_entry = self.obj_ns[session];
        let windows_entry = self.obj_ns[windows];
        let bno_entry = self.obj_ns[bno];
        if session_entry.kind != OBJ_KIND_DIRECTORY || windows_entry.kind != OBJ_KIND_DIRECTORY
            || bno_entry.kind != OBJ_KIND_DIRECTORY
            || session_entry.payload == 0 || windows_entry.payload == 0 || bno_entry.payload == 0
            || self.obj_ns.iter().any(|entry| entry.is_live()
                && (entry.parent == windows || entry.parent == bno
                    || (entry.parent == session && entry.identity != windows_entry.identity
                        && entry.identity != bno_entry.identity)))
            || self.pm.handle_object_count(nt_process::HandleObject::ObjectDirectory(session_entry.identity)) != 0
            || self.pm.handle_object_count(nt_process::HandleObject::ObjectDirectory(windows_entry.identity)) != 0
            || self.pm.handle_object_count(nt_process::HandleObject::ObjectDirectory(bno_entry.identity)) != 0
            || self.directory_security.iter().any(|record|
                (record.identity == session_entry.identity || record.identity == windows_entry.identity
                    || record.identity == bno_entry.identity)
                    && record.references != 0)
        {
            return;
        }
        let canonical = nt_object_client::SessionNamespace {
            session: nt_types::ObjectId(session_entry.payload),
            windows: nt_types::ObjectId(windows_entry.payload),
            base_named_objects: nt_types::ObjectId(bno_entry.payload),
        };
        if unsafe { crate::object_manager_retire_session_namespace_exact(session_id, canonical) }
            .is_err()
        {
            return;
        }
        self.obj_ns[bno].unlink();
        self.obj_ns[windows].unlink();
        self.obj_ns[session].unlink();
        self.directory_security.retain(|record| {
            record.identity != session_entry.identity && record.identity != windows_entry.identity
                && record.identity != bno_entry.identity
        });
    }
}
