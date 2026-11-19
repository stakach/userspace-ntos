//! Hosted native Key admission: captured subject, real namespace, exact grant and reserved output.

use super::*;
use nt_process::RegistryKeyHandlePublication;
use nt_user_host::registry_subject::RegistrySubject;

static REGISTRY_CREATE_CAPTURE_ERROR_REPORTS: AtomicU64 = AtomicU64::new(0);
static REGISTRY_OPEN_CAPTURE_ERROR_REPORTS: AtomicU64 = AtomicU64::new(0);
static COMPUTER_NAME_REGISTRY_TRACE_REPORTS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn trace_computer_name_registry(
    operation: &[u8], path: &str, status: u32, pi: usize, tid: u64,
) {
    const MARKER: &[u8] = b"\\control\\computername";
    if !path.as_bytes().windows(MARKER.len())
        .enumerate()
        .any(|(index, part)| part.eq_ignore_ascii_case(MARKER)
            && path.as_bytes().get(index + MARKER.len())
                .is_none_or(|next| *next == b'\\'))
        || COMPUTER_NAME_REGISTRY_TRACE_REPORTS.fetch_add(1, Ordering::Relaxed) >= 64
    {
        return;
    }
    print_str(b"[computer-name-registry] op=");
    print_str(operation);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" path=");
    print_ascii_str(path);
    print_str(b"\n");
}

fn note_registry_capture_error(operation: &[u8], status: u32, pi: usize, tid: u64) {
    let reports = if operation == b"create" {
        &REGISTRY_CREATE_CAPTURE_ERROR_REPORTS
    } else {
        &REGISTRY_OPEN_CAPTURE_ERROR_REPORTS
    };
    if reports.fetch_add(1, Ordering::Relaxed) >= 32 {
        return;
    }
    print_str(b"[registry-capture-error] op=");
    print_str(operation);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

/// Owned across CM work; no token/PM/namespace borrow survives an IPC boundary.
pub(crate) struct HostedRegistryPublication {
    pub subject: RegistrySubject,
    pub publication: RegistryKeyHandlePublication,
    pub path: alloc::string::String,
    pub output: u64,
    pub disposition_output: u64,
    pub desired: u32,
    pub bound_target: Option<KeyRef>,
    /// OBJ_OPENLINK / REG_OPTION_OPEN_LINK: a final symbolic link key is opened itself.
    pub open_link: bool,
    root: Option<(KeyRef, RegistryKeyHandlePublication)>,
    relative: Option<alloc::string::String>,
}

/// One registry name resolution step: the key, or the absolute name a symbolic link key
/// redirects the open to (CmpParseKey's reparse).
pub(crate) enum RegistryTargetStep {
    Key(KeyRef),
    Reparse(alloc::string::String),
}

const OBJ_OPENLINK: u32 = 0x100;
const REG_OPTION_VOLATILE: u32 = 0x1;
const REG_OPTION_CREATE_LINK: u32 = 0x2;
const REG_OPTION_BACKUP_RESTORE: u32 = 0x4;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;

impl ExecNtHandler {
    pub(super) unsafe fn read_registry_name_checked(
        &mut self,
        address: u64,
    ) -> Result<alloc::string::String, u32> {
        let mut header = [0u8; 16];
        self.process_memory_read_status(self.pi, address, &mut header)?;
        let input = nt_kernel_exec::user_string::object_name_input(&header)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let mut bytes = alloc::vec![0u8; input.length];
        if input.length != 0 {
            self.process_memory_read_status(self.pi, input.buffer, &mut bytes)?;
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
        if flags & !(0x2 | 0x40 | 0x80 | OBJ_OPENLINK | 0x200 | 0x400) != 0 {
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
                open_link: flags & OBJ_OPENLINK != 0,
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
        open_link: bool,
    ) -> Result<RegistryTargetStep, u32> {
        match &state.root {
            Some((root, _)) => self.acquire_relative_registry_target_step(
                *root,
                state.relative.as_deref().expect("relative registry name"),
                open_link,
            ),
            None => self.acquire_registry_target_step(&state.path, open_link),
        }
    }

    /// ObpLookupObjectName's reparse: the open restarts on the link's absolute target, which
    /// may be in another hive. The captured root no longer applies.
    unsafe fn reparse_hosted_registry_publication(
        &mut self,
        state: &mut HostedRegistryPublication,
        target: &str,
        reparses: &mut usize,
    ) -> Result<(), u32> {
        *reparses += 1;
        if *reparses > nt_hive_core::MAX_REPARSE {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let path = self.registry_storage_canon(target)?;
        self.release_hosted_registry_root(state);
        state.relative = None;
        state.path = path;
        Ok(())
    }

    /// The caller retains a canonical reference to root across the target service exchange.
    /// Symbolic links on the way are followed to wherever they lead.
    pub(crate) unsafe fn acquire_relative_registry_target(
        &mut self,
        root: KeyRef,
        name: &str,
    ) -> Result<KeyRef, u32> {
        match self.acquire_relative_registry_target_step(root, name, false)? {
            RegistryTargetStep::Key(target) => Ok(target),
            RegistryTargetStep::Reparse(target) => {
                let path = self.registry_storage_canon(&target)?;
                self.acquire_registry_target(&path)
            }
        }
    }

    unsafe fn install_opened_system_key(
        &mut self,
        opened: nt_config_client::OpenedSystemHiveKey,
    ) -> Result<KeyRef, u32> {
        match self.install_cm_system_key_target(CmSystemKeyTarget {
            lease: opened.lease,
            physical_path: nt_hive_core::canon_path(&opened.physical_path),
        }) {
            Ok(target) => Ok(target),
            Err(status) => {
                let _ = crate::config_manager_retire_system_hive_key(opened.lease);
                Err(status)
            }
        }
    }

    unsafe fn system_key_step(
        &mut self,
        path: &str,
        root: Option<nt_config_client::SystemHiveKeyLease>,
        open_link: bool,
    ) -> Result<RegistryTargetStep, u32> {
        match crate::cm_key_ownership::open_step(path, root, open_link)
            .map_err(|status| status as u32)?
        {
            crate::cm_key_ownership::SystemKeyOpen::Opened(opened) => {
                self.install_opened_system_key(opened).map(RegistryTargetStep::Key)
            }
            crate::cm_key_ownership::SystemKeyOpen::Reparse(target) => {
                Ok(RegistryTargetStep::Reparse(target))
            }
        }
    }

    unsafe fn acquire_relative_registry_target_step(
        &mut self,
        root: KeyRef,
        name: &str,
        open_link: bool,
    ) -> Result<RegistryTargetStep, u32> {
        if name.starts_with('\\') || name.contains('\0') {
            return Err(0xC000_003B);
        }
        if let Some(target) = self.cm_system_key_target(root) {
            return self.system_key_step(name, Some(target.lease), open_link);
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
                .install_cm_runtime_key_target(nt_hive_core::canon_path(&path), reply.detail0)
                .map(RegistryTargetStep::Key);
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
        self.acquire_registry_target_step(&path, open_link)
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

    /// The key at canonical `path`, following symbolic links to wherever they lead.
    pub(crate) unsafe fn acquire_registry_target(&mut self, path: &str) -> Result<KeyRef, u32> {
        let mut path = alloc::string::String::from(path);
        for _ in 0..=nt_hive_core::MAX_REPARSE {
            match self.acquire_registry_target_step(&path, false)? {
                RegistryTargetStep::Key(target) => return Ok(target),
                RegistryTargetStep::Reparse(target) => path = self.registry_storage_canon(&target)?,
            }
        }
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// Resolve canonical `path` in its owning hive. Only the CM-owned SYSTEM hive holds symbolic
    /// link keys; crossing one yields its target instead of a key.
    unsafe fn acquire_registry_target_step(
        &mut self,
        path: &str,
        open_link: bool,
    ) -> Result<RegistryTargetStep, u32> {
        if let Some(target) = Self::virtual_registry_root_target_from_canon(path) {
            return Ok(RegistryTargetStep::Key(target));
        }
        // Volatile link keys outside SYSTEM live in the overlay.
        if let Some(reparse) = self.overlay.link_reparse(path, open_link) {
            return reparse
                .map(RegistryTargetStep::Reparse)
                .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if let Some(index) = self.registry_overlay_index_for_canon_path(path) {
            return Ok(RegistryTargetStep::Key(OVERLAY_KEY_TAG | index as u32));
        }
        if is_cm_runtime_registry_path(path) {
            let key = crate::config_manager_open_key_id(path).map_err(|status| status as u32)?;
            return self.install_cm_runtime_key_target(path.into(), key).map(RegistryTargetStep::Key);
        }
        if is_system_registry_path(path) {
            return self.system_key_step(path, None, open_link);
        }
        match self.mutable_hives.resolve_key_following(path, open_link) {
            Ok(Some(Ok(key))) => {
                return self.install_mutable_registry_key_target(key).map(RegistryTargetStep::Key);
            }
            Ok(Some(Err(target))) => return Ok(RegistryTargetStep::Reparse(target)),
            Ok(None) => {}
            Err(_) => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
        if self.mutable_hive_owns_path(path) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        self.resolve_key(path).map(RegistryTargetStep::Key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    fn trace_key_access_denied(&self, state: &HostedRegistryPublication, status: u32) {
        if status == nt_security::STATUS_ACCESS_DENIED {
            self.trace_access_denied(crate::access_denial_trace::DeniedObject::Key,
                state.path.encode_utf16(), state.desired, 0, status);
        }
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

    /// Publish the exact child cell produced by the anchored mutable-hive WAL.
    pub(crate) unsafe fn finish_anchored_mutable_child(
        &mut self,
        state: &mut HostedRegistryPublication,
        parent: ResolvedHiveKey,
        child: nt_hive_core::CellId,
        grant: u32,
    ) -> Result<(), u32> {
        let expected = ResolvedHiveKey { hive: parent.hive, key: child };
        if self.mutable_registry_key_by_path(&state.path) != Some(expected) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let target = self.install_mutable_registry_key_target(expected)?;
        self.finish_hosted_registry_publication(state, target, grant, true)
    }

    /// An earlier queued create may have published this child before our own WAL preparation.
    /// Reopen under the retained parent and authorize it as an existing key.
    pub(crate) unsafe fn finish_existing_mutable_child(
        &mut self,
        state: &mut HostedRegistryPublication,
        parent: ResolvedHiveKey,
        backup: bool,
    ) -> Result<(), u32> {
        let (parent_path, leaf) = state.path.rsplit_once('\\').ok_or(STATUS_INVALID_HANDLE)?;
        if leaf.is_empty() || self.mutable_key_path(parent).as_deref() != Some(parent_path) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let child = self.mutable_hives.hive(parent.hive)
            .and_then(|hive| hive.open_subkey(parent.key, leaf))
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let expected = ResolvedHiveKey { hive: parent.hive, key: child };
        if self.mutable_registry_key_by_path(&state.path) != Some(expected) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let target = self.install_mutable_registry_key_target(expected)?;
        self.bind_hosted_registry_target(state, target)?;
        let granted = self.registry_open_grant(state, target, backup)?;
        self.finish_hosted_registry_publication(state, target, granted, false)
    }

    pub(super) unsafe fn nt_open_key_admitted(&mut self, args: &[u64]) -> u32 {
        self.nt_open_key_with_options(args, nt_config_manager::KeyOpenOptions::default())
    }

    pub(super) unsafe fn nt_open_key_ex_admitted(&mut self, args: &[u64]) -> u32 {
        let options = match nt_config_manager::validate_key_open_options(nt_ulong_arg(args[3])) {
            Ok(options) => options,
            Err(status) => return status,
        };
        self.nt_open_key_with_options(args, options)
    }

    unsafe fn nt_open_key_with_options(
        &mut self,
        args: &[u64],
        options: nt_config_manager::KeyOpenOptions,
    ) -> u32 {
        let backup = options.backup;
        let _durable = allocator::enter_durable();
        let (mut state, _) = match self.capture_hosted_registry_publication(args, false) {
            Ok(state) => state,
            Err(status) => {
                note_registry_capture_error(b"open", status, self.pi, self.current_tid);
                return status;
            }
        };
        state.open_link |= options.open_link;
        trace_computer_name_registry(b"open-ingress", &state.path, 0, self.pi, self.current_tid);
        let result = (|| {
            let mut reparses = 0;
            let target = loop {
                match self.acquire_hosted_registry_target(&state, state.open_link)? {
                    RegistryTargetStep::Key(target) => break target,
                    RegistryTargetStep::Reparse(target) => self
                        .reparse_hosted_registry_publication(&mut state, &target, &mut reparses)?,
                }
            };
            self.bind_hosted_registry_target(&mut state, target)?;
            let granted = match self.registry_open_grant(&state, target, backup) {
                Ok(granted) => granted,
                Err(status) => return Err(status),
            };
            self.finish_hosted_registry_publication(&mut state, target, granted, false)
        })();
        match result {
            Ok(()) => {
                trace_computer_name_registry(b"open-return", &state.path, 0, self.pi, self.current_tid);
                self.observe_install_pipe_enum_open(self.pi, &state.path, 0);
                0
            },
            Err(status) => {
                trace_computer_name_registry(b"open-return", &state.path, status, self.pi, self.current_tid);
                if status == STATUS_OBJECT_NAME_NOT_FOUND {
                    self.note_registry_open_miss(&state.path);
                    self.note_completed_installer_inf_probe(&state.path, status);
                    if state.path.split('\\').any(|part|
                        part.eq_ignore_ascii_case("image file execution options"))
                    {
                        crate::spawn_hosts::shared_ingress::owner::runtime::trace_ifeo_open_miss(
                            self.pi, self.current_tid, self.current_badge,
                        );
                    }
                }
                crate::registry_security_audit::admission_error(
                    b"open", &state.path, status, self.pi, self.current_tid,
                );
                self.trace_key_access_denied(&state, status);
                self.abort_hosted_registry_publication(&mut state);
                self.observe_install_pipe_enum_open(self.pi, &state.path, status);
                status
            }
        }
    }

    pub(super) unsafe fn nt_create_key_admitted(&mut self, args: &[u64]) -> u32 {
        let _durable = allocator::enter_durable();
        let options = nt_ulong_arg(args[5]);
        if options & !(REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK | REG_OPTION_BACKUP_RESTORE) != 0 {
            return STATUS_NOT_SUPPORTED;
        }
        let backup = options & REG_OPTION_BACKUP_RESTORE != 0;
        let volatile = options & REG_OPTION_VOLATILE != 0;
        let link = options & REG_OPTION_CREATE_LINK != 0;
        let kind = if link {
            nt_hive_core::KeyKind::SymbolicLink
        } else {
            nt_hive_core::KeyKind::Ordinary
        };
        let expected_generation =
            crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
        let (mut state, creator_pointer) =
            match self.capture_hosted_registry_publication(args, true) {
                Ok(state) => state,
                Err(status) => {
                    note_registry_capture_error(b"create", status, self.pi, self.current_tid);
                    return status;
                }
            };
        trace_computer_name_registry(b"create-ingress", &state.path, 0, self.pi, self.current_tid);
        let mut reparses = 0;
        loop {
        let mut parent_retention = None;
        let mut durable_create = None;
        let mut mutable_create = None;
        let mut reparse = None;
        let result = (|| {
            // CmpDoOpen: with CREATE_LINK an existing final key is a collision, never followed.
            match self.acquire_hosted_registry_target(&state, state.open_link || link) {
                Ok(RegistryTargetStep::Key(target)) if link => {
                    self.release_registry_key_target(target);
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                Ok(RegistryTargetStep::Key(target)) => {
                    self.bind_hosted_registry_target(&mut state, target)?;
                    let granted = match self.registry_open_grant(&state, target, backup) {
                        Ok(granted) => granted,
                        Err(status) => return Err(status),
                    };
                    return self
                        .finish_hosted_registry_publication(&mut state, target, granted, false);
                }
                Ok(RegistryTargetStep::Reparse(target)) => {
                    reparse = Some(target);
                    return Err(nt_config_abi::CM_STATUS_REPARSE as u32);
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
                    self.acquire_relative_registry_target_step(*root, relative_parent, false)
                }
                None => self.acquire_registry_target_step(parent_path, false),
            };
            let parent = match parent_result {
                Ok(RegistryTargetStep::Key(parent)) => parent,
                Ok(RegistryTargetStep::Reparse(target)) => {
                    // The parent is reached through a link: create beneath its target instead.
                    parent_owner
                        .abort(&mut self.pm)
                        .expect("parent reservation");
                    reparse = Some(alloc::format!("{target}\\{leaf}"));
                    return Err(nt_config_abi::CM_STATUS_REPARSE as u32);
                }
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
            // CM runtime keys (HARDWARE) are a separate in-memory registry without link keys.
            if link && is_cm_runtime_registry_path(&state.path) {
                return Err(STATUS_NOT_SUPPORTED);
            }
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
            if !volatile {
                if let Some(mutable) = self.mutable_key_handle(parent) {
                    match crate::fs_loader::exec_fs_mount_identity()
                        .and_then(crate::fs_loader::exec_block_route_kind) {
                        Some(nt_fs::BlockSourceKind::Native) => {
                            mutable_create = Some((parent, mutable, alloc::string::String::from(leaf),
                                class, prepared));
                            return Ok(());
                        }
                        Some(nt_fs::BlockSourceKind::Draining) => return Err(nt_fs::STATUS_DEVICE_NOT_READY),
                        _ => {}
                    }
                }
            }
            let (target, created) = self.create_secured_registry_child(
                parent,
                &state.path,
                &prepared.descriptor,
                class.as_deref(),
                volatile,
                kind,
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
            let mutation = if link {
                nt_config_client::SystemHiveMutation::CreateLinkRelative {
                    volatile,
                    parent: lease,
                    name: &leaf,
                    class_name: class.as_deref(),
                    descriptor: &prepared.descriptor,
                }
            } else {
                nt_config_client::SystemHiveMutation::CreateChildRelative {
                    parent: lease,
                    name: &leaf,
                    class_name: class.as_deref(),
                    descriptor: &prepared.descriptor,
                    volatile,
                }
            };
            trace_computer_name_registry(b"create-submit-enter", &state.path, 0, self.pi, self.current_tid);
            match crate::registry_mutation_work::submit_hosted(
                self, state, owner, parent, leaf.clone(), prepared.granted_access,
                expected_generation, mutation,
            ) {
                Ok(()) => return 0x103,
                Err((status, mut state, mut owner)) => {
                    trace_computer_name_registry(b"create-submit", &state.path, status, self.pi, self.current_tid);
                    crate::registry_security_audit::admission_error(
                        b"create-submit", &state.path, status, self.pi, self.current_tid,
                    );
                    self.trace_key_access_denied(&state, status);
                    if let Some(target) = owner.abort(&mut self.pm).expect("unsubmitted parent") {
                        self.release_registry_key_target(target);
                    }
                    self.abort_hosted_registry_publication(&mut state);
                    return status;
                }
            }
        }
        if let Some((parent, mutable, leaf, class, prepared)) = mutable_create {
            let owner = parent_retention.take().expect("mutable create parent reservation");
            match crate::mutable_hive_mutation_work::submit_hosted_create_child(
                self, state, owner, parent, mutable, leaf, class,
                prepared.descriptor, kind, prepared.granted_access, backup,
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
        if let Some(target) = reparse {
            match self.reparse_hosted_registry_publication(&mut state, &target, &mut reparses) {
                Ok(()) => continue,
                Err(status) => {
                    self.abort_hosted_registry_publication(&mut state);
                    return status;
                }
            }
        }
        return match result {
            Ok(()) => {
                trace_computer_name_registry(b"create-return", &state.path, 0, self.pi, self.current_tid);
                0
            },
            Err(status) => {
                trace_computer_name_registry(b"create-return", &state.path, status, self.pi, self.current_tid);
                crate::registry_security_audit::admission_error(
                    b"create", &state.path, status, self.pi, self.current_tid,
                );
                self.trace_key_access_denied(&state, status);
                self.abort_hosted_registry_publication(&mut state);
                status
            }
        };
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
        kind: nt_hive_core::KeyKind,
    ) -> Result<(KeyRef, bool), u32> {
        let link = kind == nt_hive_core::KeyKind::SymbolicLink;
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
            // A link is created, never opened (CmpDoOpen's collision).
            if link {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            return Ok((OVERLAY_KEY_TAG | index as u32, false));
        }
        if let Some(mutable) = self.mutable_key_handle(parent) {
            if let Some(key) = self
                .mutable_hives
                .hive(mutable.hive)
                .and_then(|hive| hive.open_subkey(mutable.key, name))
            {
                if link {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                return self
                    .install_mutable_registry_key_target(ResolvedHiveKey {
                        hive: mutable.hive,
                        key,
                    })
                    .map(|target| (target, false));
            }
            if !volatile {
                let key = self.journal_create_secured_mutable_subkey_of_kind(
                    mutable, name, class, descriptor, kind,
                )?;
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
        let index = self.overlay.create_secured_owned_of_kind(
            path.into(),
            volatile,
            class.map(Into::into),
            descriptor.to_vec(),
            link,
        )?;
        unsafe { self.registry_subkey_created(path) };
        Ok((OVERLAY_KEY_TAG | index as u32, true))
    }

    pub(crate) fn journal_create_secured_mutable_subkey(
        &mut self,
        parent: ResolvedHiveKey,
        name: &str,
        class: Option<&str>,
        descriptor: &[u8],
    ) -> Result<ResolvedHiveKey, u32> {
        self.journal_create_secured_mutable_subkey_of_kind(
            parent, name, class, descriptor, nt_hive_core::KeyKind::Ordinary,
        )
    }

    /// As [`Self::journal_create_secured_mutable_subkey`], for a child of `kind`.
    pub(crate) fn journal_create_secured_mutable_subkey_of_kind(
        &mut self,
        parent: ResolvedHiveKey,
        name: &str,
        class: Option<&str>,
        descriptor: &[u8],
        kind: nt_hive_core::KeyKind,
    ) -> Result<ResolvedHiveKey, u32> {
        let child = self
            .journal_create_secured_mutable_subkey_unreported(parent, name, class, descriptor, kind)?;
        self.mutable_registry_subkey_created(child);
        Ok(child)
    }

    fn journal_create_secured_mutable_subkey_unreported(
        &mut self,
        parent: ResolvedHiveKey,
        name: &str,
        class: Option<&str>,
        descriptor: &[u8],
        kind: nt_hive_core::KeyKind,
    ) -> Result<ResolvedHiveKey, u32> {
        if self.boot_v2_mutable_hive_journal() {
            return self.boot_v2_create_secured_mutable_subkey(parent, name, class, descriptor, kind);
        }
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
                        kind,
                    },
                    |hive| {
                        let mut transaction = hive.begin_transaction();
                        if transaction
                            .try_create_child_of_kind(
                                parent.key,
                                name.into(),
                                class.map(Into::into),
                                descriptor.to_vec(),
                                false,
                                kind,
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
